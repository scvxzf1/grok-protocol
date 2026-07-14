import json
import os
import stat
import tempfile
import threading
import time
import unittest
from unittest import mock
from pathlib import Path

import http_batch_service as svc


class ProjectBrowserCleanupTests(unittest.TestCase):
    class FakeProcess:
        def __init__(self, pid, name, cmdline, children=None):
            self.info = {
                "pid": pid,
                "ppid": 0,
                "name": name,
                "exe": name,
                "cmdline": list(cmdline),
            }
            self._children = list(children or [])
            self.terminated = 0
            self.killed = 0

        def children(self, recursive=False):
            return list(self._children)

        def terminate(self):
            self.terminated += 1

        def kill(self):
            self.killed += 1

    def test_project_tree_cleanup_requires_browser_name_and_profile_marker(self):
        child = self.FakeProcess(102, "chrome.exe", ["chrome.exe", "--type=renderer"])
        project_root = self.FakeProcess(
            101,
            "chrome.exe",
            ["chrome.exe", "--user-data-dir=C:/temp/xai-ts-chrome-owned"],
            [child],
        )
        daily_chrome = self.FakeProcess(
            201,
            "chrome.exe",
            ["chrome.exe", "--user-data-dir=C:/BrowserProfiles/default"],
        )
        marker_in_page_url = self.FakeProcess(
            202,
            "chrome.exe",
            ["chrome.exe", "https://example.test/xai-ts-chrome-owned"],
        )
        mentioning_shell = self.FakeProcess(
            301,
            "pwsh.exe",
            ["pwsh.exe", "echo", "xai-ts-chrome-owned"],
        )
        with mock.patch("psutil.wait_procs", return_value=([project_root, child], [])):
            killed = svc._terminate_project_browser_trees(
                process_iter=lambda: [
                    project_root,
                    child,
                    daily_chrome,
                    marker_in_page_url,
                    mentioning_shell,
                ]
            )
        self.assertEqual(killed, 2)
        self.assertEqual(project_root.terminated, 1)
        self.assertEqual(child.terminated, 1)
        self.assertEqual(daily_chrome.terminated, 0)
        self.assertEqual(marker_in_page_url.terminated, 0)
        self.assertEqual(mentioning_shell.terminated, 0)

    def test_cleanup_removes_only_direct_project_profile_dirs(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            owned = root / "xai-ts-chrome-owned"
            owned.mkdir()
            (root / "xai-ts-probe-keep").mkdir()
            (root / "xai-chrome-raw-keep").mkdir()
            (root / "playwright_chromiumdev_profile-keep").mkdir()
            patterns = []
            result = svc.cleanup_browser_residues(
                temp_root=root,
                kill_playwright=True,
                kill_all_chrome=True,
                pkill_fn=lambda pattern: patterns.append(pattern) or 2,
            )
        self.assertEqual(patterns, ["xai-ts-chrome-"])
        self.assertEqual(result["killed_chrome"], 2)
        self.assertEqual(result["killed_playwright"], 0)
        self.assertEqual(result["removed_temp_dirs"], 1)

    def test_windows_broker_uses_process_group_and_ctrl_break(self):
        with mock.patch.object(
            svc.subprocess,
            "CREATE_NEW_PROCESS_GROUP",
            0x200,
            create=True,
        ):
            self.assertEqual(svc._managed_broker_creation_flags("nt"), 0x200)
            self.assertEqual(svc._managed_broker_creation_flags("posix"), 0)
        process = mock.Mock()
        with mock.patch.object(svc.signal, "CTRL_BREAK_EVENT", 21, create=True):
            svc._request_graceful_broker_shutdown(process, platform_name="nt")
        process.send_signal.assert_called_once_with(21)
        process.terminate.assert_not_called()

    def test_posix_broker_shutdown_uses_terminate(self):
        process = mock.Mock()
        svc._request_graceful_broker_shutdown(process, platform_name="posix")
        process.terminate.assert_called_once_with()
        process.send_signal.assert_not_called()


class HttpBatchServiceSmokeTests(unittest.TestCase):
    def test_build_plan_keeps_msgraph_parallel_workers(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            mail_file = root / "outlook.txt"
            mail_file.write_text("", encoding="utf-8")
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "msgraph",
                        "ms_mail_file": str(mail_file),
                        "turnstile_provider": "local",
                        "turnstile_headless": True,
                        "local_turnstile_max_workers": 5,
                        "register_count": 5,
                        "concurrent_workers": 5,
                    }
                ),
                encoding="utf-8",
            )
            settings = svc.Settings(
                config_path=cfg,
                count=5,
                workers=5,
                output_dir=root / "creds",
                run_mode=svc.RUN_MODE_REGISTER_OTP,
                turnstile_provider="local",
                turnstile_headless=True,
                config=svc._read_config(cfg),
            )
            with mock.patch.dict(
                svc.os.environ,
                {
                    "XAI_CASTLE_EMAIL_TOKEN": "",
                    "XAI_CASTLE_REGISTER_TOKEN": "",
                },
                clear=False,
            ):
                plan = svc.build_plan(settings)

            self.assertEqual(plan.workers, 5)
            self.assertTrue(any("跨进程文件锁" in warning for warning in plan.warnings))
            self.assertFalse(any("强制单并发" in warning for warning in plan.warnings))

    def test_build_plan_local_caps_workers(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "local",
                        "turnstile_headless": True,
                        "register_count": 10,
                        "concurrent_workers": 10,
                    }
                ),
                encoding="utf-8",
            )
            settings = svc.Settings(
                config_path=cfg,
                count=10,
                workers=10,
                output_dir=root / "creds",
                run_mode=svc.RUN_MODE_REGISTER_OTP,
                turnstile_provider="local",
                turnstile_headless=True,
                config=svc._read_config(cfg),
            )
            plan = svc.build_plan(settings)
            # Account concurrency is independent; only Turnstile browser slots are capped.
            self.assertEqual(plan.workers, 10)
            self.assertLessEqual(plan.turnstile_workers, svc.MAX_LOCAL_TURNSTILE_WORKERS)

    def test_build_plan_local_uses_configured_cap(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "local",
                        "turnstile_headless": True,
                        "register_count": 10,
                        "concurrent_workers": 10,
                        "local_turnstile_max_workers": 8,
                    }
                ),
                encoding="utf-8",
            )
            settings = svc.Settings(
                config_path=cfg,
                count=10,
                workers=10,
                output_dir=root / "creds",
                run_mode=svc.RUN_MODE_REGISTER_OTP,
                turnstile_provider="local",
                turnstile_headless=True,
                config=svc._read_config(cfg),
            )
            plan = svc.build_plan(settings)
            self.assertEqual(plan.workers, 10)
            self.assertEqual(plan.turnstile_workers, 8)
            self.assertTrue(any("local_turnstile_max_workers" in w for w in plan.warnings))
            self.assertTrue(any("YYDS" in w for w in plan.warnings))
            self.assertFalse(
                any(("限制为" in w and "YYDS" in w) for w in plan.warnings),
                msg=f"local cap warning should not mix YYDS: {plan.warnings}",
            )

    def test_build_plan_non_local_ignores_local_cap(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "capsolver",
                        "turnstile_api_key": "CAP-test",
                        "register_count": 5,
                        "concurrent_workers": 5,
                        "local_turnstile_max_workers": 1,
                    }
                ),
                encoding="utf-8",
            )
            settings = svc.Settings(
                config_path=cfg,
                count=5,
                workers=5,
                output_dir=root / "creds",
                run_mode=svc.RUN_MODE_REGISTER_OTP,
                turnstile_provider="capsolver",
                turnstile_headless=False,
                config=svc._read_config(cfg),
            )
            plan = svc.build_plan(settings)
            self.assertEqual(plan.workers, 5)

    def test_resolve_local_turnstile_max_workers_defaults_and_strict(self):
        self.assertEqual(svc.resolve_local_turnstile_max_workers({}), 5)
        self.assertEqual(
            svc.resolve_local_turnstile_max_workers({"local_turnstile_max_workers": 12}),
            12,
        )
        self.assertEqual(
            svc.resolve_local_turnstile_max_workers({"local_turnstile_max_workers": 0}),
            5,
        )
        self.assertEqual(
            svc.resolve_local_turnstile_max_workers({"local_turnstile_max_workers": 7000}),
            5,
        )
        with self.assertRaises(svc.TuiConfigError):
            svc.resolve_local_turnstile_max_workers(
                {"local_turnstile_max_workers": 0},
                strict=True,
            )
        with self.assertRaises(svc.TuiConfigError):
            svc.resolve_local_turnstile_max_workers(
                {"local_turnstile_max_workers": 7000},
                strict=True,
            )


class CanonicalConfigTests(unittest.TestCase):
    def test_canonical_keys_win_and_persist_removes_legacy_aliases(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            pool = root / "proxies.txt"
            pool.write_text("1.1.1.1:80:u:p\n", encoding="utf-8")
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "turnstile_provider": "local",
                        "credential_flow": "sso_device",
                        "tui_run_mode": "register_otp",
                        "proxy_mode": "pool",
                        "tui_proxy_mode": "none",
                        "target_mode": "continuous",
                        "run_target_mode": "count",
                        "sso_convert_retries": 7,
                        "tui_sso_convert_retries": 2,
                        "sso_convert_cooldown": 9,
                        "tui_sso_convert_cooldown": 1,
                        "proxy_file": "proxies.txt",
                        "register_count": 11,
                        "concurrent_workers": 3,
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            settings = service.settings
            self.assertEqual(settings.run_mode, svc.RUN_MODE_REGISTER_SSO)
            self.assertEqual(settings.proxy_mode, "pool")
            self.assertEqual(settings.target_mode, svc.TARGET_MODE_CONTINUOUS)
            self.assertEqual(settings.sso_convert_retries, 7)
            self.assertEqual(settings.sso_convert_cooldown, 9)

            svc.persist_settings(settings)
            disk = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(disk["credential_flow"], "sso_device")
            self.assertEqual(disk["proxy_mode"], "pool")
            self.assertEqual(disk["target_mode"], "continuous")
            self.assertEqual(disk["sso_convert_retries"], 7)
            for legacy in (
                "tui_run_mode",
                "tui_proxy_mode",
                "run_target_mode",
                "tui_sso_convert_retries",
                "tui_sso_convert_cooldown",
            ):
                self.assertNotIn(legacy, disk)

    def test_start_overrides_use_temporary_settings_copy(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "capsolver",
                        "turnstile_api_key": "CAP-test",
                        "register_count": 9,
                        "concurrent_workers": 2,
                    }
                ),
                encoding="utf-8",
            )
            before = cfg.read_text(encoding="utf-8")
            service = svc.BatchService(config_path=cfg, root_dir=root)
            with mock.patch.object(
                svc.BatchRunner,
                "start",
                lambda self: setattr(self, "started", True) or setattr(self, "done", False),
            ), mock.patch.object(svc, "RUNS_DIR", root / "runs"), mock.patch.object(
                svc, "ROOT_DIR", root
            ):
                service.start_run({"count": 1, "workers": 1})
            self.assertEqual(service.settings.count, 9)
            self.assertEqual(service.settings.workers, 2)
            self.assertEqual(service._runner.plan.count, 1)
            self.assertEqual(service._runner.plan.workers, 1)
            self.assertEqual(cfg.read_text(encoding="utf-8"), before)


class FailureClassifyTests(unittest.TestCase):
    def test_classify_yyds_429(self):
        self.assertEqual(
            svc.classify_failure_text("YYDS create HTTP 429: Too many account creation requests"),
            "yyds_rate_limit",
        )

    def test_classify_hard_block(self):
        self.assertEqual(
            svc.classify_failure_text("检测到拦截 | kind=cloudflare_hard_block"),
            "turnstile_hard_block",
        )

    def test_classify_browser_launch(self):
        self.assertEqual(
            svc.classify_failure_text("无法启动浏览器: Maximum number of clients reached"),
            "browser_launch_failed",
        )

    def test_classify_turnstile_600010_as_transient_challenge(self):
        text = (
            "Turnstile broker 求解失败: Turnstile challenge error 600010 | "
            "category=turnstile_challenge_transient code=600010 "
            "attempts=2/2 retries=1"
        )
        self.assertEqual(
            svc.classify_failure_text(text),
            "turnstile_challenge_transient",
        )
        self.assertFalse(svc._looks_like_proxy_failure(text))


class BatchServiceSingletonTests(unittest.TestCase):
    def test_reject_second_start(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "capsolver",
                        "turnstile_api_key": "CAP-test",
                        "register_count": 1,
                        "concurrent_workers": 1,
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            with mock.patch.object(svc.BatchRunner, "start", lambda self: setattr(self, "started", True) or setattr(self, "done", False)), \
                 mock.patch.object(svc, "RUNS_DIR", root / "runs"), \
                 mock.patch.object(svc, "ROOT_DIR", root):
                # also patch build_plan output dir under temp
                snap1 = service.start_run({"count": 1, "workers": 1})
                self.assertIn("run_id", snap1)
                with self.assertRaises(svc.TuiConfigError):
                    service.start_run({"count": 1, "workers": 1})

    def test_poller_and_stop_are_serialized_by_service_lock(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text("{}\n", encoding="utf-8")
            service = svc.BatchService(config_path=cfg, root_dir=root)
            tick_entered = threading.Event()
            release_tick = threading.Event()
            stop_entered = threading.Event()

            class FakeRunner:
                started = True
                done = False
                logs = []

                def __init__(self):
                    self.tick_calls = 0

                def tick(self):
                    self.tick_calls += 1
                    if self.tick_calls == 1:
                        tick_entered.set()
                        release_tick.wait(timeout=2)

                def stop(self):
                    stop_entered.set()

                @staticmethod
                def snapshot():
                    return {"run_id": "serialized"}

            service._runner = FakeRunner()
            errors = []

            def call(method):
                try:
                    method()
                except Exception as exc:  # pragma: no cover - asserted below
                    errors.append(exc)

            poller = threading.Thread(target=call, args=(service.poll,))
            stopper = threading.Thread(target=call, args=(service.stop_run,))
            poller.start()
            self.assertTrue(tick_entered.wait(timeout=1))
            stopper.start()
            time.sleep(0.05)
            self.assertFalse(stop_entered.is_set())
            release_tick.set()
            poller.join(timeout=2)
            stopper.join(timeout=2)
            self.assertFalse(poller.is_alive())
            self.assertFalse(stopper.is_alive())
            self.assertTrue(stop_entered.is_set())
            self.assertEqual(errors, [])


class RunHistoryTests(unittest.TestCase):
    def test_resolve_run_file_blocks_escape(self):
        with tempfile.TemporaryDirectory() as d:
            runs = Path(d) / "http_runs"
            rid = "20260711_demo"
            (runs / rid).mkdir(parents=True)
            (runs / rid / "worker_001.log").write_text("ok", encoding="utf-8")
            path = svc.resolve_run_file(rid, "worker_001.log", runs_dir=runs)
            self.assertTrue(path.is_file())
            with self.assertRaises(Exception):
                svc.resolve_run_file(rid, "../secret.txt", runs_dir=runs)



class ConfigCenterTests(unittest.TestCase):
    def test_proxy_modes_and_auto_direct_resolution(self):
        self.assertEqual(
            set(svc.PROXY_MODE_LABELS),
            {"auto", "none", "direct", "pool"},
        )
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            settings = svc.Settings(
                config_path=root / "config.json",
                count=1,
                workers=1,
                output_dir=root,
                proxy_mode="auto",
                config={"proxy": "http://user:pass@proxy.example:8080"},
            )
            mode, args = svc._resolve_proxy_args(settings)
            self.assertEqual(mode, "direct")
            self.assertEqual(
                args,
                ["--proxy", "http://user:pass@proxy.example:8080"],
            )

    def test_config_center_masks_and_updates_proxy_pool(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            pool = root / "proxies.txt"
            pool.write_text("1.1.1.1:80:u:p\n", encoding="utf-8")
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "secret-yyds",
                        "turnstile_provider": "capsolver",
                        "turnstile_api_key": "CAP-SECRET",
                        "tui_proxy_mode": "none",
                        "proxy_file": "proxies.txt",
                        "register_count": 1,
                        "concurrent_workers": 1,
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            data = service.get_config_center()
            self.assertTrue(data["secret_flags"]["yyds_api_key"])
            self.assertEqual(data["fields"]["yyds_api_key"], "secret-yyds")
            self.assertEqual(data["fields"]["proxy_mode"], "none")
            self.assertEqual(data["proxy_pool"]["line_count"], 1)

            updated = service.update_config_center(
                {
                    "fields": {
                        "proxy_mode": "pool",
                        "proxy_file": "proxies.txt",
                        "yyds_api_key": "***",  # keep
                        "turnstile_api_key": "CAP-NEW",
                    },
                    "proxy_pool_text": "2.2.2.2:8080:user:pass\n# comment\n",
                }
            )
            self.assertEqual(updated["fields"]["proxy_mode"], "pool")
            self.assertEqual(updated["proxy_pool"]["line_count"], 1)
            disk = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(disk["yyds_api_key"], "secret-yyds")
            self.assertEqual(disk["turnstile_api_key"], "CAP-NEW")
            self.assertEqual(disk["proxy_mode"], "pool")
            self.assertNotIn("tui_proxy_mode", disk)
            self.assertIn("2.2.2.2:8080:user:pass", pool.read_text(encoding="utf-8"))

    def test_legacy_chain_pool_normalizes_to_plain_pool_and_prunes_parent(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            pool = root / "proxies.txt"
            pool.write_text("1.1.1.1:80:u:p\n", encoding="utf-8")
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "capsolver",
                        "turnstile_api_key": "CAP",
                        "register_count": 1,
                        "concurrent_workers": 1,
                        "tui_proxy_mode": "pool",
                        "proxy_file": "proxies.txt",
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            updated = service.update_config_center(
                {
                    "fields": {
                        "proxy_mode": "chain_pool",
                        "proxy_parent": "http://127.0.0.1:7890",
                        "proxy_file": "proxies.txt",
                        "proxy_random": True,
                    }
                }
            )
            self.assertEqual(updated["fields"]["proxy_mode"], "pool")
            plan = svc.build_plan(service.settings)
            self.assertEqual(plan.proxy_mode, "pool")
            self.assertIn("--proxy-file", plan.proxy_args)
            self.assertIn("--proxy-random", plan.proxy_args)
            self.assertNotIn("--proxy-parent", plan.proxy_args)
            disk = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(disk["proxy_mode"], "pool")
            self.assertNotIn("tui_proxy_mode", disk)
            self.assertNotIn("proxy_parent", disk)

    def test_pool_mode_does_not_require_parent(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            pool = root / "proxies.txt"
            pool.write_text("1.1.1.1:80:u:p\n", encoding="utf-8")
            settings = svc.Settings(
                config_path=root / "config.json",
                count=1,
                workers=1,
                output_dir=root,
                proxy_mode="chain_pool",
                config={"proxy_file": str(pool), "proxy_parent": ""},
            )
            mode, args = svc._resolve_proxy_args(settings)
            self.assertEqual(mode, "pool")
            self.assertIn("--proxy-file", args)
            self.assertNotIn("--proxy-parent", args)

    def test_config_center_reads_and_writes_local_turnstile_max_workers(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "local",
                        "register_count": 1,
                        "concurrent_workers": 1,
                        "local_turnstile_max_workers": 4,
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            data = service.get_config_center()
            self.assertEqual(data["fields"]["local_turnstile_max_workers"], 4)

            updated = service.update_config_center(
                {"fields": {"local_turnstile_max_workers": 9}}
            )
            self.assertEqual(updated["fields"]["local_turnstile_max_workers"], 9)
            disk = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(disk["local_turnstile_max_workers"], 9)

    def test_config_center_reads_and_writes_submit_workers(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "local",
                        "register_count": 1,
                        "concurrent_workers": 1,
                        "submit_workers": 6,
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            data = service.get_config_center()
            self.assertEqual(data["fields"]["submit_workers"], 6)

            updated = service.update_config_center({"fields": {"submit_workers": 8}})
            self.assertEqual(updated["fields"]["submit_workers"], 8)
            self.assertEqual(service.settings.submit_workers, 8)
            disk = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(disk["submit_workers"], 8)

    def test_config_center_reads_and_writes_yyds_create_spacing_sec(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "local",
                        "register_count": 1,
                        "concurrent_workers": 1,
                        "yyds_create_spacing_sec": 0.2,
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            data = service.get_config_center()
            self.assertEqual(data["fields"]["yyds_create_spacing_sec"], 0.2)

            updated = service.update_config_center(
                {"fields": {"yyds_create_spacing_sec": 0.05}}
            )
            self.assertEqual(updated["fields"]["yyds_create_spacing_sec"], 0.05)
            disk = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(disk["yyds_create_spacing_sec"], 0.05)

    def test_config_center_rejects_invalid_yyds_create_spacing_sec(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "local",
                        "register_count": 1,
                        "concurrent_workers": 1,
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            with self.assertRaises(svc.TuiConfigError):
                service.update_config_center({"fields": {"yyds_create_spacing_sec": -1}})
            with self.assertRaises(svc.TuiConfigError):
                service.update_config_center({"fields": {"yyds_create_spacing_sec": 999}})
            with self.assertRaises(svc.TuiConfigError):
                service.update_config_center({"fields": {"yyds_create_spacing_sec": "abc"}})

    def test_config_center_rejects_invalid_submit_workers(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "local",
                        "register_count": 1,
                        "concurrent_workers": 1,
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            with self.assertRaises(svc.TuiConfigError):
                service.update_config_center({"fields": {"submit_workers": 0}})
            with self.assertRaises(svc.TuiConfigError):
                service.update_config_center({"fields": {"submit_workers": 99}})
            with self.assertRaises(svc.TuiConfigError):
                service.update_config_center({"fields": {"submit_workers": "abc"}})

    def test_config_center_rejects_invalid_local_turnstile_max_workers(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "local",
                        "register_count": 1,
                        "concurrent_workers": 1,
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            with self.assertRaises(svc.TuiConfigError):
                service.update_config_center({"fields": {"local_turnstile_max_workers": 0}})
            with self.assertRaises(svc.TuiConfigError):
                service.update_config_center({"fields": {"local_turnstile_max_workers": 7000}})
            with self.assertRaises(svc.TuiConfigError):
                service.update_config_center({"fields": {"local_turnstile_max_workers": "abc"}})



    def test_proxy_mode_none_does_not_auto_enable_proxy_file(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            proxy_file = root / "proxies.txt"
            proxy_file.write_text("1.2.3.4:8080:user:pass\n", encoding="utf-8")
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "local",
                        "register_count": 1,
                        "concurrent_workers": 1,
                        "tui_proxy_mode": "none",
                        "proxy_file": "proxies.txt",
                        "proxies": ["1.2.3.4:8080:user:pass"],
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            self.assertEqual(service.settings.proxy_mode, "none")
            self.assertTrue(service.settings.no_proxy)
            plan = svc.build_plan(service.settings)
            self.assertEqual(plan.proxy_mode, "none")
            self.assertEqual(plan.proxy_args, [])
            public = service.public_settings()
            self.assertEqual(public["proxy_mode"], "none")
            self.assertTrue(public["no_proxy"])

class ProxyPoolTestTests(unittest.TestCase):
    def test_proxy_pool_sample_reports(self):
        class FakeResp:
            def __init__(self, code, text):
                self.status_code = code
                self.text = text
            def json(self):
                import json as _json
                return _json.loads(self.text)

        calls = {"n": 0}

        def fake_get(url, proxies=None, timeout=None, impersonate=None):
            calls["n"] += 1
            # first ok, second fail
            if calls["n"] == 1:
                return FakeResp(200, '{"ip":"1.2.3.4"}')
            raise RuntimeError("connect timeout")

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            pool = root / "proxies.txt"
            pool.write_text("\n".join([
                "1.1.1.1:80:u:p",
                "2.2.2.2:80:u:p",
                "3.3.3.3:80:u:p",
            ]) + "\n", encoding="utf-8")
            cfg.write_text(json.dumps({
                "email_provider": "yyds",
                "yyds_api_key": "k",
                "turnstile_provider": "capsolver",
                "turnstile_api_key": "CAP",
                "proxy_file": "proxies.txt",
            }), encoding="utf-8")
            service = svc.BatchService(config_path=cfg, root_dir=root)
            with mock.patch.dict("sys.modules", {}), mock.patch("curl_cffi.requests.get", side_effect=fake_get):
                # force deterministic sample by patching random.sample
                with mock.patch.object(svc.random, "sample", side_effect=lambda population, k: list(population)[:k]):
                    data = service.test_proxy_pool(count=2, timeout=3)
            self.assertEqual(data["tested"], 2)
            self.assertEqual(data["ok"], 1)
            self.assertEqual(data["fail"], 1)
            self.assertEqual(data["results"][0]["exit_ip"], "1.2.3.4")
            self.assertTrue(data["results"][0]["ok"])
            self.assertFalse(data["results"][1]["ok"])

    def test_proxy_pool_sample_ignores_retired_parent_chain(self):
        class FakeResp:
            status_code = 200
            text = '{"ip":"8.8.8.8"}'

            def json(self):
                return {"ip": "8.8.8.8"}

        observed = {}

        def fake_get(url, proxies=None, timeout=None, impersonate=None):
            observed["proxies"] = dict(proxies or {})
            return FakeResp()

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            pool = root / "proxies.txt"
            pool.write_text("1.1.1.1:80:u:p\n", encoding="utf-8")
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "capsolver",
                        "turnstile_api_key": "CAP",
                        "tui_proxy_mode": "chain_pool",
                        "proxy_parent": "http://127.0.0.1:7890",
                        "proxy_file": "proxies.txt",
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            with mock.patch(
                "local_proxy_forwarder.ensure_local_forwarder",
                return_value=("http://127.0.0.1:17890", True),
            ) as ensure, mock.patch(
                "local_proxy_forwarder.stop_local_forwarder"
            ) as stop, mock.patch(
                "curl_cffi.requests.get", side_effect=fake_get
            ), mock.patch.object(
                svc.random, "sample", side_effect=lambda population, k: list(population)[:k]
            ):
                data = service.test_proxy_pool(count=1, timeout=3)

            self.assertFalse(data["chain_enabled"])
            self.assertEqual(data["proxy_mode"], "pool")
            self.assertEqual(data["ok"], 1)
            self.assertEqual(
                observed["proxies"],
                {
                    "http": "http://u:p@1.1.1.1:80",
                    "https": "http://u:p@1.1.1.1:80",
                },
            )
            ensure.assert_not_called()
            stop.assert_not_called()
            self.assertTrue(data["results"][0]["ok"])




class SnapshotMetricsTests(unittest.TestCase):
    def _make_runner(self, count: int = 2) -> svc.BatchRunner:
        plan = svc.RunPlan(
            config_path=Path("config.json"),
            run_mode=svc.RUN_MODE_REGISTER_OTP,
            count=count,
            workers=1,
            output_dir=Path("."),
            provider="capsolver",
            email_provider="yyds",
            proxy_mode="none",
            proxy_args=[],
            turnstile_headless=False,
            sso_convert_retries=5,
            sso_convert_cooldown=3,
            warnings=[],
        )
        return svc.BatchRunner(plan)

    def test_snapshot_metrics_before_start(self):
        runner = self._make_runner()
        snap = runner.snapshot()
        self.assertEqual(snap["elapsed_sec"], 0)
        self.assertIsNone(snap["avg_success_per_min"])
        self.assertIsNone(snap["success_rate"])
        self.assertEqual(snap["started_at"], "")

    def test_stopped_not_counted_as_failed_or_completed(self):
        runner = self._make_runner(count=4)
        runner.started = True
        runner.phase = "running"
        runner.started_at_monotonic = 1000.0
        runner.workers = [svc.WorkerState(i) for i in range(1,5)]
        runner.worker_by_index = {w.index: w for w in runner.workers}
        runner.started_tasks = 4
        runner._mark_terminal(runner.workers[0], "succeeded")
        runner._mark_terminal(runner.workers[1], "failed")
        runner._mark_terminal(runner.workers[2], "stopped")
        runner.workers[3].status = "queued"
        with mock.patch.object(svc.time, "monotonic", return_value=1060.0):
            snap = runner.snapshot()
        self.assertEqual(snap["completed"], 2)
        self.assertEqual(snap["succeeded"], 1)
        self.assertEqual(snap["failed"], 1)
        self.assertEqual(snap["stopped"], 1)
        self.assertAlmostEqual(snap["success_rate"], 0.5)

    def test_classify_email_domain_rejected(self):
        self.assertEqual(
            svc.classify_failure_text(
                "CreateEmailValidationCode gRPC 3: This email domain has been rejected"
            ),
            "email_domain_rejected",
        )


    def test_continuous_mode_no_prealloc_and_target_success(self):
        runner = self._make_runner(count=1)
        runner.plan.target_mode = svc.TARGET_MODE_CONTINUOUS
        runner.plan.target_success = 2
        runner.plan.count = 0
        runner.plan.workers = 2
        # empty workers at init
        self.assertEqual(runner.workers, [])
        runner.started = True
        runner.phase = "running"
        runner.started_at_monotonic = 1000.0
        # simulate two successes via counters/refill logic
        runner.succeeded_count = 2
        self.assertFalse(runner._should_refill())
        runner.tick()
        snap = runner.snapshot()
        self.assertEqual(snap["target_mode"], "continuous")
        self.assertEqual(snap["target_success"], 2)
        self.assertEqual(snap["succeeded"], 2)
        self.assertIn(snap["phase"], {"draining", "done", "running"})

    def test_fixed_mode_spawn_on_demand_limit(self):
        runner = self._make_runner(count=3)
        runner.plan.workers = 2
        # no prealloc
        self.assertEqual(len(runner.workers), 0)
        with mock.patch.object(runner, "_spawn_one", side_effect=lambda w, acquire_proxy=True: (setattr(w, "status", "running") or True)):
            runner.started = True
            runner.phase = "running"
            runner._spawn_available()
            self.assertEqual(runner.started_tasks, 2)
            self.assertEqual(len(runner.workers), 2)
            # finish one and refill to third
            runner.workers[0].status = "succeeded"
            runner.succeeded_count = 1
            # active only second
            runner.workers[0].status = "succeeded"
            # mark first terminal properly
            runner.workers[1].status = "running"
            runner._spawn_available()
            self.assertEqual(runner.started_tasks, 3)



    def test_recent_failure_circuit_pauses_refill(self):
        runner = self._make_runner(count=1)
        runner.plan.target_mode = svc.TARGET_MODE_CONTINUOUS
        runner.plan.target_success = 0
        runner.plan.workers = 4
        runner.started = True
        runner.phase = "running"
        # fill outcome window with mostly failures
        for i in range(svc.CIRCUIT_WINDOW_SIZE):
            w = svc.WorkerState(index=i + 1)
            runner.workers.append(w)
            runner.worker_by_index[w.index] = w
            # 90% fail
            runner._mark_terminal(w, "failed" if i < int(svc.CIRCUIT_WINDOW_SIZE * 0.9) else "succeeded")
        self.assertTrue(runner.refill_paused)
        self.assertTrue(runner.circuit_open)
        self.assertIn("熔断", runner.refill_pause_reason)
        # while paused, no new spawns
        with mock.patch.object(runner, "_spawn_one", side_effect=AssertionError("should not spawn")):
            runner._spawn_available()
        self.assertEqual(runner.started_tasks, 0)
        snap = runner.snapshot()
        self.assertTrue(snap["circuit_open"])
        self.assertGreaterEqual(snap["recent_fail_rate"], svc.CIRCUIT_FAIL_RATE)

    def test_proxy_death_pauses_and_auto_resumes(self):
        runner = self._make_runner(count=1)
        runner.plan.target_mode = svc.TARGET_MODE_CONTINUOUS
        runner.plan.target_success = 0
        runner.plan.workers = 2
        runner.plan.embedded_proxy_enabled = True
        runner.started = True
        runner.phase = "running"

        class Manager:
            def __init__(self):
                self.running = False
                self.healthy = 0
                self.total = 3

            def status(self):
                return {
                    "running": self.running,
                    "healthy": self.healthy,
                    "total": self.total,
                }

            def acquire(self, exclude_ids=None):
                if self.healthy <= 0:
                    return None
                return mock.Mock(id="1", name="n1", local_http="http://127.0.0.1:28001", ref_count=1)

            def release(self, *a, **k):
                return None

        mgr = Manager()
        runner.embedded_proxy_manager = mgr
        # force immediate check
        runner._last_proxy_health_check_at = 0.0
        runner._evaluate_proxy_health(force=True)
        self.assertTrue(runner.refill_paused)
        self.assertTrue(runner._proxy_unhealthy)
        self.assertIn("内嵌代理", runner.refill_pause_reason)

        # recover
        mgr.running = True
        mgr.healthy = 2
        runner._last_proxy_health_check_at = 0.0
        runner._evaluate_proxy_health(force=True)
        self.assertFalse(runner._proxy_unhealthy)
        self.assertFalse(runner.refill_paused)

        # can spawn after resume
        with mock.patch.object(runner, "_spawn_one", side_effect=lambda w, acquire_proxy=True: (setattr(w, "status", "running") or True)):
            runner._spawn_available()
        self.assertEqual(runner.started_tasks, 2)

    def test_continuous_proxy_shortage_does_not_storm_failures(self):
        """Proxy lease misses must pause refill, not inflate failed into thousands."""
        runner = self._make_runner(count=1)
        runner.plan.target_mode = svc.TARGET_MODE_CONTINUOUS
        runner.plan.target_success = 0
        runner.plan.count = 0
        runner.plan.workers = 8
        runner.plan.embedded_proxy_enabled = True
        runner.started = True
        runner.phase = "running"
        runner.started_at_monotonic = 1000.0

        class FakeManager:
            def acquire(self, exclude_ids=None):
                return None

            def release(self, *args, **kwargs):
                return None

        runner.embedded_proxy_manager = FakeManager()

        # Many ticks should still keep counters near zero.
        for _ in range(50):
            runner._spawn_available()

        self.assertEqual(runner.started_tasks, 0)
        self.assertEqual(runner.failed_count, 0)
        self.assertEqual(runner.completed, 0)
        self.assertTrue(runner.refill_paused)
        self.assertLessEqual(len(runner.workers), 1)
        # next tick while paused still no storm
        before_idx = runner.next_index
        runner._spawn_available()
        self.assertEqual(runner.next_index, before_idx)
        self.assertEqual(runner.failed_count, 0)

    def test_started_tasks_only_after_process_launch(self):
        runner = self._make_runner(count=5)
        runner.plan.workers = 3
        runner.started = True
        runner.phase = "running"

        def fake_spawn(worker, acquire_proxy=True):
            # first call fails resource, later succeed
            if runner.started_tasks == 0 and worker.index == 1:
                worker.last_log = "没有可用的内嵌代理节点"
                return False
            worker.status = "running"
            return True

        with mock.patch.object(runner, "_spawn_one", side_effect=fake_spawn):
            runner._spawn_available()
            # first attempt pauses; no started_tasks
            self.assertEqual(runner.started_tasks, 0)
            self.assertTrue(runner.refill_paused)
            # force unpause and continue
            runner._clear_refill_pause()
            runner._spawn_available()
            self.assertEqual(runner.started_tasks, 3)
            self.assertEqual(len(runner.active), 3)

    def test_snapshot_metrics_running(self):
        runner = self._make_runner(count=3)
        runner.started = True
        runner.phase = "running"
        runner.started_at_wall = "2026-07-11T12:00:00"
        runner.started_at_monotonic = 1000.0
        runner.workers = [svc.WorkerState(1), svc.WorkerState(2), svc.WorkerState(3)]
        runner.worker_by_index = {w.index: w for w in runner.workers}
        runner.started_tasks = 3
        runner._mark_terminal(runner.workers[0], "succeeded")
        runner._mark_terminal(runner.workers[1], "failed")
        runner.workers[2].status = "running"
        with mock.patch.object(svc.time, "monotonic", return_value=1120.0):
            snap = runner.snapshot()
        self.assertEqual(snap["elapsed_sec"], 120)
        self.assertEqual(snap["completed"], 2)
        self.assertEqual(snap["succeeded"], 1)
        self.assertAlmostEqual(snap["avg_success_per_min"], 0.5)
        self.assertAlmostEqual(snap["success_rate"], 0.5)
        self.assertEqual(snap["started_at"], "2026-07-11T12:00:00")

    def test_snapshot_metrics_freeze_after_finalize_time(self):
        runner = self._make_runner(count=1)
        runner.started = True
        runner.phase = "done"
        runner.started_at_wall = "2026-07-11T12:00:00"
        runner.started_at_monotonic = 1000.0
        runner.finished_at_monotonic = 1060.0
        runner.workers = [svc.WorkerState(1)]
        runner.worker_by_index = {1: runner.workers[0]}
        runner.started_tasks = 1
        runner._mark_terminal(runner.workers[0], "succeeded")
        with mock.patch.object(svc.time, "monotonic", return_value=9999.0):
            snap1 = runner.snapshot()
            snap2 = runner.snapshot()
        self.assertEqual(snap1["elapsed_sec"], 60)
        self.assertEqual(snap2["elapsed_sec"], 60)
        self.assertAlmostEqual(snap1["avg_success_per_min"], 1.0)
        self.assertAlmostEqual(snap1["success_rate"], 1.0)

    def _run_exiting_child(self, root: Path, output_line: str, return_code: int):
        runner = self._make_runner(count=1)
        runner.run_dir = root
        runner.started = True
        runner.phase = "running"
        runner.started_tasks = 1
        worker = svc.WorkerState(index=1)
        runner.workers = [worker]
        runner.worker_by_index = {1: worker}
        script = (
            "import sys; "
            f"print({output_line!r}, flush=True); "
            f"sys.exit({return_code})"
        )
        with mock.patch.object(
            runner,
            "_command_for",
            return_value=[svc.sys.executable, "-u", "-c", script],
        ):
            self.assertTrue(runner._spawn_one(worker))
        process = worker.process
        self.assertIsNotNone(process)
        self.assertEqual(process.wait(timeout=10), return_code)
        # Deliberately skip _drain_events(): _check_processes must synchronize
        # the stdout reader before it builds the terminal UI state.
        runner._check_processes()
        return runner, worker, runner.snapshot()

    def test_rc2_region_detail_survives_reader_exit_race(self):
        with tempfile.TemporaryDirectory() as d:
            runner, worker, snap = self._run_exiting_child(
                Path(d),
                "[!] 打开注册页 HTTP 403: This service is not available in your region.",
                2,
            )
        self.assertEqual(worker.status, "failed")
        self.assertEqual(worker.return_code, 2)
        self.assertIn("not available in your region", worker.last_log)
        self.assertIn("退出码 2", worker.last_log)
        self.assertEqual(worker.failure_category, "region_blocked")
        self.assertEqual(runner.failure_counts["region_blocked"], 1)
        self.assertEqual(snap["workers"][0]["failure_category"], "region_blocked")
        self.assertIn("HTTP 403", snap["workers"][0]["error_detail"])

    def test_rc3_tls_detail_survives_reader_exit_race(self):
        with tempfile.TemporaryDirectory() as d:
            runner, worker, snap = self._run_exiting_child(
                Path(d),
                "[!] 未处理异常: Failed to perform, curl: (35) TLS connect error: OPENSSL_internal",
                3,
            )
        self.assertEqual(worker.status, "failed")
        self.assertEqual(worker.return_code, 3)
        self.assertIn("curl: (35) TLS connect error", worker.last_log)
        self.assertIn("退出码 3", worker.last_log)
        self.assertEqual(worker.failure_category, "tls_error")
        self.assertEqual(runner.failure_counts["tls_error"], 1)
        self.assertEqual(snap["workers"][0]["failure_category"], "tls_error")
        self.assertIn("OPENSSL_internal", snap["workers"][0]["error_detail"])



class EmbeddedProxyBatchServiceTests(unittest.TestCase):
    def _service(self, root: Path, extra=None):
        cfg = root / "config.json"
        data = {
            "email_provider": "yyds",
            "yyds_api_key": "k",
            "turnstile_provider": "capsolver",
            "turnstile_api_key": "CAP",
            "register_count": 1,
            "concurrent_workers": 1,
            "proxy_subscription_url": "https://example.test/sub",
            "embedded_proxy_enabled": True,
            "embedded_proxy_binary": "/usr/bin/verge-mihomo",
            "embedded_proxy_listen_host": "127.0.0.1",
            "embedded_proxy_base_port": 28000,
            "embedded_proxy_max_nodes": 10,
            "embedded_proxy_probe_host": "accounts.x.ai",
            "embedded_proxy_probe_port": 443,
            "embedded_proxy_probe_timeout_sec": 2,
            "embedded_proxy_max_node_retries": 3,
        }
        if extra:
            data.update(extra)
        cfg.write_text(json.dumps(data), encoding="utf-8")
        return svc.BatchService(config_path=cfg, root_dir=root)

    def test_ensure_embedded_proxy_disabled(self):
        with tempfile.TemporaryDirectory() as d:
            service = self._service(Path(d), {"embedded_proxy_enabled": False})
            out = service.ensure_embedded_proxy()
            self.assertEqual(out.get("enabled"), False)

    def test_ensure_embedded_proxy_loads_vless_and_starts(self):
        with tempfile.TemporaryDirectory() as d:
            service = self._service(Path(d))
            fake_result = mock.Mock()
            fake_result.nodes = [
                mock.Mock(
                    scheme="vless",
                    raw="vless://11111111-1111-1111-1111-111111111111@jp.example:443?security=tls&sni=jp.example#jp",
                    host="jp.example",
                    port=443,
                    name="jp",
                ),
                mock.Mock(
                    scheme="vless",
                    raw="vless://22222222-2222-2222-2222-222222222222@sg.example:443?security=tls&sni=sg.example#sg",
                    host="sg.example",
                    port=443,
                    name="sg",
                ),
                mock.Mock(scheme="http", raw="http://1.1.1.1:80", host="1.1.1.1", port=80, name=""),
            ]

            start_info = {
                "running": True,
                "total": 2,
                "listeners": 2,
                "base_port": 28000,
            }
            probe_info = {"total": 2, "healthy": 1, "results": [{"id": "n0", "healthy": True}]}
            status_info = {
                "running": True,
                "total": 2,
                "healthy": 1,
                "leases": 0,
                "nodes": [],
            }

            manager = mock.Mock()
            manager.start.return_value = start_info
            manager.probe_all.return_value = probe_info
            manager.status.return_value = status_info
            manager._running = False

            with mock.patch(
                "proxy_subscription.import_proxy_subscription",
                return_value=fake_result,
            ) as import_mock, mock.patch(
                "embedded_proxy_manager.EmbeddedProxyManager",
                return_value=manager,
            ) as mgr_cls:
                out = service.ensure_embedded_proxy(force_reload=True)

            import_mock.assert_called_once()
            self.assertTrue(out.get("enabled"))
            self.assertTrue(out.get("running"))
            self.assertEqual(out.get("total"), 2)
            self.assertEqual(out.get("healthy"), 1)
            self.assertEqual(out.get("node_count"), 2)
            manager.start.assert_called_once()
            started_nodes = manager.start.call_args[0][0]
            self.assertEqual(len(started_nodes), 2)
            self.assertEqual(started_nodes[0].protocol, "vless")
            self.assertTrue(started_nodes[0].uuid)
            manager.probe_all.assert_called_once()
            mgr_cls.assert_called()

    def test_ensure_embedded_proxy_raises_when_all_unhealthy(self):
        with tempfile.TemporaryDirectory() as d:
            service = self._service(Path(d))
            fake_result = mock.Mock()
            fake_result.nodes = [
                mock.Mock(
                    scheme="vless",
                    raw="vless://11111111-1111-1111-1111-111111111111@jp.example:443?security=tls#jp",
                    host="jp.example",
                    port=443,
                    name="jp",
                )
            ]
            manager = mock.Mock()
            manager.start.return_value = {"running": True, "total": 1}
            manager.probe_all.return_value = {"total": 1, "healthy": 0, "results": []}
            manager.status.return_value = {"running": True, "total": 1, "healthy": 0}
            manager._running = False
            with mock.patch(
                "proxy_subscription.import_proxy_subscription",
                return_value=fake_result,
            ), mock.patch(
                "embedded_proxy_manager.EmbeddedProxyManager",
                return_value=manager,
            ):
                with self.assertRaises(svc.TuiConfigError) as ctx:
                    service.ensure_embedded_proxy(force_reload=True)
            self.assertIn("预检", str(ctx.exception))

    def test_get_and_probe_embedded_proxy_status(self):
        with tempfile.TemporaryDirectory() as d:
            service = self._service(Path(d), {"embedded_proxy_enabled": False})
            st = service.get_embedded_proxy_status()
            self.assertEqual(st.get("enabled"), False)

            service = self._service(Path(d), {"embedded_proxy_enabled": True})
            manager = mock.Mock()
            manager.status.return_value = {
                "running": True,
                "total": 1,
                "healthy": 1,
                "leases": 0,
                "nodes": [],
            }
            manager.probe_all.return_value = {"total": 1, "healthy": 1, "results": []}
            service._embedded_proxy_manager = manager
            st = service.get_embedded_proxy_status()
            self.assertTrue(st.get("enabled"))
            self.assertTrue(st.get("running"))
            pr = service.probe_embedded_proxy()
            self.assertEqual(pr.get("healthy"), 1)
            manager.probe_all.assert_called_once()

    def test_config_center_persists_turnstile_proxy_fields_and_pool(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "local",
                        "register_count": 1,
                        "concurrent_workers": 1,
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            updated = service.update_config_center(
                {
                    "fields": {
                        "turnstile_proxy_enabled": True,
                        "turnstile_proxy_mode": "pool",
                        "turnstile_proxy": "http://user:pass@9.9.9.9:9999",
                        "turnstile_proxy_file": "turnstile_proxies.txt",
                        "turnstile_proxy_random": True,
                    },
                    "turnstile_proxy_pool_text": "http://a:b@1.1.1.1:1000\nhttp://c:d@2.2.2.2:1000\n",
                }
            )
            fields = updated["fields"]
            self.assertTrue(fields["turnstile_proxy_enabled"])
            self.assertEqual(fields["turnstile_proxy_mode"], "pool")
            self.assertEqual(fields["turnstile_proxy"], "http://user:pass@9.9.9.9:9999")
            self.assertEqual(fields["turnstile_proxy_file"], "turnstile_proxies.txt")
            self.assertTrue(fields["turnstile_proxy_random"])
            self.assertEqual(updated["turnstile_proxy_pool"]["line_count"], 2)
            disk = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertTrue(disk["turnstile_proxy_enabled"])
            self.assertEqual(disk["turnstile_proxy_mode"], "pool")
            self.assertEqual(disk["turnstile_proxy"], "http://user:pass@9.9.9.9:9999")
            self.assertEqual(disk["turnstile_proxy_file"], "turnstile_proxies.txt")
            pool_path = root / "turnstile_proxies.txt"
            self.assertTrue(pool_path.is_file())
            self.assertIn("http://a:b@1.1.1.1:1000", pool_path.read_text(encoding="utf-8"))
            # reload path also sees the same values
            reloaded = service.get_config_center()
            self.assertTrue(reloaded["fields"]["turnstile_proxy_enabled"])
            self.assertEqual(reloaded["turnstile_proxy_pool"]["line_count"], 2)
            # pick_turnstile_proxy should honor the dedicated pool relative to config dir
            picked = svc.pick_turnstile_proxy(disk, base_dir=root)
            self.assertIn(picked, {
                "http://a:b@1.1.1.1:1000",
                "http://c:d@2.2.2.2:1000",
            })

    def test_config_center_reads_and_writes_embedded_proxy_fields(self):

        with tempfile.TemporaryDirectory() as d:
            service = self._service(Path(d))
            data = service.get_config_center()
            fields = data["fields"]
            self.assertTrue(fields["embedded_proxy_enabled"])
            self.assertEqual(fields["embedded_proxy_binary"], "/usr/bin/verge-mihomo")
            self.assertEqual(fields["embedded_proxy_base_port"], 28000)
            self.assertEqual(fields["embedded_proxy_max_nodes"], 10)
            updated = service.update_config_center(
                {
                    "fields": {
                        "embedded_proxy_enabled": False,
                        "embedded_proxy_base_port": 29000,
                        "embedded_proxy_max_nodes": 5,
                        "embedded_proxy_probe_timeout_sec": 8,
                        "embedded_proxy_listen_host": "127.0.0.1",
                    }
                }
            )
            uf = updated["fields"]
            self.assertFalse(uf["embedded_proxy_enabled"])
            self.assertEqual(uf["embedded_proxy_base_port"], 29000)
            self.assertEqual(uf["embedded_proxy_max_nodes"], 5)
            self.assertEqual(uf["embedded_proxy_probe_timeout_sec"], 8)
            disk = json.loads((Path(d) / "config.json").read_text(encoding="utf-8"))
            self.assertFalse(disk["embedded_proxy_enabled"])
            self.assertEqual(disk["embedded_proxy_base_port"], 29000)




class EmbeddedProxyAssignmentTests(unittest.TestCase):
    """Task 5: per-worker embedded mihomo proxy assignment."""

    def _make_plan(self, *, embedded=True, proxy_args=None, max_retries=3, count=1):
        return svc.RunPlan(
            config_path=Path("config.json"),
            run_mode=svc.RUN_MODE_REGISTER_OTP,
            count=count,
            workers=1,
            output_dir=Path("."),
            provider="capsolver",
            email_provider="yyds",
            proxy_mode="pool",
            proxy_args=proxy_args or ["--proxy-file", "proxies.txt", "--proxy-random"],
            turnstile_headless=False,
            sso_convert_retries=5,
            sso_convert_cooldown=3,
            warnings=[],
            embedded_proxy_enabled=embedded,
            embedded_proxy_max_node_retries=max_retries,
        )

    def _node(self, node_id: str, name: str, port: int):
        from embedded_proxy_manager import NodeSlot

        return NodeSlot(
            id=node_id,
            name=name,
            server=f"{name}.example",
            port=443,
            protocol="vless",
            local_http=f"http://127.0.0.1:{port}",
            healthy=True,
            ref_count=1,
        )

    def test_command_for_uses_acquired_embedded_proxy(self):
        plan = self._make_plan(embedded=True)
        runner = svc.BatchRunner(plan)
        manager = mock.Mock()
        manager.acquire.return_value = self._node("12", "jp", 28005)
        runner.embedded_proxy_manager = manager

        worker = svc.WorkerState(index=1)
        runner.workers = [worker]
        runner.worker_by_index = {1: worker}
        worker.accounts_path = Path("accounts_001.txt")
        assigned = runner._acquire_embedded_proxy(worker)
        self.assertTrue(assigned)
        command = runner._command_for(worker)

        self.assertIn("--proxy", command)
        self.assertIn("http://127.0.0.1:28005", command)
        self.assertNotIn("--proxy-file", command)
        manager.acquire.assert_called()
        call_kwargs = manager.acquire.call_args.kwargs if manager.acquire.call_args else {}
        # exclude tried ids (empty first time)
        if "exclude_ids" in call_kwargs:
            self.assertEqual(set(call_kwargs["exclude_ids"] or set()), set())

    def test_command_for_keeps_proxy_args_when_embedded_disabled(self):
        plan = self._make_plan(embedded=False, proxy_args=["--proxy-file", "proxies.txt"])
        runner = svc.BatchRunner(plan)
        worker = svc.WorkerState(index=1)
        runner.workers = [worker]
        runner.worker_by_index = {1: worker}
        worker.accounts_path = Path("accounts_001.txt")
        command = runner._command_for(worker)
        self.assertIn("--proxy-file", command)
        self.assertIn("proxies.txt", command)

    def test_looks_like_proxy_failure_heuristics(self):
        self.assertTrue(svc._looks_like_proxy_failure("CONNECT tunnel failed: 403"))
        self.assertTrue(svc._looks_like_proxy_failure("ProxyError: refused"))
        self.assertTrue(svc._looks_like_proxy_failure("Connection refused by peer"))
        self.assertTrue(svc._looks_like_proxy_failure("curl: (56) Failure"))
        self.assertTrue(svc._looks_like_proxy_failure("curl: (7) Failed to connect"))
        # Bad egress often surfaces as Turnstile timeout under embedded proxy mode.
        self.assertTrue(svc._looks_like_proxy_failure("turnstile timeout"))
        self.assertTrue(svc._looks_like_proxy_failure("curl: (35) TLS connect error"))
        self.assertFalse(svc._looks_like_proxy_failure(""))

    def test_worker_proxy_failure_retries_up_to_three_nodes(self):
        plan = self._make_plan(embedded=True, max_retries=3, count=1)
        runner = svc.BatchRunner(plan)
        manager = mock.Mock()
        nodes = [
            self._node("n1", "jp", 28001),
            self._node("n2", "sg", 28002),
            self._node("n3", "us", 28003),
        ]
        manager.acquire.side_effect = list(nodes)
        runner.embedded_proxy_manager = manager

        worker = svc.WorkerState(index=1)
        runner.workers = [worker]
        runner.worker_by_index = {1: worker}
        worker.accounts_path = Path("accounts_001.txt")
        worker.log_path = Path("worker_001.log")

        def fake_spawn(w, *, acquire_proxy=True):
            # Keep the leased node sticky and mark running without real Popen.
            if acquire_proxy and runner.plan.embedded_proxy_enabled and not w.proxy_node_id:
                assert runner._acquire_embedded_proxy(w)
            w.status = "running"
            w.process = mock.Mock()
            w.process.poll.return_value = None
            return True

        # Attempt 1
        self.assertTrue(runner._acquire_embedded_proxy(worker))
        self.assertEqual(worker.proxy_node_id, "n1")
        worker.status = "running"
        worker.process = mock.Mock()
        worker.process.poll.return_value = 1
        worker.last_log = "CONNECT tunnel failed"
        with mock.patch.object(Path, "is_file", return_value=True), mock.patch.object(
            Path, "read_text", return_value="CONNECT tunnel failed\n"
        ), mock.patch.object(runner, "_spawn_one", side_effect=fake_spawn):
            runner._check_processes()

        self.assertEqual(manager.release.call_count, 1)
        rel_kwargs = manager.release.call_args.kwargs
        self.assertTrue(rel_kwargs.get("failed"))
        self.assertIn("n1", worker.tried_node_ids)
        self.assertEqual(manager.acquire.call_count, 2)
        self.assertEqual(worker.proxy_node_id, "n2")
        self.assertEqual(worker.status, "running")

        # Attempt 2
        worker.process = mock.Mock()
        worker.process.poll.return_value = 1
        worker.last_log = "ProxyError boom"
        with mock.patch.object(Path, "is_file", return_value=True), mock.patch.object(
            Path, "read_text", return_value="ProxyError\n"
        ), mock.patch.object(runner, "_spawn_one", side_effect=fake_spawn):
            runner._check_processes()
        self.assertEqual(manager.release.call_count, 2)
        self.assertEqual(manager.acquire.call_count, 3)
        self.assertEqual(worker.proxy_node_id, "n3")
        self.assertEqual(worker.status, "running")

        # Attempt 3 exhausts retries (tried=3 after release) -> final failed
        worker.process = mock.Mock()
        worker.process.poll.return_value = 1
        worker.last_log = "curl: (56) recv failure"
        with mock.patch.object(Path, "is_file", return_value=True), mock.patch.object(
            Path, "read_text", return_value="curl: (56)\n"
        ), mock.patch.object(runner, "_spawn_one", side_effect=fake_spawn) as spawn_mock:
            runner._check_processes()
        self.assertEqual(manager.release.call_count, 3)
        self.assertEqual(worker.status, "failed")
        self.assertEqual(manager.acquire.call_count, 3)
        spawn_mock.assert_not_called()

    def test_release_embedded_proxy_on_success(self):
        plan = self._make_plan(embedded=True)
        runner = svc.BatchRunner(plan)
        manager = mock.Mock()
        manager.acquire.return_value = self._node("n1", "jp", 28001)
        runner.embedded_proxy_manager = manager
        worker = svc.WorkerState(index=1)
        runner.workers = [worker]
        runner.worker_by_index = {1: worker}
        worker.accounts_path = Path("a.txt")
        self.assertTrue(runner._acquire_embedded_proxy(worker))
        worker.status = "running"
        worker.process = mock.Mock()
        worker.process.poll.return_value = 0
        runner._check_processes()
        manager.release.assert_called_with("n1", failed=False)
        self.assertEqual(worker.status, "succeeded")

    def test_start_run_ensures_embedded_proxy(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "capsolver",
                        "turnstile_api_key": "CAP",
                        "register_count": 1,
                        "concurrent_workers": 1,
                        "embedded_proxy_enabled": True,
                        "proxy_subscription_url": "https://example.test/sub",
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            ensure = mock.Mock(return_value={"enabled": True, "running": True, "healthy": 1})
            service.ensure_embedded_proxy = ensure
            manager = mock.Mock()
            manager.acquire.return_value = self._node("n9", "hk", 28009)
            service._embedded_proxy_manager = manager

            with mock.patch.object(svc.BatchRunner, "start", lambda self: setattr(self, "started", True) or setattr(self, "done", False)), \
                 mock.patch.object(svc.BatchRunner, "snapshot", return_value={"run_id": "x"}):
                service.start_run()
            ensure.assert_called()
            self.assertIs(service._runner.embedded_proxy_manager, manager)

class StaticProxySlotTests(unittest.TestCase):
    def _plan(self, root: Path, *, sticky: bool = True, pool_size: int = 5):
        cfg = root / "config.json"
        if not cfg.exists():
            cfg.write_text("{}\n", encoding="utf-8")
        return svc.RunPlan(
            config_path=cfg,
            run_mode=svc.RUN_MODE_REGISTER_OTP,
            count=10,
            workers=5,
            output_dir=root / "creds",
            provider="capsolver",
            email_provider="yyds",
            proxy_mode="pool",
            proxy_args=[
                "--proxy-file",
                str(root / "proxies.txt"),
                "--proxy-random",
                "--proxy-parent",
                "http://127.0.0.1:7890",
            ],
            proxy_slot_sticky=sticky,
            proxy_pool_size=pool_size,
        )

    def test_auto_by_proxy_sizes_local_broker_and_account_slots(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            pool = root / "proxies.txt"
            pool.write_text(
                "# five exits\n" + "\n".join(f"127.0.0.1:{9000 + i}" for i in range(5)) + "\n",
                encoding="utf-8",
            )
            cfg = root / "config.json"
            data = {
                "email_provider": "yyds",
                "turnstile_provider": "local",
                "turnstile_headless": True,
                "local_turnstile_max_workers": 8,
                "register_count": 20,
                "concurrent_workers": 9,
                "proxy_mode": "pool",
                "proxy_file": "proxies.txt",
                "proxy_random": True,
                "solver_slots": "auto_by_proxy",
                "proxy_slot_sticky": True,
            }
            cfg.write_text(json.dumps(data), encoding="utf-8")
            settings = svc.Settings(
                config_path=cfg,
                count=20,
                workers=9,
                output_dir=root / "creds",
                proxy_mode="pool",
                turnstile_provider="local",
                turnstile_headless=True,
                config=data,
            )
            plan = svc.build_plan(settings)
            self.assertEqual(plan.proxy_pool_size, 5)
            self.assertTrue(plan.proxy_slot_sticky)
            self.assertEqual(plan.workers, 5)
            self.assertEqual(plan.turnstile_workers, 5)

    def test_five_workers_get_five_unique_fixed_indexes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner = svc.BatchRunner(self._plan(root))
            commands = []
            workers = []
            for index in range(1, 6):
                worker = svc.WorkerState(index=index, accounts_path=root / f"a{index}.txt")
                workers.append(worker)
                self.assertTrue(runner._acquire_static_proxy_slot(worker))
                commands.append(runner._command_for(worker))
            self.assertEqual(set(runner._proxy_slot_leases), {0, 1, 2, 3, 4})
            for expected, command in enumerate(commands):
                self.assertNotIn("--proxy-random", command)
                self.assertEqual(command[command.index("--proxy-index") + 1], str(expected))
                self.assertIn("--proxy-parent", command)

    def test_released_slot_is_reused_without_collision(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner = svc.BatchRunner(self._plan(root))
            workers = [svc.WorkerState(index=index) for index in range(1, 6)]
            for worker in workers:
                self.assertTrue(runner._acquire_static_proxy_slot(worker))
            runner._release_static_proxy_slot(workers[1])
            replacement = svc.WorkerState(index=6)
            self.assertTrue(runner._acquire_static_proxy_slot(replacement))
            # Worker 6 would prefer index 0 by modulo, but index 0 is still
            # leased. It takes the newly free index 1 instead.
            self.assertEqual(replacement.proxy_slot_index, 1)
            self.assertEqual(len(runner._proxy_slot_leases), 5)
            self.assertEqual(len(set(runner._proxy_slot_leases)), 5)

    def test_run_snapshot_keeps_indexes_stable_when_source_pool_changes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root / "proxies.txt"
            original = [f"127.0.0.1:{9000 + index}" for index in range(5)]
            source.write_text("\n".join(original) + "\n", encoding="utf-8")
            plan = self._plan(root)
            plan.proxy_pool_entries = tuple(original)
            runner = svc.BatchRunner(plan)
            runner.run_dir = root / "run"
            runner.run_dir.mkdir()
            runner._prepare_static_proxy_snapshot()

            # A live edit no longer changes what numeric slots 0..4 address.
            source.write_text("\n".join(original[:4]) + "\n", encoding="utf-8")
            commands = []
            for index in range(1, 6):
                worker = svc.WorkerState(
                    index=index,
                    accounts_path=root / f"a{index}.txt",
                )
                commands.append(runner._command_for(worker))

            snapshot = runner._proxy_pool_snapshot_path
            self.assertIsNotNone(snapshot)
            self.assertEqual(snapshot.read_text(encoding="utf-8").splitlines(), original)
            self.assertEqual(
                {
                    command[command.index("--proxy-file") + 1]
                    for command in commands
                },
                {str(snapshot)},
            )
            self.assertEqual(
                [command[command.index("--proxy-index") + 1] for command in commands],
                ["0", "1", "2", "3", "4"],
            )
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o600)

    def test_target_aware_gate_only_leases_slots_2_3_4(self):
        """Region/TLS exits are isolated while both targets are still probed."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            entries = tuple(f"127.0.0.1:{9000 + index}" for index in range(5))
            (root / "proxies.txt").write_text(
                "\n".join(entries) + "\n",
                encoding="utf-8",
            )
            plan = self._plan(root)
            plan.proxy_pool_entries = entries
            runner = svc.BatchRunner(plan)
            runner.run_dir = root / "run"
            runner.run_dir.mkdir()
            runner._prepare_static_proxy_snapshot()

            entry_indexes = {entry: index for index, entry in enumerate(entries)}
            forwarder_calls = []
            target_calls = []

            def fake_forwarder(raw, **kwargs):
                index = entry_indexes[raw]
                forwarder_calls.append((index, dict(kwargs)))
                return f"http://127.0.0.1:{19000 + index}", True

            def fake_request(proxy_url, target):
                index = int(proxy_url.rsplit(":", 1)[1]) - 19000
                target_calls.append((index, target))
                if index == 0 and target == "signup":
                    return 403, '{"error":"unsupported_region"}'
                if index == 4 and target == "signup":
                    raise RuntimeError("curl: (35) TLS connect error: unexpected eof")
                return (200, "signup") if target == "signup" else (400, "invalid_grant")

            with mock.patch(
                "local_proxy_forwarder.ensure_local_forwarder",
                side_effect=fake_forwarder,
            ), mock.patch(
                "local_proxy_forwarder.stop_local_forwarder"
            ) as stop_forwarder, mock.patch.object(
                runner,
                "_perform_static_proxy_health_request",
                side_effect=fake_request,
            ):
                runner._probe_static_proxy_slots()

            self.assertEqual(runner._healthy_static_proxy_slots, {1, 2, 3})
            self.assertEqual(
                runner._static_proxy_health[0]["reason"],
                "signup_region_403",
            )
            self.assertEqual(
                runner._static_proxy_health[4]["reason"],
                "curl_tls_error",
            )
            # All five frozen slots and both target origins are checked even
            # when one target on a slot has already failed.
            self.assertEqual({item[0] for item in forwarder_calls}, set(range(5)))
            self.assertEqual(len(target_calls), 12)
            self.assertEqual(
                set(target_calls),
                {(index, target) for index in range(5) for target in ("signup", "ms_token")},
            )
            self.assertEqual(target_calls.count((4, "signup")), 3)
            self.assertEqual(stop_forwarder.call_count, 5)
            for _, kwargs in forwarder_calls:
                self.assertEqual(
                    kwargs["parent_proxy_raw"],
                    "",
                )

            leased = []
            workers = [svc.WorkerState(index=index) for index in range(1, 6)]
            for worker in workers:
                if runner._acquire_static_proxy_slot(worker):
                    leased.append(worker.proxy_slot_index)
            self.assertEqual(set(leased), {1, 2, 3})
            self.assertEqual(len(leased), 3)

            for worker in workers:
                runner._release_static_proxy_slot(worker)
            runner.workers = []
            runner.worker_by_index = {}
            runner.started = True
            runner.phase = "running"

            def fake_spawn(worker, acquire_proxy=True):
                if not runner._acquire_static_proxy_slot(worker):
                    return False
                worker.status = "running"
                return True

            with mock.patch.object(runner, "_spawn_one", side_effect=fake_spawn):
                runner._spawn_available()
            self.assertEqual(runner.started_tasks, 3)
            self.assertEqual(len(runner.active), 3)
            self.assertEqual(
                {worker.proxy_slot_index for worker in runner.active},
                {1, 2, 3},
            )

    def test_target_gate_retries_one_transient_tls_reset(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner = svc.BatchRunner(self._plan(root, pool_size=1))
            calls = []

            def fake_request(_proxy_url, target):
                calls.append(target)
                if target == "signup" and calls.count("signup") == 1:
                    raise RuntimeError("curl: (35) TLS connect error")
                return (200, "signup") if target == "signup" else (400, "invalid_grant")

            with mock.patch(
                "local_proxy_forwarder.ensure_local_forwarder",
                return_value=("http://127.0.0.1:19000", True),
            ), mock.patch(
                "local_proxy_forwarder.stop_local_forwarder"
            ), mock.patch.object(
                runner,
                "_perform_static_proxy_health_request",
                side_effect=fake_request,
            ), mock.patch.object(svc.time, "sleep"):
                result = runner._probe_static_proxy_slot(
                    0,
                    "127.0.0.1:9000",
                    "http://127.0.0.1:7890",
                )

            self.assertTrue(result["ok"])
            self.assertEqual(result["targets"]["signup"]["attempts"], 2)
            self.assertEqual(calls, ["signup", "signup", "ms_token"])

    def test_start_runs_snapshot_then_gate_then_spawn(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner = svc.BatchRunner(self._plan(root))
            runner.run_dir = root / "run"
            order = []

            with mock.patch.object(
                runner,
                "_prepare_static_proxy_snapshot",
                side_effect=lambda: order.append("snapshot"),
            ), mock.patch.object(
                runner,
                "_probe_static_proxy_slots",
                side_effect=lambda: order.append("gate"),
            ), mock.patch.object(
                runner,
                "_spawn_available",
                side_effect=lambda: order.append("spawn"),
            ), mock.patch.object(svc, "RUNS_DIR", root / "runs"):
                runner.start()

            self.assertEqual(order, ["snapshot", "gate", "spawn"])

    def test_runtime_isolation_removes_slot_once_and_releases_lease(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner = svc.BatchRunner(self._plan(root))
            runner._healthy_static_proxy_slots = {0, 1, 2, 3, 4}
            worker = svc.WorkerState(index=5, proxy_slot_index=4, status="running")
            runner._proxy_slot_leases[4] = worker.index

            self.assertTrue(
                runner._isolate_static_proxy_slot(worker, "curl_tls_error")
            )
            self.assertEqual(runner._healthy_static_proxy_slots, {0, 1, 2, 3})
            self.assertNotIn(4, runner._proxy_slot_leases)
            self.assertIsNone(worker.proxy_slot_index)

            duplicate = svc.WorkerState(index=6, proxy_slot_index=4, status="running")
            self.assertFalse(
                runner._isolate_static_proxy_slot(duplicate, "curl_tls_error")
            )
            self.assertEqual(
                sum("槽位 #5 运行期隔离" in line for line in runner.logs),
                1,
            )

    def test_runtime_region_diagnostic_is_requeued_without_business_failure(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner = svc.BatchRunner(self._plan(root, pool_size=2))
            runner._healthy_static_proxy_slots = {0, 1}
            runner.started = True
            runner.phase = "running"
            runner.started_tasks = 1
            runner.next_index = 6
            worker = svc.WorkerState(
                index=5,
                status="running",
                proxy_slot_index=0,
                log_path=root / "worker_005.log",
            )
            worker.log_path.write_text(
                "[!] 打开注册页 HTTP 403: This service is not available in your region.\n",
                encoding="utf-8",
            )
            worker.process = mock.Mock()
            worker.process.poll.return_value = 2
            runner.workers = [worker]
            runner.worker_by_index = {worker.index: worker}
            runner._proxy_slot_leases[0] = worker.index

            runner._check_processes()

            self.assertEqual(worker.status, "stopped")
            self.assertEqual(worker.failure_category, "region_blocked")
            self.assertIn("退出码 2", worker.last_log)
            self.assertEqual(runner.failed, 0)
            self.assertEqual(sum(runner.failure_counts.values()), 0)
            self.assertEqual(runner.started_tasks, 0)
            self.assertEqual(runner._healthy_static_proxy_slots, {1})

            def fake_spawn(replacement, acquire_proxy=True):
                self.assertTrue(runner._acquire_static_proxy_slot(replacement))
                replacement.status = "running"
                return True

            with mock.patch.object(runner, "_spawn_one", side_effect=fake_spawn):
                runner._spawn_available()
            replacement = next(item for item in runner.active if item.index == 6)
            self.assertEqual(replacement.proxy_slot_index, 1)
            self.assertEqual(runner.started_tasks, 1)

    def test_runtime_curl35_diagnostic_is_requeued_without_business_failure(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner = svc.BatchRunner(self._plan(root))
            runner._healthy_static_proxy_slots = {0, 1, 2, 3, 4}
            runner.started = True
            runner.phase = "running"
            runner.started_tasks = 1
            worker = svc.WorkerState(
                index=1,
                status="running",
                proxy_slot_index=0,
                error_detail="curl: (35) TLS connect error: unexpected eof",
            )
            worker.process = mock.Mock()
            worker.process.poll.return_value = 3
            runner.workers = [worker]
            runner.worker_by_index = {worker.index: worker}
            runner._proxy_slot_leases[0] = worker.index

            runner._check_processes()

            self.assertEqual(worker.status, "stopped")
            self.assertEqual(worker.failure_category, "tls_error")
            self.assertEqual(runner.failed, 0)
            self.assertEqual(runner.failure_counts["tls_error"], 0)
            self.assertEqual(runner.started_tasks, 0)
            self.assertEqual(runner._healthy_static_proxy_slots, {1, 2, 3, 4})
            self.assertIn("任务将重排", worker.last_log)

            replacement = svc.WorkerState(index=2)
            self.assertTrue(runner._acquire_static_proxy_slot(replacement))
            self.assertIn(replacement.proxy_slot_index, {1, 2, 3, 4})

    def test_runtime_turnstile_600010_isolates_shared_static_route(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner = svc.BatchRunner(self._plan(root, pool_size=2))
            runner._healthy_static_proxy_slots = {0, 1}
            runner.started = True
            runner.phase = "running"
            runner.started_tasks = 1
            worker = svc.WorkerState(
                index=1,
                status="running",
                proxy_slot_index=0,
                error_detail=(
                    "Turnstile broker 求解失败: Turnstile challenge error 600010 | "
                    "category=turnstile_challenge_transient code=600010 "
                    "attempts=2/2 retries=1"
                ),
            )
            worker.process = mock.Mock()
            worker.process.poll.return_value = 2
            runner.workers = [worker]
            runner.worker_by_index = {worker.index: worker}
            runner._proxy_slot_leases[0] = worker.index

            runner._check_processes()

            self.assertEqual(worker.status, "stopped")
            self.assertEqual(
                worker.failure_category,
                "turnstile_challenge_transient",
            )
            self.assertEqual(runner.failed, 0)
            self.assertEqual(runner.started_tasks, 0)
            self.assertEqual(runner._healthy_static_proxy_slots, {1})
            self.assertIn("任务将重排", worker.last_log)

    def test_runtime_turnstile_600010_keeps_registration_route_for_independent_solver(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner = svc.BatchRunner(self._plan(root, pool_size=2))
            runner._healthy_static_proxy_slots = {0, 1}
            worker = svc.WorkerState(
                index=1,
                status="running",
                proxy_slot_index=0,
                uses_independent_turnstile_proxy=True,
                error_detail=(
                    "Turnstile challenge error 600010 | "
                    "category=turnstile_challenge_transient"
                ),
            )
            worker.process = mock.Mock()
            worker.process.poll.return_value = 2
            runner.workers = [worker]
            runner.worker_by_index = {worker.index: worker}
            runner._proxy_slot_leases[0] = worker.index

            runner._check_processes()

            self.assertEqual(worker.status, "failed")
            self.assertEqual(runner.failed, 1)
            self.assertEqual(runner._healthy_static_proxy_slots, {0, 1})

    def test_embedded_proxy_does_not_inherit_static_pool_worker_cap(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            pool = root / "proxies.txt"
            pool.write_text(
                "\n".join(f"127.0.0.1:{9000 + i}" for i in range(5)) + "\n",
                encoding="utf-8",
            )
            cfg = root / "config.json"
            data = {
                "email_provider": "yyds",
                "turnstile_provider": "local",
                "local_turnstile_max_workers": 8,
                "register_count": 20,
                "concurrent_workers": 9,
                "proxy_mode": "pool",
                "proxy_file": "proxies.txt",
                "solver_slots": "auto_by_proxy",
                "proxy_slot_sticky": True,
                "embedded_proxy_enabled": True,
            }
            cfg.write_text(json.dumps(data), encoding="utf-8")
            settings = svc.Settings(
                config_path=cfg,
                count=20,
                workers=9,
                output_dir=root / "creds",
                proxy_mode="pool",
                turnstile_provider="local",
                config=data,
            )
            plan = svc.build_plan(settings)
            self.assertEqual(plan.workers, 9)
            self.assertFalse(plan.proxy_slot_sticky)
            self.assertEqual(plan.turnstile_workers, 8)

    def test_opt_out_keeps_legacy_random_pool_arguments(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner = svc.BatchRunner(self._plan(root, sticky=False))
            worker = svc.WorkerState(index=1, accounts_path=root / "a.txt")
            command = runner._command_for(worker)
            self.assertIn("--proxy-random", command)
            self.assertNotIn("--proxy-index", command)


if __name__ == "__main__":
    unittest.main()

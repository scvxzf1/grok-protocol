import json
import os
import stat
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import http_batch_service as svc


class HttpBatchServiceSmokeTests(unittest.TestCase):
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
        self.assertEqual(svc.resolve_local_turnstile_max_workers({}), 3)
        self.assertEqual(
            svc.resolve_local_turnstile_max_workers({"local_turnstile_max_workers": 12}),
            12,
        )
        self.assertEqual(
            svc.resolve_local_turnstile_max_workers({"local_turnstile_max_workers": 0}),
            3,
        )
        self.assertEqual(
            svc.resolve_local_turnstile_max_workers({"local_turnstile_max_workers": 7000}),
            3,
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
            self.assertEqual(disk["tui_proxy_mode"], "pool")
            self.assertIn("2.2.2.2:8080:user:pass", pool.read_text(encoding="utf-8"))

    def test_config_center_defaults_proxy_pool_source_manual(self):
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
            data = service.get_config_center()
            self.assertEqual(data["fields"]["proxy_pool_source"], "manual")

    def test_config_center_persists_proxy_pool_source(self):
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
                        "proxy_pool_source": "manual",
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            updated = service.update_config_center(
                {"fields": {"proxy_pool_source": "subscription"}}
            )
            self.assertEqual(updated["fields"]["proxy_pool_source"], "subscription")
            disk = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(disk["proxy_pool_source"], "subscription")

            # switch back
            updated = service.update_config_center(
                {"fields": {"proxy_pool_source": "manual"}}
            )
            self.assertEqual(updated["fields"]["proxy_pool_source"], "manual")
            disk = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(disk["proxy_pool_source"], "manual")

    def test_set_proxy_pool_rejects_when_source_is_subscription(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            pool = root / "proxies.txt"
            pool.write_text("1.1.1.1:80\n", encoding="utf-8")
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "local",
                        "register_count": 1,
                        "concurrent_workers": 1,
                        "proxy_file": "proxies.txt",
                        "proxy_pool_source": "subscription",
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            with self.assertRaises(svc.TuiConfigError) as ctx:
                service.set_proxy_pool("9.9.9.9:8080\n")
            self.assertIn("手动维护", str(ctx.exception))
            self.assertEqual(pool.read_text(encoding="utf-8").strip(), "1.1.1.1:80")

    def test_update_config_center_ignores_pool_text_when_subscription_source(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            pool = root / "proxies.txt"
            pool.write_text("keep-me:1\n", encoding="utf-8")
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "local",
                        "register_count": 1,
                        "concurrent_workers": 1,
                        "proxy_file": "proxies.txt",
                        "proxy_pool_source": "subscription",
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            service.update_config_center(
                {
                    "fields": {"proxy_pool_source": "subscription"},
                    "proxy_pool_text": "overwrite:999\n",
                }
            )
            self.assertEqual(pool.read_text(encoding="utf-8").strip(), "keep-me:1")

    def test_import_subscription_rejects_when_source_is_manual(self):
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
                        "proxy_pool_source": "manual",
                        "proxy_subscription_url": "https://example.test/sub",
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            with self.assertRaises(svc.TuiConfigError) as ctx:
                service.import_proxy_subscription(url="https://example.test/sub")
            self.assertIn("订阅导入", str(ctx.exception))

    def test_import_subscription_writes_pool_when_source_is_subscription(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            pool = root / "proxies.txt"
            pool.write_text("old:1\n", encoding="utf-8")
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "local",
                        "register_count": 1,
                        "concurrent_workers": 1,
                        "proxy_file": "proxies.txt",
                        "proxy_pool_source": "subscription",
                        "proxy_subscription_url": "https://example.test/sub",
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)

            class FakeResult:
                usable_pool_lines = ["http://u:p@2.2.2.2:8080"]
                pool_lines = ["# hdr", "http://u:p@2.2.2.2:8080"]
                def to_dict(self):
                    return {
                        "url": "https://example.test/sub",
                        "body_kind": "plain",
                        "node_count": 1,
                        "usable_http_count": 1,
                        "skipped_count": 0,
                        "scheme_counts": {"http": 1},
                        "warnings": [],
                        "sample_nodes": [],
                    }

            with mock.patch(
                "proxy_subscription.import_proxy_subscriptions",
                return_value=FakeResult(),
            ):
                out = service.import_proxy_subscription(
                    url="https://example.test/sub",
                    write_pool=True,
                )
            self.assertEqual(out.get("proxy_pool_source"), "subscription")
            text = pool.read_text(encoding="utf-8")
            self.assertIn("http://u:p@2.2.2.2:8080", text)
            self.assertNotIn("old:1", text)
            disk = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(disk["proxy_pool_source"], "subscription")
            self.assertEqual(disk.get("tui_proxy_mode"), "pool")

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

    def _seed_vless_cache(self, service, lines):
        path = service.embedded_vless_cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_ensure_embedded_proxy_loads_vless_and_starts(self):
        with tempfile.TemporaryDirectory() as d:
            service = self._service(Path(d))
            self._seed_vless_cache(
                service,
                [
                    "vless://11111111-1111-1111-1111-111111111111@jp.example:443?security=tls&sni=jp.example#jp",
                    "vless://22222222-2222-2222-2222-222222222222@sg.example:443?security=tls&sni=sg.example#sg",
                ],
            )

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
                "proxy_subscription.fetch_subscription_body",
                side_effect=AssertionError("ensure must not fetch subscription"),
            ) as fetch_mock, mock.patch(
                "embedded_proxy_manager.EmbeddedProxyManager",
                return_value=manager,
            ) as mgr_cls:
                out = service.ensure_embedded_proxy(force_reload=True)

            fetch_mock.assert_not_called()
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

    def test_ensure_embedded_proxy_raises_when_cache_empty(self):
        with tempfile.TemporaryDirectory() as d:
            service = self._service(Path(d))
            with self.assertRaises(svc.TuiConfigError) as ctx:
                service.ensure_embedded_proxy(force_reload=True)
            self.assertIn("缓存", str(ctx.exception))

    def test_fetch_embedded_subscription_nodes_writes_cache(self):
        with tempfile.TemporaryDirectory() as d:
            service = self._service(Path(d))
            plain = (
                "vless://11111111-1111-1111-1111-111111111111@jp.example:443?security=tls#jp\n"
                "hy2://secret@hy.example:8443?sni=hy.example#hy\n"
                "anytls://pwd@any.example:443?sni=any.example#any\n"
                "trojan://synthetic-secret@trojan.example:443?sni=edge.example#trojan\n"
                "http://1.1.1.1:80\n"
            )
            with mock.patch(
                "proxy_subscription.fetch_subscription_body",
                return_value=(plain, "plain"),
            ):
                data = service.fetch_embedded_subscription_nodes(
                    urls=["https://example.test/sub"]
                )
            self.assertEqual(data.get("cached_node_count"), 4)
            self.assertEqual(data.get("cached_vless_count"), 1)
            self.assertEqual((data.get("cached_by_protocol") or {}).get("hysteria2"), 1)
            self.assertEqual((data.get("cached_by_protocol") or {}).get("anytls"), 1)
            self.assertEqual((data.get("cached_by_protocol") or {}).get("trojan"), 1)
            cache_path = service.embedded_node_cache_path()
            self.assertTrue(cache_path.is_file())
            text = cache_path.read_text(encoding="utf-8")
            self.assertIn("vless://11111111-1111-1111-1111-111111111111@jp.example:443", text)
            self.assertIn("hy2://secret@hy.example:8443", text)
            self.assertIn("anytls://pwd@any.example:443", text)
            self.assertIn("trojan://synthetic-secret@trojan.example:443", text)
            disk = json.loads((Path(d) / "config.json").read_text(encoding="utf-8"))
            self.assertEqual(disk.get("proxy_subscription_urls"), ["https://example.test/sub"])

    def test_ensure_embedded_proxy_raises_when_all_unhealthy(self):
        with tempfile.TemporaryDirectory() as d:
            service = self._service(Path(d))
            self._seed_vless_cache(
                service,
                [
                    "vless://11111111-1111-1111-1111-111111111111@jp.example:443?security=tls#jp",
                ],
            )
            manager = mock.Mock()
            manager.start.return_value = {"running": True, "total": 1}
            manager.probe_all.return_value = {"total": 1, "healthy": 0, "results": []}
            manager.status.return_value = {"running": True, "total": 1, "healthy": 0}
            manager._running = False
            with mock.patch(
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
        # Pure embedded tests should not also enable HTTP pool hybrid scheduling.
        if proxy_args is None:
            proxy_args = (
                []
                if embedded
                else ["--proxy-file", "proxies.txt", "--proxy-random"]
            )
        return svc.RunPlan(
            config_path=Path("config.json"),
            run_mode=svc.RUN_MODE_REGISTER_OTP,
            count=count,
            workers=1,
            output_dir=Path("."),
            provider="capsolver",
            email_provider="yyds",
            proxy_mode="pool" if (not embedded or proxy_args) else "none",
            proxy_args=list(proxy_args),
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
        # Turnstile quality timeouts should not burn proxy node retries.
        self.assertFalse(svc._looks_like_proxy_failure("turnstile timeout"))
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
        self.assertTrue(manager.release.called)
        self.assertEqual(manager.release.call_args.args[0], "n1")
        self.assertFalse(manager.release.call_args.kwargs.get("failed"))
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


class StaticHttpProxyLeaseTests(unittest.TestCase):
    def _runner(
        self,
        root: Path,
        *,
        proxy_count: int = 2,
        workers: int = 4,
        count: int = 8,
        embedded: bool = False,
    ):
        source = root / "proxies.txt"
        entries = [
            f"http://user{i}:secret{i}@p{i}.example:8080"
            for i in range(proxy_count)
        ]
        source.write_text("\n".join(entries) + "\n", encoding="utf-8")
        cfg = root / "config.json"
        cfg.write_text(
            json.dumps(
                {
                    "proxy_file": str(source),
                    "proxy_slot_sticky": True,
                    "turnstile_proxy_enabled": False,
                }
            ),
            encoding="utf-8",
        )
        plan = svc.RunPlan(
            config_path=cfg,
            run_mode=svc.RUN_MODE_REGISTER_OTP,
            count=count,
            workers=workers,
            output_dir=root / "creds",
            provider="capsolver",
            email_provider="yyds",
            proxy_mode="pool",
            proxy_args=["--proxy-file", str(source), "--proxy-random"],
            embedded_proxy_enabled=embedded,
            embedded_proxy_max_node_retries=3,
            proxy_slot_sticky=True,
        )
        runner = svc.BatchRunner(plan)
        runner.run_dir = root / "run"
        runner.run_dir.mkdir(parents=True, exist_ok=True)
        runner._prepare_static_proxy_snapshot()
        # Keep test health output out of the repository-level stats file.
        runner._manual_proxy_rotator._stats_file = str(root / "proxy_stats.log")
        return runner, source, entries

    @staticmethod
    def _fake_spawn(runner):
        def spawn(worker, *, acquire_proxy=True):
            if acquire_proxy and not runner._acquire_worker_proxy(worker):
                return False
            worker.status = "running"
            worker.process = mock.Mock()
            worker.process.poll.return_value = None
            return True

        return spawn

    def test_snapshot_is_private_and_frozen_during_source_edits(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner, source, entries = self._runner(root, proxy_count=2)
            snapshot = runner._proxy_pool_snapshot_path
            self.assertIsNotNone(snapshot)
            self.assertEqual(snapshot.read_text(encoding="utf-8").splitlines(), entries)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o600)

            source.write_text(
                "http://changed:new-secret@replacement.example:9000\n",
                encoding="utf-8",
            )
            workers = [svc.WorkerState(index=i) for i in (1, 2)]
            self.assertTrue(runner._acquire_manual_proxy(workers[0]))
            self.assertTrue(runner._acquire_manual_proxy(workers[1]))
            self.assertEqual({worker.manual_proxy for worker in workers}, set(entries))
            self.assertNotIn("replacement.example", runner._static_proxy_entries)

    def test_worker_leases_are_unique_and_release_exactly_once(self):
        with tempfile.TemporaryDirectory() as d:
            runner, _source, _entries = self._runner(Path(d), proxy_count=2)
            first = svc.WorkerState(index=1)
            second = svc.WorkerState(index=2)
            self.assertTrue(runner._acquire_manual_proxy(first))
            self.assertTrue(runner._acquire_manual_proxy(second))
            self.assertNotEqual(first.manual_proxy, second.manual_proxy)
            rotator = runner._manual_proxy_rotator
            with mock.patch.object(
                rotator,
                "release_lease",
                wraps=rotator.release_lease,
            ) as release:
                self.assertTrue(
                    runner._release_manual_proxy(first, success=True, reason="ok")
                )
                self.assertFalse(
                    runner._release_manual_proxy(first, success=True, reason="duplicate")
                )
            self.assertEqual(release.call_count, 1)
            replacement = svc.WorkerState(index=3)
            self.assertTrue(runner._acquire_manual_proxy(replacement))

    def test_probe_gate_is_bounded_and_cools_failed_routes(self):
        with tempfile.TemporaryDirectory() as d:
            runner, _source, _entries = self._runner(Path(d), proxy_count=3)

            def probe(index, _proxy):
                return {
                    "index": index,
                    "ok": index != 1,
                    "reason": "ok" if index != 1 else "signup_region_403",
                    "targets": {},
                }

            with mock.patch.object(
                runner,
                "_probe_static_proxy_slot",
                side_effect=probe,
            ) as mocked:
                runner._probe_static_proxy_slots()
            self.assertEqual(mocked.call_count, 3)
            self.assertEqual(svc.STATIC_PROXY_HEALTH_TIMEOUT_SEC, 12.0)
            self.assertEqual(svc.STATIC_PROXY_HEALTH_PROBE_WORKERS, 2)
            self.assertEqual(svc.STATIC_PROXY_HEALTH_ATTEMPTS, 3)
            self.assertEqual(svc.STATIC_PROXY_HEALTH_BACKOFF_SEC, 0.35)
            self.assertEqual(runner._manual_proxy_rotator.available_lease_count(), 2)
            self.assertFalse(runner._static_proxy_health[1]["ok"])

    def test_start_freezes_and_probes_before_spawning(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner, _source, _entries = self._runner(root, proxy_count=2)
            # Exercise the real start orchestration from a fresh pre-start state.
            runner._manual_proxy_rotator = None
            runner._static_proxy_entries = tuple()
            runner._proxy_pool_snapshot_path = None
            runner.plan.proxy_pool_entries = tuple()

            def healthy(index, _proxy):
                return {
                    "index": index,
                    "ok": True,
                    "reason": "ok",
                    "targets": {
                        "signup": {"ok": True},
                        "ms_token": {"ok": True},
                    },
                }

            with mock.patch.object(
                runner,
                "_probe_static_proxy_slot",
                side_effect=healthy,
            ) as probe, mock.patch.object(
                runner,
                "_spawn_available",
            ) as spawn, mock.patch("proxy_pool.ProxyRotator._append_log"):
                runner.start()
            self.assertTrue(runner.started)
            self.assertEqual(probe.call_count, 2)
            self.assertTrue(runner._proxy_pool_snapshot_path.is_file())
            spawn.assert_called_once_with()

    def test_http_only_capacity_refills_as_leases_return(self):
        with tempfile.TemporaryDirectory() as d:
            runner, _source, _entries = self._runner(
                Path(d), proxy_count=2, workers=5, count=5
            )
            runner.started = True
            runner.phase = "running"
            with mock.patch.object(
                runner,
                "_spawn_one",
                side_effect=self._fake_spawn(runner),
            ):
                runner._spawn_available()
                self.assertEqual(len(runner.active), 2)
                self.assertEqual(
                    len({worker.manual_proxy for worker in runner.active}),
                    2,
                )
                completed = runner.active[0]
                runner._release_manual_proxy(completed, success=True, reason="ok")
                runner._mark_terminal(completed, "succeeded")
                runner._spawn_available()
            self.assertEqual(len(runner.active), 2)
            self.assertEqual(runner.started_tasks, 3)

    def test_hybrid_keeps_node_capacity_when_http_pool_is_small(self):
        class Manager:
            def __init__(self):
                self.next_id = 0
                self.released = []

            def status(self):
                return {"running": True, "healthy": 10, "total": 10}

            def acquire(self, exclude_ids=()):
                from embedded_proxy_manager import NodeSlot

                self.next_id += 1
                return NodeSlot(
                    id=f"node-{self.next_id}",
                    name=f"node-{self.next_id}",
                    server="node.example",
                    port=443,
                    protocol="vless",
                    local_http=f"http://127.0.0.1:{28000 + self.next_id}",
                    healthy=True,
                    ref_count=1,
                )

            def release(self, node_id, **kwargs):
                self.released.append((node_id, kwargs))

        with tempfile.TemporaryDirectory() as d:
            runner, _source, _entries = self._runner(
                Path(d), proxy_count=1, workers=4, count=4, embedded=True
            )
            runner.embedded_proxy_manager = Manager()
            runner.started = True
            runner.phase = "running"
            with mock.patch.object(
                runner,
                "_spawn_one",
                side_effect=self._fake_spawn(runner),
            ):
                runner._spawn_available()
            self.assertEqual(len(runner.active), 4)
            self.assertEqual(sum(bool(w.manual_proxy) for w in runner.active), 1)
            self.assertEqual(sum(bool(w.proxy_node_id) for w in runner.active), 3)

    def test_local_turnstile_shares_registration_route_unless_dedicated(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner, _source, _entries = self._runner(root, proxy_count=1)
            worker = svc.WorkerState(index=1, accounts_path=root / "accounts.txt")
            self.assertTrue(runner._acquire_manual_proxy(worker))
            command = runner._command_for(worker)
            proxy_index = command.index("--proxy")
            self.assertEqual(command[proxy_index + 1], worker.manual_proxy)
            self.assertNotIn("--turnstile-proxy", command)
            self.assertFalse(worker.uses_independent_turnstile_proxy)

            cfg = json.loads(runner.plan.config_path.read_text(encoding="utf-8"))
            cfg.update(
                {
                    "turnstile_proxy_enabled": True,
                    "turnstile_proxy_mode": "direct",
                    "turnstile_proxy": "http://solver:secret@solver.example:8080",
                }
            )
            runner.plan.config_path.write_text(json.dumps(cfg), encoding="utf-8")
            command = runner._command_for(worker)
            self.assertIn("--turnstile-proxy", command)
            self.assertTrue(worker.uses_independent_turnstile_proxy)

    def test_runtime_bad_route_is_not_charged_as_business_failure(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner, _source, _entries = self._runner(root, proxy_count=1, count=1)
            worker = svc.WorkerState(index=1)
            worker.log_path = runner.run_dir / "worker.log"
            worker.log_path.write_text("curl: (35) TLS connect error\n", encoding="utf-8")
            self.assertTrue(runner._acquire_manual_proxy(worker))
            worker.status = "running"
            worker.process = mock.Mock()
            worker.process.poll.return_value = 1
            runner.workers = [worker]
            runner.worker_by_index = {1: worker}
            runner.started_tasks = 1
            runner._check_processes()
            self.assertEqual(worker.status, "stopped")
            self.assertEqual(runner.failed, 0)
            self.assertEqual(runner.started_tasks, 0)
            self.assertEqual(runner._manual_proxy_rotator.active_lease_count(), 0)
            self.assertEqual(runner._manual_proxy_rotator.available_lease_count(), 0)

    def test_permanently_bad_static_route_exhausts_logical_retry_budget(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner, _source, entries = self._runner(
                root,
                proxy_count=1,
                workers=1,
                count=1,
            )
            runner.started = True
            runner.phase = "running"

            with mock.patch.object(
                runner,
                "_spawn_one",
                side_effect=self._fake_spawn(runner),
            ):
                runner._spawn_available()
                self.assertEqual(runner.started_tasks, 1)
                self.assertEqual(len(runner.active), 1)

                for attempt in range(1, 4):
                    worker = runner.active[0]
                    worker.log_path = runner.run_dir / f"worker_{attempt}.log"
                    worker.log_path.write_text(
                        "curl: (35) TLS connect error\n",
                        encoding="utf-8",
                    )
                    worker.process.poll.return_value = 1
                    runner._check_processes()

                    if attempt < 3:
                        self.assertEqual(worker.status, "stopped")
                        self.assertEqual(runner.failed, 0)
                        self.assertEqual(runner.started_tasks, 0)
                        runner._spawn_available()
                        self.assertEqual(len(runner.active), 0)
                        runner._manual_proxy_rotator.mark_good(entries[0])
                        runner._spawn_available()
                        self.assertEqual(len(runner.active), 1)
                        self.assertEqual(runner.active[0].proxy_attempt, attempt + 1)
                    else:
                        self.assertEqual(worker.status, "failed")

            self.assertEqual(runner.failed, 1)
            self.assertEqual(runner.stopped, 2)
            self.assertEqual(runner.started_tasks, 1)
            self.assertEqual(runner.failure_counts["tls_error"], 1)
            self.assertFalse(runner._should_refill())
            self.assertEqual(runner._manual_proxy_rotator.active_lease_count(), 0)
            runner.tick()
            self.assertTrue(runner.done)

    def test_dedicated_turnstile_failure_does_not_cool_registration_route(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner, _source, _entries = self._runner(root, proxy_count=1, count=1)
            worker = svc.WorkerState(index=1)
            worker.log_path = runner.run_dir / "worker.log"
            worker.log_path.write_text(
                "Turnstile dedicated proxy ProxyError\n",
                encoding="utf-8",
            )
            self.assertTrue(runner._acquire_manual_proxy(worker))
            worker.uses_independent_turnstile_proxy = True
            worker.status = "running"
            worker.process = mock.Mock()
            worker.process.poll.return_value = 1
            runner.workers = [worker]
            runner.worker_by_index = {1: worker}
            runner.started_tasks = 1
            runner._check_processes()
            self.assertEqual(worker.status, "failed")
            self.assertEqual(runner.failed, 1)
            self.assertEqual(runner._manual_proxy_rotator.active_lease_count(), 0)
            self.assertEqual(runner._manual_proxy_rotator.available_lease_count(), 1)

    def test_success_then_finalize_does_not_double_release(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner, _source, _entries = self._runner(root, proxy_count=1, count=1)
            worker = svc.WorkerState(index=1)
            self.assertTrue(runner._acquire_manual_proxy(worker))
            worker.status = "running"
            worker.process = mock.Mock()
            worker.process.poll.return_value = 0
            runner.workers = [worker]
            runner.worker_by_index = {1: worker}
            rotator = runner._manual_proxy_rotator
            with mock.patch.object(
                rotator,
                "release_lease",
                wraps=rotator.release_lease,
            ) as release:
                runner._check_processes()
                runner._release_all_manual_proxies()
            self.assertEqual(release.call_count, 1)
            self.assertEqual(worker.status, "succeeded")

    def test_spawn_exception_and_stop_paths_return_leases(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner, _source, _entries = self._runner(root, proxy_count=1)
            worker = svc.WorkerState(index=1)
            with mock.patch.object(
                runner,
                "_command_for",
                side_effect=RuntimeError("boom"),
            ):
                self.assertFalse(runner._spawn_one(worker))
            self.assertEqual(runner._manual_proxy_rotator.active_lease_count(), 0)

            # Restore the failed route without waiting for its cooldown, then
            # verify a queued cancellation is neutral and idempotent.
            proxy = runner._static_proxy_entries[0]
            runner._manual_proxy_rotator.mark_good(proxy)
            queued = svc.WorkerState(index=2)
            self.assertTrue(runner._acquire_manual_proxy(queued))
            queued.status = "queued"
            runner.workers = [queued]
            runner.worker_by_index = {2: queued}
            runner.stop()
            self.assertEqual(runner._manual_proxy_rotator.active_lease_count(), 0)

            second_root = root / "second"
            second_root.mkdir()
            running_runner, _source, _entries = self._runner(
                second_root,
                proxy_count=1,
            )
            running = svc.WorkerState(index=3)
            self.assertTrue(running_runner._acquire_manual_proxy(running))
            running.status = "running"
            running.process = mock.Mock()
            running.process.poll.return_value = None
            running_runner.workers = [running]
            running_runner.worker_by_index = {3: running}
            running_runner.stop()
            running.process.terminate.assert_called_once_with()
            running.process.poll.return_value = -15
            running_runner._check_processes()
            self.assertEqual(
                running_runner._manual_proxy_rotator.active_lease_count(),
                0,
            )

    def test_logs_and_snapshot_state_do_not_expose_credentials(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner, _source, entries = self._runner(root, proxy_count=1)
            worker = svc.WorkerState(
                index=1,
                status="failed",
                last_log=f"failure through {entries[0]}",
            )
            runner.workers = [worker]
            runner.worker_by_index = {1: worker}
            runner._log("W01", worker.last_log)
            state = json.dumps(runner.snapshot(), ensure_ascii=False)
            logs = "\n".join(runner.logs)
            for secret in ("user0", "secret0"):
                self.assertNotIn(secret, state)
                self.assertNotIn(secret, logs)



if __name__ == "__main__":
    unittest.main()

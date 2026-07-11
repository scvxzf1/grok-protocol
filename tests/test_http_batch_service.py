import json
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
            self.assertLessEqual(plan.workers, svc.MAX_LOCAL_TURNSTILE_WORKERS)

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
            self.assertEqual(plan.workers, 8)
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

    def test_snapshot_metrics_running(self):
        runner = self._make_runner(count=3)
        runner.started = True
        runner.started_at_wall = "2026-07-11T12:00:00"
        runner.started_at_monotonic = 1000.0
        runner.workers[0].status = "succeeded"
        runner.workers[1].status = "failed"
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
        runner.started_at_wall = "2026-07-11T12:00:00"
        runner.started_at_monotonic = 1000.0
        runner.finished_at_monotonic = 1060.0
        runner.workers[0].status = "succeeded"
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

        worker = runner.workers[0]
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
        worker = runner.workers[0]
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
        self.assertFalse(svc._looks_like_proxy_failure("turnstile timeout"))
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

        worker = runner.workers[0]
        worker.accounts_path = Path("accounts_001.txt")
        worker.log_path = Path("worker_001.log")

        def fake_spawn(w, *, acquire_proxy=True):
            # Keep the leased node sticky and mark running without real Popen.
            if acquire_proxy and runner.plan.embedded_proxy_enabled and not w.proxy_node_id:
                assert runner._acquire_embedded_proxy(w)
            w.status = "running"
            w.process = mock.Mock()
            w.process.poll.return_value = None

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
        worker = runner.workers[0]
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



if __name__ == "__main__":
    unittest.main()

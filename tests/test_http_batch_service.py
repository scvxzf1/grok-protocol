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


if __name__ == "__main__":
    unittest.main()

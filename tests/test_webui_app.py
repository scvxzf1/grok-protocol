import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

import http_batch_service as svc
import webui_app


class WebUIAppTests(unittest.TestCase):
    def _service(self, root: Path) -> svc.BatchService:
        cfg = root / "config.json"
        cfg.write_text(
            json.dumps(
                {
                    "email_provider": "yyds",
                    "yyds_api_key": "secret-key",
                    "turnstile_provider": "capsolver",
                    "turnstile_api_key": "CAP-SECRET",
                    "register_count": 2,
                    "concurrent_workers": 1,
                }
            ),
            encoding="utf-8",
        )
        return svc.BatchService(config_path=cfg, root_dir=root)

    def test_health_and_settings_get_masks_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            service = self._service(root)
            app = webui_app.create_app(service=service)
            client = TestClient(app)
            r = client.get("/api/health")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["host"], "127.0.0.1")
            s = client.get("/api/settings")
            self.assertEqual(s.status_code, 200)
            body = s.json()
            self.assertEqual(body["count"], 2)
            self.assertEqual(body["config"]["turnstile_api_key"], "***")
            self.assertEqual(body["config"]["yyds_api_key"], "***")
            center = client.get("/api/config-center").json()
            # config-center intentionally exposes plaintext keys for local editing
            self.assertEqual(center["fields"]["yyds_api_key"], "secret-key")
            self.assertEqual(center["fields"]["turnstile_api_key"], "CAP-SECRET")

    def test_start_run_conflict(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            service = self._service(root)
            app = webui_app.create_app(service=service)
            client = TestClient(app)

            def fake_start(self):
                self.started = True
                self.done = False

            with mock.patch.object(svc.BatchRunner, "start", fake_start), mock.patch.object(
                svc.BatchRunner, "tick", lambda self: None
            ), mock.patch.object(svc, "ROOT_DIR", root), mock.patch.object(svc, "RUNS_DIR", root / "runs"):
                r1 = client.post("/api/runs", json={"count": 1, "workers": 1})
                self.assertEqual(r1.status_code, 202)
                r2 = client.post("/api/runs", json={"count": 1, "workers": 1})
                self.assertEqual(r2.status_code, 409)

    def test_run_file_escape_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runs = root / "http_runs"
            rid = "demo_run"
            (runs / rid).mkdir(parents=True)
            (runs / rid / "worker_001.log").write_text("hello", encoding="utf-8")
            service = self._service(root)
            app = webui_app.create_app(service=service)
            client = TestClient(app)
            with mock.patch.object(svc, "RUNS_DIR", runs):
                ok = client.get(f"/api/runs/{rid}/files", params={"path": "worker_001.log"})
                self.assertEqual(ok.status_code, 200)
                self.assertIn("hello", ok.text)
                bad = client.get(f"/api/runs/{rid}/files", params={"path": "../secret.txt"})
                self.assertIn(bad.status_code, {403, 404, 400})



    def test_config_center_page_and_api(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            service = self._service(root)
            (root / "proxies.txt").write_text("9.9.9.9:1:u:p\n", encoding="utf-8")
            # reload after file create via config path already set
            service.settings.config["proxy_file"] = "proxies.txt"
            app = webui_app.create_app(service=service)
            client = TestClient(app)
            page = client.get("/config")
            self.assertEqual(page.status_code, 200)
            self.assertIn("配置中心", page.text)
            self.assertIn("运行台", page.text)
            self.assertIn('name="local_turnstile_max_workers"', page.text)
            self.assertIn('name="submit_workers"', page.text)
            self.assertIn('name="yyds_create_spacing_sec"', page.text)
            self.assertIn('class="help-tip"', page.text)
            self.assertIn('data-tip="选临时邮箱服务商，决定用哪套邮箱配置"', page.text)
            self.assertIn('data-tip="仅 local 生效；总并发仍受运行台与 32 上限约束"', page.text)
            self.assertGreaterEqual(page.text.count('class="help-tip"'), 23)
            data = client.get("/api/config-center")
            self.assertEqual(data.status_code, 200)
            body = data.json()
            self.assertIn("proxy_pool", body)
            put = client.put(
                "/api/config-center",
                json={
                    "fields": {"proxy_mode": "pool", "turnstile_api_key": "***"},
                    "proxy_pool_text": "8.8.8.8:80:a:b\n",
                },
            )
            self.assertEqual(put.status_code, 200)
            self.assertEqual(put.json()["fields"]["proxy_mode"], "pool")
            pool = client.get("/api/proxy-pool")
            self.assertEqual(pool.status_code, 200)
            self.assertGreaterEqual(pool.json()["line_count"], 1)



    def test_proxy_pool_test_api(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            service = self._service(root)
            app = webui_app.create_app(service=service)
            client = TestClient(app)
            fake = {
                "tested": 1,
                "ok": 1,
                "fail": 0,
                "results": [{"index": 1, "ok": True, "display": "h:1:u:***", "latency_ms": 12, "exit_ip": "8.8.8.8"}],
                "probe_url": "https://api.ipify.org?format=json",
                "total_available": 3,
            }
            with mock.patch.object(service, "test_proxy_pool", return_value=fake):
                r = client.post("/api/proxy-pool/test", json={"count": 5, "text": "1.1.1.1:80:u:p\n"})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["ok"], 1)
            page = client.get("/config")
            self.assertIn("随机测试5条", page.text)

    def test_embedded_proxy_status_and_reload_guard(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            service = self._service(root)
            service.settings.config["embedded_proxy_enabled"] = True
            service.settings.config["embedded_proxy_binary"] = "/usr/bin/verge-mihomo"
            service.settings.config["embedded_proxy_base_port"] = 28000
            service.settings.config["embedded_proxy_max_nodes"] = 10
            app = webui_app.create_app(service=service)
            client = TestClient(app)

            status_payload = {
                "enabled": True,
                "running": True,
                "healthy": 2,
                "total": 3,
                "leases": 1,
                "last_error": "",
            }
            with mock.patch.object(service, "get_embedded_proxy_status", return_value=status_payload):
                r = client.get("/api/embedded-proxy/status")
            self.assertEqual(r.status_code, 200)
            body = r.json()
            self.assertTrue(body["enabled"])
            self.assertTrue(body["running"])
            self.assertEqual(body["healthy"], 2)
            self.assertEqual(body["total"], 3)

            start_payload = dict(status_payload)
            start_payload["healthy"] = 3
            with mock.patch.object(service, "ensure_embedded_proxy", return_value=start_payload) as ensure:
                with mock.patch.object(service, "probe_embedded_proxy", return_value={"enabled": True, "healthy": 3, "total": 3}):
                    r = client.post("/api/embedded-proxy/start", json={})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["healthy"], 3)
            ensure.assert_called()

            with mock.patch.object(service, "probe_embedded_proxy", return_value={"enabled": True, "healthy": 2, "total": 3}):
                r = client.post("/api/embedded-proxy/probe", json={})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["healthy"], 2)

            with mock.patch.object(service, "is_busy", return_value=True):
                r = client.post("/api/embedded-proxy/reload", json={})
            self.assertIn(r.status_code, {400, 409})
            detail = r.json().get("detail") or ""
            self.assertTrue(any("一" <= ch <= "鿿" for ch in str(detail)), detail)

            with mock.patch.object(service, "is_busy", return_value=True):
                r = client.post("/api/embedded-proxy/stop", json={})
            self.assertIn(r.status_code, {400, 409})

    def test_config_page_has_embedded_proxy_fields(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            service = self._service(root)
            app = webui_app.create_app(service=service)
            client = TestClient(app)
            page = client.get("/config")
            self.assertEqual(page.status_code, 200)
            self.assertIn("embedded_proxy_enabled", page.text)
            self.assertIn("btnEmbeddedProbe", page.text)
            self.assertIn("内嵌代理内核", page.text)
            self.assertIn("embedded_proxy_base_port", page.text)
            self.assertIn("btnEmbeddedStart", page.text)
            self.assertIn("btnEmbeddedStatus", page.text)

    def test_embedded_proxy_autostart_on_app_boot(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            service = self._service(root)
            service.settings.config["embedded_proxy_enabled"] = True
            called = {"n": 0}
            status_payload = {
                "enabled": True,
                "running": False,
                "phase": "starting",
                "message": "正在启动/重载内嵌代理…",
                "healthy": 0,
                "total": 0,
                "leases": 0,
            }

            def fake_auto(force=False):
                called["n"] += 1
                return dict(status_payload)

            with mock.patch.object(service, "maybe_autostart_embedded_proxy", side_effect=fake_auto) as auto:
                with mock.patch.object(service, "get_embedded_proxy_status", return_value=status_payload):
                    app = webui_app.create_app(service=service)
                    with TestClient(app) as client:
                        r = client.get("/api/health")
            self.assertEqual(r.status_code, 200)
            body = r.json()
            self.assertIn("embedded_proxy", body)
            self.assertEqual(body["embedded_proxy"]["phase"], "starting")
            auto.assert_called()
            self.assertGreaterEqual(called["n"], 1)

    def test_run_page_has_embedded_status_widgets(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            service = self._service(root)
            app = webui_app.create_app(service=service)
            client = TestClient(app)
            page = client.get("/")
            self.assertEqual(page.status_code, 200)
            self.assertIn("embeddedProxySummaryRun", page.text)
            self.assertIn("embeddedBadge", page.text)



if __name__ == "__main__":
    unittest.main()

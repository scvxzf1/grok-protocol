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


if __name__ == "__main__":
    unittest.main()

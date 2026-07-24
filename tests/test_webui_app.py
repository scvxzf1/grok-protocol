import json
import os
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
            (runs / rid / "worker_001.log").write_text(
                "hello private-mailbox@example.test "
                "refresh_token=M.C_PRIVATE_REFRESH_TOKEN\n",
                encoding="utf-8",
            )
            (runs / rid / "accounts_001.txt").write_text(
                "private-mailbox@example.test----PASSWORD----SSO_TOKEN\n",
                encoding="utf-8",
            )
            (runs / rid / "proxy_pool.snapshot.txt").write_text(
                "proxy.example.test:9000:USER:PASSWORD\n",
                encoding="utf-8",
            )
            (runs / rid / "summary.json").write_text(
                json.dumps(
                    {
                        "run_id": rid,
                        "done": True,
                        "workers": [
                            {
                                "index": 1,
                                "status": "failed",
                                "last_log": "private-mailbox@example.test refresh_token=M.C_PRIVATE_REFRESH_TOKEN",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            service = self._service(root)
            app = webui_app.create_app(service=service)
            client = TestClient(app)
            with mock.patch.object(svc, "RUNS_DIR", runs):
                ok = client.get(f"/api/runs/{rid}/files", params={"path": "worker_001.log"})
                self.assertEqual(ok.status_code, 200)
                self.assertIn("hello", ok.text)
                self.assertNotIn("private-mailbox@example.test", ok.text)
                self.assertNotIn("M.C_PRIVATE_REFRESH_TOKEN", ok.text)
                logs = client.get(f"/api/runs/{rid}/logs", params={"worker": 1})
                self.assertEqual(logs.status_code, 200)
                self.assertNotIn("private-mailbox@example.test", logs.text)
                self.assertNotIn("M.C_PRIVATE_REFRESH_TOKEN", logs.text)
                for private_name in ("accounts_001.txt", "proxy_pool.snapshot.txt"):
                    private = client.get(
                        f"/api/runs/{rid}/files",
                        params={"path": private_name},
                    )
                    self.assertEqual(private.status_code, 403)
                detail = client.get(f"/api/runs/{rid}")
                self.assertEqual(detail.status_code, 200)
                detail_text = json.dumps(detail.json(), ensure_ascii=False)
                self.assertNotIn("private-mailbox@example.test", detail_text)
                self.assertNotIn("M.C_PRIVATE_REFRESH_TOKEN", detail_text)
                self.assertFalse(
                    any(
                        item["name"].startswith("accounts_")
                        for item in detail.json().get("files", [])
                    )
                )
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
            self.assertIn("凭证列表", page.text)
            self.assertIn('href="/credentials"', page.text)
            self.assertIn('href="/config/mail"', page.text)
            self.assertIn('href="/config/proxy"', page.text)
            mail = client.get("/config/mail")
            self.assertEqual(mail.status_code, 200)
            self.assertIn('name="local_turnstile_max_workers"', mail.text)
            self.assertIn('name="submit_workers"', mail.text)
            self.assertIn('name="yyds_create_spacing_sec"', mail.text)
            self.assertIn('class="help-tip"', mail.text)
            self.assertIn('data-tip="选临时邮箱服务商，决定用哪套邮箱配置"', mail.text)
            self.assertIn('data-tip="仅 local 生效；总并发仍受运行台与 128 上限约束"', mail.text)
            self.assertGreaterEqual(mail.text.count('class="help-tip"'), 10)
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
            page = client.get("/config/proxy")
            self.assertIn("测试代理池", page.text)

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
            page = client.get("/config/proxy")
            self.assertEqual(page.status_code, 200)
            self.assertIn("embedded_proxy_enabled", page.text)
            self.assertIn("btnEmbeddedProbe", page.text)
            self.assertIn("节点池", page.text)
            self.assertIn("mihomo", page.text)
            self.assertIn("embedded_proxy_base_port", page.text)
            self.assertIn("btnEmbeddedStart", page.text)
            self.assertIn("btnEmbeddedFetchSub", page.text)
            self.assertIn("proxy_subscription_urls", page.text)
            self.assertIn("btnEmbeddedStatus", page.text)
            self.assertIn("btnEmbeddedRefresh", page.text)
            self.assertIn("btnEmbeddedRefreshProbeOnly", page.text)
            self.assertIn("embedded_proxy_refresh_fetch_subscription", page.text)
            self.assertIn("embedded_proxy_refresh_export_healthy", page.text)

    def test_embedded_proxy_refresh_api(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            service = self._service(root)
            app = webui_app.create_app(service=service)
            client = TestClient(app)
            payload = {
                "ok": True,
                "message": "节点池已刷新：缓存 2 · 已重载 · 健康 1/2",
                "healthy": 1,
                "total": 2,
                "steps": {
                    "fetch_subscription": True,
                    "reload": True,
                    "probe": True,
                    "export_healthy": False,
                },
            }
            with mock.patch.object(
                service, "refresh_embedded_node_pool", return_value=payload
            ) as refresh:
                r = client.post(
                    "/api/embedded-proxy/refresh",
                    json={
                        "proxy_subscription_urls": "https://example.test/sub",
                        "fetch_subscription": True,
                        "reload": True,
                        "probe": True,
                        "export_healthy": False,
                    },
                )
            self.assertEqual(r.status_code, 200)
            body = r.json()
            self.assertTrue(body.get("ok"))
            self.assertEqual(body.get("healthy"), 1)
            refresh.assert_called_once()
            kwargs = refresh.call_args.kwargs
            self.assertTrue(kwargs.get("fetch_subscription"))
            self.assertTrue(kwargs.get("reload"))
            self.assertTrue(kwargs.get("probe"))
            self.assertFalse(kwargs.get("export_healthy"))

            busy_exc = __import__(
                "http_batch_service", fromlist=["BatchBusyError"]
            ).BatchBusyError("busy")
            with mock.patch.object(
                service,
                "refresh_embedded_node_pool",
                side_effect=busy_exc,
            ):
                r = client.post("/api/embedded-proxy/refresh", json={"reload": True})
            self.assertEqual(r.status_code, 409)

    def test_embedded_proxy_fetch_subscription_api(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            service = self._service(root)
            app = webui_app.create_app(service=service)
            client = TestClient(app)
            payload = {
                "cached_vless_count": 2,
                "message": "ok",
                "urls": ["https://example.test/sub"],
            }
            with mock.patch.object(
                service, "fetch_embedded_subscription_nodes", return_value=payload
            ) as fetch:
                r = client.post(
                    "/api/embedded-proxy/fetch-subscription",
                    json={"proxy_subscription_urls": "https://example.test/sub"},
                )
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["cached_vless_count"], 2)
            fetch.assert_called_once()

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




    def test_credentials_list_api_and_page_panel(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            out = root / "xai_credentials"
            out.mkdir()
            (out / "xai-a@example.com.json").write_text(
                '{"access_token":"tok-a","email":"a@example.com"}\n',
                encoding="utf-8",
            )
            (out / "xai-a@example.com.sso").write_text("sso-a-value\n", encoding="utf-8")
            (out / "xai-b@example.com.json").write_text(
                '{"access_token":"tok-b"}',
                encoding="utf-8",
            )
            # lone sso without json should be ignored
            (out / "orphan.sso").write_text("orphan", encoding="utf-8")

            service = self._service(root)
            service.settings.output_dir = out
            app = webui_app.create_app(service=service)
            client = TestClient(app)

            cfg_page = client.get("/config")
            self.assertEqual(cfg_page.status_code, 200)
            self.assertIn("凭证列表", cfg_page.text)  # nav link
            self.assertNotIn("credListText", cfg_page.text)
            self.assertIn("overviewMailSummary", cfg_page.text)

            page = client.get("/credentials")
            self.assertEqual(page.status_code, 200)
            self.assertIn("凭证列表", page.text)
            self.assertIn("credListText", page.text)
            self.assertIn("btnCredNext", page.text)
            self.assertIn("exportTableBody", page.text)
            self.assertIn("btnExportRefresh", page.text)
            self.assertIn("exportPreviewText", page.text)
            self.assertIn("历史文件预览", page.text)
            self.assertIn("1000", page.text)

            # Default listing returns full plaintext json____sso lines.
            data = client.get("/api/credentials", params={"page": 1, "page_size": 1000})
            self.assertEqual(data.status_code, 200)
            body = data.json()
            self.assertEqual(body["total"], 2)
            self.assertEqual(body["page"], 1)
            self.assertEqual(body["page_size"], 1000)
            self.assertEqual(body["total_pages"], 1)
            self.assertEqual(len(body["items"]), 2)
            self.assertTrue(body.get("revealed"))
            lines = body["text"].splitlines()
            self.assertEqual(len(lines), 2)
            self.assertTrue(all("____" in ln for ln in lines))
            joined = "\n".join(lines)
            self.assertIn('{"access_token":"tok-a","email":"a@example.com"}____sso-a-value', joined)
            self.assertIn('{"access_token":"tok-b"}____', joined)
            self.assertNotIn("orphan", joined)

            # pagination boundary
            page2 = client.get("/api/credentials", params={"page": 1, "page_size": 1}).json()
            self.assertEqual(page2["total"], 2)
            self.assertEqual(page2["page_size"], 1)
            self.assertEqual(page2["total_pages"], 2)
            self.assertEqual(len(page2["items"]), 1)



    def test_credentials_export_page_deletes_local_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            out = root / "xai_credentials"
            out.mkdir()
            json_a = out / "xai-a@example.com.json"
            sso_a = out / "xai-a@example.com.sso"
            json_b = out / "xai-b@example.com.json"
            sso_b = out / "xai-b@example.com.sso"
            json_a.write_text('{"access_token":"tok-a"}', encoding="utf-8")
            sso_a.write_text("sso-a", encoding="utf-8")
            json_b.write_text('{"access_token":"tok-b"}', encoding="utf-8")
            sso_b.write_text("sso-b", encoding="utf-8")

            service = self._service(root)
            service.settings.output_dir = out
            app = webui_app.create_app(service=service)
            client = TestClient(app)

            page = client.get("/credentials")
            self.assertEqual(page.status_code, 200)
            self.assertIn("btnCredExportPage", page.text)

            # export only first page with page_size=1
            resp = client.post(
                "/api/credentials/export-page",
                json={"page": 1, "page_size": 1},
            )
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertTrue(body.get("ok"))
            self.assertEqual(body.get("exported_count"), 1)
            self.assertGreaterEqual(int(body.get("deleted_count") or 0), 1)
            filename = str(body.get("filename") or "")
            self.assertTrue(filename.startswith("grok+"))
            self.assertTrue(filename.endswith(".txt"))
            export_path = Path(body["path"])
            self.assertTrue(export_path.is_file())
            self.assertEqual(export_path.parent.name, "exports")
            self.assertIn("/exports/", str(export_path).replace("\\", "/"))
            content = export_path.read_text(encoding="utf-8")
            self.assertIn("____", content)
            self.assertTrue(content.endswith("\n") or "____" in content)

            # exactly one pair remains
            remaining_json = list(out.glob("*.json"))
            self.assertEqual(len(remaining_json), 1)

            # empty page export fails without deleting remaining
            # first export remaining
            resp2 = client.post(
                "/api/credentials/export-page",
                json={"page": 1, "page_size": 1000},
            )
            self.assertEqual(resp2.status_code, 200)
            self.assertEqual(len(list(out.glob("*.json"))), 0)
            bad = client.post(
                "/api/credentials/export-page",
                json={"page": 1, "page_size": 1000},
            )
            self.assertEqual(bad.status_code, 400)



    def test_credential_exports_list_download_delete(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            out = root / "xai_credentials"
            out.mkdir()
            (out / "xai-a@example.com.json").write_text('{"access_token":"tok-a"}', encoding="utf-8")
            (out / "xai-a@example.com.sso").write_text("sso-a", encoding="utf-8")

            # legacy root-level export should be migrated into exports/
            legacy = root / "grok+legacy.txt"
            legacy.write_text("legacy-line\n", encoding="utf-8")

            service = self._service(root)
            service.settings.output_dir = out
            app = webui_app.create_app(service=service)
            client = TestClient(app)

            # list migrates legacy
            listed = client.get("/api/credential-exports")
            self.assertEqual(listed.status_code, 200)
            body = listed.json()
            self.assertTrue(str(body.get("export_dir") or "").endswith("exports"))
            names = [i["name"] for i in body.get("items") or []]
            self.assertIn("grok+legacy.txt", names)
            self.assertFalse(legacy.exists())
            self.assertTrue((root / "exports" / "grok+legacy.txt").is_file())

            # export creates new file in exports/
            exported = client.post("/api/credentials/export-page", json={"page": 1, "page_size": 1000})
            self.assertEqual(exported.status_code, 200)
            exp = exported.json()
            self.assertEqual(Path(exp["path"]).parent.name, "exports")
            fname = exp["filename"]

            # download
            dl = client.get("/api/credential-exports/download", params={"name": fname})
            self.assertEqual(dl.status_code, 200)
            self.assertIn("____", dl.text)

            # path traversal blocked
            bad = client.get("/api/credential-exports/download", params={"name": "../config.json"})
            self.assertIn(bad.status_code, {400, 403, 404})

            # delete
            deleted = client.request("DELETE", "/api/credential-exports", params={"name": fname})
            self.assertEqual(deleted.status_code, 200)
            self.assertFalse((root / "exports" / fname).exists())



    def test_credential_export_preview(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            exports = root / "exports"
            exports.mkdir()
            name = "grok+history.txt"
            content = "{\"a\":1}____sso-a\n{\"b\":2}____sso-b\n"
            (exports / name).write_text(content, encoding="utf-8")
            service = self._service(root)
            app = webui_app.create_app(service=service)
            client = TestClient(app)

            page = client.get("/credentials")
            self.assertEqual(page.status_code, 200)
            self.assertIn("exportPreviewText", page.text)
            self.assertIn("历史文件预览", page.text)
            self.assertIn("btnExportPreviewCopy", page.text)

            prev = client.get("/api/credential-exports/preview", params={"name": name})
            self.assertEqual(prev.status_code, 200)
            body = prev.json()
            self.assertTrue(body.get("ok"))
            self.assertEqual(body.get("name"), name)
            self.assertIn("____", body.get("text") or "")
            self.assertEqual(body.get("line_count"), 2)
            self.assertFalse(body.get("truncated"))




    def test_run_console_defaults_and_slim_snapshot_api(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            service = self._service(root)
            app = webui_app.create_app(service=service)
            client = TestClient(app)
            page = client.get("/")
            self.assertEqual(page.status_code, 200)
            self.assertIn('id="liveLogs"', page.text)
            self.assertIn("默认关闭实时日志", page.text)
            # live logs checkbox should not be pre-checked
            self.assertNotIn('id="liveLogs" checked', page.text)

            fake_snap = {
                "run_id": "demo",
                "started": True,
                "done": False,
                "stopping": False,
                "count": 64,
                "completed": 3,
                "succeeded": 2,
                "failed": 1,
                "active": 8,
                "elapsed_sec": 12,
                "avg_success_per_min": 10.0,
                "success_rate": 0.66,
                "failure_counts": {"turnstile_timeout": 1},
                "workers": [
                    {"index": i, "status": "running" if i <= 8 else "queued", "last_log": ("x" * 300), "return_code": None}
                    for i in range(1, 65)
                ],
            }
            with mock.patch.object(service, "current_snapshot", return_value=fake_snap):
                cur = client.get("/api/runs/current")
            self.assertEqual(cur.status_code, 200)
            run = cur.json()["run"]
            self.assertEqual(run["run_id"], "demo")
            self.assertEqual(run["worker_total"], 64)
            self.assertLessEqual(len(run["workers"]), 16)
            self.assertGreater(run["workers_truncated"], 0)
            self.assertLessEqual(len(run["workers"][0]["last_log"]), 120)

    def test_run_events_default_skips_log_listener(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            service = self._service(root)
            app = webui_app.create_app(service=service)
            client = TestClient(app)
            attached = {"n": 0}
            real_attach = service.attach_log_listener

            def track_attach(cb):
                attached["n"] += 1
                return real_attach(cb)

            with mock.patch.object(service, "attach_log_listener", side_effect=track_attach):
                with mock.patch.object(service, "current_snapshot", return_value={
                    "run_id": "demo",
                    "started": True,
                    "done": True,
                    "count": 1,
                    "completed": 1,
                    "succeeded": 1,
                    "failed": 0,
                    "active": 0,
                    "workers": [{"index": 1, "status": "succeeded", "last_log": "ok"}],
                    "failure_counts": {},
                }):
                    with client.stream("GET", "/api/runs/current/events") as resp:
                        self.assertEqual(resp.status_code, 200)
                        # Read a little so generator starts.
                        for i, chunk in enumerate(resp.iter_text()):
                            if i > 2:
                                break
            self.assertEqual(attached["n"], 0)

            with mock.patch.object(service, "attach_log_listener", side_effect=track_attach):
                with mock.patch.object(service, "current_snapshot", return_value={
                    "run_id": "demo",
                    "started": True,
                    "done": True,
                    "count": 1,
                    "completed": 1,
                    "succeeded": 1,
                    "failed": 0,
                    "active": 0,
                    "workers": [{"index": 1, "status": "succeeded", "last_log": "ok"}],
                    "failure_counts": {},
                }):
                    with client.stream("GET", "/api/runs/current/events?logs=1") as resp:
                        self.assertEqual(resp.status_code, 200)
                        for i, chunk in enumerate(resp.iter_text()):
                            if i > 2:
                                break
            self.assertGreaterEqual(attached["n"], 1)

    def test_webui_main_constructs_service_from_custom_config(self):
        with tempfile.TemporaryDirectory() as d:
            config_path = (Path(d) / "isolated-config.json").resolve()
            service = object()
            app = object()
            with mock.patch.object(
                webui_app,
                "BatchService",
                return_value=service,
            ) as service_type, mock.patch.object(
                webui_app,
                "create_app",
                return_value=app,
            ) as create, mock.patch(
                "uvicorn.run"
            ) as run_server, mock.patch(
                "builtins.print"
            ) as printed:
                rc = webui_app.main(
                    [
                        "--config",
                        str(config_path),
                        "--host",
                        "127.0.0.1",
                        "--port",
                        "33999",
                    ]
                )

            self.assertEqual(rc, 0)
            service_type.assert_called_once_with(
                config_path=config_path,
                root_dir=webui_app.ROOT_DIR,
            )
            create.assert_called_once_with(service=service)
            run_server.assert_called_once_with(
                app,
                host="127.0.0.1",
                port=33999,
                log_level="info",
            )
            printed_text = "\n".join(
                " ".join(str(value) for value in call.args)
                for call in printed.call_args_list
            )
            self.assertNotIn(str(config_path), printed_text)

    def test_webui_parser_uses_config_environment_default(self):
        with tempfile.TemporaryDirectory() as d:
            config_path = str((Path(d) / "env-config.json").resolve())
            with mock.patch.dict(os.environ, {"XAI_CONFIG_PATH": config_path}):
                args = webui_app.build_parser().parse_args([])
            self.assertEqual(args.config, config_path)


if __name__ == "__main__":
    unittest.main()

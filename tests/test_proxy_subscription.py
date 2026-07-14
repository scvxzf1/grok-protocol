# -*- coding: utf-8 -*-
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import http_batch_service as svc
import proxy_subscription as sub
import webui_app
from fastapi.testclient import TestClient


class ProxySubscriptionParseTests(unittest.TestCase):
    def test_parse_http_and_hostport_lines(self):
        nodes = sub.parse_subscription_text(
            "\n".join(
                [
                    "http://user:pass@1.2.3.4:8080",
                    "5.6.7.8:1000:u:p",
                    "socks5://u:p@9.9.9.9:1080",
                ]
            )
        )
        self.assertEqual(len(nodes), 3)
        self.assertTrue(nodes[0].usable_http)
        self.assertEqual(nodes[0].pool_line, "1.2.3.4:8080:user:pass")
        self.assertTrue(nodes[1].usable_http)
        self.assertEqual(nodes[1].pool_line, "5.6.7.8:1000:u:p")
        self.assertFalse(nodes[2].usable_http)

    def test_parse_vless_not_usable(self):
        node = sub.parse_share_link(
            "vless://uuid@example.com:443?encryption=none&security=tls#node-a"
        )
        self.assertIsNotNone(node)
        self.assertEqual(node.scheme, "vless")
        self.assertEqual(node.host, "example.com")
        self.assertEqual(node.port, 443)
        self.assertFalse(node.usable_http)
        self.assertEqual(node.pool_line, "")

    def test_import_base64_subscription_only_http_goes_to_pool(self):
        plain = "\n".join(
            [
                "vless://uuid@a.example:443?security=tls#v1",
                "http://user:pass@10.0.0.2:8080#http1",
                "ss://YWVzLTI1Ni1nY206cGFzcw@b.example:8388#ss1",
            ]
        )
        body = base64.b64encode(plain.encode("utf-8")).decode("ascii")
        with mock.patch.object(sub, "fetch_subscription_body", return_value=(plain, "base64")):
            result = sub.import_proxy_subscription("https://example.test/sub")
        self.assertEqual(result.body_kind, "base64")
        self.assertEqual(result.usable_http_count if hasattr(result, "usable_http_count") else len(result.usable_pool_lines), 1)
        self.assertEqual(result.usable_pool_lines, ["10.0.0.2:8080:user:pass"])
        self.assertTrue(any("没有可直接用于注册机" not in w for w in result.warnings) or not result.warnings)
        self.assertTrue(any(line.startswith("#") for line in result.pool_lines))
        # body unused except to keep local var
        self.assertTrue(body)

    def test_import_all_vless_warns(self):
        plain = "vless://uuid@a.example:443?security=tls#v1\nvless://uuid2@b.example:443#v2\n"
        with mock.patch.object(sub, "fetch_subscription_body", return_value=(plain, "plain")):
            result = sub.import_proxy_subscription("https://example.test/sub2")
        self.assertEqual(len(result.usable_pool_lines), 0)
        self.assertEqual(len(result.nodes), 2)
        self.assertTrue(result.warnings)


class ProxySubscriptionServiceTests(unittest.TestCase):
    def test_service_writes_pool_and_switches_mode(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "proxy_file": "proxies.txt",
                        "tui_proxy_mode": "none",
                        "proxy_subscription_local_http": "http://127.0.0.1:7890",
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            plain = "http://u:p@1.1.1.1:8080\nvless://id@x.com:443#n\n"
            with mock.patch(
                "proxy_subscription.fetch_subscription_body",
                return_value=(plain, "plain"),
            ):
                data = service.import_proxy_subscription(
                    url="https://example.test/sub",
                    write_pool=True,
                )
            self.assertEqual(data["usable_http_count"], 1)
            self.assertEqual(data["proxy_mode"], "pool")
            pool_path = root / "proxies.txt"
            text = pool_path.read_text(encoding="utf-8")
            self.assertIn("1.1.1.1:8080:u:p", text)
            disk = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(disk.get("proxy_mode"), "pool")
            self.assertNotIn("tui_proxy_mode", disk)
            self.assertEqual(disk.get("proxy_subscription_url"), "https://example.test/sub")

    def test_service_vless_never_falls_back_to_external_local_http(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "proxy_file": "proxies.txt",
                        "tui_proxy_mode": "none",
                        "proxy_subscription_local_http": "http://127.0.0.1:7890",
                    }
                ),
                encoding="utf-8",
            )
            service = svc.BatchService(config_path=cfg, root_dir=root)
            plain = "vless://uuid@a.example:443#v1\n"
            with mock.patch(
                "proxy_subscription.fetch_subscription_body",
                return_value=(plain, "base64"),
            ):
                data = service.import_proxy_subscription(
                    url="https://example.test/vless",
                    write_pool=True,
                    use_local_http_if_empty=True,
                    local_http="http://127.0.0.1:7890",
                )
            self.assertEqual(data["usable_http_count"], 0)
            self.assertFalse(data["applied_local_http"])
            self.assertEqual(data["proxy_mode"], "none")
            text = (root / "proxies.txt").read_text(encoding="utf-8")
            self.assertNotIn("http://127.0.0.1:7890", text)
            disk = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertNotIn("proxy", disk)
            self.assertEqual(disk.get("proxy_mode"), "none")
            self.assertNotIn("proxy_subscription_local_http", disk)
            self.assertNotIn("tui_proxy_mode", disk)

    def test_webui_import_subscription_api(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(json.dumps({"proxy_file": "proxies.txt"}), encoding="utf-8")
            service = svc.BatchService(config_path=cfg, root_dir=root)
            app = webui_app.create_app(service=service)
            client = TestClient(app)
            page = client.get("/config")
            self.assertEqual(page.status_code, 200)
            self.assertIn("proxy_subscription_url", page.text)
            self.assertIn("btnImportSub", page.text)
            plain = "http://a:b@2.2.2.2:9000\n"
            with mock.patch(
                "proxy_subscription.fetch_subscription_body",
                return_value=(plain, "plain"),
            ):
                r = client.post(
                    "/api/proxy-pool/import-subscription",
                    json={"url": "https://example.test/api/sub", "write_pool": True},
                )
            self.assertEqual(r.status_code, 200)
            body = r.json()
            self.assertEqual(body["usable_http_count"], 1)
            self.assertIn("2.2.2.2:9000:a:b", body.get("text") or "")


if __name__ == "__main__":
    unittest.main()

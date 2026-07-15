import unittest
from unittest.mock import patch

import xai_http_flow as flow


class DummyResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = ""

    def json(self):
        return self._payload


class CloudflareAdminCreateTests(unittest.TestCase):
    def _mailbox(self, **overrides):
        config = {"cloudflare_api_base": "https://mail.invalid.test"}
        config.update(overrides)
        return flow.CloudflareTempMailbox(config)

    def test_default_config_uses_anonymous_new_address(self):
        mailbox = self._mailbox()
        captured = {}

        def fake_request(method, url, **kwargs):
            captured.update({"method": method, "url": url, **kwargs})
            return DummyResponse({"address": "anon@invalid.test", "jwt": "default-jwt"})

        with patch.object(mailbox, "_request", side_effect=fake_request):
            address, jwt = mailbox.create()

        self.assertEqual((address, jwt), ("anon@invalid.test", "default-jwt"))
        self.assertEqual(captured["method"], "post")
        self.assertEqual(captured["url"], "https://mail.invalid.test/api/new_address")
        self.assertEqual(captured["json"], {})
        self.assertEqual(captured["headers"], {"content-type": "application/json"})

    def test_admin_new_address_uses_x_admin_auth(self):
        mailbox = self._mailbox(
            cloudflare_api_key="admin-secret",
            cloudflare_auth_mode="x-admin-auth",
            cloudflare_path_accounts="/admin/new_address",
            defaultDomains="mail.invalid.test",
        )
        captured = {}

        def fake_request(method, url, **kwargs):
            captured.update({"method": method, "url": url, **kwargs})
            return DummyResponse({"address": "xaiaaaaaaaaaa@mail.invalid.test", "jwt": "address-jwt"})

        with patch.object(flow.secrets, "choice", return_value="a"), patch.object(
            mailbox, "_request", side_effect=fake_request
        ):
            address, jwt = mailbox.create()

        self.assertEqual(address, "xaiaaaaaaaaaa@mail.invalid.test")
        self.assertEqual(jwt, "address-jwt")
        self.assertEqual(captured["url"], "https://mail.invalid.test/admin/new_address")
        self.assertEqual(
            captured["json"],
            {
                "name": "xaiaaaaaaaaaa",
                "domain": "mail.invalid.test",
                "enablePrefix": True,
            },
        )
        self.assertEqual(captured["headers"]["content-type"], "application/json")
        self.assertEqual(captured["headers"]["x-admin-auth"], "admin-secret")

    def test_anonymous_new_address_keeps_domain_without_auth(self):
        mailbox = self._mailbox(
            cloudflare_api_key="",
            cloudflare_auth_mode="none",
            cloudflare_path_accounts="api/new_address",
            defaultDomains="mail.invalid.test",
        )
        captured = {}

        def fake_request(method, url, **kwargs):
            captured.update({"method": method, "url": url, **kwargs})
            return DummyResponse({"address": "anon@mail.invalid.test", "jwt": "anon-jwt"})

        with patch.object(mailbox, "_request", side_effect=fake_request):
            address, jwt = mailbox.create()

        self.assertEqual((address, jwt), ("anon@mail.invalid.test", "anon-jwt"))
        self.assertEqual(captured["url"], "https://mail.invalid.test/api/new_address")
        self.assertEqual(captured["json"], {"domain": "mail.invalid.test"})
        self.assertEqual(captured["headers"], {"content-type": "application/json"})


if __name__ == "__main__":
    unittest.main()

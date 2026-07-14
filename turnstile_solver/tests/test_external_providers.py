from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config import SolverConfig
from src.external_providers import _build_task, solve_external
from src.models import SolveRequest
from turnstile_broker import SolveRequest as BrokerSolveRequest


def _broker_request(provider: str, proxy: str = "") -> BrokerSolveRequest:
    return BrokerSolveRequest(
        provider=provider,
        sitekey="0x4AAAA-test",
        page_url="https://example.test/sign-up",
        api_key="provider-key",
        proxy=proxy,
        action="signup",
        cdata="opaque-cdata",
    )


class ExternalProviderPayloadTests(unittest.TestCase):
    def test_2captcha_uses_official_authenticated_proxy_fields(self):
        task = _build_task(
            _broker_request("2captcha", "socks5://proxy-user:proxy-secret@8.8.8.8:1080"),
            "2captcha",
        )

        self.assertEqual(task["type"], "TurnstileTask")
        self.assertEqual(task["proxyType"], "socks5")
        self.assertEqual(task["proxyAddress"], "8.8.8.8")
        self.assertEqual(task["proxyPort"], 1080)
        self.assertEqual(task["proxyLogin"], "proxy-user")
        self.assertEqual(task["proxyPassword"], "proxy-secret")
        self.assertEqual(task["action"], "signup")
        self.assertEqual(task["data"], "opaque-cdata")

    def test_yescaptcha_uses_m1_proxy_url_and_challenge_fields(self):
        task = _build_task(
            _broker_request("yescaptcha", "http://proxy-user:proxy-secret@8.8.4.4:8080"),
            "yescaptcha",
        )

        self.assertEqual(task["type"], "TurnstileTaskProxylessM1")
        self.assertEqual(task["proxy"], "http://proxy-user:proxy-secret@8.8.4.4:8080")
        self.assertEqual(task["action"], "signup")
        self.assertEqual(task["data"], "opaque-cdata")

    def test_loopback_proxy_falls_back_to_proxyless_without_credentials(self):
        for provider in ("2captcha", "yescaptcha"):
            with self.subTest(provider=provider):
                task = _build_task(
                    _broker_request(
                        provider,
                        "http://local-user:local-secret@127.0.0.1:7890",
                    ),
                    provider,
                )
                self.assertEqual(task["type"], "TurnstileTaskProxyless")
                self.assertNotIn("proxy", task)
                self.assertNotIn("proxyPassword", task)
                self.assertNotIn("local-secret", repr(task))

    def test_capsolver_uses_authenticated_proxy_and_forwards_metadata(self):
        task = _build_task(
            _broker_request("capsolver", "http://proxy-user:proxy-secret@8.8.8.8:8080"),
            "capsolver",
        )

        self.assertEqual(task["type"], "AntiTurnstileTask")
        self.assertEqual(task["proxyType"], "http")
        self.assertEqual(task["proxyAddress"], "8.8.8.8")
        self.assertEqual(task["proxyPort"], 8080)
        self.assertEqual(task["proxyLogin"], "proxy-user")
        self.assertEqual(task["proxyPassword"], "proxy-secret")
        self.assertEqual(task["metadata"], {"action": "signup", "cdata": "opaque-cdata"})

    def test_unexpected_failure_does_not_expose_api_key_or_proxy_credentials(self):
        api_key = "private-provider-key"
        proxy = "http://private-user:private-password@8.8.8.8:8080"

        class LeakyBroker:
            def solve_sync(self, _request, _solver):
                raise RuntimeError(f"request failed: {api_key} {proxy}")

        request = SolveRequest(
            provider="2captcha",
            api_key=api_key,
            proxy=proxy,
            sitekey="0x4AAAA-test",
            page_url="https://example.test/sign-up",
        )
        with patch("src.external_providers.get_shared_broker", return_value=LeakyBroker()):
            result = solve_external(request, SolverConfig())

        self.assertFalse(result.ok)
        self.assertNotIn(api_key, result.error)
        self.assertNotIn("private-user", result.error)
        self.assertNotIn("private-password", result.error)
        self.assertEqual(result.proxy, "http://8.8.8.8:8080")


if __name__ == "__main__":
    unittest.main()

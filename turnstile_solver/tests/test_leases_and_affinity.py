from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.browser_runtime import BrowserAffinity
from src.models import FingerprintSnapshot, TokenLease, TokenLeaseError


class TokenLeaseTests(unittest.TestCase):
    def test_single_consume(self):
        lease = TokenLease.issue("token", ttl_sec=240)
        self.assertEqual(lease.consume(lease.issued_at_ms + 1), "token")
        with self.assertRaises(TokenLeaseError):
            lease.consume(lease.issued_at_ms + 2)

    def test_expired_lease_rejected(self):
        lease = TokenLease.issue("token", ttl_sec=1)
        with self.assertRaises(TokenLeaseError):
            lease.consume(lease.expires_at_ms)

    def test_fingerprint_round_trip(self):
        fp = FingerprintSnapshot.from_dict(
            {
                "user_agent": "Mozilla/5.0 Chrome/136.0.0.0",
                "navigator_languages": ["zh-CN", "zh"],
                "webdriver": False,
            }
        )
        self.assertEqual(fp.browser_major, 136)
        self.assertEqual(fp.navigator_languages, ("zh-CN", "zh"))
        self.assertFalse(fp.webdriver)


class BrowserAffinityTests(unittest.TestCase):
    def test_proxy_credentials_affect_affinity_without_exposure(self):
        first = BrowserAffinity.build(
            proxy="http://user-a:secret@127.0.0.1:8080",
            user_agent="",
            headless=False,
            locale="zh-CN",
        )
        second = BrowserAffinity.build(
            proxy="http://user-b:secret@127.0.0.1:8080",
            user_agent="",
            headless=False,
            locale="zh-CN",
        )
        self.assertNotEqual(first, second)
        self.assertNotIn("secret", repr(first))

    def test_ua_and_mode_are_strict_affinity_fields(self):
        base = dict(proxy="", locale="")
        headed = BrowserAffinity.build(user_agent="UA-1", headless=False, **base)
        headless = BrowserAffinity.build(user_agent="UA-1", headless=True, **base)
        other_ua = BrowserAffinity.build(user_agent="UA-2", headless=False, **base)
        self.assertNotEqual(headed, headless)
        self.assertNotEqual(headed, other_ua)

    def test_browser_binary_and_expected_platform_are_affinity_fields(self):
        base = dict(
            proxy="",
            user_agent="UA",
            headless=False,
            locale="zh-CN",
        )
        linux = BrowserAffinity.build(
            browser_path="/usr/bin/google-chrome",
            expected_platform="Linux x86_64",
            expected_client_hint_platform="Linux",
            expected_browser_major=136,
            **base,
        )
        other = BrowserAffinity.build(
            browser_path="/opt/chrome/chrome",
            expected_platform="Linux x86_64",
            expected_client_hint_platform="Linux",
            expected_browser_major=136,
            **base,
        )
        self.assertNotEqual(linux, other)

    def test_no_sandbox_is_an_explicit_affinity_field(self):
        base = dict(
            proxy="",
            user_agent="UA",
            headless=False,
            locale="zh-CN",
        )
        sandboxed = BrowserAffinity.build(no_sandbox=False, **base)
        unsandboxed = BrowserAffinity.build(no_sandbox=True, **base)
        self.assertNotEqual(sandboxed, unsandboxed)


if __name__ == "__main__":
    unittest.main()

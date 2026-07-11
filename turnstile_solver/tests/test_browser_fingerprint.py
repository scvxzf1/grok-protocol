from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.browser_worker import (
    _client_hint_browser_majors,
    _parse_high_entropy_cdp_response,
    read_browser_fingerprint,
)


class FakeCdpPage:
    def __init__(self):
        self.cdp_call = None

    def run_js(self, _script):
        return {
            "user_agent": "Mozilla/5.0 Chrome/136.0.0.0",
            "user_agent_data": {
                "brands": [
                    {"brand": "Chromium", "version": "136"},
                    {"brand": "Google Chrome", "version": "136"},
                ],
                "platform": "Linux",
            },
            "navigator_language": "zh-CN",
            "navigator_languages": ["zh-CN", "zh"],
            "platform": "Linux x86_64",
        }

    def run_cdp(self, method, **kwargs):
        self.cdp_call = (method, kwargs)
        return {
            "result": {
                "type": "object",
                "value": {
                    "fullVersionList": [
                        {"brand": "Chromium", "version": "136.0.7103.92"},
                        {"brand": "Google Chrome", "version": "136.0.7103.92"},
                    ],
                    "platformVersion": "6.8.0",
                    "architecture": "x86",
                    "bitness": "64",
                },
            }
        }


class BrowserFingerprintTests(unittest.TestCase):
    def test_cdp_high_entropy_result_is_awaited_parsed_and_merged(self):
        page = FakeCdpPage()
        fingerprint = read_browser_fingerprint(page)
        method, kwargs = page.cdp_call
        self.assertEqual(method, "Runtime.evaluate")
        self.assertTrue(kwargs["awaitPromise"])
        self.assertTrue(kwargs["returnByValue"])
        self.assertIn("'platform'", kwargs["expression"])
        self.assertEqual(fingerprint.user_agent_data["architecture"], "x86")
        brands, full_versions = _client_hint_browser_majors(fingerprint.user_agent_data)
        self.assertEqual(brands, [136])
        self.assertEqual(full_versions, [136])

    def test_cdp_parser_rejects_malformed_structure(self):
        with self.assertRaisesRegex(ValueError, "result.value"):
            _parse_high_entropy_cdp_response({"result": {"type": "object"}})

    def test_fake_page_without_run_cdp_records_clear_missing_reason(self):
        class FakePageWithoutCdp:
            def run_js(self, _script):
                return {
                    "user_agent": "Mozilla/5.0 Chrome/136.0.0.0",
                    "user_agent_data": {
                        "brands": [{"brand": "Chromium", "version": "136"}],
                        "platform": "Linux",
                    },
                }

        fingerprint = read_browser_fingerprint(FakePageWithoutCdp())
        self.assertEqual(
            fingerprint.user_agent_data["_high_entropy_error"],
            "page.run_cdp is unavailable",
        )
        _, full_versions = _client_hint_browser_majors(fingerprint.user_agent_data)
        self.assertEqual(full_versions, [])


if __name__ == "__main__":
    unittest.main()

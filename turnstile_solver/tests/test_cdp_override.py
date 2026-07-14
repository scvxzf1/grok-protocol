from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.browser_runtime import _require_browser_version
from src.browser_worker import BrowserWorker, build_cdp_user_agent_metadata
from src.config import SolverConfig
from src.models import SolveRequest


class FakePage:
    def __init__(self):
        self.events = []
        self.wait = Mock()

    def run_cdp(self, method, **kwargs):
        self.events.append(("cdp", method, kwargs))
        if method == "Runtime.evaluate":
            return {
                "result": {
                    "value": {
                        "fullVersionList": [
                            {"brand": "Chromium", "version": "136.0.7103.92"}
                        ],
                        "platformVersion": "0.0.0",
                        "architecture": "x86",
                        "bitness": "64",
                    }
                }
            }
        return {}

    def get(self, url):
        self.events.append(("get", url))

    def run_js(self, script):
        if "cf-turnstile-response" in script:
            return "t" * 100
        if "user_agent_data" in script:
            return {
                "user_agent": "Mozilla/5.0 Chrome/136.0.0.0",
                "user_agent_data": {
                    "brands": [{"brand": "Chromium", "version": "136"}],
                    "platform": "Linux",
                },
                "accept_language": "zh-CN, zh",
                "navigator_language": "zh-CN",
                "navigator_languages": ["zh-CN", "zh"],
                "platform": "Linux x86_64",
            }
        return False

    def cookies(self, **_kwargs):
        return []


class CdpOverrideTests(unittest.TestCase):
    def test_override_happens_before_navigation_with_complete_metadata(self):
        page = FakePage()
        worker = BrowserWorker(SolverConfig(strict_fingerprint=True))
        request = SolveRequest(
            user_agent="Mozilla/5.0 Chrome/136.0.0.0",
            accept_language="zh-CN,zh;q=0.9",
            expected_platform="Linux x86_64",
            expected_client_hint_platform="Linux",
            expected_browser_major=136,
            timeout_sec=5,
        )
        with patch("src.browser_worker.click_email_signup_entry", return_value=False):
            result = worker.solve_on_page(
                page,
                request,
                browser_version="136.0.7103.92",
            )
        self.assertTrue(result.ok)
        self.assertEqual(page.events[0][0:2], ("cdp", "Emulation.setUserAgentOverride"))
        get_index = next(i for i, event in enumerate(page.events) if event[0] == "get")
        self.assertGreater(get_index, 0)
        metadata = page.events[0][2]["userAgentMetadata"]
        self.assertEqual(metadata["brands"][0], {"brand": "Chromium", "version": "136"})
        self.assertEqual(metadata["brands"][1], {"brand": "Google Chrome", "version": "136"})
        self.assertEqual(metadata["fullVersionList"][0]["version"], "136.0.7103.92")
        self.assertEqual(metadata["platform"], "Linux")
        self.assertEqual(metadata["architecture"], "x86")
        self.assertEqual(metadata["bitness"], "64")
        self.assertFalse(metadata["mobile"])
        self.assertFalse(metadata["wow64"])
        self.assertNotIn("cookies", result.extras)

    def test_metadata_uses_full_browser_version(self):
        metadata = build_cdp_user_agent_metadata(
            browser_version="136.0.7103.92",
            client_hint_platform="Linux",
        )
        self.assertEqual(metadata["brands"][0]["version"], "136")
        self.assertEqual(metadata["fullVersionList"][2]["version"], "99.0.0.0")

    def test_browser_binary_major_mismatch_is_rejected(self):
        with patch(
            "src.browser_runtime.detect_chrome_full_version",
            return_value="135.0.7049.95",
        ):
            with self.assertRaisesRegex(RuntimeError, "expected=136"):
                _require_browser_version("/opt/chrome/chrome", 136)

    def test_explicit_sitekey_injects_widget_without_email_entry_click(self):
        class ExplicitWidgetPage(FakePage):
            def __init__(self):
                super().__init__()
                self.injected_scripts = []

            def run_js(self, script):
                if "const sitekey =" in script and "turnstile.render" in script:
                    self.injected_scripts.append(script)
                    return {"ok": True, "reason": "rendered", "widgetId": "widget-1"}
                return super().run_js(script)

        page = ExplicitWidgetPage()
        worker = BrowserWorker(SolverConfig(strict_fingerprint=True))
        request = SolveRequest(
            user_agent="Mozilla/5.0 Chrome/136.0.0.0",
            accept_language="zh-CN,zh;q=0.9",
            expected_platform="Linux x86_64",
            expected_client_hint_platform="Linux",
            expected_browser_major=136,
            sitekey="site-key-test",
            action="signup",
            cdata="opaque-cdata",
            timeout_sec=5,
        )
        with patch("src.browser_worker.click_email_signup_entry") as email_click:
            result = worker.solve_on_page(
                page,
                request,
                browser_version="136.0.7103.92",
            )
        self.assertTrue(result.ok)
        email_click.assert_not_called()
        self.assertEqual(len(page.injected_scripts), 1)
        script = page.injected_scripts[0]
        self.assertIn('const sitekey = "site-key-test"', script)
        self.assertIn('const action = "signup"', script)
        self.assertIn('const cdata = "opaque-cdata"', script)
        self.assertIn("api.js?render=explicit", script)
        self.assertIn("window.__xaiTsWidgetId", script)



    def test_timeout_without_uadata_reports_token_timeout_not_platform_mismatch(self):
        class EmptyUaDataPage(FakePage):
            def run_js(self, script):
                if "cf-turnstile-response" in script:
                    return ""
                if "user_agent_data" in script:
                    return {
                        "user_agent": "Mozilla/5.0 Chrome/136.0.0.0",
                        "user_agent_data": {},
                        "accept_language": "zh-CN, zh",
                        "navigator_language": "zh-CN",
                        "navigator_languages": ["zh-CN", "zh"],
                        "platform": "Linux x86_64",
                    }
                return False

            def run_cdp(self, method, **kwargs):
                self.events.append(("cdp", method, kwargs))
                if method == "Runtime.evaluate":
                    raise RuntimeError("navigator.userAgentData unavailable")
                return {}

        page = EmptyUaDataPage()
        worker = BrowserWorker(SolverConfig(strict_fingerprint=True))
        request = SolveRequest(
            user_agent="Mozilla/5.0 Chrome/136.0.0.0",
            accept_language="zh-CN,zh;q=0.9",
            expected_platform="Linux x86_64",
            expected_client_hint_platform="Linux",
            expected_browser_major=136,
            timeout_sec=1,
        )
        with patch("src.browser_worker.click_email_signup_entry", return_value=False):
            result = worker.solve_on_page(
                page,
                request,
                browser_version="136.0.7103.92",
            )
        self.assertFalse(result.ok)
        self.assertIn("未捕获到可用 Turnstile token", result.error or "")
        self.assertNotIn("UAData platform 不一致", result.error or "")
        self.assertIn("fingerprint_warning", result.extras)

    def test_success_with_empty_uadata_still_fails_strict_check(self):
        class EmptyButTokenPage(FakePage):
            def run_js(self, script):
                if "cf-turnstile-response" in script:
                    return "t" * 100
                if "user_agent_data" in script:
                    return {
                        "user_agent": "Mozilla/5.0 Chrome/136.0.0.0",
                        "user_agent_data": {},
                        "accept_language": "zh-CN, zh",
                        "navigator_language": "zh-CN",
                        "navigator_languages": ["zh-CN", "zh"],
                        "platform": "Linux x86_64",
                    }
                return False

            def run_cdp(self, method, **kwargs):
                self.events.append(("cdp", method, kwargs))
                if method == "Runtime.evaluate":
                    raise RuntimeError("navigator.userAgentData unavailable")
                return {}

        page = EmptyButTokenPage()
        worker = BrowserWorker(SolverConfig(strict_fingerprint=True))
        request = SolveRequest(
            user_agent="Mozilla/5.0 Chrome/136.0.0.0",
            accept_language="zh-CN,zh;q=0.9",
            expected_platform="Linux x86_64",
            expected_client_hint_platform="Linux",
            expected_browser_major=136,
            timeout_sec=5,
        )
        with patch("src.browser_worker.click_email_signup_entry", return_value=False):
            result = worker.solve_on_page(
                page,
                request,
                browser_version="136.0.7103.92",
            )
        self.assertFalse(result.ok)
        self.assertIn("UAData platform 不可用", result.error or "")


if __name__ == "__main__":
    unittest.main()

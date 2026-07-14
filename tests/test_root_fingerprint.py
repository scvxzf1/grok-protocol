import sys
import unittest

import xai_http_flow as flow


class _Session:
    def __init__(self):
        self.headers = {}


class RootFingerprintTests(unittest.TestCase):
    def test_default_profile_matches_runtime_os(self):
        profile = flow.DEFAULT_FINGERPRINT
        # Stable fallback profile used when no local Chrome is available.
        self.assertEqual(profile.browser_major, "136")
        self.assertEqual(
            profile.sec_ch_ua,
            '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
        )
        self.assertIn("Google Chrome", profile.sec_ch_ua)
        if sys.platform.startswith("linux"):
            self.assertIn("X11; Linux x86_64", profile.user_agent)
            self.assertEqual(profile.navigator_platform, "Linux x86_64")
            self.assertEqual(profile.client_hint_platform, "Linux")
        elif sys.platform == "darwin":
            self.assertIn("Macintosh; Intel Mac OS X 10_15_7", profile.user_agent)
            self.assertEqual(profile.navigator_platform, "MacIntel")
            self.assertEqual(profile.client_hint_platform, "macOS")
        else:
            self.assertIn("Windows NT 10.0; Win64; x64", profile.user_agent)
            self.assertEqual(profile.navigator_platform, "Win32")
            self.assertEqual(profile.client_hint_platform, "Windows")

    def test_client_applies_profile_headers_before_first_request(self):
        session = _Session()
        client = flow.BrowserlessXAIClient(session=session)
        profile = flow.build_runtime_fingerprint_profile()
        self.assertEqual(session.headers["user-agent"], profile.user_agent)
        self.assertEqual(session.headers["accept-language"], profile.accept_language)
        self.assertEqual(session.headers["sec-ch-ua"], profile.sec_ch_ua)
        self.assertEqual(
            session.headers["sec-ch-ua-platform"],
            f'"{profile.client_hint_platform}"',
        )
        self.assertEqual(client.fingerprint.browser_major, profile.browser_major)
        self.assertEqual(client.fingerprint.user_agent, profile.user_agent)

    def test_local_platform_mismatch_fails_closed(self):
        profile = flow.DEFAULT_FINGERPRINT
        with self.assertRaises(flow.VerificationRequiredError):
            flow._validate_local_fingerprint(
                expected_user_agent=profile.user_agent,
                observed_user_agent=profile.user_agent,
                expected_language=profile.accept_language,
                observed_language=profile.accept_language.split(",", 1)[0],
                expected_platform=profile.navigator_platform,
                observed_platform="mismatch",
                expected_client_hint_platform=profile.client_hint_platform,
                observed_client_hint_platform=profile.client_hint_platform,
                expected_browser_major=profile.browser_major,
                observed_browser_major=profile.browser_major,
            )


if __name__ == "__main__":
    unittest.main()

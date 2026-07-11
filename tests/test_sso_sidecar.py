# -*- coding: utf-8 -*-
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sso_to_auth_json as conv
import xai_http_flow as flow


class SsoSidecarTests(unittest.TestCase):
    def test_sso_file_name_matches_credential_stem(self):
        self.assertEqual(conv.credential_file_name("a@b.com"), "xai-a@b.com.json")
        self.assertEqual(conv.sso_file_name("a@b.com"), "xai-a@b.com.sso")

    def test_write_sso_file_and_save_sso_record(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path = conv.write_sso_file(root / conv.sso_file_name("u@x.ai"), "sso-cookie-value")
            self.assertEqual(path.name, "xai-u@x.ai.sso")
            self.assertEqual(path.read_text(encoding="utf-8").strip(), "sso-cookie-value")

            saved = flow.save_sso_record(str(root), email="u@x.ai", sso="another-sso")
            self.assertTrue(saved.endswith("xai-u@x.ai.sso"))
            self.assertEqual(Path(saved).read_text(encoding="utf-8").strip(), "another-sso")

    def test_process_auth_one_writes_sso_sidecar(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            fake_token = {
                "access_token": "a",
                "refresh_token": "r",
                "email": "u@x.ai",
                "sub": "sub-1",
            }
            with mock.patch.object(conv, "sso_to_token", return_value=fake_token), mock.patch.object(
                conv, "build_xai_credential", return_value=fake_token
            ):
                ok = conv.process_auth_one(1, 1, "cookie-sso", root, "u@x.ai")
            self.assertTrue(ok)
            self.assertTrue((root / "xai-u@x.ai.json").is_file())
            self.assertEqual((root / "xai-u@x.ai.sso").read_text(encoding="utf-8").strip(), "cookie-sso")


if __name__ == "__main__":
    unittest.main()

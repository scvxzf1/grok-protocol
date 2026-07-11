# -*- coding: utf-8 -*-
from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from turnstile_solver.src.config import SolverConfig


class BrowserPathDetectTests(unittest.TestCase):
    def test_resolved_browser_path_auto_detects_when_unset(self):
        config = SolverConfig(strict_fingerprint=True, browser_path="")
        fake = "/usr/bin/google-chrome-stable"
        with mock.patch(
            "turnstile_solver.src.config.detect_system_chrome_path",
            return_value=fake,
        ), mock.patch.object(Path, "is_file", return_value=True), mock.patch(
            "os.access", return_value=True
        ), mock.patch.object(Path, "resolve", return_value=Path(fake)):
            path = config.resolved_browser_path()
        self.assertEqual(path, fake)

    def test_resolved_browser_path_prefers_explicit_config(self):
        config = SolverConfig(strict_fingerprint=True, browser_path="/custom/chrome")
        with mock.patch.object(Path, "is_file", return_value=True), mock.patch(
            "os.access", return_value=True
        ), mock.patch.object(Path, "resolve", return_value=Path("/custom/chrome")):
            path = config.resolved_browser_path()
        self.assertEqual(path, "/custom/chrome")


if __name__ == "__main__":
    unittest.main()

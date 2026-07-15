# -*- coding: utf-8 -*-
from __future__ import annotations

import unittest
import os
import tempfile
from pathlib import Path
from unittest import mock

from turnstile_solver.src.config import (
    SolverConfig,
    detect_chrome_full_version,
    detect_chrome_major,
    detect_system_chrome_path,
)


class BrowserPathDetectTests(unittest.TestCase):
    @staticmethod
    def _make_windows_chrome(root: Path) -> Path:
        chrome = root / "Google" / "Chrome" / "Application" / "chrome.exe"
        chrome.parent.mkdir(parents=True, exist_ok=True)
        chrome.write_bytes(b"test chrome fixture")
        chrome.chmod(0o755)
        return chrome

    def test_detect_system_chrome_path_finds_program_files_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Program Files"
            chrome = self._make_windows_chrome(root)
            with mock.patch.dict(os.environ, {"ProgramFiles": str(root)}, clear=True):
                detected = detect_system_chrome_path()
        self.assertEqual(detected, str(chrome.resolve(strict=False)))

    def test_detect_system_chrome_path_falls_back_to_local_app_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / "LocalAppData"
            chrome = self._make_windows_chrome(local)
            with mock.patch.dict(
                os.environ,
                {
                    "ProgramFiles": str(Path(tmp) / "missing-program-files"),
                    "ProgramFiles(x86)": str(Path(tmp) / "missing-program-files-x86"),
                    "LOCALAPPDATA": str(local),
                },
                clear=True,
            ):
                detected = detect_system_chrome_path()
        self.assertEqual(detected, str(chrome.resolve(strict=False)))

    def test_detect_chrome_version_prefers_windows_file_metadata(self):
        with mock.patch(
            "turnstile_solver.src.config._windows_file_version",
            return_value="150.0.7871.101",
        ), mock.patch(
            "turnstile_solver.src.config.subprocess.check_output"
        ) as check_output:
            full = detect_chrome_full_version("C:/fixture/chrome.exe")
            major = detect_chrome_major("C:/fixture/chrome.exe")
        self.assertEqual(full, "150.0.7871.101")
        self.assertEqual(major, "150")
        check_output.assert_not_called()

    def test_detect_chrome_version_parses_command_output_fallback(self):
        with mock.patch(
            "turnstile_solver.src.config._windows_file_version",
            return_value="",
        ), mock.patch(
            "turnstile_solver.src.config.subprocess.check_output",
            return_value="Google Chrome 142.0.7444.176",
        ):
            self.assertEqual(
                detect_chrome_full_version("/fixture/google-chrome"),
                "142.0.7444.176",
            )
            self.assertEqual(detect_chrome_major("/fixture/google-chrome"), "142")

    def test_resolved_browser_path_auto_detects_when_unset(self):
        config = SolverConfig(strict_fingerprint=True, browser_path="")
        fake = str((Path.cwd() / "google-chrome-stable").resolve())
        with mock.patch(
            "turnstile_solver.src.config.detect_system_chrome_path",
            return_value=fake,
        ), mock.patch.object(Path, "is_file", return_value=True), mock.patch(
            "os.access", return_value=True
        ), mock.patch.object(Path, "resolve", return_value=Path(fake)):
            path = config.resolved_browser_path()
        self.assertEqual(path, fake)

    def test_resolved_browser_path_prefers_explicit_config(self):
        fake = str((Path.cwd() / "custom-chrome").resolve())
        config = SolverConfig(strict_fingerprint=True, browser_path=fake)
        with mock.patch.object(Path, "is_file", return_value=True), mock.patch(
            "os.access", return_value=True
        ), mock.patch.object(Path, "resolve", return_value=Path(fake)):
            path = config.resolved_browser_path()
        self.assertEqual(path, fake)


if __name__ == "__main__":
    unittest.main()

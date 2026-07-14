from __future__ import annotations

import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.browser_runtime import BrowserAffinity, BrowserSlot
from src.browser_worker import BrowserWorker
from src.config import SolverConfig
from src.models import SolveRequest, SolveResult
from src.service import SolverService


def _slot(headless: bool) -> BrowserSlot:
    config = SolverConfig(strict_fingerprint=False, headless=headless)
    affinity = BrowserAffinity.build(
        proxy="",
        user_agent="",
        headless=headless,
        locale="",
    )
    return BrowserSlot(
        config,
        BrowserWorker(config),
        affinity=affinity,
        upstream_proxy="",
        user_agent="",
    )


class NativeHeadlessTests(unittest.TestCase):
    def test_solver_modules_import_when_launched_from_solver_directory(self):
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                "from src.browser_runtime import PersistentBrowserPool; "
                "from src.browser_worker import BrowserWorker",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_headless_affinity_stays_native_headless(self):
        slot = _slot(True)
        self.assertTrue(slot._resolve_launch_headless())
        self.assertEqual(slot._browser_mode, "headless-new")

    def test_headed_affinity_stays_headed(self):
        slot = _slot(False)
        self.assertFalse(slot._resolve_launch_headless())
        self.assertEqual(slot._browser_mode, "headed")

    def test_service_routes_local_solves_through_bounded_pool(self):
        service = SolverService(SolverConfig(strict_fingerprint=False))
        service.pool.solve = Mock(return_value=SolveResult(ok=False, error="fixture"))

        result = service.solve(SolveRequest(provider="local", timeout_sec=10))

        self.assertFalse(result.ok)
        service.pool.solve.assert_called_once()
        service.close()

    def test_slot_close_unregisters_and_reaps_its_browser_tree(self):
        class Browser:
            def __init__(self):
                self.quit_called = False

            def quit(self):
                self.quit_called = True

        slot = _slot(True)
        browser = Browser()
        slot.browser = browser
        slot.browser_pid = 424242
        slot._registry_registered = True
        with tempfile.TemporaryDirectory() as root:
            slot.profile_dir = str(Path(root) / "xai-ts-chrome-fixture")
            Path(slot.profile_dir).mkdir()
            with patch("src.browser_runtime._reap_chrome_process_tree") as reap, patch(
                "src.browser_runtime.unregister_project_browser"
            ) as unregister, patch("src.browser_runtime.stop_browser_proxy"):
                slot.close()

        self.assertTrue(browser.quit_called)
        reap.assert_called_once_with(424242, timeout_sec=2.0)
        unregister.assert_called_once_with(424242, slot.profile_dir)


if __name__ == "__main__":
    unittest.main()

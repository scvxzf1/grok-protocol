from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import http_batch_service as service


class BrowserCleanupScopeTests(unittest.TestCase):
    def test_cleanup_never_invokes_broad_process_patterns(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            stale = root / "xai-ts-chrome-stale"
            stale.mkdir()
            os.utime(stale, (1, 1))
            active = root / "xai-ts-chrome-active"
            active.mkdir()
            os.utime(active, (1, 1))
            similarly_named = root / "xai-ts-probe-unowned"
            similarly_named.mkdir()
            daily = root / "daily-chrome-profile"
            daily.mkdir()
            pkill = Mock()
            with patch.object(
                service,
                "terminate_project_browser_trees",
                return_value={"browser_roots": 1, "profiles_removed": 0},
            ), patch.object(
                service,
                "registered_project_browsers",
                return_value=[{"profile_dir": str(active)}],
            ), patch.object(service, "_kill_orphan_turnstile_solvers", return_value=0), patch.object(
                service,
                "_reap_zombie_children",
                return_value=0,
            ), patch.object(
                service,
                "browser_health_status",
                return_value={
                    "chrome_count": 1,
                    "playwright_count": 0,
                    "solver_count": 0,
                    "zombie_chrome_count": 0,
                },
            ):
                result = service.cleanup_browser_residues(
                    temp_root=root,
                    kill_playwright=True,
                    kill_all_chrome=True,
                    pkill_fn=pkill,
                )

            pkill.assert_not_called()
            self.assertFalse(stale.exists())
            self.assertTrue(active.exists())
            self.assertTrue(similarly_named.exists())
            self.assertTrue(daily.exists())
            self.assertEqual(result["killed_chrome"], 1)
            self.assertEqual(result["killed_playwright"], 0)


if __name__ == "__main__":
    unittest.main()

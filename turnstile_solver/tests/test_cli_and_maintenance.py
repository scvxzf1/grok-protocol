from __future__ import annotations

import sys
import threading
import time
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.__main__ import (
    _apply_serve_overrides,
    _current_os_fingerprint,
    _strict_solve_fingerprint,
    build_parser,
    main,
)
from src.browser_runtime import PersistentBrowserPool
from src.config import SolverConfig
from src.models import SolveResult


class CliDefaultsTests(unittest.TestCase):
    def test_public_json_masks_proxy_while_cli_keeps_internal_raw_value(self):
        raw_proxy = "http://proxy-user:proxy-password@192.0.2.10:8080"
        result = SolveResult(ok=True, token="token", proxy=raw_proxy)

        self.assertEqual(result.proxy, raw_proxy)
        self.assertEqual(result.to_dict()["proxy"], "http://192.0.2.10:8080")

    def test_defaults_use_canonical_reduced_chrome136_profile(self):
        values = _current_os_fingerprint("136.0.7103.113")
        self.assertIn("Chrome/136.0.0.0", values["user_agent"])
        self.assertEqual(values["expected_browser_major"], 136)
        self.assertEqual(values["accept_language"], "zh-CN,zh;q=0.9,en;q=0.8")

    def test_strict_cli_rejects_noncanonical_browser_binary(self):
        args = build_parser().parse_args(["solve"])
        config = SolverConfig(browser_path="/test/chrome")
        with patch.object(config, "resolved_browser_path", return_value="/test/chrome"), patch(
            "src.__main__._read_browser_full_version", return_value="137.0.0.0"
        ):
            with self.assertRaisesRegex(ValueError, "expected=136, actual=137"):
                _strict_solve_fingerprint(args, config)

    def test_strict_cli_rejects_explicit_noncanonical_override(self):
        args = build_parser().parse_args(["solve", "--accept-language", "en-US,en;q=0.9"])
        config = SolverConfig(browser_path="/test/chrome")
        with patch.object(config, "resolved_browser_path", return_value="/test/chrome"), patch(
            "src.__main__._read_browser_full_version", return_value="136.0.7103.113"
        ):
            with self.assertRaisesRegex(ValueError, "accept_language override"):
                _strict_solve_fingerprint(args, config)

    def test_serve_concurrency_overrides_are_applied(self):
        args = build_parser().parse_args(
            [
                "serve",
                "--max-concurrency",
                "4",
                "--external-provider-workers",
                "30",
                "--external-queue-limit",
                "90",
                "--submit-workers",
                "8",
            ]
        )
        config = SolverConfig()
        _apply_serve_overrides(args, config)
        self.assertEqual(config.max_concurrency, 4)
        self.assertEqual(config.external_provider_workers, 30)
        self.assertEqual(config.external_queue_limit, 90)
        self.assertEqual(config.submit_workers, 8)

    def test_serve_closes_service_after_uvicorn_returns(self):
        service = Mock()
        uvicorn_run = Mock()
        uvicorn_module = types.SimpleNamespace(run=uvicorn_run)
        with patch("src.__main__.SolverService", return_value=service), patch(
            "src.api.create_app", return_value="app"
        ), patch.dict(sys.modules, {"uvicorn": uvicorn_module}):
            exit_code = main(["serve"])

        self.assertEqual(exit_code, 0)
        uvicorn_run.assert_called_once()
        service.close.assert_called_once()


class BrowserPoolMaintenanceTests(unittest.TestCase):
    def test_maintenance_reaps_idle_slot_and_close_stops_thread(self):
        config = SolverConfig(
            browser_idle_ttl_sec=1,
            browser_maintenance_interval_sec=0.05,
        )
        pool = PersistentBrowserPool(config, worker=object())

        class Affinity:
            affinity_id = "test-affinity"

        class Slot:
            slot_id = "idle-slot"
            affinity = Affinity()
            last_used_monotonic = time.monotonic() - 10

            def __init__(self):
                self.closed = threading.Event()

            def close(self):
                self.closed.set()

        slot = Slot()
        with pool._condition:
            pool._slots[slot.slot_id] = slot
        pool.start()
        thread = pool._maintenance_thread
        self.assertTrue(slot.closed.wait(0.5))
        pool.close()
        self.assertIsNotNone(thread)
        self.assertFalse(thread.is_alive())
        self.assertEqual(pool.stats.recycle_reasons.get("idle_ttl"), 1)


if __name__ == "__main__":
    unittest.main()

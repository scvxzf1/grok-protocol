from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.browser_runtime import PersistentBrowserPool, classify_turnstile_failure
from src.config import SolverConfig
from src.models import SolveRequest, SolveResult


class _FakeSlot:
    def __init__(self, slot_id: str, result: SolveResult):
        self.slot_id = slot_id
        self.result = result

    def solve(self, _request: SolveRequest) -> SolveResult:
        return self.result


def _challenge_failure(code: str) -> SolveResult:
    return SolveResult(
        ok=False,
        error=f"Turnstile challenge error {code}",
        elapsed_ms=30_000,
        extras={"turnstile_error": code},
    )


class TurnstileFailureClassificationTests(unittest.TestCase):
    def test_600010_is_retryable_and_rebuilds_browser(self):
        diagnosis = classify_turnstile_failure(_challenge_failure("600010"))
        self.assertEqual(diagnosis["category"], "turnstile_challenge_transient")
        self.assertEqual(diagnosis["error_code"], "600010")
        self.assertTrue(diagnosis["retryable"])
        self.assertEqual(diagnosis["rebuild"], "browser")

    def test_documented_timeout_uses_fresh_context(self):
        diagnosis = classify_turnstile_failure(_challenge_failure("110600"))
        self.assertTrue(diagnosis["retryable"])
        self.assertEqual(diagnosis["rebuild"], "context")

    def test_configuration_error_is_not_retried(self):
        diagnosis = classify_turnstile_failure(_challenge_failure("110100"))
        self.assertEqual(diagnosis["category"], "turnstile_configuration")
        self.assertFalse(diagnosis["retryable"])


class PersistentBrowserRetryTests(unittest.TestCase):
    def _pool(self, attempts: int = 2) -> PersistentBrowserPool:
        config = SolverConfig(
            strict_fingerprint=False,
            browser_solve_max_attempts=attempts,
            browser_retry_backoff_sec=0,
        )
        pool = PersistentBrowserPool(config)
        pool.start = Mock()
        pool._release = Mock()
        return pool

    def test_transient_challenge_recycles_and_recovers_inside_deadline(self):
        pool = self._pool()
        first = _FakeSlot("slot-1", _challenge_failure("600010"))
        second = _FakeSlot(
            "slot-2",
            SolveResult(ok=True, token="t" * 100, elapsed_ms=1200),
        )
        pool._acquire = Mock(side_effect=[first, second])

        result = pool.solve(SolveRequest(timeout_sec=90))

        self.assertTrue(result.ok)
        self.assertEqual(result.extras["retry_count"], 1)
        self.assertEqual(result.extras["solve_attempt"], 2)
        self.assertEqual(
            result.extras["retry_history"][0]["error_code"],
            "600010",
        )
        self.assertEqual(pool.stats.retry_attempts, 1)
        self.assertEqual(pool.stats.retry_successes, 1)
        first_release = pool._release.call_args_list[0]
        self.assertEqual(
            first_release.kwargs["force_recycle_reason"],
            "turnstile_challenge_600010_rebuild",
        )
        self.assertIs(pool._release.call_args_list[-1].args[0], second)

    def test_retry_exhaustion_has_stable_web_diagnostics(self):
        pool = self._pool()
        pool._acquire = Mock(
            side_effect=[
                _FakeSlot("slot-1", _challenge_failure("600010")),
                _FakeSlot("slot-2", _challenge_failure("600010")),
            ]
        )

        result = pool.solve(SolveRequest(timeout_sec=90))

        self.assertFalse(result.ok)
        self.assertEqual(result.extras["failure_category"], "turnstile_challenge_transient")
        self.assertEqual(result.extras["error_code"], "600010")
        self.assertEqual(result.extras["solve_attempt"], 2)
        self.assertEqual(result.extras["retry_count"], 1)
        self.assertEqual(pool.stats.failed, 1)
        self.assertEqual(pool.stats.last_failure_category, "turnstile_challenge_transient")
        self.assertEqual(pool.stats.last_error_code, "600010")
        self.assertEqual(
            pool.stats.failure_categories["turnstile_challenge_transient"],
            1,
        )
        self.assertEqual(
            pool._release.call_args_list[-1].kwargs["force_recycle_reason"],
            "turnstile_challenge_600010_rebuild",
        )

    def test_configuration_error_stops_after_first_context(self):
        pool = self._pool(attempts=3)
        slot = _FakeSlot("slot-1", _challenge_failure("110100"))
        pool._acquire = Mock(return_value=slot)

        result = pool.solve(SolveRequest(timeout_sec=90))

        self.assertFalse(result.ok)
        self.assertEqual(result.extras["failure_category"], "turnstile_configuration")
        self.assertEqual(pool._acquire.call_count, 1)
        self.assertEqual(pool.stats.retry_attempts, 0)

    def test_retryable_timeout_reuses_process_but_gets_new_context(self):
        pool = self._pool()
        first = _FakeSlot("slot-1", _challenge_failure("110600"))
        second = _FakeSlot(
            "slot-1",
            SolveResult(ok=True, token="t" * 100, elapsed_ms=500),
        )
        pool._acquire = Mock(side_effect=[first, second])

        result = pool.solve(SolveRequest(timeout_sec=90))

        self.assertTrue(result.ok)
        first_release = pool._release.call_args_list[0]
        self.assertEqual(first_release.kwargs["force_recycle_reason"], "")


if __name__ == "__main__":
    unittest.main()

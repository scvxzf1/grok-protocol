import asyncio
import concurrent.futures
import threading
import time
import unittest
from unittest import mock

from turnstile_broker import (
    BrokerQueueFull,
    FingerprintProfile,
    SolveRequest,
    SolveResult,
    TokenLease,
    TokenLeaseError,
    TurnstileBroker,
    build_chrome_brand_version_list,
    serialize_sec_ch_ua,
)
import xai_http_flow as flow


class TurnstileBrokerTests(unittest.TestCase):
    def test_chrome_brand_list_uses_full_version_and_product_brand(self):
        reduced = build_chrome_brand_version_list("136")
        full = build_chrome_brand_version_list("136.0.7103.92", full_version=True)

        self.assertEqual([brand for brand, _version in reduced], [
            "Chromium",
            "Google Chrome",
            "Not.A/Brand",
        ])
        self.assertEqual(dict(reduced)["Chromium"], "136")
        self.assertEqual(dict(reduced)["Google Chrome"], "136")
        self.assertEqual(dict(full)["Chromium"], "136.0.7103.92")
        self.assertEqual(dict(full)["Google Chrome"], "136.0.7103.92")
        self.assertEqual(
            serialize_sec_ch_ua("136"),
            '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
        )

    def test_token_lease_is_single_use_and_uses_240_second_default(self):
        result = SolveResult("t" * 100, "local", 10.0, 1)
        lease = TokenLease(result)
        self.assertEqual(lease.expires_at, 250.0)
        self.assertEqual(lease.consume(now=20.0), "t" * 100)
        with self.assertRaises(TokenLeaseError):
            lease.consume(now=21.0)

    def test_token_lease_fails_closed_when_expired(self):
        lease = TokenLease(SolveResult("t" * 100, "local", 10.0, 1))
        with self.assertRaises(TokenLeaseError):
            lease.consume(now=250.0)

    def test_broker_passes_injected_nonblocking_sleep_to_adapter(self):
        sleeps = []

        async def fake_sleep(seconds):
            sleeps.append(seconds)
            await asyncio.sleep(0)

        async def solver(request, sleep):
            await sleep(0.25)
            return SolveResult(
                token="t" * 100,
                provider=request.provider,
                received_at=time.monotonic(),
                elapsed_ms=1,
            )

        broker = TurnstileBroker(provider_limits={"local": 1}, sleep=fake_sleep)
        self.addCleanup(broker.close)
        request = SolveRequest(
            provider="local",
            sitekey="sitekey",
            page_url="https://example.test",
            fingerprint=FingerprintProfile("test", "chrome136", "ua", "zh-CN"),
        )
        self.assertEqual(broker.solve_sync(request, solver).token, "t" * 100)
        self.assertEqual(sleeps, [0.25])

    def test_queue_deadline_does_not_start_cancelled_solver(self):
        first_started = threading.Event()
        release_first = threading.Event()
        second_started = threading.Event()

        async def solver(request, sleep):
            if request.sitekey == "first":
                first_started.set()
                while not release_first.is_set():
                    await sleep(0.01)
            else:
                second_started.set()
            return SolveResult(
                token="t" * 100,
                provider=request.provider,
                received_at=time.monotonic(),
                elapsed_ms=1,
            )

        broker = TurnstileBroker(provider_limits={"local": 1})
        self.addCleanup(broker.close)
        first_request = SolveRequest(
            provider="local",
            sitekey="first",
            page_url="https://example.test",
            timeout_sec=5,
        )
        second_request = SolveRequest(
            provider="local",
            sitekey="second",
            page_url="https://example.test",
            timeout_sec=1,
        )
        first_errors = []

        def run_first():
            try:
                broker.solve_sync(first_request, solver)
            except Exception as exc:  # pragma: no cover - asserted below
                first_errors.append(exc)

        first_thread = threading.Thread(target=run_first)
        first_thread.start()
        self.assertTrue(first_started.wait(timeout=1.0))
        with self.assertRaises(TimeoutError):
            broker.solve_sync(second_request, solver)
        release_first.set()
        first_thread.join(timeout=2.0)
        self.assertFalse(first_thread.is_alive())
        self.assertEqual(first_errors, [])
        self.assertFalse(second_started.is_set())

    def test_local_solver_is_not_cancelled_by_broker_solve_wait_for(self):
        """Local browser captures enforce their own timeout and may first wait
        for a cross-process Chrome slot. The broker must not wrap that path in
        wait_for(timeout_sec) or high concurrency surfaces as an empty timeout.
        """

        async def slow_local_solver(request, sleep):
            # Exceeds timeout_sec=1 but finishes well under the outer grace.
            await sleep(1.5)
            return SolveResult(
                token="t" * 100,
                provider=request.provider,
                received_at=time.monotonic(),
                elapsed_ms=1500,
            )

        broker = TurnstileBroker(provider_limits={"local": 1})
        self.addCleanup(broker.close)
        request = SolveRequest(
            provider="local",
            sitekey="sitekey",
            page_url="https://example.test",
            timeout_sec=1,
        )
        started = time.monotonic()
        result = broker.solve_sync(request, slow_local_solver)
        elapsed = time.monotonic() - started
        self.assertEqual(result.token, "t" * 100)
        self.assertGreaterEqual(elapsed, 1.4)

    def test_timeout_errors_include_readable_message(self):
        async def never_finishes(request, sleep):
            while True:
                await sleep(0.05)

        broker = TurnstileBroker(provider_limits={"capsolver": 1})
        self.addCleanup(broker.close)
        request = SolveRequest(
            provider="capsolver",
            sitekey="sitekey",
            page_url="https://example.test",
            timeout_sec=1,
        )
        with self.assertRaises(TimeoutError) as ctx:
            broker.solve_sync(request, never_finishes)
        self.assertTrue(str(ctx.exception).strip())

    def test_close_stops_loop_published_before_run_forever(self):
        broker = TurnstileBroker(provider_limits={"local": 1})
        loop = asyncio.new_event_loop()
        allow_run = threading.Event()
        run_forever_entered = threading.Event()
        stop_queued = threading.Event()
        original_run_forever = loop.run_forever
        original_call_soon_threadsafe = loop.call_soon_threadsafe

        def delayed_run_forever():
            run_forever_entered.set()
            allow_run.wait(timeout=2.0)
            original_run_forever()

        def tracked_call_soon_threadsafe(callback, *args):
            if getattr(callback, "__self__", None) is loop and getattr(
                callback, "__name__", ""
            ) == "stop":
                stop_queued.set()
            return original_call_soon_threadsafe(callback, *args)

        loop.run_forever = delayed_run_forever
        loop.call_soon_threadsafe = tracked_call_soon_threadsafe
        ensure_errors = []

        def ensure_loop():
            try:
                broker._ensure_loop()
            except Exception as exc:  # pragma: no cover - asserted below
                ensure_errors.append(exc)

        with mock.patch("turnstile_broker.asyncio.new_event_loop", return_value=loop):
            starter = threading.Thread(target=ensure_loop)
            starter.start()
            self.assertTrue(run_forever_entered.wait(timeout=1.0))
            closer = threading.Thread(target=broker.close)
            closer.start()
            self.assertTrue(stop_queued.wait(timeout=1.0))
            allow_run.set()
            closer.join(timeout=2.0)
            starter.join(timeout=2.0)

        self.assertFalse(closer.is_alive())
        self.assertFalse(starter.is_alive())
        self.assertEqual(ensure_errors, [])
        self.assertTrue(broker.closed)
        broker.close()

    def test_submit_close_race_closes_unscheduled_coroutine(self):
        broker = TurnstileBroker(provider_limits={"local": 1})
        loop = mock.Mock()
        coroutine = mock.Mock()

        def close_then_return_loop():
            broker.close()
            return loop

        with mock.patch.object(
            broker,
            "_ensure_loop",
            side_effect=close_then_return_loop,
        ), mock.patch.object(
            broker,
            "_solve_on_loop",
            new=lambda *_args, **_kwargs: coroutine,
        ), mock.patch(
            "turnstile_broker.asyncio.run_coroutine_threadsafe"
        ) as schedule:
            with self.assertRaisesRegex(RuntimeError, "broker is closed"):
                broker._submit(
                    SolveRequest("local", "sitekey", "https://example.test"),
                    mock.Mock(),
                )

        coroutine.close.assert_called_once_with()
        schedule.assert_not_called()

    def test_queue_limit_bounds_active_and_waiting_work(self):
        started = threading.Event()
        release = threading.Event()

        async def solver(request, sleep):
            started.set()
            while not release.is_set():
                await sleep(0.01)
            return SolveResult(
                token="t" * 100,
                provider=request.provider,
                received_at=time.monotonic(),
                elapsed_ms=1,
            )

        broker = TurnstileBroker(provider_limits={"local": 1}, queue_limit=1)
        self.addCleanup(broker.close)
        first = broker._submit(
            SolveRequest("local", "first", "https://example.test", timeout_sec=5),
            solver,
        )
        self.assertTrue(started.wait(timeout=1.0))
        second = broker._submit(
            SolveRequest("local", "second", "https://example.test", timeout_sec=5),
            solver,
        )
        with self.assertRaises(BrokerQueueFull):
            second.result(timeout=1.0)
        release.set()
        self.assertEqual(first.result(timeout=2.0).token, "t" * 100)
        self.assertEqual(broker._pending, 0)

    def test_close_cancels_active_solver_and_drains_pending(self):
        started = threading.Event()
        finalized = threading.Event()

        async def solver(_request, sleep):
            started.set()
            try:
                while True:
                    await sleep(0.01)
            finally:
                finalized.set()

        broker = TurnstileBroker(provider_limits={"local": 1})
        future = broker._submit(
            SolveRequest("local", "sitekey", "https://example.test", timeout_sec=30),
            solver,
        )
        self.assertTrue(started.wait(timeout=1.0))
        broker.close()

        self.assertTrue(finalized.wait(timeout=1.0))
        with self.assertRaises(concurrent.futures.CancelledError):
            future.result(timeout=1.0)
        self.assertEqual(broker._pending, 0)

    def test_lease_only_solve_response_is_accepted_until_consume(self):
        class LeaseOnlyBroker:
            @staticmethod
            def solve_sync(_request, _solver):
                return SolveResult(
                    token="",
                    provider="local",
                    received_at=time.monotonic(),
                    elapsed_ms=1,
                    extras={
                        "broker_url": "http://127.0.0.1:8010",
                        "lease_id": "lease-1",
                        "token_length": 100,
                    },
                )

        result = flow.solve_turnstile_result(
            sitekey="sitekey",
            provider="local",
            broker=LeaseOnlyBroker(),
        )
        self.assertEqual(result.token, "")
        self.assertEqual(result.extras["lease_id"], "lease-1")

    def test_remote_lease_metadata_is_kept_for_atomic_consume(self):
        result = SolveResult(
            token="t" * 100,
            provider="local",
            received_at=time.monotonic(),
            elapsed_ms=1,
            extras={"broker_url": "http://127.0.0.1:8010", "lease_id": "lease-1"},
        )
        self.assertEqual(result.extras["lease_id"], "lease-1")



    def test_lease_with_zero_reported_length_is_rejected(self):
        class LeaseOnlyBroker:
            @staticmethod
            def solve_sync(_request, _solver):
                return SolveResult(
                    token="",
                    provider="local",
                    received_at=time.monotonic(),
                    elapsed_ms=1,
                    extras={
                        "broker_url": "http://127.0.0.1:8010",
                        "lease_id": "lease-zero",
                        "token_length": 0,
                    },
                )

        with self.assertRaises(flow.VerificationRequiredError):
            flow.solve_turnstile_result(
                sitekey="sitekey",
                provider="local",
                broker=LeaseOnlyBroker(),
            )

    def test_lease_without_token_length_is_rejected(self):
        class LeaseOnlyBroker:
            @staticmethod
            def solve_sync(_request, _solver):
                return SolveResult(
                    token="",
                    provider="local",
                    received_at=time.monotonic(),
                    elapsed_ms=1,
                    extras={
                        "broker_url": "http://127.0.0.1:8010",
                        "lease_id": "lease-missing-len",
                    },
                )

        with self.assertRaises(flow.VerificationRequiredError):
            flow.solve_turnstile_result(
                sitekey="sitekey",
                provider="local",
                broker=LeaseOnlyBroker(),
            )

if __name__ == "__main__":
    unittest.main()

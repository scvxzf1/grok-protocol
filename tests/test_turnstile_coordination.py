import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import http_tui as tui
import xai_http_flow as flow


class TurnstileCoordinationTests(unittest.TestCase):
    @staticmethod
    def _registration_client(events):
        client = mock.Mock()
        client.proxy = ""
        client.timeout = 30
        client.log_callback = None
        client.fingerprint = flow.DEFAULT_FINGERPRINT
        client.signup_page_url = "https://accounts.x.ai/sign-up?redirect=grok-com"
        client.signup_page_html = ""
        client.open_signup.return_value = {"turnstile_sitekey": "sitekey"}
        client.verify_email_validation_code.return_value = "123456"

        def submit_registration(**_kwargs):
            events.append("submit")
            return "sso-value"

        client.submit_registration.side_effect = submit_registration
        return client

    @staticmethod
    def _lease_only_result():
        return flow.SolveResult(
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

    def test_registration_orders_permit_then_consume_then_submit(self):
        events = []
        client = self._registration_client(events)

        def solve(**_kwargs):
            events.append("solve")
            return self._lease_only_result()

        def acquire(*_args, **_kwargs):
            events.append("acquire")
            return "permit-1"

        def consume(*_args, **_kwargs):
            events.append("consume")
            return "t" * 100

        def release(*_args, **_kwargs):
            events.append("release")

        with mock.patch.object(flow, "solve_turnstile_result", side_effect=solve), mock.patch.object(
            flow, "_acquire_remote_submit_permit", side_effect=acquire
        ), mock.patch.object(
            flow, "_consume_remote_turnstile_lease", side_effect=consume
        ), mock.patch.object(
            flow, "_release_remote_submit_permit", side_effect=release
        ), mock.patch.object(flow, "save_account_record", return_value=""):
            flow.run_registration(
                client=client,
                email="user@example.test",
                email_code="123456",
                turnstile_provider="local",
                turnstile_broker_url="http://127.0.0.1:8010",
                given_name="Test",
                family_name="User",
                password="password",
            )

        self.assertEqual(events, ["solve", "acquire", "consume", "submit", "release"])

    def test_consume_failure_releases_permit_without_submit(self):
        events = []
        client = self._registration_client(events)

        def solve(**_kwargs):
            events.append("solve")
            return self._lease_only_result()

        def acquire(*_args, **_kwargs):
            events.append("acquire")
            return "permit-1"

        def consume(*_args, **_kwargs):
            events.append("consume")
            raise flow.VerificationRequiredError("consume failed")

        def release(*_args, **_kwargs):
            events.append("release")

        with mock.patch.object(flow, "solve_turnstile_result", side_effect=solve), mock.patch.object(
            flow, "_acquire_remote_submit_permit", side_effect=acquire
        ), mock.patch.object(
            flow, "_consume_remote_turnstile_lease", side_effect=consume
        ), mock.patch.object(
            flow, "_release_remote_submit_permit", side_effect=release
        ), mock.patch.object(flow, "save_account_record", return_value=""):
            with self.assertRaisesRegex(flow.VerificationRequiredError, "consume failed"):
                flow.run_registration(
                    client=client,
                    email="user@example.test",
                    email_code="123456",
                    turnstile_provider="local",
                    turnstile_broker_url="http://127.0.0.1:8010",
                    given_name="Test",
                    family_name="User",
                    password="password",
                )

        self.assertEqual(events, ["solve", "acquire", "consume", "release"])
        client.submit_registration.assert_not_called()

    def test_registration_rejects_lease_without_reported_token_length(self):
        events = []
        client = self._registration_client(events)
        invalid = flow.SolveResult(
            token="",
            provider="local",
            received_at=time.monotonic(),
            elapsed_ms=1,
            extras={
                "broker_url": "http://127.0.0.1:8010",
                "lease_id": "lease-without-length",
            },
        )

        with mock.patch.object(flow, "solve_turnstile_result", return_value=invalid), mock.patch.object(
            flow,
            "_acquire_remote_submit_permit",
        ) as acquire:
            with self.assertRaisesRegex(flow.VerificationRequiredError, "reported_len=0"):
                flow.run_registration(
                    client=client,
                    email="user@example.test",
                    email_code="123456",
                    turnstile_provider="local",
                    turnstile_broker_url="http://127.0.0.1:8010",
                    given_name="Test",
                    family_name="User",
                    password="password",
                )

        acquire.assert_not_called()
        client.submit_registration.assert_not_called()

    def test_managed_broker_command_receives_all_concurrency_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = tui.RunPlan(
                config_path=root / "config.json",
                run_mode=tui.DEFAULT_RUN_MODE,
                count=2,
                workers=8,
                output_dir=root / "credentials",
                provider="local",
                email_provider="yyds",
                proxy_mode="none",
                proxy_args=[],
                turnstile_workers=3,
                turnstile_queue_size=17,
                submit_workers=2,
                manage_turnstile_broker=True,
            )
            command = tui.BatchRunner(plan)._shared_broker_command(9010)

        def option(name):
            return command[command.index(name) + 1]

        self.assertEqual(option("--max-concurrency"), "3")
        self.assertEqual(option("--external-provider-workers"), "3")
        self.assertEqual(option("--external-queue-limit"), "17")
        self.assertEqual(option("--submit-workers"), "2")

    def test_batch_starts_managed_broker_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = tui.RunPlan(
                config_path=root / "config.json",
                run_mode=tui.DEFAULT_RUN_MODE,
                count=2,
                workers=2,
                output_dir=root / "credentials",
                provider="local",
                email_provider="yyds",
                proxy_mode="none",
                proxy_args=[],
                manage_turnstile_broker=True,
            )
            runner = tui.BatchRunner(plan)
            with mock.patch.object(runner, "_start_shared_broker") as start_broker, mock.patch.object(
                runner, "_spawn_available"
            ):
                runner.start()
                runner.start()
            start_broker.assert_called_once_with()

    def test_submit_permit_is_released_on_submit_failure(self):
        fingerprint = flow.DEFAULT_FINGERPRINT
        with mock.patch.object(
            flow, "_acquire_remote_submit_permit", return_value="permit-1"
        ) as acquire, mock.patch.object(flow, "_release_remote_submit_permit") as release:
            with self.assertRaisesRegex(RuntimeError, "submit failed"):
                with flow._submit_permit(
                    broker_url="http://127.0.0.1:8010",
                    submit_workers=2,
                    timeout_sec=30,
                    fingerprint=fingerprint,
                ):
                    raise RuntimeError("submit failed")
        acquire.assert_called_once()
        acquire.assert_called_once_with(
            "http://127.0.0.1:8010",
            timeout_sec=30,
            lease_sec=60,
            fingerprint=fingerprint,
        )
        release.assert_called_once_with(
            "http://127.0.0.1:8010",
            "permit-1",
            fingerprint=fingerprint,
        )


if __name__ == "__main__":
    unittest.main()

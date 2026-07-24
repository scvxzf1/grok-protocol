import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from cross_process_lock import CrossProcessFileLock
import http_batch_service as batch
import webui_app
import xai_http_flow as flow


CLIENT_ID = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"


def mail_line(email="mailbox@example.test", token="M.Crefresh"):
    return f"{email}----MAIL_PASSWORD----{CLIENT_ID}----{token}"


class MicrosoftOAuthBackendTests(unittest.TestCase):
    class _Response:
        status_code = 200
        text = ""

        def __init__(self, data):
            self._data = dict(data)

        def json(self):
            return dict(self._data)

    def _mailbox(self, root: Path, line: str = ""):
        pool = root / "pool.txt"
        pool.write_text((line or mail_line()) + "\n", encoding="utf-8")
        return flow.MicrosoftGraphMailbox(str(pool), timeout=5)

    def test_thunderbird_token_uses_imap_profile_and_persists_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            mailbox = self._mailbox(Path(directory))
            account = flow.parse_ms_mail_line(mail_line(token="M.COLD"))
            response = self._Response(
                {
                    "access_token": "IMAP_ACCESS",
                    "refresh_token": "M.CROTATED",
                    "expires_in": 3600,
                }
            )
            with mock.patch.object(mailbox, "_request", return_value=response) as request:
                with mock.patch.object(mailbox, "_update_account_record") as persist:
                    access = mailbox._refresh_access_token(account)

            self.assertEqual(access, "IMAP_ACCESS")
            self.assertEqual(mailbox.mail_backend, "imap")
            self.assertEqual(account["refresh_token"], "M.CROTATED")
            persist.assert_called_once_with(account)
            args, kwargs = request.call_args
            self.assertEqual(args[:2], ("post", flow.MS_IMAP_TOKEN_URL))
            self.assertEqual(kwargs["data"]["scope"], flow.MS_IMAP_SCOPE)
            self.assertEqual(kwargs["data"]["client_id"], CLIENT_ID)

    def test_other_public_client_keeps_graph_profile(self):
        account = {
            "client_id": "11111111-2222-4333-8444-555555555555",
        }
        self.assertEqual(
            flow.MicrosoftGraphMailbox._oauth_profile(account),
            ("graph", flow.MS_GRAPH_TOKEN_URL, flow.MS_GRAPH_SCOPE),
        )

    def test_imap_xoauth_poll_extracts_xai_code_without_marking_mail_read(self):
        raw_message = (
            "From: xAI <accounts@x.ai>\r\n"
            "To: mailbox@example.test\r\n"
            "Date: Sun, 19 Jul 2026 02:00:00 +0000\r\n"
            "Subject: xAI confirmation MWM-AME\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Use MWM-AME to validate your email.\r\n"
        ).encode("utf-8")

        class FakeIMAP:
            def __init__(self):
                self.auth_payload = b""
                self.fetch_query = ""
                self.logged_out = False

            def authenticate(self, mechanism, callback):
                self.mechanism = mechanism
                self.auth_payload = callback(b"")
                return "OK", [b"authenticated"]

            def select(self, mailbox, readonly=False):
                self.selected = (mailbox, readonly)
                return "OK", [b"1"]

            def uid(self, command, *args):
                if command == "search":
                    return "OK", [b"42"]
                if command == "fetch":
                    self.fetch_query = str(args[-1])
                    return "OK", [(b"42 (BODY[])", raw_message), b")"]
                raise AssertionError(command)

            def logout(self):
                self.logged_out = True
                return "BYE", [b"logout"]

        with tempfile.TemporaryDirectory() as directory:
            mailbox = self._mailbox(Path(directory))
            mailbox.account = flow.parse_ms_mail_line(mail_line())
            mailbox.mail_backend = "imap"
            mailbox.access_token = "IMAP_ACCESS"
            mailbox.access_expires_at = flow.time.monotonic() + 3600
            fake = FakeIMAP()
            with mock.patch.object(flow.imaplib, "IMAP4_SSL", return_value=fake) as connect:
                code = mailbox.wait_for_xai_code(
                    "mailbox@example.test",
                    "IMAP_ACCESS",
                    timeout=5,
                    poll_interval=1,
                )

            self.assertEqual(code, "MWMAME")
            connect.assert_called_once_with(flow.MS_IMAP_HOST, flow.MS_IMAP_PORT, timeout=5)
            self.assertEqual(fake.mechanism, "XOAUTH2")
            self.assertEqual(fake.selected, ("INBOX", True))
            self.assertIn(b"user=mailbox@example.test", fake.auth_payload)
            self.assertIn(b"auth=Bearer IMAP_ACCESS", fake.auth_payload)
            self.assertEqual(fake.fetch_query, "(BODY.PEEK[])")


class MailPoolWebUITests(unittest.TestCase):
    def _service(self, root: Path) -> batch.BatchService:
        config = root / "config.json"
        config.write_text(
            json.dumps(
                {
                    "email_provider": "msgraph",
                    "ms_mail_file": "private/mail-pool.txt",
                    "turnstile_provider": "local",
                    "turnstile_headless": True,
                    "register_count": 2,
                    "concurrent_workers": 2,
                }
            ),
            encoding="utf-8",
        )
        return batch.BatchService(config_path=config, root_dir=root)

    def test_get_put_round_trip_invalid_accounting_permissions_and_empty_pool(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = self._service(root)
            client = TestClient(webui_app.create_app(service=service))
            invalid_client = "RAW_INVALID_CLIENT_IDENTIFIER"
            valid = mail_line(token="M.Cpart----suffix")
            text = f"# comment\n\n{valid}\nmailbox2@example.test----pw----{invalid_client}----M.Csecret\n"

            written = client.put("/api/ms-mail-pool", json={"text": text})

            self.assertEqual(written.status_code, 200)
            body = written.json()
            self.assertEqual(body["line_count"], 1)
            self.assertEqual(body["invalid_count"], 1)
            self.assertNotIn(invalid_client, json.dumps(body["errors"], ensure_ascii=False))
            pool_path = root / "private" / "mail-pool.txt"
            self.assertTrue(pool_path.is_file())
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(pool_path.stat().st_mode), 0o600)
                self.assertEqual(
                    stat.S_IMODE(pool_path.with_suffix(".txt.lock").stat().st_mode),
                    0o600,
                )

            fetched = client.get("/api/ms-mail-pool")
            self.assertEqual(fetched.status_code, 200)
            fetched_body = fetched.json()
            self.assertEqual(fetched_body["line_count"], 1)
            self.assertEqual(fetched_body["invalid_count"], 1)
            self.assertIn("M.Cpart----suffix", fetched_body["text"])
            self.assertNotIn(
                invalid_client,
                json.dumps(fetched_body["errors"], ensure_ascii=False),
            )

            emptied = client.put(
                "/api/ms-mail-pool",
                json={"ms_mail_pool_text": "\n# retained comment\n"},
            )
            self.assertEqual(emptied.status_code, 200)
            self.assertEqual(emptied.json()["line_count"], 0)
            self.assertEqual(emptied.json()["invalid_count"], 0)
            self.assertTrue(pool_path.is_file())

    def test_admin_write_uses_same_bounded_lock_as_graph_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = self._service(root)
            pool_path = root / "private" / "mail-pool.txt"
            pool_path.parent.mkdir(parents=True)
            pool_path.write_text(mail_line() + "\n", encoding="utf-8")
            lock_path = pool_path.with_suffix(".txt.lock")
            with CrossProcessFileLock(lock_path, timeout=1):
                with mock.patch.object(batch, "MS_MAIL_POOL_UI_LOCK_TIMEOUT_SEC", 0.05):
                    with self.assertRaises(batch.TuiConfigError):
                        batch.write_ms_mail_pool_text(service.settings, mail_line("other@example.test"))
            self.assertIn("mailbox@example.test", pool_path.read_text(encoding="utf-8"))

    def test_mail_secrets_stay_out_of_general_status_apis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = self._service(root)
            client = TestClient(webui_app.create_app(service=service))
            full_email = "private-mailbox@example.test"
            refresh = "M.C_PRIVATE_REFRESH_TOKEN"
            password = "PRIVATE_MAIL_PASSWORD"
            payload = f"{full_email}----{password}----{CLIENT_ID}----{refresh}\n"
            self.assertEqual(
                client.put("/api/ms-mail-pool", json={"text": payload}).status_code,
                200,
            )

            general = json.dumps(
                {
                    "health": client.get("/api/health").json(),
                    "settings": client.get("/api/settings").json(),
                    "run": client.get("/api/runs/current").json(),
                },
                ensure_ascii=False,
            )
            for secret in (full_email, password, CLIENT_ID, refresh, payload.strip()):
                self.assertNotIn(secret, general)

    def test_runtime_log_redactor_removes_mail_record_and_token_shapes(self):
        raw = (
            mail_line("private-mailbox@example.test", "M.C_PRIVATE_REFRESH_TOKEN")
            + " access_token=eyJheader.eyJbody.signature"
        )
        redacted = batch._redact_sensitive_runtime_text(raw)
        for secret in (
            "private-mailbox@example.test",
            "MAIL_PASSWORD",
            CLIENT_ID,
            "M.C_PRIVATE_REFRESH_TOKEN",
            "eyJheader.eyJbody.signature",
        ):
            self.assertNotIn(secret, redacted)


class MailPoolCliAndLifecycleTests(unittest.TestCase):
    def test_parse_serialize_joins_refresh_token_suffix_and_redacts_uuid_error(self):
        source = mail_line(token="M.Cfirst----second----third")
        parsed = flow.parse_ms_mail_line(source)
        self.assertEqual(parsed["refresh_token"], "M.Cfirst----second----third")
        self.assertEqual(flow.serialize_ms_mail_line(parsed), source)

        invalid = "SENSITIVE_INVALID_CLIENT"
        with self.assertRaises(flow.MailboxError) as raised:
            flow.parse_ms_mail_line(
                f"mailbox@example.test----pw----{invalid}----M.Crefresh"
            )
        self.assertNotIn(invalid, str(raised.exception))

    def test_provider_aliases_and_batch_msgraph_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pool = root / "pool.txt"
            pool.write_text(mail_line() + "\n", encoding="utf-8")
            for alias in ("msgraph", "microsoft", "hotmail", "outlook"):
                mailbox = flow.build_mailbox(
                    config={"email_provider": alias, "ms_mail_file": str(pool)}
                )
                self.assertIsInstance(mailbox, flow.MicrosoftGraphMailbox)

            config = root / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "email_provider": "outlook",
                        "ms_mail_file": str(pool),
                        "turnstile_provider": "local",
                        "turnstile_headless": True,
                        "register_count": 2,
                        "concurrent_workers": 2,
                    }
                ),
                encoding="utf-8",
            )
            service = batch.BatchService(config_path=config, root_dir=root)
            plan = batch.build_plan(service.settings)
            self.assertEqual(plan.email_provider, "outlook")
            self.assertTrue(any("Graph" in warning for warning in plan.warnings))

    def test_mail_probe_file_is_non_consuming_by_default_and_commits_when_requested(self):
        instances = []

        class FakeGraphMailbox:
            def __init__(self, *_args, **kwargs):
                self.mark_used = bool(kwargs.get("mark_used"))
                self.commits = 0
                self.releases = 0
                instances.append(self)

            def create(self):
                return "private-mailbox@example.test", "PRIVATE_ACCESS_TOKEN"

            def _messages(self, _token):
                return []

            def commit_success(self):
                self.commits += 1
                return True

            def release(self, **_kwargs):
                self.releases += 1
                return True

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(flow, "MicrosoftGraphMailbox", FakeGraphMailbox):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(flow.main(["mail-probe", "--mail-file", "fixture.txt"]), 0)
                self.assertEqual(
                    flow.main(
                        ["mail-probe", "--mail-file", "fixture.txt", "--mark-used"]
                    ),
                    0,
                )
        self.assertEqual(instances[0].commits, 0)
        self.assertEqual(instances[1].commits, 1)
        output = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn("private-mailbox@example.test", output)
        self.assertNotIn("PRIVATE_ACCESS_TOKEN", output)

    def test_mail_probe_mark_used_releases_when_inbox_probe_fails(self):
        instances = []

        class FailingInboxMailbox:
            def __init__(self, *_args, **_kwargs):
                self.commits = 0
                self.releases = 0
                instances.append(self)

            def create(self):
                return "private-mailbox@example.test", "PRIVATE_ACCESS_TOKEN"

            def _messages(self, _token):
                raise flow.MailboxError("synthetic inbox failure")

            def commit_success(self):
                self.commits += 1
                return True

            def release(self, **_kwargs):
                self.releases += 1
                return True

        with mock.patch.object(flow, "MicrosoftGraphMailbox", FailingInboxMailbox):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                self.assertEqual(
                    flow.main(
                        ["mail-probe", "--mail-file", "fixture.txt", "--mark-used"]
                    ),
                    0,
                )
        self.assertEqual(instances[0].commits, 0)
        self.assertEqual(instances[0].releases, 1)

    class _Mailbox:
        def __init__(self):
            self.creates = 0
            self.release_calls = 0
            self.release_successes = 0
            self.commits = 0
            self.reserved = False
            self.committed = False

        def create(self):
            self.creates += 1
            self.reserved = True
            self.committed = False
            return f"mailbox{self.creates}@example.test", "ACCESS_TOKEN"

        def wait_for_xai_code(self, *_args, **_kwargs):
            return "123456"

        def release(self, **_kwargs):
            self.release_calls += 1
            if not self.reserved or self.committed:
                return False
            self.reserved = False
            self.release_successes += 1
            return True

        def commit_success(self):
            if not self.reserved or self.committed:
                return False
            self.committed = True
            self.commits += 1
            return True

    class _Client:
        proxy = ""
        timeout = 10
        log_callback = None
        fingerprint = flow.DEFAULT_FINGERPRINT
        user_agent = flow.DEFAULT_FINGERPRINT.user_agent

        def __init__(self, *, fail_open=False, reject_first=False):
            self.fail_open = fail_open
            self.reject_first = reject_first
            self.requests = 0

        def open_signup(self):
            if self.fail_open:
                raise flow.XAIHttpFlowError("synthetic signup failure")
            return {}

        def request_email_validation_code(self, *_args):
            self.requests += 1
            if self.reject_first and self.requests == 1:
                raise flow.XAIHttpFlowError("email-domain-rejected")

        def verify_email_validation_code(self, _email, code):
            return code

        def submit_registration(self, **_kwargs):
            return "SYNTHETIC_SSO"

    def test_registration_failure_releases_imported_record_exactly_once(self):
        mailbox = self._Mailbox()
        with mock.patch.object(flow, "build_mailbox", return_value=mailbox):
            with self.assertRaises(flow.XAIHttpFlowError):
                flow.run_registration(
                    client=self._Client(fail_open=True),
                    mail_file="fixture.txt",
                    email_code="123456",
                    turnstile_token="T" * 100,
                    given_name="Test",
                    family_name="User",
                    password="PASSWORD",
                )
        self.assertEqual(mailbox.creates, 1)
        self.assertEqual(mailbox.release_calls, 1)
        self.assertEqual(mailbox.release_successes, 1)
        self.assertEqual(mailbox.commits, 0)

    def test_domain_retry_returns_old_record_and_success_commits_new_record(self):
        mailbox = self._Mailbox()
        with mock.patch.object(flow, "build_mailbox", return_value=mailbox):
            result = flow.run_registration(
                client=self._Client(reject_first=True),
                mail_file="fixture.txt",
                turnstile_token="T" * 100,
                given_name="Test",
                family_name="User",
                password="PASSWORD",
            )
        self.assertEqual(result.email, "mailbox2@example.test")
        self.assertEqual(mailbox.creates, 2)
        self.assertEqual(mailbox.release_successes, 1)
        self.assertEqual(mailbox.commits, 1)
        self.assertTrue(mailbox.committed)


if __name__ == "__main__":
    unittest.main()

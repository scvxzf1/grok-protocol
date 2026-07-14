import ast
import concurrent.futures
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import xai_http_flow as flow
from cross_process_lock import CrossProcessFileLock


CLIENT_ID = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"


def record(index: int, token: str = "") -> str:
    suffix = token or f"M.Ctoken{index}"
    return f"worker{index}@hotmail.test----pw----{CLIENT_ID}----{suffix}"


class MailboxAtomicTests(unittest.TestCase):
    def test_xai_flow_has_no_direct_fcntl_import(self):
        source = Path(flow.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertNotIn("fcntl", imported)

    @unittest.skipUnless(os.name == "nt", "Windows-specific import smoke")
    def test_windows_import_smoke(self):
        completed = subprocess.run(
            [sys.executable, "-c", "import xai_http_flow"],
            cwd=str(Path(flow.__file__).resolve().parent),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_claims_are_unique_across_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pool.txt"
            path.write_text(
                "\n".join(record(index) for index in range(6)) + "\n",
                encoding="utf-8",
            )
            script = (
                "import sys\n"
                "from xai_http_flow import MicrosoftGraphMailbox\n"
                "item = MicrosoftGraphMailbox(sys.argv[1], mark_used=True).reserve()\n"
                "sys.stdout.write(item['email'])\n"
            )
            processes = [
                subprocess.Popen(
                    [sys.executable, "-c", script, str(path)],
                    cwd=str(Path(flow.__file__).resolve().parent),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for _ in range(6)
            ]
            claimed = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=30)
                self.assertEqual(process.returncode, 0, stderr)
                claimed.append(stdout.strip())
            self.assertEqual(len(claimed), len(set(claimed)))
            self.assertEqual(path.read_text(encoding="utf-8"), "")
            used = path.with_suffix(".txt.used").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(used), 6)

    def test_mailbox_timeout_is_typed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pool.txt"
            path.write_text(record(0) + "\n", encoding="utf-8")
            box = flow.MicrosoftGraphMailbox(
                str(path),
                mark_used=True,
                lock_timeout=0.1,
            )
            with CrossProcessFileLock(box.lock_path, timeout=1):
                with self.assertRaises(flow.MailboxPoolLockTimeout):
                    box.reserve()

    def test_exhausted_pool_is_reported_after_unique_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pool.txt"
            path.write_text(record(0) + "\n", encoding="utf-8")
            first = flow.MicrosoftGraphMailbox(str(path), mark_used=True).reserve()
            self.assertEqual(first["email"], "worker0@hotmail.test")
            with self.assertRaises(flow.MailboxError):
                flow.MicrosoftGraphMailbox(str(path), mark_used=True).reserve()

    @unittest.skipIf(os.name == "nt", "POSIX permission bits")
    def test_constructor_tightens_source_and_used_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pool.txt"
            used = path.with_suffix(".txt.used")
            path.write_text(record(0) + "\n", encoding="utf-8")
            used.write_text(record(1) + "\n", encoding="utf-8")
            os.chmod(path, 0o644)
            os.chmod(used, 0o644)

            flow.MicrosoftGraphMailbox(str(path), mark_used=True)

            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(used.stat().st_mode & 0o777, 0o600)

    def test_used_ledger_prevents_duplicate_after_source_replace_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pool.txt"
            path.write_text(record(0) + "\n" + record(1) + "\n", encoding="utf-8")
            original = flow._atomic_write_utf8_lines

            def interrupt_source(target, lines):
                if Path(target).resolve() == path.resolve():
                    raise PermissionError("synthetic source interruption")
                return original(target, lines)

            first_box = flow.MicrosoftGraphMailbox(str(path), mark_used=True)
            with mock.patch.object(
                flow,
                "_atomic_write_utf8_lines",
                side_effect=interrupt_source,
            ):
                first = first_box.reserve()
            self.assertEqual(first["email"], "worker0@hotmail.test")
            self.assertIn("worker0@hotmail.test", path.read_text(encoding="utf-8"))

            second = flow.MicrosoftGraphMailbox(str(path), mark_used=True).reserve()
            self.assertEqual(second["email"], "worker1@hotmail.test")
            used = path.with_suffix(".txt.used").read_text(encoding="utf-8")
            self.assertEqual(used.count("worker0@hotmail.test"), 1)
            self.assertEqual(used.count("worker1@hotmail.test"), 1)

    def test_concurrent_rotated_tokens_merge_without_lost_update(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pool.txt"
            path.write_text(record(0) + "\n" + record(1) + "\n", encoding="utf-8")
            boxes = [
                flow.MicrosoftGraphMailbox(str(path), mark_used=True)
                for _ in range(2)
            ]
            accounts = [box.reserve() for box in boxes]
            accounts[0]["refresh_token"] = "M.CrotatedA"
            accounts[1]["refresh_token"] = "M.CrotatedB"
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                list(executor.map(lambda pair: pair[0]._update_account_record(pair[1]), zip(boxes, accounts)))
            used = path.with_suffix(".txt.used").read_text(encoding="utf-8")
            self.assertIn("M.CrotatedA", used)
            self.assertIn("M.CrotatedB", used)

    def test_non_consuming_rotation_updates_source_without_removing_record(self):
        class Response:
            status_code = 200
            text = ""

            @staticmethod
            def json():
                return {
                    "access_token": "synthetic-access",
                    "refresh_token": "M.Crotated",
                    "expires_in": 3600,
                }

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pool.txt"
            path.write_text(record(0) + "\n", encoding="utf-8")
            box = flow.MicrosoftGraphMailbox(str(path), mark_used=False)
            account = box.reserve()
            with mock.patch.object(box, "_request", return_value=Response()):
                box._refresh_access_token(account)
            source = path.read_text(encoding="utf-8")
            self.assertIn("worker0@hotmail.test", source)
            self.assertIn("M.Crotated", source)
            self.assertFalse(path.with_suffix(".txt.used").exists())

    def test_non_consuming_refresh_failure_does_not_retry_same_record(self):
        class Response:
            status_code = 400
            text = "synthetic invalid token"

            @staticmethod
            def json():
                return {"error": "invalid_grant"}

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pool.txt"
            path.write_text(record(0) + "\n", encoding="utf-8")
            box = flow.MicrosoftGraphMailbox(str(path), mark_used=False)
            with mock.patch.object(box, "_request", return_value=Response()) as request:
                with self.assertRaises(flow.MailboxError):
                    box.create()
            self.assertEqual(request.call_count, 1)
            self.assertIn("worker0@hotmail.test", path.read_text(encoding="utf-8"))
            self.assertFalse(path.with_suffix(".txt.used").exists())

    def test_invalid_client_id_error_is_redacted(self):
        secret = "client-secret-looking-value"
        line = f"worker0@hotmail.test----pw----{secret}----M.Ctoken"
        with self.assertRaises(flow.MailboxError) as raised:
            flow.parse_ms_mail_line(line)
        self.assertNotIn(secret, str(raised.exception))


if __name__ == "__main__":
    unittest.main()

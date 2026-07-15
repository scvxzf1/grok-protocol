import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import cross_process_lock as locks


class CrossProcessLockTests(unittest.TestCase):
    def test_timeout_is_typed_and_bounded_across_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.lock"
            script = (
                "import sys\n"
                "from cross_process_lock import CrossProcessFileLock, CrossProcessLockTimeout\n"
                "try:\n"
                "    with CrossProcessFileLock(sys.argv[1], timeout=0.2):\n"
                "        raise SystemExit(7)\n"
                "except CrossProcessLockTimeout:\n"
                "    raise SystemExit(23)\n"
            )
            with locks.CrossProcessFileLock(path, timeout=1):
                completed = subprocess.run(
                    [sys.executable, "-c", script, str(path)],
                    cwd=str(Path(locks.__file__).resolve().parent),
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
            self.assertEqual(completed.returncode, 23, completed.stderr)

    def test_context_releases_after_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.lock"
            with self.assertRaisesRegex(RuntimeError, "synthetic"):
                with locks.CrossProcessFileLock(path, timeout=1):
                    raise RuntimeError("synthetic")
            with locks.CrossProcessFileLock(path, timeout=0.2) as acquired:
                self.assertTrue(acquired.is_locked)

    def test_atomic_write_keeps_previous_complete_file_on_replace_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text('{"version": 1}', encoding="utf-8")
            with mock.patch.object(
                locks.os,
                "replace",
                side_effect=PermissionError("synthetic replace failure"),
            ):
                with self.assertRaises(PermissionError):
                    locks.atomic_write_private_text(path, '{"version": 2}')
            self.assertEqual(path.read_text(encoding="utf-8"), '{"version": 1}')
            self.assertEqual(list(path.parent.glob(f".{path.name}.*.tmp")), [])

    @unittest.skipIf(os.name == "nt", "POSIX mode bits are not Windows ACLs")
    def test_lock_and_atomic_state_are_owner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "state.lock"
            state_path = Path(directory) / "state.txt"
            with locks.CrossProcessFileLock(lock_path, timeout=1):
                locks.atomic_write_private_text(state_path, "ok")
            self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(state_path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()

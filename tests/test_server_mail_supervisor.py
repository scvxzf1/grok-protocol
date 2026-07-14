import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from filelock import FileLock

from sso_to_auth_json import sso_file_name

import server_mail_supervisor as sup


def mail_line(email: str, refresh: str = "REFRESH_TOKEN") -> str:
    return f"{email}----MAIL_PASSWORD----00000000-0000-4000-8000-000000000001----{refresh}"


def write_valid_credential(output: Path, email: str) -> None:
    output.mkdir(parents=True, exist_ok=True)
    path = output / f"credential-{len(list(output.glob('*.json')))}.json"
    path.write_text(
        json.dumps(
            {
                "email": email,
                "type": "xai",
                "auth_kind": "oauth",
                "disabled": False,
                "access_token": "ACCESS_TOKEN",
                "refresh_token": "OAUTH_REFRESH_TOKEN",
            }
        ),
        encoding="utf-8",
    )


class FakeBatchService:
    def __init__(self, *, on_start=None, **_kwargs):
        self.on_start = on_start
        self.payload = None
        self.snapshot = {
            "done": False,
            "active": 0,
            "started_tasks": 0,
            "completed": 0,
            "succeeded": 0,
            "failed": 0,
        }

    def start_run(self, payload):
        self.payload = dict(payload)
        if self.on_start:
            self.on_start(self.payload)
        count = int(payload["count"])
        self.snapshot = {
            "done": True,
            "active": 0,
            "started_tasks": count,
            "completed": count,
            "succeeded": count,
            "failed": 0,
        }
        return dict(self.snapshot)

    def poll(self):
        return None

    def current_snapshot(self):
        return dict(self.snapshot)

    def is_busy(self):
        return not bool(self.snapshot.get("done"))

    def stop_run(self):
        self.snapshot["done"] = True
        self.snapshot["active"] = 0
        return dict(self.snapshot)


class ServerMailSupervisorTests(unittest.TestCase):
    def make_supervisor(self, root: Path, **kwargs) -> sup.ServerMailSupervisor:
        config = root / "config.json"
        config.write_text(
            json.dumps(
                {
                    "email_provider": "msgraph",
                    "turnstile_provider": "local",
                    "legacy_secret": "KEEP_ME",
                    "proxy_mode": "direct",
                    "proxy": "http://PROXY_USER:PROXY_PASSWORD@proxy.example.test:9000",
                }
            ),
            encoding="utf-8",
        )
        proxy = root / "proxy.txt"
        proxy.write_text(
            "proxy.example.test:9000:PROXY_USER:PROXY_PASSWORD\n",
            encoding="utf-8",
        )
        options = {
            "config_path": config,
            "master_path": root / "master.txt",
            "work_path": root / "work.txt",
            "proxy_path": proxy,
            "output_dir": root / "credentials",
            "state_path": root / "state.json",
            "retry_delay_sec": 0,
            "poll_interval_sec": 0.01,
            "logger": lambda _message: None,
        }
        options.update(kwargs)
        return sup.ServerMailSupervisor(**options)

    def test_reconcile_three_states_and_used_record_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            emails = ["complete@example.test", "convert@example.test", "pending@example.test"]
            (root / "master.txt").write_text(
                "\n".join(mail_line(email, "OLD_REFRESH") for email in emails) + "\n",
                encoding="utf-8",
            )
            work_used = root / "work.txt.used"
            work_used.write_text(mail_line(emails[2], "ROTATED_REFRESH") + "\n", encoding="utf-8")
            write_valid_credential(root / "credentials", emails[0])
            sso_path = root / "credentials" / sso_file_name(emails[1])
            sso_path.parent.mkdir(parents=True, exist_ok=True)
            sso_path.write_text("SSO_VALUE\n", encoding="utf-8")

            supervisor = self.make_supervisor(root)
            result = supervisor.reconcile()

            self.assertEqual(result.planned, 3)
            self.assertEqual(result.complete, 1)
            self.assertEqual(result.convert, 1)
            self.assertEqual(result.pending, 1)
            self.assertIn("ROTATED_REFRESH", (root / "master.txt").read_text(encoding="utf-8"))

    def test_work_rebuild_is_selected_only_and_clears_used(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            emails = [f"role{i}@example.test" for i in range(3)]
            (root / "master.txt").write_text(
                "\n".join(mail_line(email) for email in emails) + "\n",
                encoding="utf-8",
            )
            supervisor = self.make_supervisor(root)
            result = supervisor.reconcile()
            supervisor._rebuild_work(result.pending_keys[:2])

            work_lines = (root / "work.txt").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(work_lines), 2)
            self.assertEqual((root / "work.txt.used").read_text(encoding="utf-8"), "")
            self.assertTrue(supervisor.mail_lock_path.is_file())

    def test_reconcile_uses_same_mailbox_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "master.txt").write_text(
                mail_line("locked@example.test") + "\n", encoding="utf-8"
            )
            supervisor = self.make_supervisor(root)
            with FileLock(str(supervisor.mail_lock_path)):
                with mock.patch.object(sup, "MS_MAIL_POOL_LOCK_TIMEOUT_SEC", 0.05):
                    with self.assertRaises(sup.SupervisorError):
                        supervisor.reconcile()

    def test_state_file_contains_integer_counts_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "master.txt").write_text(mail_line("state@example.test") + "\n", encoding="utf-8")
            supervisor = self.make_supervisor(root)
            result = supervisor.reconcile()
            supervisor._write_state(result, epoch_succeeded=2, epoch_failed=1)

            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            self.assertTrue(state)
            self.assertTrue(all(isinstance(value, int) for value in state.values()))
            state_text = json.dumps(state)
            self.assertNotIn("example.test", state_text)
            self.assertNotIn("PROXY", state_text)

    def test_sso_conversion_uses_one_proxy_but_logs_no_identity_or_proxy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            email = "convert-only@example.test"
            (root / "master.txt").write_text(mail_line(email) + "\n", encoding="utf-8")
            output = root / "credentials"
            output.mkdir()
            (output / sso_file_name(email)).write_text("SSO_VALUE\n", encoding="utf-8")
            commands = []
            logs = []

            def command_runner(command, _timeout):
                commands.append(list(command))
                write_valid_credential(output, email)
                return 0

            supervisor = self.make_supervisor(
                root,
                command_runner=command_runner,
                logger=logs.append,
                service_factory=lambda **_kwargs: self.fail("registration service should not start"),
            )
            rc = supervisor.run(max_epochs=1)

            self.assertEqual(rc, 0)
            self.assertEqual(len(commands), 1)
            command = commands[0]
            self.assertNotIn("--proxy", command)
            self.assertIn("--proxy-file", command)
            self.assertIn("--proxy-random", command)
            self.assertIn("--sso-file", command)
            joined_command = " ".join(command)
            self.assertNotIn("PROXY_USER", joined_command)
            self.assertNotIn("PROXY_PASSWORD", joined_command)
            joined_logs = "\n".join(logs)
            self.assertNotIn(email, joined_logs)
            self.assertNotIn("PROXY_USER", joined_logs)
            self.assertNotIn("PROXY_PASSWORD", joined_logs)
            self.assertNotIn("SSO_VALUE", joined_logs)

    def test_noninteractive_epoch_caps_concurrency_and_finishes_by_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            emails = [f"batch{i:02d}@example.test" for i in range(25)]
            (root / "master.txt").write_text(
                "\n".join(mail_line(email) for email in emails) + "\n",
                encoding="utf-8",
            )
            services = []

            def factory(**kwargs):
                def on_start(payload):
                    work = (root / "work.txt").read_text(encoding="utf-8").splitlines()
                    self.assertLessEqual(len(work), 20)
                    self.assertEqual(payload["workers"], 4)
                    for line in work:
                        write_valid_credential(root / "credentials", line.split("----", 1)[0])

                service = FakeBatchService(on_start=on_start, **kwargs)
                services.append(service)
                return service

            supervisor = self.make_supervisor(root, service_factory=factory)
            rc = supervisor.run(max_epochs=3)

            self.assertEqual(rc, 0)
            self.assertEqual(len(services), 2)
            self.assertEqual(services[0].payload["count"], 20)
            self.assertEqual(services[1].payload["count"], 5)
            disk_config = json.loads((root / "config.json").read_text(encoding="utf-8"))
            self.assertEqual(disk_config["concurrent_workers"], 4)
            self.assertEqual(disk_config["turnstile_workers"], 2)
            self.assertEqual(disk_config["submit_workers"], 2)
            self.assertEqual(disk_config["proxy_mode"], "pool")
            self.assertEqual(disk_config["proxy_file"], str((root / "proxy.txt").resolve()))
            self.assertTrue(disk_config["proxy_random"])
            self.assertTrue(disk_config["proxy_slot_sticky"])
            self.assertNotIn("proxy", disk_config)
            self.assertEqual(disk_config["legacy_secret"], "KEEP_ME")

    def test_state_counters_resume_epoch_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            email = "done@example.test"
            (root / "master.txt").write_text(mail_line(email) + "\n", encoding="utf-8")
            write_valid_credential(root / "credentials", email)
            (root / "state.json").write_text(
                json.dumps({"epochs": 7, "no_progress_epochs": 4}),
                encoding="utf-8",
            )
            supervisor = self.make_supervisor(root)

            self.assertEqual(supervisor.run(), 0)
            self.assertEqual(supervisor.epoch, 7)
            self.assertEqual(supervisor.no_progress_epochs, 4)
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["epochs"], 7)

    def test_stop_service_requires_done_even_when_active_is_zero(self):
        class UndrainedService:
            def is_busy(self):
                return True

            def stop_run(self):
                return {"done": False, "active": 0}

            def poll(self):
                return None

            def current_snapshot(self):
                return {"done": False, "active": 0}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "master.txt").write_text(
                mail_line("pending@example.test") + "\n", encoding="utf-8"
            )
            supervisor = self.make_supervisor(
                root, stop_grace_sec=0.04, poll_interval_sec=0.01
            )
            self.assertFalse(supervisor._stop_service(UndrainedService()))

    def test_undrained_epoch_keeps_used_for_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            email = "claimed@example.test"
            original = mail_line(email, "ORIGINAL_REFRESH")
            rotated = mail_line(email, "ROTATED_REFRESH")
            (root / "master.txt").write_text(original + "\n", encoding="utf-8")

            class StuckService:
                def start_run(self, _payload):
                    (root / "work.txt").write_text("", encoding="utf-8")
                    (root / "work.txt.used").write_text(rotated + "\n", encoding="utf-8")
                    return {
                        "done": False,
                        "active": 1,
                        "started_tasks": 1,
                        "completed": 0,
                    }

                def poll(self):
                    return None

                def current_snapshot(self):
                    return {
                        "done": False,
                        "active": 1,
                        "started_tasks": 1,
                        "completed": 0,
                    }

                def is_busy(self):
                    return True

                def stop_run(self):
                    return self.current_snapshot()

            supervisor = self.make_supervisor(
                root,
                service_factory=lambda **_kwargs: StuckService(),
                idle_timeout_sec=0.03,
                stop_grace_sec=0.04,
                poll_interval_sec=0.01,
            )
            with self.assertRaises(sup.SupervisorError):
                supervisor.run(max_epochs=1)
            self.assertIn(
                "ROTATED_REFRESH",
                (root / "work.txt.used").read_text(encoding="utf-8"),
            )

    def test_quiet_subprocess_stops_promptly(self):
        stop = threading.Event()

        def trigger_stop():
            time.sleep(0.1)
            stop.set()

        thread = threading.Thread(target=trigger_stop)
        thread.start()
        started = time.monotonic()
        rc = sup._quiet_subprocess(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            30,
            stop_requested=stop.is_set,
        )
        elapsed = time.monotonic() - started
        thread.join(timeout=1)
        self.assertEqual(rc, 130)
        self.assertLess(elapsed, 3.0)

    def test_single_instance_lock_is_nonblocking(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "supervisor.lock"
            with sup.SingleInstanceLock(lock_path):
                with self.assertRaises(sup.AlreadyRunningError):
                    with sup.SingleInstanceLock(lock_path):
                        pass


if __name__ == "__main__":
    unittest.main()

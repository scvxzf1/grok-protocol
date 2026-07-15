from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import project_browser_registry as registry


class _FakeProcess:
    def __init__(self, pid: int, name: str, cmdline: list[str], *, children=None):
        self.pid = pid
        self.info = {"pid": pid, "name": name, "cmdline": cmdline}
        self._children = list(children or [])
        self.terminated = False
        self.killed = False

    def create_time(self):
        return float(self.pid)

    def children(self, recursive=True):
        return list(self._children)

    def parent(self):
        return None

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


class _FakePsutil:
    def __init__(self, processes):
        self.processes = list(processes)

    def process_iter(self, _attrs):
        return list(self.processes)

    @staticmethod
    def wait_procs(processes, timeout):
        return list(processes), []


class ProjectBrowserRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="grok-browser-registry-test-")
        self.root = Path(self.temp.name)
        self.registry_path = self.root / "registry.json"
        self.path_patch = mock.patch.multiple(
            registry,
            _REGISTRY_PATH=self.registry_path,
            _REGISTRY_LOCK_PATH=Path(f"{self.registry_path}.lock"),
        )
        self.path_patch.start()

    def tearDown(self):
        self.path_patch.stop()
        self.temp.cleanup()

    def test_register_and_unregister_publishes_private_json(self):
        profile = self.root / "xai-ts-chrome-fixture"
        profile.mkdir()
        with mock.patch.object(registry, "_process_create_time", return_value=123.5):
            registry.register_project_browser(424242, profile)

        entries = registry.registered_project_browsers()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["pid"], 424242)
        self.assertEqual(entries[0]["profile_dir"], str(profile.resolve()))
        payload = json.loads(self.registry_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["version"], 1)

        registry.unregister_project_browser(424242, profile)
        self.assertEqual(registry.registered_project_browsers(), [])

    def test_cleanup_uses_profile_marker_and_preserves_daily_chrome(self):
        project_profile = self.root / "xai-ts-chrome-project"
        project_profile.mkdir()
        daily_profile = self.root / "daily-chrome-profile"
        daily_profile.mkdir()
        child = _FakeProcess(201, "chrome.exe", ["--type=renderer"])
        project = _FakeProcess(
            200,
            "chrome.exe",
            [f"--user-data-dir={project_profile}"],
            children=[child],
        )
        daily = _FakeProcess(
            100,
            "chrome.exe",
            [f"--user-data-dir={daily_profile}"],
        )
        fake_psutil = _FakePsutil([daily, project, child])

        with mock.patch.object(registry, "_load_psutil", return_value=fake_psutil):
            result = registry.terminate_project_browser_trees(grace_sec=0)

        self.assertEqual(result["browser_roots"], 1)
        self.assertTrue(project.terminated)
        self.assertTrue(child.terminated)
        self.assertFalse(daily.terminated)
        self.assertFalse(daily.killed)
        self.assertFalse(project_profile.exists())
        self.assertTrue(daily_profile.exists())

    def test_non_project_profile_is_rejected(self):
        daily_profile = self.root / "daily-profile"
        daily_profile.mkdir()
        registry.register_project_browser(0, daily_profile)
        self.assertEqual(registry.registered_project_browsers(), [])

    def test_registered_pid_still_requires_matching_chromium_profile(self):
        project_profile = self.root / "xai-ts-chrome-project"
        project_profile.mkdir()
        daily_profile = self.root / "daily-profile"
        daily_profile.mkdir()
        with mock.patch.object(registry, "_process_create_time", return_value=200.0):
            registry.register_project_browser(200, project_profile)
        daily = _FakeProcess(
            200,
            "chrome.exe",
            [f"--user-data-dir={daily_profile}"],
        )

        with mock.patch.object(registry, "_load_psutil", return_value=_FakePsutil([daily])):
            result = registry.terminate_project_browser_trees(
                owner_pid=registry.os.getpid(),
                grace_sec=0,
                remove_profiles=False,
            )

        self.assertEqual(result["browser_roots"], 0)
        self.assertFalse(daily.terminated)
        self.assertFalse(daily.killed)

    def test_owner_cleanup_preserves_profile_used_by_another_live_browser(self):
        project_profile = self.root / "xai-ts-chrome-shared"
        project_profile.mkdir()
        with mock.patch.object(registry, "_process_create_time", return_value=200.0):
            registry.register_project_browser(200, project_profile)
        mismatched = _FakeProcess(200, "chrome.exe", ["--user-data-dir=daily-profile"])
        other_owner_browser = _FakeProcess(
            300,
            "chrome.exe",
            [f"--user-data-dir={project_profile}"],
        )

        with mock.patch.object(
            registry,
            "_load_psutil",
            return_value=_FakePsutil([mismatched, other_owner_browser]),
        ):
            result = registry.terminate_project_browser_trees(
                owner_pid=registry.os.getpid(),
                grace_sec=0,
                remove_profiles=True,
            )

        self.assertEqual(result["browser_roots"], 0)
        self.assertTrue(project_profile.exists())
        self.assertFalse(other_owner_browser.terminated)

    def test_owner_cleanup_preserves_a_newer_registration(self):
        profile = self.root / "xai-ts-chrome-reregistered"
        profile.mkdir()
        old_entry = {
            "pid": 200,
            "owner_pid": 111,
            "profile_dir": str(profile),
            "create_time": 200.0,
            "registered_at": 1.0,
        }
        new_entry = dict(old_entry, owner_pid=222, registered_at=2.0)
        registry._write_entries_unlocked([new_entry])

        with mock.patch.object(
            registry,
            "registered_project_browsers",
            return_value=[old_entry],
        ), mock.patch.object(registry, "_load_psutil", return_value=None):
            registry.terminate_project_browser_trees(
                owner_pid=111,
                grace_sec=0,
                remove_profiles=True,
            )

        self.assertEqual(registry.registered_project_browsers(), [new_entry])
        self.assertTrue(profile.exists())

    def test_interpreter_exit_cleanup_is_owner_scoped(self):
        with mock.patch.object(registry, "terminate_project_browser_trees") as terminate, mock.patch.object(
            registry.os,
            "getpid",
            return_value=9876,
        ):
            registry._cleanup_owned_browsers_at_exit()
        terminate.assert_called_once_with(owner_pid=9876, grace_sec=1.0)


if __name__ == "__main__":
    unittest.main()

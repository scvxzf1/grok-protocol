"""Project-scoped Chromium PID/profile tracking and bounded cleanup.

Only processes launched with this project's private ``xai-ts-chrome-*`` profile
marker are eligible.  Daily-use browser processes are deliberately outside the
selection rule even when their executable name is Chrome/Chromium.
"""

from __future__ import annotations

import atexit
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from cross_process_lock import (
    CrossProcessFileLock,
    atomic_write_private_text,
    configured_lock_timeout,
)


PROJECT_PROFILE_PREFIX = "xai-ts-chrome-"
_REGISTRY_VERSION = 1
_CHROMIUM_PROCESS_NAMES = frozenset(
    {
        "chrome",
        "chrome.exe",
        "chromium",
        "chromium.exe",
        "chromium-browser",
        "chromium-browser.exe",
        "google-chrome",
        "google-chrome-stable",
    }
)
_REGISTRY_PATH = Path(
    os.environ.get("XAI_BROWSER_REGISTRY_PATH")
    or (Path(tempfile.gettempdir()) / "grok-protocol-browser-registry.json")
).expanduser().resolve(strict=False)
_REGISTRY_LOCK_PATH = Path(f"{_REGISTRY_PATH}.lock")
_REGISTRY_LOCK_TIMEOUT = configured_lock_timeout(
    "XAI_BROWSER_REGISTRY_LOCK_TIMEOUT_SECONDS",
    default=10.0,
    maximum=120.0,
)


def browser_registry_path() -> Path:
    return _REGISTRY_PATH


def _resolved_profile(value: object) -> Optional[Path]:
    text = str(value or "").strip().strip('"')
    if not text:
        return None
    path = Path(text).expanduser().resolve(strict=False)
    if not path.name.startswith(PROJECT_PROFILE_PREFIX):
        return None
    temp_root = Path(tempfile.gettempdir()).expanduser().resolve(strict=False)
    try:
        if os.path.commonpath((str(path), str(temp_root))) != str(temp_root):
            return None
    except (OSError, ValueError):
        return None
    return path


def is_project_browser_profile(value: object) -> bool:
    return _resolved_profile(value) is not None


def _clean_entry(value: object) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict):
        return None
    try:
        pid = int(value.get("pid") or 0)
        owner_pid = int(value.get("owner_pid") or 0)
        create_time = float(value.get("create_time") or 0.0)
        registered_at = float(value.get("registered_at") or 0.0)
    except (TypeError, ValueError):
        return None
    profile = _resolved_profile(value.get("profile_dir"))
    if pid <= 1 and profile is None:
        return None
    return {
        "pid": pid if pid > 1 else 0,
        "owner_pid": owner_pid if owner_pid > 1 else 0,
        "profile_dir": str(profile) if profile is not None else "",
        "create_time": max(0.0, create_time),
        "registered_at": max(0.0, registered_at),
    }


def _read_entries_unlocked() -> list[Dict[str, Any]]:
    try:
        payload = json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []
    raw_entries = payload.get("entries") if isinstance(payload, dict) else []
    entries: list[Dict[str, Any]] = []
    for raw in raw_entries if isinstance(raw_entries, list) else []:
        entry = _clean_entry(raw)
        if entry is not None:
            entries.append(entry)
    return entries


def _write_entries_unlocked(entries: Iterable[Dict[str, Any]]) -> None:
    cleaned = [entry for item in entries if (entry := _clean_entry(item)) is not None]
    payload = {
        "version": _REGISTRY_VERSION,
        "entries": cleaned,
    }
    atomic_write_private_text(
        _REGISTRY_PATH,
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
    )


def _load_psutil():
    try:
        import psutil

        return psutil
    except Exception:
        return None


def _process_create_time(pid: int) -> float:
    psutil = _load_psutil()
    if psutil is None or int(pid or 0) <= 1:
        return 0.0
    try:
        return float(psutil.Process(int(pid)).create_time())
    except Exception:
        return 0.0


def register_project_browser(pid: int, profile_dir: object) -> None:
    profile = _resolved_profile(profile_dir)
    normalized_pid = int(pid or 0)
    if normalized_pid <= 1 and profile is None:
        return
    entry = {
        "pid": normalized_pid if normalized_pid > 1 else 0,
        "owner_pid": os.getpid(),
        "profile_dir": str(profile) if profile is not None else "",
        "create_time": _process_create_time(normalized_pid),
        "registered_at": time.time(),
    }
    with CrossProcessFileLock(_REGISTRY_LOCK_PATH, timeout=_REGISTRY_LOCK_TIMEOUT):
        entries = _read_entries_unlocked()
        entries = [
            item
            for item in entries
            if not (
                (entry["pid"] > 1 and item.get("pid") == entry["pid"])
                or (
                    entry["profile_dir"]
                    and item.get("profile_dir") == entry["profile_dir"]
                )
            )
        ]
        entries.append(entry)
        _write_entries_unlocked(entries)


def unregister_project_browser(pid: int = 0, profile_dir: object = "") -> None:
    normalized_pid = int(pid or 0)
    profile = _resolved_profile(profile_dir)
    profile_text = str(profile) if profile is not None else ""
    if normalized_pid <= 1 and not profile_text:
        return
    owner_pid = os.getpid()
    with CrossProcessFileLock(_REGISTRY_LOCK_PATH, timeout=_REGISTRY_LOCK_TIMEOUT):
        entries = _read_entries_unlocked()
        kept = [
            item
            for item in entries
            if not (
                int(item.get("owner_pid") or 0) == owner_pid
                and (
                    (normalized_pid > 1 and item.get("pid") == normalized_pid)
                    or (profile_text and item.get("profile_dir") == profile_text)
                )
            )
        ]
        if kept != entries:
            _write_entries_unlocked(kept)


def registered_project_browsers() -> list[Dict[str, Any]]:
    with CrossProcessFileLock(_REGISTRY_LOCK_PATH, timeout=_REGISTRY_LOCK_TIMEOUT):
        return [dict(entry) for entry in _read_entries_unlocked()]


def _process_info_value(process: Any, key: str, default: Any = None) -> Any:
    info = getattr(process, "info", None)
    if isinstance(info, dict) and key in info:
        return info.get(key, default)
    value = getattr(process, key, default)
    try:
        return value() if callable(value) else value
    except Exception:
        return default


def _project_profiles_from_cmdline(cmdline: object) -> list[Path]:
    args = [str(item or "") for item in (cmdline or [])] if isinstance(cmdline, (list, tuple)) else []
    profiles: list[Path] = []
    for index, arg in enumerate(args):
        value = ""
        if arg.startswith("--user-data-dir="):
            value = arg.split("=", 1)[1]
        elif arg == "--user-data-dir" and index + 1 < len(args):
            value = args[index + 1]
        profile = _resolved_profile(value)
        if profile is not None and profile not in profiles:
            profiles.append(profile)
    return profiles


def _entry_matches_process(entry: Dict[str, Any], process: Any) -> bool:
    pid = int(_process_info_value(process, "pid", 0) or 0)
    if pid <= 1 or pid != int(entry.get("pid") or 0):
        return False
    name = str(_process_info_value(process, "name", "") or "").lower()
    if name not in _CHROMIUM_PROCESS_NAMES:
        return False
    expected_create_time = float(entry.get("create_time") or 0.0)
    if expected_create_time:
        try:
            actual_create_time = float(process.create_time())
        except Exception:
            actual_create_time = 0.0
        if actual_create_time and abs(actual_create_time - expected_create_time) > 0.01:
            return False
    expected_profile = _resolved_profile(entry.get("profile_dir"))
    if expected_profile is None:
        return False
    profiles = _project_profiles_from_cmdline(_process_info_value(process, "cmdline", []))
    return expected_profile in profiles


def _entry_identity(entry: Dict[str, Any]) -> tuple[int, int, str, float, float]:
    """Return a stable identity so cleanup cannot erase a newer registration."""

    return (
        int(entry.get("pid") or 0),
        int(entry.get("owner_pid") or 0),
        str(entry.get("profile_dir") or ""),
        float(entry.get("create_time") or 0.0),
        float(entry.get("registered_at") or 0.0),
    )


def _is_marker_process(process: Any) -> tuple[bool, list[Path]]:
    name = str(_process_info_value(process, "name", "") or "").lower()
    if name not in _CHROMIUM_PROCESS_NAMES:
        return False, []
    profiles = _project_profiles_from_cmdline(_process_info_value(process, "cmdline", []))
    return bool(profiles), profiles


def _remove_profile_dir(profile_dir: object) -> bool:
    profile = _resolved_profile(profile_dir)
    if profile is None or not profile.exists():
        return False
    try:
        import shutil

        shutil.rmtree(profile, ignore_errors=False)
        return not profile.exists()
    except OSError:
        return False


def terminate_project_browser_trees(
    *,
    owner_pid: Optional[int] = None,
    grace_sec: float = 2.0,
    remove_profiles: bool = True,
) -> Dict[str, int]:
    """Terminate only registered/marker-profile Chromium trees.

    ``owner_pid`` restricts interpreter-exit cleanup to registrations made by
    that Python process.  A service-wide stale cleanup omits it and also scans
    command lines for the project profile marker.
    """

    psutil = _load_psutil()
    entries = registered_project_browsers()
    selected_entries = [
        entry
        for entry in entries
        if owner_pid is None or int(entry.get("owner_pid") or 0) == int(owner_pid)
    ]
    roots: Dict[int, Any] = {}
    marker_profiles_by_pid: Dict[int, set[str]] = {}
    live_unselected_profiles: set[str] = set()
    profiles = {
        str(profile)
        for entry in selected_entries
        if (profile := _resolved_profile(entry.get("profile_dir"))) is not None
    }

    if psutil is not None:
        by_pid: Dict[int, Any] = {}
        try:
            processes = list(psutil.process_iter(["pid", "name", "cmdline"]))
        except Exception:
            processes = []
        for process in processes:
            pid = int(_process_info_value(process, "pid", 0) or 0)
            if pid > 1:
                by_pid[pid] = process
            marked, found_profiles = _is_marker_process(process)
            if marked and pid > 1:
                marker_profiles_by_pid[pid] = {
                    str(profile) for profile in found_profiles
                }
                if owner_pid is None:
                    roots[pid] = process
                    profiles.update(str(profile) for profile in found_profiles)
        for entry in selected_entries:
            pid = int(entry.get("pid") or 0)
            process = by_pid.get(pid)
            if process is not None and _entry_matches_process(entry, process):
                roots[pid] = process

        # If both a browser root and one of its children were discovered, keep
        # only the highest selected ancestor so each tree is closed once.
        for pid, process in list(roots.items()):
            try:
                parent = process.parent()
            except Exception:
                parent = None
            while parent is not None:
                parent_pid = int(getattr(parent, "pid", 0) or 0)
                if parent_pid in roots:
                    roots.pop(pid, None)
                    break
                try:
                    parent = parent.parent()
                except Exception:
                    break

        targets: Dict[int, Any] = {}
        for root in roots.values():
            try:
                descendants = root.children(recursive=True)
            except Exception:
                descendants = []
            for process in [*descendants, root]:
                pid = int(getattr(process, "pid", 0) or 0)
                if pid > 1:
                    targets[pid] = process
        # Owner-scoped cleanup must not remove a profile currently used by a
        # different live project browser.  Global cleanup selects every marker
        # root, so its target PIDs intentionally receive no such protection.
        live_unselected_profiles = {
            profile
            for pid, found_profiles in marker_profiles_by_pid.items()
            if pid not in targets
            for profile in found_profiles
        }
        for process in targets.values():
            try:
                process.terminate()
            except Exception:
                pass
        alive = list(targets.values())
        if alive:
            try:
                _gone, alive = psutil.wait_procs(alive, timeout=max(0.0, float(grace_sec)))
            except Exception:
                pass
        for process in alive:
            try:
                process.kill()
            except Exception:
                pass
        if alive:
            try:
                psutil.wait_procs(alive, timeout=max(0.2, min(2.0, float(grace_sec))))
            except Exception:
                pass

    selected_keys = {_entry_identity(entry) for entry in selected_entries}
    removed_profiles = 0
    with CrossProcessFileLock(_REGISTRY_LOCK_PATH, timeout=_REGISTRY_LOCK_TIMEOUT):
        current = _read_entries_unlocked()
        # A browser may have re-registered the same profile while process-tree
        # shutdown was in progress.  Keep that newer owner's directory and
        # registry row together; holding the lock closes the check/delete gap.
        protected_profiles = {
            str(profile)
            for entry in current
            if _entry_identity(entry) not in selected_keys
            if (profile := _resolved_profile(entry.get("profile_dir"))) is not None
        }
        protected_profiles.update(live_unselected_profiles)
        if remove_profiles:
            for profile in profiles:
                if str(profile) in protected_profiles:
                    continue
                if _remove_profile_dir(profile):
                    removed_profiles += 1
        kept = [
            entry
            for entry in current
            if _entry_identity(entry) not in selected_keys
        ]
        if kept != current:
            _write_entries_unlocked(kept)

    return {
        "registered": len(selected_entries),
        "browser_roots": len(roots),
        "profiles_removed": removed_profiles,
    }


def _cleanup_owned_browsers_at_exit() -> None:
    try:
        terminate_project_browser_trees(owner_pid=os.getpid(), grace_sec=1.0)
    except Exception:
        pass


atexit.register(_cleanup_owned_browsers_at_exit)

"""Canonical locations for machine-local configuration, fixtures, and output."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple


PROJECT_ROOT = Path(__file__).resolve().parent


def _resolved_path(value: object, default: Path) -> Path:
    raw = str(value or "").strip()
    path = Path(raw).expanduser() if raw else Path(default)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


LOCAL_ROOT = _resolved_path(os.environ.get("XAI_LOCAL_DIR"), PROJECT_ROOT / ".local")
CONFIG_PATH = _resolved_path(os.environ.get("XAI_CONFIG_PATH"), LOCAL_ROOT / "config.json")
ACCOUNTS_DIR = LOCAL_ROOT / "accounts"
CREDENTIALS_DIR = LOCAL_ROOT / "credentials"
REGISTRATION_INFO_DIR = LOCAL_ROOT / "registration_info"
RUNS_DIR = LOCAL_ROOT / "runs"
EXPORTS_DIR = LOCAL_ROOT / "exports"
FIXTURES_DIR = LOCAL_ROOT / "fixtures"
STATE_DIR = LOCAL_ROOT / "state"


def path_is_file(path: Path) -> bool:
    """True when ``path`` is a regular file; False on missing/unreadable FS errors.

    NTFS/ntfs3 can leave directory entries whose name is still listed but
    ``stat``/``open`` fail with ``OSError(EINVAL)``. Treat those as absent so
    callers can skip them instead of aborting a whole directory scan.
    """
    try:
        return path.is_file()
    except OSError:
        return False


def path_mtime(path: Path, default: float = 0.0) -> float:
    """Return ``st_mtime`` or ``default`` when the path cannot be statted."""
    try:
        return float(path.stat().st_mtime)
    except OSError:
        return float(default)


def iter_readable_files(
    directory: Path | str,
    *,
    suffixes: Optional[Sequence[str]] = None,
    sort_by_mtime: bool = True,
) -> Tuple[List[Path], List[str]]:
    """List readable files under ``directory``, skipping corrupt entries.

    Returns ``(files, skipped_names)``. ``skipped_names`` are basenames that
    appear in the directory listing but raise ``OSError`` on ``is_file``/``stat``
    (common with damaged NTFS MFT records).
    """
    root = Path(directory).expanduser()
    files: List[Path] = []
    skipped: List[str] = []
    try:
        if not root.is_dir():
            return files, skipped
    except OSError:
        return files, skipped

    allowed: Optional[set[str]] = None
    if suffixes is not None:
        allowed = {str(s).lower() if str(s).startswith(".") else f".{str(s).lower()}" for s in suffixes}

    try:
        entries: Iterable[Path] = root.iterdir()
    except OSError:
        return files, skipped

    timed: List[Tuple[Path, float]] = []
    for entry in entries:
        if allowed is not None and entry.suffix.lower() not in allowed:
            continue
        try:
            if not entry.is_file():
                continue
            mtime = float(entry.stat().st_mtime)
        except OSError:
            skipped.append(entry.name)
            continue
        timed.append((entry, mtime))

    if sort_by_mtime:
        timed.sort(key=lambda item: item[1], reverse=True)
    else:
        timed.sort(key=lambda item: item[0].name.lower())
    files = [path for path, _mtime in timed]
    return files, skipped


__all__ = [
    "PROJECT_ROOT",
    "LOCAL_ROOT",
    "CONFIG_PATH",
    "ACCOUNTS_DIR",
    "CREDENTIALS_DIR",
    "REGISTRATION_INFO_DIR",
    "RUNS_DIR",
    "EXPORTS_DIR",
    "FIXTURES_DIR",
    "STATE_DIR",
    "path_is_file",
    "path_mtime",
    "iter_readable_files",
]

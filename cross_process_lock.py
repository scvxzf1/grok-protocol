"""Cross-platform locks and crash-safe writes for machine-local state.

The project has several short read/modify/write transactions shared by worker
processes.  Keep the platform-specific locking inside this module so importing
callers never depends on :mod:`fcntl` being available.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Iterable, Optional, Union

from filelock import FileLock, Timeout as FileLockTimeout


PathLike = Union[str, os.PathLike[str]]
DEFAULT_LOCK_TIMEOUT_SECONDS = 60.0


class CrossProcessLockError(RuntimeError):
    """Base operational error for a machine-local process lock."""


class CrossProcessLockTimeout(CrossProcessLockError):
    """Raised when a process lock is not acquired within its bounded wait."""

    def __init__(self, path: PathLike, timeout: float):
        self.path = Path(path)
        self.timeout = float(timeout)
        super().__init__(
            f"process lock timed out after {self.timeout:g}s ({self.path.name})"
        )


def configured_lock_timeout(
    env_name: str,
    *,
    default: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
    minimum: float = 0.05,
    maximum: float = 600.0,
) -> float:
    """Read a bounded lock timeout from an environment variable."""

    raw = str(os.environ.get(env_name) or "").strip()
    if not raw:
        return float(default)
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return float(default)
    return max(float(minimum), min(float(maximum), value))


def _make_parent(path: Path) -> None:
    parent = path.parent
    existed = parent.exists()
    parent.mkdir(parents=True, exist_ok=True)
    if not existed:
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass


def ensure_private_file(path: PathLike) -> None:
    """Best-effort owner-only permissions for an existing local state file."""

    target = Path(path)
    if not target.exists():
        return
    try:
        os.chmod(target, 0o600)
    except OSError:
        # Windows ACLs are platform/configuration dependent.  FileLock still
        # provides mutual exclusion and callers keep these files machine-local.
        pass


class CrossProcessFileLock:
    """A bounded, typed wrapper around :class:`filelock.FileLock`."""

    def __init__(
        self,
        path: PathLike,
        *,
        timeout: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
    ) -> None:
        self.path = Path(path).expanduser().resolve(strict=False)
        self.timeout = max(0.0, float(timeout))
        self._lock = FileLock(str(self.path))
        self._acquired = False

    @property
    def is_locked(self) -> bool:
        return bool(self._acquired and self._lock.is_locked)

    def acquire(self, *, timeout: Optional[float] = None) -> "CrossProcessFileLock":
        wait = self.timeout if timeout is None else max(0.0, float(timeout))
        _make_parent(self.path)
        try:
            self._lock.acquire(timeout=wait)
        except FileLockTimeout as exc:
            raise CrossProcessLockTimeout(self.path, wait) from exc
        self._acquired = True
        ensure_private_file(self.path)
        return self

    def release(self) -> None:
        if not self._acquired:
            return
        try:
            self._lock.release()
        finally:
            self._acquired = False

    def __enter__(self) -> "CrossProcessFileLock":
        return self.acquire()

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.release()


def _fsync_parent_directory(path: Path) -> None:
    """Best-effort persistence of the directory entry published by replace."""

    flags = getattr(os, "O_RDONLY", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(str(path.parent), flags)
    except (AttributeError, OSError):
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write_private_text(path: PathLike, text: str) -> None:
    """Atomically publish UTF-8 text without exposing a partial target file."""

    target = Path(path).expanduser().resolve(strict=False)
    _make_parent(target)
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=str(target.parent),
    )
    temp_path = Path(temp_name)
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            fd = -1
            handle.write(str(text))
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        os.replace(temp_path, target)
        ensure_private_file(target)
        _fsync_parent_directory(target)
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            temp_path.unlink()
        except OSError:
            pass


def atomic_write_private_lines(path: PathLike, lines: Iterable[str]) -> None:
    """Atomically publish a newline-terminated UTF-8 line file."""

    materialized = [str(line) for line in lines]
    payload = "\n".join(materialized)
    if materialized:
        payload += "\n"
    atomic_write_private_text(path, payload)

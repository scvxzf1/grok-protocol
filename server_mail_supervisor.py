#!/usr/bin/env python3
"""Crash-resumable, non-interactive mailbox drain supervisor.

The master file is the durable target manifest.  A small working mailbox file is
rebuilt for every fixed-size epoch.  Mailbox rows claimed by a failed worker are
therefore returned to the next epoch, while rows with a valid credential JSON
are never submitted again.  An exact ``xai-<email>.sso`` sidecar is treated as a
credential-conversion job rather than a registration job.

Supervisor output intentionally contains counters only.  Mailbox rows, email
addresses, SSO values, and proxy values are never written to its log or state
file.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence

from filelock import FileLock, Timeout as FileLockTimeout

from http_batch_service import BatchService, cleanup_browser_residues
from sso_to_auth_json import sso_file_name
from xai_http_flow import (
    MS_MAIL_POOL_LOCK_TIMEOUT_SEC,
    parse_ms_mail_line,
    serialize_ms_mail_line,
)


ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_EPOCH_SIZE = 20
DEFAULT_WORKERS = 4
DEFAULT_TURNSTILE_WORKERS = 2
DEFAULT_SUBMIT_WORKERS = 2


class SupervisorError(RuntimeError):
    """Operational error whose message is safe to print."""


class AlreadyRunningError(SupervisorError):
    pass


@dataclass(frozen=True)
class MailRecord:
    email: str
    line: str

    @property
    def key(self) -> str:
        return _email_key(self.email)


@dataclass(frozen=True)
class ReconcileResult:
    planned: int
    complete_keys: frozenset[str]
    convert_keys: frozenset[str]
    pending_keys: tuple[str, ...]

    @property
    def complete(self) -> int:
        return len(self.complete_keys)

    @property
    def convert(self) -> int:
        return len(self.convert_keys)

    @property
    def pending(self) -> int:
        return len(self.pending_keys)


def _email_key(value: object) -> str:
    return str(value or "").strip().lower()


def _atomic_write_text(path: Path, text: str, *, mode: int = 0o600) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        try:
            os.fchmod(fd, mode)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _atomic_write_lines(path: Path, lines: Iterable[str]) -> None:
    values = [str(line) for line in lines]
    payload = "\n".join(values)
    if values:
        payload += "\n"
    _atomic_write_text(path, payload)


def _atomic_write_json(path: Path, payload: Mapping[str, object]) -> None:
    _atomic_write_text(path, json.dumps(dict(payload), ensure_ascii=False, indent=2) + "\n")


def _read_mail_records(path: Path, *, required: bool) -> Dict[str, MailRecord]:
    path = Path(path)
    if not path.is_file():
        if required:
            raise SupervisorError("目标邮箱清单不存在")
        return {}
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        raise SupervisorError("目标邮箱清单读取失败") from exc

    records: Dict[str, MailRecord] = {}
    for number, raw in enumerate(lines, 1):
        stripped = str(raw or "").strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            account = parse_ms_mail_line(stripped)
            serialized = serialize_ms_mail_line(account)
        except Exception as exc:
            raise SupervisorError(f"目标邮箱清单第 {number} 行格式异常") from exc
        email = str(account.get("email") or "").strip()
        key = _email_key(email)
        if not key:
            raise SupervisorError(f"目标邮箱清单第 {number} 行缺少身份字段")
        # Last occurrence wins.  This is important when a rotated Graph refresh
        # token was appended after an older copy of the same account.
        records[key] = MailRecord(email=email, line=serialized)
    if required and not records:
        raise SupervisorError("目标邮箱清单没有有效记录")
    return records


def _read_proxy_rows(path: Path) -> list[str]:
    try:
        lines = Path(path).read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        raise SupervisorError("代理清单读取失败") from exc
    rows: list[str] = []
    seen: set[str] = set()
    for raw in lines:
        value = str(raw or "").strip()
        if not value or value.startswith("#") or value in seen:
            continue
        seen.add(value)
        rows.append(value)
    if not rows:
        raise SupervisorError("代理清单没有有效记录")
    return rows


class SingleInstanceLock:
    """Hold a non-blocking OS lock for the whole supervisor lifetime."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._handle = None

    def __enter__(self) -> "SingleInstanceLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        try:
            if os.name == "nt":
                import msvcrt

                if self.path.stat().st_size == 0:
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError) as exc:
            handle.close()
            raise AlreadyRunningError("已有监督进程持有运行锁") from exc
        self._handle = handle
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        handle = self._handle
        self._handle = None
        if handle is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        handle.close()


def _terminate_process_group(process: subprocess.Popen) -> None:
    """Stop a helper and any descendants without copying its secret argv."""

    if process.poll() is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=5)
        return
    except Exception:
        pass
    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=2)
    except Exception:
        pass


def _quiet_subprocess(
    command: Sequence[str],
    timeout_sec: float,
    *,
    stop_requested: Optional[Callable[[], bool]] = None,
) -> int:
    """Run a secret-bearing argv without copying child output into logs."""

    kwargs: Dict[str, object] = {
        "cwd": str(ROOT_DIR),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    process = subprocess.Popen(list(command), **kwargs)
    deadline = time.monotonic() + max(1.0, float(timeout_sec))
    while True:
        return_code = process.poll()
        if return_code is not None:
            return int(return_code)
        if stop_requested is not None and bool(stop_requested()):
            _terminate_process_group(process)
            return 130
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_process_group(process)
            return 124
        time.sleep(min(0.2, remaining))


class ServerMailSupervisor:
    def __init__(
        self,
        *,
        config_path: Path,
        master_path: Path,
        work_path: Path,
        proxy_path: Path,
        output_dir: Path,
        state_path: Optional[Path] = None,
        epoch_size: int = DEFAULT_EPOCH_SIZE,
        workers: int = DEFAULT_WORKERS,
        turnstile_workers: int = DEFAULT_TURNSTILE_WORKERS,
        submit_workers: int = DEFAULT_SUBMIT_WORKERS,
        epoch_timeout_sec: float = 3600.0,
        idle_timeout_sec: float = 900.0,
        stop_grace_sec: float = 45.0,
        credential_timeout_sec: float = 300.0,
        poll_interval_sec: float = 0.5,
        retry_delay_sec: float = 10.0,
        service_factory: Optional[Callable[..., object]] = None,
        command_runner: Optional[Callable[[Sequence[str], float], int]] = None,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.config_path = Path(config_path).expanduser().resolve()
        self.master_path = Path(master_path).expanduser().resolve()
        self.work_path = Path(work_path).expanduser().resolve()
        self.proxy_path = Path(proxy_path).expanduser().resolve()
        self.output_dir = Path(output_dir).expanduser().resolve()
        self.state_path = Path(state_path or self.master_path.with_suffix(self.master_path.suffix + ".state.json")).expanduser().resolve()
        self.epoch_size = max(1, min(DEFAULT_EPOCH_SIZE, int(epoch_size or DEFAULT_EPOCH_SIZE)))
        self.workers = max(1, min(DEFAULT_WORKERS, int(workers or DEFAULT_WORKERS)))
        self.turnstile_workers = max(1, min(DEFAULT_TURNSTILE_WORKERS, int(turnstile_workers or DEFAULT_TURNSTILE_WORKERS)))
        self.submit_workers = max(1, min(DEFAULT_SUBMIT_WORKERS, int(submit_workers or DEFAULT_SUBMIT_WORKERS)))
        self.epoch_timeout_sec = max(1.0, float(epoch_timeout_sec))
        self.idle_timeout_sec = max(1.0, float(idle_timeout_sec))
        self.stop_grace_sec = max(1.0, float(stop_grace_sec))
        self.credential_timeout_sec = max(1.0, float(credential_timeout_sec))
        self.poll_interval_sec = max(0.01, float(poll_interval_sec))
        self.retry_delay_sec = max(0.0, float(retry_delay_sec))
        self.service_factory = service_factory or (
            lambda **kwargs: BatchService(**kwargs)
        )
        self.command_runner = command_runner or (
            lambda command, timeout: _quiet_subprocess(
                command,
                timeout,
                stop_requested=lambda: self.stop_requested,
            )
        )
        self.logger = logger or (lambda message: print(message, flush=True))
        self.records: Dict[str, MailRecord] = {}
        self.order: list[str] = []
        self.proxy_rows: list[str] = []
        self.epoch = 0
        self.no_progress_epochs = 0
        self.stop_requested = False
        self._stop_event = threading.Event()

    @property
    def used_path(self) -> Path:
        return self.work_path.with_suffix(self.work_path.suffix + ".used")

    @property
    def mail_lock_path(self) -> Path:
        return self.work_path.with_suffix(self.work_path.suffix + ".lock")

    def _log_counts(self, label: str, result: ReconcileResult) -> None:
        self.logger(
            f"{label} planned={result.planned} complete={result.complete} "
            f"convert={result.convert} pending={result.pending}"
        )

    def _load_master_and_latest(self) -> None:
        try:
            with FileLock(
                str(self.mail_lock_path),
                timeout=MS_MAIL_POOL_LOCK_TIMEOUT_SEC,
            ):
                master = _read_mail_records(self.master_path, required=True)
                if not self.order:
                    self.order = list(master)
                # Master is the target boundary.  Work files may only update
                # credentials for identities already present in that manifest.
                for extra_path in (self.work_path, self.used_path):
                    for key, record in _read_mail_records(extra_path, required=False).items():
                        if key in master:
                            master[key] = record
                self.records = master
                # Persist rotated refresh tokens while holding the same lock used
                # by MicrosoftGraphMailbox, before a later epoch clears .used.
                _atomic_write_lines(
                    self.master_path,
                    (master[key].line for key in self.order if key in master),
                )
        except FileLockTimeout as exc:
            raise SupervisorError("邮箱池 checkpoint 锁等待超时") from exc

    def _valid_credential_keys(self) -> set[str]:
        target_keys = set(self.records)
        complete: set[str] = set()
        if not self.output_dir.is_dir():
            return complete
        for path in self.output_dir.rglob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeError):
                continue
            if not isinstance(data, dict):
                continue
            key = _email_key(data.get("email"))
            if key not in target_keys:
                continue
            if str(data.get("type") or "").strip().lower() != "xai":
                continue
            if str(data.get("auth_kind") or "").strip().lower() != "oauth":
                continue
            if data.get("disabled") is not False:
                continue
            if not str(data.get("access_token") or "").strip():
                continue
            if not str(data.get("refresh_token") or "").strip():
                continue
            complete.add(key)
        return complete

    def _exact_sso_path(self, key: str) -> Path:
        record = self.records[key]
        return self.output_dir / sso_file_name(record.email)

    def reconcile(self) -> ReconcileResult:
        self._load_master_and_latest()
        complete = self._valid_credential_keys()
        convert: set[str] = set()
        for key in self.order:
            if key in complete or key not in self.records:
                continue
            path = self._exact_sso_path(key)
            try:
                if path.is_file() and path.stat().st_size > 1:
                    convert.add(key)
            except OSError:
                continue
        pending = tuple(
            key
            for key in self.order
            if key in self.records and key not in complete and key not in convert
        )
        return ReconcileResult(
            planned=len(self.records),
            complete_keys=frozenset(complete),
            convert_keys=frozenset(convert),
            pending_keys=pending,
        )

    def _write_state(
        self,
        result: ReconcileResult,
        *,
        epoch_succeeded: int = 0,
        epoch_failed: int = 0,
    ) -> None:
        # Values are deliberately integers only; no identity, path, SSO, or
        # proxy material is ever persisted here.
        payload = {
            "epochs": int(self.epoch),
            "planned": int(result.planned),
            "complete": int(result.complete),
            "convert": int(result.convert),
            "pending": int(result.pending),
            "epoch_succeeded": int(epoch_succeeded),
            "epoch_failed": int(epoch_failed),
            "no_progress_epochs": int(self.no_progress_epochs),
        }
        _atomic_write_json(self.state_path, payload)

    def _load_state_counters(self) -> None:
        """Resume rotation/backoff counters; the state contains no identities."""

        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeError):
            return
        if not isinstance(payload, dict):
            return
        try:
            epochs = int(payload.get("epochs") or 0)
            no_progress = int(payload.get("no_progress_epochs") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        self.epoch = max(0, epochs)
        self.no_progress_epochs = max(0, no_progress)

    def _select_epoch(self, pending: Sequence[str]) -> list[str]:
        values = list(pending)
        if len(values) <= self.epoch_size:
            return values
        offset = (max(0, self.epoch - 1) * self.epoch_size) % len(values)
        rotated = values[offset:] + values[:offset]
        return rotated[: self.epoch_size]

    def _rebuild_work(self, keys: Sequence[str]) -> None:
        try:
            with FileLock(
                str(self.mail_lock_path),
                timeout=MS_MAIL_POOL_LOCK_TIMEOUT_SEC,
            ):
                _atomic_write_lines(
                    self.work_path,
                    (self.records[key].line for key in keys),
                )
                _atomic_write_lines(self.used_path, ())
        except FileLockTimeout as exc:
            raise SupervisorError("邮箱池重建锁等待超时") from exc

    def _patch_runtime_config(self, count: int) -> None:
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SupervisorError("运行配置读取失败") from exc
        if not isinstance(data, dict):
            raise SupervisorError("运行配置根节点格式异常")
        config: MutableMapping[str, object] = dict(data)
        config.update(
            {
                "email_provider": "msgraph",
                "ms_mail_file": str(self.work_path),
                "credential_flow": "pkce",
                "register_count": max(1, int(count)),
                "concurrent_workers": self.workers,
                "target_mode": "count",
                "turnstile_provider": "local",
                "turnstile_headless": True,
                "local_turnstile_max_workers": self.turnstile_workers,
                "turnstile_workers": self.turnstile_workers,
                "turnstile_queue_size": 8,
                "submit_workers": self.submit_workers,
                "browser_max_tasks": 6,
                "proxy_mode": "pool",
                "proxy_file": str(self.proxy_path),
                "proxy_random": True,
                "proxy_slot_sticky": True,
                "embedded_proxy_enabled": False,
                "xai_oauth_output_dir": str(self.output_dir),
            }
        )
        # Registration and Turnstile share the proxy-pool row selected by the
        # registration child unless an independent solver proxy is configured.
        for key in (
            "proxy_rotate_session",
            "proxy",
            "proxy_parent",
            "proxy_subscription_local_http",
            "turnstile_proxy",
            "turnstile_proxy_file",
            "turnstile_proxy_enabled",
            "turnstile_proxy_mode",
            "turnstile_proxy_random",
            "solver_slots",
        ):
            config.pop(key, None)
        _atomic_write_json(self.config_path, config)

    def _convert_one(self, key: str) -> bool:
        sso_path = self._exact_sso_path(key)
        record = self.records[key]
        command = [
            sys.executable,
            str(ROOT_DIR / "grok_register_ttk.py"),
            "http",
            "credential",
            "--proxy-file",
            str(self.proxy_path),
            "--proxy-random",
            "--sso-file",
            str(sso_path),
            "--output-dir",
            str(self.output_dir),
            "--email",
            record.email,
        ]
        try:
            return_code = int(self.command_runner(command, self.credential_timeout_sec))
        except Exception:
            return_code = 125
        # Do not include command, identity, child output, or exception text.
        self.logger(f"credential-convert result={return_code}")
        return return_code == 0

    def _convert_pending(self, result: ReconcileResult) -> None:
        for key in self.order:
            if self.stop_requested:
                return
            if key in result.convert_keys:
                self._convert_one(key)

    def _stop_service(self, service: object) -> bool:
        """Request a drain and return only after BatchService reports done."""

        try:
            if bool(service.is_busy()):
                service.stop_run()
        except Exception:
            pass
        deadline = time.monotonic() + self.stop_grace_sec
        while time.monotonic() < deadline:
            try:
                service.poll()
                snap = service.current_snapshot() or {}
            except Exception:
                return False
            if bool(snap.get("done")):
                return True
            time.sleep(self.poll_interval_sec)
        return False

    def _run_epoch(self, selected: Sequence[str]) -> Dict[str, int]:
        self._rebuild_work(selected)
        self._patch_runtime_config(len(selected))
        service = self.service_factory(config_path=self.config_path, root_dir=ROOT_DIR)
        started = time.monotonic()
        last_progress_at = started
        last_progress: tuple[int, int, int] = (-1, -1, -1)
        snapshot: Dict[str, object] = {}
        drained = False
        drain_attempted = False
        try:
            snapshot = dict(
                service.start_run(
                    {
                        "count": len(selected),
                        "workers": self.workers,
                        "target_mode": "count",
                    }
                )
                or {}
            )
            while not self.stop_requested:
                service.poll()
                snapshot = dict(service.current_snapshot() or {})
                progress = (
                    int(snapshot.get("started_tasks") or 0),
                    int(snapshot.get("completed") or 0),
                    int(snapshot.get("active") or 0),
                )
                if progress != last_progress:
                    last_progress = progress
                    last_progress_at = time.monotonic()
                now = time.monotonic()
                if bool(snapshot.get("done")):
                    break
                if now - started >= self.epoch_timeout_sec:
                    self.logger("epoch watchdog=runtime")
                    drain_attempted = True
                    drained = self._stop_service(service)
                    if not drained:
                        raise SupervisorError("批次运行看门狗收尾超时")
                    snapshot = dict(service.current_snapshot() or snapshot)
                    break
                if now - last_progress_at >= self.idle_timeout_sec:
                    self.logger("epoch watchdog=idle")
                    drain_attempted = True
                    drained = self._stop_service(service)
                    if not drained:
                        raise SupervisorError("批次空闲看门狗收尾超时")
                    snapshot = dict(service.current_snapshot() or snapshot)
                    break
                self._stop_event.wait(self.poll_interval_sec)
        except SupervisorError:
            raise
        except Exception:
            self.logger("epoch service-error=1")
            drain_attempted = True
            drained = self._stop_service(service)
            if not drained:
                raise SupervisorError("批次异常后收尾超时")
            try:
                snapshot = dict(service.current_snapshot() or snapshot)
            except Exception:
                pass
        finally:
            if not drained and not drain_attempted:
                drain_attempted = True
                drained = self._stop_service(service)
            if not drained:
                raise SupervisorError("批次子进程未在宽限期内结束")
        return {
            "succeeded": int(snapshot.get("succeeded") or 0),
            "failed": int(snapshot.get("failed") or 0),
        }

    def request_stop(self, *_args) -> None:
        self.stop_requested = True
        self._stop_event.set()

    def run(self, *, max_epochs: int = 0) -> int:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.output_dir, 0o700)
        except OSError:
            pass
        self.proxy_rows = _read_proxy_rows(self.proxy_path)
        self._load_state_counters()
        initial_state = self.reconcile()
        self._write_state(initial_state)
        self._log_counts("supervisor-start", initial_state)

        while not self.stop_requested:
            before = self.reconcile()
            if before.complete >= before.planned:
                self._write_state(before)
                self._log_counts("supervisor-complete", before)
                return 0

            self._convert_pending(before)
            after_convert = self.reconcile()
            if self.stop_requested:
                self._write_state(after_convert)
                return 130
            if after_convert.complete >= after_convert.planned:
                self._write_state(after_convert)
                self._log_counts("supervisor-complete", after_convert)
                return 0

            epoch_stats = {"succeeded": 0, "failed": 0}
            if after_convert.pending:
                self.epoch += 1
                if max_epochs > 0 and self.epoch > max_epochs:
                    self._write_state(after_convert)
                    return 2
                selected = self._select_epoch(after_convert.pending_keys)
                self.logger(f"epoch-start epoch={self.epoch} size={len(selected)}")
                epoch_stats = self._run_epoch(selected)

            after = self.reconcile()
            progressed = after.complete > before.complete
            self.no_progress_epochs = 0 if progressed else self.no_progress_epochs + 1
            self._write_state(
                after,
                epoch_succeeded=epoch_stats["succeeded"],
                epoch_failed=epoch_stats["failed"],
            )
            self._log_counts("epoch-end", after)
            if after.complete >= after.planned:
                return 0
            if self.stop_requested:
                return 130
            if self.retry_delay_sec > 0:
                multiplier = min(30, 2 ** min(5, max(0, self.no_progress_epochs - 1)))
                self._stop_event.wait(self.retry_delay_sec * multiplier)
        return 130

    def cleanup(self) -> None:
        try:
            cleanup_browser_residues(kill_playwright=True, kill_all_chrome=False)
        except Exception:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="服务器邮箱持续批次监督器")
    parser.add_argument("--config", required=True, help="服务器运行配置 JSON")
    parser.add_argument("--master", required=True, help="目标邮箱 master 文件")
    parser.add_argument("--work", required=True, help="每轮重建的工作邮箱文件")
    parser.add_argument("--proxy", required=True, help="代理清单文件")
    parser.add_argument("--output", required=True, help="凭证输出目录")
    parser.add_argument("--state", default="", help="仅含计数的状态 JSON")
    parser.add_argument("--lock", default="", help="单实例锁文件")
    parser.add_argument("--epoch-size", type=int, default=DEFAULT_EPOCH_SIZE)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--turnstile-workers", type=int, default=DEFAULT_TURNSTILE_WORKERS)
    parser.add_argument("--submit-workers", type=int, default=DEFAULT_SUBMIT_WORKERS)
    parser.add_argument("--epoch-timeout", type=float, default=3600.0)
    parser.add_argument("--idle-timeout", type=float, default=900.0)
    parser.add_argument("--credential-timeout", type=float, default=300.0)
    parser.add_argument("--retry-delay", type=float, default=10.0)
    parser.add_argument("--max-epochs", type=int, default=0, help=argparse.SUPPRESS)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    master = Path(args.master).expanduser().resolve()
    state = Path(args.state).expanduser().resolve() if str(args.state or "").strip() else master.with_suffix(master.suffix + ".state.json")
    lock = Path(args.lock).expanduser().resolve() if str(args.lock or "").strip() else state.with_suffix(state.suffix + ".lock")
    supervisor = ServerMailSupervisor(
        config_path=Path(args.config),
        master_path=master,
        work_path=Path(args.work),
        proxy_path=Path(args.proxy),
        output_dir=Path(args.output),
        state_path=state,
        epoch_size=args.epoch_size,
        workers=args.workers,
        turnstile_workers=args.turnstile_workers,
        submit_workers=args.submit_workers,
        epoch_timeout_sec=args.epoch_timeout,
        idle_timeout_sec=args.idle_timeout,
        credential_timeout_sec=args.credential_timeout,
        retry_delay_sec=args.retry_delay,
    )
    previous_int = signal.getsignal(signal.SIGINT)
    previous_term = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGINT, supervisor.request_stop)
    signal.signal(signal.SIGTERM, supervisor.request_stop)
    try:
        with SingleInstanceLock(lock):
            return supervisor.run(max_epochs=max(0, int(args.max_epochs or 0)))
    except AlreadyRunningError:
        print("supervisor-lock busy=1", file=sys.stderr, flush=True)
        return 3
    except SupervisorError as exc:
        print(f"supervisor-error type={type(exc).__name__}", file=sys.stderr, flush=True)
        return 2
    finally:
        supervisor.cleanup()
        signal.signal(signal.SIGINT, previous_int)
        signal.signal(signal.SIGTERM, previous_term)


if __name__ == "__main__":
    raise SystemExit(main())

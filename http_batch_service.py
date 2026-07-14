# -*- coding: utf-8 -*-
"""HTTP batch registration service shared by WebUI and the transitional TUI.

No curses UI lives here. This module owns config, plan building, BatchRunner
process orchestration, and browser residue tools.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import queue
import secrets
import shutil
import signal
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Sequence, Tuple

from cross_process_lock import (
    CrossProcessFileLock,
    CrossProcessLockTimeout,
    atomic_write_private_text,
    configured_lock_timeout,
    ensure_private_file,
)
from project_browser_registry import (
    registered_project_browsers,
    terminate_project_browser_trees,
)
from local_paths import (
    CONFIG_PATH as LOCAL_CONFIG_PATH,
    CREDENTIALS_DIR as LOCAL_CREDENTIALS_DIR,
    EXPORTS_DIR as LOCAL_EXPORTS_DIR,
    FIXTURES_DIR as LOCAL_FIXTURES_DIR,
    LOCAL_ROOT,
    RUNS_DIR as LOCAL_RUNS_DIR,
)


ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = LOCAL_CONFIG_PATH
DEFAULT_OUTPUT_DIR = LOCAL_CREDENTIALS_DIR
DEFAULT_EXPORT_DIR = LOCAL_EXPORTS_DIR
RUNS_DIR = LOCAL_RUNS_DIR
MAX_COUNT = 99999999
TARGET_MODE_COUNT = "count"
TARGET_MODE_CONTINUOUS = "continuous"
DEFAULT_REFILL_PAUSE_SEC = 2.0
REFILL_PAUSE_LOG_INTERVAL_SEC = 5.0
CIRCUIT_WINDOW_SIZE = 50
CIRCUIT_FAIL_RATE = 0.8
CIRCUIT_PAUSE_SEC = 30.0
# Continuous mode: if no active workers and no progress for this long while
# refill is allowed, force-clear soft pauses so high-concurrency runs cannot
# freeze forever after a pause/spawn glitch.
CONTINUOUS_STALL_RECOVERY_SEC = 20.0
PROXY_HEALTH_CHECK_INTERVAL_SEC = 15.0
PROXY_DEAD_PAUSE_SEC = 15.0
STATIC_PROXY_HEALTH_TIMEOUT_SEC = 12.0
STATIC_PROXY_HEALTH_PROBE_WORKERS = 2
STATIC_PROXY_HEALTH_ATTEMPTS = 3
STATIC_PROXY_HEALTH_BACKOFF_SEC = 0.35
STATIC_PROXY_SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"
STATIC_PROXY_MS_TOKEN_URL = (
    "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
)
RECENT_WORKER_WINDOW = 200
MAX_WORKERS = 128
MAX_LOCAL_TURNSTILE_WORKERS = 3  # default local Turnstile concurrency cap
MIN_LOCAL_TURNSTILE_WORKERS = 1
ABS_MAX_LOCAL_TURNSTILE_WORKERS = 6666
DEFAULT_TURNSTILE_QUEUE_SIZE = 64
DEFAULT_SUBMIT_WORKERS = 4
MAX_SUBMIT_WORKERS = 32
MAX_LOG_LINES = 700
DEFAULT_SSO_CONVERT_RETRIES = 5
DEFAULT_SSO_CONVERT_COOLDOWN = 3
MAX_SSO_CONVERT_RETRIES = 20
MAX_SSO_CONVERT_COOLDOWN = 120
MS_MAIL_POOL_UI_LOCK_TIMEOUT_SEC = configured_lock_timeout(
    "XAI_MS_MAIL_POOL_LOCK_TIMEOUT_SEC",
    default=60.0,
)
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
MAIL_RECORD_RE = re.compile(
    r"(?i)[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+----[^\r\n]+"
)
EMAIL_ADDRESS_RE = re.compile(
    r"(?i)(?<![A-Z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+"
)
SENSITIVE_VALUE_RE = re.compile(
    r"(?i)\b(access[_-]?token|refresh[_-]?token|sso(?:[_-]?cookie)?|password|client[_-]?id)"
    r"(\s*[=:]\s*[\"']?)([^\s\"',;}]+)"
)
BEARER_VALUE_RE = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]+")
MS_REFRESH_VALUE_RE = re.compile(r"\bM\.[A-Za-z0-9._~+/=-]{8,}")
JWT_VALUE_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)
UUID_VALUE_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}\b"
)

STATUS_LABELS = {
    "queued": "排队中",
    "running": "运行中",
    "converting": "转换中",
    "succeeded": "成功",
    "failed": "失败",
    "stopped": "已停止",
}

PROXY_MODE_LABELS = {
    "auto": "自动",
    "none": "不使用",
    "direct": "直连代理",
    "pool": "代理池",
}

# 面向 UI 的出口组合（proxy_mode + embedded_proxy_enabled）
# 运行台「代理模式」与配置中心「出口方式」共用同一套语义。
EGRESS_MODE_NODES = "nodes"
EGRESS_MODE_HTTP = "http"
EGRESS_MODE_HYBRID = "hybrid"
EGRESS_MODE_DIRECT = "direct"
EGRESS_MODE_AUTO = "auto"
EGRESS_MODE_OFF = "off"
EGRESS_MODE_ORDER = [
    EGRESS_MODE_NODES,
    EGRESS_MODE_HTTP,
    EGRESS_MODE_HYBRID,
    EGRESS_MODE_DIRECT,
    EGRESS_MODE_AUTO,
    EGRESS_MODE_OFF,
]
EGRESS_MODE_LABELS = {
    EGRESS_MODE_NODES: "只用节点池",
    EGRESS_MODE_HTTP: "只用 HTTP 池",
    EGRESS_MODE_HYBRID: "一起用",
    EGRESS_MODE_DIRECT: "固定一个",
    EGRESS_MODE_AUTO: "自动",
    EGRESS_MODE_OFF: "完全关闭",
}
EGRESS_MODE_HINTS = {
    EGRESS_MODE_NODES: "VLESS/Hy2 订阅 → mihomo",
    EGRESS_MODE_HTTP: "手写 / 订阅 HTTP 代理",
    EGRESS_MODE_HYBRID: "节点池 + HTTP 池轮询",
    EGRESS_MODE_DIRECT: "只用一个 HTTP 代理 URL",
    EGRESS_MODE_AUTO: "有固定 URL 用固定，否则走 HTTP 池",
    EGRESS_MODE_OFF: "节点池和 HTTP 池都不用",
}

TURNSTILE_PROVIDER_ORDER = ["capsolver", "2captcha", "yescaptcha", "local"]
TURNSTILE_PROVIDER_LABELS = {
    "capsolver": "CapSolver",
    "2captcha": "2Captcha",
    "yescaptcha": "YesCaptcha",
    "local": "本地浏览器仅求解",
}

# 运行链路模式：模式1 是现有注册链路，模式2 仅做占位。
RUN_MODE_REGISTER_OTP = "register_otp"
RUN_MODE_REGISTER_SSO = "register_sso"
DEFAULT_RUN_MODE = RUN_MODE_REGISTER_OTP
RUN_MODE_ORDER = [RUN_MODE_REGISTER_OTP, RUN_MODE_REGISTER_SSO]
RUN_MODE_LABELS = {
    RUN_MODE_REGISTER_OTP: "模式1:注册+otp",
    RUN_MODE_REGISTER_SSO: "模式2:注册+sso转换",
}
RUN_MODE_ALIASES = {
    "1": RUN_MODE_REGISTER_OTP,
    "mode1": RUN_MODE_REGISTER_OTP,
    "otp": RUN_MODE_REGISTER_OTP,
    "register_otp": RUN_MODE_REGISTER_OTP,
    "register+otp": RUN_MODE_REGISTER_OTP,
    "2": RUN_MODE_REGISTER_SSO,
    "mode2": RUN_MODE_REGISTER_SSO,
    "sso": RUN_MODE_REGISTER_SSO,
    "register_sso": RUN_MODE_REGISTER_SSO,
    "register+sso": RUN_MODE_REGISTER_SSO,
    "sso_convert": RUN_MODE_REGISTER_SSO,
}


class TuiConfigError(RuntimeError):
    """批量任务启动前，启动参数不合法时抛出。"""


def _pgrep_count(pattern: str) -> int:
    """Count processes matching pattern via pgrep -c -f."""
    try:
        result = subprocess.run(
            ["pgrep", "-c", "-f", pattern],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return 0
    raw = (result.stdout or "").strip()
    if result.returncode not in {0, 1}:
        return 0
    try:
        return max(0, int(raw or "0"))
    except ValueError:
        return 0


def _count_zombie_chrome() -> int:
    """Count [chrome] <defunct> processes (zombie chrome leftovers)."""
    try:
        result = subprocess.run(
            ["ps", "-eo", "stat=,comm="],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return 0
    count = 0
    for line in str(result.stdout or "").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        stat, comm = parts[0], parts[1]
        # Zombie processes report state starting with Z.
        if not stat.startswith("Z"):
            continue
        name = comm.lower()
        if "chrome" in name or "chromium" in name:
            count += 1
    return count


def browser_health_status() -> Dict[str, int]:
    """Snapshot local browser residue pressure for Turnstile headed launches."""
    return {
        "chrome_count": _pgrep_count("chrome"),
        "playwright_count": _pgrep_count("ms-playwright/chromium"),
        "solver_count": _pgrep_count("turnstile_solver.src serve"),
        "zombie_chrome_count": _count_zombie_chrome(),
    }


def format_browser_health(status: Optional[Dict[str, int]] = None) -> str:
    data = status or browser_health_status()
    chrome = int(data.get("chrome_count") or 0)
    playwright = int(data.get("playwright_count") or 0)
    solvers = int(data.get("solver_count") or 0)
    zombies = int(data.get("zombie_chrome_count") or 0)
    level = "正常"
    if chrome >= 200 or playwright >= 100 or zombies >= 80 or solvers >= 5:
        level = "高风险"
    elif chrome >= 80 or playwright >= 30 or zombies >= 20 or solvers >= 3:
        level = "偏高"
    return (
        f"{level} | chrome={chrome} | zombie={zombies} | "
        f"solver={solvers} | playwright={playwright}"
    )


_TEMP_DIR_GLOBS = (
    "xai-ts-chrome-*",
)
_TEMP_DIR_ORPHAN_GRACE_SEC = 30.0


def _reap_zombie_children() -> int:
    """Reap any already-dead child processes of the current process."""
    reaped = 0
    if os.name == "nt":
        return 0
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        except OSError:
            break
        if pid <= 0:
            break
        reaped += 1
    return reaped


def _kill_orphan_turnstile_solvers(*, keep_pids: Optional[set[int]] = None) -> int:
    """Kill leftover `turnstile_solver.src serve` processes not in keep_pids.

    Historical runs leave many solver parents alive; their dead chrome children
    then accumulate as zombies. Cleaning these orphans is safe for this project
    and does not touch the user's daily Chrome browser.
    """
    if os.name == "nt":
        return 0
    keep = set(int(x) for x in (keep_pids or set()) if int(x) > 1)
    keep.add(os.getpid())
    killed = 0
    pattern = "turnstile_solver.src serve"
    try:
        # Prefer pgrep list for precise pids.
        listed = subprocess.run(
            ["pgrep", "-f", pattern],
            capture_output=True,
            text=True,
            check=False,
        )
        pids = []
        for line in str(listed.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                pids.append(int(line))
            except ValueError:
                continue
        for pid in pids:
            if pid in keep:
                continue
            try:
                os.kill(pid, signal.SIGTERM)
                killed += 1
            except ProcessLookupError:
                continue
            except PermissionError:
                continue
        if killed:
            time.sleep(0.25)
            for pid in pids:
                if pid in keep:
                    continue
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    continue
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    pass
    except Exception:
        # Fallback to pkill pattern.
        before = _pgrep_count(pattern)
        if before > 0:
            subprocess.run(["pkill", "-f", pattern], capture_output=True, text=True, check=False)
            time.sleep(0.2)
            after = _pgrep_count(pattern)
            killed = max(0, before - after)
    _reap_zombie_children()
    return int(killed)


def cleanup_browser_residues(
    *,
    temp_root: Optional[Path] = None,
    kill_playwright: bool = True,
    kill_all_chrome: bool = False,
    kill_orphan_solvers: bool = True,
    keep_solver_pids: Optional[set[int]] = None,
    pkill_fn=None,
) -> Dict[str, int]:
    """Clean only Chromium trees bearing this project's profile marker.

    The legacy ``kill_playwright``/``kill_all_chrome``/``pkill_fn`` arguments
    remain call-compatible but never widen selection to unrelated browsers.
    """
    del kill_playwright, kill_all_chrome, pkill_fn

    killed_solvers = int(_kill_orphan_turnstile_solvers(keep_pids=keep_solver_pids) if kill_orphan_solvers else 0)
    project_cleanup = terminate_project_browser_trees(grace_sec=2.0)
    killed_project_chrome = int(project_cleanup.get("browser_roots") or 0)
    killed_playwright = 0
    killed_chrome = killed_project_chrome
    reaped_zombies = int(_reap_zombie_children())

    root = Path(temp_root or tempfile.gettempdir()).expanduser().resolve(strict=False)
    removed = int(project_cleanup.get("profiles_removed") or 0)
    try:
        protected_profiles = {
            str(Path(entry.get("profile_dir") or "").expanduser().resolve(strict=False))
            for entry in registered_project_browsers()
            if str(entry.get("profile_dir") or "").strip()
        }
    except Exception:
        protected_profiles = set()
    now = time.time()
    for pattern in _TEMP_DIR_GLOBS:
        for path in root.glob(pattern):
            try:
                resolved = path.resolve(strict=False)
                if os.path.commonpath((str(resolved), str(root))) != str(root):
                    continue
                if str(resolved) in protected_profiles:
                    continue
                # Browser launch creates its profile shortly before publishing
                # the PID.  A short grace period prevents a concurrent cleanup
                # pass from deleting that not-yet-registered directory.
                age = max(0.0, now - float(resolved.stat().st_mtime))
                if age < _TEMP_DIR_ORPHAN_GRACE_SEC:
                    continue
                if resolved.is_dir():
                    shutil.rmtree(resolved, ignore_errors=True)
                    removed += 1
                elif resolved.exists():
                    resolved.unlink(missing_ok=True)
                    removed += 1
            except (OSError, ValueError):
                continue

    health = browser_health_status()
    return {
        "killed_playwright": killed_playwright,
        "killed_chrome": killed_chrome,
        "killed_solvers": killed_solvers,
        "reaped_zombies": reaped_zombies,
        "removed_temp_dirs": removed,
        "chrome_count": int(health.get("chrome_count") or 0),
        "playwright_count": int(health.get("playwright_count") or 0),
        "solver_count": int(health.get("solver_count") or 0),
        "zombie_chrome_count": int(health.get("zombie_chrome_count") or 0),
    }


def format_cleanup_result(result: Dict[str, int]) -> str:
    return (
        f"已清理 Playwright={int(result.get('killed_playwright') or 0)}，"
        f"项目Chrome={int(result.get('killed_chrome') or 0)}，"
        f"残留solver={int(result.get('killed_solvers') or 0)}，"
        f"僵尸回收={int(result.get('reaped_zombies') or 0)}，"
        f"临时目录={int(result.get('removed_temp_dirs') or 0)}；"
        f"当前 chrome={int(result.get('chrome_count') or 0)}，"
        f"zombie={int(result.get('zombie_chrome_count') or 0)}，"
        f"solver={int(result.get('solver_count') or 0)}，"
        f"playwright={int(result.get('playwright_count') or 0)}"
    )




@dataclass
class Settings:
    config_path: Path
    count: int
    workers: int
    output_dir: Path
    run_mode: str = DEFAULT_RUN_MODE
    proxy_mode: str = "auto"
    no_proxy: bool = False
    turnstile_provider: str = "capsolver"
    turnstile_headless: bool = False
    turnstile_workers: int = 0
    turnstile_queue_size: int = DEFAULT_TURNSTILE_QUEUE_SIZE
    submit_workers: int = DEFAULT_SUBMIT_WORKERS
    turnstile_broker_url: str = ""
    sso_convert_retries: int = DEFAULT_SSO_CONVERT_RETRIES
    sso_convert_cooldown: int = DEFAULT_SSO_CONVERT_COOLDOWN
    target_mode: str = TARGET_MODE_COUNT
    target_success: int = 0
    continuous_max_runtime_min: int = 0
    config: Dict[str, object] = field(default_factory=dict)


@dataclass
class RunPlan:
    config_path: Path
    run_mode: str
    count: int
    workers: int
    output_dir: Path
    provider: str
    email_provider: str
    proxy_mode: str
    proxy_args: List[str]
    turnstile_headless: bool = False
    turnstile_workers: int = 1
    turnstile_queue_size: int = DEFAULT_TURNSTILE_QUEUE_SIZE
    submit_workers: int = DEFAULT_SUBMIT_WORKERS
    turnstile_broker_url: str = ""
    manage_turnstile_broker: bool = False
    sso_convert_retries: int = DEFAULT_SSO_CONVERT_RETRIES
    sso_convert_cooldown: int = DEFAULT_SSO_CONVERT_COOLDOWN
    warnings: List[str] = field(default_factory=list)
    embedded_proxy_enabled: bool = False
    embedded_proxy_max_node_retries: int = 3
    # Static HTTP affinity remains opt-in for compatibility with generic
    # weighted rotation.  A durable supervisor may force this switch per run.
    proxy_slot_sticky: bool = False
    proxy_pool_entries: Tuple[str, ...] = field(default_factory=tuple)
    target_mode: str = TARGET_MODE_COUNT
    target_success: int = 0
    continuous_max_runtime_min: int = 0


@dataclass
class WorkerState:
    index: int
    status: str = "queued"
    process: Optional[subprocess.Popen[str]] = None
    convert_thread: Optional[threading.Thread] = None
    log_path: Optional[Path] = None
    accounts_path: Optional[Path] = None
    last_log: str = "等待空闲槽位"
    return_code: Optional[int] = None
    proxy_node_id: Optional[str] = None
    proxy_node_name: str = ""
    proxy_local_http: str = ""
    # HTTP pool assignment (proxies.txt / subscription HTTP). Can mix with embedded.
    manual_proxy: str = ""
    manual_proxy_lease_token: str = field(default="", repr=False)
    uses_independent_turnstile_proxy: bool = False
    tried_node_ids: List[str] = field(default_factory=list)
    proxy_attempt: int = 0


def _char_width(char: str) -> int:
    if char in {"\n", "\r"}:
        return 0
    if unicodedata.east_asian_width(char) in {"F", "W"}:
        return 2
    if unicodedata.combining(char):
        return 0
    return 1


def _display_width(text: str) -> int:
    return sum(_char_width(char) for char in text)


def _clip_display(text: str, width: int) -> str:
    if width <= 0:
        return ""
    result: List[str] = []
    used = 0
    for char in text:
        char_width = _char_width(char)
        if used + char_width > width:
            break
        result.append(char)
        used += char_width
    return "".join(result)


def _pad_display(text: str, width: int) -> str:
    clipped = _clip_display(text, width)
    padding = max(0, width - _display_width(clipped))
    return clipped + (" " * padding)


def _safe_text(value: object, limit: int = 400) -> str:
    text = ANSI_ESCAPE_RE.sub("", str(value or "")).replace("\r", "").replace("\t", "    ")
    text = " ".join(text.split())
    return text[:limit]


def _redact_sensitive_runtime_text(value: object) -> str:
    """Remove mailbox identities and credentials from ordinary runtime logs."""

    text_value = str(value or "")
    text_value = MAIL_RECORD_RE.sub("[mail-record-redacted]", text_value)

    def mask_email(match: re.Match[str]) -> str:
        address = match.group(0)
        local, domain = address.split("@", 1)
        return f"{local[:1] or '*'}***@{domain}"

    text_value = EMAIL_ADDRESS_RE.sub(mask_email, text_value)
    text_value = SENSITIVE_VALUE_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}***",
        text_value,
    )
    text_value = BEARER_VALUE_RE.sub(r"\1***", text_value)
    text_value = MS_REFRESH_VALUE_RE.sub("[refresh-token-redacted]", text_value)
    text_value = JWT_VALUE_RE.sub("[jwt-redacted]", text_value)
    return UUID_VALUE_RE.sub("[uuid-redacted]", text_value)


def _status_label(status: str) -> str:
    return STATUS_LABELS.get(status, status)


def _proxy_mode_label(mode: str) -> str:
    return PROXY_MODE_LABELS.get(mode, mode)


def _normalize_proxy_mode(value: object) -> str:
    mode = str(value or "auto").strip().lower()
    if mode in PROXY_MODE_LABELS:
        return mode
    # 兼容旧别名
    aliases = {
        "off": "none",
        "disabled": "none",
        "disable": "none",
        "no": "none",
        "noproxy": "none",
        "no_proxy": "none",
        "fixed": "direct",
        "url": "direct",
        "single": "direct",
        "http": "pool",
        "http_pool": "pool",
        "proxies": "pool",
    }
    return aliases.get(mode, "auto")


def normalize_egress_mode(value: object) -> str:
    """Normalize UI egress mode; unknown → empty string."""
    raw = str(value or "").strip().lower()
    aliases = {
        "node": EGRESS_MODE_NODES,
        "nodes": EGRESS_MODE_NODES,
        "embedded": EGRESS_MODE_NODES,
        "mihomo": EGRESS_MODE_NODES,
        "vless": EGRESS_MODE_NODES,
        "http": EGRESS_MODE_HTTP,
        "http_pool": EGRESS_MODE_HTTP,
        "pool_only": EGRESS_MODE_HTTP,
        "hybrid": EGRESS_MODE_HYBRID,
        "both": EGRESS_MODE_HYBRID,
        "mix": EGRESS_MODE_HYBRID,
        "mixed": EGRESS_MODE_HYBRID,
        "direct": EGRESS_MODE_DIRECT,
        "fixed": EGRESS_MODE_DIRECT,
        "single": EGRESS_MODE_DIRECT,
        "auto": EGRESS_MODE_AUTO,
        "off": EGRESS_MODE_OFF,
        "close": EGRESS_MODE_OFF,
        "closed": EGRESS_MODE_OFF,
        "disabled": EGRESS_MODE_OFF,
        "none": EGRESS_MODE_OFF,
        "full_off": EGRESS_MODE_OFF,
    }
    mode = aliases.get(raw, raw)
    return mode if mode in EGRESS_MODE_LABELS else ""


def encode_egress_mode(proxy_mode: object, embedded_enabled: object) -> str:
    """Map (proxy_mode, embedded_proxy_enabled) → UI egress mode."""
    mode = _normalize_proxy_mode(proxy_mode)
    emb = _as_bool(embedded_enabled)
    if emb and mode == "none":
        return EGRESS_MODE_NODES
    if emb and mode in {"pool", "auto"}:
        # auto + embedded 历史上可能被当成混合；统一按 hybrid 展示
        return EGRESS_MODE_HYBRID
    if emb and mode == "direct":
        # 固定 URL 一般不混节点池；若误开节点池，仍按固定展示并在 apply 时关掉
        return EGRESS_MODE_DIRECT
    if not emb and mode == "pool":
        return EGRESS_MODE_HTTP
    if not emb and mode == "direct":
        return EGRESS_MODE_DIRECT
    if not emb and mode == "auto":
        return EGRESS_MODE_AUTO
    if not emb and mode == "none":
        return EGRESS_MODE_OFF
    # fallback
    if emb:
        return EGRESS_MODE_NODES
    return EGRESS_MODE_AUTO


def decode_egress_mode(egress_mode: object) -> Tuple[str, bool]:
    """Map UI egress mode → (proxy_mode, embedded_proxy_enabled)."""
    mode = normalize_egress_mode(egress_mode)
    if mode == EGRESS_MODE_NODES:
        return "none", True
    if mode == EGRESS_MODE_HTTP:
        return "pool", False
    if mode == EGRESS_MODE_HYBRID:
        return "pool", True
    if mode == EGRESS_MODE_DIRECT:
        return "direct", False
    if mode == EGRESS_MODE_AUTO:
        return "auto", False
    if mode == EGRESS_MODE_OFF:
        return "none", False
    # default safe-ish: auto HTTP side only
    return "auto", False


def apply_egress_mode_to_config(cfg: Dict[str, object], egress_mode: object) -> str:
    """Write proxy_mode/tui_proxy_mode/embedded_proxy_enabled into cfg. Return normalized egress mode."""
    mode = normalize_egress_mode(egress_mode)
    if not mode:
        raise TuiConfigError(
            "出口模式无效，可选: nodes/http/hybrid/direct/auto/off"
        )
    proxy_mode, embedded = decode_egress_mode(mode)
    cfg["proxy_mode"] = proxy_mode
    cfg["tui_proxy_mode"] = proxy_mode
    cfg["embedded_proxy_enabled"] = bool(embedded)
    cfg.pop("proxy_parent", None)
    return mode


def _egress_mode_label(mode: str) -> str:
    return EGRESS_MODE_LABELS.get(mode, mode)


# 注册代理池维护来源：手动编辑 proxies 文件 vs 从订阅导入覆盖写入。
PROXY_POOL_SOURCE_MANUAL = "manual"
PROXY_POOL_SOURCE_SUBSCRIPTION = "subscription"
PROXY_POOL_SOURCE_LABELS = {
    PROXY_POOL_SOURCE_MANUAL: "手动维护",
    PROXY_POOL_SOURCE_SUBSCRIPTION: "订阅导入",
}
# 内嵌 mihomo 节点缓存（VLESS/Hysteria2/AnyTLS/Trojan；与订阅拉取解耦；启动只读此文件）
EMBEDDED_VLESS_CACHE_REL = Path("state") / "embedded_mihomo" / "vless_nodes.txt"
EMBEDDED_NODE_CACHE_REL = Path("state") / "embedded_mihomo" / "nodes.txt"


def normalize_proxy_pool_source(value: object) -> str:
    """Normalize proxy_pool_source; unknown/empty → manual (safe default)."""
    raw = str(value or "").strip().lower()
    if raw in {
        PROXY_POOL_SOURCE_MANUAL,
        "file",
        "pool",
        "text",
        "hand",
        "manual_pool",
    }:
        return PROXY_POOL_SOURCE_MANUAL
    if raw in {
        PROXY_POOL_SOURCE_SUBSCRIPTION,
        "sub",
        "subscribe",
        "url",
        "import",
    }:
        return PROXY_POOL_SOURCE_SUBSCRIPTION
    return PROXY_POOL_SOURCE_MANUAL


def _subscription_urls_for_fields(raw: object) -> List[str]:
    """Expose multi-URL list for settings UI (compat with legacy single URL)."""
    from proxy_subscription import resolve_subscription_urls_from_config

    return resolve_subscription_urls_from_config(raw)


def _apply_subscription_urls_to_config(cfg: dict, urls_value: object) -> List[str]:
    """Write proxy_subscription_urls + legacy proxy_subscription_url into cfg."""
    from proxy_subscription import normalize_subscription_urls

    urls = normalize_subscription_urls(urls_value)
    cfg["proxy_subscription_urls"] = list(urls)
    cfg["proxy_subscription_url"] = urls[0] if urls else ""
    return urls


def resolve_proxy_pool_source(config: object, *, strict: bool = False) -> str:
    """Read proxy_pool_source from config dict; default manual for legacy configs."""
    cfg = config if isinstance(config, dict) else {}
    raw = cfg.get("proxy_pool_source")
    if raw is None or str(raw).strip() == "":
        if strict:
            raise TuiConfigError("proxy_pool_source 不能为空，可选: manual/subscription")
        return PROXY_POOL_SOURCE_MANUAL
    text = str(raw).strip().lower()
    if text in {
        PROXY_POOL_SOURCE_MANUAL,
        PROXY_POOL_SOURCE_SUBSCRIPTION,
        "file",
        "pool",
        "text",
        "hand",
        "manual_pool",
        "sub",
        "subscribe",
        "url",
        "import",
    }:
        return normalize_proxy_pool_source(text)
    if strict:
        raise TuiConfigError("注册代理池来源无效，可选: manual/subscription")
    return PROXY_POOL_SOURCE_MANUAL


def require_proxy_pool_source(settings: Settings, expected: str, *, action: str) -> str:
    """Ensure current pool source matches expected; return normalized source."""
    source = resolve_proxy_pool_source(settings.config or {}, strict=False)
    expected_norm = normalize_proxy_pool_source(expected)
    if source != expected_norm:
        if expected_norm == PROXY_POOL_SOURCE_MANUAL:
            raise TuiConfigError(
                f"{action}仅在「手动维护」来源下可用；当前为「订阅导入」。"
                "请先在配置中心切换注册代理池来源。"
            )
        raise TuiConfigError(
            f"{action}仅在「订阅导入」来源下可用；当前为「手动维护」。"
            "请先在配置中心切换注册代理池来源。"
        )
    return source


PROXY_FAILURE_MARKERS = (
    "CONNECT tunnel failed",
    "ProxyError",
    "Connection refused",
    "curl: (56)",
    "curl: (7)",
    "curl: (35)",
    "TLS connect error",
    "OPENSSL_internal",
    "Tunnel connection failed",
    "407 Proxy Authentication Required",
    "Read timed out",
    # Cloudflare / xAI egress quality failures: rotate the node.
    "abusive traffic patterns",
    "Blocked due to abusive traffic",
    "打开注册页 HTTP 403",
    "HTTP 403",
    "cf-ray",
    "与页面的连接已断开",
    "浏览器启动/连接失败",
    "token_len=0",
)

# Challenge, mail, and token-verify issues should not burn embedded proxy retries.
# IMPORTANT: do NOT use bare keywords like "邮箱" — normal success logs also contain
# "邮箱验证码已通过校验", which would falsely suppress proxy rotation.
NON_PROXY_FAILURE_MARKERS = (
    "Failed to verify Cloudflare turnstile token",
    "Turnstile consume 后 token 无效",
    "返回的 Turnstile token 无效",
    "solver pool busy",
    "turnstile timeout",
    "turnstile challenge error",
    "未捕获到可用 turnstile token",
    "YYDS create HTTP",
    "YYDS create",
    "shared_domain_restricted",
    "shared domain is currently restricted",
    "email domain has been rejected",
    "email-domain-rejected",
    "account:email-domain-rejected",
    "没有可用邮箱",
    "邮箱池为空",
    "mail pool",
)


def _looks_like_proxy_failure(text: str) -> bool:
    """Heuristics for embedded-proxy node failures / bad egress.

    Browser disconnects and transport errors rotate nodes. Challenge timeouts and
    Turnstile error families stay with the browser retry classifier instead of
    charging an infrastructure failure to the route.
    """
    blob = str(text or "")
    if not blob:
        return False
    lower = blob.lower()

    # Strong proxy/browser signals first (may coexist with earlier successful mail logs).
    strong_proxy_signals = (
        "与页面的连接已断开",
        "浏览器启动/连接失败",
        "token_len=0",
        "abusive traffic",
        "blocked due to abusive traffic",
        "curl: (35)",
        "curl: (56)",
        "curl: (7)",
        "tls connect error",
        "openssl_internal",
        "connect tunnel failed",
        "proxyerror",
        "connection refused",
        "打开注册页 http 403",
    )
    last_strong_signal = max((lower.rfind(sig) for sig in strong_proxy_signals), default=-1)
    last_non_proxy_signal = max(
        (lower.rfind(marker.lower()) for marker in NON_PROXY_FAILURE_MARKERS),
        default=-1,
    )
    # Worker logs are chronological.  Let the later terminal diagnosis win so
    # an earlier token_len=0 does not mask a subsequent token-verification
    # rejection, while a later transport error still rotates the route.
    if last_non_proxy_signal > last_strong_signal:
        return False
    if last_strong_signal >= 0:
        return True

    if last_non_proxy_signal >= 0:
        return False
    if "没有可用的内嵌代理节点" in blob or "内嵌代理已启用但管理器未就绪" in blob:
        return True
    for marker in PROXY_FAILURE_MARKERS:
        if marker.lower() in lower:
            return True
    if "tls" in lower and ("error" in lower or "connect" in lower):
        return True
    return False



def _normalize_turnstile_provider(value: object) -> str:
    raw = str(value or "capsolver").strip().lower().replace(" ", "")
    aliases = {
        "cap": "capsolver",
        "cap-solver": "capsolver",
        "cap_solver": "capsolver",
        "2cap": "2captcha",
        "two": "2captcha",
        "yes": "yescaptcha",
        "browser": "local",
        "chrome": "local",
        "headless": "local",
        "local-browser": "local",
    }
    provider = aliases.get(raw, raw)
    if provider not in TURNSTILE_PROVIDER_LABELS:
        raise TuiConfigError(f"不支持的 Turnstile 求解方式: {value}")
    return provider


def _turnstile_provider_label(provider: str, *, headless: bool = False) -> str:
    base = TURNSTILE_PROVIDER_LABELS.get(provider, provider)
    if provider == "local" and headless:
        return f"{base}(无头,仅Turnstile阶段)"
    if provider == "local":
        return f"{base}(有界面,仅Turnstile阶段)"
    return base


def _run_mode_label(mode: str) -> str:
    return RUN_MODE_LABELS.get(mode, mode)


def _normalize_run_mode(value: object) -> str:
    raw = str(value or DEFAULT_RUN_MODE).strip().lower().replace(" ", "")
    mode = RUN_MODE_ALIASES.get(raw, raw)
    if mode not in RUN_MODE_LABELS:
        raise TuiConfigError(f"不支持的运行模式: {value}")
    return mode


def _sso_converter_path() -> Path:
    return ROOT_DIR / "sso_to_auth_json.py"


def _ensure_mode2_ready() -> None:
    converter = _sso_converter_path()
    if not converter.is_file():
        raise TuiConfigError(f"模式2 缺少转换脚本: {converter}")
    try:
        import curl_cffi  # noqa: F401
    except ImportError as exc:  # pragma: no cover - depends on local env
        raise TuiConfigError(
            "模式2 需要 curl_cffi（sso_to_auth_json Device Flow）。"
            f"当前 Python={sys.executable} 未安装 curl_cffi。"
            f"请执行: {sys.executable} -m pip install -r requirements.txt"
        ) from exc
    except Exception as exc:  # pragma: no cover - depends on local env
        raise TuiConfigError(
            "模式2 依赖 curl_cffi 但当前环境导入异常: "
            f"Python={sys.executable} err={exc}"
        ) from exc


def _parse_account_row(line: str) -> Optional[Tuple[str, str, str]]:
    """Parse email----password----sso.

    Password may end with '-' and produce '-----' before JWT, which used to make
    SSO become '-eyJ...' and break --sso-cookie. Prefer JWT-looking tail.
    """
    raw = str(line or "").strip()
    if not raw or raw.startswith("#"):
        return None
    # Fast path: normal 3-field split.
    parts = [part.strip() for part in raw.split("----")]
    if len(parts) >= 3:
        email = parts[0]
        password = "----".join(parts[1:-1]).strip() if len(parts) > 3 else parts[1]
        sso = parts[-1].lstrip("-").strip()
        if email and sso:
            return email, password, sso
    # Fallback: locate JWT-like SSO at end even if separators are messy.
    import re
    m = re.search(
        r"^(?P<email>[^\s@]+@[^\s@]+)-{2,}(?P<password>.+?)-{2,}(?P<sso>eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\s*$",
        raw,
    )
    if not m:
        return None
    email = m.group("email").strip()
    password = m.group("password").strip(" -")
    sso = m.group("sso").strip()
    if not email or not sso:
        return None
    return email, password, sso


def _read_config(path: Path) -> Dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TuiConfigError(f"找不到配置文件: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise TuiConfigError(f"无法读取配置 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise TuiConfigError("配置 JSON 根节点必须是对象")
    # Retire settings whose implementations were removed. Keeping them out of
    # memory also removes them the next time configuration is persisted.
    for retired_key in (
        "proxy_parent",
        "grok2api_auto_add_local",
        "grok2api_local_token_file",
        "grok2api_pool_name",
        "grok2api_auto_add_remote",
        "grok2api_remote_base",
        "grok2api_remote_app_key",
        "cloudflare_path_domains",
        "cloudflare_path_token",
        "enable_nsfw",
        "xai_oauth_auto",
        "xai_oauth_callback_port",
    ):
        data.pop(retired_key, None)
    return data


def _write_config(path: Path, data: Dict[str, object]) -> None:
    try:
        payload = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        atomic_write_private_text(path, payload)
    except OSError as exc:
        raise TuiConfigError(f"无法写入配置文件: {exc}") from exc


def _config_path_value(path: Path, base: Path) -> str:
    """尽量把路径写成相对配置目录，方便迁移。"""
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except Exception:
        return str(path)



def resolve_yyds_create_spacing_sec(
    config: Optional[Dict[str, object]] = None,
    *,
    strict: bool = False,
) -> float:
    """Return YYDS create spacing seconds from config/env.

    Default 1.5s keeps multi-worker create bursts from tripping older quotas.
    Set config.yyds_create_spacing_sec or env XAI_YYDS_CREATE_SPACING_SEC.
    """
    try:
        from xai_http_flow import resolve_yyds_create_spacing_sec as _resolve
    except Exception:
        # Fallback if import path is broken during partial boots.
        raw = None if not isinstance(config, dict) else config.get("yyds_create_spacing_sec")
        env_raw = str(os.environ.get("XAI_YYDS_CREATE_SPACING_SEC") or "").strip()
        text_value = env_raw if env_raw else ("" if raw is None else str(raw).strip())
        if text_value == "":
            return 1.5
        try:
            value = float(text_value)
        except (TypeError, ValueError) as exc:
            if strict:
                raise TuiConfigError("YYDS 建邮间隔必须是数字（秒）") from exc
            return 1.5
        if not 0.0 <= value <= 60.0:
            if strict:
                raise TuiConfigError("YYDS 建邮间隔必须介于 0 到 60 秒之间")
            return 1.5
        return value
    try:
        return float(_resolve(config if isinstance(config, dict) else None, strict=strict))
    except ValueError as exc:
        raise TuiConfigError(str(exc)) from exc
    except Exception as exc:
        if strict:
            raise TuiConfigError(f"YYDS 建邮间隔无效: {exc}") from exc
        return 1.5



def resolve_local_turnstile_max_inflight_cfg(config: object = None, *, strict: bool = False) -> int:
    """UI/config helper for cross-process local Turnstile inflight slots (1-12)."""
    try:
        from xai_http_flow import resolve_local_turnstile_max_inflight
    except Exception:
        raw = None
        if isinstance(config, dict):
            raw = config.get("local_turnstile_max_inflight")
            if raw is None or str(raw).strip() == "":
                raw = config.get("local_turnstile_max_workers")
        try:
            value = int(float(raw if raw is not None else 2))
        except Exception:
            value = 2
        return max(1, min(12, value))
    return int(resolve_local_turnstile_max_inflight(config if isinstance(config, dict) else None, strict=strict))


def resolve_local_turnstile_max_workers(
    config: Optional[Dict[str, object]] = None,
    *,
    strict: bool = False,
) -> int:
    """Return configured local Turnstile worker cap.

    strict=True: invalid values raise TuiConfigError (config-center save path).
    strict=False: missing/invalid values fall back to MAX_LOCAL_TURNSTILE_WORKERS.
    """
    raw = None if not isinstance(config, dict) else config.get("local_turnstile_max_workers")
    if raw is None or str(raw).strip() == "":
        return MAX_LOCAL_TURNSTILE_WORKERS
    try:
        number = int(str(raw).strip())
    except (TypeError, ValueError) as exc:
        if strict:
            raise TuiConfigError("本地 Turnstile 并发上限必须是整数") from exc
        return MAX_LOCAL_TURNSTILE_WORKERS
    if not MIN_LOCAL_TURNSTILE_WORKERS <= number <= ABS_MAX_LOCAL_TURNSTILE_WORKERS:
        if strict:
            raise TuiConfigError(
                "本地 Turnstile 并发上限必须介于 "
                f"{MIN_LOCAL_TURNSTILE_WORKERS} 到 {ABS_MAX_LOCAL_TURNSTILE_WORKERS} 之间"
            )
        return MAX_LOCAL_TURNSTILE_WORKERS
    return number


def _positive_int(value: object, label: str, maximum: int) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise TuiConfigError(f"{label} 必须是整数") from exc
    if not 1 <= number <= maximum:
        raise TuiConfigError(f"{label} 必须介于 1 到 {maximum} 之间")
    return number




def _optional_int(value: object, *, default: int) -> int:
    """Parse int; empty/None -> default. Preserves 0 (unlike `x or default`)."""
    if value is None or str(value).strip() == "":
        return int(default)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise TuiConfigError("必须是整数") from exc


def _bounded_int(value: object, label: str, *, minimum: int, maximum: int, default: int) -> int:
    if value is None or str(value).strip() == "":
        return default
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise TuiConfigError(f"{label} 必须是整数") from exc
    if not minimum <= number <= maximum:
        raise TuiConfigError(f"{label} 必须介于 {minimum} 到 {maximum} 之间")
    return number


def _absolute_path(value: str, base: Path = ROOT_DIR) -> Path:
    candidate = Path(str(value or "")).expanduser()
    if not candidate.is_absolute():
        candidate = base / candidate
    return candidate.resolve()


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _load_runtime_fields(settings: Settings) -> None:
    """从配置文件填充 TUI 运行设置。"""
    config = settings.config
    settings.count = _positive_int(config.get("register_count", 1), "注册数量", MAX_COUNT)
    settings.workers = _positive_int(config.get("concurrent_workers", 1), "并发数", MAX_WORKERS)
    settings.target_mode = _normalize_target_mode(
        config.get("run_target_mode") or config.get("target_mode") or TARGET_MODE_COUNT
    )
    settings.target_success = _bounded_int(
        config.get("target_success"),
        "成功目标",
        minimum=0,
        maximum=MAX_COUNT,
        default=0,
    )
    settings.continuous_max_runtime_min = _bounded_int(
        config.get("continuous_max_runtime_min"),
        "持续运行最长分钟",
        minimum=0,
        maximum=10080,
        default=0,
    )

    output_raw = str(
        config.get("xai_oauth_output_dir")
        or config.get("tui_output_dir")
        or ""
    ).strip()
    if output_raw:
        settings.output_dir = _absolute_path(output_raw, settings.config_path.parent)
    else:
        settings.output_dir = DEFAULT_OUTPUT_DIR.resolve()

    settings.run_mode = _normalize_run_mode(
        config.get("tui_run_mode") or config.get("run_mode") or DEFAULT_RUN_MODE
    )

    proxy_mode = _normalize_proxy_mode(config.get("tui_proxy_mode") or config.get("proxy_mode") or "auto")
    # Keep "none" as a real mode. Older code rewrote it to "auto", which made
    # build_plan re-enable proxies.txt even after the UI selected "不使用".
    settings.proxy_mode = proxy_mode
    settings.no_proxy = proxy_mode == "none"
    settings.turnstile_provider = _normalize_turnstile_provider(
        config.get("turnstile_provider") or "capsolver"
    )
    settings.turnstile_headless = _as_bool(config.get("turnstile_headless", False))
    settings.submit_workers = max(
        1,
        min(
            MAX_SUBMIT_WORKERS,
            _positive_int(
                config.get("submit_workers", DEFAULT_SUBMIT_WORKERS),
                "提交并发",
                MAX_SUBMIT_WORKERS,
            ),
        ),
    )
    settings.sso_convert_retries = _bounded_int(
        config.get("tui_sso_convert_retries", config.get("sso_convert_retries")),
        "SSO转换重试次数",
        minimum=1,
        maximum=MAX_SSO_CONVERT_RETRIES,
        default=DEFAULT_SSO_CONVERT_RETRIES,
    )
    settings.sso_convert_cooldown = _bounded_int(
        config.get("tui_sso_convert_cooldown", config.get("sso_convert_cooldown")),
        "SSO转换冷却秒数",
        minimum=0,
        maximum=MAX_SSO_CONVERT_COOLDOWN,
        default=DEFAULT_SSO_CONVERT_COOLDOWN,
    )


def persist_settings(settings: Settings) -> None:
    """把当前 TUI 运行设置写回配置文件。"""
    config = dict(settings.config or {})
    config["register_count"] = int(settings.count)
    config["concurrent_workers"] = int(settings.workers)
    config["run_target_mode"] = _normalize_target_mode(settings.target_mode)
    config["target_success"] = int(settings.target_success)
    config["continuous_max_runtime_min"] = int(settings.continuous_max_runtime_min)
    config["tui_run_mode"] = _normalize_run_mode(settings.run_mode)
    mode_now = "none" if settings.no_proxy else str(settings.proxy_mode or "auto")
    config["tui_proxy_mode"] = mode_now
    config["proxy_mode"] = mode_now
    config["xai_oauth_output_dir"] = _config_path_value(
        settings.output_dir, settings.config_path.parent
    )
    config["tui_sso_convert_retries"] = int(settings.sso_convert_retries)
    config["tui_sso_convert_cooldown"] = int(settings.sso_convert_cooldown)
    config["turnstile_provider"] = _normalize_turnstile_provider(settings.turnstile_provider)
    config["turnstile_headless"] = bool(settings.turnstile_headless)
    config["submit_workers"] = int(settings.submit_workers)
    _write_config(settings.config_path, config)
    settings.config = config


def settings_from_args(args: argparse.Namespace) -> Settings:
    config_path = _absolute_path(args.config or str(DEFAULT_CONFIG_PATH))
    config = _read_config(config_path)
    settings = Settings(
        config_path=config_path,
        count=1,
        workers=1,
        output_dir=DEFAULT_OUTPUT_DIR.resolve(),
        config=config,
    )
    _load_runtime_fields(settings)

    if getattr(args, "count", None) is not None:
        settings.count = _positive_int(args.count, "注册数量", MAX_COUNT)
    if getattr(args, "workers", None) is not None:
        settings.workers = _positive_int(args.workers, "并发数", MAX_WORKERS)
    # argparse 默认值可能已给出 mode/output-dir；仅在显式传入时覆盖。
    explicit = set(getattr(args, "_explicit_cli", set()) or set())
    if "mode" in explicit and getattr(args, "mode", None):
        settings.run_mode = _normalize_run_mode(args.mode)
    elif getattr(args, "mode", None):
        settings.run_mode = _normalize_run_mode(args.mode)
    if "output_dir" in explicit and getattr(args, "output_dir", None):
        settings.output_dir = _absolute_path(args.output_dir, settings.config_path.parent)
    elif getattr(args, "output_dir", None):
        settings.output_dir = _absolute_path(args.output_dir, settings.config_path.parent)
    if bool(getattr(args, "no_proxy", False)):
        settings.no_proxy = True
        settings.proxy_mode = "none"
    return settings


def refresh_settings_config(settings: Settings, *, reset_defaults: bool = True) -> None:
    settings.config = _read_config(settings.config_path)
    if reset_defaults:
        _load_runtime_fields(settings)


def _resolve_proxy_args(settings: Settings) -> Tuple[str, List[str]]:
    mode = str(settings.proxy_mode or "").strip().lower()
    if settings.no_proxy or mode == "none":
        return "none", []

    config = settings.config
    direct_proxy = str(config.get("proxy") or "").strip()
    proxy_file_value = str(config.get("proxy_file") or "fixtures/proxies.txt").strip()
    proxy_file = _absolute_path(proxy_file_value, settings.config_path.parent) if proxy_file_value else None
    if mode == "auto":
        mode = "direct" if direct_proxy else "pool" if proxy_file and proxy_file.is_file() else "none"

    args: List[str] = []
    if mode == "direct":
        if not direct_proxy:
            raise TuiConfigError("代理模式为直连，但 config.proxy 为空")
        args.extend(["--proxy", direct_proxy])
    elif mode == "pool":
        if not proxy_file or not proxy_file.is_file():
            raise TuiConfigError("代理模式为代理池，但 config.proxy_file 不可用")
        args.extend(["--proxy-file", str(proxy_file)])
        if _as_bool(config.get("proxy_random")):
            args.append("--proxy-random")
    elif mode != "none":
        raise TuiConfigError(f"不支持的代理模式: {mode}")

    return mode, args


def _normalize_target_mode(value: object) -> str:
    raw = str(value or TARGET_MODE_COUNT).strip().lower()
    if raw in {TARGET_MODE_COUNT, "fixed", "total"}:
        return TARGET_MODE_COUNT
    if raw in {TARGET_MODE_CONTINUOUS, "infinite", "unlimited", "forever", "stream"}:
        return TARGET_MODE_CONTINUOUS
    return TARGET_MODE_COUNT


def build_plan(settings: Settings) -> RunPlan:
    config = settings.config
    target_mode = _normalize_target_mode(getattr(settings, "target_mode", None) or config.get("run_target_mode"))
    target_success = _bounded_int(
        getattr(settings, "target_success", None)
        if getattr(settings, "target_success", None) is not None
        else config.get("target_success"),
        "成功目标",
        minimum=0,
        maximum=MAX_COUNT,
        default=0,
    )
    continuous_max_runtime_min = _bounded_int(
        getattr(settings, "continuous_max_runtime_min", None)
        if getattr(settings, "continuous_max_runtime_min", None) is not None
        else config.get("continuous_max_runtime_min"),
        "持续运行最长分钟",
        minimum=0,
        maximum=10080,
        default=0,
    )
    count = _positive_int(settings.count, "注册数量", MAX_COUNT)
    workers = _positive_int(settings.workers, "并发数", MAX_WORKERS)
    if target_mode == TARGET_MODE_COUNT:
        workers = min(workers, count)
    else:
        # continuous: count is ignored as preallocation size
        count = 0
    provider = _normalize_turnstile_provider(
        settings.turnstile_provider or config.get("turnstile_provider") or "capsolver"
    )
    turnstile_headless = bool(settings.turnstile_headless)
    email_provider = str(config.get("email_provider") or "cloudflare").strip().lower() or "cloudflare"
    warnings: List[str] = []

    if provider == "capsolver":
        has_key = bool(
            str(config.get("turnstile_api_key") or "").strip()
            or os.environ.get("CAPSOLVER_API_KEY")
            or os.environ.get("XAI_TURNSTILE_API_KEY")
        )
        if not has_key:
            raise TuiConfigError(
                "缺少 CapSolver API 密钥。请设置 config.turnstile_api_key 或 CAPSOLVER_API_KEY。"
            )
    elif provider in {"2captcha", "yescaptcha"}:
        env_names = {
            "2captcha": ("TWOCAPTCHA_API_KEY", "TWO_CAPTCHA_API_KEY", "XAI_TURNSTILE_API_KEY"),
            "yescaptcha": ("YESCAPTCHA_API_KEY", "XAI_TURNSTILE_API_KEY"),
        }[provider]
        has_key = bool(
            str(config.get("turnstile_api_key") or "").strip()
            or any(os.environ.get(name) for name in env_names)
        )
        if not has_key:
            raise TuiConfigError(
                f"缺少 {TURNSTILE_PROVIDER_LABELS[provider]} API 密钥。请设置 config.turnstile_api_key 或对应环境变量。"
            )
    elif provider == "local":
        local_cap = resolve_local_turnstile_max_workers(config, strict=False)
        warnings.append(
            "主流程仍是 HTTP 协议；仅在 Turnstile 求解阶段临时打开本地浏览器"
            + ("（无头）" if turnstile_headless else "（有界面）")
            + "，拿完 token 立即关闭。"
        )
        warnings.append(
            "本地 Turnstile 使用「每任务独立求解」（不走共享 broker），"
            "与已验证成功的无头 batch 路径一致。"
        )
        if turnstile_headless:
            warnings.append(
                "本地浏览器无头使用原生 Chrome --headless=new（不会启动可见窗口或有头回退）；"
                f"建议账号并发 ≤ {local_cap}"
                "（配置 concurrent_workers / local_turnstile_max_workers）。"
            )
        if workers > local_cap:
            warnings.append(
                f"账号并发 {workers} 高于本地 Turnstile 建议上限 {local_cap}；"
                "高并发可能抢占浏览器/代理资源导致超时。"
            )

    is_graph = email_provider in {"msgraph", "microsoft", "hotmail", "outlook"}
    has_mail_file = bool(str(config.get("ms_mail_file") or "").strip())
    if workers > 1 and (is_graph or has_mail_file):
        # Claim is cross-process flock-safe; parallel workers each get a distinct line.
        warnings.append(
            "Outlook/Graph 邮箱池已支持多并发领取（文件锁）；"
            "请保证池内可用账号数 ≥ 并发，否则后启动的任务会因池空失败。"
        )
    if workers > 1 and (
        os.environ.get("XAI_CASTLE_EMAIL_TOKEN") or os.environ.get("XAI_CASTLE_REGISTER_TOKEN")
    ):
        workers = 1
        warnings.append("绑定会话的 Castle token 会强制单并发执行。")
    if str(email_provider or "").strip().lower() == "yyds" and workers > 1:
        yyds_spacing = resolve_yyds_create_spacing_sec(config, strict=False)
        warnings.append(
            "YYDS 建邮有全局限流（跨进程文件锁 + "
            f"{yyds_spacing:g}s 间隔，配置 yyds_create_spacing_sec）；"
            "并发越高排队越久，429 会自动退避重试。"
        )

    proxy_mode, proxy_args = _resolve_proxy_args(settings)
    local_cap = resolve_local_turnstile_max_workers(config, strict=False)
    requested_turnstile_workers = int(
        settings.turnstile_workers
        or config.get("turnstile_workers")
        or (local_cap if provider == "local" else workers)
    )
    turnstile_workers = max(1, min(MAX_WORKERS, requested_turnstile_workers))
    if provider == "local":
        turnstile_workers = min(turnstile_workers, local_cap)
    turnstile_queue_size = max(
        1,
        int(
            config.get("turnstile_queue_size")
            or settings.turnstile_queue_size
            or DEFAULT_TURNSTILE_QUEUE_SIZE
        ),
    )
    submit_workers = max(
        1,
        min(
            MAX_SUBMIT_WORKERS,
            int(
                config.get("submit_workers")
                or settings.submit_workers
                or DEFAULT_SUBMIT_WORKERS
            ),
        ),
    )
    turnstile_broker_url = str(
        settings.turnstile_broker_url or config.get("turnstile_broker_url") or ""
    ).strip()
    # Local native-headless capture is process-local and stable only when
    # each register worker solves independently. The shared HTTP broker path has
    # repeatedly timed out under concurrency (browser_starts=0 / Read timed out),
    # so default local runs force direct capture unless an external broker URL is
    # explicitly configured.
    if provider == "local" and not turnstile_broker_url:
        # keep empty url; manage_turnstile_broker will be disabled below
        pass
    run_mode = _normalize_run_mode(settings.run_mode)
    sso_convert_retries = _bounded_int(
        settings.sso_convert_retries,
        "SSO转换重试次数",
        minimum=1,
        maximum=MAX_SSO_CONVERT_RETRIES,
        default=DEFAULT_SSO_CONVERT_RETRIES,
    )
    sso_convert_cooldown = _bounded_int(
        settings.sso_convert_cooldown,
        "SSO转换冷却秒数",
        minimum=0,
        maximum=MAX_SSO_CONVERT_COOLDOWN,
        default=DEFAULT_SSO_CONVERT_COOLDOWN,
    )
    if run_mode == RUN_MODE_REGISTER_SSO:
        _ensure_mode2_ready()
        warnings.append(
            "模式2：注册成功后用 sso_to_auth_json 转换；"
            f"失败最多重试 {sso_convert_retries} 次，冷却 {sso_convert_cooldown}s。"
        )
    embedded_proxy_enabled = _as_bool(config.get("embedded_proxy_enabled"))
    embedded_proxy_max_node_retries = _bounded_int(
        config.get("embedded_proxy_max_node_retries"),
        "内嵌代理节点重试次数",
        minimum=1,
        maximum=20,
        default=3,
    )
    proxy_slot_sticky = _as_bool(config.get("proxy_slot_sticky"))
    if target_mode == TARGET_MODE_CONTINUOUS:
        if target_success > 0:
            warnings.append(
                f"持续运行：成功达到 {target_success} 后自动停止补货；也可手动停止。"
            )
        else:
            warnings.append("持续运行：按并发水位线补货，直到手动停止。")
        if continuous_max_runtime_min > 0:
            warnings.append(f"持续运行最长 {continuous_max_runtime_min} 分钟。")
    return RunPlan(
        config_path=settings.config_path,
        run_mode=run_mode,
        count=count,
        workers=workers,
        output_dir=settings.output_dir,
        provider=provider,
        email_provider=email_provider,
        proxy_mode=proxy_mode,
        proxy_args=proxy_args,
        turnstile_headless=turnstile_headless,
        turnstile_workers=turnstile_workers,
        turnstile_queue_size=turnstile_queue_size,
        submit_workers=submit_workers,
        turnstile_broker_url=turnstile_broker_url,
        # Local provider: never auto-start shared broker. Only use broker when the
        # user/config explicitly provided turnstile_broker_url.
        manage_turnstile_broker=(
            False if provider == "local" else (not bool(turnstile_broker_url))
        ),
        sso_convert_retries=sso_convert_retries,
        sso_convert_cooldown=sso_convert_cooldown,
        warnings=warnings,
        embedded_proxy_enabled=embedded_proxy_enabled,
        embedded_proxy_max_node_retries=embedded_proxy_max_node_retries,
        proxy_slot_sticky=proxy_slot_sticky,
        target_mode=target_mode,
        target_success=target_success,
        continuous_max_runtime_min=continuous_max_runtime_min,
    )


def describe_plan(plan: RunPlan, *, dry_run: bool = False) -> str:
    lines = [
        "HTTP 协议 TUI",
        f"运行模式: {_run_mode_label(plan.run_mode)}",
        f"配置文件: {plan.config_path}",
        f"邮箱: {plan.email_provider}",
        f"Turnstile: {_turnstile_provider_label(plan.provider, headless=plan.turnstile_headless)}",
        (f"目标模式: 持续运行 | 成功目标: {plan.target_success if plan.target_success else '不限'}" if getattr(plan, "target_mode", TARGET_MODE_COUNT) == TARGET_MODE_CONTINUOUS else f"注册数量: {plan.count}"),
        f"并发数: {plan.workers}",
        f"Turnstile并发: {plan.turnstile_workers} / 队列: {plan.turnstile_queue_size}",
        f"提交并发: {plan.submit_workers}",
        f"代理: {_egress_mode_label(encode_egress_mode(plan.proxy_mode, plan.embedded_proxy_enabled))} ({_proxy_mode_label(plan.proxy_mode)}{' +节点池' if plan.embedded_proxy_enabled else ''})",
        f"OAuth 输出: {plan.output_dir}",
    ]
    if plan.run_mode == RUN_MODE_REGISTER_SSO:
        lines.append(
            f"SSO转换重试: {plan.sso_convert_retries} 次 / 冷却 {plan.sso_convert_cooldown}s"
        )
    lines.extend(f"警告: {warning}" for warning in plan.warnings)
    if dry_run:
        if plan.run_mode == RUN_MODE_REGISTER_SSO:
            lines.append(
                f"[dry-run] 将启动 {plan.count} 个注册任务；成功后用 sso_to_auth_json 转换凭证，最大并发 {plan.workers}。"
            )
        else:
            lines.append(
                f"[dry-run] 将启动 {plan.count} 个 HTTP 协议任务，最大并发 {plan.workers}。"
            )
    return "\n".join(lines)



FAILURE_CATEGORIES = (
    "yyds_rate_limit",
    "email_domain_rejected",
    "turnstile_hard_block",
    "turnstile_timeout",
    "tls_error",
    "proxy_error",
    "browser_launch_failed",
    "sso_convert_failed",
    "register_failed",
    "unknown",
)


def classify_failure_text(text: str) -> str:
    """Map worker log / last_log text into a coarse failure bucket."""
    raw = str(text or "")
    t = raw.lower()
    if ("yyds" in t or "too many account creation" in t) and ("429" in t or "too many" in t):
        return "yyds_rate_limit"
    if (
        "email domain has been rejected" in t
        or "email-domain-rejected" in t
        or "account:email-domain-rejected" in t
    ):
        return "email_domain_rejected"
    if "cloudflare_hard_block" in t or "hard_block" in t or "硬拦截" in raw:
        return "turnstile_hard_block"
    if (
        "curl: (35)" in t
        or "tls connect error" in t
        or "openssl_internal" in t
        or "invalid library" in t
    ):
        return "tls_error"
    if (
        "curl: (56)" in t
        or "curl: (7)" in t
        or "proxyerror" in t
        or "407" in t
        or "connect tunnel failed" in t
        or "没有可用的内嵌代理节点" in raw
        or "内嵌代理" in raw and "未就绪" in raw
    ):
        return "proxy_error"
    if "turnstile" in t and ("timeout" in t or "超时" in raw or "未捕获到可用" in raw):
        return "turnstile_timeout"
    if (
        "无法启动浏览器" in raw
        or "browser" in t and "launch" in t
        or "maximum number of clients" in t
        or ("x11" in t and "client" in t)
    ):
        return "browser_launch_failed"
    if "sso" in t and ("转换失败" in raw or "convert" in t or "退出码" in raw or "无法做 sso" in t):
        return "sso_convert_failed"
    if ("注册" in raw and "失败" in raw) or "register" in t and "fail" in t:
        return "register_failed"
    return "unknown"


class BatchRunner:
    """调度 HTTP 协议子进程，并把每一行输出流式送到 TUI。"""

    def __init__(self, plan: RunPlan):
        self.plan = plan
        self.run_id = f"{time.strftime('%Y%m%d_%H%M%S')}_{os.getpid()}"
        self.run_dir = RUNS_DIR / self.run_id
        # On-demand workers: do not preallocate plan.count objects.
        self.workers: List[WorkerState] = []
        self.worker_by_index: Dict[int, WorkerState] = {}
        self.events: queue.Queue[Tuple[int, str]] = queue.Queue()
        self.logs: Deque[str] = deque(maxlen=MAX_LOG_LINES)
        self.started = False
        self.done = False
        self.stopping = False
        self.phase: str = "idle"  # idle|running|draining|done
        self.next_index = 1
        self.started_tasks = 0
        self.succeeded_count = 0
        self.failed_count = 0
        self.stopped_count = 0
        self.summary_path: Optional[Path] = None
        self.account_count = 0
        self.failure_counts: Dict[str, int] = {key: 0 for key in FAILURE_CATEGORIES}
        self._failure_recorded: set[int] = set()
        self.started_at_wall: Optional[str] = None
        self.started_at_monotonic: Optional[float] = None
        self.finished_at_monotonic: Optional[float] = None
        self.broker_process: Optional[subprocess.Popen[str]] = None
        self.owns_broker = False
        self.embedded_proxy_manager = None
        self.recent_workers: Deque[WorkerState] = deque(maxlen=RECENT_WORKER_WINDOW)
        self.refill_paused = False
        self.refill_pause_until: float = 0.0
        self.refill_pause_reason: str = ""
        self._last_refill_pause_log_at: float = 0.0
        # outcome window for circuit breaker: True=success, False=failed (ignore stopped)
        self._outcome_window: Deque[bool] = deque(maxlen=CIRCUIT_WINDOW_SIZE)
        self.circuit_open = False
        self._last_progress_at: float = 0.0
        self._last_stall_recover_at: float = 0.0
        self._last_proxy_health_check_at: float = 0.0
        self._proxy_unhealthy = False
        self._last_browser_residue_cleanup_at: float = 0.0
        self._hybrid_proxy_seq: int = 0
        self._manual_proxy_rotator = None
        self._proxy_pool_snapshot_path: Optional[Path] = None
        self._static_proxy_health: Dict[int, Dict[str, object]] = {}
        self._static_proxy_entries: Tuple[str, ...] = tuple()
        # A stopped static-route attempt is replaced by a fresh WorkerState.
        # Carry its proxy-attempt budget across that replacement so a fixed
        # count run cannot refill forever on permanently failing routes.
        self._static_proxy_retry_queue: Deque[int] = deque()

    @staticmethod
    def _free_loopback_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def _shared_broker_command(self, port: int) -> List[str]:
        return [
            sys.executable,
            "-m",
            "turnstile_solver.src",
            "serve",
            "--config",
            str(self.plan.config_path),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--max-concurrency",
            str(self.plan.turnstile_workers),
            "--external-provider-workers",
            str(self.plan.turnstile_workers),
            "--external-queue-limit",
            str(self.plan.turnstile_queue_size),
            "--submit-workers",
            str(self.plan.submit_workers),
        ]

    def _start_shared_broker(self) -> None:
        if self.plan.turnstile_broker_url or not self.plan.manage_turnstile_broker:
            if self.plan.provider == "local" and not self.plan.turnstile_broker_url:
                self._log(
                    "SYSTEM",
                    "本地 Turnstile：跳过共享 broker，改为每个注册任务独立无头求解",
                )
            return
        port = self._free_loopback_port()
        url = f"http://127.0.0.1:{port}"
        command = self._shared_broker_command(port)
        log_path = self.run_dir / "broker.log"
        log_handle = log_path.open("ab")
        broker_env = os.environ.copy()
        # Ensure managed broker can find a real Chrome for strict fingerprint mode.
        browser_path = ""
        try:
            plan_config = _read_config(self.plan.config_path)
        except Exception:
            plan_config = {}
        if isinstance(plan_config, dict):
            browser_path = str(plan_config.get("browser_path") or "").strip()
        if not browser_path:
            browser_path = str(broker_env.get("TURNSTILE_BROWSER_PATH") or "").strip()
        if not browser_path:
            try:
                from turnstile_solver.src.config import detect_system_chrome_path

                browser_path = str(detect_system_chrome_path() or "").strip()
            except Exception:
                browser_path = ""
        if browser_path:
            broker_env["TURNSTILE_BROWSER_PATH"] = browser_path
            self._log("SYSTEM", f"Turnstile broker 浏览器: {browser_path}")
        try:
            process = subprocess.Popen(
                command,
                cwd=str(ROOT_DIR),
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                text=False,
                env=broker_env,
            )
        finally:
            log_handle.close()
        deadline = time.monotonic() + 45.0
        last_error = ""
        # Always hit loopback directly; never inherit a process-global proxy opener.
        health_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        while time.monotonic() < deadline:
            return_code = process.poll()
            if return_code is not None:
                last_error = f"进程提前退出，退出码 {return_code}"
                break
            try:
                with health_opener.open(url + "/health", timeout=1.5) as response:
                    status = int(getattr(response, "status", 0) or response.getcode() or 0)
                    if 200 <= status < 300:
                        self.broker_process = process
                        self.owns_broker = True
                        self.plan.turnstile_broker_url = url
                        self._log("SYSTEM", f"共享 Turnstile broker 已就绪: {url}")
                        self._log("SYSTEM", f"broker 日志: {log_path}")
                        return
            except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
                last_error = str(exc)
            time.sleep(0.15)
        try:
            process.terminate()
            process.wait(timeout=3)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass
        raise TuiConfigError(
            f"共享 Turnstile broker 启动失败: {last_error or 'health timeout'}；"
            f"详见 {log_path}"
        )

    def _stop_shared_broker(self) -> None:
        process = self.broker_process
        keep_pid = None
        self.broker_process = None
        if not self.owns_broker or process is None:
            # Still try a conservative residue cleanup for local mode leftovers.
            if self.plan.provider == "local":
                cleanup = cleanup_browser_residues(
                    kill_playwright=True,
                    kill_all_chrome=False,
                    kill_orphan_solvers=True,
                )
                self._log("SYSTEM", f"结束后清理浏览器残留: {format_cleanup_result(cleanup)}")
            return
        self.owns_broker = False
        try:
            keep_pid = int(getattr(process, "pid", 0) or 0)
        except Exception:
            keep_pid = 0
        try:
            process.terminate()
            process.wait(timeout=5)
        except Exception:
            try:
                process.kill()
                process.wait(timeout=2)
            except Exception:
                pass
        # Reap any remaining children of this process group leftovers.
        try:
            _reap_zombie_children()
        except Exception:
            pass
        self._log("SYSTEM", "共享 Turnstile broker 已关闭")
        if self.plan.provider == "local":
            keep = {keep_pid} if keep_pid else set()
            cleanup = cleanup_browser_residues(
                kill_playwright=True,
                kill_all_chrome=False,
                kill_orphan_solvers=True,
                keep_solver_pids=keep,
            )
            self._log("SYSTEM", f"结束后清理浏览器残留: {format_cleanup_result(cleanup)}")

    def _maybe_cleanup_browser_residues(self, *, force: bool = False) -> None:
        """Periodically clean orphan solvers / project chrome leftovers during local runs.

        Chrome zombies hang under dead turnstile_solver parents. Waiting only on
        this process cannot reap them; killing orphan solvers is required.
        """
        if self.plan.provider != "local":
            return
        now = time.monotonic()
        # Keep interval modest so zombies cannot pile up for a full batch.
        interval = 30.0
        if (
            not force
            and (now - float(self._last_browser_residue_cleanup_at or 0.0)) < interval
        ):
            return
        self._last_browser_residue_cleanup_at = now
        keep: set[int] = set()
        try:
            pid = int(getattr(self.broker_process, "pid", 0) or 0)
            if pid > 1:
                keep.add(pid)
        except Exception:
            pass
        # External/shared broker: never kill turnstile_solver parents we do not own.
        kill_orphan_solvers = bool(self.owns_broker) or not bool(self.plan.turnstile_broker_url)
        try:
            # Reap our own dead children first (worker subprocesses / broker).
            _reap_zombie_children()
        except Exception:
            pass
        try:
            health = browser_health_status()
        except Exception:
            health = {}
        zombies = int(health.get("zombie_chrome_count") or 0)
        solvers = int(health.get("solver_count") or 0)
        # Trigger when pressure is visible, or every forced pass.
        expected_solvers = max(1, len(keep)) if kill_orphan_solvers else max(1, solvers)
        if not force and zombies < 5 and (not kill_orphan_solvers or solvers <= expected_solvers):
            # Still scrub project chrome temp profiles occasionally when zombies are low.
            if not force and zombies < 1:
                return
        try:
            cleanup = cleanup_browser_residues(
                kill_playwright=True,
                kill_all_chrome=False,
                kill_orphan_solvers=kill_orphan_solvers,
                keep_solver_pids=keep,
            )
        except Exception as exc:
            self._log("SYSTEM", f"运行中清理浏览器残留失败: {exc}")
            return
        killed = (
            int(cleanup.get("killed_solvers") or 0)
            + int(cleanup.get("killed_chrome") or 0)
            + int(cleanup.get("killed_playwright") or 0)
            + int(cleanup.get("reaped_zombies") or 0)
        )
        if killed > 0 or int(cleanup.get("zombie_chrome_count") or 0) > 0 or force:
            self._log("SYSTEM", f"运行中清理浏览器残留: {format_cleanup_result(cleanup)}")

    @property
    def active(self) -> List[WorkerState]:
        # 注册中 + 后台 SSO 转换中都占并发槽，保证每个 worker 一对一跟随转换。
        return [worker for worker in self.workers if worker.status in {"running", "converting"}]

    @property
    def completed(self) -> int:
        return int(self.succeeded_count + self.failed_count)

    @property
    def succeeded(self) -> int:
        return int(self.succeeded_count)

    @property
    def failed(self) -> int:
        return int(self.failed_count)

    @property
    def stopped(self) -> int:
        return int(self.stopped_count)

    @property
    def is_continuous(self) -> bool:
        return str(getattr(self.plan, "target_mode", TARGET_MODE_COUNT)) == TARGET_MODE_CONTINUOUS

    def _mark_terminal(self, worker: WorkerState, status: str) -> None:
        """Apply terminal status once and keep counters consistent."""
        if worker.status in {"succeeded", "failed", "stopped"}:
            # already terminal
            if worker.status != status:
                worker.status = status
            return
        worker.status = status
        if status == "succeeded":
            self.succeeded_count += 1
            self._outcome_window.append(True)
            self._maybe_trip_circuit()
        elif status == "failed":
            self.failed_count += 1
            self._outcome_window.append(False)
            self._maybe_trip_circuit()
        elif status == "stopped":
            self.stopped_count += 1
        # Any terminal transition counts as progress for stall detection.
        self._last_progress_at = time.monotonic()
        # Keep a compact recent window for UI; full history stays on disk logs.
        self.recent_workers.append(worker)

    def _should_refill(self) -> bool:
        if self.done or self.stopping or self.phase == "draining":
            return False
        if self.is_continuous:
            target = int(getattr(self.plan, "target_success", 0) or 0)
            if target > 0 and self.succeeded_count >= target:
                return False
            max_min = int(getattr(self.plan, "continuous_max_runtime_min", 0) or 0)
            if max_min > 0 and self.started_at_monotonic is not None:
                if (time.monotonic() - self.started_at_monotonic) >= max_min * 60:
                    return False
            return True
        # fixed count mode
        return self.started_tasks < int(self.plan.count or 0)

    def _prune_finished_workers(self) -> None:
        """Drop terminal workers from hot lists; keep recent window + active only."""
        keep_idx = {w.index for w in self.recent_workers}
        for w in self.active:
            keep_idx.add(w.index)
        # Always retain non-terminal.
        new_workers = []
        for w in self.workers:
            if w.status in {"running", "converting", "queued"} or w.index in keep_idx:
                new_workers.append(w)
            else:
                self.worker_by_index.pop(w.index, None)
        self.workers = new_workers

    def _log(self, source: str, message: str) -> None:
        message = _safe_text(
            _redact_sensitive_runtime_text(self._redact_proxy_text(message))
        )
        if message:
            self.logs.append(f"[{source}] {message}")

    def _redact_proxy_text(self, value: object) -> str:
        """Return secret-free text for UI state and persisted worker logs."""
        proxies: Sequence[str] = self._static_proxy_entries
        rotator = getattr(self, "_manual_proxy_rotator", None)
        if rotator is not None:
            try:
                proxies = tuple(rotator.proxies())
            except Exception:
                pass
        try:
            from proxy_pool import redact_proxy_text

            return redact_proxy_text(value, proxies)
        except Exception:
            return str(value or "")

    def _uses_static_proxy_leases(self) -> bool:
        return bool(
            getattr(self.plan, "proxy_slot_sticky", False)
            and self._http_proxy_pool_active()
        )

    def _manual_proxy_source_path(self) -> Optional[Path]:
        args = list(self.plan.proxy_args or [])
        for index, token in enumerate(args):
            if token == "--proxy-file" and index + 1 < len(args):
                return Path(args[index + 1]).expanduser().resolve()
        try:
            cfg = _read_config(self.plan.config_path)
        except Exception:
            cfg = {}
        raw = str((cfg or {}).get("proxy_file") or "").strip()
        if not raw:
            return None
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = self.plan.config_path.parent / path
        return path.resolve()

    def _prepare_static_proxy_snapshot(self) -> None:
        """Freeze the HTTP pool once for this batch and build its lease owner."""
        if not self._uses_static_proxy_leases():
            return
        try:
            from proxy_pool import ProxyRotator, load_proxy_lines, normalize_proxy_pool
        except Exception as exc:  # pragma: no cover - import failure is fatal
            raise TuiConfigError(f"加载静态代理租约组件失败: {exc}") from exc

        configured = tuple(getattr(self.plan, "proxy_pool_entries", ()) or ())
        if configured:
            entries = normalize_proxy_pool(configured)
            source_name = "plan"
        else:
            source = self._manual_proxy_source_path()
            entries = load_proxy_lines(str(source)) if source is not None else []
            source_name = source.name if source is not None else "proxy-file"
        if not entries:
            raise TuiConfigError("静态 HTTP 代理租约缺少有效的启动快照条目")

        self.run_dir.mkdir(parents=True, exist_ok=True)
        target = self.run_dir / "proxy_pool.snapshot.txt"
        temp = target.with_name(
            f".{target.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
        )
        fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write("\n".join(entries) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, target)
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass

        self._proxy_pool_snapshot_path = target
        self._static_proxy_entries = tuple(entries)
        self.plan.proxy_pool_entries = tuple(entries)
        self._manual_proxy_rotator = ProxyRotator(
            entries,
            stats_file=str(self.plan.config_path.parent / "state" / "proxy_stats.log"),
        )
        self._log(
            "SYSTEM",
            f"[Proxy] 本批次静态 HTTP 池已冻结 | source={source_name} valid={len(entries)}",
        )

    def _perform_static_proxy_health_request(
        self,
        proxy_url: str,
        target: str,
    ) -> Tuple[int, str]:
        """Probe one real registration dependency through a prepared route."""
        from curl_cffi import requests as curl_requests

        common = {
            "proxies": {"http": proxy_url, "https": proxy_url},
            "timeout": STATIC_PROXY_HEALTH_TIMEOUT_SEC,
            "impersonate": "chrome136",
            "allow_redirects": False,
        }
        if target == "signup":
            response = curl_requests.get(STATIC_PROXY_SIGNUP_URL, **common)
        elif target == "ms_token":
            response = curl_requests.post(
                STATIC_PROXY_MS_TOKEN_URL,
                data={
                    "client_id": "PROXY_HEALTH_CHECK",
                    "grant_type": "refresh_token",
                    "refresh_token": "PROXY_HEALTH_CHECK",
                },
                **common,
            )
        else:  # pragma: no cover - internal programming error
            raise ValueError(f"unknown proxy health target: {target}")
        return (
            int(getattr(response, "status_code", 0) or 0),
            str(getattr(response, "text", "") or "")[:4096],
        )

    @staticmethod
    def _static_proxy_transport_reason(exc: BaseException) -> str:
        text_value = f"{type(exc).__name__}: {exc}".lower()
        if any(
            marker in text_value
            for marker in (
                "curl: (35)",
                "tls connect",
                "ssl connect",
                "openssl",
                "unexpected eof",
                "certificate verify",
            )
        ):
            return "curl_tls_error"
        if any(
            marker in text_value
            for marker in (
                "curl: (5)",
                "curl: (6)",
                "curl: (7)",
                "curl: (28)",
                "curl: (56)",
                "proxy",
                "connect",
                "timeout",
                "timed out",
            )
        ):
            return "proxy_transport_error"
        return "target_transport_error"

    @staticmethod
    def _classify_static_proxy_target(
        target: str,
        status_code: int,
        body: str,
    ) -> Tuple[bool, str]:
        status = int(status_code or 0)
        lowered = str(body or "").lower()
        region_markers = (
            "unsupported region",
            "unsupported_region",
            "restricted region",
            "restricted_region",
            "not available in your region",
            "not available in your country",
            "unsupported country",
            "unsupported_country",
            "country_block",
            "cf_country",
            "geo_block",
        )
        if target == "signup":
            if status == 403 or (
                status == 451 and any(marker in lowered for marker in region_markers)
            ):
                return False, "signup_region_403"
            if 200 <= status < 400:
                return True, "ok"
            return False, f"signup_http_{status or 0}"
        if target == "ms_token":
            if 200 <= status < 500 and status not in {403, 407, 429}:
                return True, "ok"
            return False, f"ms_token_http_{status or 0}"
        return False, "unknown_target"

    def _probe_static_proxy_slot(
        self,
        slot_index: int,
        proxy_raw: str,
    ) -> Dict[str, object]:
        """Probe signup and Microsoft token routes for one frozen entry."""
        forwarder_key = (
            f"batch-proxy-health-{self.run_id}-{int(slot_index)}-"
            f"{secrets.token_hex(3)}"
        )
        target_results: Dict[str, Dict[str, object]] = {}
        try:
            from local_proxy_forwarder import ensure_local_forwarder

            proxy_url, _ = ensure_local_forwarder(
                proxy_raw,
                preferred_local_port=0,
                instance_key=forwarder_key,
            )
        except Exception as exc:
            try:
                from local_proxy_forwarder import stop_local_forwarder

                stop_local_forwarder(instance_key=forwarder_key)
            except Exception:
                pass
            return {
                "index": int(slot_index),
                "ok": False,
                "reason": self._static_proxy_transport_reason(exc),
                "targets": target_results,
            }

        try:
            for target in ("signup", "ms_token"):
                for attempt in range(1, STATIC_PROXY_HEALTH_ATTEMPTS + 1):
                    try:
                        status, body = self._perform_static_proxy_health_request(
                            proxy_url,
                            target,
                        )
                        ok, reason = self._classify_static_proxy_target(
                            target,
                            status,
                            body,
                        )
                        target_results[target] = {
                            "ok": ok,
                            "status_code": status,
                            "reason": reason,
                            "attempts": attempt,
                        }
                    except Exception as exc:
                        reason = self._static_proxy_transport_reason(exc)
                        target_results[target] = {
                            "ok": False,
                            "status_code": None,
                            "reason": reason,
                            "attempts": attempt,
                        }
                    item = target_results[target]
                    if item.get("ok"):
                        break
                    reason = str(item.get("reason") or "")
                    retryable = reason in {
                        "curl_tls_error",
                        "proxy_transport_error",
                        "target_transport_error",
                    } or reason.endswith("_429") or bool(
                        re.search(r"_http_5\d\d$", reason)
                    )
                    if not retryable or attempt >= STATIC_PROXY_HEALTH_ATTEMPTS:
                        break
                    time.sleep(
                        STATIC_PROXY_HEALTH_BACKOFF_SEC * attempt
                        + min(0.2, int(slot_index) * 0.04)
                    )
        finally:
            try:
                from local_proxy_forwarder import stop_local_forwarder

                stop_local_forwarder(instance_key=forwarder_key)
            except Exception:
                pass

        failures = [
            str(item.get("reason") or "target_probe_failed")
            for item in target_results.values()
            if not item.get("ok")
        ]
        return {
            "index": int(slot_index),
            "ok": not failures and len(target_results) == 2,
            "reason": ",".join(dict.fromkeys(failures)) if failures else "ok",
            "targets": target_results,
        }

    def _probe_static_proxy_slots(self) -> None:
        """Run the bounded two-target gate before any registration starts."""
        if not self._uses_static_proxy_leases():
            return
        entries = list(self._static_proxy_entries)
        if not entries:
            raise TuiConfigError("静态 HTTP 代理探测缺少完整的启动快照")

        results: Dict[int, Dict[str, object]] = {}
        with ThreadPoolExecutor(
            max_workers=max(1, min(len(entries), STATIC_PROXY_HEALTH_PROBE_WORKERS)),
            thread_name_prefix="static-proxy-health",
        ) as executor:
            futures = {
                executor.submit(self._probe_static_proxy_slot, index, proxy): index
                for index, proxy in enumerate(entries)
            }
            for future in as_completed(futures):
                index = int(futures[future])
                try:
                    results[index] = dict(future.result())
                except Exception as exc:  # one bad probe must not hide peers
                    results[index] = {
                        "index": index,
                        "ok": False,
                        "reason": self._static_proxy_transport_reason(exc),
                        "targets": {},
                    }

        self._static_proxy_health = results
        rotator = self._manual_proxy_rotator
        healthy = 0
        isolated: List[int] = []
        for index, proxy in enumerate(entries):
            item = results.get(index) or {
                "ok": False,
                "reason": "target_probe_missing",
            }
            ok = bool(item.get("ok"))
            reason = str(item.get("reason") or ("ok" if ok else "target_probe_failed"))
            if rotator is not None:
                rotator.record_result(proxy, ok, f"preflight:{reason}")
                if ok:
                    rotator.mark_good(proxy)
                else:
                    rotator.mark_bad(proxy)
            if ok:
                healthy += 1
            else:
                isolated.append(index)
                self._log(
                    "SYSTEM",
                    f"[Proxy] 静态 HTTP 槽位 #{index + 1} 启动隔离: {reason}",
                )
        suffix = ""
        if isolated:
            suffix = "；隔离 " + ", ".join(f"#{index + 1}" for index in isolated)
        self._log(
            "SYSTEM",
            f"[Proxy] 双目标启动探测完成: 健康 {healthy}/{len(entries)}{suffix}",
        )
        if healthy <= 0 and not self.plan.embedded_proxy_enabled:
            raise TuiConfigError("静态 HTTP 代理均未通过注册依赖探测")

    def start(self) -> None:
        if self.started:
            return
        self.plan.output_dir.mkdir(parents=True, exist_ok=True)
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        for directory in (RUNS_DIR, self.run_dir):
            try:
                os.chmod(directory, 0o700)
            except OSError:
                pass
        self._prepare_static_proxy_snapshot()
        self._probe_static_proxy_slots()
        if self.plan.provider == "local":
            cleanup = cleanup_browser_residues(kill_playwright=True, kill_all_chrome=False)
            self._last_browser_residue_cleanup_at = time.monotonic()
            self._log("SYSTEM", f"启动前清理浏览器残留: {format_cleanup_result(cleanup)}")
            self._log("SYSTEM", f"浏览器健康: {format_browser_health()}")
        self._start_shared_broker()
        self.started = True
        self.phase = "running"
        self.started_at_monotonic = time.monotonic()
        self.started_at_wall = time.strftime("%Y-%m-%dT%H:%M:%S")
        self._last_progress_at = self.started_at_monotonic
        self._last_stall_recover_at = 0.0
        if self.is_continuous:
            self._log(
                "SYSTEM",
                "持续运行已启动（水位线补货，不预创建超大任务表；邮箱/OTP/注册走协议；仅 local Turnstile 会临时开浏览器）",
            )
        else:
            self._log("SYSTEM", "HTTP 协议批量任务已启动（邮箱/OTP/注册走协议；仅 local Turnstile 会临时开浏览器）")
        for warning in self.plan.warnings:
            self._log("SYSTEM", warning)
        self._spawn_available()

    def _command_for(self, worker: WorkerState) -> List[str]:
        assert worker.accounts_path is not None
        command = [
            sys.executable,
            str(ROOT_DIR / "xai_http_flow.py"),
            "register",
            "--mail-config",
            str(self.plan.config_path),
            "--turnstile-provider",
            self.plan.provider,
            "--accounts-output",
            str(worker.accounts_path),
        ]
        if self.plan.provider == "local" and self.plan.turnstile_headless:
            command.append("--turnstile-headless")
        command.extend(["--turnstile-workers", str(self.plan.turnstile_workers)])
        command.extend(["--turnstile-queue-size", str(self.plan.turnstile_queue_size)])
        command.extend(["--submit-workers", str(self.plan.submit_workers)])
        # Turnstile per-try timeout + retries (defaults: 30s x 3)
        cfg = {}
        try:
            cfg = _read_config(self.plan.config_path)
        except Exception:
            cfg = {}
        solve_timeout = max(5, int(cfg.get("turnstile_solve_timeout") or 90))
        solve_retries = max(1, int(cfg.get("turnstile_solve_retries") or 1))
        command.extend(["--turnstile-solve-timeout", str(solve_timeout)])
        command.extend(["--turnstile-solve-retries", str(solve_retries)])
        if self.plan.turnstile_broker_url:
            command.extend(["--turnstile-broker-url", self.plan.turnstile_broker_url])
        # 模式1：仓库内 PKCE OAuth。
        # 模式2：显式传空 output-dir，关闭注册内置换票，改由 sso_to_auth_json 一对一转换。
        if self.plan.run_mode == RUN_MODE_REGISTER_OTP:
            command.extend(["--output-dir", str(self.plan.output_dir)])
        else:
            command.extend(["--output-dir", ""])
        if self.plan.embedded_proxy_enabled and worker.proxy_local_http:
            command.extend(["--proxy", worker.proxy_local_http])
        elif str(worker.manual_proxy or "").strip():
            # Batch-side pool assignment: one concrete proxy per worker.
            command.extend(["--proxy", str(worker.manual_proxy).strip()])
        else:
            command.extend(self.plan.proxy_args)
        # Independent Turnstile solve proxy (optional).
        try:
            ts_proxy = pick_turnstile_proxy(
                cfg if isinstance(cfg, dict) else {},
                base_dir=self.plan.config_path.parent,
            )
        except Exception:
            ts_proxy = ""
        worker.uses_independent_turnstile_proxy = bool(ts_proxy)
        if ts_proxy:
            command.extend(["--turnstile-proxy", ts_proxy])
        return command

    def _append_worker_log(self, worker: WorkerState, message: str) -> None:
        text_line = _safe_text(
            _redact_sensitive_runtime_text(self._redact_proxy_text(message))
        )
        if not text_line:
            return
        self.events.put((worker.index, text_line))
        if worker.log_path is not None:
            try:
                with worker.log_path.open("a", encoding="utf-8") as handle:
                    handle.write(text_line + "\n")
            except OSError:
                pass

    def _convert_sso_accounts(self, worker: WorkerState) -> Tuple[bool, str]:
        """注册成功后，用 sso_to_auth_json 把 sso 转成 xai-*.json。"""
        if not worker.accounts_path or not worker.accounts_path.is_file():
            return False, "注册成功但没有账号文件，无法做 SSO 转换"
        try:
            rows = [
                row
                for row in (
                    _parse_account_row(line)
                    for line in worker.accounts_path.read_text(encoding="utf-8").splitlines()
                )
                if row is not None
            ]
        except OSError as exc:
            return False, f"读取账号文件失败: {exc}"
        if not rows:
            return False, "注册成功但账号行为空，无法做 SSO 转换"

        converter = _sso_converter_path()
        retries = max(1, int(self.plan.sso_convert_retries or DEFAULT_SSO_CONVERT_RETRIES))
        cooldown = max(0, int(self.plan.sso_convert_cooldown or 0))
        ok_count = 0
        fail_messages: List[str] = []
        self.plan.output_dir.mkdir(parents=True, exist_ok=True)
        for email, _password, sso in rows:
            display_email = _redact_sensitive_runtime_text(email)
            if self.stopping:
                fail_messages.append(f"{display_email}: 批次停止，跳过")
                continue
            sso = str(sso or "").strip().lstrip("-")
            if not sso:
                fail_messages.append(f"{display_email}: SSO 为空，跳过转换")
                self._append_worker_log(worker, f"SSO 为空，跳过转换 | email={display_email}")
                continue
            last_error = "未知错误"
            success = False
            # Always keep a single-account SSO sidecar next to credentials.
            try:
                from sso_to_auth_json import sso_file_name, write_sso_file

                sso_path = self.plan.output_dir / sso_file_name(email)
                write_sso_file(sso_path, sso)
                self._append_worker_log(
                    worker,
                    f"SSO 已单独保存 | email={display_email}",
                )
            except Exception as exc:
                self._append_worker_log(worker, f"SSO 单文件保存失败: {exc}")

            for attempt in range(1, retries + 1):
                if self.stopping:
                    last_error = "批次停止，跳过"
                    break
                command = [
                    sys.executable,
                    str(converter),
                    "--mode",
                    "auth",
                    "--sso-cookie",
                    sso,
                    "--out-dir",
                    str(self.plan.output_dir),
                    "--workers",
                    "1",
                ]
                if email:
                    command.extend(["--email", email])
                self._append_worker_log(
                    worker,
                    f"开始 SSO→凭证转换 | email={display_email} | 尝试 {attempt}/{retries}",
                )
                output_lines: List[str] = []
                try:
                    process = subprocess.Popen(
                        command,
                        cwd=str(ROOT_DIR),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        bufsize=1,
                    )
                except OSError as exc:
                    last_error = f"无法启动转换器 {exc}"
                    self._append_worker_log(worker, last_error)
                else:
                    assert process.stdout is not None
                    try:
                        for line in iter(process.stdout.readline, ""):
                            output_lines.append(line)
                    finally:
                        try:
                            process.stdout.close()
                        except OSError:
                            pass
                    return_code = process.wait()
                    if return_code == 0:
                        success = True
                        break
                    joined = " ".join(_safe_text(x, 200) for x in output_lines[-8:])
                    last_error = f"转换退出码 {return_code}"
                    if "429" in joined or "slow_down" in joined.lower():
                        last_error += " (限流/slow_down)"
                    self._append_worker_log(
                        worker,
                        f"SSO 转换失败 | email={display_email} | 尝试 {attempt}/{retries} | {last_error}",
                    )
                if attempt < retries and not self.stopping:
                    wait_s = cooldown
                    # 限流时至少冷却配置秒数，避免连打 device/code
                    self._append_worker_log(
                        worker,
                        f"SSO 转换冷却 {wait_s}s 后重试 | email={display_email} | 下一轮 {attempt + 1}/{retries}",
                    )
                    # 分段 sleep，便于 stop 时尽快退出
                    deadline = time.monotonic() + wait_s
                    while time.monotonic() < deadline:
                        if self.stopping:
                            break
                        time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
            if success:
                ok_count += 1
            else:
                fail_messages.append(f"{display_email}: {last_error}")

        if ok_count == len(rows):
            return True, f"SSO 转换完成 {ok_count}/{len(rows)}"
        if ok_count == 0:
            return False, "SSO 转换全部失败: " + "; ".join(fail_messages[:3])
        return False, f"SSO 转换部分失败 {ok_count}/{len(rows)}: " + "; ".join(fail_messages[:3])

    def _start_sso_convert(self, worker: WorkerState) -> None:
        """每个 worker 注册成功后立即后台转换，互不阻塞主循环。"""
        worker.status = "converting"
        worker.last_log = "注册完成，后台 SSO 转换中"
        self._log(f"W{worker.index:02d}", worker.last_log)

        def runner() -> None:
            try:
                if self.stopping:
                    ok, msg = False, "批次停止，跳过 SSO 转换"
                else:
                    ok, msg = self._convert_sso_accounts(worker)
            except Exception as exc:  # pragma: no cover - defensive
                ok, msg = False, f"SSO 转换异常: {exc}"
            self.events.put((worker.index, f"__CONVERT_DONE__|{1 if ok else 0}|{msg}"))

        worker.convert_thread = threading.Thread(
            target=runner,
            name=f"sso-convert-{worker.index}",
            daemon=True,
        )
        worker.convert_thread.start()

    def _pause_refill(
        self,
        reason: str,
        *,
        seconds: float | None = None,
        hold: bool = False,
        kind: str = "resource",
    ) -> None:
        """Temporarily stop creating new tasks.

        hold=True means "pause until condition clears" (proxy dead / circuit).
        Timed pauses still auto-clear after seconds.
        """
        wait = DEFAULT_REFILL_PAUSE_SEC if seconds is None else max(0.2, float(seconds))
        now = time.monotonic()
        if hold:
            # far-future sentinel; health/circuit logic clears it explicitly
            until = now + max(wait, 24 * 3600)
        else:
            until = now + wait
        # Keep the longer pause if already paused.
        if self.refill_paused and self.refill_pause_until > until:
            until = self.refill_pause_until
        prev_reason = self.refill_pause_reason
        self.refill_paused = True
        self.refill_pause_until = until
        self.refill_pause_reason = str(reason or "补货暂停")
        if kind == "circuit":
            self.circuit_open = True
        if kind == "proxy":
            self._proxy_unhealthy = True
        should_log = (
            prev_reason != self.refill_pause_reason
            or (now - float(self._last_refill_pause_log_at or 0.0)) >= REFILL_PAUSE_LOG_INTERVAL_SEC
        )
        if should_log:
            self._last_refill_pause_log_at = now
            if hold:
                self._log(
                    "SYSTEM",
                    f"补货暂停（等待恢复）：{self.refill_pause_reason}",
                )
            else:
                self._log(
                    "SYSTEM",
                    f"补货暂停 {wait:.1f}s：{self.refill_pause_reason}（不计入失败）",
                )

    def _clear_refill_pause(self, *, resume_log: bool = False, clear_circuit: bool = False) -> None:
        was_paused = bool(self.refill_paused)
        reason = self.refill_pause_reason
        self.refill_paused = False
        self.refill_pause_until = 0.0
        self.refill_pause_reason = ""
        if clear_circuit:
            self.circuit_open = False
        if was_paused and resume_log:
            self._log("SYSTEM", f"补货恢复：{reason or '资源已恢复'}")

    def _recent_fail_rate(self) -> tuple[int, int, float]:
        outcomes = list(self._outcome_window)
        total = len(outcomes)
        if total <= 0:
            return 0, 0, 0.0
        fails = sum(1 for ok in outcomes if not ok)
        return fails, total, float(fails) / float(total)

    def _maybe_trip_circuit(self) -> None:
        fails, total, rate = self._recent_fail_rate()
        if total < CIRCUIT_WINDOW_SIZE:
            return
        if rate < CIRCUIT_FAIL_RATE:
            # healthy enough; allow circuit to close on next timed resume
            if self.circuit_open and rate <= 0.5:
                self.circuit_open = False
            return
        self._pause_refill(
            f"近窗失败熔断：最近 {total} 单失败率 {rate:.0%}（失败 {fails}）",
            seconds=CIRCUIT_PAUSE_SEC,
            hold=False,
            kind="circuit",
        )

    def _proxy_health_snapshot(self) -> dict:
        manager = self.embedded_proxy_manager
        if manager is None:
            return {"enabled": True, "ready": False, "running": False, "healthy": 0, "total": 0}
        try:
            st = dict(manager.status() or {})
        except Exception as exc:  # pragma: no cover - defensive
            return {
                "enabled": True,
                "ready": False,
                "running": False,
                "healthy": 0,
                "total": 0,
                "error": str(exc),
            }
        healthy = int(st.get("healthy") or 0)
        total = int(st.get("total") or 0)
        running = bool(st.get("running"))
        ready = running and healthy > 0
        return {
            "enabled": True,
            "ready": ready,
            "running": running,
            "healthy": healthy,
            "total": total,
            "error": st.get("error") or "",
        }

    def _evaluate_proxy_health(self, *, force: bool = False) -> None:
        """Pause when embedded proxy is dead; auto-resume when healthy nodes return."""
        if not self.plan.embedded_proxy_enabled:
            self._proxy_unhealthy = False
            return
        if self.done or self.stopping or self.phase == "draining":
            return
        now = time.monotonic()
        if (
            not force
            and (now - float(self._last_proxy_health_check_at or 0.0)) < PROXY_HEALTH_CHECK_INTERVAL_SEC
        ):
            return
        self._last_proxy_health_check_at = now
        manager = self.embedded_proxy_manager
        if manager is not None and hasattr(manager, "revive_cooled_nodes"):
            try:
                revived = int(manager.revive_cooled_nodes() or 0)
                if revived > 0:
                    self._log("SYSTEM", f"内嵌代理冷却结束，恢复 {revived} 个节点可调度")
            except Exception:
                pass
        snap = self._proxy_health_snapshot()
        http_fallback = False
        if self._http_proxy_pool_active():
            try:
                rotator = self._ensure_manual_proxy_rotator()
                http_fallback = bool(rotator is not None and len(rotator) > 0)
            except Exception:
                http_fallback = False
        if not snap.get("ready"):
            if http_fallback:
                # Hybrid mode: keep registering via HTTP pool while mihomo recovers.
                if self._proxy_unhealthy or (
                    self.refill_paused and ("内嵌代理" in (self.refill_pause_reason or ""))
                ):
                    self._proxy_unhealthy = False
                    if self.refill_paused and not self.circuit_open:
                        self._clear_refill_pause(resume_log=True, clear_circuit=False)
                return
            if snap.get("error"):
                reason = f"内嵌代理不可用：{snap.get('error')}"
            elif not snap.get("running"):
                reason = "内嵌代理进程未运行"
            elif int(snap.get("total") or 0) <= 0:
                reason = "内嵌代理无节点"
            else:
                reason = (
                    f"内嵌代理无可用节点（healthy={snap.get('healthy')}/"
                    f"{snap.get('total')}）"
                )
            self._proxy_unhealthy = True
            self._pause_refill(reason, seconds=PROXY_DEAD_PAUSE_SEC, hold=True, kind="proxy")
            return
        # healthy again
        if self._proxy_unhealthy or (
            self.refill_paused and ("内嵌代理" in (self.refill_pause_reason or ""))
        ):
            self._proxy_unhealthy = False
            # only auto-resume if pause was proxy-related (not circuit hold still needed)
            if self.circuit_open:
                # keep paused for circuit timer; just clear proxy flag
                if "内嵌代理" in (self.refill_pause_reason or ""):
                    # replace reason to circuit if still open
                    fails, total, rate = self._recent_fail_rate()
                    self.refill_pause_reason = (
                        f"近窗失败熔断：最近 {total} 单失败率 {rate:.0%}（失败 {fails}）"
                    )
                return
            if self.refill_paused:
                self._clear_refill_pause(resume_log=True, clear_circuit=False)

    def _refill_pause_active(self) -> bool:
        # Always re-check proxy health on a cadence while running.
        self._evaluate_proxy_health(force=False)
        if not self.refill_paused:
            return False
        now = time.monotonic()
        # Hold pauses (proxy dead) do not auto-clear by timer.
        if self._proxy_unhealthy:
            if (now - float(self._last_refill_pause_log_at or 0.0)) >= REFILL_PAUSE_LOG_INTERVAL_SEC:
                self._last_refill_pause_log_at = now
                self._log(
                    "SYSTEM",
                    f"补货仍暂停（等待代理恢复）：{self.refill_pause_reason or '代理不可用'}",
                )
            return True
        if now >= float(self.refill_pause_until or 0.0):
            # timed pause expired
            if self.circuit_open:
                # re-evaluate circuit with latest window
                fails, total, rate = self._recent_fail_rate()
                if total >= CIRCUIT_WINDOW_SIZE and rate >= CIRCUIT_FAIL_RATE:
                    # still bad: extend
                    self._pause_refill(
                        f"近窗失败熔断延续：最近 {total} 单失败率 {rate:.0%}（失败 {fails}）",
                        seconds=CIRCUIT_PAUSE_SEC,
                        hold=False,
                        kind="circuit",
                    )
                    return True
                self.circuit_open = False
            self._clear_refill_pause(resume_log=True, clear_circuit=False)
            return False
        # Throttled reminder while still paused.
        if (now - float(self._last_refill_pause_log_at or 0.0)) >= REFILL_PAUSE_LOG_INTERVAL_SEC:
            remain = max(0.0, float(self.refill_pause_until) - now)
            self._last_refill_pause_log_at = now
            self._log(
                "SYSTEM",
                f"补货仍暂停，剩余 {remain:.1f}s：{self.refill_pause_reason or '等待资源'}",
            )
        return True

    def _acquire_embedded_proxy(self, worker: WorkerState) -> bool:
        """Lease a node for this worker. Returns False if none available."""
        if not self.plan.embedded_proxy_enabled:
            return True
        manager = self.embedded_proxy_manager
        if manager is None:
            worker.last_log = "内嵌代理已启用但管理器未就绪"
            self._log(f"W{worker.index:02d}", worker.last_log)
            return False
        exclude = set(worker.tried_node_ids or [])
        node = manager.acquire(exclude_ids=exclude)
        if node is None:
            worker.last_log = "没有可用的内嵌代理节点"
            self._log(f"W{worker.index:02d}", worker.last_log)
            return False
        if worker.manual_proxy or worker.manual_proxy_lease_token:
            self._release_manual_proxy(worker, success=None, reason="switch_to_embedded")
        worker.proxy_node_id = str(node.id)
        worker.proxy_node_name = str(getattr(node, "name", "") or "")
        worker.proxy_local_http = str(getattr(node, "local_http", "") or "")
        worker.proxy_attempt = int(worker.proxy_attempt or 0) + 1
        lease = int(getattr(node, "ref_count", 0) or 0)
        self._log(
            f"W{worker.index:02d}",
            f"[Proxy] 分配节点 #{worker.proxy_node_id} {worker.proxy_node_name} "
            f"-> {worker.proxy_local_http} (lease={lease})",
        )
        return True

    def _release_embedded_proxy(
        self,
        worker: WorkerState,
        *,
        failed: bool = False,
        reason: str = "",
    ) -> None:
        if not worker.proxy_node_id:
            return
        manager = self.embedded_proxy_manager
        node_id = worker.proxy_node_id
        reason_text = self._redact_proxy_text(reason or worker.last_log or "")
        if manager is not None:
            try:
                manager.release(node_id, failed=failed, reason=reason_text)
            except TypeError:
                # Backward-compatible with older manager signatures.
                try:
                    manager.release(node_id, failed=failed)
                except Exception as exc:  # pragma: no cover - defensive
                    self._log(f"W{worker.index:02d}", f"[Proxy] 释放节点失败: {exc}")
            except Exception as exc:  # pragma: no cover - defensive
                self._log(f"W{worker.index:02d}", f"[Proxy] 释放节点失败: {exc}")
            else:
                if failed and ("tls" in reason_text.lower() or "curl: (35)" in reason_text.lower() or "openssl" in reason_text.lower()):
                    self._log(
                        f"W{worker.index:02d}",
                        f"[Proxy] 节点 TLS 失败已冷却 #{node_id}",
                    )
        worker.proxy_node_id = None
        worker.proxy_node_name = ""
        worker.proxy_local_http = ""

    def _http_proxy_pool_active(self) -> bool:
        """True when HTTP proxy pool (proxies.txt) is configured for this run.

        Can be combined with embedded mihomo: registration workers may use either
        embedded VLESS/Hy2/AnyTLS/Trojan nodes or subscription HTTP proxies.
        """
        mode = str(self.plan.proxy_mode or "").strip().lower()
        if mode in {"none", "direct"}:
            return False
        return "--proxy-file" in list(self.plan.proxy_args or []) or mode in {"pool", "auto"}

    def _manual_proxy_pool_active(self) -> bool:
        """Backward-compatible alias: HTTP pool only when embedded is off."""
        if self.plan.embedded_proxy_enabled:
            # Hybrid mode uses _http_proxy_pool_active via _acquire_worker_proxy.
            return False
        return self._http_proxy_pool_active()

    def _ensure_manual_proxy_rotator(self):
        """Build the rotator from the frozen snapshot or legacy live pool."""
        if getattr(self, "_manual_proxy_rotator", None) is not None:
            return self._manual_proxy_rotator
        try:
            from proxy_pool import configure_global_rotator, load_proxy_lines, ProxyRotator
        except Exception as exc:  # pragma: no cover
            self._log("SYSTEM", f"[Proxy] 无法加载 proxy_pool: {exc}")
            self._manual_proxy_rotator = None
            return None
        source = self._manual_proxy_source_path()
        proxy_file = str(source or "")
        if self._uses_static_proxy_leases():
            proxies = list(
                self._static_proxy_entries
                or tuple(getattr(self.plan, "proxy_pool_entries", ()) or ())
            )
            if not proxies and source is not None:
                # Direct unit/integration callers may acquire before start();
                # production start() always freezes the file first.
                proxies = load_proxy_lines(str(source))
                self._static_proxy_entries = tuple(proxies)
            stats_file = str(self.plan.config_path.parent / "state" / "proxy_stats.log")
            rotator = ProxyRotator(proxies, stats_file=stats_file)
        else:
            proxies = load_proxy_lines(proxy_file)
            rotator = configure_global_rotator(
                proxies,
                stats_file=str(self.plan.config_path.parent / "state" / "proxy_stats.log"),
                force=True,
            )
        self._manual_proxy_rotator = rotator
        self._log(
            "SYSTEM",
            f"[Proxy] 手动代理池已就绪 | file={os.path.basename(proxy_file) or 'snapshot'} valid={len(rotator)}",
        )
        if len(rotator) == 0:
            self._log("SYSTEM", "[Proxy][warn] 手动代理池有效条目为 0（可能全是 null host）")
        return rotator

    def _acquire_manual_proxy(self, worker: WorkerState) -> bool:
        """Acquire one HTTP proxy from proxies.txt pool."""
        if not self._http_proxy_pool_active():
            return False
        rotator = self._ensure_manual_proxy_rotator()
        if rotator is None or len(rotator) == 0:
            worker.last_log = "HTTP 代理池无有效条目（请检查 proxies.txt / 订阅 HTTP 节点）"
            self._log(f"W{worker.index:02d}", worker.last_log)
            return False
        lease = None
        if self._uses_static_proxy_leases():
            lease = rotator.acquire_lease(owner=f"worker-{worker.index}")
            proxy = str(getattr(lease, "proxy", "") or "").strip()
        else:
            proxy = str(rotator.next() or "").strip()
        if not proxy:
            worker.last_log = "HTTP 代理池暂时无空闲健康租约（可能占用中或冷却中）"
            self._log(f"W{worker.index:02d}", worker.last_log)
            return False
        # Clear any previous embedded lease; one worker owns one egress.
        if worker.proxy_node_id:
            self._release_embedded_proxy(worker, failed=False)
        worker.manual_proxy = proxy
        worker.manual_proxy_lease_token = str(getattr(lease, "token", "") or "")
        worker.proxy_attempt = int(worker.proxy_attempt or 0) + 1
        try:
            from proxy_pool import extract_country, mask_proxy

            country = extract_country(proxy)
            display = mask_proxy(proxy)
        except Exception:
            country, display = "??", proxy
        self._log(
            f"W{worker.index:02d}",
            f"[Proxy] 分配 HTTP 代理 country={country} attempt={worker.proxy_attempt} -> {display}",
        )
        return True

    def _acquire_worker_proxy(self, worker: WorkerState) -> bool:
        """Acquire egress for one worker: embedded mihomo and/or HTTP pool (hybrid).

        Preference is round-robin when both sources are available, with fallback
        to the other source if the preferred one has no free node/proxy.
        """
        use_embedded = bool(self.plan.embedded_proxy_enabled)
        use_http = bool(self._http_proxy_pool_active())
        if not use_embedded and not use_http:
            return True

        order: List[str] = []
        if use_embedded and use_http:
            # Round-robin so best-cn HTTP and mihomo nodes share registration load.
            seq = int(getattr(self, "_hybrid_proxy_seq", 0) or 0)
            self._hybrid_proxy_seq = seq + 1
            order = ["http", "embedded"] if (seq % 2) else ["embedded", "http"]
        elif use_embedded:
            order = ["embedded"]
        else:
            order = ["http"]

        errors: List[str] = []
        for source in order:
            if source == "embedded":
                # Ensure no stale HTTP assignment remains.
                self._release_manual_proxy(worker, success=None, reason="switch_to_embedded")
                if self._acquire_embedded_proxy(worker):
                    return True
                errors.append(worker.last_log or "内嵌代理无可用节点")
            else:
                # Ensure no stale embedded assignment remains (should already be empty).
                if worker.proxy_node_id:
                    self._release_embedded_proxy(worker, failed=False)
                if self._acquire_manual_proxy(worker):
                    return True
                errors.append(worker.last_log or "HTTP 代理池无可用代理")

        worker.last_log = " / ".join([e for e in errors if e][:2]) or "没有可用代理"
        self._log(f"W{worker.index:02d}", worker.last_log)
        return False

    def _release_manual_proxy(
        self,
        worker: WorkerState,
        *,
        success: Optional[bool] = None,
        reason: str = "",
    ) -> bool:
        """Release a worker's HTTP route exactly once and attribute an outcome."""
        proxy = str(worker.manual_proxy or "").strip()
        token = str(worker.manual_proxy_lease_token or "").strip()
        if not proxy and not token:
            return False
        rotator = getattr(self, "_manual_proxy_rotator", None)
        if rotator is None:
            try:
                from proxy_pool import get_global_rotator

                rotator = get_global_rotator()
            except Exception:
                rotator = None
        released = False
        try:
            clean_reason = self._redact_proxy_text(reason)[:120]
            if rotator is not None and token:
                released = bool(
                    rotator.release_lease(
                        token,
                        success=success,
                        reason=clean_reason,
                    )
                )
            elif rotator is not None and proxy:
                # Legacy non-sticky rotation has no token, but clearing the
                # assignment still makes duplicate exit-path calls idempotent.
                if success is not None:
                    rotator.record_result(proxy, bool(success), reason=clean_reason)
                    if success:
                        rotator.mark_good(proxy)
                    else:
                        rotator.mark_bad(proxy)
                released = True
            else:
                released = bool(proxy or token)
        except Exception:
            released = False
        finally:
            worker.manual_proxy = ""
            worker.manual_proxy_lease_token = ""
        return released

    def _report_manual_proxy_outcome(
        self,
        worker: WorkerState,
        *,
        success: bool,
        reason: str = "",
    ) -> None:
        """Compatibility wrapper for callers using the pre-lease method name."""
        self._release_manual_proxy(worker, success=success, reason=reason)

    def _worker_proxy_failure_blob(self, worker: WorkerState, reason_text: str = "") -> str:
        parts = [reason_text, worker.last_log]
        if worker.log_path and worker.log_path.is_file():
            try:
                parts.append(worker.log_path.read_text(encoding="utf-8", errors="replace")[-4000:])
            except OSError:
                pass
        return "\n".join(str(p) for p in parts if p)

    @staticmethod
    def _uses_independent_turnstile_route_for_failure(
        worker: WorkerState,
        failure_blob: str,
    ) -> bool:
        text_value = str(failure_blob or "").lower()
        return bool(
            worker.uses_independent_turnstile_proxy
            and ("turnstile" in text_value or "captcha" in text_value)
        )

    def _isolate_static_proxy_lease(
        self,
        worker: WorkerState,
        reason: str,
    ) -> bool:
        """Cooldown one runtime-bad static route and return its lease once."""
        if not self._uses_static_proxy_leases() or not worker.manual_proxy_lease_token:
            return False
        proxy = str(worker.manual_proxy or "")
        try:
            index = self._static_proxy_entries.index(proxy)
        except ValueError:
            index = -1
        released = self._release_manual_proxy(
            worker,
            success=False,
            reason=self._redact_proxy_text(reason)[:120],
        )
        if not released:
            return False
        if index >= 0:
            self._static_proxy_health[index] = {
                "index": index,
                "ok": False,
                "reason": "runtime_proxy_failure",
                "targets": {},
            }
        self._log(
            "SYSTEM",
            f"[Proxy] 静态 HTTP 槽位 "
            f"#{index + 1 if index >= 0 else '?'} 运行期隔离并进入冷却",
        )
        return True

    # Compatibility hook retained for callers of the previous indexed-slot API.
    def _isolate_static_proxy_slot(self, worker: WorkerState, reason: str) -> bool:
        return self._isolate_static_proxy_lease(worker, reason)

    def _maybe_retry_proxy_node(self, worker: WorkerState, reason_text: str = "") -> bool:
        """If failure looks proxy-related and retries remain, switch egress and respawn.

        Hybrid mode may switch between embedded mihomo nodes and HTTP pool proxies.
        """
        if self.stopping:
            return False
        use_embedded = bool(self.plan.embedded_proxy_enabled)
        use_http = bool(self._http_proxy_pool_active())
        if not use_embedded and not use_http:
            return False
        max_retries = max(1, int(self.plan.embedded_proxy_max_node_retries or 3))
        blob = self._worker_proxy_failure_blob(worker, reason_text)
        if self._uses_independent_turnstile_route_for_failure(worker, blob):
            # A dedicated solver route owns this failure.  Keep the registration
            # route out of proxy retry/isolation attribution.
            return False
        if not _looks_like_proxy_failure(blob):
            return False

        if self._isolate_static_proxy_lease(worker, blob):
            attempt = max(1, int(worker.proxy_attempt or 0))
            if attempt >= max_retries:
                worker.last_log = (
                    f"[Proxy] 静态 HTTP 路由失败已达上限 "
                    f"({attempt}/{max_retries})，计入失败"
                )
                self._log(f"W{worker.index:02d}", worker.last_log)
                return False
            # This attempt diagnosed infrastructure rather than a business
            # account result.  Refill creates a replacement logical task while
            # retaining the attempt budget in _static_proxy_retry_queue.
            self._static_proxy_retry_queue.append(attempt)
            worker.last_log = "[Proxy] 静态 HTTP 路由已隔离，任务将重排"
            self._mark_terminal(worker, "stopped")
            self.started_tasks = max(0, int(self.started_tasks) - 1)
            return True

        current_id = worker.proxy_node_id
        if current_id and current_id not in worker.tried_node_ids:
            worker.tried_node_ids.append(current_id)
        if worker.proxy_node_id:
            self._release_embedded_proxy(worker, failed=True, reason=reason_text)
        if worker.manual_proxy:
            self._report_manual_proxy_outcome(
                worker,
                success=False,
                reason=_safe_text(reason_text, 120),
            )
            worker.manual_proxy = ""

        attempt = int(worker.proxy_attempt or 0)
        if attempt >= max_retries:
            worker.last_log = (
                f"[Proxy] 代理失败已达上限 ({attempt}/{max_retries})，放弃重试"
            )
            self._log(f"W{worker.index:02d}", worker.last_log)
            return False
        next_attempt = attempt + 1
        reason_short = _safe_text(reason_text, 120)
        kind = "TLS" if _looks_like_proxy_failure(reason_text) and (
            "tls" in str(reason_text or "").lower()
            or "curl: (35)" in str(reason_text or "").lower()
            or "openssl" in str(reason_text or "").lower()
        ) else "代理"
        self._log(
            f"W{worker.index:02d}",
            f"[Proxy] {kind}失败，切换出口 ({next_attempt}/{max_retries}) | {reason_short}",
        )
        # Respawn same logical task with a fresh egress (embedded and/or HTTP).
        worker.status = "queued"
        worker.process = None
        worker.return_code = None
        if not self._acquire_worker_proxy(worker):
            worker.last_log = worker.last_log or "没有可用代理"
            self._mark_terminal(worker, "failed")
            self._record_failure(worker, worker.last_log)
            self._log(
                f"W{worker.index:02d}",
                f"[Proxy] 无可用出口，停止本任务重试并暂停补货 | {worker.last_log}",
            )
            self._pause_refill(worker.last_log)
            return True  # handled (terminal)
        launched = self._spawn_one(worker, acquire_proxy=False)
        if not launched:
            if worker.status not in {"failed", "succeeded", "stopped"}:
                self._mark_terminal(worker, "failed")
                self._record_failure(worker, worker.last_log or "启动失败")
            self._pause_refill(worker.last_log or "启动失败")
            return True
        return True

    def _release_all_embedded_proxies(self) -> None:
        if not self.plan.embedded_proxy_enabled:
            return
        for worker in self.workers:
            if worker.proxy_node_id:
                self._release_embedded_proxy(worker, failed=False)

    def _release_all_manual_proxies(self) -> None:
        for worker in self.workers:
            if worker.manual_proxy or worker.manual_proxy_lease_token:
                self._release_manual_proxy(worker, success=None, reason="batch_finalize")

    def _spawn_one(self, worker: WorkerState, *, acquire_proxy: bool = True) -> bool:
        """Try to launch one worker process.

        Returns True only when the subprocess is actually running.
        Resource shortages (no proxy node) return False without counting failure.
        """
        worker.accounts_path = self.run_dir / f"accounts_{worker.index:03d}.txt"
        worker.log_path = self.run_dir / f"worker_{worker.index:03d}.log"
        if acquire_proxy and (self.plan.embedded_proxy_enabled or self._http_proxy_pool_active()):
            if not self._acquire_worker_proxy(worker):
                if not worker.last_log:
                    worker.last_log = "没有可用代理"
                # Do not mark failed / do not write failure counters.
                return False
        try:
            command = self._command_for(worker)
        except Exception as exc:
            self._mark_terminal(worker, "failed")
            worker.last_log = self._redact_proxy_text(f"构建工作进程命令失败: {exc}")
            self._release_manual_proxy(
                worker,
                success=False,
                reason="command_build_failed",
            )
            self._release_embedded_proxy(worker, failed=False, reason=worker.last_log)
            self._record_failure(worker, worker.last_log)
            self._log(f"W{worker.index:02d}", worker.last_log)
            return False
        log_handle = None
        try:
            log_handle = worker.log_path.open("w", encoding="utf-8", buffering=1)
            try:
                os.chmod(worker.log_path, 0o600)
            except OSError:
                pass
            child_env = os.environ.copy()
            try:
                cfg_for_env = _read_config(self.plan.config_path)
            except Exception:
                cfg_for_env = {}
            try:
                inflight = resolve_local_turnstile_max_inflight_cfg(cfg_for_env, strict=False)
            except Exception:
                inflight = 2
            child_env["XAI_LOCAL_TURNSTILE_MAX_INFLIGHT"] = str(max(1, min(12, int(inflight))))
            child_env["XAI_CONFIG_PATH"] = str(self.plan.config_path)
            child_env["XAI_MAIL_CONFIG"] = str(self.plan.config_path)
            process = subprocess.Popen(
                command,
                cwd=str(ROOT_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=child_env,
            )
        except Exception as exc:
            self._mark_terminal(worker, "failed")
            worker.last_log = self._redact_proxy_text(f"无法启动进程: {exc}")
            self._release_manual_proxy(
                worker,
                success=False,
                reason="process_spawn_failed",
            )
            self._release_embedded_proxy(worker, failed=True, reason=worker.last_log)
            self._record_failure(worker, worker.last_log)
            self._log(f"W{worker.index:02d}", worker.last_log)
            if log_handle is not None:
                try:
                    log_handle.close()
                except OSError:
                    pass
            return False

        worker.process = process
        worker.status = "running"
        worker.last_log = "协议进程已启动"
        self._log(f"W{worker.index:02d}", worker.last_log)

        def copy_and_queue() -> None:
            assert process.stdout is not None
            try:
                for line in iter(process.stdout.readline, ""):
                    safe_line = _redact_sensitive_runtime_text(
                        self._redact_proxy_text(line)
                    )
                    try:
                        log_handle.write(safe_line)
                    except OSError:
                        pass
                    self.events.put((worker.index, safe_line))
            finally:
                try:
                    process.stdout.close()
                except OSError:
                    pass
                try:
                    log_handle.close()
                except OSError:
                    pass

        threading.Thread(target=copy_and_queue, daemon=True).start()
        return True


    def _maybe_recover_continuous_stall(self) -> None:
        """Unstick continuous runs that have zero active work but still claim running.

        High-concurrency batches can end up with active=0 after pause/spawn glitches
        or after a poller gap. Soft pauses (non-proxy-hold) are force-cleared so
        refill can continue. Proxy-dead holds are left to health recovery.
        """
        if not self.is_continuous or self.done or self.stopping:
            return
        if self.phase != "running":
            return
        if self.active:
            self._last_progress_at = time.monotonic()
            return
        if not self._should_refill():
            return
        now = time.monotonic()
        last = float(self._last_progress_at or self.started_at_monotonic or now)
        idle_for = now - last
        if idle_for < float(CONTINUOUS_STALL_RECOVERY_SEC):
            return
        # Do not thrash recovery logs.
        if (now - float(self._last_stall_recover_at or 0.0)) < float(CONTINUOUS_STALL_RECOVERY_SEC):
            return
        self._last_stall_recover_at = now
        # Proxy hard-hold: only nudge health evaluation; do not clear blindly.
        if self._proxy_unhealthy:
            self._evaluate_proxy_health(force=True)
            if self._proxy_unhealthy:
                self._log(
                    "SYSTEM",
                    f"持续运行空闲 {idle_for:.0f}s：内嵌代理仍不可用，等待恢复后继续补货",
                )
                return
        reason = self.refill_pause_reason or ("circuit" if self.circuit_open else "未知")
        if self.refill_paused or self.circuit_open:
            self._clear_refill_pause(resume_log=False, clear_circuit=True)
            self._log(
                "SYSTEM",
                f"持续运行空闲 {idle_for:.0f}s 且无活动任务，强制恢复补货（原暂停：{reason}）",
            )
        else:
            self._log(
                "SYSTEM",
                f"持续运行空闲 {idle_for:.0f}s 且无活动任务，重新尝试补货",
            )
        # Touch progress so next recovery waits another full window if spawn still fails.
        self._last_progress_at = now

    def _available_spawn_slots(self) -> int:
        """Return general worker slots, capped only for HTTP-only sticky runs."""
        slots = max(0, int(self.plan.workers) - len(self.active))
        if (
            slots > 0
            and self._uses_static_proxy_leases()
            and not self.plan.embedded_proxy_enabled
        ):
            rotator = self._ensure_manual_proxy_rotator()
            free_leases = 0
            if rotator is not None:
                try:
                    free_leases = int(rotator.available_lease_count())
                except Exception:
                    free_leases = 0
            slots = min(slots, max(0, free_leases))
        return slots

    def _spawn_available(self) -> None:
        if self.done:
            return
        if not self._should_refill():
            if self.phase == "running" and (self.stopping or not self._should_refill()):
                # Enter draining when no more work should be created.
                if self.stopping or self.is_continuous or self.started_tasks >= int(self.plan.count or 0):
                    if self.phase != "draining":
                        self.phase = "draining"
                        if self.is_continuous and not self.stopping:
                            if int(getattr(self.plan, "target_success", 0) or 0) > 0 and self.succeeded_count >= int(self.plan.target_success):
                                self._log("SYSTEM", f"已达成功目标 {self.plan.target_success}，停止补货并收尾")
                            elif int(getattr(self.plan, "continuous_max_runtime_min", 0) or 0) > 0:
                                self._log("SYSTEM", "已达最长运行时间，停止补货并收尾")
            return
        if self._refill_pause_active():
            return

        # Hard cap attempts in one tick: never create more than worker slots.
        slots = self._available_spawn_slots()
        attempts = 0
        while slots > 0 and attempts < int(self.plan.workers) and self._should_refill():
            if self._refill_pause_active():
                break
            static_retry_attempt: Optional[int] = None
            if self._static_proxy_retry_queue:
                static_retry_attempt = self._static_proxy_retry_queue.popleft()
            worker = WorkerState(
                index=self.next_index,
                proxy_attempt=int(static_retry_attempt or 0),
            )
            self.next_index += 1
            attempts += 1
            # staged until process actually starts
            worker.status = "queued"
            self.workers.append(worker)
            self.worker_by_index[worker.index] = worker
            launched = self._spawn_one(worker)
            if launched:
                self.started_tasks += 1
                self._last_progress_at = time.monotonic()
                slots = self._available_spawn_slots()
                continue
            # Launch failed without becoming active.
            reason = worker.last_log or "启动失败"
            # Drop this logical slot from hot lists; do not count as business failure
            # when it is a resource shortage (proxy unavailable).
            resource_shortage = (
                "没有可用的内嵌代理节点" in reason
                or "内嵌代理已启用但管理器未就绪" in reason
                or "无空闲健康租约" in reason
                or "HTTP 代理池无有效条目" in reason
                or "没有可用代理" in reason
            )
            if resource_shortage:
                if static_retry_attempt is not None:
                    self._static_proxy_retry_queue.appendleft(static_retry_attempt)
                # Remove non-started worker so it does not pollute active/queues.
                try:
                    self.workers.remove(worker)
                except ValueError:
                    pass
                self.worker_by_index.pop(worker.index, None)
                self._pause_refill(reason)
                break
            # Real launch error already marked failed inside _spawn_one.
            if worker.status not in {"failed", "stopped", "succeeded"}:
                self._mark_terminal(worker, "failed")
                self._record_failure(worker, reason)
            if static_retry_attempt is not None:
                # The original launched attempt was removed from started_tasks
                # when it was scheduled for replacement.  A hard replacement
                # launch failure terminates that same logical task.
                self.started_tasks += 1
            # Still respect one-tick budget; avoid tight-loop storm.
            slots = self._available_spawn_slots()
            # brief pause after hard spawn errors too
            self._pause_refill(reason, seconds=min(DEFAULT_REFILL_PAUSE_SEC, 1.0))
            break

    def _drain_events(self) -> None:
        while True:
            try:
                worker_index, message = self.events.get_nowait()
            except queue.Empty:
                return
            worker = self.worker_by_index.get(worker_index) or self.workers[worker_index - 1]
            raw = str(message or "")
            if raw.startswith("__CONVERT_DONE__|"):
                parts = raw.split("|", 2)
                ok = len(parts) >= 2 and parts[1] == "1"
                msg = parts[2] if len(parts) >= 3 else "SSO 转换结束"
                worker.convert_thread = None
                if self.stopping and not ok:
                    self._mark_terminal(worker, "stopped")
                else:
                    self._mark_terminal(worker, "succeeded" if ok else "failed")
                worker.last_log = msg
                if worker.status == "failed":
                    self._record_failure(worker, msg)
                self._log(f"W{worker_index:02d}", worker.last_log)
                continue
            worker.last_log = _safe_text(
                _redact_sensitive_runtime_text(self._redact_proxy_text(raw))
            )
            self._log(f"W{worker_index:02d}", worker.last_log)

    def _check_processes(self) -> None:
        for worker in list(self.workers):
            if worker.status != "running" or worker.process is None:
                continue
            return_code = worker.process.poll()
            if return_code is None:
                continue
            worker.return_code = return_code
            worker.process = None
            if self.stopping:
                self._mark_terminal(worker, "stopped")
                worker.last_log = "已被操作者停止"
                self._release_manual_proxy(worker, success=None, reason="batch_stopped")
                self._release_embedded_proxy(worker, failed=False)
                self._log(f"W{worker.index:02d}", worker.last_log)
            elif return_code == 0:
                self._release_embedded_proxy(worker, failed=False)
                self._report_manual_proxy_outcome(worker, success=True, reason="register_ok")
                if self.plan.run_mode == RUN_MODE_REGISTER_SSO:
                    self._start_sso_convert(worker)
                else:
                    self._mark_terminal(worker, "succeeded")
                    worker.last_log = "协议任务已完成"
                    self._log(f"W{worker.index:02d}", worker.last_log)
            else:
                reason = f"协议任务退出，退出码 {return_code}"
                worker.last_log = reason
                if self._maybe_retry_proxy_node(worker, reason):
                    # either respawned (running) or already marked terminal inside helper
                    if worker.status == "running":
                        continue
                    self._log(f"W{worker.index:02d}", worker.last_log)
                    continue
                blob = self._worker_proxy_failure_blob(worker, reason)
                category = classify_failure_text(blob)
                if self._uses_independent_turnstile_route_for_failure(worker, blob):
                    self._release_manual_proxy(
                        worker,
                        success=None,
                        reason="independent_turnstile_failure",
                    )
                else:
                    self._report_manual_proxy_outcome(
                        worker,
                        success=False,
                        reason=category if category != "unknown" else reason,
                    )
                self._mark_terminal(worker, "failed")
                # Attribute proxy/TLS failure to the node only when it looks like egress/TLS.
                self._release_embedded_proxy(
                    worker,
                    failed=_looks_like_proxy_failure(blob),
                    reason=blob,
                )
                self._record_failure(worker, worker.last_log)
                self._log(f"W{worker.index:02d}", worker.last_log)

    def _finalize(self) -> None:
        if self.done:
            return
        try:
            summary_dir = self.run_dir.parent.parent / "accounts"
            summary_dir.mkdir(parents=True, exist_ok=True)
            summary = summary_dir / f"accounts_http_{self.run_id}.txt"
            lines: List[str] = []
            account_files = sorted(self.run_dir.glob("accounts_*.txt"))
            for accounts_path in account_files:
                try:
                    lines.extend(
                        line
                        for line in accounts_path.read_text(encoding="utf-8").splitlines()
                        if line.strip()
                    )
                except OSError as exc:
                    self._log("SYSTEM", f"无法读取工作线程账号文件: {exc}")
            if lines:
                summary.write_text("\n".join(lines) + "\n", encoding="utf-8")
                try:
                    os.chmod(summary, 0o600)
                except OSError:
                    pass
                self.summary_path = summary
                self.account_count = len(lines)
            if self.finished_at_monotonic is None:
                self.finished_at_monotonic = time.monotonic()
            self._write_summary_json()
            self._log(
                "SYSTEM",
                f"批量完成: 成功={self.succeeded}, 失败={self.failed}, 账号数={self.account_count}",
            )
        finally:
            self._release_all_manual_proxies()
            self._release_all_embedded_proxies()
            self._stop_shared_broker()
            self.phase = "done"
            self.done = True

    def tick(self) -> None:
        if not self.started:
            return
        self._drain_events()
        self._check_processes()
        self._prune_finished_workers()
        # Keep proxy health / circuit state fresh even when idle slots exist.
        self._evaluate_proxy_health(force=False)
        # Local Turnstile: scrub orphan solvers so chrome zombies cannot accumulate.
        self._maybe_cleanup_browser_residues(force=False)
        # Continuous anti-stall: never sit forever at active=0 while refill is allowed.
        self._maybe_recover_continuous_stall()
        # If success target / runtime reached, flip to draining.
        if self.phase == "running" and not self._should_refill():
            self.phase = "draining"
        self._spawn_available()
        if self.phase in {"draining", "running"} and (not self.active) and (not self._should_refill()):
            self._drain_events()
            self._finalize()

    def stop(self) -> None:
        if self.done:
            return
        self.stopping = True
        self.phase = "draining"
        self._log("SYSTEM", "正在停止活动中的协议任务（停止补货并收尾）")
        for worker in list(self.workers):
            if worker.status == "queued":
                self._mark_terminal(worker, "stopped")
                worker.last_log = "因批次被停止而未启动"
                self._release_manual_proxy(worker, success=None, reason="batch_stopped")
                self._release_embedded_proxy(worker, failed=False)
                self._log(f"W{worker.index:02d}", worker.last_log)
        for worker in list(self.workers):
            if worker.status == "running" and worker.process is not None:
                try:
                    worker.process.terminate()
                except OSError:
                    pass
            elif worker.status == "converting":
                worker.last_log = "停止中：等待当前 SSO 转换收尾"
                self._log(f"W{worker.index:02d}", worker.last_log)
        # Keep proxy/broker alive until finalize so in-flight converts can finish cleanly.

    def _record_failure(self, worker: WorkerState, reason_text: str = "") -> None:
        if worker.index in self._failure_recorded:
            return
        blob_parts = [reason_text, worker.last_log]
        if worker.log_path and worker.log_path.is_file():
            try:
                blob_parts.append(worker.log_path.read_text(encoding="utf-8", errors="replace")[-4000:])
            except OSError:
                pass
        category = classify_failure_text("\n".join(str(p) for p in blob_parts if p))
        self.failure_counts[category] = int(self.failure_counts.get(category) or 0) + 1
        self._failure_recorded.add(worker.index)

    def snapshot(self) -> Dict[str, object]:
        if self.started_at_monotonic is None:
            elapsed_sec = 0
        elif self.finished_at_monotonic is not None:
            elapsed_sec = max(0, int(self.finished_at_monotonic - self.started_at_monotonic))
        else:
            elapsed_sec = max(0, int(time.monotonic() - self.started_at_monotonic))

        completed = self.completed
        succeeded = self.succeeded
        avg_success_per_min = (
            None if elapsed_sec < 1 else float(succeeded) / (elapsed_sec / 60.0)
        )
        success_rate = None if completed == 0 else float(succeeded) / float(completed)
        win_fails, win_total, win_rate = self._recent_fail_rate()

        # UI only needs active + recent terminals; full history is on disk.
        active_workers = self.active
        recent = list(self.recent_workers)
        shown_map = {}
        for worker in list(active_workers) + recent:
            shown_map[worker.index] = worker
        shown_workers = sorted(shown_map.values(), key=lambda w: int(w.index))
        planned_count = int(self.plan.count or 0)
        if self.is_continuous:
            planned_count = int(getattr(self.plan, "target_success", 0) or 0)
        return {
            "run_id": self.run_id,
            "started": self.started,
            "done": self.done,
            "stopping": self.stopping,
            "phase": self.phase,
            "refill_paused": bool(self.refill_paused),
            "refill_pause_reason": self._redact_proxy_text(self.refill_pause_reason or ""),
            "pause_reason": self._redact_proxy_text(self.refill_pause_reason or ""),
            "circuit_open": bool(self.circuit_open),
            "proxy_unhealthy": bool(self._proxy_unhealthy),
            "target_mode": getattr(self.plan, "target_mode", TARGET_MODE_COUNT),
            "target_success": int(getattr(self.plan, "target_success", 0) or 0),
            "count": planned_count,
            "started_tasks": int(self.started_tasks),
            "completed": completed,
            "succeeded": succeeded,
            "failed": self.failed,
            "stopped": self.stopped,
            "active": len(active_workers),
            "account_count": self.account_count,
            "failure_counts": dict(self.failure_counts),
            "warnings": list(self.plan.warnings),
            "run_dir": str(self.run_dir),
            "summary_path": str(self.summary_path) if self.summary_path else "",
            "started_at": self.started_at_wall or "",
            "elapsed_sec": elapsed_sec,
            "avg_success_per_min": avg_success_per_min,
            "success_rate": success_rate,
            "recent_fail_count": int(win_fails),
            "recent_total": int(win_total),
            "recent_fail_rate": float(win_rate),
            "worker_total": len(shown_workers),
            "workers_truncated": max(0, int(self.started_tasks) - len(shown_workers)),
            "workers": [
                {
                    "index": worker.index,
                    "status": worker.status,
                    "last_log": _redact_sensitive_runtime_text(
                        self._redact_proxy_text(worker.last_log)
                    ),
                    "return_code": worker.return_code,
                }
                for worker in shown_workers
            ],
        }

    def _write_summary_json(self) -> None:
        payload = self.snapshot()
        target = self.run_dir / "summary.json"
        try:
            atomic_write_private_text(
                target,
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            )
        except OSError as exc:
            self._log("SYSTEM", f"无法写入 summary.json: {exc}")

    def exit_code(self) -> int:
        return 0 if self.done and self.failed == 0 else 2


class BatchBusyError(TuiConfigError):
    """Raised when a second batch is requested while one is still active."""


def list_runs(runs_dir: Optional[Path] = None, *, limit: int = 50) -> List[Dict[str, object]]:
    root = Path(runs_dir or RUNS_DIR)
    if not root.is_dir():
        return []
    entries: List[Tuple[float, Path]] = []
    for path in root.iterdir():
        if path.is_dir():
            try:
                entries.append((path.stat().st_mtime, path))
            except OSError:
                continue
    entries.sort(key=lambda item: item[0], reverse=True)
    result: List[Dict[str, object]] = []
    for _, path in entries[: max(1, int(limit or 50))]:
        detail = _run_summary_from_dir(path)
        result.append(detail)
    return result


def _run_summary_from_dir(run_dir: Path) -> Dict[str, object]:
    summary_path = run_dir / "summary.json"
    if summary_path.is_file():
        try:
            data = json.loads(summary_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data.setdefault("run_id", run_dir.name)
                data.setdefault("run_dir", str(run_dir))
                return data
        except (OSError, json.JSONDecodeError):
            pass
    workers = sorted(run_dir.glob("worker_*.log"))
    accounts = list(run_dir.glob("accounts_*.txt"))
    return {
        "run_id": run_dir.name,
        "run_dir": str(run_dir),
        "done": True,
        "count": len(workers),
        "succeeded": len(accounts),
        "failed": max(0, len(workers) - len(accounts)),
        "account_count": len(accounts),
        "failure_counts": {},
        "workers": [],
    }


def get_run_detail(run_id: str, runs_dir: Optional[Path] = None) -> Dict[str, object]:
    run_dir = Path(runs_dir or RUNS_DIR) / str(run_id)
    if not run_dir.is_dir():
        raise TuiConfigError(f"找不到运行记录: {run_id}")
    detail = _run_summary_from_dir(run_dir)
    files = []
    for path in sorted(run_dir.iterdir()):
        if path.is_file():
            files.append({"name": path.name, "size": path.stat().st_size})
    detail["files"] = files
    return detail


def resolve_run_file(run_id: str, rel_path: str, runs_dir: Optional[Path] = None) -> Path:
    run_dir = (Path(runs_dir or RUNS_DIR) / str(run_id)).resolve()
    if not run_dir.is_dir():
        raise TuiConfigError(f"找不到运行记录: {run_id}")
    candidate = (run_dir / str(rel_path)).resolve()
    try:
        candidate.relative_to(run_dir)
    except ValueError as exc:
        raise TuiConfigError("非法文件路径") from exc
    if not candidate.is_file():
        raise TuiConfigError(f"文件不存在: {rel_path}")
    return candidate


SENSITIVE_CONFIG_KEYS = (
    "turnstile_api_key",
    "yyds_api_key",
    "yyds_jwt",
    "duckmail_api_key",
    "cloudflare_api_key",
    "cpa_api_key",
)


def _mask_config_dict(config: Dict[str, object]) -> Dict[str, object]:
    masked = dict(config or {})
    for key in SENSITIVE_CONFIG_KEYS:
        if key in masked and str(masked.get(key) or "").strip():
            masked[key] = "***"
    return masked


def _settings_to_public_dict(settings: Settings) -> Dict[str, object]:
    config = _mask_config_dict(dict(settings.config or {}))
    return {
        "config_path": str(settings.config_path),
        "count": settings.count,
        "workers": settings.workers,
        "target_mode": _normalize_target_mode(getattr(settings, "target_mode", TARGET_MODE_COUNT)),
        "target_success": int(getattr(settings, "target_success", 0) or 0),
        "continuous_max_runtime_min": int(getattr(settings, "continuous_max_runtime_min", 0) or 0),
        "output_dir": str(settings.output_dir),
        "run_mode": settings.run_mode,
        "proxy_mode": "none" if settings.no_proxy or str(settings.proxy_mode or "").strip().lower() == "none" else str(settings.proxy_mode or "auto"),
        "no_proxy": bool(settings.no_proxy or str(settings.proxy_mode or "").strip().lower() == "none"),
        "embedded_proxy_enabled": _as_bool((settings.config or {}).get("embedded_proxy_enabled")),
        "egress_mode": encode_egress_mode(
            "none" if settings.no_proxy or str(settings.proxy_mode or "").strip().lower() == "none" else str(settings.proxy_mode or "auto"),
            (settings.config or {}).get("embedded_proxy_enabled"),
        ),
        "egress_mode_label": _egress_mode_label(
            encode_egress_mode(
                "none" if settings.no_proxy or str(settings.proxy_mode or "").strip().lower() == "none" else str(settings.proxy_mode or "auto"),
                (settings.config or {}).get("embedded_proxy_enabled"),
            )
        ),
        "turnstile_provider": settings.turnstile_provider,
        "turnstile_headless": settings.turnstile_headless,
        "local_turnstile_max_workers": resolve_local_turnstile_max_workers(settings.config or {}, strict=False),
        "local_turnstile_max_inflight": resolve_local_turnstile_max_inflight_cfg(settings.config or {}, strict=False),
        "submit_workers": max(1, min(MAX_SUBMIT_WORKERS, int((settings.config or {}).get("submit_workers") or settings.submit_workers or DEFAULT_SUBMIT_WORKERS))),
        "turnstile_solve_timeout": _bounded_int((settings.config or {}).get("turnstile_solve_timeout"), "Turnstile单次超时", minimum=5, maximum=600, default=90),
        "turnstile_solve_retries": _bounded_int((settings.config or {}).get("turnstile_solve_retries"), "Turnstile重试次数", minimum=1, maximum=10, default=1),
        "mail_code_timeout_sec": _bounded_int((settings.config or {}).get("mail_code_timeout_sec"), "邮箱验证码等待", minimum=10, maximum=180, default=40),
        "sso_convert_retries": settings.sso_convert_retries,
        "sso_convert_cooldown": settings.sso_convert_cooldown,
        "email_provider": str(config.get("email_provider") or ""),
        "config": config,
    }


def _proxy_file_path(settings: Settings) -> Path:
    raw = str(
        (settings.config or {}).get("proxy_file") or "fixtures/proxies.txt"
    ).strip() or "fixtures/proxies.txt"
    return _absolute_path(raw, settings.config_path.parent)


def _ms_mail_file_path(settings: Settings) -> Path:
    """Resolve Outlook/Hotmail Graph pool file path from config.ms_mail_file."""
    raw = str((settings.config or {}).get("ms_mail_file") or "").strip()
    if not raw:
        # Sensible default next to config; user can change path in UI.
        raw = "fixtures/outlook_mail.txt"
    return _absolute_path(raw, settings.config_path.parent)


def read_ms_mail_pool_text(settings: Settings) -> Dict[str, object]:
    path = _ms_mail_file_path(settings)
    text_value = ""
    exists = path.is_file()
    if exists:
        try:
            ensure_private_file(path)
            text_value = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise TuiConfigError("读取微软邮箱池失败") from exc
    valid = 0
    invalid = 0
    errors: List[str] = []
    for idx, ln in enumerate(text_value.splitlines(), start=1):
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        try:
            from xai_http_flow import parse_ms_mail_line

            parse_ms_mail_line(s)
            valid += 1
        except Exception as exc:
            invalid += 1
            if len(errors) < 8:
                errors.append(f"L{idx}: {_safe_text(exc)}")
    return {
        "path": str(path),
        "exists": exists,
        "line_count": valid,
        "invalid_count": invalid,
        "errors": errors,
        "text": text_value,
        "format": "email----password----client_id----refresh_token",
    }


def write_ms_mail_pool_text(settings: Settings, text_value: str) -> Dict[str, object]:
    path = _ms_mail_file_path(settings)
    content = str(text_value or "")
    if content and not content.endswith("\n"):
        content += "\n"
    # Normalize colon format → dash format for on-disk consistency.
    normalized_lines: List[str] = []
    valid = 0
    invalid = 0
    errors: List[str] = []
    for idx, ln in enumerate(content.splitlines(), start=1):
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#"):
            normalized_lines.append(s)
            continue
        try:
            from xai_http_flow import parse_ms_mail_line, serialize_ms_mail_line

            account = parse_ms_mail_line(s)
            normalized_lines.append(serialize_ms_mail_line(account))
            valid += 1
        except Exception as exc:
            invalid += 1
            if len(errors) < 8:
                errors.append(f"L{idx}: {_safe_text(exc)}")
            # Keep original so user can fix later
            normalized_lines.append(s)
    out = "\n".join(normalized_lines)
    if out and not out.endswith("\n"):
        out += "\n"
    lock_path = path.with_suffix(path.suffix + ".lock")
    try:
        with CrossProcessFileLock(
            lock_path,
            timeout=MS_MAIL_POOL_UI_LOCK_TIMEOUT_SEC,
        ):
            atomic_write_private_text(path, out)
    except CrossProcessLockTimeout as exc:
        raise TuiConfigError("写入微软邮箱池时锁等待超时") from exc
    except OSError as exc:
        raise TuiConfigError("写入微软邮箱池失败") from exc
    cfg = dict(settings.config or {})
    cfg["ms_mail_file"] = _config_path_value(path, settings.config_path.parent)
    # When user edits pool, prefer msgraph provider if they had empty path before.
    if not str(cfg.get("email_provider") or "").strip():
        cfg["email_provider"] = "msgraph"
    settings.config = cfg
    persist_settings(settings)
    return {
        "path": str(path),
        "exists": True,
        "line_count": valid,
        "invalid_count": invalid,
        "errors": errors,
        "text": out,
        "format": "email----password----client_id----refresh_token",
    }



def _credential_single_line(text: object) -> str:
    """Collapse credential/SSO payloads into one display line without losing characters."""
    return (
        str(text or "")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\n", "")
    )


def list_credential_pairs(
    output_dir: Path,
    *,
    page: int = 1,
    page_size: int = 1000,
) -> Dict[str, object]:
    """List credential JSON + matching SSO pairs as plain text lines.

    Line format: ``<json-full-text>____<sso-full-text>``
    Only ``*.json`` files are primary rows; missing ``.sso`` yields an empty right side.
    """
    directory = Path(output_dir).expanduser()
    try:
        directory = directory.resolve(strict=False)
    except OSError:
        directory = Path(output_dir).expanduser()

    page_i = max(1, int(page or 1))
    size_i = max(1, min(1000, int(page_size or 1000)))

    rows: list[Dict[str, object]] = []
    if directory.is_dir():
        json_files = [p for p in directory.iterdir() if p.is_file() and p.suffix.lower() == ".json"]
        json_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        for json_path in json_files:
            try:
                json_text = json_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            sso_path = json_path.with_suffix(".sso")
            sso_text = ""
            if sso_path.is_file():
                try:
                    sso_text = sso_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    sso_text = ""
            left = _credential_single_line(json_text)
            right = _credential_single_line(sso_text)
            rows.append(
                {
                    "name": json_path.stem,
                    "json_name": json_path.name,
                    "json_path": str(json_path),
                    "sso_name": sso_path.name if sso_path.is_file() else "",
                    "sso_path": str(sso_path) if sso_path.is_file() else "",
                    "has_sso": bool(sso_path.is_file()),
                    "mtime": float(json_path.stat().st_mtime),
                    "line": f"{left}____{right}",
                }
            )

    total = len(rows)
    total_pages = max(1, (total + size_i - 1) // size_i) if total else 1
    if page_i > total_pages:
        page_i = total_pages
    start = (page_i - 1) * size_i
    end = start + size_i
    page_rows = rows[start:end]
    return {
        "output_dir": str(directory),
        "exists": directory.is_dir(),
        "total": total,
        "page": page_i,
        "page_size": size_i,
        "total_pages": total_pages,
        "items": [
            {
                "name": r["name"],
                "json_name": r["json_name"],
                "json_path": r.get("json_path") or "",
                "sso_name": r["sso_name"],
                "sso_path": r.get("sso_path") or "",
                "has_sso": r["has_sso"],
                "line": r["line"],
            }
            for r in page_rows
        ],
        "text": "\n".join(str(r["line"]) for r in page_rows),
    }




def export_credential_page_and_delete(
    output_dir: Path,
    *,
    page: int = 1,
    page_size: int = 1000,
    export_dir: Path | None = None,
) -> Dict[str, object]:
    """Export current credential page to ``grok+{timestamp}.txt``, then delete sources.

    Safety order:
    1) build page rows
    2) write export file
    3) verify file content
    4) delete only the json/sso files belonging to that page
    """
    from datetime import datetime

    page_data = list_credential_pairs(output_dir, page=page, page_size=page_size)
    items = list(page_data.get("items") or [])
    if not items:
        raise TuiConfigError("当前页没有可导出的凭证")

    lines = [str(item.get("line") or "") for item in items]
    payload = "\n".join(lines)
    if payload and not payload.endswith("\n"):
        payload += "\n"

    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"grok+{stamp}.txt"
    target_dir = Path(export_dir or resolve_export_dir(ROOT_DIR)).expanduser()
    try:
        target_dir = target_dir.resolve(strict=False)
    except OSError:
        target_dir = Path(export_dir or resolve_export_dir(ROOT_DIR)).expanduser()
    target_dir.mkdir(parents=True, exist_ok=True)
    export_path = target_dir / filename

    try:
        export_path.write_text(payload, encoding="utf-8")
    except OSError as exc:
        raise TuiConfigError(f"导出文件写入失败: {exc}") from exc

    try:
        written = export_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TuiConfigError(f"导出后校验读取失败，已中止删除本地凭证: {exc}") from exc
    if written != payload:
        raise TuiConfigError("导出后内容校验不一致，已中止删除本地凭证")

    # Only delete files under the credential output directory.
    cred_dir = Path(page_data.get("output_dir") or output_dir).expanduser()
    try:
        cred_dir = cred_dir.resolve(strict=False)
    except OSError:
        pass
    deleted: list[str] = []
    delete_errors: list[str] = []
    for item in items:
        for key in ("json_path", "sso_path"):
            raw = str(item.get(key) or "").strip()
            if not raw:
                continue
            path_obj = Path(raw)
            try:
                resolved = path_obj.resolve(strict=False)
            except OSError:
                resolved = path_obj
            try:
                resolved.relative_to(cred_dir)
            except ValueError:
                delete_errors.append(f"拒绝删除目录外文件: {resolved}")
                continue
            if not resolved.is_file():
                continue
            try:
                resolved.unlink()
                deleted.append(str(resolved))
            except OSError as exc:
                delete_errors.append(f"{resolved.name}: {exc}")

    return {
        "ok": True,
        "filename": filename,
        "path": str(export_path),
        "export_dir": str(target_dir),
        "page": int(page_data.get("page") or page),
        "page_size": int(page_data.get("page_size") or page_size),
        "exported_count": len(items),
        "deleted_count": len(deleted),
        "deleted": deleted,
        "delete_errors": delete_errors,
        "text": payload,
        "output_dir": str(cred_dir),
    }



def resolve_export_dir(root_dir: Path | None = None) -> Path:
    """Dedicated folder for grok+timestamp.txt exports."""
    root = Path(root_dir or LOCAL_ROOT)
    export_dir = (root / "exports").expanduser()
    try:
        export_dir = export_dir.resolve(strict=False)
    except OSError:
        pass
    export_dir.mkdir(parents=True, exist_ok=True)
    # Soft-migrate legacy root-level export files once.
    try:
        for legacy in root.glob("grok+*.txt"):
            if not legacy.is_file():
                continue
            target = export_dir / legacy.name
            if target.exists():
                continue
            try:
                legacy.replace(target)
            except OSError:
                try:
                    target.write_bytes(legacy.read_bytes())
                except OSError:
                    pass
    except OSError:
        pass
    return export_dir


def _is_safe_export_name(name: str) -> bool:
    text = str(name or "").strip()
    if not text or "/" in text or "\\" in text or text in {".", ".."}:
        return False
    # Only plain export text files.
    if not text.endswith(".txt"):
        return False
    if text.startswith("."):
        return False
    return True


def resolve_export_file(root_dir: Path | None, name: str) -> Path:
    export_dir = resolve_export_dir(root_dir)
    filename = str(name or "").strip()
    if not _is_safe_export_name(filename):
        raise TuiConfigError("非法导出文件名")
    path = (export_dir / filename).resolve(strict=False)
    try:
        path.relative_to(export_dir.resolve(strict=False))
    except Exception as exc:
        raise TuiConfigError("非法导出路径") from exc
    return path


def list_export_files(root_dir: Path | None = None) -> Dict[str, object]:
    export_dir = resolve_export_dir(root_dir)
    files = []
    for path in export_dir.glob("*.txt"):
        if not path.is_file():
            continue
        if not _is_safe_export_name(path.name):
            continue
        try:
            st = path.stat()
            size = int(st.st_size)
            mtime = float(st.st_mtime)
        except OSError:
            continue
        # line count best-effort
        lines = 0
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for lines, _ in enumerate(fh, 1):
                    pass
        except OSError:
            lines = 0
        files.append(
            {
                "name": path.name,
                "path": str(path),
                "size": size,
                "mtime": mtime,
                "line_count": lines,
            }
        )
    files.sort(key=lambda x: float(x.get("mtime") or 0), reverse=True)
    return {
        "export_dir": str(export_dir),
        "exists": export_dir.is_dir(),
        "total": len(files),
        "items": files,
    }


def delete_export_file(root_dir: Path | None, name: str) -> Dict[str, object]:
    path = resolve_export_file(root_dir, name)
    if not path.is_file():
        raise TuiConfigError(f"导出文件不存在: {name}")
    try:
        path.unlink()
    except OSError as exc:
        raise TuiConfigError(f"删除导出文件失败: {exc}") from exc
    return {"ok": True, "deleted": path.name, "export_dir": str(path.parent)}

def read_proxy_pool_text(settings: Settings) -> Dict[str, object]:
    path = _proxy_file_path(settings)
    text_value = ""
    exists = path.is_file()
    if exists:
        try:
            text_value = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise TuiConfigError(f"读取代理池文件失败: {exc}") from exc
    lines = [ln.strip() for ln in text_value.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    return {
        "path": str(path),
        "exists": exists,
        "line_count": len(lines),
        "text": text_value,
    }


def write_proxy_pool_text(settings: Settings, text_value: str, *, sync_proxies_array: bool = True) -> Dict[str, object]:
    path = _proxy_file_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = str(text_value or "")
    if content and not content.endswith("\n"):
        content += "\n"
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise TuiConfigError(f"写入代理池文件失败: {exc}") from exc
    lines = [ln.strip() for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if sync_proxies_array:
        cfg = dict(settings.config or {})
        cfg["proxies"] = lines
        cfg["proxy_file"] = _config_path_value(path, settings.config_path.parent)
        settings.config = cfg
        # keep proxy_file path relative-friendly in config
        persist_settings(settings)
    return {
        "path": str(path),
        "exists": True,
        "line_count": len(lines),
        "text": content,
    }




def turnstile_proxy_file_path(settings: Settings) -> Path:
    raw = str(
        (settings.config or {}).get("turnstile_proxy_file")
        or "fixtures/turnstile_proxies.txt"
    ).strip() or "fixtures/turnstile_proxies.txt"
    return _absolute_path(raw, settings.config_path.parent)


def read_turnstile_proxy_pool_text(settings: Settings) -> Dict[str, object]:
    path = turnstile_proxy_file_path(settings)
    text_value = ""
    exists = path.is_file()
    if exists:
        try:
            text_value = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise TuiConfigError(f"读取求解代理池文件失败: {exc}") from exc
    lines = [ln.strip() for ln in text_value.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    return {
        "path": str(path),
        "exists": exists,
        "line_count": len(lines),
        "text": text_value,
    }


def write_turnstile_proxy_pool_text(settings: Settings, text_value: str) -> Dict[str, object]:
    path = turnstile_proxy_file_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = str(text_value or "")
    if content and not content.endswith("\n"):
        content += "\n"
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise TuiConfigError(f"写入求解代理池文件失败: {exc}") from exc
    lines = [ln.strip() for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    cfg = dict(settings.config or {})
    cfg["turnstile_proxy_file"] = _config_path_value(path, settings.config_path.parent)
    settings.config = cfg
    persist_settings(settings)
    return {
        "path": str(path),
        "exists": True,
        "line_count": len(lines),
        "text": content,
    }


def pick_turnstile_proxy(config: Dict[str, object], *, base_dir: Optional[Path] = None) -> str:
    """Pick an independent Turnstile solve proxy if enabled; else empty.

    Relative pool files resolve against base_dir (preferred), then ROOT_DIR.
    """
    cfg = dict(config or {})
    if not _as_bool(cfg.get("turnstile_proxy_enabled")):
        return ""
    mode = str(cfg.get("turnstile_proxy_mode") or "pool").strip().lower()
    if mode not in {"pool", "direct"}:
        mode = "pool"
    if mode == "direct":
        return str(cfg.get("turnstile_proxy") or "").strip()
    # pool mode
    file_raw = str(
        cfg.get("turnstile_proxy_file") or "fixtures/turnstile_proxies.txt"
    ).strip() or "fixtures/turnstile_proxies.txt"
    try:
        path = Path(file_raw).expanduser()
        if not path.is_absolute():
            bases = []
            if base_dir is not None:
                bases.append(Path(base_dir))
            bases.extend([LOCAL_ROOT, ROOT_DIR])
            # Keep first existing candidate; otherwise fall back to preferred base.
            resolved = None
            for base in bases:
                candidate = (Path(base) / path).resolve()
                if candidate.is_file():
                    resolved = candidate
                    break
                if resolved is None:
                    resolved = candidate
            path = resolved if resolved is not None else (LOCAL_ROOT / path).resolve()
        else:
            path = path.resolve()
    except Exception:
        path = LOCAL_FIXTURES_DIR / "turnstile_proxies.txt"
    lines: List[str] = []
    if path.is_file():
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                s = str(line or "").strip()
                if not s or s.startswith("#"):
                    continue
                if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
                    s = s[1:-1].strip()
                if s:
                    lines.append(s)
        except OSError:
            lines = []
    if not lines:
        # fallback to direct field if pool empty
        return str(cfg.get("turnstile_proxy") or "").strip()
    if _as_bool(cfg.get("turnstile_proxy_random", True)):
        return random.choice(lines)
    return lines[0]


def _proxy_pool_lines_from_text(text_value: str) -> List[str]:
    lines: List[str] = []
    for line in str(text_value or "").splitlines():
        s = str(line or "").strip()
        if not s or s.startswith("#"):
            continue
        if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
            s = s[1:-1].strip()
        if s:
            lines.append(s)
    return lines


def _normalize_proxy_url_for_test(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    try:
        from proxy_pool import validate_proxy_line

        normalized, err = validate_proxy_line(text)
        if err:
            return ""
        if normalized:
            return normalized
    except Exception:
        pass
    try:
        from local_proxy_forwarder import normalize_proxy_config, parse_proxy_string

        normalized = normalize_proxy_config(text)
        if normalized:
            return normalized
        parsed = parse_proxy_string(text)
        if parsed is None:
            return text
        auth = ""
        if parsed.username or parsed.password:
            from urllib.parse import quote

            auth = f"{quote(parsed.username or '', safe='')}:{quote(parsed.password or '', safe='')}@"
        return f"http://{auth}{parsed.host}:{parsed.port}"
    except Exception:
        # host:port:user:pass fallback
        if "://" not in text and text.count(":") >= 3:
            parts = text.split(":")
            host, port, user = parts[0], parts[1], parts[2]
            password = ":".join(parts[3:])
            from urllib.parse import quote

            return f"http://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}"
        if "://" not in text:
            return "http://" + text
        return text


def _proxy_display_for_test(raw: str) -> str:
    text = str(raw or "").strip()
    try:
        from local_proxy_forwarder import parse_proxy_string

        up = parse_proxy_string(text)
        if up is None:
            return text
        if up.username:
            return f"{up.host}:{up.port}:{up.username}:***"
        return f"{up.host}:{up.port}"
    except Exception:
        return text


def test_proxy_pool_sample(
    settings: Settings,
    *,
    count: int = 5,
    text_value: Optional[str] = None,
    timeout: float = 12.0,
    probe_url: str = "",
) -> Dict[str, object]:
    """Randomly sample up to N proxies and probe exit IP connectivity."""
    if text_value is None:
        pool_info = read_proxy_pool_text(settings)
        source_text = str(pool_info.get("text") or "")
        source = "file"
        source_path = str(pool_info.get("path") or "")
    else:
        source_text = str(text_value)
        source = "request"
        source_path = ""
    lines = _proxy_pool_lines_from_text(source_text)
    total = len(lines)
    n = max(0, min(int(count or 5), total, 20))
    timeout = max(2.0, float(timeout or 12.0))
    url = str(
        probe_url
        or (settings.config or {}).get("proxy_preflight_url")
        or "https://api.ipify.org?format=json"
    ).strip()
    sample = random.sample(lines, n) if n else []
    results: List[Dict[str, object]] = []
    ok_count = 0
    for idx, raw in enumerate(sample, start=1):
        item: Dict[str, object] = {
            "index": idx,
            "proxy": raw,
            "display": _proxy_display_for_test(raw),
            "ok": False,
            "latency_ms": None,
            "status_code": None,
            "exit_ip": "",
            "body_preview": "",
            "error": "",
        }
        proxy_url = _normalize_proxy_url_for_test(raw)
        if not proxy_url:
            # Distinguish invalid host placeholders (null/none) from parse failure.
            try:
                from proxy_pool import validate_proxy_line

                _norm, verr = validate_proxy_line(raw)
                item["error"] = verr or "无法解析代理"
            except Exception:
                item["error"] = "无法解析代理"
            results.append(item)
            continue
        started = time.monotonic()
        try:
            # Prefer curl_cffi (same stack as registration flow).
            try:
                from curl_cffi import requests as curl_requests

                resp = curl_requests.get(
                    url,
                    proxies={"http": proxy_url, "https": proxy_url},
                    timeout=timeout,
                    impersonate="chrome120",
                )
            except Exception:
                import requests as std_requests

                resp = std_requests.get(
                    url,
                    proxies={"http": proxy_url, "https": proxy_url},
                    timeout=timeout,
                )
            elapsed_ms = int((time.monotonic() - started) * 1000)
            item["latency_ms"] = elapsed_ms
            item["status_code"] = int(getattr(resp, "status_code", 0) or 0)
            body = str(getattr(resp, "text", "") or "").strip()
            item["body_preview"] = body[:120]
            exit_ip = ""
            try:
                payload = resp.json()
                if isinstance(payload, dict):
                    exit_ip = str(payload.get("ip") or payload.get("origin") or "").strip()
            except Exception:
                # plain text IP
                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", body):
                    exit_ip = body
            item["exit_ip"] = exit_ip
            if 200 <= int(item["status_code"] or 0) < 300:
                item["ok"] = True
                ok_count += 1
            else:
                item["error"] = f"HTTP {item['status_code']}"
        except Exception as exc:
            item["latency_ms"] = int((time.monotonic() - started) * 1000)
            item["error"] = str(exc)[:300]
        results.append(item)
    return {
        "source": source,
        "source_path": source_path,
        "probe_url": url,
        "timeout_sec": timeout,
        "total_available": total,
        "tested": len(results),
        "ok": ok_count,
        "fail": max(0, len(results) - ok_count),
        "results": results,
    }


def build_config_center(settings: Settings) -> Dict[str, object]:
    raw = dict(settings.config or {})
    secret_flags = {
        key: bool(str(raw.get(key) or "").strip()) for key in SENSITIVE_CONFIG_KEYS
    }
    public = _settings_to_public_dict(settings)
    pool = read_proxy_pool_text(settings)
    ts_pool = read_turnstile_proxy_pool_text(settings)
    ms_pool = read_ms_mail_pool_text(settings)
    # Do not dump full proxy text into config blob twice; keep top-level pool.
    return {
        **public,
        "secret_flags": secret_flags,
        "proxy_pool": {
            "path": pool["path"],
            "exists": pool["exists"],
            "line_count": pool["line_count"],
            "text": pool["text"],
        },
        "turnstile_proxy_pool": {
            "path": ts_pool["path"],
            "exists": ts_pool["exists"],
            "line_count": ts_pool["line_count"],
            "text": ts_pool["text"],
        },
        "ms_mail_pool": {
            "path": ms_pool["path"],
            "exists": ms_pool["exists"],
            "line_count": ms_pool["line_count"],
            "invalid_count": ms_pool.get("invalid_count", 0),
            "text": ms_pool["text"],
            "format": ms_pool.get("format") or "",
        },
        "fields": {
            "email_provider": str(raw.get("email_provider") or ""),
            "yyds_api_base": str(raw.get("yyds_api_base") or ""),
            # Local-only config center intentionally returns plaintext secrets so
            # operators can inspect values already stored in config.json.
            "yyds_api_key": str(raw.get("yyds_api_key") or ""),
            "yyds_jwt": str(raw.get("yyds_jwt") or ""),
            "yyds_create_spacing_sec": resolve_yyds_create_spacing_sec(raw, strict=False),
            "turnstile_provider": settings.turnstile_provider,
            "turnstile_api_key": str(raw.get("turnstile_api_key") or ""),
            "turnstile_headless": bool(settings.turnstile_headless),
            "local_turnstile_max_workers": resolve_local_turnstile_max_workers(raw, strict=False),
            "local_turnstile_max_inflight": resolve_local_turnstile_max_inflight_cfg(raw, strict=False),
            "submit_workers": max(
                1,
                min(
                    MAX_SUBMIT_WORKERS,
                    int(raw.get("submit_workers") or settings.submit_workers or DEFAULT_SUBMIT_WORKERS),
                ),
            ),
            "turnstile_solve_timeout": _bounded_int(
                raw.get("turnstile_solve_timeout"),
                "Turnstile单次超时",
                minimum=5,
                maximum=600,
                default=90,
            ),
            "mail_code_timeout_sec": _bounded_int(
                raw.get("mail_code_timeout_sec"),
                "邮箱验证码等待",
                minimum=10,
                maximum=180,
                default=40,
            ),
            "turnstile_solve_retries": _bounded_int(
                raw.get("turnstile_solve_retries"),
                "Turnstile重试次数",
                minimum=1,
                maximum=10,
                default=1,
            ),
            "duckmail_api_key": str(raw.get("duckmail_api_key") or ""),
            "cloudflare_api_base": str(raw.get("cloudflare_api_base") or ""),
            "cloudflare_api_key": str(raw.get("cloudflare_api_key") or ""),
            "cloudflare_auth_mode": str(raw.get("cloudflare_auth_mode") or "none"),
            "ms_mail_file": str(raw.get("ms_mail_file") or ""),
            "proxy_mode": "none" if settings.no_proxy else str(settings.proxy_mode or "auto"),
            "embedded_proxy_enabled": _as_bool(raw.get("embedded_proxy_enabled")),
            "egress_mode": encode_egress_mode(
                "none" if settings.no_proxy else str(settings.proxy_mode or "auto"),
                raw.get("embedded_proxy_enabled"),
            ),
            "egress_mode_label": _egress_mode_label(
                encode_egress_mode(
                    "none" if settings.no_proxy else str(settings.proxy_mode or "auto"),
                    raw.get("embedded_proxy_enabled"),
                )
            ),
            "proxy": str(raw.get("proxy") or ""),
            "proxy_file": str(raw.get("proxy_file") or "fixtures/proxies.txt"),
            "proxy_pool_source": resolve_proxy_pool_source(raw, strict=False),
            "proxy_subscription_url": str(raw.get("proxy_subscription_url") or ""),
            "proxy_subscription_urls": _subscription_urls_for_fields(raw),
            "proxy_subscription_local_http": str(raw.get("proxy_subscription_local_http") or ""),
            "embedded_proxy_enabled": _as_bool(raw.get("embedded_proxy_enabled")),
            "embedded_proxy_binary": str(raw.get("embedded_proxy_binary") or ""),
            "embedded_proxy_listen_host": str(raw.get("embedded_proxy_listen_host") or "127.0.0.1") or "127.0.0.1",
            "embedded_proxy_base_port": _bounded_int(
                raw.get("embedded_proxy_base_port"),
                "内嵌代理起始端口",
                minimum=1024,
                maximum=65000,
                default=28000,
            ),
            "embedded_proxy_max_nodes": _bounded_int(
                raw.get("embedded_proxy_max_nodes"),
                "内嵌代理最大节点数（0=不限制）",
                minimum=0,
                maximum=10000,
                default=50,
            ),
            "embedded_proxy_probe_host": str(raw.get("embedded_proxy_probe_host") or "accounts.x.ai") or "accounts.x.ai",
            "embedded_proxy_probe_port": _bounded_int(
                raw.get("embedded_proxy_probe_port"),
                "内嵌代理探测端口",
                minimum=1,
                maximum=65535,
                default=443,
            ),
            "embedded_proxy_probe_timeout_sec": float(raw.get("embedded_proxy_probe_timeout_sec") or 5),
            "embedded_proxy_max_node_retries": _bounded_int(
                raw.get("embedded_proxy_max_node_retries"),
                "内嵌代理节点重试次数",
                minimum=0,
                maximum=20,
                default=3,
            ),
            "proxy_random": _as_bool(raw.get("proxy_random")),
            "proxy_rotate_session": _as_bool(raw.get("proxy_rotate_session")),
            "turnstile_proxy_enabled": _as_bool(raw.get("turnstile_proxy_enabled")),
            "turnstile_proxy_mode": str(raw.get("turnstile_proxy_mode") or "pool") or "pool",
            "turnstile_proxy": str(raw.get("turnstile_proxy") or ""),
            "turnstile_proxy_file": str(
                raw.get("turnstile_proxy_file") or "fixtures/turnstile_proxies.txt"
            ),
            "turnstile_proxy_random": _as_bool(raw.get("turnstile_proxy_random", True)),
            "local_proxy_port": int(raw.get("local_proxy_port") or 17890),
            "xai_oauth_output_dir": str(settings.output_dir),
            "cpa_api_url": str(raw.get("cpa_api_url") or ""),
            "cpa_api_key": str(raw.get("cpa_api_key") or ""),
            "cpa_auto_upload": _as_bool(raw.get("cpa_auto_upload")),
            "cpa_use_local_name": _as_bool(raw.get("cpa_use_local_name", True)),
            "cpa_skip_duplicates": _as_bool(raw.get("cpa_skip_duplicates", True)),
        },
    }


class BatchService:
    """Process-local single-batch controller for WebUI (and other UIs)."""

    def __init__(
        self,
        *,
        config_path: Optional[Path] = None,
        root_dir: Optional[Path] = None,
    ) -> None:
        self.root_dir = Path(root_dir or ROOT_DIR)
        self.config_path = Path(config_path or DEFAULT_CONFIG_PATH)
        self.settings = self._load_settings()
        self._runner: Optional[BatchRunner] = None
        self._listeners: List[Callable[[str], None]] = []
        self._log_cursor = 0
        self._lock = threading.Lock()
        self._embedded_proxy_manager = None
        self._embedded_proxy_last: Dict[str, object] = {"enabled": False}
        self._embedded_proxy_boot: Dict[str, object] = {
            "phase": "idle",  # idle|starting|ready|error|disabled
            "message": "",
            "started_at": 0.0,
            "finished_at": 0.0,
            "auto": False,
        }
        self._embedded_proxy_boot_lock = threading.Lock()
        self._embedded_proxy_boot_thread: Optional[threading.Thread] = None

    def _load_settings(self) -> Settings:
        config = _read_config(self.config_path) if self.config_path.is_file() else {}
        settings = Settings(
            config_path=self.config_path,
            count=_positive_int(config.get("register_count", 1), "注册数量", MAX_COUNT),
            workers=_positive_int(config.get("concurrent_workers", 1), "并发数", MAX_WORKERS),
            output_dir=_absolute_path(
                str(config.get("xai_oauth_output_dir") or DEFAULT_OUTPUT_DIR),
                self.config_path.parent,
            ),
            run_mode=_normalize_run_mode(config.get("tui_run_mode") or DEFAULT_RUN_MODE),
            proxy_mode=str(config.get("tui_proxy_mode") or "auto"),
            no_proxy=str(config.get("tui_proxy_mode") or "auto").strip().lower() == "none",
            turnstile_provider=_normalize_turnstile_provider(config.get("turnstile_provider") or "capsolver"),
            turnstile_headless=_as_bool(config.get("turnstile_headless")),
            submit_workers=max(
                1,
                min(
                    MAX_SUBMIT_WORKERS,
                    _positive_int(
                        config.get("submit_workers", DEFAULT_SUBMIT_WORKERS),
                        "提交并发",
                        MAX_SUBMIT_WORKERS,
                    ),
                ),
            ),
            sso_convert_retries=_bounded_int(
                config.get("tui_sso_convert_retries"),
                "SSO转换重试",
                minimum=1,
                maximum=MAX_SSO_CONVERT_RETRIES,
                default=DEFAULT_SSO_CONVERT_RETRIES,
            ),
            sso_convert_cooldown=_bounded_int(
                config.get("tui_sso_convert_cooldown"),
                "SSO转换冷却",
                minimum=0,
                maximum=MAX_SSO_CONVERT_COOLDOWN,
                default=DEFAULT_SSO_CONVERT_COOLDOWN,
            ),
            config=config,
        )
        _load_runtime_fields(settings)
        return settings

    def get_settings(self) -> Settings:
        return self.settings

    def public_settings(self) -> Dict[str, object]:
        return _settings_to_public_dict(self.settings)

    def reload_settings(self) -> Settings:
        self.settings = self._load_settings()
        return self.settings

    def update_settings_from_mapping(self, data: Dict[str, object], *, persist: bool) -> Settings:
        data = dict(data or {})
        if "count" in data:
            self.settings.count = _positive_int(data.get("count"), "注册数量", MAX_COUNT)
        if "target_mode" in data or "run_target_mode" in data:
            self.settings.target_mode = _normalize_target_mode(data.get("target_mode", data.get("run_target_mode")))
        if "target_success" in data:
            self.settings.target_success = _bounded_int(data.get("target_success"), "成功目标", minimum=0, maximum=MAX_COUNT, default=0)
        if "continuous_max_runtime_min" in data:
            self.settings.continuous_max_runtime_min = _bounded_int(data.get("continuous_max_runtime_min"), "持续运行最长分钟", minimum=0, maximum=10080, default=0)
        if "workers" in data:
            self.settings.workers = _positive_int(data.get("workers"), "并发数", MAX_WORKERS)
        if "output_dir" in data and str(data.get("output_dir") or "").strip():
            self.settings.output_dir = _absolute_path(
                str(data.get("output_dir")), self.config_path.parent
            )
        if "run_mode" in data:
            self.settings.run_mode = _normalize_run_mode(data.get("run_mode"))
        if "egress_mode" in data and str(data.get("egress_mode") or "").strip():
            cfg = dict(self.settings.config or {})
            mode = apply_egress_mode_to_config(cfg, data.get("egress_mode"))
            proxy_mode, embedded = decode_egress_mode(mode)
            self.settings.proxy_mode = proxy_mode
            self.settings.no_proxy = proxy_mode == "none"
            self.settings.config = cfg
        elif "proxy_mode" in data or "embedded_proxy_enabled" in data:
            cfg = dict(self.settings.config or {})
            if "proxy_mode" in data:
                mode = _normalize_proxy_mode(data.get("proxy_mode") or "auto")
                self.settings.proxy_mode = mode
                self.settings.no_proxy = mode == "none"
                cfg["proxy_mode"] = mode
                cfg["tui_proxy_mode"] = mode
            if "embedded_proxy_enabled" in data:
                cfg["embedded_proxy_enabled"] = _as_bool(data.get("embedded_proxy_enabled"))
            self.settings.config = cfg
        if "turnstile_provider" in data:
            self.settings.turnstile_provider = _normalize_turnstile_provider(data.get("turnstile_provider"))
        if "turnstile_headless" in data:
            self.settings.turnstile_headless = _as_bool(data.get("turnstile_headless"))
        cfg_speed = dict(self.settings.config or {})
        speed_touched = False
        if "local_turnstile_max_workers" in data:
            cfg_speed["local_turnstile_max_workers"] = resolve_local_turnstile_max_workers(
                {"local_turnstile_max_workers": data.get("local_turnstile_max_workers")},
                strict=True,
            )
            speed_touched = True
        if "local_turnstile_max_inflight" in data:
            cfg_speed["local_turnstile_max_inflight"] = resolve_local_turnstile_max_inflight_cfg(
                {"local_turnstile_max_inflight": data.get("local_turnstile_max_inflight")},
                strict=True,
            )
            speed_touched = True
        if "submit_workers" in data:
            sw = _positive_int(data.get("submit_workers"), "提交并发", MAX_SUBMIT_WORKERS)
            self.settings.submit_workers = sw
            cfg_speed["submit_workers"] = int(sw)
            speed_touched = True
        if "turnstile_solve_timeout" in data:
            cfg_speed["turnstile_solve_timeout"] = _bounded_int(
                data.get("turnstile_solve_timeout"),
                "Turnstile单次超时",
                minimum=5,
                maximum=600,
                default=int(cfg_speed.get("turnstile_solve_timeout") or 90),
            )
            speed_touched = True
        if "turnstile_solve_retries" in data:
            cfg_speed["turnstile_solve_retries"] = _bounded_int(
                data.get("turnstile_solve_retries"),
                "Turnstile重试次数",
                minimum=1,
                maximum=10,
                default=int(cfg_speed.get("turnstile_solve_retries") or 1),
            )
            speed_touched = True
        if "mail_code_timeout_sec" in data:
            cfg_speed["mail_code_timeout_sec"] = _bounded_int(
                data.get("mail_code_timeout_sec"),
                "邮箱验证码等待",
                minimum=10,
                maximum=180,
                default=int(cfg_speed.get("mail_code_timeout_sec") or 40),
            )
            speed_touched = True
        if speed_touched:
            self.settings.config = cfg_speed
        if "sso_convert_retries" in data:
            self.settings.sso_convert_retries = _bounded_int(
                data.get("sso_convert_retries"),
                "SSO转换重试",
                minimum=1,
                maximum=MAX_SSO_CONVERT_RETRIES,
                default=DEFAULT_SSO_CONVERT_RETRIES,
            )
        if "sso_convert_cooldown" in data:
            self.settings.sso_convert_cooldown = _bounded_int(
                data.get("sso_convert_cooldown"),
                "SSO转换冷却",
                minimum=0,
                maximum=MAX_SSO_CONVERT_COOLDOWN,
                default=DEFAULT_SSO_CONVERT_COOLDOWN,
            )
        # Optional nested config keys (non-secret runtime toggles only unless persist raw provided)
        cfg_patch = data.get("config")
        if isinstance(cfg_patch, dict):
            merged = dict(self.settings.config or {})
            for key, value in cfg_patch.items():
                if str(value) == "***":
                    continue
                merged[key] = value
            self.settings.config = merged
        if persist:
            persist_settings(self.settings)
            # re-read to keep memory aligned with disk
            self.settings.config = _read_config(self.settings.config_path)
        return self.settings


    def get_config_center(self) -> Dict[str, object]:
        return build_config_center(self.settings)

    def update_config_center(self, data: Dict[str, object]) -> Dict[str, object]:
        """Update runtime + secret-capable config fields from the config-center page."""
        data = dict(data or {})
        fields = data.get("fields") if isinstance(data.get("fields"), dict) else data
        fields = dict(fields or {})

        # Runtime-facing fields.
        if "egress_mode" in fields and str(fields.get("egress_mode") or "").strip():
            fields = dict(fields)
            mode = normalize_egress_mode(fields.get("egress_mode"))
            if not mode:
                raise TuiConfigError("出口模式无效，可选: nodes/http/hybrid/direct/auto/off")
            proxy_mode, embedded = decode_egress_mode(mode)
            self.settings.proxy_mode = proxy_mode
            self.settings.no_proxy = proxy_mode == "none"
            fields["proxy_mode"] = proxy_mode
            fields["embedded_proxy_enabled"] = bool(embedded)
            fields["egress_mode"] = mode
        elif "proxy_mode" in fields:
            mode = _normalize_proxy_mode(fields.get("proxy_mode") or "auto")
            if mode not in PROXY_MODE_LABELS:
                raise TuiConfigError("代理模式无效，可选: auto/none/direct/pool")
            self.settings.proxy_mode = mode
            self.settings.no_proxy = mode == "none"
            # Keep both keys in sync; older UIs / files may still read proxy_mode.
            fields = dict(fields)
            fields["proxy_mode"] = mode
        if "proxy_pool_source" in fields:
            raw_source = str(fields.get("proxy_pool_source") or "").strip().lower()
            if raw_source not in {
                PROXY_POOL_SOURCE_MANUAL,
                PROXY_POOL_SOURCE_SUBSCRIPTION,
                "file",
                "pool",
                "text",
                "hand",
                "manual_pool",
                "sub",
                "subscribe",
                "url",
                "import",
            }:
                raise TuiConfigError("注册代理池来源无效，可选: manual/subscription")
            fields["proxy_pool_source"] = normalize_proxy_pool_source(raw_source)
        if "turnstile_proxy_mode" in fields:
            ts_mode = str(fields.get("turnstile_proxy_mode") or "pool").strip().lower()
            if ts_mode not in {"pool", "direct"}:
                raise TuiConfigError("求解代理模式无效，可选: pool/direct")
            fields["turnstile_proxy_mode"] = ts_mode
        if "turnstile_provider" in fields:
            self.settings.turnstile_provider = _normalize_turnstile_provider(fields.get("turnstile_provider"))
        if "turnstile_headless" in fields:
            self.settings.turnstile_headless = _as_bool(fields.get("turnstile_headless"))
        if "xai_oauth_output_dir" in fields and str(fields.get("xai_oauth_output_dir") or "").strip():
            self.settings.output_dir = _absolute_path(
                str(fields.get("xai_oauth_output_dir")), self.config_path.parent
            )

        cfg = dict(self.settings.config or {})
        plain_keys = [
            "email_provider",
            "yyds_api_base",
            "cloudflare_api_base",
            "cloudflare_auth_mode",
            "ms_mail_file",
            "proxy",
            "proxy_file",
            "proxy_pool_source",
            "proxy_subscription_local_http",
            "embedded_proxy_binary",
            "embedded_proxy_listen_host",
            "embedded_proxy_probe_host",
            "turnstile_proxy",
            "turnstile_proxy_file",
            "turnstile_proxy_mode",
            "cpa_api_url",
            "defaultDomains",
            "user_agent",
        ]
        for key in plain_keys:
            if key in fields:
                cfg[key] = str(fields.get(key) or "").strip()

        # Multi-URL subscription list (textarea / array). Keep legacy single field in sync.
        if "proxy_subscription_urls" in fields or "proxy_subscription_url" in fields:
            if "proxy_subscription_urls" in fields:
                urls_value = fields.get("proxy_subscription_urls")
            else:
                urls_value = fields.get("proxy_subscription_url")
            _apply_subscription_urls_to_config(cfg, urls_value)

        bool_keys = [
            "proxy_random",
            "proxy_rotate_session",
            "cpa_auto_upload",
            "cpa_use_local_name",
            "cpa_skip_duplicates",
            "embedded_proxy_enabled",
            "turnstile_proxy_enabled",
            "turnstile_proxy_random",
        ]
        for key in bool_keys:
            if key in fields:
                cfg[key] = _as_bool(fields.get(key))

        if "local_proxy_port" in fields:
            cfg["local_proxy_port"] = _bounded_int(
                fields.get("local_proxy_port"),
                "本地代理端口",
                minimum=1,
                maximum=65535,
                default=int(cfg.get("local_proxy_port") or 17890),
            )

        if "embedded_proxy_base_port" in fields:
            cfg["embedded_proxy_base_port"] = _bounded_int(
                fields.get("embedded_proxy_base_port"),
                "内嵌代理起始端口",
                minimum=1024,
                maximum=65000,
                default=int(cfg.get("embedded_proxy_base_port") or 28000),
            )
        if "embedded_proxy_max_nodes" in fields:
            cfg["embedded_proxy_max_nodes"] = _bounded_int(
                fields.get("embedded_proxy_max_nodes"),
                "内嵌代理最大节点数（0=不限制）",
                minimum=0,
                maximum=10000,
                default=_optional_int(cfg.get("embedded_proxy_max_nodes"), default=50),
            )
        if "embedded_proxy_probe_port" in fields:
            cfg["embedded_proxy_probe_port"] = _bounded_int(
                fields.get("embedded_proxy_probe_port"),
                "内嵌代理探测端口",
                minimum=1,
                maximum=65535,
                default=int(cfg.get("embedded_proxy_probe_port") or 443),
            )
        if "embedded_proxy_probe_timeout_sec" in fields:
            try:
                timeout_sec = float(fields.get("embedded_proxy_probe_timeout_sec"))
            except (TypeError, ValueError) as exc:
                raise TuiConfigError("内嵌代理探测超时必须是数字（秒）") from exc
            if timeout_sec <= 0 or timeout_sec > 120:
                raise TuiConfigError("内嵌代理探测超时必须介于 0 到 120 秒之间（不含 0）")
            cfg["embedded_proxy_probe_timeout_sec"] = timeout_sec
        if "embedded_proxy_max_node_retries" in fields:
            cfg["embedded_proxy_max_node_retries"] = _bounded_int(
                fields.get("embedded_proxy_max_node_retries"),
                "内嵌代理节点重试次数",
                minimum=0,
                maximum=20,
                default=int(cfg.get("embedded_proxy_max_node_retries") or 3),
            )

        if "local_turnstile_max_workers" in fields:
            cfg["local_turnstile_max_workers"] = resolve_local_turnstile_max_workers(
                {"local_turnstile_max_workers": fields.get("local_turnstile_max_workers")},
                strict=True,
            )
        if "local_turnstile_max_inflight" in fields:
            cfg["local_turnstile_max_inflight"] = resolve_local_turnstile_max_inflight_cfg(
                {"local_turnstile_max_inflight": fields.get("local_turnstile_max_inflight")},
                strict=True,
            )

        if "turnstile_solve_timeout" in fields:
            cfg["turnstile_solve_timeout"] = _bounded_int(
                fields.get("turnstile_solve_timeout"),
                "Turnstile单次超时",
                minimum=5,
                maximum=600,
                default=int(cfg.get("turnstile_solve_timeout") or 90),
            )
        if "mail_code_timeout_sec" in fields:
            cfg["mail_code_timeout_sec"] = _bounded_int(
                fields.get("mail_code_timeout_sec"),
                "邮箱验证码等待",
                minimum=10,
                maximum=180,
                default=int(cfg.get("mail_code_timeout_sec") or 40),
            )
        if "turnstile_solve_retries" in fields:
            cfg["turnstile_solve_retries"] = _bounded_int(
                fields.get("turnstile_solve_retries"),
                "Turnstile重试次数",
                minimum=1,
                maximum=10,
                default=int(cfg.get("turnstile_solve_retries") or 1),
            )
        if "submit_workers" in fields:
            self.settings.submit_workers = _positive_int(
                fields.get("submit_workers"),
                "提交并发",
                MAX_SUBMIT_WORKERS,
            )
            cfg["submit_workers"] = int(self.settings.submit_workers)

        if "yyds_create_spacing_sec" in fields:
            cfg["yyds_create_spacing_sec"] = resolve_yyds_create_spacing_sec(
                {"yyds_create_spacing_sec": fields.get("yyds_create_spacing_sec")},
                strict=True,
            )

        # Secrets from config-center are plaintext-editable.
        # - non-empty value: overwrite
        # - "***": keep existing (compat)
        # - empty string: clear
        for key in SENSITIVE_CONFIG_KEYS:
            if key not in fields:
                continue
            value = fields.get(key)
            if value is None:
                continue
            text_value = str(value)
            if text_value.strip() == "***":
                continue
            cfg[key] = text_value.strip()

        # Canonical proxy mode keys for disk consumers.
        mode_now = "none" if self.settings.no_proxy else str(self.settings.proxy_mode or "auto")
        cfg["tui_proxy_mode"] = mode_now
        cfg["proxy_mode"] = mode_now

        self.settings.config = cfg
        persist_settings(self.settings)
        self.settings.config = _read_config(self.settings.config_path)
        _load_runtime_fields(self.settings)

        # Optional proxy pool text write in same request.
        # Only allowed when pool source is manual — subscription mode owns the pool via import.
        if "proxy_pool_text" in data:
            source_now = resolve_proxy_pool_source(self.settings.config or {}, strict=False)
            if source_now == PROXY_POOL_SOURCE_MANUAL:
                write_proxy_pool_text(
                    self.settings,
                    str(data.get("proxy_pool_text") or ""),
                    sync_proxies_array=True,
                )
                self.settings.config = _read_config(self.settings.config_path)
                _load_runtime_fields(self.settings)
            # subscription 模式下忽略表单里的 pool 文本，避免误覆盖订阅导入结果
        if "turnstile_proxy_pool_text" in data:
            # Always materialize the dedicated solve-proxy pool file when the
            # config-center payload includes the field (even if empty).
            write_turnstile_proxy_pool_text(self.settings, str(data.get("turnstile_proxy_pool_text") or ""))
            self.settings.config = _read_config(self.settings.config_path)
            _load_runtime_fields(self.settings)
        if "ms_mail_pool_text" in data:
            write_ms_mail_pool_text(self.settings, str(data.get("ms_mail_pool_text") or ""))
            self.settings.config = _read_config(self.settings.config_path)
            _load_runtime_fields(self.settings)
        # Ensure default turnstile proxy file path exists in config once enabled/configured.
        cfg_now = dict(self.settings.config or {})
        if any(k in cfg_now for k in (
            "turnstile_proxy_enabled",
            "turnstile_proxy_mode",
            "turnstile_proxy",
            "turnstile_proxy_file",
            "turnstile_proxy_random",
        )) and not str(cfg_now.get("turnstile_proxy_file") or "").strip():
            cfg_now["turnstile_proxy_file"] = "fixtures/turnstile_proxies.txt"
            self.settings.config = cfg_now
            persist_settings(self.settings)
            self.settings.config = _read_config(self.settings.config_path)
            _load_runtime_fields(self.settings)
        return self.get_config_center()

    def list_credentials(self, *, page: int = 1, page_size: int = 1000) -> Dict[str, object]:
        """Return paginated plaintext credential lines from the OAuth output directory."""
        return list_credential_pairs(self.settings.output_dir, page=page, page_size=page_size)

    def export_dir(self) -> Path:
        return resolve_export_dir(self.config_path.parent)

    def export_credentials_page(self, *, page: int = 1, page_size: int = 1000) -> Dict[str, object]:
        """Export one credentials page to exports/grok+timestamp.txt, then delete local pairs."""
        return export_credential_page_and_delete(
            self.settings.output_dir,
            page=page,
            page_size=page_size,
            export_dir=self.export_dir(),
        )

    def list_export_files(self) -> Dict[str, object]:
        return list_export_files(self.config_path.parent)

    def delete_export_file(self, name: str) -> Dict[str, object]:
        return delete_export_file(self.config_path.parent, name)

    def resolve_export_file(self, name: str) -> Path:
        return resolve_export_file(self.config_path.parent, name)

    def check_cpa_connection(self, payload: Optional[Dict[str, object]] = None) -> Dict[str, object]:
        """Test CPA management endpoint connectivity (override fields optional)."""
        import cpa_push

        cfg = dict(self.settings.config or {})
        override = dict(payload or {})
        base_url = str(override.get("cpa_api_url") or cfg.get("cpa_api_url") or "").strip()
        api_key = str(override.get("cpa_api_key") or cfg.get("cpa_api_key") or "").strip()
        if str(api_key).strip() == "***":
            api_key = str(cfg.get("cpa_api_key") or "").strip()
        try:
            return cpa_push.check_cpa_connection(base_url, api_key)
        except Exception as exc:
            raise TuiConfigError(str(exc)) from exc

    def push_cpa_credentials(self, payload: Optional[Dict[str, object]] = None) -> Dict[str, object]:
        """Push local OAuth credentials from output_dir to CPA."""
        import cpa_push

        cfg = dict(self.settings.config or {})
        data = dict(payload or {})
        base_url = str(data.get("cpa_api_url") or cfg.get("cpa_api_url") or "").strip()
        api_key = str(data.get("cpa_api_key") or cfg.get("cpa_api_key") or "").strip()
        if str(api_key).strip() == "***":
            api_key = str(cfg.get("cpa_api_key") or "").strip()
        use_local_name = data.get("cpa_use_local_name")
        if use_local_name is None:
            use_local_name = cfg.get("cpa_use_local_name", True)
        skip_duplicates = data.get("cpa_skip_duplicates")
        if skip_duplicates is None:
            skip_duplicates = cfg.get("cpa_skip_duplicates", True)
        names = data.get("names")
        if names is not None and not isinstance(names, (list, tuple, set)):
            raise TuiConfigError("names 必须是数组")
        logs: list[str] = []

        def _log(msg: str) -> None:
            logs.append(str(msg))

        try:
            result = cpa_push.push_local_credentials(
                base_url=base_url,
                api_key=api_key,
                output_dir=self.settings.output_dir,
                use_local_name=bool(use_local_name),
                names=names,
                skip_duplicates=bool(skip_duplicates),
                log=_log,
            )
        except Exception as exc:
            raise TuiConfigError(str(exc)) from exc
        result = dict(result)
        result["logs"] = logs
        result["output_dir"] = str(self.settings.output_dir)
        return result

    def get_proxy_pool(self) -> Dict[str, object]:
        data = read_proxy_pool_text(self.settings)
        data["proxy_pool_source"] = resolve_proxy_pool_source(self.settings.config or {}, strict=False)
        return data

    def set_proxy_pool(self, text_value: str) -> Dict[str, object]:
        require_proxy_pool_source(
            self.settings,
            PROXY_POOL_SOURCE_MANUAL,
            action="手动保存注册代理池",
        )
        result = write_proxy_pool_text(self.settings, text_value, sync_proxies_array=True)
        self.settings.config = _read_config(self.settings.config_path)
        _load_runtime_fields(self.settings)
        result["proxy_pool_source"] = PROXY_POOL_SOURCE_MANUAL
        return result

    def export_embedded_nodes_to_proxy_pool(
        self,
        *,
        healthy_only: bool = True,
        switch_to_manual: bool = True,
        set_proxy_mode: str = "pool",
        keep_embedded_enabled: bool = True,
    ) -> Dict[str, object]:
        """Export running embedded local HTTP endpoints into proxies.txt.

        This is a convenience bridge between the node pool UI and the HTTP proxy pool.
        """
        status = self.get_embedded_proxy_status() or {}
        if not status.get("running"):
            raise TuiConfigError("节点池未运行。请先在右侧启动/重载内嵌 mihomo")
        nodes = list(status.get("nodes") or [])
        if not nodes and self._embedded_proxy_manager is not None:
            try:
                nodes = list((self._embedded_proxy_manager.status() or {}).get("nodes") or [])
            except Exception:
                nodes = []
        lines: List[str] = []
        seen = set()
        for node in nodes:
            if not isinstance(node, dict):
                continue
            if healthy_only and not bool(node.get("healthy")):
                continue
            local_http = str(node.get("local_http") or "").strip()
            if not local_http:
                port = node.get("local_port") or node.get("port")
                host = str(node.get("listen_host") or node.get("host") or "127.0.0.1").strip() or "127.0.0.1"
                if port:
                    local_http = f"http://{host}:{int(port)}"
            if not local_http:
                continue
            if not local_http.startswith("http://") and not local_http.startswith("https://"):
                local_http = "http://" + local_http.lstrip("/")
            key = local_http.lower()
            if key in seen:
                continue
            seen.add(key)
            name = str(node.get("name") or node.get("id") or "").strip()
            if name:
                lines.append(f"# {name}")
            lines.append(local_http)
        if not lines:
            kind = "健康" if healthy_only else "可用"
            raise TuiConfigError(f"没有可导出的{kind}节点本地口（可先点「探测健康」）")

        header = [
            "# exported from embedded mihomo node pool",
            f"# healthy_only={bool(healthy_only)} count={sum(1 for x in lines if not x.startswith('#'))}",
        ]
        content = "\n".join(header + lines) + "\n"

        cfg = dict(self.settings.config or {})
        if switch_to_manual:
            cfg["proxy_pool_source"] = PROXY_POOL_SOURCE_MANUAL
        if keep_embedded_enabled:
            cfg["embedded_proxy_enabled"] = True
        mode = str(set_proxy_mode or "").strip().lower()
        if mode in PROXY_MODE_LABELS:
            self.settings.proxy_mode = mode
            self.settings.no_proxy = mode == "none"
            cfg["tui_proxy_mode"] = mode
            cfg["proxy_mode"] = mode
        self.settings.config = cfg
        # force source check path for write
        written = write_proxy_pool_text(self.settings, content, sync_proxies_array=True)
        cfg = dict(self.settings.config or {})
        if switch_to_manual:
            cfg["proxy_pool_source"] = PROXY_POOL_SOURCE_MANUAL
        if keep_embedded_enabled:
            cfg["embedded_proxy_enabled"] = True
        if mode in PROXY_MODE_LABELS:
            cfg["tui_proxy_mode"] = mode
            cfg["proxy_mode"] = mode
        self.settings.config = cfg
        persist_settings(self.settings)
        self.settings.config = _read_config(self.settings.config_path)
        _load_runtime_fields(self.settings)
        exported = sum(1 for x in lines if x and not x.startswith("#"))
        return {
            "ok": True,
            "exported_count": exported,
            "healthy_only": bool(healthy_only),
            "proxy_pool_source": resolve_proxy_pool_source(self.settings.config or {}, strict=False),
            "proxy_mode": "none" if self.settings.no_proxy else str(self.settings.proxy_mode or "auto"),
            "embedded_proxy_enabled": _as_bool((self.settings.config or {}).get("embedded_proxy_enabled")),
            "proxy_pool": written,
            "message": f"已导出 {exported} 条节点本地口到代理池",
        }

    def import_clean_embedded_proxy_list(self, *, write_pool: bool = False) -> Dict[str, object]:
        """Load verified clean embedded local endpoints for the proxy pool editor."""
        candidates = [
            self.config_path.parent / "fixtures" / "proxies.clean_embedded.txt",
            LOCAL_FIXTURES_DIR / "proxies.clean_embedded.txt",
            Path("/tmp/xai_good_proxies.txt"),
            # Compatibility fallback for older local layouts.
            self.root_dir / "proxies.clean_embedded.txt",
        ]
        path = next((p for p in candidates if p.is_file()), None)
        if path is None:
            raise TuiConfigError(
                "未找到 clean 本地口文件（.local/fixtures/proxies.clean_embedded.txt 或 /tmp/xai_good_proxies.txt）"
            )
        try:
            text_value = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise TuiConfigError(f"读取 clean 本地口失败: {exc}") from exc
        lines = [
            ln.strip()
            for ln in text_value.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        result = {
            "ok": True,
            "path": str(path),
            "exists": True,
            "line_count": len(lines),
            "text": text_value if text_value.endswith("\n") or not text_value else text_value + "\n",
            "written": False,
        }
        if write_pool:
            require_proxy_pool_source(
                self.settings,
                PROXY_POOL_SOURCE_MANUAL,
                action="导入 clean 本地口到注册代理池",
            )
            written = write_proxy_pool_text(self.settings, result["text"], sync_proxies_array=True)
            self.settings.config = _read_config(self.settings.config_path)
            _load_runtime_fields(self.settings)
            result["written"] = True
            result["proxy_pool"] = written
            result["line_count"] = written.get("line_count", result["line_count"])
        return result


    def get_ms_mail_pool(self) -> Dict[str, object]:
        return read_ms_mail_pool_text(self.settings)

    def set_ms_mail_pool(self, text_value: str) -> Dict[str, object]:
        result = write_ms_mail_pool_text(self.settings, text_value)
        self.settings.config = _read_config(self.settings.config_path)
        _load_runtime_fields(self.settings)
        return result

    def get_turnstile_proxy_pool(self) -> Dict[str, object]:
        return read_turnstile_proxy_pool_text(self.settings)

    def set_turnstile_proxy_pool(self, text_value: str) -> Dict[str, object]:
        result = write_turnstile_proxy_pool_text(self.settings, text_value)
        self.settings.config = _read_config(self.settings.config_path)
        _load_runtime_fields(self.settings)
        return result

    def test_turnstile_proxy_pool(
        self, *, count: int = 5, text_value: Optional[str] = None, timeout: float = 12.0
    ) -> Dict[str, object]:
        if text_value is None:
            text_value = str(read_turnstile_proxy_pool_text(self.settings).get("text") or "")
        return test_proxy_pool_sample(
            self.settings,
            count=count,
            text_value=text_value,
            timeout=timeout,
        )


    def import_proxy_subscription(
        self,
        *,
        url: str = "",
        urls: object = None,
        write_pool: bool = True,
        timeout: float = 20.0,
        use_local_http_if_empty: bool = True,
        local_http: str = "",
    ) -> Dict[str, object]:
        """Fetch one or more subscription URLs and import usable HTTP proxies into the pool file."""
        from proxy_subscription import import_proxy_subscriptions, normalize_subscription_urls

        require_proxy_pool_source(
            self.settings,
            PROXY_POOL_SOURCE_SUBSCRIPTION,
            action="拉取订阅写入注册代理池",
        )

        cfg = dict(self.settings.config or {})
        url_list = normalize_subscription_urls(urls if urls is not None else None, url)
        if not url_list:
            url_list = _subscription_urls_for_fields(cfg)
        if not url_list:
            raise TuiConfigError("请先填写订阅链接（支持多行多个 URL）")
        try:
            result = import_proxy_subscriptions(url_list, timeout=timeout)
        except ValueError as exc:
            raise TuiConfigError(str(exc)) from exc
        data = result.to_dict()
        _apply_subscription_urls_to_config(cfg, url_list)
        cfg["proxy_pool_source"] = PROXY_POOL_SOURCE_SUBSCRIPTION
        # 若启用内嵌 mihomo 且主要是可内嵌协议，弱化“只能走 Clash”的通用警告。
        schemes = dict(data.get("scheme_counts") or {})
        embedded_candidate_n = (
            int(schemes.get("vless") or 0)
            + int(schemes.get("hysteria2") or 0)
            + int(schemes.get("hy2") or 0)
            + int(schemes.get("anytls") or 0)
            + int(schemes.get("trojan") or 0)
        )
        if _as_bool(cfg.get("embedded_proxy_enabled")):
            if embedded_candidate_n > 0 and not result.usable_pool_lines:
                filtered = []
                for w in list(data.get("warnings") or []):
                    if "需要先导入本地 Clash" in str(w) or "没有可直接用于注册机的 HTTP" in str(w):
                        continue
                    filtered.append(w)
                data["warnings"] = filtered

        local_http = str(local_http or cfg.get("proxy_subscription_local_http") or "").strip()
        if local_http:
            cfg["proxy_subscription_local_http"] = local_http
        pool_text_lines = list(result.pool_lines)
        applied_local = False
        embedded_enabled = _as_bool(cfg.get("embedded_proxy_enabled"))
        vless_count = int(schemes.get("vless") or 0)
        # 内嵌 mihomo 开启时，可内嵌协议订阅走内嵌池，不应再强行回退本地 Clash 口。
        if (
            use_local_http_if_empty
            and not result.usable_pool_lines
            and local_http
            and not (embedded_enabled and embedded_candidate_n > 0)
        ):
            pool_text_lines.append(local_http)
            applied_local = True
            data.setdefault("warnings", []).append(
                f"订阅无直连 HTTP 节点，已写入本地客户端入口: {local_http}"
            )
            self.settings.proxy_mode = "direct"
            self.settings.no_proxy = False
            cfg["proxy"] = local_http
        elif not result.usable_pool_lines and embedded_enabled and embedded_candidate_n > 0:
            data.setdefault("warnings", []).append(
                f"订阅含 {embedded_candidate_n} 个可内嵌节点（VLESS/Hysteria2/AnyTLS/Trojan）。"
                "HTTP 代理池不可直接使用它们；请到左列“内嵌 mihomo”先「拉取订阅节点」再「启动/重载」。"
            )
            data["vless_for_embedded"] = True
            data["vless_count"] = vless_count
            data["embedded_candidate_count"] = embedded_candidate_n
        elif result.usable_pool_lines:
            # HTTP/SOCKS 可入池时，默认切到代理池模式，避免用户还要手动改开关。
            self.settings.proxy_mode = "pool"
            self.settings.no_proxy = False

        if write_pool:
            content = chr(10).join(pool_text_lines) + chr(10)
            # import 前强制保持 subscription 来源
            self.settings.config = cfg
            written = write_proxy_pool_text(
                self.settings,
                content,
                sync_proxies_array=True,
            )
            cfg = dict(self.settings.config or {})
            _apply_subscription_urls_to_config(cfg, url_list)
            cfg["proxy_pool_source"] = PROXY_POOL_SOURCE_SUBSCRIPTION
            if local_http:
                cfg["proxy_subscription_local_http"] = local_http
            if applied_local:
                cfg["proxy"] = local_http
                cfg["tui_proxy_mode"] = "direct"
            elif result.usable_pool_lines:
                cfg["tui_proxy_mode"] = "pool"
            self.settings.config = cfg
            persist_settings(self.settings)
            self.settings.config = _read_config(self.settings.config_path)
            _load_runtime_fields(self.settings)
            data["proxy_pool"] = {
                "path": written.get("path"),
                "line_count": written.get("line_count"),
                "exists": written.get("exists"),
            }
            data["text"] = written.get("text")
        else:
            cfg["proxy_pool_source"] = PROXY_POOL_SOURCE_SUBSCRIPTION
            self.settings.config = cfg
            persist_settings(self.settings)
            self.settings.config = _read_config(self.settings.config_path)
            _load_runtime_fields(self.settings)

        data["applied_local_http"] = applied_local
        data["proxy_pool_source"] = PROXY_POOL_SOURCE_SUBSCRIPTION
        data["proxy_mode"] = (
            "none"
            if self.settings.no_proxy
            else str(self.settings.proxy_mode or "auto")
        )
        data["proxy"] = str((self.settings.config or {}).get("proxy") or "")
        return data

    def embedded_vless_cache_path(self) -> Path:
        """Legacy path (vless-only). Prefer embedded_node_cache_path."""
        return self.config_path.parent / EMBEDDED_VLESS_CACHE_REL

    def embedded_node_cache_path(self) -> Path:
        """Primary cache for embedded nodes (vless/hysteria2/anytls/trojan)."""
        return self.config_path.parent / EMBEDDED_NODE_CACHE_REL

    def _embedded_proxy_cfg_from_settings(self):
        from embedded_proxy_manager import EmbeddedProxyConfig

        raw = dict(self.settings.config or {})
        return EmbeddedProxyConfig(
            binary_path=str(raw.get("embedded_proxy_binary") or ""),
            listen_host=str(raw.get("embedded_proxy_listen_host") or "127.0.0.1") or "127.0.0.1",
            base_port=int(raw.get("embedded_proxy_base_port") or 28000),
            max_nodes=_optional_int(raw.get("embedded_proxy_max_nodes"), default=50),
            probe_host=str(raw.get("embedded_proxy_probe_host") or "accounts.x.ai") or "accounts.x.ai",
            probe_port=int(raw.get("embedded_proxy_probe_port") or 443),
            probe_timeout_sec=float(raw.get("embedded_proxy_probe_timeout_sec") or 5),
            probe_max_workers=int(raw.get("embedded_proxy_probe_max_workers") or 32),
            max_node_retries=int(raw.get("embedded_proxy_max_node_retries") or 3),
        )

    def _embedded_slots_from_nodes(self, nodes, *, max_nodes: int = 50):
        from embedded_proxy_manager import NodeSlot, parse_embedded_node

        slots = []
        for idx, node in enumerate(nodes or []):
            scheme = str(getattr(node, "scheme", "") or "").lower()
            raw_line = str(getattr(node, "raw", "") or "")
            if scheme in {"hy2"}:
                scheme = "hysteria2"
            parsed = None
            if raw_line:
                parsed = parse_embedded_node(raw_line)
            if not parsed and scheme in {"vless", "hysteria2", "anytls", "trojan"}:
                # Fallback: reconstruct is not available without raw; skip incomplete inventory.
                continue
            if not parsed:
                continue
            protocol = str(parsed.get("protocol") or scheme or "vless")
            server = str(parsed.get("server") or "")
            port = int(parsed.get("port") or 0)
            slots.append(
                NodeSlot(
                    id=f"{protocol}-{idx}-{server}:{port}",
                    name=str(parsed.get("name") or f"{protocol}-{idx}"),
                    server=server,
                    port=port,
                    protocol=protocol,
                    local_http="",
                    raw=str(parsed.get("raw") or raw_line),
                    params=dict(parsed.get("params") or {}),
                    uuid=str(parsed.get("uuid") or ""),
                    password=str(parsed.get("password") or ""),
                    healthy=False,
                )
            )
            if max_nodes > 0 and len(slots) >= max_nodes:
                break
        return slots

    # Backward-compatible alias used by older tests/callers.
    def _vless_slots_from_nodes(self, nodes, *, max_nodes: int = 50):
        return self._embedded_slots_from_nodes(nodes, max_nodes=max_nodes)

    def _write_embedded_node_cache(self, slots, *, urls: Optional[List[str]] = None) -> Path:
        path = self.embedded_node_cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"# embedded node cache written_at={time.strftime('%Y-%m-%dT%H:%M:%S')}",
            f"# protocols=vless,hysteria2,anytls,trojan",
            f"# urls={', '.join(urls or [])}",
            f"# count={len(slots)}",
        ]
        for slot in slots:
            raw = str(getattr(slot, "raw", "") or "").strip()
            if raw:
                lines.append(raw)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        # Keep legacy file in sync for older tooling that still reads vless_nodes.txt.
        legacy = self.embedded_vless_cache_path()
        try:
            legacy.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        except OSError:
            pass
        return path

    def _write_vless_cache(self, slots, *, urls: Optional[List[str]] = None) -> Path:
        return self._write_embedded_node_cache(slots, urls=urls)

    def _read_embedded_node_cache_lines(self) -> List[str]:
        from embedded_proxy_manager import is_embedded_share_link

        candidates = [self.embedded_node_cache_path(), self.embedded_vless_cache_path()]
        for path in candidates:
            if not path.is_file():
                continue
            out: List[str] = []
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                text = line.strip()
                if not text or text.startswith("#"):
                    continue
                if is_embedded_share_link(text):
                    out.append(text)
            if out:
                return out
        return []

    def _read_vless_cache_lines(self) -> List[str]:
        return self._read_embedded_node_cache_lines()

    def get_embedded_vless_cache_info(self) -> Dict[str, object]:
        path = self.embedded_node_cache_path()
        if not path.is_file():
            path = self.embedded_vless_cache_path()
        lines = self._read_embedded_node_cache_lines()
        mtime = 0.0
        if path.is_file():
            try:
                mtime = float(path.stat().st_mtime)
            except OSError:
                mtime = 0.0
        by_proto: Dict[str, int] = {}
        for line in lines:
            lower = line.lower()
            if lower.startswith("vless://"):
                key = "vless"
            elif lower.startswith("hy2://") or lower.startswith("hysteria2://"):
                key = "hysteria2"
            elif lower.startswith("anytls://"):
                key = "anytls"
            elif lower.startswith("trojan://"):
                key = "trojan"
            else:
                key = "other"
            by_proto[key] = by_proto.get(key, 0) + 1
        return {
            "path": str(path),
            "exists": path.is_file(),
            "count": len(lines),
            "by_protocol": by_proto,
            "mtime": mtime,
            "mtime_text": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime)) if mtime else "",
        }


    def get_embedded_node_cache_text(self) -> Dict[str, object]:
        """Return editable embedded node cache text for WebUI."""
        path = self.embedded_node_cache_path()
        legacy = self.embedded_vless_cache_path()
        text_value = ""
        exists = False
        used = path
        if path.is_file():
            exists = True
            used = path
            try:
                text_value = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise TuiConfigError(f"读取节点缓存失败: {exc}") from exc
        elif legacy.is_file():
            exists = True
            used = legacy
            try:
                text_value = legacy.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise TuiConfigError(f"读取节点缓存失败: {exc}") from exc
        info = self.get_embedded_vless_cache_info()
        lines = [
            ln.strip()
            for ln in text_value.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        return {
            "path": str(used),
            "exists": exists,
            "line_count": len(lines),
            "text": text_value,
            "cache": info,
        }

    def set_embedded_node_cache_text(self, text_value: str) -> Dict[str, object]:
        """Write manually edited node cache (one share-link per line)."""
        from embedded_proxy_manager import is_embedded_share_link, parse_embedded_node

        raw = str(text_value or "")
        kept: List[str] = []
        skipped = 0
        for line in raw.splitlines():
            text = line.strip()
            if not text:
                continue
            if text.startswith("#"):
                kept.append(text)
                continue
            if not is_embedded_share_link(text):
                skipped += 1
                continue
            if not parse_embedded_node(text):
                skipped += 1
                continue
            kept.append(text)
        node_lines = [ln for ln in kept if not ln.startswith("#")]
        if not node_lines and raw.strip():
            # allow explicit clear via empty node lines even if comments remain
            pass
        header = [
            f"# embedded node cache written_at={time.strftime('%Y-%m-%dT%H:%M:%S')}",
            "# source=manual-edit",
            f"# count={len(node_lines)}",
        ]
        # keep user comments after header
        user_comments = [ln for ln in kept if ln.startswith("#")]
        body = header + user_comments + node_lines
        content = "\n".join(body) + ("\n" if body else "")
        path = self.embedded_node_cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.write_text(content, encoding="utf-8")
            legacy = self.embedded_vless_cache_path()
            legacy.write_text(content, encoding="utf-8")
        except OSError as exc:
            raise TuiConfigError(f"写入节点缓存失败: {exc}") from exc
        info = self.get_embedded_vless_cache_info()
        return {
            "ok": True,
            "path": str(path),
            "exists": True,
            "line_count": len(node_lines),
            "skipped": skipped,
            "text": content,
            "cache": info,
            "message": f"节点缓存已保存：{len(node_lines)} 条"
            + (f"，跳过 {skipped} 条无效行" if skipped else ""),
        }

    def clear_embedded_node_cache(self) -> Dict[str, object]:
        """Clear embedded node cache files."""
        paths = [self.embedded_node_cache_path(), self.embedded_vless_cache_path()]
        deleted = []
        for path in paths:
            if path.is_file():
                try:
                    path.unlink()
                    deleted.append(str(path))
                except OSError as exc:
                    raise TuiConfigError(f"清空节点缓存失败: {exc}") from exc
        # write empty marker file so UI has a path to edit
        empty = self.set_embedded_node_cache_text("")
        empty["deleted"] = deleted
        empty["message"] = "节点缓存已清空"
        empty["line_count"] = 0
        return empty

    def fetch_embedded_subscription_nodes(
        self,
        *,
        urls: object = None,
        url: str = "",
        timeout: float = 20.0,
    ) -> Dict[str, object]:
        """Pull subscription URL(s), cache embedded nodes for later start/reload."""
        from proxy_subscription import import_proxy_subscriptions, normalize_subscription_urls

        cfg = dict(self.settings.config or {})
        url_list = normalize_subscription_urls(urls if urls is not None else None, url)
        if not url_list:
            url_list = _subscription_urls_for_fields(cfg)
        if not url_list:
            raise TuiConfigError("请先填写订阅链接（支持多行多个 URL）")
        try:
            result = import_proxy_subscriptions(url_list, timeout=timeout)
        except ValueError as exc:
            raise TuiConfigError(str(exc)) from exc

        max_nodes = _optional_int(cfg.get("embedded_proxy_max_nodes"), default=50)
        # Cache all supported nodes before max_nodes trim so start can re-apply limit later.
        all_slots = self._embedded_slots_from_nodes(result.nodes or [], max_nodes=0)
        if not all_slots:
            raise TuiConfigError(
                "订阅中没有可用的内嵌节点（VLESS / Hysteria2 / AnyTLS / Trojan），无法缓存内嵌池"
            )
        path = self._write_embedded_node_cache(all_slots, urls=url_list)
        _apply_subscription_urls_to_config(cfg, url_list)
        self.settings.config = cfg
        persist_settings(self.settings)
        self.settings.config = _read_config(self.settings.config_path)
        _load_runtime_fields(self.settings)

        by_proto: Dict[str, int] = {}
        for slot in all_slots:
            p = str(getattr(slot, "protocol", "") or "unknown")
            by_proto[p] = by_proto.get(p, 0) + 1

        data = result.to_dict()
        cache_info = self.get_embedded_vless_cache_info()
        limit_txt = "不限制" if max_nodes <= 0 else f"最多用 {max_nodes} 个"
        msg = (
            f"已缓存内嵌节点 {len(all_slots)} 个"
            f"（{', '.join(f'{k}:{v}' for k, v in sorted(by_proto.items())) or '-'}；"
            f"启动时{limit_txt}）。可点「启动/重载」。"
        )
        data.update(
            {
                "cached_vless_count": int(by_proto.get("vless") or 0),
                "cached_node_count": len(all_slots),
                "cached_by_protocol": by_proto,
                "max_nodes": max_nodes,
                "cache_path": str(path),
                "cache": cache_info,
                "message": msg,
                "phase": "idle",
                "enabled": _as_bool(cfg.get("embedded_proxy_enabled")),
                "running": False,
            }
        )
        # 清掉启动期遗留的「缓存为空」失败态，避免 UI 拉取成功后又显示旧错误。
        self._set_embedded_boot(phase="idle", message=msg, auto=False)
        last = dict(self._embedded_proxy_last or {})
        last.update(
            {
                "enabled": _as_bool(cfg.get("embedded_proxy_enabled")),
                "running": bool(last.get("running")),
                "last_error": "",
                "phase": "idle" if not last.get("running") else last.get("phase") or "ready",
                "message": msg if not last.get("running") else last.get("message") or msg,
                "cache": cache_info,
            }
        )
        self._embedded_proxy_last = last
        return data

    def _load_vless_nodes_from_cache(self):
        """Load embedded NodeSlots from local cache only (no network)."""
        raw = dict(self.settings.config or {})
        max_nodes = _optional_int(raw.get("embedded_proxy_max_nodes"), default=50)
        lines = self._read_embedded_node_cache_lines()
        if not lines:
            raise TuiConfigError(
                "内嵌节点缓存为空。请先在「内嵌 mihomo」点击「拉取订阅节点」"
            )

        class _Line:
            def __init__(self, raw_line: str) -> None:
                lower = raw_line.lower()
                if lower.startswith("vless://"):
                    self.scheme = "vless"
                elif lower.startswith("hy2://") or lower.startswith("hysteria2://"):
                    self.scheme = "hysteria2"
                elif lower.startswith("anytls://"):
                    self.scheme = "anytls"
                elif lower.startswith("trojan://"):
                    self.scheme = "trojan"
                else:
                    self.scheme = ""
                self.raw = raw_line

        slots = self._embedded_slots_from_nodes([_Line(x) for x in lines], max_nodes=max_nodes)
        if not slots:
            raise TuiConfigError(
                "内嵌节点缓存无效。请重新「拉取订阅节点」"
            )
        return slots

    def _load_vless_nodes_from_subscription(self, *, timeout: float = 20.0):
        """Backward-compatible: refresh cache then return slots (prefer explicit fetch)."""
        data = self.fetch_embedded_subscription_nodes(timeout=timeout)
        slots = self._load_vless_nodes_from_cache()
        return slots, data

    def _set_embedded_boot(
        self,
        *,
        phase: str,
        message: str = "",
        auto: Optional[bool] = None,
    ) -> None:
        with self._embedded_proxy_boot_lock:
            boot = dict(self._embedded_proxy_boot or {})
            boot["phase"] = str(phase or "idle")
            boot["message"] = str(message or "")
            if auto is not None:
                boot["auto"] = bool(auto)
            now = time.time()
            if phase == "starting":
                boot["started_at"] = now
                boot["finished_at"] = 0.0
            elif phase in {"ready", "error", "disabled", "idle"}:
                boot["finished_at"] = now
            self._embedded_proxy_boot = boot

    def maybe_autostart_embedded_proxy(self, *, force: bool = False) -> Dict[str, object]:
        """Start embedded proxy in background when enabled (WebUI boot)."""
        raw = dict(self.settings.config or {})
        enabled = _as_bool(raw.get("embedded_proxy_enabled"))
        if not enabled:
            self._set_embedded_boot(phase="disabled", message="内嵌代理未启用", auto=True)
            return self.get_embedded_proxy_status()

        with self._embedded_proxy_boot_lock:
            thread = self._embedded_proxy_boot_thread
            phase = str((self._embedded_proxy_boot or {}).get("phase") or "idle")
            manager = self._embedded_proxy_manager
            already_running = bool(manager is not None and getattr(manager, "_running", False))
            if already_running and not force:
                self._embedded_proxy_boot = {
                    **dict(self._embedded_proxy_boot or {}),
                    "phase": "ready",
                    "message": "内嵌代理已在运行",
                    "auto": True,
                    "finished_at": time.time(),
                }
                return self.get_embedded_proxy_status()
            if thread is not None and thread.is_alive() and not force:
                return self.get_embedded_proxy_status()

            self._embedded_proxy_boot = {
                "phase": "starting",
                "message": "正在启动/重载内嵌代理…",
                "started_at": time.time(),
                "finished_at": 0.0,
                "auto": True,
            }

            def _worker() -> None:
                try:
                    self._set_embedded_boot(
                        phase="starting",
                        message="正在启动/重载内嵌代理…",
                        auto=True,
                    )
                    out = self.ensure_embedded_proxy(force_reload=bool(force))
                    healthy = out.get("healthy")
                    total = out.get("total")
                    msg = (
                        f"内嵌代理已就绪：健康 "
                        f"{healthy if healthy is not None else 0}/"
                        f"{total if total is not None else 0}"
                    )
                    self._set_embedded_boot(
                        phase="ready" if out.get("running") or out.get("enabled") else "idle",
                        message=msg,
                        auto=True,
                    )
                    # Keep last snapshot for UI.
                    merged = dict(out or {})
                    merged["phase"] = "ready"
                    merged["message"] = msg
                    self._embedded_proxy_last = merged
                except Exception as exc:
                    err = str(exc)
                    self._set_embedded_boot(phase="error", message=err, auto=True)
                    last = dict(self._embedded_proxy_last or {})
                    last.update(
                        {
                            "enabled": True,
                            "running": False,
                            "last_error": err,
                            "phase": "error",
                            "message": err,
                        }
                    )
                    self._embedded_proxy_last = last
                finally:
                    with self._embedded_proxy_boot_lock:
                        # allow future manual restarts to spawn a new worker
                        if self._embedded_proxy_boot_thread is threading.current_thread():
                            self._embedded_proxy_boot_thread = None

            self._embedded_proxy_boot_thread = threading.Thread(
                target=_worker,
                name="embedded-proxy-autostart",
                daemon=True,
            )
            self._embedded_proxy_boot_thread.start()
        return self.get_embedded_proxy_status()

    def ensure_embedded_proxy(self, force_reload: bool = False) -> dict:
        """Start/reload embedded mihomo from cached VLESS nodes (no network fetch)."""
        raw = dict(self.settings.config or {})
        enabled = _as_bool(raw.get("embedded_proxy_enabled"))
        if not enabled:
            out = {"enabled": False, "phase": "disabled", "message": "内嵌代理未启用"}
            self._embedded_proxy_last = out
            self._set_embedded_boot(phase="disabled", message="内嵌代理未启用")
            return out
        # When called synchronously (manual start/reload), surface starting state.
        if str((self._embedded_proxy_boot or {}).get("phase") or "") != "starting":
            self._set_embedded_boot(phase="starting", message="正在启动/重载内嵌代理…")

        manager = self._embedded_proxy_manager
        already_running = bool(manager is not None and getattr(manager, "_running", False))
        if already_running and not force_reload:
            status = dict(manager.status() or {})
            status["enabled"] = True
            status["node_count"] = int(status.get("total") or 0)
            status["phase"] = "ready"
            status["message"] = (
                f"内嵌代理已就绪：健康 {status.get('healthy', 0)}/{status.get('total', 0)}"
            )
            status["cache"] = self.get_embedded_vless_cache_info()
            self._embedded_proxy_last = status
            self._set_embedded_boot(phase="ready", message=status["message"])
            return status

        from embedded_proxy_manager import EmbeddedProxyManager

        # force_reload only rebuilds process from cache; never re-fetches subscription.
        try:
            nodes = self._load_vless_nodes_from_cache()
        except TuiConfigError as exc:
            err = str(exc)
            self._set_embedded_boot(phase="error", message=err)
            raise
        cfg = self._embedded_proxy_cfg_from_settings()
        if manager is None:
            manager = EmbeddedProxyManager(cfg)
            self._embedded_proxy_manager = manager
        try:
            start_info = manager.start(nodes, cfg)
        except Exception as exc:
            err = f"启动内嵌 mihomo 失败: {exc}"
            self._set_embedded_boot(phase="error", message=err)
            raise TuiConfigError(err) from exc

        # Fast path for large pools:
        # 1) higher concurrency
        # 2) shorter first-pass timeout
        # 3) become ready once some nodes are healthy
        # 4) continue probing the rest in background
        total_nodes = max(1, len(nodes))
        probe_workers = int(getattr(cfg, "probe_max_workers", 0) or 0)
        if probe_workers <= 0:
            probe_workers = 32 if total_nodes >= 40 else 16 if total_nodes >= 16 else 8
        probe_workers = max(1, min(probe_workers, total_nodes, 64))
        first_timeout = min(3.0, max(1.0, float(getattr(cfg, "probe_timeout_sec", 5) or 5)))
        min_ready = 1 if total_nodes <= 8 else min(8, max(2, total_nodes // 15))
        ready_wait = min(12.0, max(4.0, first_timeout * 3.0))
        self._set_embedded_boot(
            phase="starting",
            message=(
                f"节点预检中（并发 {probe_workers}，先就绪 {min_ready} 个）…"
            ),
        )
        try:
            probe_info = manager.probe_all(
                max_workers=probe_workers,
                timeout_sec=first_timeout,
                min_healthy=min_ready,
                ready_wait_sec=ready_wait,
                continue_in_background=True,
            )
        except Exception as exc:
            err = f"内嵌节点预检失败: {exc}"
            self._set_embedded_boot(phase="error", message=err)
            raise TuiConfigError(err) from exc
        healthy = int(probe_info.get("healthy") or 0)
        if healthy <= 0:
            # Second chance: full probe with normal timeout before failing hard.
            try:
                probe_info = manager.probe_all(
                    max_workers=probe_workers,
                    timeout_sec=float(getattr(cfg, "probe_timeout_sec", 5) or 5),
                    min_healthy=0,
                    continue_in_background=False,
                )
            except Exception as exc:
                err = f"内嵌节点预检失败: {exc}"
                self._set_embedded_boot(phase="error", message=err)
                raise TuiConfigError(err) from exc
            healthy = int(probe_info.get("healthy") or 0)
        if healthy <= 0:
            err = "内嵌节点预检全失败，请检查订阅节点或探测目标 accounts.x.ai"
            self._set_embedded_boot(phase="error", message=err)
            raise TuiConfigError(err)
        status = dict(manager.status() or {})
        out = {
            "enabled": True,
            "running": bool(status.get("running") or start_info.get("running")),
            "total": int(status.get("total") or start_info.get("total") or len(nodes)),
            "healthy": healthy,
            "leases": int(status.get("leases") or 0),
            "node_count": int(status.get("total") or len(nodes)),
            "probe": probe_info,
            "start": start_info,
            "nodes": status.get("nodes") or [],
            "cache": self.get_embedded_vless_cache_info(),
        }
        out["phase"] = "ready"
        out["message"] = f"内嵌代理已就绪：健康 {healthy}/{out.get('total') or 0}"
        self._embedded_proxy_last = out
        self._set_embedded_boot(phase="ready", message=out["message"])
        return out

    def get_embedded_proxy_status(self) -> dict:
        raw = dict(self.settings.config or {})
        enabled = _as_bool(raw.get("embedded_proxy_enabled"))
        boot = dict(self._embedded_proxy_boot or {})
        if not enabled:
            out = {
                "enabled": False,
                "running": False,
                "total": 0,
                "healthy": 0,
                "leases": 0,
                "phase": "disabled",
                "message": "内嵌代理未启用",
                "boot": boot,
                "cache": self.get_embedded_vless_cache_info(),
            }
            return out
        cache_info = self.get_embedded_vless_cache_info()
        cache_count = int(cache_info.get("count") or 0)
        manager = self._embedded_proxy_manager
        if manager is None:
            last = dict(self._embedded_proxy_last or {})
            last.setdefault("enabled", True)
            last.setdefault("running", False)
            last.setdefault("total", 0)
            last.setdefault("healthy", 0)
            last.setdefault("leases", 0)
            last.setdefault("last_error", "")
            boot_phase = str(boot.get("phase") or "idle")
            boot_msg = str(boot.get("message") or "")
            # 自动启动时若缓存为空会留下 error；用户后来拉成功后应覆盖，不再显示旧错误。
            stale_empty_cache_error = (
                boot_phase == "error"
                and cache_count > 0
                and ("缓存" in boot_msg and ("空" in boot_msg or "无效" in boot_msg))
            )
            if stale_empty_cache_error:
                boot_phase = "idle"
                boot_msg = f"已缓存 {cache_count} 个节点，待启动/重载"
                self._set_embedded_boot(phase="idle", message=boot_msg)
            elif boot_phase == "error" and not boot_msg and last.get("last_error"):
                boot_msg = str(last.get("last_error") or "")
            if boot_phase in {"", "idle"} and cache_count > 0 and not last.get("running"):
                boot_msg = boot_msg or f"已缓存 {cache_count} 个节点，待启动/重载"
            last["phase"] = boot_phase or ("starting" if last.get("running") else "idle")
            last["message"] = boot_msg or str(last.get("last_error") or "")
            last["boot"] = dict(self._embedded_proxy_boot or {})
            last["cache"] = cache_info
            return last
        status = dict(manager.status() or {})
        status["enabled"] = True
        status["node_count"] = int(status.get("total") or 0)
        status["cache"] = cache_info
        status.setdefault("leases", int(status.get("leases") or 0))
        last = dict(self._embedded_proxy_last or {})
        status.setdefault("last_error", last.get("last_error") or "")
        # Manager status is authoritative while running. Do NOT keep a stale
        # "healthy=21" cache when live nodes are all cooled down / unhealthy.
        if last.get("total") is not None and not status.get("total"):
            status["total"] = last.get("total")
        # Keep cache in sync with live truth for UI boot messages.
        try:
            self._embedded_proxy_last = {
                **last,
                "enabled": True,
                "running": bool(status.get("running")),
                "total": int(status.get("total") or 0),
                "healthy": int(status.get("healthy") or 0),
                "leases": int(status.get("leases") or 0),
            }
        except Exception:
            pass

        boot_phase = str(boot.get("phase") or "idle")
        boot_msg = str(boot.get("message") or "")
        stale_empty_cache_error = (
            boot_phase == "error"
            and cache_count > 0
            and ("缓存" in boot_msg and ("空" in boot_msg or "无效" in boot_msg))
        )
        if stale_empty_cache_error:
            boot_phase = "idle"
            boot_msg = f"已缓存 {cache_count} 个节点，待启动/重载"
            self._set_embedded_boot(phase="idle", message=boot_msg)
            boot = dict(self._embedded_proxy_boot or {})
        if boot_phase == "starting":
            status["phase"] = "starting"
            status["message"] = boot_msg or "正在启动/重载内嵌代理…"
        elif boot_phase == "error":
            status["phase"] = "error"
            status["message"] = boot_msg or status.get("last_error") or "内嵌代理启动失败"
        elif status.get("running"):
            status["phase"] = "ready"
            live_h = int(status.get("healthy") if status.get("healthy") is not None else last.get("healthy") or 0)
            live_t = int(status.get("total") if status.get("total") is not None else last.get("total") or 0)
            status["healthy"] = live_h
            status["total"] = live_t
            status["message"] = f"运行中 健康 {live_h}/{live_t}"
            # 运行中持续用 live 数字覆盖 boot 文案，防止 UI 摘要旁还挂着启动时的旧 47/50
            if str(boot.get("phase") or "") in {"ready", "idle", "starting", ""}:
                self._set_embedded_boot(phase="ready", message=status["message"])
                boot = dict(self._embedded_proxy_boot or {})
        else:
            status["phase"] = boot_phase or "idle"
            status["message"] = str(boot.get("message") or status.get("last_error") or "")
        status["boot"] = boot
        return status

    def probe_embedded_proxy(self) -> dict:
        raw = dict(self.settings.config or {})
        enabled = _as_bool(raw.get("embedded_proxy_enabled"))
        if not enabled:
            return {"enabled": False, "total": 0, "healthy": 0, "results": [], "running": False}
        manager = self._embedded_proxy_manager
        if manager is None or not getattr(manager, "_running", False):
            raise TuiConfigError("内嵌代理尚未启动，请先调用 ensure_embedded_proxy")
        probe_info = dict(manager.probe_all() or {})
        status = dict(manager.status() or {})
        healthy = int(probe_info.get("healthy") if probe_info.get("healthy") is not None else status.get("healthy") or 0)
        total = int(probe_info.get("total") if probe_info.get("total") is not None else status.get("total") or 0)
        msg = f"探测完成：健康 {healthy}/{total}"
        out = {
            "enabled": True,
            "running": bool(status.get("running")),
            "phase": "ready" if status.get("running") else "idle",
            "message": msg,
            "healthy": healthy,
            "total": total,
            "leases": int(status.get("leases") or 0),
            "node_count": int(status.get("total") or total),
            "nodes": status.get("nodes") or [],
            "probe": probe_info,
            "cache": self.get_embedded_vless_cache_info(),
            "last_error": "",
        }
        self._embedded_proxy_last = dict(out)
        # 同步 boot 文案，避免轮询仍显示启动时的「健康 47/50」旧数字
        if status.get("running"):
            self._set_embedded_boot(phase="ready", message=f"运行中 健康 {healthy}/{total}")
        return out




    def stop_embedded_proxy(self) -> dict:
        """Stop embedded mihomo; reject when a batch is running."""
        if self.is_busy():
            raise BatchBusyError("批次运行中，禁止停止内嵌代理")
        raw = dict(self.settings.config or {})
        enabled = _as_bool(raw.get("embedded_proxy_enabled"))
        manager = self._embedded_proxy_manager
        if manager is not None:
            try:
                manager.stop()
            except Exception as exc:
                raise TuiConfigError(f"停止内嵌 mihomo 失败: {exc}") from exc
        out = {
            "enabled": enabled,
            "running": False,
            "total": 0,
            "healthy": 0,
            "leases": 0,
            "node_count": 0,
            "last_error": "",
        }
        # Keep last known totals if manager still holds node table after stop.
        if manager is not None:
            try:
                status = dict(manager.status() or {})
                out["total"] = int(status.get("total") or 0)
                out["healthy"] = int(status.get("healthy") or 0)
                out["leases"] = int(status.get("leases") or 0)
                out["node_count"] = int(status.get("total") or 0)
                out["nodes"] = status.get("nodes") or []
            except Exception:
                pass
        self._embedded_proxy_last = out
        return out

    def reload_embedded_proxy(self) -> dict:
        """Stop then ensure/start embedded mihomo; reject when a batch is running."""
        if self.is_busy():
            raise BatchBusyError("批次运行中，禁止重载内嵌代理")
        # Force rebuild even if currently running.
        return self.ensure_embedded_proxy(force_reload=True)

    def test_proxy_pool(self, *, count: int = 5, text_value: Optional[str] = None, timeout: float = 12.0) -> Dict[str, object]:
        return test_proxy_pool_sample(
            self.settings,
            count=count,
            text_value=text_value,
            timeout=timeout,
        )

    def attach_log_listener(self, callback: Callable[[str], None]) -> None:
        self._listeners.append(callback)

    def detach_log_listener(self, callback: Callable[[str], None]) -> None:
        try:
            self._listeners.remove(callback)
        except ValueError:
            pass

    def _emit_log(self, line: str) -> None:
        for callback in list(self._listeners):
            try:
                callback(line)
            except Exception:
                pass

    def _sync_logs(self) -> None:
        runner = self._runner
        if runner is None:
            return
        logs = list(runner.logs)
        if self._log_cursor > len(logs):
            self._log_cursor = 0
        while self._log_cursor < len(logs):
            self._emit_log(logs[self._log_cursor])
            self._log_cursor += 1

    def is_busy(self) -> bool:
        runner = self._runner
        return bool(runner is not None and runner.started and not runner.done)

    def start_run(self, overrides: Optional[Dict[str, object]] = None) -> Dict[str, object]:
        with self._lock:
            if self.is_busy():
                raise BatchBusyError("当前已有批次在运行")
            if overrides:
                self.update_settings_from_mapping(overrides, persist=False)
            plan = build_plan(self.settings)
            if plan.embedded_proxy_enabled:
                self.ensure_embedded_proxy()
            runner = BatchRunner(plan)
            if plan.embedded_proxy_enabled:
                runner.embedded_proxy_manager = self._embedded_proxy_manager
            self._runner = runner
            self._log_cursor = 0
            runner.start()
            self._sync_logs()
            return runner.snapshot()

    def stop_run(self) -> Dict[str, object]:
        with self._lock:
            if self._runner is None:
                raise TuiConfigError("当前没有运行中的批次")
            self._runner.stop()
            self._runner.tick()
            self._sync_logs()
            return self._runner.snapshot()

    def current_snapshot(self) -> Optional[Dict[str, object]]:
        if self._runner is None:
            return None
        return self._runner.snapshot()

    def poll(self) -> None:
        runner = self._runner
        if runner is None:
            return
        runner.tick()
        self._sync_logs()

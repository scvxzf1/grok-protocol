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
import shutil
import re
import socket
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Sequence, Tuple


ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = ROOT_DIR / "config.json"
DEFAULT_OUTPUT_DIR = ROOT_DIR / "xai_credentials"
DEFAULT_EXPORT_DIR = ROOT_DIR / "exports"
RUNS_DIR = ROOT_DIR / "http_runs"
MAX_COUNT = 99999999
TARGET_MODE_COUNT = "count"
TARGET_MODE_CONTINUOUS = "continuous"
DEFAULT_REFILL_PAUSE_SEC = 2.0
REFILL_PAUSE_LOG_INTERVAL_SEC = 5.0
CIRCUIT_WINDOW_SIZE = 50
CIRCUIT_FAIL_RATE = 0.8
CIRCUIT_PAUSE_SEC = 30.0
PROXY_HEALTH_CHECK_INTERVAL_SEC = 15.0
PROXY_DEAD_PAUSE_SEC = 15.0
RECENT_WORKER_WINDOW = 200
MAX_WORKERS = 32
MAX_LOCAL_TURNSTILE_WORKERS = 3  # default local Turnstile concurrency cap
MIN_LOCAL_TURNSTILE_WORKERS = 1
ABS_MAX_LOCAL_TURNSTILE_WORKERS = 6666
DEFAULT_TURNSTILE_QUEUE_SIZE = 64
DEFAULT_SUBMIT_WORKERS = 4
MAX_LOG_LINES = 700
DEFAULT_SSO_CONVERT_RETRIES = 5
DEFAULT_SSO_CONVERT_COOLDOWN = 3
MAX_SSO_CONVERT_RETRIES = 20
MAX_SSO_CONVERT_COOLDOWN = 120
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

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


def browser_health_status() -> Dict[str, int]:
    """Snapshot local browser residue pressure for Turnstile headed launches."""
    return {
        "chrome_count": _pgrep_count("chrome"),
        "playwright_count": _pgrep_count("ms-playwright/chromium"),
    }


def format_browser_health(status: Optional[Dict[str, int]] = None) -> str:
    data = status or browser_health_status()
    chrome = int(data.get("chrome_count") or 0)
    playwright = int(data.get("playwright_count") or 0)
    level = "正常"
    if chrome >= 200 or playwright >= 100:
        level = "高风险"
    elif chrome >= 80 or playwright >= 30:
        level = "偏高"
    return f"{level} | chrome={chrome} | playwright={playwright}"


_TEMP_DIR_GLOBS = (
    "xai-ts-chrome-*",
    "xai-ts-probe*",
    "xai-chrome-raw-*",
    "playwright_chromiumdev_profile-*",
)


def cleanup_browser_residues(
    *,
    temp_root: Optional[Path] = None,
    kill_playwright: bool = True,
    kill_all_chrome: bool = False,
    pkill_fn=None,
) -> Dict[str, int]:
    """Clean Playwright/Chrome residues that commonly block headed Turnstile launches.

    Default is conservative:
      - kill Playwright Chromium leftovers
      - remove this project's temp Chrome profile dirs
      - do NOT kill every Chrome process unless explicitly requested
    """
    if pkill_fn is None:
        def pkill_fn(pattern: str) -> int:
            before = _pgrep_count(pattern)
            if before <= 0:
                return 0
            subprocess.run(
                ["pkill", "-f", pattern],
                capture_output=True,
                text=True,
                check=False,
            )
            # Give the kernel a moment to reap.
            time.sleep(0.2)
            after = _pgrep_count(pattern)
            return max(0, before - after)

    killed_playwright = int(pkill_fn("ms-playwright/chromium") if kill_playwright else 0)
    # Always reap this project's headless profiles; do not touch the user's daily Chrome.
    killed_project_chrome = int(pkill_fn("xai-ts-chrome-") + pkill_fn("xai-chrome-raw-"))
    killed_chrome = int(pkill_fn("chrome") if kill_all_chrome else 0) + killed_project_chrome

    root = Path(temp_root or "/tmp")
    removed = 0
    for pattern in _TEMP_DIR_GLOBS:
        for path in root.glob(pattern):
            try:
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                    removed += 1
                elif path.exists():
                    path.unlink(missing_ok=True)
                    removed += 1
            except OSError:
                continue

    return {
        "killed_playwright": killed_playwright,
        "killed_chrome": killed_chrome,
        "removed_temp_dirs": removed,
        "chrome_count": _pgrep_count("chrome"),
        "playwright_count": _pgrep_count("ms-playwright/chromium"),
    }


def format_cleanup_result(result: Dict[str, int]) -> str:
    return (
        f"已清理 Playwright={int(result.get('killed_playwright') or 0)}，"
        f"临时目录={int(result.get('removed_temp_dirs') or 0)}；"
        f"当前 chrome={int(result.get('chrome_count') or 0)}，"
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


def _status_label(status: str) -> str:
    return STATUS_LABELS.get(status, status)


def _proxy_mode_label(mode: str) -> str:
    return PROXY_MODE_LABELS.get(mode, mode)


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
    "未捕获到可用 Turnstile token",
    "Turnstile broker 求解失败",
    "Read timed out",
)


def _looks_like_proxy_failure(text: str) -> bool:
    """Heuristics for embedded-proxy node failures / bad egress."""
    blob = str(text or "")
    if not blob:
        return False
    lower = blob.lower()
    if "没有可用的内嵌代理节点" in blob or "内嵌代理已启用但管理器未就绪" in blob:
        return True
    for marker in PROXY_FAILURE_MARKERS:
        if marker.lower() in lower:
            return True
    # Broad but still useful under embedded mode.
    if "turnstile" in lower and ("timeout" in lower or "超时" in blob or "token" in lower and "0" in blob):
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
    raw = str(line or "").strip()
    if not raw or raw.startswith("#"):
        return None
    parts = [part.strip() for part in raw.split("----")]
    if len(parts) < 3:
        return None
    email, password, sso = parts[0], parts[1], parts[-1]
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
    return data


def _write_config(path: Path, data: Dict[str, object]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
        payload = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, path)
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

    proxy_mode = str(config.get("tui_proxy_mode") or config.get("proxy_mode") or "auto").strip().lower()
    if proxy_mode not in PROXY_MODE_LABELS:
        proxy_mode = "auto"
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
            MAX_WORKERS,
            _positive_int(config.get("submit_workers", DEFAULT_SUBMIT_WORKERS), "提交并发", MAX_WORKERS),
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
    config["tui_proxy_mode"] = "none" if settings.no_proxy else str(settings.proxy_mode or "auto")
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
        settings.output_dir = _absolute_path(args.output_dir)
    elif getattr(args, "output_dir", None):
        settings.output_dir = _absolute_path(args.output_dir)
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
    proxy_file_value = str(config.get("proxy_file") or "").strip()
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

    parent_proxy = str(config.get("proxy_parent") or "").strip()
    if mode != "none" and parent_proxy:
        args.extend(["--proxy-parent", parent_proxy])
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
        if turnstile_headless:
            warnings.append(
                "本地无头会映射为 virtual-headed（Xvfb）；"
                f"Turnstile 浏览器并发独立限制为 {local_cap}"
                "（配置 local_turnstile_max_workers）。"
            )
        if workers > local_cap:
            warnings.append(
                f"本地浏览器 Turnstile 独立限制为 {local_cap}"
                "（配置 local_turnstile_max_workers）；"
                "账号任务并发不再被该限制覆盖。"
            )

    is_graph = email_provider in {"msgraph", "microsoft", "hotmail", "outlook"}
    has_mail_file = bool(str(config.get("ms_mail_file") or "").strip())
    if workers > 1 and (is_graph or has_mail_file):
        workers = 1
        warnings.append("Outlook/Graph 邮箱池会强制单并发，避免重复领取邮箱。")
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
            MAX_WORKERS,
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
        manage_turnstile_broker=not bool(turnstile_broker_url),
        sso_convert_retries=sso_convert_retries,
        sso_convert_cooldown=sso_convert_cooldown,
        warnings=warnings,
        embedded_proxy_enabled=embedded_proxy_enabled,
        embedded_proxy_max_node_retries=embedded_proxy_max_node_retries,
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
        f"代理: {_proxy_mode_label(plan.proxy_mode)}",
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
        self._last_proxy_health_check_at: float = 0.0
        self._proxy_unhealthy = False

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
        self.broker_process = None
        if not self.owns_broker or process is None:
            return
        self.owns_broker = False
        try:
            process.terminate()
            process.wait(timeout=5)
        except Exception:
            try:
                process.kill()
                process.wait(timeout=2)
            except Exception:
                pass
        self._log("SYSTEM", "共享 Turnstile broker 已关闭")
        if self.plan.provider == "local":
            cleanup = cleanup_browser_residues(kill_playwright=True, kill_all_chrome=False)
            self._log("SYSTEM", f"结束后清理浏览器残留: {format_cleanup_result(cleanup)}")

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
        message = _safe_text(message)
        if message:
            self.logs.append(f"[{source}] {message}")

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
        if self.plan.provider == "local":
            cleanup = cleanup_browser_residues(kill_playwright=True, kill_all_chrome=False)
            self._log("SYSTEM", f"启动前清理浏览器残留: {format_cleanup_result(cleanup)}")
            self._log("SYSTEM", f"浏览器健康: {format_browser_health()}")
        self._start_shared_broker()
        self.started = True
        self.phase = "running"
        self.started_at_monotonic = time.monotonic()
        self.started_at_wall = time.strftime("%Y-%m-%dT%H:%M:%S")
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
            str(ROOT_DIR / "grok_register_ttk.py"),
            "http",
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
        else:
            command.extend(self.plan.proxy_args)
        return command

    def _append_worker_log(self, worker: WorkerState, message: str) -> None:
        text_line = _safe_text(message)
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
            if self.stopping:
                fail_messages.append(f"{email}: 批次停止，跳过")
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
                    f"SSO 已单独保存 | email={email} | {sso_path.name}",
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
                    f"开始 SSO→凭证转换 | email={email} | 尝试 {attempt}/{retries}",
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
                            self._append_worker_log(worker, line)
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
                        f"SSO 转换失败 | email={email} | 尝试 {attempt}/{retries} | {last_error}",
                    )
                if attempt < retries and not self.stopping:
                    wait_s = cooldown
                    # 限流时至少冷却配置秒数，避免连打 device/code
                    self._append_worker_log(
                        worker,
                        f"SSO 转换冷却 {wait_s}s 后重试 | email={email} | 下一轮 {attempt + 1}/{retries}",
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
                fail_messages.append(f"{email}: {last_error}")

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
        snap = self._proxy_health_snapshot()
        if not snap.get("ready"):
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

    def _release_embedded_proxy(self, worker: WorkerState, *, failed: bool = False) -> None:
        if not worker.proxy_node_id:
            return
        manager = self.embedded_proxy_manager
        node_id = worker.proxy_node_id
        if manager is not None:
            try:
                manager.release(node_id, failed=failed)
            except Exception as exc:  # pragma: no cover - defensive
                self._log(f"W{worker.index:02d}", f"[Proxy] 释放节点失败: {exc}")
        worker.proxy_node_id = None
        worker.proxy_node_name = ""
        worker.proxy_local_http = ""

    def _worker_proxy_failure_blob(self, worker: WorkerState, reason_text: str = "") -> str:
        parts = [reason_text, worker.last_log]
        if worker.log_path and worker.log_path.is_file():
            try:
                parts.append(worker.log_path.read_text(encoding="utf-8", errors="replace")[-4000:])
            except OSError:
                pass
        return "\n".join(str(p) for p in parts if p)

    def _maybe_retry_proxy_node(self, worker: WorkerState, reason_text: str = "") -> bool:
        """If failure looks proxy-related and retries remain, switch node and respawn."""
        if not self.plan.embedded_proxy_enabled or self.stopping:
            return False
        max_retries = max(1, int(self.plan.embedded_proxy_max_node_retries or 3))
        blob = self._worker_proxy_failure_blob(worker, reason_text)
        if not _looks_like_proxy_failure(blob):
            return False
        current_id = worker.proxy_node_id
        if current_id and current_id not in worker.tried_node_ids:
            worker.tried_node_ids.append(current_id)
        self._release_embedded_proxy(worker, failed=True)
        attempt = len(worker.tried_node_ids)
        if attempt >= max_retries:
            worker.last_log = (
                f"[Proxy] 节点失败已达上限 ({attempt}/{max_retries})，放弃重试"
            )
            self._log(f"W{worker.index:02d}", worker.last_log)
            return False
        next_attempt = attempt + 1
        self._log(
            f"W{worker.index:02d}",
            f"[Proxy] 节点失败，切换 ... ({next_attempt}/{max_retries})",
        )
        # Respawn same logical task with a fresh node.
        worker.status = "queued"
        worker.process = None
        worker.return_code = None
        if not self._acquire_embedded_proxy(worker):
            # Already-started task cannot recover: count one failure, then pause refill.
            worker.last_log = worker.last_log or "没有可用的内嵌代理节点"
            self._mark_terminal(worker, "failed")
            self._record_failure(worker, worker.last_log)
            self._log(
                f"W{worker.index:02d}",
                f"[Proxy] 无可用节点，停止本任务重试并暂停补货 | {worker.last_log}",
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

    def _spawn_one(self, worker: WorkerState, *, acquire_proxy: bool = True) -> bool:
        """Try to launch one worker process.

        Returns True only when the subprocess is actually running.
        Resource shortages (no proxy node) return False without counting failure.
        """
        worker.accounts_path = self.run_dir / f"accounts_{worker.index:03d}.txt"
        worker.log_path = self.run_dir / f"worker_{worker.index:03d}.log"
        if acquire_proxy and self.plan.embedded_proxy_enabled:
            if not self._acquire_embedded_proxy(worker):
                if not worker.last_log:
                    worker.last_log = "没有可用的内嵌代理节点"
                # Do not mark failed / do not write failure counters.
                return False
        command = self._command_for(worker)
        log_handle = None
        try:
            log_handle = worker.log_path.open("w", encoding="utf-8", buffering=1)
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
            self._mark_terminal(worker, "failed")
            worker.last_log = f"无法启动进程: {exc}"
            self._release_embedded_proxy(worker, failed=True)
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
                    try:
                        log_handle.write(line)
                    except OSError:
                        pass
                    self.events.put((worker.index, line))
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
        slots = max(0, int(self.plan.workers) - len(self.active))
        attempts = 0
        while slots > 0 and attempts < int(self.plan.workers) and self._should_refill():
            if self._refill_pause_active():
                break
            worker = WorkerState(index=self.next_index)
            self.next_index += 1
            attempts += 1
            # staged until process actually starts
            worker.status = "queued"
            self.workers.append(worker)
            self.worker_by_index[worker.index] = worker
            launched = self._spawn_one(worker)
            if launched:
                self.started_tasks += 1
                slots = max(0, int(self.plan.workers) - len(self.active))
                continue
            # Launch failed without becoming active.
            reason = worker.last_log or "启动失败"
            # Drop this logical slot from hot lists; do not count as business failure
            # when it is a resource shortage (proxy unavailable).
            resource_shortage = (
                "没有可用的内嵌代理节点" in reason
                or "内嵌代理已启用但管理器未就绪" in reason
            )
            if resource_shortage:
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
            # Still respect one-tick budget; avoid tight-loop storm.
            slots = max(0, int(self.plan.workers) - len(self.active))
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
            worker.last_log = _safe_text(raw)
            self._log(f"W{worker_index:02d}", raw)

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
                self._release_embedded_proxy(worker, failed=False)
                self._log(f"W{worker.index:02d}", worker.last_log)
            elif return_code == 0:
                self._release_embedded_proxy(worker, failed=False)
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
                self._mark_terminal(worker, "failed")
                self._release_embedded_proxy(worker, failed=False)
                self._record_failure(worker, worker.last_log)
                self._log(f"W{worker.index:02d}", worker.last_log)

    def _finalize(self) -> None:
        if self.done:
            return
        try:
            summary = ROOT_DIR / f"accounts_http_{self.run_id}.txt"
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
            "refill_pause_reason": self.refill_pause_reason or "",
            "pause_reason": self.refill_pause_reason or "",
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
                    "last_log": worker.last_log,
                    "return_code": worker.return_code,
                }
                for worker in shown_workers
            ],
        }

    def _write_summary_json(self) -> None:
        payload = self.snapshot()
        target = self.run_dir / "summary.json"
        try:
            target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
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
    "grok2api_remote_app_key",
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
        "turnstile_provider": settings.turnstile_provider,
        "turnstile_headless": settings.turnstile_headless,
        "sso_convert_retries": settings.sso_convert_retries,
        "sso_convert_cooldown": settings.sso_convert_cooldown,
        "email_provider": str(config.get("email_provider") or ""),
        "config": config,
    }


def _proxy_file_path(settings: Settings) -> Path:
    raw = str((settings.config or {}).get("proxy_file") or "proxies.txt").strip() or "proxies.txt"
    return _absolute_path(raw, settings.config_path.parent)



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
    root = Path(root_dir or ROOT_DIR)
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
            "submit_workers": max(
                1,
                min(
                    MAX_WORKERS,
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
            "proxy": str(raw.get("proxy") or ""),
            "proxy_file": str(raw.get("proxy_file") or "proxies.txt"),
            "proxy_subscription_url": str(raw.get("proxy_subscription_url") or ""),
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
                "内嵌代理最大节点数",
                minimum=1,
                maximum=500,
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
            "proxy_parent": str(raw.get("proxy_parent") or ""),
            "proxy_random": _as_bool(raw.get("proxy_random")),
            "proxy_rotate_session": _as_bool(raw.get("proxy_rotate_session")),
            "local_proxy_port": int(raw.get("local_proxy_port") or 17890),
            "xai_oauth_output_dir": str(settings.output_dir),
            "grok2api_remote_base": str(raw.get("grok2api_remote_base") or ""),
            "grok2api_remote_app_key": str(raw.get("grok2api_remote_app_key") or ""),
            "grok2api_pool_name": str(raw.get("grok2api_pool_name") or ""),
            "grok2api_auto_add_local": _as_bool(raw.get("grok2api_auto_add_local")),
            "grok2api_auto_add_remote": _as_bool(raw.get("grok2api_auto_add_remote")),
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
        self.config_path = Path(config_path or (self.root_dir / "config.json"))
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
            output_dir=_absolute_path(str(config.get("xai_oauth_output_dir") or DEFAULT_OUTPUT_DIR), self.root_dir),
            run_mode=_normalize_run_mode(config.get("tui_run_mode") or DEFAULT_RUN_MODE),
            proxy_mode=str(config.get("tui_proxy_mode") or "auto"),
            no_proxy=str(config.get("tui_proxy_mode") or "auto").strip().lower() == "none",
            turnstile_provider=_normalize_turnstile_provider(config.get("turnstile_provider") or "capsolver"),
            turnstile_headless=_as_bool(config.get("turnstile_headless")),
            submit_workers=max(
                1,
                min(
                    MAX_WORKERS,
                    _positive_int(
                        config.get("submit_workers", DEFAULT_SUBMIT_WORKERS),
                        "提交并发",
                        MAX_WORKERS,
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
            self.settings.output_dir = _absolute_path(str(data.get("output_dir")), self.root_dir)
        if "run_mode" in data:
            self.settings.run_mode = _normalize_run_mode(data.get("run_mode"))
        if "proxy_mode" in data:
            mode = str(data.get("proxy_mode") or "auto").strip().lower()
            self.settings.proxy_mode = mode
            self.settings.no_proxy = mode == "none"
        if "turnstile_provider" in data:
            self.settings.turnstile_provider = _normalize_turnstile_provider(data.get("turnstile_provider"))
        if "turnstile_headless" in data:
            self.settings.turnstile_headless = _as_bool(data.get("turnstile_headless"))
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
        if "proxy_mode" in fields:
            mode = str(fields.get("proxy_mode") or "auto").strip().lower()
            if mode not in PROXY_MODE_LABELS:
                raise TuiConfigError("代理模式无效，可选: auto/none/direct/pool")
            self.settings.proxy_mode = mode
            self.settings.no_proxy = mode == "none"
        if "turnstile_provider" in fields:
            self.settings.turnstile_provider = _normalize_turnstile_provider(fields.get("turnstile_provider"))
        if "turnstile_headless" in fields:
            self.settings.turnstile_headless = _as_bool(fields.get("turnstile_headless"))
        if "xai_oauth_output_dir" in fields and str(fields.get("xai_oauth_output_dir") or "").strip():
            self.settings.output_dir = _absolute_path(str(fields.get("xai_oauth_output_dir")), self.root_dir)

        cfg = dict(self.settings.config or {})
        plain_keys = [
            "email_provider",
            "yyds_api_base",
            "cloudflare_api_base",
            "cloudflare_auth_mode",
            "ms_mail_file",
            "proxy",
            "proxy_file",
            "proxy_subscription_url",
            "proxy_subscription_local_http",
            "embedded_proxy_binary",
            "embedded_proxy_listen_host",
            "embedded_proxy_probe_host",
            "proxy_parent",
            "grok2api_remote_base",
            "grok2api_pool_name",
            "grok2api_local_token_file",
            "defaultDomains",
            "user_agent",
        ]
        for key in plain_keys:
            if key in fields:
                cfg[key] = str(fields.get(key) or "").strip()

        bool_keys = [
            "proxy_random",
            "proxy_rotate_session",
            "grok2api_auto_add_local",
            "grok2api_auto_add_remote",
            "enable_nsfw",
            "xai_oauth_auto",
            "embedded_proxy_enabled",
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
                "内嵌代理最大节点数",
                minimum=1,
                maximum=500,
                default=int(cfg.get("embedded_proxy_max_nodes") or 50),
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

        if "turnstile_solve_timeout" in fields:
            cfg["turnstile_solve_timeout"] = _bounded_int(
                fields.get("turnstile_solve_timeout"),
                "Turnstile单次超时",
                minimum=5,
                maximum=600,
                default=int(cfg.get("turnstile_solve_timeout") or 90),
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
                MAX_WORKERS,
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

        self.settings.config = cfg
        persist_settings(self.settings)
        self.settings.config = _read_config(self.settings.config_path)
        _load_runtime_fields(self.settings)

        # Optional proxy pool text write in same request.
        if "proxy_pool_text" in data:
            write_proxy_pool_text(self.settings, str(data.get("proxy_pool_text") or ""), sync_proxies_array=True)
            self.settings.config = _read_config(self.settings.config_path)
            _load_runtime_fields(self.settings)
        return self.get_config_center()

    def list_credentials(self, *, page: int = 1, page_size: int = 1000) -> Dict[str, object]:
        """Return paginated plaintext credential lines from the OAuth output directory."""
        return list_credential_pairs(self.settings.output_dir, page=page, page_size=page_size)

    def export_dir(self) -> Path:
        return resolve_export_dir(self.root_dir)

    def export_credentials_page(self, *, page: int = 1, page_size: int = 1000) -> Dict[str, object]:
        """Export one credentials page to exports/grok+timestamp.txt, then delete local pairs."""
        return export_credential_page_and_delete(
            self.settings.output_dir,
            page=page,
            page_size=page_size,
            export_dir=self.export_dir(),
        )

    def list_export_files(self) -> Dict[str, object]:
        return list_export_files(self.root_dir)

    def delete_export_file(self, name: str) -> Dict[str, object]:
        return delete_export_file(self.root_dir, name)

    def resolve_export_file(self, name: str) -> Path:
        return resolve_export_file(self.root_dir, name)

    def get_proxy_pool(self) -> Dict[str, object]:
        return read_proxy_pool_text(self.settings)

    def set_proxy_pool(self, text_value: str) -> Dict[str, object]:
        result = write_proxy_pool_text(self.settings, text_value, sync_proxies_array=True)
        self.settings.config = _read_config(self.settings.config_path)
        _load_runtime_fields(self.settings)
        return result

    def import_proxy_subscription(
        self,
        *,
        url: str = "",
        write_pool: bool = True,
        timeout: float = 20.0,
        use_local_http_if_empty: bool = True,
        local_http: str = "",
    ) -> Dict[str, object]:
        """Fetch a subscription URL and import usable HTTP proxies into the pool file."""
        from proxy_subscription import import_proxy_subscription

        cfg = dict(self.settings.config or {})
        sub_url = str(url or cfg.get("proxy_subscription_url") or "").strip()
        if not sub_url:
            raise TuiConfigError("请先填写 proxy_subscription_url 订阅链接")
        result = import_proxy_subscription(sub_url, timeout=timeout)
        data = result.to_dict()
        cfg["proxy_subscription_url"] = sub_url
        # 若启用内嵌 mihomo 且主要是 VLESS，弱化“只能走 Clash”的通用警告。
        if _as_bool(cfg.get("embedded_proxy_enabled")):
            vless_n = int((data.get("scheme_counts") or {}).get("vless") or 0)
            if vless_n > 0 and not result.usable_pool_lines:
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
        vless_count = int((data.get("scheme_counts") or {}).get("vless") or 0)
        # 内嵌 mihomo 开启时，VLESS 订阅走内嵌池，不应再强行回退本地 Clash 口。
        if (
            use_local_http_if_empty
            and not result.usable_pool_lines
            and local_http
            and not (embedded_enabled and vless_count > 0)
        ):
            pool_text_lines.append(local_http)
            applied_local = True
            data.setdefault("warnings", []).append(
                f"订阅无直连 HTTP 节点，已写入本地客户端入口: {local_http}"
            )
            self.settings.proxy_mode = "direct"
            self.settings.no_proxy = False
            cfg["proxy"] = local_http
        elif not result.usable_pool_lines and embedded_enabled and vless_count > 0:
            data.setdefault("warnings", []).append(
                f"订阅含 {vless_count} 个 VLESS 节点。HTTP 代理池不可直接使用它们；"
                "请到“内嵌代理内核”点击启动/重载与预检。"
            )
            data["vless_for_embedded"] = True
            data["vless_count"] = vless_count
        elif result.usable_pool_lines:
            # HTTP/SOCKS 可入池时，默认切到代理池模式，避免用户还要手动改开关。
            self.settings.proxy_mode = "pool"
            self.settings.no_proxy = False

        if write_pool:
            content = chr(10).join(pool_text_lines) + chr(10)
            written = write_proxy_pool_text(
                self.settings,
                content,
                sync_proxies_array=True,
            )
            cfg = dict(self.settings.config or {})
            cfg["proxy_subscription_url"] = sub_url
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
            self.settings.config = cfg
            persist_settings(self.settings)
            self.settings.config = _read_config(self.settings.config_path)
            _load_runtime_fields(self.settings)

        data["applied_local_http"] = applied_local
        data["proxy_mode"] = (
            "none"
            if self.settings.no_proxy
            else str(self.settings.proxy_mode or "auto")
        )
        data["proxy"] = str((self.settings.config or {}).get("proxy") or "")
        return data

    def _embedded_proxy_cfg_from_settings(self):
        from embedded_proxy_manager import EmbeddedProxyConfig

        raw = dict(self.settings.config or {})
        return EmbeddedProxyConfig(
            binary_path=str(raw.get("embedded_proxy_binary") or ""),
            listen_host=str(raw.get("embedded_proxy_listen_host") or "127.0.0.1") or "127.0.0.1",
            base_port=int(raw.get("embedded_proxy_base_port") or 28000),
            max_nodes=int(raw.get("embedded_proxy_max_nodes") or 50),
            probe_host=str(raw.get("embedded_proxy_probe_host") or "accounts.x.ai") or "accounts.x.ai",
            probe_port=int(raw.get("embedded_proxy_probe_port") or 443),
            probe_timeout_sec=float(raw.get("embedded_proxy_probe_timeout_sec") or 5),
            max_node_retries=int(raw.get("embedded_proxy_max_node_retries") or 3),
        )

    def _load_vless_nodes_from_subscription(self, *, timeout: float = 20.0):
        from proxy_subscription import import_proxy_subscription
        from embedded_proxy_manager import NodeSlot, parse_vless_node

        raw = dict(self.settings.config or {})
        sub_url = str(raw.get("proxy_subscription_url") or "").strip()
        if not sub_url:
            raise TuiConfigError("请先填写 proxy_subscription_url 订阅链接")
        result = import_proxy_subscription(sub_url, timeout=timeout)
        max_nodes = int(raw.get("embedded_proxy_max_nodes") or 50)
        slots = []
        for idx, node in enumerate(result.nodes or []):
            scheme = str(getattr(node, "scheme", "") or "").lower()
            if scheme != "vless":
                continue
            parsed = parse_vless_node(getattr(node, "raw", "") or "")
            if not parsed:
                continue
            slots.append(
                NodeSlot(
                    id=f"vless-{idx}-{parsed['server']}:{parsed['port']}",
                    name=str(parsed.get("name") or f"vless-{idx}"),
                    server=str(parsed["server"]),
                    port=int(parsed["port"]),
                    protocol="vless",
                    local_http="",
                    raw=str(parsed.get("raw") or ""),
                    params=dict(parsed.get("params") or {}),
                    uuid=str(parsed.get("uuid") or ""),
                    healthy=False,
                )
            )
            if max_nodes > 0 and len(slots) >= max_nodes:
                break
        if not slots:
            raise TuiConfigError("订阅中没有可用的 VLESS 节点，无法启动内嵌 mihomo 池")
        return slots, result

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
        """Load subscription VLESS nodes into embedded mihomo pool and probe them."""
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
            self._embedded_proxy_last = status
            self._set_embedded_boot(phase="ready", message=status["message"])
            return status

        from embedded_proxy_manager import EmbeddedProxyManager

        nodes, _result = self._load_vless_nodes_from_subscription()
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
        try:
            probe_info = manager.probe_all()
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
            }
            return out
        manager = self._embedded_proxy_manager
        if manager is None:
            last = dict(self._embedded_proxy_last or {})
            last.setdefault("enabled", True)
            last.setdefault("running", False)
            last.setdefault("total", 0)
            last.setdefault("healthy", 0)
            last.setdefault("leases", 0)
            last.setdefault("last_error", "")
            last["phase"] = str(boot.get("phase") or ("starting" if last.get("running") else "idle"))
            last["message"] = str(boot.get("message") or last.get("last_error") or "")
            last["boot"] = boot
            return last
        status = dict(manager.status() or {})
        status["enabled"] = True
        status["node_count"] = int(status.get("total") or 0)
        status.setdefault("leases", int(status.get("leases") or 0))
        last = dict(self._embedded_proxy_last or {})
        status.setdefault("last_error", last.get("last_error") or "")
        # Prefer freshest healthy counts from last ensure/probe when manager status is sparse.
        if last.get("healthy") is not None:
            try:
                if status.get("healthy") is None or int(status.get("healthy") or 0) == 0:
                    if int(last.get("healthy") or 0) > 0:
                        status["healthy"] = last.get("healthy")
            except Exception:
                status["healthy"] = last.get("healthy")
        if last.get("total") is not None and not status.get("total"):
            status["total"] = last.get("total")

        boot_phase = str(boot.get("phase") or "idle")
        if boot_phase == "starting":
            status["phase"] = "starting"
            status["message"] = str(boot.get("message") or "正在启动/重载内嵌代理…")
        elif boot_phase == "error":
            status["phase"] = "error"
            status["message"] = str(boot.get("message") or status.get("last_error") or "内嵌代理启动失败")
        elif status.get("running"):
            status["phase"] = "ready"
            status["message"] = (
                f"运行中 健康 {status.get('healthy', last.get('healthy', 0))}/"
                f"{status.get('total', 0)}"
            )
        else:
            status["phase"] = boot_phase or "idle"
            status["message"] = str(boot.get("message") or status.get("last_error") or "")
        status["boot"] = boot
        return status

    def probe_embedded_proxy(self) -> dict:
        raw = dict(self.settings.config or {})
        enabled = _as_bool(raw.get("embedded_proxy_enabled"))
        if not enabled:
            return {"enabled": False, "total": 0, "healthy": 0, "results": []}
        manager = self._embedded_proxy_manager
        if manager is None or not getattr(manager, "_running", False):
            raise TuiConfigError("内嵌代理尚未启动，请先调用 ensure_embedded_proxy")
        probe_info = dict(manager.probe_all() or {})
        probe_info["enabled"] = True
        return probe_info




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


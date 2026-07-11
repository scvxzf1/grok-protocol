# -*- coding: utf-8 -*-
"""HTTP batch registration service shared by WebUI and the transitional TUI.

No curses UI lives here. This module owns config, plan building, BatchRunner
process orchestration, and browser residue tools.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import re
import subprocess
import sys
import threading
import time
import unicodedata
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Sequence, Tuple


ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = ROOT_DIR / "config.json"
DEFAULT_OUTPUT_DIR = ROOT_DIR / "xai_credentials"
RUNS_DIR = ROOT_DIR / "http_runs"
MAX_COUNT = 1000
MAX_WORKERS = 32
MAX_LOCAL_TURNSTILE_WORKERS = 3
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
    killed_chrome = int(pkill_fn("chrome") if kill_all_chrome else 0)

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
    sso_convert_retries: int = DEFAULT_SSO_CONVERT_RETRIES
    sso_convert_cooldown: int = DEFAULT_SSO_CONVERT_COOLDOWN
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
    sso_convert_retries: int = DEFAULT_SSO_CONVERT_RETRIES
    sso_convert_cooldown: int = DEFAULT_SSO_CONVERT_COOLDOWN
    warnings: List[str] = field(default_factory=list)


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
    except Exception as exc:  # pragma: no cover - depends on local env
        raise TuiConfigError(
            "模式2 需要 curl_cffi（sso_to_auth_json Device Flow）。请先安装 requirements.txt"
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
    settings.no_proxy = proxy_mode == "none"
    settings.proxy_mode = "auto" if proxy_mode == "none" else proxy_mode
    settings.turnstile_provider = _normalize_turnstile_provider(
        config.get("turnstile_provider") or "capsolver"
    )
    settings.turnstile_headless = _as_bool(config.get("turnstile_headless", False))
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
    config["tui_run_mode"] = _normalize_run_mode(settings.run_mode)
    config["tui_proxy_mode"] = "none" if settings.no_proxy else str(settings.proxy_mode or "auto")
    config["xai_oauth_output_dir"] = _config_path_value(
        settings.output_dir, settings.config_path.parent
    )
    config["tui_sso_convert_retries"] = int(settings.sso_convert_retries)
    config["tui_sso_convert_cooldown"] = int(settings.sso_convert_cooldown)
    config["turnstile_provider"] = _normalize_turnstile_provider(settings.turnstile_provider)
    config["turnstile_headless"] = bool(settings.turnstile_headless)
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
    if settings.no_proxy or settings.proxy_mode == "none":
        return "none", []

    config = settings.config
    mode = settings.proxy_mode
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


def build_plan(settings: Settings) -> RunPlan:
    config = settings.config
    count = _positive_int(settings.count, "注册数量", MAX_COUNT)
    workers = min(_positive_int(settings.workers, "并发数", MAX_WORKERS), count)
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
        warnings.append(
            "主流程仍是 HTTP 协议；仅在 Turnstile 求解阶段临时打开本地浏览器"
            + ("（无头）" if turnstile_headless else "（有界面）")
            + "，拿完 token 立即关闭。"
        )
        if turnstile_headless:
            warnings.append(
                "本地无头会映射为 virtual-headed（Xvfb）；"
                "每个 worker 都会起浏览器，建议并发 <= "
                f"{MAX_LOCAL_TURNSTILE_WORKERS}。"
            )
        if workers > MAX_LOCAL_TURNSTILE_WORKERS:
            workers = MAX_LOCAL_TURNSTILE_WORKERS
            warnings.append(
                f"本地浏览器 Turnstile 已将并发限制为 {MAX_LOCAL_TURNSTILE_WORKERS}，"
                "避免 YYDS 建邮限流和本机浏览器资源打满。"
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
        warnings.append(
            "YYDS 建邮有全局限流（跨进程文件锁 + 默认 1.5s 间隔）；"
            "并发越高排队越久，429 会自动退避重试。"
        )

    proxy_mode, proxy_args = _resolve_proxy_args(settings)
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
        sso_convert_retries=sso_convert_retries,
        sso_convert_cooldown=sso_convert_cooldown,
        warnings=warnings,
    )


def describe_plan(plan: RunPlan, *, dry_run: bool = False) -> str:
    lines = [
        "HTTP 协议 TUI",
        f"运行模式: {_run_mode_label(plan.run_mode)}",
        f"配置文件: {plan.config_path}",
        f"邮箱: {plan.email_provider}",
        f"Turnstile: {_turnstile_provider_label(plan.provider, headless=plan.turnstile_headless)}",
        f"注册数量: {plan.count}",
        f"并发数: {plan.workers}",
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
    "turnstile_hard_block",
    "turnstile_timeout",
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
    if "cloudflare_hard_block" in t or "hard_block" in t or "硬拦截" in raw:
        return "turnstile_hard_block"
    if "turnstile" in t and ("timeout" in t or "超时" in raw):
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
        self.workers = [WorkerState(index=index) for index in range(1, plan.count + 1)]
        self.events: queue.Queue[Tuple[int, str]] = queue.Queue()
        self.logs: Deque[str] = deque(maxlen=MAX_LOG_LINES)
        self.started = False
        self.done = False
        self.stopping = False
        self.next_index = 0
        self.summary_path: Optional[Path] = None
        self.account_count = 0
        self.failure_counts: Dict[str, int] = {key: 0 for key in FAILURE_CATEGORIES}
        self._failure_recorded: set[int] = set()

    @property
    def active(self) -> List[WorkerState]:
        # 注册中 + 后台 SSO 转换中都占并发槽，保证每个 worker 一对一跟随转换。
        return [worker for worker in self.workers if worker.status in {"running", "converting"}]

    @property
    def completed(self) -> int:
        return sum(worker.status in {"succeeded", "failed", "stopped"} for worker in self.workers)

    @property
    def succeeded(self) -> int:
        return sum(worker.status == "succeeded" for worker in self.workers)

    @property
    def failed(self) -> int:
        return sum(worker.status in {"failed", "stopped"} for worker in self.workers)

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
        self.started = True
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
        # 模式1：仓库内 PKCE OAuth。
        # 模式2：显式传空 output-dir，关闭注册内置换票，改由 sso_to_auth_json 一对一转换。
        if self.plan.run_mode == RUN_MODE_REGISTER_OTP:
            command.extend(["--output-dir", str(self.plan.output_dir)])
        else:
            command.extend(["--output-dir", ""])
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

    def _spawn_one(self, worker: WorkerState) -> None:
        worker.accounts_path = self.run_dir / f"accounts_{worker.index:03d}.txt"
        worker.log_path = self.run_dir / f"worker_{worker.index:03d}.log"
        command = self._command_for(worker)
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
            worker.status = "failed"
            worker.last_log = f"无法启动进程: {exc}"
            self._log(f"W{worker.index:02d}", worker.last_log)
            try:
                log_handle.close()
            except UnboundLocalError:
                pass
            return

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
                log_handle.close()

        threading.Thread(target=copy_and_queue, daemon=True).start()

    def _spawn_available(self) -> None:
        if self.stopping:
            return
        while len(self.active) < self.plan.workers and self.next_index < len(self.workers):
            worker = self.workers[self.next_index]
            self.next_index += 1
            self._spawn_one(worker)

    def _drain_events(self) -> None:
        while True:
            try:
                worker_index, message = self.events.get_nowait()
            except queue.Empty:
                return
            worker = self.workers[worker_index - 1]
            raw = str(message or "")
            if raw.startswith("__CONVERT_DONE__|"):
                parts = raw.split("|", 2)
                ok = len(parts) >= 2 and parts[1] == "1"
                msg = parts[2] if len(parts) >= 3 else "SSO 转换结束"
                worker.convert_thread = None
                if self.stopping and not ok:
                    worker.status = "stopped"
                else:
                    worker.status = "succeeded" if ok else "failed"
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
                worker.status = "stopped"
                worker.last_log = "已被操作者停止"
                self._log(f"W{worker.index:02d}", worker.last_log)
            elif return_code == 0:
                if self.plan.run_mode == RUN_MODE_REGISTER_SSO:
                    self._start_sso_convert(worker)
                else:
                    worker.status = "succeeded"
                    worker.last_log = "协议任务已完成"
                    self._log(f"W{worker.index:02d}", worker.last_log)
            else:
                worker.status = "failed"
                worker.last_log = f"协议任务退出，退出码 {return_code}"
                self._record_failure(worker, worker.last_log)
                self._log(f"W{worker.index:02d}", worker.last_log)

    def _finalize(self) -> None:
        if self.done:
            return
        summary = ROOT_DIR / f"accounts_http_{self.run_id}.txt"
        lines: List[str] = []
        for worker in self.workers:
            if not worker.accounts_path or not worker.accounts_path.is_file():
                continue
            try:
                lines.extend(
                    line for line in worker.accounts_path.read_text(encoding="utf-8").splitlines() if line.strip()
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
        self.done = True
        self._write_summary_json()
        self._log(
            "SYSTEM",
            f"批量完成: 成功={self.succeeded}, 失败={self.failed}, 账号数={self.account_count}",
        )

    def tick(self) -> None:
        if not self.started:
            return
        self._drain_events()
        self._check_processes()
        self._spawn_available()
        if self.completed == len(self.workers) and not self.active:
            self._drain_events()
            self._finalize()

    def stop(self) -> None:
        if self.done:
            return
        self.stopping = True
        self._log("SYSTEM", "正在停止活动中的协议任务")
        for worker in self.workers:
            if worker.status == "queued":
                worker.status = "stopped"
                worker.last_log = "因批次被停止而未启动"
                self._log(f"W{worker.index:02d}", worker.last_log)
        for worker in self.workers:
            if worker.status == "running" and worker.process is not None:
                try:
                    worker.process.terminate()
                except OSError:
                    pass
            elif worker.status == "converting":
                worker.last_log = "停止中：等待当前 SSO 转换收尾"
                self._log(f"W{worker.index:02d}", worker.last_log)


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
        return {
            "run_id": self.run_id,
            "started": self.started,
            "done": self.done,
            "stopping": self.stopping,
            "count": len(self.workers),
            "completed": self.completed,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "active": len(self.active),
            "account_count": self.account_count,
            "failure_counts": dict(self.failure_counts),
            "warnings": list(self.plan.warnings),
            "run_dir": str(self.run_dir),
            "summary_path": str(self.summary_path) if self.summary_path else "",
            "workers": [
                {
                    "index": worker.index,
                    "status": worker.status,
                    "last_log": worker.last_log,
                    "return_code": worker.return_code,
                }
                for worker in self.workers
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
        "output_dir": str(settings.output_dir),
        "run_mode": settings.run_mode,
        "proxy_mode": settings.proxy_mode,
        "no_proxy": settings.no_proxy,
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
            "yyds_api_key": "***" if secret_flags.get("yyds_api_key") else "",
            "yyds_jwt": "***" if secret_flags.get("yyds_jwt") else "",
            "turnstile_provider": settings.turnstile_provider,
            "turnstile_api_key": "***" if secret_flags.get("turnstile_api_key") else "",
            "turnstile_headless": bool(settings.turnstile_headless),
            "duckmail_api_key": "***" if secret_flags.get("duckmail_api_key") else "",
            "cloudflare_api_base": str(raw.get("cloudflare_api_base") or ""),
            "cloudflare_api_key": "***" if secret_flags.get("cloudflare_api_key") else "",
            "cloudflare_auth_mode": str(raw.get("cloudflare_auth_mode") or "none"),
            "ms_mail_file": str(raw.get("ms_mail_file") or ""),
            "proxy_mode": "none" if settings.no_proxy else str(settings.proxy_mode or "auto"),
            "proxy": str(raw.get("proxy") or ""),
            "proxy_file": str(raw.get("proxy_file") or "proxies.txt"),
            "proxy_parent": str(raw.get("proxy_parent") or ""),
            "proxy_random": _as_bool(raw.get("proxy_random")),
            "proxy_rotate_session": _as_bool(raw.get("proxy_rotate_session")),
            "local_proxy_port": int(raw.get("local_proxy_port") or 17890),
            "xai_oauth_output_dir": str(settings.output_dir),
            "grok2api_remote_base": str(raw.get("grok2api_remote_base") or ""),
            "grok2api_remote_app_key": "***" if secret_flags.get("grok2api_remote_app_key") else "",
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

        # Secrets: keep existing when UI sends *** or omit-empty keep.
        for key in SENSITIVE_CONFIG_KEYS:
            if key not in fields:
                continue
            value = fields.get(key)
            if value is None:
                continue
            text_value = str(value)
            if text_value.strip() in {"", "***"}:
                # empty means clear only if explicit clear_secrets contains key
                clear_list = data.get("clear_secrets") or fields.get("clear_secrets") or []
                if isinstance(clear_list, list) and key in clear_list:
                    cfg[key] = ""
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

    def get_proxy_pool(self) -> Dict[str, object]:
        return read_proxy_pool_text(self.settings)

    def set_proxy_pool(self, text_value: str) -> Dict[str, object]:
        result = write_proxy_pool_text(self.settings, text_value, sync_proxies_array=True)
        self.settings.config = _read_config(self.settings.config_path)
        _load_runtime_fields(self.settings)
        return result

    def attach_log_listener(self, callback: Callable[[str], None]) -> None:
        self._listeners.append(callback)

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
            runner = BatchRunner(plan)
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


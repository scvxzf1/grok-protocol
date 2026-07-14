from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Union


DEFAULT_SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"
MAX_SUBMIT_WORKERS = 32


def _config_bool(value: Any, *, default: bool = False) -> bool:
    """Parse JSON/env-style booleans without Python string truthiness."""

    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if not text:
        return bool(default)
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    raise ValueError("无效布尔配置值")


def _config_value(data: Dict[str, Any], key: str, default: Any) -> Any:
    value = data.get(key)
    return default if value is None or value == "" else value


def _config_alias_value(
    data: Dict[str, Any],
    keys: tuple[str, ...],
    default: Any,
) -> Any:
    for key in keys:
        value = data.get(key)
        if value is not None and value != "":
            return value
    return default


def detect_system_chrome_path() -> str:
    """Best-effort discovery of a local Chrome/Chromium binary."""
    env = str(os.environ.get("TURNSTILE_BROWSER_PATH") or "").strip()
    candidates = []
    if env:
        candidates.append(env)
    # Chrome is not normally added to PATH on Windows.  Probe standard
    # per-machine/per-user install roots before command lookup.
    windows_roots = []
    for name in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        value = str(os.environ.get(name) or "").strip()
        if value and value not in windows_roots:
            windows_roots.append(value)
    for root in windows_roots:
        candidates.append(
            str(Path(root) / "Google" / "Chrome" / "Application" / "chrome.exe")
        )

    # Common Linux/mac locations.
    candidates.extend(
        [
            "/usr/bin/google-chrome-stable",
            "/usr/bin/google-chrome",
            "/opt/google/chrome/chrome",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/snap/bin/chromium",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        ]
    )
    try:
        import shutil

        for name in (
            "google-chrome-stable",
            "google-chrome",
            "chromium-browser",
            "chromium",
            "chrome",
        ):
            found = shutil.which(name)
            if found:
                candidates.append(found)
    except Exception:
        pass
    seen = set()
    for raw in candidates:
        text = str(raw or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        path = Path(text).expanduser()
        try:
            if path.is_file() and os.access(str(path), os.X_OK):
                return str(path.resolve(strict=False))
        except OSError:
            continue
    return ""


def _windows_file_version(browser_path: str) -> str:
    """Read a Windows executable's fixed file version without launching it."""

    if os.name != "nt":
        return ""
    try:
        import ctypes
        from ctypes import wintypes

        version = ctypes.windll.version
        handle = wintypes.DWORD(0)
        size = int(
            version.GetFileVersionInfoSizeW(
                str(browser_path),
                ctypes.byref(handle),
            )
        )
        if size <= 0:
            return ""
        buffer = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(str(browser_path), 0, size, buffer):
            return ""
        value = ctypes.c_void_p()
        value_len = wintypes.UINT(0)
        if not version.VerQueryValueW(
            buffer,
            "\\",
            ctypes.byref(value),
            ctypes.byref(value_len),
        ):
            return ""

        class VS_FIXEDFILEINFO(ctypes.Structure):
            _fields_ = [
                ("dwSignature", wintypes.DWORD),
                ("dwStrucVersion", wintypes.DWORD),
                ("dwFileVersionMS", wintypes.DWORD),
                ("dwFileVersionLS", wintypes.DWORD),
                ("dwProductVersionMS", wintypes.DWORD),
                ("dwProductVersionLS", wintypes.DWORD),
                ("dwFileFlagsMask", wintypes.DWORD),
                ("dwFileFlags", wintypes.DWORD),
                ("dwFileOS", wintypes.DWORD),
                ("dwFileType", wintypes.DWORD),
                ("dwFileSubtype", wintypes.DWORD),
                ("dwFileDateMS", wintypes.DWORD),
                ("dwFileDateLS", wintypes.DWORD),
            ]

        info = ctypes.cast(value, ctypes.POINTER(VS_FIXEDFILEINFO)).contents
        if int(info.dwSignature) != 0xFEEF04BD:
            return ""
        parts = (
            int(info.dwFileVersionMS) >> 16,
            int(info.dwFileVersionMS) & 0xFFFF,
            int(info.dwFileVersionLS) >> 16,
            int(info.dwFileVersionLS) & 0xFFFF,
        )
        return ".".join(str(part) for part in parts)
    except (AttributeError, OSError, TypeError, ValueError):
        return ""


def detect_chrome_full_version(browser_path: str = "") -> str:
    """Read Chrome's four-part version without opening a window on Windows."""

    path = str(browser_path or detect_system_chrome_path() or "").strip()
    if not path:
        return ""
    file_version = _windows_file_version(path)
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", file_version):
        return file_version
    try:
        output = subprocess.check_output(
            [path, "--version"],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5,
        )
    except Exception:
        return ""
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", str(output or ""))
    return str(match.group(1)) if match else ""


def detect_chrome_major(browser_path: str = "") -> str:
    """Read Chrome's major version from metadata/version output."""

    full_version = detect_chrome_full_version(browser_path)
    return full_version.split(".", 1)[0] if full_version else ""



@dataclass
class SolverConfig:
    host: str = "127.0.0.1"
    port: int = 8787
    max_concurrency: int = 2
    browser_timeout_sec: int = 90
    token_min_length: int = 80
    signup_url: str = DEFAULT_SIGNUP_URL
    headless: bool = False
    proxy: str = ""
    proxy_file: str = ""
    local_proxy_port: int = 0
    user_agent: str = ""
    enable_metrics: bool = True
    browser_max_tasks: int = 12
    browser_max_age_sec: int = 900
    browser_idle_ttl_sec: int = 90
    browser_maintenance_interval_sec: float = 5.0
    # Chrome process-tree RSS; shared pages may be counted in multiple children.
    # 1024 MiB allows for shared-page double counting while bounding bloated slots.
    browser_max_rss_mb: int = 1024
    browser_max_consecutive_failures: int = 2
    browser_solve_max_attempts: int = 2
    browser_retry_backoff_sec: float = 1.25
    lease_ttl_sec: int = 240
    queue_timeout_sec: int = 180
    strict_fingerprint: bool = True
    locale: str = ""
    accept_language: str = ""
    external_provider_workers: int = 20
    external_queue_limit: int = 64
    submit_workers: int = 5
    submit_permit_lease_sec: int = 120
    browser_path: str = ""
    no_sandbox: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SolverConfig":
        return cls(
            host=str(data.get("host") or "127.0.0.1"),
            port=int(data.get("port") or 8787),
            max_concurrency=max(1, int(data.get("max_concurrency") or 2)),
            browser_timeout_sec=max(
                5,
                int(
                    data.get("browser_timeout_sec")
                    or data.get("turnstile_solve_timeout")
                    or 90
                ),
            ),
            token_min_length=max(20, int(data.get("token_min_length") or 80)),
            signup_url=str(data.get("signup_url") or DEFAULT_SIGNUP_URL),
            headless=_config_bool(
                _config_alias_value(data, ("headless", "turnstile_headless"), False),
                default=False,
            ),
            proxy=str(data.get("proxy") or ""),
            proxy_file=str(data.get("proxy_file") or ""),
            local_proxy_port=int(data.get("local_proxy_port") or 0),
            user_agent=str(data.get("user_agent") or ""),
            enable_metrics=_config_bool(data.get("enable_metrics"), default=True),
            browser_max_tasks=max(1, int(_config_value(data, "browser_max_tasks", 12))),
            browser_max_age_sec=max(
                60,
                int(
                    _config_alias_value(
                        data,
                        ("browser_max_age_seconds", "browser_max_age_sec"),
                        900,
                    )
                ),
            ),
            browser_idle_ttl_sec=max(
                0,
                int(
                    _config_alias_value(
                        data,
                        ("browser_idle_ttl_seconds", "browser_idle_ttl_sec"),
                        90,
                    )
                ),
            ),
            browser_maintenance_interval_sec=max(
                0.05,
                float(
                    _config_alias_value(
                        data,
                        (
                            "browser_maintenance_interval_seconds",
                            "browser_maintenance_interval_sec",
                        ),
                        5.0,
                    )
                ),
            ),
            browser_max_rss_mb=max(
                0,
                int(_config_value(data, "browser_max_rss_mb", 1024)),
            ),
            browser_max_consecutive_failures=max(
                1, int(data.get("browser_max_consecutive_failures") or 2)
            ),
            browser_solve_max_attempts=max(
                1,
                min(
                    4,
                    int(_config_value(data, "browser_solve_max_attempts", 2)),
                ),
            ),
            browser_retry_backoff_sec=max(
                0.0,
                min(
                    10.0,
                    float(
                        _config_alias_value(
                            data,
                            (
                                "browser_retry_backoff_seconds",
                                "browser_retry_backoff_sec",
                            ),
                            1.25,
                        )
                    ),
                ),
            ),
            lease_ttl_sec=max(1, min(240, int(data.get("lease_ttl_sec") or 240))),
            queue_timeout_sec=max(
                1,
                int(
                    data.get("queue_timeout_sec")
                    or data.get("turnstile_solve_timeout")
                    or 180
                ),
            ),
            strict_fingerprint=_config_bool(
                data.get("strict_fingerprint"),
                default=True,
            ),
            locale=str(data.get("locale") or ""),
            accept_language=str(data.get("accept_language") or ""),
            external_provider_workers=max(1, int(data.get("external_provider_workers") or 20)),
            external_queue_limit=max(1, int(data.get("external_queue_limit") or 64)),
            submit_workers=max(
                1,
                min(MAX_SUBMIT_WORKERS, int(data.get("submit_workers") or 5)),
            ),
            submit_permit_lease_sec=max(
                1, int(data.get("submit_permit_lease_sec") or 120)
            ),
            browser_path=str(data.get("browser_path") or ""),
            no_sandbox=_config_bool(data.get("no_sandbox"), default=False),
        )

    def resolved_browser_path(self) -> str:
        raw = str(os.environ.get("TURNSTILE_BROWSER_PATH") or self.browser_path or "").strip()
        if not raw:
            raw = detect_system_chrome_path()
        if not raw:
            if self.strict_fingerprint:
                raise ValueError(
                    "严格指纹模式必须通过 browser_path 或 TURNSTILE_BROWSER_PATH 指定浏览器"
                    "（也可用本机已安装的 google-chrome / chromium）"
                )
            return ""
        path = Path(raw).expanduser()
        if self.strict_fingerprint:
            if not path.is_absolute():
                raise ValueError(f"严格指纹模式 browser_path 必须是绝对路径: {path}")
            if not path.is_file():
                raise ValueError(f"严格指纹模式 browser_path 不是可执行文件: {path}")
            if not os.access(str(path), os.X_OK):
                raise ValueError(f"严格指纹模式 browser_path 不可执行: {path}")
        try:
            return str(path.resolve(strict=False))
        except OSError:
            return str(path)

    def resolved_no_sandbox(self) -> bool:
        raw = os.environ.get("TURNSTILE_NO_SANDBOX")
        if raw is None or not str(raw).strip():
            return bool(self.no_sandbox)
        try:
            return _config_bool(raw)
        except ValueError as exc:
            raise ValueError(
                "TURNSTILE_NO_SANDBOX 必须是 1/0、true/false、yes/no 或 on/off"
            ) from exc


def load_config(path: Optional[Union[str, Path]] = None) -> SolverConfig:
    if not path:
        return SolverConfig()
    cfg_path = Path(path).expanduser().resolve()
    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"config root must be object: {cfg_path}")
    return SolverConfig.from_dict(data)

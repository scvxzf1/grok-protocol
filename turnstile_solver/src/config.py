from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Union


DEFAULT_SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"


def _config_bool(value: Any, *, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if not text:
        return default
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"无效布尔配置值: {value!r}")


def detect_system_chrome_path() -> str:
    """Best-effort discovery of a local Chrome/Chromium binary."""
    env = str(os.environ.get("TURNSTILE_BROWSER_PATH") or "").strip()
    candidates = []
    if env:
        candidates.append(env)

    # Chrome is normally not added to PATH on Windows.  Probe its standard
    # per-machine and per-user install roots before falling back to command
    # lookup.  Keep these candidates Chrome-only: the canonical HTTP/browser
    # fingerprint currently advertises the Google Chrome product brand, so
    # silently selecting Edge or an unbranded Chromium binary would recreate
    # the very product/UA mismatch this discovery is intended to prevent.
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
    """Read the four-part Chrome version without starting a GUI on Windows."""

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
    """Read Chrome's major version from its executable metadata/version output."""

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
    parent_proxy: str = ""
    proxy_file: str = ""
    local_proxy_port: int = 0
    user_agent: str = ""
    enable_metrics: bool = True
    browser_max_tasks: int = 12
    browser_max_age_sec: int = 900
    browser_idle_ttl_sec: int = 90
    browser_maintenance_interval_sec: float = 5.0
    # Chrome process-tree RSS; shared pages may be counted in multiple children.
    # 1024 MiB keeps a bloated slot from lingering while leaving enough room for
    # Chrome's shared pages being counted once per child by the simple RSS sum.
    browser_max_rss_mb: int = 1024
    browser_max_consecutive_failures: int = 2
    # A 300*/600* Turnstile callback is explicitly retryable.  Retry inside
    # the broker's original deadline so callers do not have to spend another
    # mailbox/registration attempt merely to obtain a fresh browser context.
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
            max_concurrency=max(
                1,
                int(
                    data.get("max_concurrency")
                    or data.get("local_turnstile_max_workers")
                    or 2
                ),
            ),
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
            # The parent project calls this setting turnstile_headless.  Accept
            # both names so a standalone broker and the in-process path agree.
            headless=_config_bool(
                data.get("headless", data.get("turnstile_headless")), default=False
            ),
            proxy=str(data.get("proxy") or ""),
            # Parent chaining is request-scoped and injected only for a leased
            # embedded mihomo listener.  Retired file-config values are ignored.
            parent_proxy="",
            proxy_file=str(data.get("proxy_file") or ""),
            local_proxy_port=int(data.get("local_proxy_port") or 0),
            user_agent=str(data.get("user_agent") or ""),
            enable_metrics=_config_bool(data.get("enable_metrics"), default=True),
            browser_max_tasks=max(1, int(data.get("browser_max_tasks") or 12)),
            browser_max_age_sec=max(60, int(data.get("browser_max_age_sec") or 900)),
            browser_idle_ttl_sec=max(
                0,
                int(
                    90
                    if data.get("browser_idle_ttl_sec") in (None, "")
                    else data.get("browser_idle_ttl_sec")
                ),
            ),
            browser_maintenance_interval_sec=max(
                0.05, float(data.get("browser_maintenance_interval_sec") or 5.0)
            ),
            browser_max_rss_mb=max(
                0,
                int(
                    1024
                    if data.get("browser_max_rss_mb") in (None, "")
                    else data.get("browser_max_rss_mb")
                ),
            ),
            browser_max_consecutive_failures=max(
                1, int(data.get("browser_max_consecutive_failures") or 2)
            ),
            browser_solve_max_attempts=max(
                1,
                min(
                    4,
                    int(
                        2
                        if data.get("browser_solve_max_attempts") in (None, "")
                        else data.get("browser_solve_max_attempts")
                    ),
                ),
            ),
            browser_retry_backoff_sec=max(
                0.0,
                min(
                    10.0,
                    float(
                        1.25
                        if data.get("browser_retry_backoff_sec") in (None, "")
                        else data.get("browser_retry_backoff_sec")
                    ),
                ),
            ),
            lease_ttl_sec=max(1, min(240, int(data.get("lease_ttl_sec") or 240))),
            queue_timeout_sec=max(
                1,
                int(
                    data.get("queue_timeout_sec")
                    or data.get("turnstile_solve_timeout")
                    or 90
                ),
            ),
            strict_fingerprint=_config_bool(data.get("strict_fingerprint"), default=True),
            locale=str(data.get("locale") or ""),
            accept_language=str(data.get("accept_language") or ""),
            external_provider_workers=max(1, int(data.get("external_provider_workers") or 20)),
            external_queue_limit=max(1, int(data.get("external_queue_limit") or 64)),
            submit_workers=max(1, int(data.get("submit_workers") or 5)),
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
        value = str(raw).strip().lower()
        if value in {"1", "true", "yes", "on"}:
            return True
        if value in {"0", "false", "no", "off"}:
            return False
        raise ValueError(
            "TURNSTILE_NO_SANDBOX 必须是 1/0、true/false、yes/no 或 on/off"
        )


def load_config(path: Optional[Union[str, Path]] = None) -> SolverConfig:
    if not path:
        return SolverConfig()
    cfg_path = Path(path).expanduser().resolve()
    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"config root must be object: {cfg_path}")
    return SolverConfig.from_dict(data)

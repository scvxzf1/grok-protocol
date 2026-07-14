#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Grok 注册机 - TTK GUI 版本
整合 DrissionPage_example.py, openai_register.py, batch_open_nsfw.py
"""

# Keep the browserless HTTP entry point independent from Tk/DrissionPage.  This
# branch must run before importing the legacy GUI module graph (and before the
# POSIX-only lock compatibility shim below).
import sys as _bootstrap_sys

if __name__ == "__main__" and len(_bootstrap_sys.argv) > 1 and _bootstrap_sys.argv[1].lower() in {"http", "headless"}:
    from xai_http_flow import main as _http_flow_main

    raise SystemExit(_http_flow_main(_bootstrap_sys.argv[2:]))

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import datetime
import time
import atexit
import os
import sys
import gc
import queue
import secrets
import struct
import random
import re
try:
    import fcntl
except ImportError:
    # The statistics file is best-effort on Windows.  The browserless workflow
    # bypasses this module entirely; this fallback simply keeps the legacy GUI
    # and its existing unit tests importable on Windows.
    class _FcntlCompat:
        LOCK_EX = LOCK_SH = LOCK_UN = 0

        @staticmethod
        def flock(*_args, **_kwargs):
            return None

    fcntl = _FcntlCompat()
from pathlib import Path
import string
import json
import tempfile

os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

def monotonic_now():
    return time.monotonic()


# === 全局统计计数器 ===
# 全局统计文件路径（多进程共享）
STATS_FILE = Path(__file__).parent / ".grok_register_stats.json"
WORKER_STATE_DIR = Path(__file__).parent / ".grok_register_worker_state"
PROXY_HEALTH_FILE = Path(__file__).parent / ".grok_proxy_health.json"


def update_global_stats_batch(success_inc=0, fail_inc=0):
    """批量更新全局统计（多进程安全，使用文件锁）"""
    try:
        with open(STATS_FILE, "a+") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.seek(0)
                content = f.read().strip()
                stats = json.loads(content) if content else {"success": 0, "fail": 0}
            except (json.JSONDecodeError, ValueError):
                stats = {"success": 0, "fail": 0}

            stats["success"] += max(0, int(success_inc or 0))
            stats["fail"] += max(0, int(fail_inc or 0))

            f.seek(0)
            f.truncate()
            json.dump(stats, f, ensure_ascii=False)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            return stats["success"], stats["fail"]
    except Exception as e:
        print(f"[!] 更新全局统计失败: {e}")
        return 0, 0


def update_global_stats(success):
    """更新全局统计（单次 +1 包装）"""
    return update_global_stats_batch(success_inc=1 if success else 0, fail_inc=0 if success else 1)


def get_global_stats():
    """读取全局统计（多进程安全）"""
    try:
        if not STATS_FILE.exists():
            return 0, 0
        with open(STATS_FILE, "r") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                stats = json.load(f)
                return stats.get("success", 0), stats.get("fail", 0)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception:
        return 0, 0


def reset_global_stats():
    """重置全局统计（并发任务开始时调用）"""
    try:
        if STATS_FILE.exists():
            STATS_FILE.unlink()
    except Exception:
        pass


def _worker_state_path(worker_id, run_id=None):
    if run_id is not None and str(run_id).strip():
        return WORKER_STATE_DIR / f"worker_{int(worker_id)}_{str(run_id).strip()}.json"
    return WORKER_STATE_DIR / f"worker_{int(worker_id)}.json"


def _atomic_write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp_path, path)


def reset_worker_states():
    try:
        if not WORKER_STATE_DIR.exists():
            return
        for p in WORKER_STATE_DIR.glob("worker_*.json*"):
            try:
                p.unlink()
            except Exception:
                pass
    except Exception:
        pass


def read_worker_state(worker_id, run_id=None):
    path = _worker_state_path(worker_id, run_id=run_id)
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        if run_id is not None and str(data.get("run_id") or "") != str(run_id):
            return {}
        return data
    except Exception:
        return {}


def write_worker_state(worker_id, run_id=None, **fields):
    try:
        current = read_worker_state(worker_id, run_id=run_id)
        current.update(fields)
        current["worker_id"] = int(worker_id)
        if run_id is not None:
            current["run_id"] = str(run_id)
        current["heartbeat_mono"] = monotonic_now()
        current["heartbeat_ts"] = time.time()
        current["updated_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _atomic_write_json(_worker_state_path(worker_id, run_id=run_id), current)
        return current
    except Exception:
        return {}


def remove_worker_state(worker_id, run_id=None):
    try:
        candidates = []
        if run_id is not None:
            candidates.append(_worker_state_path(worker_id, run_id=run_id))
        candidates.append(_worker_state_path(worker_id))
        for path in candidates:
            if path.exists():
                path.unlink()
    except Exception:
        pass


def _read_nonempty_lines(path):
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        return []


def _email_from_account_line(line):
    text = str(line or "").strip()
    if not text:
        return ""
    if "----" in text:
        return text.split("----", 1)[0].strip()
    return text.split()[0].strip() if text.split() else ""


def count_oauth_credentials_for_accounts(accounts_output_file):
    output_dir = str(config.get("xai_oauth_output_dir", "") or "").strip()
    if not output_dir or not os.path.isdir(output_dir):
        return 0, 0, output_dir
    emails = [e for e in (_email_from_account_line(x) for x in _read_nonempty_lines(accounts_output_file)) if e]
    if not emails:
        return 0, 0, output_dir
    found = 0
    for email in emails:
        if os.path.exists(os.path.join(output_dir, f"xai-{email}.json")):
            found += 1
    return found, len(emails), output_dir


def reconcile_registration_outputs(accounts_output_file, expected_success=None, log_callback=None):
    lines = _read_nonempty_lines(accounts_output_file)
    account_rows = len(lines)
    expected = int(expected_success or 0)
    oauth_found, oauth_expected, oauth_dir = count_oauth_credentials_for_accounts(accounts_output_file)
    mismatch = expected and account_rows != expected
    if log_callback:
        level = "[!]" if mismatch else "[*]"
        log_callback(f"{level} 输出对账 | success计数={expected} | accounts行数={account_rows} | 文件={accounts_output_file}")
        if mismatch:
            log_callback(f"[!] 输出对账发现差异: success计数 - accounts行数 = {expected - account_rows}")
        if oauth_dir:
            oauth_level = "[!]" if oauth_expected and oauth_found != oauth_expected else "[*]"
            log_callback(f"{oauth_level} OAuth凭证对账 | 凭证={oauth_found}/{oauth_expected} | dir={oauth_dir}")
    return {
        "account_rows": account_rows,
        "expected_success": expected,
        "account_mismatch": bool(mismatch),
        "oauth_found": oauth_found,
        "oauth_expected": oauth_expected,
        "oauth_dir": oauth_dir,
    }

from DrissionPage import Chromium, ChromiumOptions
from DrissionPage.errors import PageDisconnectedError
from curl_cffi import requests

from xai_oauth import run_xai_oauth_after_sso
from local_proxy_forwarder import (
    ensure_local_forwarder,
    normalize_proxy_config,
    parse_proxy_string,
    stop_local_forwarder,
)
from proxy_pool import (
    configure_global_rotator,
    get_global_rotator,
    normalize_proxy_line,
    validate_proxy_line,
)
import turnstile_flow as _tf
from turnstile_flow import (
    SCENE_FINAL,
    SCENE_OAUTH,
    SCENE_REGISTER,
    TURNSTILE_MIN_TOKEN_LEN,
    classify_cf_status,
    clear_cf_for_scene,
    clear_turnstile_session_cache,
    ensure_cf_token,
    is_cf_ready,
    log_turnstile_status,
    probe_turnstile_status,
    remember_turnstile_token,
    retry_turnstile_and_sync as _tf_retry_turnstile_and_sync,
    sync_turnstile_token_to_page,
    update_token_stability,
    wait_cf_ready,
)


CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
MEMORY_CLEANUP_INTERVAL = 5

UI_BG = "#242424"
UI_PANEL_BG = "#2b2b2b"
UI_FG = "#f2f2f2"
UI_MUTED_FG = "#b8b8b8"
UI_ENTRY_BG = "#333333"
UI_BUTTON_BG = "#3a3a3a"
UI_ACTIVE_BG = "#4a6078"

DEFAULT_CONFIG = {
    "duckmail_api_key": "",
    "cloudflare_api_base": "",
    "cloudflare_api_key": "",
    "cloudflare_auth_mode": "none",
    "cloudflare_path_domains": "/api/domains",
    "cloudflare_path_accounts": "/api/new_address",
    "cloudflare_path_token": "/api/token",
    "cloudflare_path_messages": "/api/mails",
    "proxy": "http://127.0.0.1:7890",
    "proxies": [],
    "proxy_file": "proxies.txt",
    "proxy_random": True,
    "proxy_rotate_session": True,
    "local_proxy_port": 17890,
    "proxy_preflight_enabled": True,
    "proxy_preflight_url": "https://api.ipify.org?format=json",
    "proxy_preflight_timeout": 12,
    "proxy_blacklist_threshold": 2,
    "proxy_blacklist_minutes": 20,
    "proxy_preflight_max_attempts": 6,
    "browser_restart_strategy": "always",
    "browser_restart_every_n": 5,
    "concurrent_workers": 1,
    "enable_nsfw": True,
    "register_count": 1,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "grok2api_auto_add_local": True,
    "grok2api_local_token_file": "",
    "grok2api_pool_name": "ssoBasic",
    "grok2api_auto_add_remote": False,
    "grok2api_remote_base": "",
    "grok2api_remote_app_key": "",
    "xai_oauth_auto": True,
    "xai_oauth_output_dir": "",
    "xai_oauth_callback_port": 56121,
}

config = DEFAULT_CONFIG.copy()
_cf_domain_index = 0

# Active upstream proxy chosen for the current browser lifetime.
_active_proxy_raw = ""
_active_proxy_display = ""
_last_forwarder_log_key = ""


class RegistrationCancelled(Exception):
    pass


class AccountRetryNeeded(Exception):
    pass


def load_config():
    global config
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                loaded.pop("proxy_parent", None)
            config = {**DEFAULT_CONFIG, **loaded}
        except Exception:
            config = DEFAULT_CONFIG.copy()
    return config


def save_config():
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"保存配置失败: {e}")


def ensure_stable_python_runtime():
    if sys.version_info < (3, 14) or os.environ.get("DPE_REEXEC_DONE") == "1":
        return

    local_app_data = os.environ.get("LOCALAPPDATA", "")
    candidates = [
        os.path.join(local_app_data, "Programs", "Python", "Python312", "python.exe"),
        os.path.join(local_app_data, "Programs", "Python", "Python313", "python.exe"),
    ]

    current_python = os.path.normcase(os.path.abspath(sys.executable))
    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        if os.path.normcase(os.path.abspath(candidate)) == current_python:
            return

        print(
            f"[*] 检测到 Python {sys.version.split()[0]}，自动切换到更稳定的解释器: {candidate}"
        )
        env = os.environ.copy()
        env["DPE_REEXEC_DONE"] = "1"
        os.execve(candidate, [candidate, os.path.abspath(__file__), *sys.argv[1:]], env)


def warn_runtime_compatibility():
    if sys.version_info >= (3, 14):
        print(
            "[提示] 当前 Python 为 3.14+；若出现 Mail.tm TLS 异常，建议改用 Python 3.12 或 3.13。"
        )


ensure_stable_python_runtime()
warn_runtime_compatibility()

load_config()
atexit.register(stop_local_forwarder)

EXTENSION_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "turnstilePatch")
)


DUCKMAIL_API_BASE = "https://api.duckmail.sbs"


def _split_proxy_entries(raw):
    """Split proxy config text into candidate entries.

    Supports:
      - single proxy string
      - multi-line / comma / semicolon / '|' separated list
      - JSON array via config["proxies"]
    """
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        items = []
        for item in raw:
            items.extend(_split_proxy_entries(item))
        return items
    text = str(raw).strip()
    if not text:
        return []
    # JSON array pasted into the proxy field
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return _split_proxy_entries(parsed)
        except Exception:
            pass
    parts = re.split(r"[\n\r,;|]+", text)
    return [p.strip() for p in parts if p and p.strip()]


def _resolve_proxy_file_path():
    """Resolve proxy list file path from config.proxy_file (relative to project dir)."""
    raw = str(config.get("proxy_file", "proxies.txt") or "").strip()
    if not raw:
        return ""
    if os.path.isabs(raw):
        return raw
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), raw)


def load_proxy_file_entries(log_callback=None):
    """Load plain-text proxy list: one proxy per line, # comments allowed, no quotes needed."""
    path = _resolve_proxy_file_path()
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except Exception as exc:
        if log_callback:
            log_callback(f"[!] 读取代理文件失败: {path} | {exc}")
        return []
    items = []
    skipped = 0
    for line in lines:
        s = str(line or "").strip()
        if not s or s.startswith("#"):
            continue
        # allow accidental quotes around a whole line
        if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
            s = s[1:-1].strip()
        normalized, err = validate_proxy_line(s)
        if err or not normalized:
            skipped += 1
            continue
        items.append(normalized)
    if skipped and log_callback:
        log_callback(f"[!] 代理文件跳过无效条目 {skipped} 条（如 host=null）")
    return items


def get_proxy_pool(log_callback=None, *, sync_rotator=True):
    """Collect proxy candidates from proxies.txt + config.proxies + config.proxy.

    Preferred manual config:
      proxies.txt  (plain text, one proxy per line, no JSON quotes)

    Invalid hosts (null/none/empty) are dropped. When sync_rotator=True, the
    process-level ProxyRotator is refreshed from the resulting pool.
    """
    pool = []
    seen = set()
    skipped = 0
    sources = (
        load_proxy_file_entries(log_callback=None),
        config.get("proxies"),
        config.get("proxy"),
    )
    for source in sources:
        for item in _split_proxy_entries(source):
            normalized, err = validate_proxy_line(item)
            if err or not normalized:
                skipped += 1
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            pool.append(normalized)
    if skipped and log_callback:
        log_callback(f"[!] 代理池跳过无效条目 {skipped} 条")
    if sync_rotator:
        try:
            stats = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy_stats.log")
            configure_global_rotator(pool, stats_file=stats)
        except Exception as exc:
            if log_callback:
                log_callback(f"[!] 代理轮换器初始化失败: {exc}")
    return pool


def _format_proxy_for_log(raw, max_len=180):
    """Format proxy for debug logs so the exact pool entry is identifiable.

    Prefer host:port:user:pass form. Keep session id visible; only truncate if extremely long.
    """
    raw = str(raw or "").strip()
    if not raw:
        return ""
    try:
        up = parse_proxy_string(raw)
    except Exception:
        up = None
    if up:
        if up.username or up.password:
            text = f"{up.host}:{up.port}:{up.username}:{up.password}"
        else:
            text = f"{up.host}:{up.port}"
    else:
        text = raw
    if max_len and len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def _proxy_session_tag(raw):
    """Extract trailing country-session tag for compact logs, e.g. US-01268296."""
    try:
        up = parse_proxy_string(raw)
    except Exception:
        up = None
    pwd = (up.password if up else "") or ""
    m = re.search(r"([A-Za-z]{2}-?\d{4,})$", pwd)
    if m:
        return m.group(1)
    if pwd:
        return pwd[-16:]
    return ""


def _mask_proxy_for_log(raw):
    # backward-compatible alias used by older call sites
    return _format_proxy_for_log(raw)


def _rotate_kookeey_session(raw):
    """If proxy password looks like kookeey session form, randomize session id.

    Common forms:
      password-US-12345678
      password-sessid-US-12345678
      password:region-session
    We only rewrite trailing -COUNTRY-NUMBER style session tokens.
    """
    try:
        up = parse_proxy_string(raw)
    except Exception:
        return raw
    if not up or not up.password:
        return raw
    pwd = up.password
    # e.g. 6dd4a906-US-79607439  or  xxx-sess-US-123
    m = re.match(r"^(?P<head>.+-)(?P<cc>[A-Za-z]{2})-(?P<sid>\d{4,})$", pwd)
    if not m:
        # also support ...-US79607439
        m2 = re.match(r"^(?P<head>.+-)(?P<cc>[A-Za-z]{2})(?P<sid>\d{4,})$", pwd)
        if not m2:
            return raw
        head, cc = m2.group("head"), m2.group("cc")
        new_sid = str(random.randint(10000000, 99999999))
        new_pwd = f"{head}{cc}{new_sid}"
    else:
        head, cc = m.group("head"), m.group("cc")
        new_sid = str(random.randint(10000000, 99999999))
        new_pwd = f"{head}{cc}-{new_sid}"

    # rebuild host:port:user:pass preferred for kookeey style
    if "://" not in str(raw) and str(raw).count(":") >= 3:
        return f"{up.host}:{up.port}:{up.username}:{new_pwd}"
    from urllib.parse import quote
    auth = ""
    if up.username or new_pwd:
        auth = f"{quote(up.username or '', safe='')}:{quote(new_pwd, safe='')}@"
    return f"http://{auth}{up.host}:{up.port}"

def _proxy_health_key(raw):
    return _format_proxy_for_log(raw, max_len=0) or str(raw or "").strip()


def _load_proxy_health_unlocked(f):
    try:
        f.seek(0)
        content = f.read().strip()
        data = json.loads(content) if content else {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _update_proxy_health(key, updater):
    if not key:
        return {}
    PROXY_HEALTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(PROXY_HEALTH_FILE, "a+", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        data = _load_proxy_health_unlocked(f)
        item = data.get(key) if isinstance(data.get(key), dict) else {}
        item = updater(dict(item or {})) or {}
        data[key] = item
        f.seek(0)
        f.truncate()
        json.dump(data, f, ensure_ascii=False)
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return item


def get_proxy_health(raw):
    key = _proxy_health_key(raw)
    if not key or not PROXY_HEALTH_FILE.exists():
        return {}
    try:
        with open(PROXY_HEALTH_FILE, "r", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            data = json.load(f) or {}
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        item = data.get(key)
        return item if isinstance(item, dict) else {}
    except Exception:
        return {}


def is_proxy_blacklisted(raw):
    item = get_proxy_health(raw)
    until = float(item.get("blacklist_until") or 0)
    return until > time.time(), until, item


def record_proxy_preflight_success(raw):
    key = _proxy_health_key(raw)
    def _ok(item):
        item["failures"] = 0
        item["last_success_at"] = time.time()
        item["blacklist_until"] = 0
        item["last_error"] = ""
        return item
    return _update_proxy_health(key, _ok)


def record_proxy_preflight_failure(raw, error):
    key = _proxy_health_key(raw)
    threshold = max(1, int(config.get("proxy_blacklist_threshold", 2) or 2))
    minutes = max(1, int(config.get("proxy_blacklist_minutes", 20) or 20))
    def _fail(item):
        failures = int(item.get("failures") or 0) + 1
        item["failures"] = failures
        item["last_failure_at"] = time.time()
        item["last_error"] = str(error or "")[:300]
        if failures >= threshold:
            item["blacklist_until"] = time.time() + minutes * 60
        return item
    return _update_proxy_health(key, _fail)


def preflight_proxy(raw, log_callback=None, health_raw=None):
    if not bool(config.get("proxy_preflight_enabled", True)):
        return True
    proxy_url = normalize_proxy_config(raw) or str(raw or "").strip()
    health_target = health_raw if health_raw is not None else raw
    if not proxy_url:
        return True
    url = str(config.get("proxy_preflight_url", "https://api.ipify.org?format=json") or "").strip()
    timeout = max(3, int(config.get("proxy_preflight_timeout", 12) or 12))
    started = monotonic_now()
    try:
        resp = requests.get(url, proxies={"http": proxy_url, "https": proxy_url}, timeout=timeout, impersonate="chrome120")
        elapsed_ms = int((monotonic_now() - started) * 1000)
        if 200 <= int(resp.status_code) < 300:
            record_proxy_preflight_success(health_target)
            if log_callback:
                preview = str(getattr(resp, "text", "") or "").strip().replace("\n", " ")[:80]
                log_callback(f"[*] 代理预检通过 | {elapsed_ms}ms | {preview}")
            return True
        raise RuntimeError(f"HTTP {resp.status_code}: {response_preview(resp)}")
    except Exception as exc:
        item = record_proxy_preflight_failure(health_target, exc)
        if log_callback:
            failures = int(item.get("failures") or 0)
            until = float(item.get("blacklist_until") or 0)
            tail = ""
            if until > time.time():
                remain = int(max(0, until - time.time()))
                tail = f" | 已临时隔离 {remain}s"
            log_callback(f"[!] 代理预检失败 | failures={failures} | {exc}{tail}")
        return False


def report_proxy_outcome(success: bool, reason: str = "", proxy_raw: str = "") -> None:
    """Feed registration / preflight outcome into the GPT-style ProxyRotator."""
    target = str(proxy_raw or _active_proxy_raw or "").strip()
    if not target:
        return
    try:
        rotator = get_global_rotator()
        if rotator is None:
            return
        pool = list(rotator.proxies())
        key = target
        if target not in pool:
            norm = normalize_proxy_line(target)
            if norm in pool:
                key = norm
            else:
                host = ""
                try:
                    up = parse_proxy_string(target)
                    host = f"{up.host}:{up.port}" if up else ""
                except Exception:
                    host = ""
                if host:
                    for item in pool:
                        if host in item:
                            key = item
                            break
        rotator.record_result(key, bool(success), reason=str(reason or "")[:120])
        if success:
            rotator.mark_good(key)
        else:
            rotator.mark_bad(key)
    except Exception:
        pass


def select_proxy_for_browser(log_callback=None, force_new=True):
    """Pick an upstream proxy for the next browser launch.

    - Prefer GPT-style ProxyRotator (country weight + dynamic cooldown)
    - Fall back to random/fixed scan with preflight + blacklist
    - If proxy_rotate_session=true: randomize kookeey-like session id
    - Stores selection in module globals for get_runtime_proxy_url()
    """
    global _active_proxy_raw, _active_proxy_display
    pool = get_proxy_pool(log_callback=log_callback, sync_rotator=True)
    if not pool:
        _active_proxy_raw = ""
        _active_proxy_display = ""
        stop_local_forwarder()
        if log_callback:
            log_callback("[*] 当前未配置代理")
        return ""

    do_random = bool(config.get("proxy_random", True))
    attempts = min(len(pool), max(1, int(config.get("proxy_preflight_max_attempts", 6) or 6)))
    rotator = get_global_rotator()

    ordered = []
    seen = set()
    if rotator is not None and len(rotator) > 0 and (do_random or force_new):
        for _ in range(min(len(pool), max(attempts * 2, 4))):
            cand = rotator.next()
            if not cand or cand in seen:
                continue
            seen.add(cand)
            ordered.append(cand)
    rest = list(pool)
    if do_random:
        random.shuffle(rest)
    elif _active_proxy_raw and _active_proxy_raw in rest and not force_new:
        rest.remove(_active_proxy_raw)
        rest.insert(0, _active_proxy_raw)
    for item in rest:
        if item not in seen:
            ordered.append(item)

    chosen = ""
    rotated = ""
    skipped_blacklist = 0
    tested = 0
    for candidate in ordered:
        blacklisted, until, _item = is_proxy_blacklisted(candidate)
        if blacklisted:
            skipped_blacklist += 1
            continue
        tested += 1
        candidate_rotated = _rotate_kookeey_session(candidate) if bool(config.get("proxy_rotate_session", True)) else candidate
        if preflight_proxy(candidate_rotated, log_callback=log_callback, health_raw=candidate):
            chosen = candidate
            rotated = candidate_rotated
            report_proxy_outcome(True, "preflight_ok", proxy_raw=candidate)
            break
        report_proxy_outcome(False, "preflight_fail", proxy_raw=candidate)
        if tested >= attempts:
            break

    if not chosen:
        fallback_pool = [p for p in ordered if not is_proxy_blacklisted(p)[0]] or ordered
        if rotator is not None and len(rotator) > 0:
            chosen = rotator.next() or (fallback_pool[0] if fallback_pool else "")
        else:
            chosen = fallback_pool[0] if not do_random else random.choice(fallback_pool)
        rotated = _rotate_kookeey_session(chosen) if bool(config.get("proxy_rotate_session", True)) else chosen
        if log_callback:
            log_callback(f"[!] 未找到预检通过代理，使用候选继续 | skipped_blacklist={skipped_blacklist} tested={tested}")

    try:
        pool_index = pool.index(chosen) + 1
    except ValueError:
        pool_index = 0

    _active_proxy_raw = rotated
    _active_proxy_display = _format_proxy_for_log(rotated)
    stop_local_forwarder()
    if log_callback:
        pool_n = len(pool)
        mode = "rotator" if rotator is not None else ("random" if do_random else "fixed")
        proxy_file = _resolve_proxy_file_path()
        file_hint = os.path.basename(proxy_file) if proxy_file and os.path.exists(proxy_file) else "-"
        chosen_disp = _format_proxy_for_log(chosen)
        active_disp = _format_proxy_for_log(rotated)
        chosen_tag = _proxy_session_tag(chosen)
        active_tag = _proxy_session_tag(rotated)
        idx_txt = f"#{pool_index}/{pool_n}" if pool_index else f"#?/{pool_n}"
        log_callback(
            f"[*] 代理已选择 {idx_txt} | mode={mode} | file={file_hint} | 条目={chosen_disp}"
        )
        if skipped_blacklist:
            log_callback(f"[*] 代理黑名单跳过 {skipped_blacklist} 条")
        if rotated != chosen:
            log_callback(
                f"[*] 代理会话已轮换 {chosen_tag or '-'} -> {active_tag or '-'} | 实际使用={active_disp}"
            )
        else:
            log_callback(f"[*] 代理实际使用={active_disp}")
    return _active_proxy_raw


def get_selected_proxy_raw(log_callback=None, ensure=True):
    global _active_proxy_raw
    if ensure and not str(_active_proxy_raw or "").strip():
        select_proxy_for_browser(log_callback=log_callback, force_new=True)
    return str(_active_proxy_raw or "").strip()


def get_runtime_proxy_url(log_callback=None):
    """Resolve selected upstream proxy into an effective proxy URL for browser/API.

    Authenticated proxies are automatically exposed via local no-auth forwarder
    on 127.0.0.1 so Chrome/DrissionPage can use them.
    """
    global _last_forwarder_log_key
    raw = get_selected_proxy_raw(log_callback=log_callback, ensure=True)
    if not raw:
        stop_local_forwarder()
        _last_forwarder_log_key = ""
        return ""
    try:
        preferred = int(config.get("local_proxy_port", 17890) or 17890)
        worker_id = int(config.get("_worker_id", 0) or 0)
        instance_key = f"worker-{worker_id}" if worker_id > 0 else "default"
        effective, used_fwd = ensure_local_forwarder(
            raw,
            preferred_local_port=preferred,
            instance_key=instance_key,
        )
    except Exception as exc:
        if log_callback:
            log_callback(f"[!] 本地代理转发启动失败: {exc}")
        # fall back to normalized raw url for HTTP clients
        try:
            return normalize_proxy_config(raw)
        except Exception:
            return raw
    if used_fwd and log_callback:
        key = f"{effective}|{raw}"
        if key != _last_forwarder_log_key:
            try:
                up = parse_proxy_string(raw)
                up_desc = f"{up.host}:{up.port}" if up else _mask_proxy_for_log(raw)
            except Exception:
                up_desc = _mask_proxy_for_log(raw)
            log_callback(f"[*] 已启动本机代理转发 {effective} -> {up_desc}")
            _last_forwarder_log_key = key
    return effective


def get_proxies(log_callback=None):
    proxy = get_runtime_proxy_url(log_callback=log_callback)
    if proxy:
        return {"http": proxy, "https": proxy}
    return {}


def get_duckmail_api_key():
    return config.get("duckmail_api_key", "")


def get_cloudflare_api_base():
    return str(config.get("cloudflare_api_base", "") or "").rstrip("/")


def get_cloudflare_api_key():
    return config.get("cloudflare_api_key", "")


def get_cloudflare_auth_mode():
    return str(config.get("cloudflare_auth_mode", "none") or "none").lower()


def get_cloudflare_path(key, default_path):
    raw = str(config.get(key, default_path) or default_path).strip()
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw


def cloudflare_build_headers(content_type=False):
    headers = {"Content-Type": "application/json"} if content_type else {}
    key = get_cloudflare_api_key()
    mode = get_cloudflare_auth_mode()
    if key:
        if mode == "x-api-key":
            headers["X-API-Key"] = key
        elif mode == "x-admin-auth":
            headers["x-admin-auth"] = key
        elif mode != "none":
            headers["Authorization"] = f"Bearer {key}"
    return headers


def cloudflare_apply_auth_params(params=None):
    merged = dict(params or {})
    key = get_cloudflare_api_key()
    mode = get_cloudflare_auth_mode()
    if key and mode == "query-key":
        merged["key"] = key
    return merged


def cloudflare_next_default_domain():
    """按配置轮换选择 Cloudflare 临时邮箱域名。"""
    global _cf_domain_index
    domains = [x.strip() for x in str(config.get("defaultDomains", "") or "").split(",") if x.strip()]
    if not domains:
        return ""
    domain = domains[_cf_domain_index % len(domains)]
    _cf_domain_index += 1
    return domain


def cloudflare_is_admin_create_path(path):
    """判断当前创建邮箱路径是否为 cloudflare_temp_email 管理员创建接口。"""
    return str(path or "").rstrip("/").lower() == "/admin/new_address"


def _pick_list_payload(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            return data.get("results")
        if isinstance(data.get("hydra:member"), list):
            return data.get("hydra:member")
        if isinstance(data.get("data"), list):
            return data.get("data")
        if isinstance(data.get("messages"), list):
            return data.get("messages")
        if isinstance(data.get("data"), dict):
            nested = data.get("data")
            if isinstance(nested.get("messages"), list):
                return nested.get("messages")
    return []


def cloudflare_create_temp_address(api_base):
    """适配 cloudflare_temp_email 新建地址接口并兼容 admin 创建模式。"""
    path = get_cloudflare_path("cloudflare_path_accounts", "/api/new_address")
    url = f"{api_base}{path}"
    domain = cloudflare_next_default_domain()
    is_admin_create = cloudflare_is_admin_create_path(path)
    if is_admin_create:
        payload = {"name": generate_username(10), "enablePrefix": True}
        if domain:
            payload["domain"] = domain
        headers = cloudflare_build_headers(content_type=True)
    else:
        payload = {}
        if domain:
            payload["domain"] = domain
        headers = {"Content-Type": "application/json"}
    resp = http_post(url, json=payload, headers=headers)
    resp.raise_for_status()
    try:
        data = resp.json()
    except Exception:
        raise Exception(f"Cloudflare {path} 返回非JSON: {resp.text[:300]}")
    address = data.get("address")
    jwt = data.get("jwt")
    if not address or not jwt:
        raise Exception(f"Cloudflare {path} 缺少 address/jwt: {data}")
    return address, jwt


def get_user_agent():
    return config.get(
        "user_agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    )


def resolve_grok2api_local_token_file():
    configured = str(config.get("grok2api_local_token_file", "") or "").strip()
    if configured:
        return configured
    return os.path.join(os.path.dirname(__file__), "token.json")


def _normalize_sso_token(raw_token):
    token = str(raw_token or "").strip()
    if token.startswith("sso="):
        token = token[4:]
    return token


def add_token_to_grok2api_local_pool(raw_token, email="", log_callback=None):
    token = _normalize_sso_token(raw_token)
    if not token:
        return False
    token_file = resolve_grok2api_local_token_file()
    pool_name = str(config.get("grok2api_pool_name", "ssoBasic") or "ssoBasic").strip()
    if not pool_name:
        pool_name = "ssoBasic"
    os.makedirs(os.path.dirname(token_file), exist_ok=True)
    data = {}
    if os.path.exists(token_file):
        try:
            with open(token_file, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
        except Exception:
            data = {}
    if not isinstance(data, dict):
        data = {}
    pool = data.get(pool_name)
    if not isinstance(pool, list):
        pool = []
    existing = set()
    for item in pool:
        if isinstance(item, str):
            existing.add(_normalize_sso_token(item))
        elif isinstance(item, dict):
            existing.add(_normalize_sso_token(item.get("token", "")))
    if token in existing:
        if log_callback:
            log_callback(f"[*] grok2api 本地池已存在 token: {pool_name}")
        return True
    entry = {"token": token, "tags": ["auto-register"], "note": email}
    pool.append(entry)
    data[pool_name] = pool
    with open(token_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    if log_callback:
        log_callback(f"[+] 已写入 grok2api 本地池: {pool_name} ({token_file})")
    return True


def get_grok2api_remote_api_bases(base):
    """生成 grok2api 管理 API 候选根路径。

    参数:
      - base str: 用户配置的 grok2api 远端地址

    返回:
      - list[str]: 依次尝试的管理 API 根路径
    """
    normalized = str(base or "").strip().rstrip("/")
    if not normalized:
        return []
    lower = normalized.lower()
    candidates = [normalized]
    if lower.endswith("/admin/api"):
        return candidates
    if lower.endswith("/admin"):
        candidates.append(f"{normalized}/api")
    else:
        candidates.append(f"{normalized}/admin/api")
    seen = set()
    unique = []
    for item in candidates:
        if item not in seen:
            unique.append(item)
            seen.add(item)
    return unique


def add_token_to_grok2api_remote_pool(raw_token, email="", log_callback=None):
    token = _normalize_sso_token(raw_token)
    if not token:
        return False
    base = str(config.get("grok2api_remote_base", "") or "").strip().rstrip("/")
    app_key = str(config.get("grok2api_remote_app_key", "") or "").strip()
    pool_name = str(config.get("grok2api_pool_name", "ssoBasic") or "ssoBasic").strip() or "ssoBasic"
    if not base or not app_key:
        if log_callback:
            log_callback("[Debug] grok2api 远端未配置 base/app_key，跳过")
        return False
    headers = {"Content-Type": "application/json"}
    query = {"app_key": app_key}
    pool_map = {"ssoBasic": "basic", "ssoSuper": "super"}
    remote_pool = pool_map.get(pool_name, "basic")
    api_bases = get_grok2api_remote_api_bases(base)
    add_errors = []
    # 优先使用 add 接口，避免全量覆盖远端池
    add_payload = {"tokens": [token], "pool": remote_pool, "tags": ["auto-register"]}
    for api_base in api_bases:
        endpoint = f"{api_base}/tokens/add"
        try:
            resp_add = http_post(
                endpoint,
                headers=headers,
                params=query,
                json=add_payload,
                timeout=30,
                proxies={},
            )
            resp_add.raise_for_status()
            if log_callback:
                log_callback(f"[+] 已写入 grok2api 远端池: {pool_name} ({endpoint})")
            return True
        except Exception as add_exc:
            add_errors.append(f"{endpoint}: {add_exc}")
    if log_callback:
        log_callback(f"[Debug] /tokens/add 写入失败，尝试 /tokens 全量模式: {'; '.join(add_errors)}")

    # 兜底：旧版全量保存接口
    current = {}
    fallback_base = api_bases[0] if api_bases else base
    for api_base in api_bases or [base]:
        try:
            resp = http_get(f"{api_base}/tokens", headers=headers, params=query, timeout=20, proxies={})
            if resp.status_code == 200:
                payload = resp.json()
                current = payload.get("tokens", {}) if isinstance(payload, dict) else {}
                fallback_base = api_base
                break
        except Exception:
            continue
    if not isinstance(current, dict):
        current = {}
    pool = current.get(pool_name)
    if not isinstance(pool, list):
        pool = []
    existing = set()
    for item in pool:
        if isinstance(item, str):
            existing.add(_normalize_sso_token(item))
        elif isinstance(item, dict):
            existing.add(_normalize_sso_token(item.get("token", "")))
    if token not in existing:
        pool.append({"token": token, "tags": ["auto-register"], "note": email})
    current[pool_name] = pool
    save_errors = []
    save_bases = []
    for item in [fallback_base, *(api_bases or [base])]:
        if item and item not in save_bases:
            save_bases.append(item)
    for api_base in save_bases:
        try:
            resp2 = http_post(f"{api_base}/tokens", headers=headers, params=query, json=current, timeout=30, proxies={})
            resp2.raise_for_status()
            if log_callback:
                log_callback(f"[+] 已写入 grok2api 远端池: {pool_name} ({api_base}/tokens)")
            return True
        except Exception as save_exc:
            save_errors.append(f"{api_base}/tokens: {save_exc}")
    raise RuntimeError(f"grok2api 远端 /tokens 全量模式写入失败: {'; '.join(save_errors)}")


def add_token_to_grok2api_pools(raw_token, email="", log_callback=None):
    if config.get("grok2api_auto_add_local", True):
        try:
            add_token_to_grok2api_local_pool(raw_token, email=email, log_callback=log_callback)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] 写入 grok2api 本地池失败: {exc}")
    if config.get("grok2api_auto_add_remote", False):
        try:
            add_token_to_grok2api_remote_pool(raw_token, email=email, log_callback=log_callback)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] 写入 grok2api 远端池失败: {exc}")


def create_browser_options(log_callback=None):
    options = ChromiumOptions()
    options.auto_port()
    options.set_timeouts(base=1)
    if os.path.exists(EXTENSION_PATH):
        options.add_extension(EXTENSION_PATH)

    # Browser proxy: use local no-auth forwarder for authenticated upstreams
    proxy_url = get_runtime_proxy_url(log_callback=log_callback)
    if proxy_url:
        # Chrome cannot reliably consume user:pass@host; forwarder returns 127.0.0.1 URL
        if "@" in proxy_url.split("://", 1)[-1]:
            if log_callback:
                log_callback("[!] 浏览器暂不支持带账号密码的代理 URL，请使用本机转发（方案1）")
        else:
            try:
                options.set_proxy(proxy_url)
                if log_callback:
                    upstream = _format_proxy_for_log(get_selected_proxy_raw(ensure=False))
                    if upstream:
                        log_callback(f"[*] 浏览器已设置代理: {proxy_url}  (上游 {upstream})")
                    else:
                        log_callback(f"[*] 浏览器已设置代理: {proxy_url}")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[!] 浏览器设置代理失败: {exc}")
    return options


def _build_request_kwargs(**kwargs):
    request_kwargs = dict(kwargs)
    proxies = request_kwargs.pop("proxies", None)
    if proxies is None:
        proxies = get_proxies()
    if proxies:
        request_kwargs["proxies"] = proxies
    request_kwargs.setdefault("timeout", 15)
    return request_kwargs


def http_get(url, **kwargs):
    try:
        return requests.get(url, **_build_request_kwargs(**kwargs))
    except Exception as exc:
        err = str(exc)
        # 代理不可用时自动回退为直连，避免整个流程直接失败
        if "127.0.0.1 port 7890" in err or "Could not connect to server" in err:
            retry_kwargs = dict(kwargs)
            retry_kwargs["proxies"] = {}
            return requests.get(url, **_build_request_kwargs(**retry_kwargs))
        raise


def http_post(url, **kwargs):
    try:
        return requests.post(url, **_build_request_kwargs(**kwargs))
    except Exception as exc:
        err = str(exc)
        if "127.0.0.1 port 7890" in err or "Could not connect to server" in err:
            retry_kwargs = dict(kwargs)
            retry_kwargs["proxies"] = {}
            return requests.post(url, **_build_request_kwargs(**retry_kwargs))
        raise


def raise_if_cancelled(cancel_callback=None):
    if cancel_callback and cancel_callback():
        raise RegistrationCancelled("鐢ㄦ埛鍋滄娉ㄥ唽")


def sleep_with_cancel(seconds, cancel_callback=None):
    deadline = monotonic_now() + max(seconds, 0)
    while True:
        raise_if_cancelled(cancel_callback)
        remaining = deadline - monotonic_now()
        if remaining <= 0:
            return
        time.sleep(min(0.2, remaining))


def get_domains(api_key=None):
    headers = {}
    key = api_key or get_duckmail_api_key()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    resp = http_get(f"{DUCKMAIL_API_BASE}/domains", headers=headers)
    resp.raise_for_status()
    return resp.json().get("hydra:member", [])


def create_account(address, password, api_key=None, expires_in=0):
    headers = {"Content-Type": "application/json"}
    key = api_key or get_duckmail_api_key()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    data = {"address": address, "password": password, "expiresIn": expires_in}
    resp = http_post(f"{DUCKMAIL_API_BASE}/accounts", json=data, headers=headers)
    resp.raise_for_status()
    return resp.json()


def get_token(address, password):
    data = {"address": address, "password": password}
    resp = http_post(f"{DUCKMAIL_API_BASE}/token", json=data)
    resp.raise_for_status()
    return resp.json().get("token")


def get_messages(token):
    headers = {"Authorization": f"Bearer {token}"}
    resp = http_get(f"{DUCKMAIL_API_BASE}/messages", headers=headers)
    resp.raise_for_status()
    return resp.json().get("hydra:member", [])


def get_message_detail(token, message_id):
    headers = {"Authorization": f"Bearer {token}"}
    resp = http_get(f"{DUCKMAIL_API_BASE}/messages/{message_id}", headers=headers)
    resp.raise_for_status()
    return resp.json()


def cloudflare_get_domains(api_base, api_key=None):
    headers = cloudflare_build_headers(content_type=False)
    if api_key and "Authorization" in headers:
        headers["Authorization"] = f"Bearer {api_key}"
    if api_key and "X-API-Key" in headers:
        headers["X-API-Key"] = api_key
    path = get_cloudflare_path("cloudflare_path_domains", "/domains")
    params = cloudflare_apply_auth_params()
    resp = http_get(f"{api_base}{path}", headers=headers, params=params)
    resp.raise_for_status()
    return _pick_list_payload(resp.json())


def cloudflare_create_account(api_base, address, password, api_key=None, expires_in=0):
    headers = cloudflare_build_headers(content_type=True)
    if api_key and "Authorization" in headers:
        headers["Authorization"] = f"Bearer {api_key}"
    if api_key and "X-API-Key" in headers:
        headers["X-API-Key"] = api_key
    payload = {"address": address, "password": password, "expiresIn": expires_in}
    path = get_cloudflare_path("cloudflare_path_accounts", "/accounts")
    params = cloudflare_apply_auth_params()
    resp = http_post(f"{api_base}{path}", json=payload, headers=headers, params=params)
    resp.raise_for_status()
    return resp.json()


def cloudflare_get_token(api_base, address, password, api_key=None):
    headers = cloudflare_build_headers(content_type=True)
    if api_key and "Authorization" in headers:
        headers["Authorization"] = f"Bearer {api_key}"
    if api_key and "X-API-Key" in headers:
        headers["X-API-Key"] = api_key
    path = get_cloudflare_path("cloudflare_path_token", "/token")
    resp = http_post(
        f"{api_base}{path}",
        json={"address": address, "password": password},
        headers=headers,
        params=cloudflare_apply_auth_params(),
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict):
        if data.get("token"):
            return data.get("token")
        if isinstance(data.get("data"), dict) and data["data"].get("token"):
            return data["data"].get("token")
    return None


def cloudflare_get_messages(api_base, token):
    headers = {"Authorization": f"Bearer {token}"}
    path = get_cloudflare_path("cloudflare_path_messages", "/messages")
    params = {"limit": 20, "offset": 0}
    params = cloudflare_apply_auth_params(params)
    resp = http_get(f"{api_base}{path}", headers=headers, params=params)
    resp.raise_for_status()
    try:
        data = resp.json()
    except Exception:
        raise Exception(f"Cloudflare messages 返回非JSON: {resp.text[:300]}")
    return _pick_list_payload(data)


def cloudflare_get_message_detail(api_base, token, message_id):
    headers = {"Authorization": f"Bearer {token}"}
    candidates = [
        f"{api_base}/api/mail/{message_id}",
        f"{api_base}{get_cloudflare_path('cloudflare_path_messages', '/messages')}/{message_id}",
    ]
    last_err = None
    for url in candidates:
        try:
            resp = http_get(
                url,
                headers=headers,
                params=cloudflare_apply_auth_params(),
            )
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict) and isinstance(data.get("data"), dict):
                return data["data"]
            return data
        except Exception as exc:
            last_err = exc
            continue
    raise Exception(f"Cloudflare 获取邮件详情失败: {last_err}")


YYDS_API_BASE = "https://maliapi.215.im/v1"


def get_yyds_api_key():
    return config.get("yyds_api_key", "")


def get_yyds_jwt():
    return config.get("yyds_jwt", "")


def yyds_get_domains(api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif key:
        headers["X-API-Key"] = key
    resp = http_get(f"{YYDS_API_BASE}/domains", headers=headers)
    resp.raise_for_status()
    data = resp.json()
    return data.get("data", []) if data.get("success") else []


def yyds_create_account(address=None, domain=None, api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif key:
        headers["X-API-Key"] = key
    payload = {}
    if address:
        payload["address"] = address
    if domain:
        payload["domain"] = domain
    elif key or token:
        payload["autoDomainStrategy"] = "prefer_owned"
    resp = http_post(f"{YYDS_API_BASE}/accounts", json=payload, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {})
    raise Exception(f"YYDS 鍒涘缓閭澶辫触: {data}")


def yyds_get_token(address, api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif key:
        headers["X-API-Key"] = key
    resp = http_post(
        f"{YYDS_API_BASE}/token", json={"address": address}, headers=headers
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {}).get("token")
    raise Exception(f"YYDS 鑾峰彇token澶辫触: {data}")


def yyds_get_messages(address, token=None, api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    temp_token = token or jwt or get_yyds_jwt()
    headers = {}
    if temp_token:
        headers["Authorization"] = f"Bearer {temp_token}"
    elif key:
        headers["X-API-Key"] = key
    resp = http_get(
        f"{YYDS_API_BASE}/messages",
        params={"address": address},
        headers=headers,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {}).get("messages", [])
    return []


def yyds_get_message_detail(message_id, token=None, api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    temp_token = token or jwt or get_yyds_jwt()
    headers = {}
    if temp_token:
        headers["Authorization"] = f"Bearer {temp_token}"
    elif key:
        headers["X-API-Key"] = key
    resp = http_get(f"{YYDS_API_BASE}/messages/{message_id}", headers=headers)
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {})
    raise Exception(f"YYDS 鑾峰彇閭欢璇︽儏澶辫触: {data}")


def yyds_generate_username(length=10):
    chars = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))



_YYDS_DOMAIN_RR_LOCK = Path(tempfile.gettempdir()) / "xai-yyds-domain-rr.lock"
_YYDS_DOMAIN_RR_STATE = Path(tempfile.gettempdir()) / "xai-yyds-domain-rr-state.json"


def _yyds_next_domain_rr(domains):
    cleaned = [str(d).strip() for d in domains if str(d or "").strip()]
    if not cleaned:
        raise Exception("YYDS 域名池为空")
    if len(cleaned) == 1:
        return cleaned[0]
    _YYDS_DOMAIN_RR_LOCK.parent.mkdir(parents=True, exist_ok=True)
    with open(_YYDS_DOMAIN_RR_LOCK, "a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            idx = 0
            try:
                raw = _YYDS_DOMAIN_RR_STATE.read_text(encoding="utf-8").strip()
                if raw:
                    idx = int(json.loads(raw).get("index") or 0)
            except Exception:
                idx = 0
            if idx < 0:
                idx = 0
            pick = cleaned[idx % len(cleaned)]
            _YYDS_DOMAIN_RR_STATE.write_text(
                json.dumps({"index": idx + 1}, ensure_ascii=False),
                encoding="utf-8",
            )
            return pick
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def yyds_pick_domain(api_key=None, jwt=None):
    domains = yyds_get_domains(api_key=api_key, jwt=jwt)
    if not domains:
        raise Exception("YYDS 没有返回任何可用域名")
    private = [d for d in domains if d.get("isVerified") and not d.get("isPublic")]
    public = [d for d in domains if d.get("isVerified") and d.get("isPublic")]
    verified = [d for d in domains if d.get("isVerified")]
    pool = []
    for group in (private, public, verified, domains):
        names = []
        seen = set()
        for item in group:
            domain = str(item.get("domain") or "").strip()
            if not domain:
                continue
            key = domain.lower()
            if key in seen:
                continue
            seen.add(key)
            names.append(domain)
        if names:
            pool = names
            break
    if not pool:
        raise Exception("YYDS 无已验证域名可用")
    return _yyds_next_domain_rr(pool)

def yyds_get_email_and_token(api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    if not token and not key:
        raise Exception("YYDS API Key 或 JWT 未配置")
    domain = yyds_pick_domain(api_key=key, jwt=token)
    username = yyds_generate_username(10)
    result = yyds_create_account(
        address=username, domain=domain, api_key=key, jwt=token
    )
    address = result.get("address") or f"{username}@{domain}"
    temp_token = result.get("token")
    if not temp_token:
        temp_token = yyds_get_token(address, api_key=key, jwt=token)
    if not temp_token:
        raise Exception("鑾峰彇 YYDS token 澶辫触")
    print(f"[*] 宸插垱寤?YYDS 閭: {address}")
    return address, temp_token


def yyds_get_oai_code(
    token,
    address,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    jwt=None,
    cancel_callback=None,
):
    deadline = monotonic_now() + timeout
    seen_ids = set()
    while monotonic_now() < deadline:
        raise_if_cancelled(cancel_callback)
        try:
            messages = yyds_get_messages(address, token=token, jwt=jwt)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] YYDS 鎷夊彇閭欢鍒楄〃澶辫触: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        for msg in messages:
            msg_id = msg.get("id")
            if not msg_id or msg_id in seen_ids:
                continue
            seen_ids.add(msg_id)
            to_addrs = [t.get("address", "").lower() for t in (msg.get("to") or [])]
            if address.lower() not in to_addrs:
                continue
            try:
                detail = yyds_get_message_detail(msg_id, token=token, jwt=jwt)
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] YYDS 鑾峰彇閭欢璇︽儏澶辫触: {exc}")
                continue
            parts = []
            text_body = detail.get("text") or ""
            if text_body:
                parts.append(text_body)
            html_list = detail.get("html") or []
            for h in html_list:
                parts.append(re.sub(r"<[^>]+>", " ", h))
            combined = "\n".join(parts)
            subject = detail.get("subject", "")
            if log_callback:
                log_callback(f"[Debug] YYDS 鏀跺埌閭欢: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] YYDS 浠庨偖浠朵腑鎻愬彇鍒伴獙璇佺爜: {code}")
                return code
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"YYDS 在 {timeout}s 内未收到验证码邮件")


def generate_username(length=10):
    chars = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def pick_domain(api_key=None):
    domains = get_domains(api_key=api_key)
    if not domains:
        raise Exception("DuckMail 娌℃湁杩斿洖浠讳綍鍙敤鍩熷悕")
    private = [d for d in domains if d.get("ownerId")]
    verified_private = [d for d in private if d.get("isVerified")]
    if verified_private:
        return verified_private[0]["domain"]
    public = [d for d in domains if d.get("isVerified")]
    if public:
        return public[0]["domain"]
    raise Exception("DuckMail 鏃犲凡楠岃瘉鍩熷悕鍙敤")


def get_email_provider():
    return config.get("email_provider", "duckmail")


def get_email_and_token(api_key=None):
    provider = get_email_provider()
    if provider == "yyds":
        return yyds_get_email_and_token(api_key=api_key, jwt=get_yyds_jwt())
    if provider == "cloudflare":
        api_base = get_cloudflare_api_base()
        if not api_base:
            raise Exception("Cloudflare API Base 未配置")
        try:
            # cloudflare_temp_email 专用模式
            return cloudflare_create_temp_address(api_base)
        except Exception as primary_exc:
            # 兜底回退到 Mail.tm 风格
            key = api_key or get_cloudflare_api_key()
            domains = cloudflare_get_domains(api_base, api_key=key)
            if not domains:
                raise Exception(f"Cloudflare 创建邮箱失败: {primary_exc}")
            verified = [d for d in domains if d.get("isVerified")]
            target = verified[0] if verified else domains[0]
            domain = target.get("domain")
            if not domain:
                raise Exception("Cloudflare 域名数据格式错误，缺少 domain 字段")
            username = generate_username(10)
            address = f"{username}@{domain}"
            password = secrets.token_urlsafe(12)
            cloudflare_create_account(
                api_base, address, password, api_key=key, expires_in=0
            )
            token = cloudflare_get_token(api_base, address, password, api_key=key)
            if not token:
                raise Exception("获取 Cloudflare 邮箱 token 失败")
            return address, token
    key = api_key or get_duckmail_api_key()
    domain = pick_domain(api_key=key)
    username = generate_username(10)
    address = f"{username}@{domain}"
    password = secrets.token_urlsafe(12)
    create_account(address, password, api_key=key, expires_in=0)
    token = get_token(address, password)
    if not token:
        raise Exception("鑾峰彇 DuckMail token 澶辫触")
    return address, token


def get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    provider = get_email_provider()
    if provider == "yyds":
        return yyds_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            jwt=get_yyds_jwt(),
            cancel_callback=cancel_callback,
        )
    if provider == "cloudflare":
        return cloudflare_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
        )
    return duckmail_get_oai_code(
        dev_token,
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )


def extract_verification_code(text, subject=""):
    if subject:
        match = re.search(r"^([A-Z0-9]{3}-[A-Z0-9]{3})\s+xAI", subject, re.IGNORECASE)
        if match:
            return match.group(1)
    match = re.search(r"\b([A-Z0-9]{3}-[A-Z0-9]{3})\b", text, re.IGNORECASE)
    if match:
        return match.group(1)
    patterns = [
        r"verification\s+code[:\s]+(\d{4,8})",
        r"your\s+code[:\s]+(\d{4,8})",
        r"confirm(?:ation)?\s+code[:\s]+(\d{4,8})",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def duckmail_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
):
    deadline = monotonic_now() + timeout
    seen_ids = set()
    while monotonic_now() < deadline:
        raise_if_cancelled(cancel_callback)
        try:
            messages = get_messages(dev_token)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] 鎷夊彇閭欢鍒楄〃澶辫触: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        for msg in messages:
            msg_id = msg.get("id") or msg.get("msgid")
            if not msg_id or msg_id in seen_ids:
                continue
            seen_ids.add(msg_id)
            recipients = [t.get("address", "").lower() for t in (msg.get("to") or [])]
            if email.lower() not in recipients:
                continue
            try:
                detail = get_message_detail(dev_token, msg_id)
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 鑾峰彇閭欢璇︽儏澶辫触: {exc}")
                continue
            parts = []
            text_body = detail.get("text") or ""
            if text_body:
                parts.append(text_body)
            html_list = detail.get("html") or []
            for h in html_list:
                parts.append(re.sub(r"<[^>]+>", " ", h))
            combined = "\n".join(parts)
            subject = detail.get("subject", "")
            if log_callback:
                log_callback(f"[Debug] 鏀跺埌閭欢: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] 浠庨偖浠朵腑鎻愬彇鍒伴獙璇佺爜: {code}")
                return code
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"在 {timeout}s 内未收到验证码邮件")


def cloudflare_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    api_base = get_cloudflare_api_base()
    if not api_base:
        raise Exception("Cloudflare API Base 未配置")
    deadline = monotonic_now() + timeout
    # 同一封邮件正文可能延迟可读，允许多次重试解析，避免偶发漏码
    seen_attempts = {}
    next_resend_at = monotonic_now() + 35
    while monotonic_now() < deadline:
        raise_if_cancelled(cancel_callback)
        if resend_callback and monotonic_now() >= next_resend_at:
            try:
                resend_callback()
                if log_callback:
                    log_callback("[*] 已触发重新发送验证码")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 触发重发验证码失败: {exc}")
            next_resend_at = monotonic_now() + 35
        try:
            messages = cloudflare_get_messages(api_base, dev_token)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] Cloudflare 拉取邮件列表失败: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        if log_callback:
            log_callback(f"[Debug] Cloudflare 本轮邮件数量: {len(messages)}")

        for msg in messages:
            msg_id = msg.get("id") or msg.get("msgid")
            if not msg_id:
                continue
            attempt = int(seen_attempts.get(msg_id, 0))
            if attempt >= 5:
                continue
            seen_attempts[msg_id] = attempt + 1
            recipients = [t.get("address", "").lower() for t in (msg.get("to") or [])]
            msg_addr = str(msg.get("address", "")).lower()
            # 优先匹配目标邮箱；若结构不一致也允许继续解析，避免接口字段漂移导致漏码
            address_matched = True
            if recipients:
                address_matched = email.lower() in recipients
            elif msg_addr:
                address_matched = msg_addr == email.lower()
            if not address_matched and log_callback:
                log_callback(f"[Debug] 跳过疑似非目标邮件 id={msg_id} address={msg_addr} to={recipients}")
                continue
            parts = []
            # 先直接从列表项取内容，避免 detail 接口差异导致漏码
            for field in ("text", "raw", "content", "intro", "body", "snippet"):
                value = msg.get(field)
                if isinstance(value, str) and value.strip():
                    parts.append(value)
            html_list = msg.get("html") or []
            if isinstance(html_list, str):
                html_list = [html_list]
            for h in html_list:
                parts.append(re.sub(r"<[^>]+>", " ", h))
            subject = str(msg.get("subject", "") or "")
            combined = "\n".join(parts)
            # 再尝试 detail 接口补全内容
            try:
                detail = cloudflare_get_message_detail(api_base, dev_token, msg_id)
                for field in ("text", "raw", "content", "intro", "body", "snippet"):
                    value = detail.get(field)
                    if isinstance(value, str) and value.strip():
                        combined += "\n" + value
                html_list2 = detail.get("html") or []
                if isinstance(html_list2, str):
                    html_list2 = [html_list2]
                for h in html_list2:
                    combined += "\n" + re.sub(r"<[^>]+>", " ", h)
                if not subject:
                    subject = str(detail.get("subject", "") or "")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] Cloudflare detail接口失败，改用列表内容解析: {exc}")
            if log_callback:
                log_callback(f"[Debug] Cloudflare 收到邮件: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] Cloudflare 从邮件中提取到验证码: {code}")
                return code
            elif log_callback:
                log_callback(f"[Debug] 邮件已解析但未提取到验证码 id={msg_id} attempt={seen_attempts[msg_id]}")
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"Cloudflare 在 {timeout}s 内未收到验证码邮件")


def generate_random_birthdate():
    import datetime as dt

    today = dt.date.today()
    age = random.randint(20, 40)
    birth_year = today.year - age
    birth_month = random.randint(1, 12)
    birth_day = random.randint(1, 28)
    return f"{birth_year}-{birth_month:02d}-{birth_day:02d}T16:00:00.000Z"


def response_preview(res, limit=200):
    try:
        text = str(res.text or "")
    except Exception:
        text = ""
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def is_cloudflare_block_response(res):
    try:
        headers = {str(k).lower(): str(v).lower() for k, v in dict(res.headers).items()}
        text = str(res.text or "").lower()
        server = headers.get("server", "")
        content_type = headers.get("content-type", "")
        return (
            res.status_code in (403, 429, 503)
            and (
                "cloudflare" in server
                or "cloudflare" in text
                or "cf-error" in text
                or "__cf_chl" in text
                or "text/html" in content_type
            )
        )
    except Exception:
        return False


def set_birth_date(session, log_callback=None, timeout=20):
    url = "https://grok.com/rest/auth/set-birth-date"
    new_headers = {
        "content-type": "application/json",
        "origin": "https://grok.com",
        "referer": "https://grok.com/",
    }
    payload = {"birthDate": generate_random_birthdate()}
    try:
        res = session.post(url, json=payload, headers=new_headers, timeout=timeout)
        if log_callback:
            log_callback(
                f"[Debug] set_birth_date status: {res.status_code}, body: {response_preview(res)}"
            )
        if 200 <= res.status_code < 300:
            return True, "ok"
        if is_cloudflare_block_response(res):
            return (
                False,
                "set_birth_date 被 grok.com 的 Cloudflare 防护拦截，HTTP "
                f"{res.status_code}",
            )
        return False, f"set_birth_date HTTP {res.status_code}: {response_preview(res)}"
    except Exception as e:
        if log_callback:
            log_callback(f"[set_birth_date] 异常: {e}")
        return False, f"set_birth_date 异常: {e}"


def set_tos_accepted(session, log_callback=None, timeout=20):
    url = "https://accounts.x.ai/auth_mgmt.AuthManagement/SetTosAcceptedVersion"
    payload = struct.pack("B", (2 << 3) | 0) + struct.pack("B", 1)
    data = b"\x00" + struct.pack(">I", len(payload)) + payload
    new_headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "x-user-agent": "connect-es/2.1.1",
        "origin": "https://accounts.x.ai",
        "referer": "https://accounts.x.ai/accept-tos",
    }
    try:
        res = session.post(url, data=data, headers=new_headers, timeout=timeout)
        if log_callback:
            log_callback(f"[Debug] set_tos_accepted status: {res.status_code}")
        if 200 <= res.status_code < 300:
            return True, "ok"
        if is_cloudflare_block_response(res):
            return (
                False,
                "set_tos_accepted 被 accounts.x.ai 的 Cloudflare 防护拦截，HTTP "
                f"{res.status_code}",
            )
        return False, f"set_tos_accepted HTTP {res.status_code}: {response_preview(res)}"
    except Exception as e:
        if log_callback:
            log_callback(f"[set_tos_accepted] 异常: {e}")
        return False, f"set_tos_accepted 异常: {e}"


def encode_grpc_nsfw_settings():
    field1_content = bytes([0x10, 0x01])
    field1 = bytes([0x0A, len(field1_content)]) + field1_content
    nsfw_string = b"always_show_nsfw_content"
    field2_inner = bytes([0x0A, len(nsfw_string)]) + nsfw_string
    field2 = bytes([0x12, len(field2_inner)]) + field2_inner
    payload = field1 + field2
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def update_nsfw_settings(session, log_callback=None, timeout=20):
    url = "https://grok.com/auth_mgmt.AuthManagement/UpdateUserFeatureControls"
    data = encode_grpc_nsfw_settings()
    new_headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "origin": "https://grok.com",
        "referer": "https://grok.com/",
    }
    try:
        res = session.post(url, data=data, headers=new_headers, timeout=timeout)
        if log_callback:
            log_callback(
                f"[Debug] update_nsfw status: {res.status_code}, body: {response_preview(res)}"
            )
        if 200 <= res.status_code < 300:
            return True, "ok"
        if is_cloudflare_block_response(res):
            return (
                False,
                "update_nsfw_settings 被 grok.com 的 Cloudflare 防护拦截，HTTP "
                f"{res.status_code}",
            )
        return False, f"update_nsfw_settings HTTP {res.status_code}: {response_preview(res)}"
    except Exception as e:
        if log_callback:
            log_callback(f"[update_nsfw] 异常: {e}")
        return False, f"update_nsfw_settings 异常: {e}"




def fetch_xai_oauth_otp(email, mail_token, log_callback=None, cancel_callback=None):
    if not mail_token:
        raise Exception("缺少邮箱 token，无法拉取 xAI OAuth OTP")
    if log_callback:
        local = email.split("@", 1)[0] if "@" in email else email
        masked = (local[:2] + "***@" + email.split("@", 1)[1]) if "@" in email else email
        log_callback(f"[xAI-OAuth][Debug] 开始从邮箱拉取 OTP | email={masked}")
    return get_oai_code(
        mail_token,
        email,
        timeout=180,
        poll_interval=3,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )


def try_xai_oauth_after_sso(email, password, mail_token="", log_callback=None, cancel_callback=None):
    if not config.get("xai_oauth_auto", True):
        if log_callback:
            log_callback("[xAI-OAuth][Debug] xai_oauth_auto=false，跳过 OAuth")
        return ""
    output_dir = str(config.get("xai_oauth_output_dir", "") or "").strip()
    if not output_dir:
        if log_callback:
            log_callback("[xAI-OAuth][!] 已开启但未配置 xai_oauth_output_dir，跳过")
        return ""
    if not str(password or "").strip():
        if log_callback:
            log_callback("[xAI-OAuth][!] 缺少注册密码，跳过")
        return ""
    if log_callback:
        has_pwd = bool(str(password or "").strip())
        log_callback(
            f"[xAI-OAuth][Debug] 准备 OAuth | email={email} | hasPassword={has_pwd} | hasMailToken={bool(str(mail_token or '').strip())} | outDir={output_dir}"
        )
    try:
        refresh_active_page()
        if page is None:
            raise RuntimeError("browser page unavailable")
        # 注册页 token 不能带到 OAuth 登录页，否则几乎必现 Failed to verify
        clear_cf_for_scene(SCENE_OAUTH, log_callback=log_callback)
        clear_turnstile_session_cache(reason="before-xai-oauth", log_callback=log_callback)

        def _fetch_otp(log_callback=None, cancel_callback=None):
            return fetch_xai_oauth_otp(
                email,
                mail_token,
                log_callback=log_callback,
                cancel_callback=cancel_callback,
            )

        path = run_xai_oauth_after_sso(
            page,
            email_hint=email,
            password=str(password).strip(),
            mail_token=str(mail_token or "").strip(),
            output_dir=output_dir,
            callback_port=int(config.get("xai_oauth_callback_port", 56121) or 56121),
            proxy=get_runtime_proxy_url(log_callback=log_callback),
            fetch_otp=_fetch_otp if mail_token else None,
            get_turnstile=getTurnstileToken,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
        )
        if log_callback:
            if path:
                log_callback(f"[xAI-OAuth][+] OAuth 流程结束，继续后续步骤 | cred={path}")
            else:
                log_callback("[xAI-OAuth][Debug] OAuth 流程结束（无凭证路径），继续后续步骤")
        return path
    except Exception as exc:
        if log_callback:
            log_callback(f"[xAI-OAuth][!] OAuth 失败，继续保存 sso: {exc}")
        return ""

def enable_nsfw_for_token(token, cf_clearance="", log_callback=None, timeout=30):
    proxies = get_proxies()
    user_agent = get_user_agent()
    try:
        with requests.Session(impersonate="chrome120", proxies=proxies) as session:
            cookie_parts = [f"sso={token}", f"sso-rw={token}"]
            if cf_clearance:
                cookie_parts.append(f"cf_clearance={cf_clearance}")
            session.headers.update(
                {
                    "user-agent": user_agent,
                    "cookie": "; ".join(cookie_parts),
                }
            )
            ok, message = set_tos_accepted(session, log_callback, timeout)
            if not ok:
                return False, message
            ok, message = set_birth_date(session, log_callback, timeout)
            if not ok:
                return False, message
            ok, message = update_nsfw_settings(session, log_callback, timeout)
            if not ok:
                return False, message
            return True, "成功开启 NSFW"
    except Exception as e:
        return False, f"异常: {str(e)}"


SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"

browser = None
page = None


def setup_light_theme(root):
    try:
        root.option_add("*Background", UI_BG)
        root.option_add("*Foreground", UI_FG)
        root.option_add("*selectBackground", UI_ACTIVE_BG)
        root.option_add("*selectForeground", UI_FG)
        root.option_add("*insertBackground", UI_FG)
        root.option_add("*Entry.Background", UI_ENTRY_BG)
        root.option_add("*Text.Background", UI_ENTRY_BG)
        root.option_add("*Menu.Background", UI_ENTRY_BG)
        root.option_add("*Menu.Foreground", UI_FG)
        style = ttk.Style(root)
        available = set(style.theme_names())
        if "clam" in available:
            style.theme_use("clam")
        elif "default" in available:
            style.theme_use("default")
        root.configure(bg=UI_BG)
        style.configure(".", background=UI_BG, foreground=UI_FG, fieldbackground=UI_ENTRY_BG)
        style.configure("TFrame", background=UI_BG)
        style.configure("TLabelframe", background=UI_BG, foreground=UI_FG)
        style.configure("TLabelframe.Label", background=UI_BG, foreground=UI_FG)
        style.configure("TLabel", background=UI_BG, foreground=UI_FG)
        style.configure("TCheckbutton", background=UI_BG, foreground=UI_FG)
        style.configure("TButton", background=UI_BUTTON_BG, foreground=UI_FG)
        style.configure("TEntry", fieldbackground=UI_ENTRY_BG, foreground=UI_FG)
        style.configure("TCombobox", fieldbackground=UI_ENTRY_BG, foreground=UI_FG)
        style.configure("TSpinbox", fieldbackground=UI_ENTRY_BG, foreground=UI_FG)
    except Exception:
        pass


def tk_label(parent, text="", **kwargs):
    return tk.Label(parent, text=text, bg=kwargs.pop("bg", UI_BG), fg=kwargs.pop("fg", UI_FG), **kwargs)


def tk_entry(parent, textvariable=None, width=30, **kwargs):
    return tk.Entry(
        parent,
        textvariable=textvariable,
        width=width,
        bg=UI_ENTRY_BG,
        fg=UI_FG,
        insertbackground=UI_FG,
        disabledbackground="#2f2f2f",
        disabledforeground=UI_MUTED_FG,
        highlightthickness=1,
        highlightbackground="#555555",
        relief=tk.SOLID,
        **kwargs,
    )


def tk_button(parent, text="", command=None, state=tk.NORMAL, **kwargs):
    return tk.Button(
        parent,
        text=text,
        command=command,
        state=state,
        bg=UI_BUTTON_BG,
        fg=UI_FG,
        activebackground=UI_ACTIVE_BG,
        activeforeground=UI_FG,
        disabledforeground="#777777",
        relief=tk.RAISED,
        padx=10,
        pady=3,
        **kwargs,
    )


def tk_checkbutton(parent, text="", variable=None, **kwargs):
    return tk.Checkbutton(
        parent,
        text=text,
        variable=variable,
        bg=UI_BG,
        fg=UI_FG,
        activebackground=UI_BG,
        activeforeground=UI_FG,
        selectcolor="#3d7be0",
        **kwargs,
    )


def tk_option_menu(parent, variable, values, width=12):
    menu = tk.OptionMenu(parent, variable, *values)
    menu.configure(
        width=width,
        bg=UI_ENTRY_BG,
        fg=UI_FG,
        activebackground=UI_ACTIVE_BG,
        activeforeground=UI_FG,
        highlightthickness=1,
        highlightbackground="#555555",
        relief=tk.SOLID,
    )
    menu["menu"].configure(bg=UI_ENTRY_BG, fg=UI_FG, activebackground=UI_ACTIVE_BG, activeforeground=UI_FG)
    return menu


def start_browser(log_callback=None):
    global browser, page
    last_exc = None
    # Every browser launch picks a (possibly new) proxy from the pool.
    select_proxy_for_browser(log_callback=log_callback, force_new=True)
    for attempt in range(1, 5):
        try:
            browser = Chromium(create_browser_options(log_callback=log_callback))
            tabs = browser.get_tabs()
            page = tabs[-1] if tabs else browser.new_tab()
            if log_callback and getattr(browser, "user_data_path", None):
                log_callback(f"[Debug] 当前浏览器资料目录: {browser.user_data_path}")
            if log_callback and attempt > 1:
                log_callback(f"[*] 浏览器第 {attempt} 次启动成功")
            return browser, page
        except Exception as exc:
            last_exc = exc
            if log_callback:
                log_callback(f"[Debug] 浏览器启动失败(第{attempt}/4次): {exc}")
            try:
                if browser is not None:
                    browser.quit(del_data=True)
            except Exception:
                pass
            browser = None
            page = None
            time.sleep(min(1.5 * attempt, 4))
    raise Exception(f"浏览器启动失败，已重试4次: {last_exc}")


def stop_browser():
    global browser, page
    if browser is not None:
        try:
            browser.quit(del_data=True)
        except Exception:
            pass
    browser = None
    page = None


def restart_browser(log_callback=None):
    stop_browser()
    return start_browser(log_callback=log_callback)


def browser_restart_strategy():
    mode = str(config.get("browser_restart_strategy", "always") or "always").strip().lower()
    if mode not in ("always", "on_fail", "every_n"):
        mode = "always"
    every_n = max(1, int(config.get("browser_restart_every_n", 5) or 5))
    return mode, every_n


def finish_account_browser_cycle(success, completed_count, log_callback=None, cancel_callback=None):
    if cancel_callback and cancel_callback():
        return
    mode, every_n = browser_restart_strategy()
    should_restart = False
    reason = ""
    if browser is None:
        start_browser(log_callback=log_callback)
        sleep_with_cancel(1, cancel_callback)
        return
    if mode == "always":
        should_restart = True
        reason = "always"
    elif mode == "on_fail":
        should_restart = not bool(success)
        reason = "on_fail"
    else:
        should_restart = (not bool(success)) or (int(completed_count or 0) > 0 and int(completed_count or 0) % every_n == 0)
        reason = f"every_n:{every_n}"
    if should_restart:
        if log_callback:
            log_callback(f"[Debug] 浏览器按策略重启 | mode={mode} reason={reason} success={bool(success)} completed={completed_count}")
        restart_browser(log_callback=log_callback)
    else:
        if log_callback:
            log_callback(f"[Debug] 浏览器按策略保留 | mode={mode} success={bool(success)} completed={completed_count}")
    sleep_with_cancel(1, cancel_callback)


def cleanup_runtime_memory(log_callback=None, reason="定期清理"):
    if log_callback:
        log_callback(f"[*] {reason}: 关闭浏览器并清理内存")
    stop_browser()
    collected = gc.collect()
    if log_callback:
        log_callback(f"[*] Python GC 已回收对象数: {collected}")


def refresh_active_page():
    global browser, page
    if browser is None:
        restart_browser()
    try:
        tabs = browser.get_tabs()
        if tabs:
            page = tabs[-1]
        else:
            page = browser.new_tab()
    except Exception:
        restart_browser()
    return page


def click_email_signup_button(timeout=10, log_callback=None, cancel_callback=None):
    global page
    deadline = monotonic_now() + timeout
    while monotonic_now() < deadline:
        raise_if_cancelled(cancel_callback)
        if log_callback:
            log_callback("[Debug] 尝试查找“使用邮箱注册”按钮...")

        clicked = page.run_js(r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function nodeText(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
        node.getAttribute('href'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
function scoreEntry(node) {
    const compact = nodeText(node).replace(/\s+/g, '');
    const lower = compact.toLowerCase();
    if (compact.includes('使用邮箱注册')) return 100;
    if (lower.includes('signupwithemail')) return 95;
    if (lower.includes('continuewithemail')) return 90;
    if (lower.includes('email') && (lower.includes('sign') || lower.includes('continue') || lower.includes('use') || lower.includes('with'))) return 80;
    if (lower === 'email' || lower.includes('邮箱')) return 70;
    return 0;
}
const candidates = Array.from(document.querySelectorAll('button, a, [role="button"]'))
    .filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true')
    .map((node) => ({ node, score: scoreEntry(node), text: nodeText(node) }))
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score);
const target = candidates[0]?.node || null;
if (!target) {
    return false;
}
target.click();
return candidates[0].text || true;
        """)

        if clicked:
            if log_callback:
                detail = f": {clicked}" if isinstance(clicked, str) else ""
                log_callback(f"[*] 已点击「使用邮箱注册」按钮{detail}")
            sleep_with_cancel(2, cancel_callback)
            return True

        if log_callback:
            current_url = page.url if page else "none"
            log_callback(f"[Debug] 当前URL: {current_url}")

        sleep_with_cancel(1, cancel_callback)

    if log_callback:
        page_html = page.html[:500] if page else "no page"
        log_callback(f"[Debug] 页面内容片段: {page_html}")

    raise Exception("未找到「使用邮箱注册」按钮")


def open_signup_page(log_callback=None, cancel_callback=None):
    global browser, page
    raise_if_cancelled(cancel_callback)
    if browser is None:
        start_browser()
        if log_callback:
            log_callback("[*] 浏览器已启动")
    try:
        page = browser.get_tab(0)
        page.get(SIGNUP_URL)
    except Exception as e:
        if log_callback:
            log_callback(f"[Debug] 打开URL异常: {e}")
        try:
            page = browser.new_tab(SIGNUP_URL)
        except Exception as e2:
            if log_callback:
                log_callback(f"[Debug] 创建新标签页异常: {e2}")
            restart_browser()
            page = browser.new_tab(SIGNUP_URL)
    page.wait.doc_loaded()
    sleep_with_cancel(2, cancel_callback)
    if log_callback:
        log_callback(f"[*] 当前URL: {page.url}")
    click_email_signup_button(
        log_callback=log_callback, cancel_callback=cancel_callback
    )


def has_profile_form(log_callback=None):
    refresh_active_page()
    try:
        return bool(
            page.run_js(
                """
const givenInput = document.querySelector('input[data-testid="givenName"], input[name="givenName"], input[autocomplete="given-name"]');
const familyInput = document.querySelector('input[data-testid="familyName"], input[name="familyName"], input[autocomplete="family-name"]');
const passwordInput = document.querySelector('input[data-testid="password"], input[name="password"], input[type="password"]');
return !!(givenInput && familyInput && passwordInput);
            """
            )
        )
    except Exception:
        return False


def fill_email_and_submit(timeout=45, log_callback=None, cancel_callback=None):
    raise_if_cancelled(cancel_callback)
    email, dev_token = get_email_and_token()
    if not email or not dev_token:
        raise Exception("获取邮箱失败")
    if log_callback:
        log_callback(f"[*] 已创建邮箱: {email}")
    deadline = monotonic_now() + timeout
    last_diag_time = 0.0
    last_reclick_time = 0.0
    last_snapshot = None
    while monotonic_now() < deadline:
        raise_if_cancelled(cancel_callback)
        filled = page.run_js(
            r"""
const email = arguments[0];
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function textOf(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
        node.getAttribute('placeholder'),
        node.getAttribute('data-testid'),
        node.getAttribute('name'),
        node.getAttribute('id'),
        node.getAttribute('autocomplete'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
function describeInput(node) {
    return [
        `type=${node.getAttribute('type') || ''}`,
        `name=${node.getAttribute('name') || ''}`,
        `id=${node.getAttribute('id') || ''}`,
        `placeholder=${node.getAttribute('placeholder') || ''}`,
        `aria=${node.getAttribute('aria-label') || ''}`,
        `testid=${node.getAttribute('data-testid') || ''}`,
    ].join(' ').replace(/\s+/g, ' ').trim().slice(0, 160);
}
function describeAction(node) {
    return textOf(node).slice(0, 120);
}
function emailCandidates() {
    const direct = Array.from(document.querySelectorAll('input[data-testid="email"], input[name="email"], input[type="email"], input[autocomplete="email"], input[placeholder*="mail" i], input[aria-label*="mail" i]'));
    const all = Array.from(document.querySelectorAll('input, textarea'));
    for (const node of all) {
        const type = (node.getAttribute('type') || '').toLowerCase();
        if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'file', 'search'].includes(type)) continue;
        const meta = textOf(node).toLowerCase();
        if (meta.includes('email') || meta.includes('e-mail') || meta.includes('mail') || meta.includes('邮箱') || meta.includes('电子邮件')) {
            direct.push(node);
        }
    }
    return Array.from(new Set(direct));
}
const visibleInputs = Array.from(document.querySelectorAll('input, textarea'))
    .filter((node) => isVisible(node) && !node.disabled && !node.readOnly)
    .map(describeInput)
    .slice(0, 8);
const visibleActions = Array.from(document.querySelectorAll('button, a, [role="button"]'))
    .filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true')
    .map(describeAction)
    .filter(Boolean)
    .slice(0, 10);
const input = emailCandidates().find((node) => isVisible(node) && !node.disabled && !node.readOnly) || null;
if (!input) {
    return {
        state: 'not-ready',
        url: location.href,
        title: document.title,
        inputs: visibleInputs,
        buttons: visibleActions,
    };
}
input.focus(); input.click();
const valueProto = input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
const valueSetter = Object.getOwnPropertyDescriptor(valueProto, 'value')?.set;
const tracker = input._valueTracker;
if (tracker) tracker.setValue('');
if (valueSetter) valueSetter.call(input, email); else input.value = email;
input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: email, inputType: 'insertText' }));
input.dispatchEvent(new InputEvent('input', { bubbles: true, data: email, inputType: 'insertText' }));
input.dispatchEvent(new Event('change', { bubbles: true }));
const inputType = (input.getAttribute('type') || '').toLowerCase();
const isValid = inputType !== 'email' || input.checkValidity();
if ((input.value || '').trim() !== email || !isValid) {
    return {
        state: 'fill-failed',
        value: input.value || '',
        valid: isValid,
        input: describeInput(input),
        url: location.href,
    };
}
input.blur();
return {
    state: 'filled',
    input: describeInput(input),
    url: location.href,
};
            """,
            email,
        )
        state = filled.get("state") if isinstance(filled, dict) else filled
        if isinstance(filled, dict):
            last_snapshot = filled
        if state == "not-ready":
            now = monotonic_now()
            if now - last_reclick_time >= 3:
                reclicked = page.run_js(r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function nodeText(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
        node.getAttribute('href'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
function scoreEntry(node) {
    const compact = nodeText(node).replace(/\s+/g, '');
    const lower = compact.toLowerCase();
    if (compact.includes('使用邮箱注册')) return 100;
    if (lower.includes('signupwithemail')) return 95;
    if (lower.includes('continuewithemail')) return 90;
    if (lower.includes('email') && (lower.includes('sign') || lower.includes('continue') || lower.includes('use') || lower.includes('with'))) return 80;
    if (lower === 'email' || lower.includes('邮箱')) return 70;
    return 0;
}
const candidates = Array.from(document.querySelectorAll('button, a, [role="button"]'))
    .filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true')
    .map((node) => ({ node, score: scoreEntry(node), text: nodeText(node) }))
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score);
if (!candidates.length) return false;
candidates[0].node.click();
return candidates[0].text || true;
                """)
                last_reclick_time = now
                if reclicked and log_callback:
                    detail = f": {reclicked}" if isinstance(reclicked, str) else ""
                    log_callback(f"[Debug] 邮箱输入框未出现，已再次触发邮箱注册入口{detail}")
            if log_callback and now - last_diag_time >= 5:
                last_diag_time = now
                inputs = " | ".join((filled or {}).get("inputs", [])[:6]) if isinstance(filled, dict) else ""
                buttons = " | ".join((filled or {}).get("buttons", [])[:8]) if isinstance(filled, dict) else ""
                url = (filled or {}).get("url", page.url if page else "") if isinstance(filled, dict) else (page.url if page else "")
                log_callback(f"[Debug] 等待邮箱输入框: url={url}; inputs={inputs or 'none'}; buttons={buttons or 'none'}")
            sleep_with_cancel(0.5, cancel_callback)
            continue
        if state != "filled":
            if log_callback:
                log_callback(f"[Debug] 邮箱输入框已出现，但写入失败: {filled}")
            sleep_with_cancel(0.5, cancel_callback)
            continue
        sleep_with_cancel(0.8, cancel_callback)
        clicked = page.run_js(
            r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function textOf(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
        node.getAttribute('placeholder'),
        node.getAttribute('data-testid'),
        node.getAttribute('name'),
        node.getAttribute('id'),
        node.getAttribute('autocomplete'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
function emailCandidates() {
    const direct = Array.from(document.querySelectorAll('input[data-testid="email"], input[name="email"], input[type="email"], input[autocomplete="email"], input[placeholder*="mail" i], input[aria-label*="mail" i]'));
    const all = Array.from(document.querySelectorAll('input, textarea'));
    for (const node of all) {
        const type = (node.getAttribute('type') || '').toLowerCase();
        if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'file', 'search'].includes(type)) continue;
        const meta = textOf(node).toLowerCase();
        if (meta.includes('email') || meta.includes('e-mail') || meta.includes('mail') || meta.includes('邮箱') || meta.includes('电子邮件')) {
            direct.push(node);
        }
    }
    return Array.from(new Set(direct));
}
const input = emailCandidates().find((node) => isVisible(node) && !node.disabled && !node.readOnly) || null;
if (!input || !(input.value || '').trim()) return false;
const inputType = (input.getAttribute('type') || '').toLowerCase();
if (inputType === 'email' && !input.checkValidity()) return false;
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], input[type="submit"]'))
    .filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true');
const submitButton = buttons.find((node) => {
    const text = textOf(node).replace(/\s+/g, '');
    const lower = text.toLowerCase();
    return (
        text === '注册' ||
        text.includes('注册') ||
        text.includes('继续') ||
        text.includes('下一步') ||
        text.includes('确认') ||
        lower.includes('signup') ||
        lower.includes('sign up') ||
        lower.includes('continue') ||
        lower.includes('next') ||
        lower.includes('createaccount') ||
        lower.includes('submit')
    );
});
if (submitButton) {
    submitButton.click();
    return textOf(submitButton) || true;
}
const form = input.closest('form');
if (form) {
    if (form.requestSubmit) form.requestSubmit();
    else form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    return 'form-submit';
}
input.focus();
input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }));
input.dispatchEvent(new KeyboardEvent('keyup', { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }));
return 'enter';
            """
        )
        if clicked:
            if log_callback:
                detail = f" ({clicked})" if isinstance(clicked, str) else ""
                log_callback(f"[*] 已填写邮箱并提交: {email}{detail}")
            return email, dev_token
        sleep_with_cancel(0.5, cancel_callback)
    if last_snapshot:
        inputs = " | ".join(last_snapshot.get("inputs", [])[:6])
        buttons = " | ".join(last_snapshot.get("buttons", [])[:8])
        url = last_snapshot.get("url", page.url if page else "")
        raise Exception(
            f"未找到邮箱输入框或注册按钮，最后页面: url={url}; inputs={inputs or 'none'}; buttons={buttons or 'none'}"
        )
    raise Exception("未找到邮箱输入框或注册按钮")


def fill_code_and_submit(email, dev_token, timeout=180, log_callback=None, cancel_callback=None):
    def _resend_code():
        page.run_js(
            r"""
const nodes = Array.from(document.querySelectorAll('button, a, [role="button"]'));
const target = nodes.find((node) => {
  const t = (node.innerText || node.textContent || '').replace(/\s+/g, '').toLowerCase();
  return t.includes('重新发送') || t.includes('resend') || t.includes('再次发送');
});
if (target && !target.disabled) { target.click(); return true; }
return false;
            """
        )

    code = get_oai_code(
        dev_token,
        email,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
        resend_callback=_resend_code,
    )
    if not code:
        raise Exception("获取验证码失败")
    clean_code = str(code).replace("-", "").strip()
    deadline = monotonic_now() + timeout

    while monotonic_now() < deadline:
        raise_if_cancelled(cancel_callback)
        filled = page.run_js(
            """
const code = String(arguments[0] || '').trim();
if (!code) return 'empty-code';

function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

function setInputValue(input, value) {
    const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    const tracker = input._valueTracker;
    if (tracker) tracker.setValue('');
    if (nativeSetter) nativeSetter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new InputEvent('input', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
}

const aggregate = Array.from(document.querySelectorAll(
  'input[data-input-otp=\"true\"], input[name=\"code\"], input[autocomplete=\"one-time-code\"], input[inputmode=\"numeric\"], input[inputmode=\"text\"]'
)).find((node) => isVisible(node) && !node.disabled && !node.readOnly && Number(node.maxLength || 6) > 1);

if (aggregate) {
    aggregate.focus();
    aggregate.click();
    setInputValue(aggregate, code);
    return String(aggregate.value || '').replace(/\\s+/g, '') ? 'filled-aggregate' : 'aggregate-failed';
}

const otpBoxes = Array.from(document.querySelectorAll('input')).filter((node) => {
    if (!isVisible(node) || node.disabled || node.readOnly) return false;
    const maxLength = Number(node.maxLength || 0);
    const ac = String(node.autocomplete || '').toLowerCase();
    return maxLength === 1 || ac === 'one-time-code';
});

if (otpBoxes.length >= code.length) {
    for (let i = 0; i < code.length; i += 1) {
        const ch = code[i] || '';
        const box = otpBoxes[i];
        box.focus();
        box.click();
        setInputValue(box, ch);
        box.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: ch }));
        box.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: ch }));
    }
    const merged = otpBoxes.slice(0, code.length).map((x) => String(x.value || '').trim()).join('');
    return merged.length ? 'filled-boxes' : 'boxes-failed';
}

return 'not-ready';
            """,
            clean_code,
        )

        if filled == "not-ready":
            sleep_with_cancel(0.5, cancel_callback)
            continue
        if "failed" in str(filled):
            if log_callback:
                log_callback(f"[Debug] 验证码填写失败: {filled}")
            sleep_with_cancel(0.5, cancel_callback)
            continue

        clicked = page.run_js(
            r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

const buttons = Array.from(document.querySelectorAll('button[type=\"submit\"], button')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});

const btn = buttons.find((node) => {
    const t = (node.innerText || node.textContent || '').replace(/\\s+/g, '').toLowerCase();
    return (
        t.includes('确认邮箱') ||
        t.includes('继续') ||
        t.includes('下一步') ||
        t.includes('confirm') ||
        t.includes('continue') ||
        t.includes('next')
    );
});

if (!btn) return 'no-button';
btn.focus();
btn.click();
return 'clicked';
            """
        )

        if clicked == "clicked" or clicked == "no-button":
            if log_callback:
                log_callback(f"[*] 已填写验证码并提交: {code}")
            sleep_with_cancel(1.5, cancel_callback)
            return code

        sleep_with_cancel(0.5, cancel_callback)

    raise Exception("验证码已获取，但自动填写/提交失败")


# ---- Turnstile unified layer (see turnstile_flow.py) ----
# Re-export / thin wrappers keep existing call sites stable.

def retry_turnstile_and_sync(page, log_callback=None, cancel_callback=None, scene=SCENE_REGISTER, reset=False):
    """Register-compatible retry: uses local getTurnstileToken solver."""
    return ensure_cf_token(
        page,
        scene=scene,
        get_token_fn=getTurnstileToken,
        reset=reset,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )


PROFILE_SUBMIT_JS = r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function readCfToken() {
    const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
    const inputVal = cfInput ? String(cfInput.value || '').trim() : '';
    let apiVal = '';
    try {
        if (window.turnstile && typeof turnstile.getResponse === 'function') {
            apiVal = String(turnstile.getResponse() || '').trim();
            if (!apiVal) {
                const widgets = document.querySelectorAll('.cf-turnstile, [data-sitekey]');
                for (const w of widgets) {
                    const id = w.getAttribute('data-turnstile-id') || w.id;
                    if (!id) continue;
                    const one = String(turnstile.getResponse(id) || '').trim();
                    if (one) { apiVal = one; break; }
                }
            }
        }
    } catch (e) {}
    const token = inputVal.length >= apiVal.length ? inputVal : apiVal;
    return { token, inputLen: inputVal.length, apiLen: apiVal.length };
}
function buttonText(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('value'),
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
const forceToken = String((arguments && arguments[0]) || '').trim();
const cfInfo = readCfToken();
if (forceToken.length >= 80) { cfInfo.token = forceToken; cfInfo.inputLen = Math.max(cfInfo.inputLen, forceToken.length); }
const cfPresent = !!document.querySelector('input[name="cf-turnstile-response"], iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey]');
if (cfPresent && cfInfo.token.length < 80) {
    return { state: 'wait-cloudflare', tokenLen: cfInfo.token.length, inputLen: cfInfo.inputLen, apiLen: cfInfo.apiLen };
}
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], input[type="submit"]')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});
const submitBtn = buttons.find((node) => {
    const t = buttonText(node).replace(/\s+/g, '').toLowerCase();
    return t.includes('完成注册') || t.includes('创建账户') || t.includes('signup') || t.includes('createaccount');
});
if (!submitBtn) {
    return { state: 'no-submit-button', buttons: buttons.map(buttonText).filter(Boolean).slice(0, 8), tokenLen: cfInfo.token.length };
}
submitBtn.focus();
submitBtn.click();
return { state: 'submitted', tokenLen: cfInfo.token.length, button: buttonText(submitBtn) };
"""


def attempt_profile_submit(page, log_callback=None, force_cf_token=""):
    try:
        token = str(force_cf_token or _tf.get_cached_token() or "").strip()
        if token:
            result = page.run_js(PROFILE_SUBMIT_JS, token)
        else:
            result = page.run_js(PROFILE_SUBMIT_JS)
    except Exception as exc:
        result = {"state": "js-error", "error": str(exc)}
    if not isinstance(result, dict):
        result = {"state": str(result or "unknown"), "raw": result}
    state = str(result.get("state") or "")
    if log_callback:
        if state == "submitted":
            log_callback(
                f"[*] 注册提交成功 | button={result.get('button', '')} cfTokenLen={result.get('tokenLen', 0)}"
            )
        elif state == "wait-cloudflare":
            log_callback(
                f"[Debug] 提交仍等待 CF | tokenLen={result.get('tokenLen')} input={result.get('inputLen')} api={result.get('apiLen')}"
            )
        elif state == "no-submit-button":
            log_callback(f"[Debug] 未找到提交按钮 | 可见={result.get('buttons')}")
        else:
            log_callback(f"[Debug] 提交尝试结果={result}")
    return result


def submit_profile_after_turnstile(page, given_name, family_name, password, log_callback=None, cancel_callback=None, turnstile_status=None):
    status = turnstile_status or probe_turnstile_status(page, use_cache=True, scene=SCENE_REGISTER)
    classified = classify_cf_status(status, scene=SCENE_REGISTER, token_good_since=monotonic_now())
    log_turnstile_status("提交前复测 Cloudflare", status, log_callback=log_callback, classified=classified)
    force_token = str(status.get("token") or _tf.get_cached_token() or "").strip()
    ready = bool(classified.get("ready") or status.get("solved") or status.get("success_mark"))
    if ready and force_token:
        remember_turnstile_token(force_token)
        sync_turnstile_token_to_page(page, force_token, log_callback=log_callback)
    if not ready and not status.get("solved"):
        return None
    result = attempt_profile_submit(page, log_callback=log_callback, force_cf_token=force_token)
    if result.get("state") == "submitted":
        return {"given_name": given_name, "family_name": family_name, "password": password}
    if result.get("state") in ("wait-cloudflare", "no-submit-button"):
        sleep_with_cancel(0.5, cancel_callback)
        sync_turnstile_token_to_page(page, force_token, log_callback=log_callback)
        result = attempt_profile_submit(page, log_callback=log_callback, force_cf_token=force_token)
        if result.get("state") == "submitted":
            return {"given_name": given_name, "family_name": family_name, "password": password}
    return None



def getTurnstileToken(log_callback=None, cancel_callback=None, skip_reset=False):
    global page
    if page is None:
        raise Exception("页面未就绪，无法执行 Turnstile")

    if not skip_reset:
        try:
            page.run_js(
                "try { if (window.turnstile && typeof turnstile.reset === 'function') turnstile.reset(); } catch(e) {}"
            )
        except Exception:
            pass

    for _ in range(0, 20):
        raise_if_cancelled(cancel_callback)
        try:
            probe = probe_turnstile_status(page)
            if probe.get('solved') and probe.get('token'):
                token = probe['token']
            else:
                token = page.run_js(
                """
try {
  const byInput = String((document.querySelector('input[name="cf-turnstile-response"]') || {}).value || '').trim();
  if (byInput) return byInput;
  if (window.turnstile && typeof turnstile.getResponse === 'function') {
    return String(turnstile.getResponse() || '').trim();
  }
  return '';
} catch(e) { return ''; }
                """
            )
            token = str(token or "").strip()
            if len(token) >= 80:
                remember_turnstile_token(token)
                if log_callback:
                    log_callback(f"[*] Turnstile 已通过，token长度={len(token)}")
                return token

            challenge_input = page.ele("@name=cf-turnstile-response")
            if challenge_input:
                wrapper = challenge_input.parent()
                iframe = None
                try:
                    iframe = wrapper.shadow_root.ele("tag:iframe")
                except Exception:
                    iframe = None
                if iframe:
                    try:
                        iframe.run_js(
                            """
window.dtp = 1;
function getRandomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
let sx = getRandomInt(800, 1200);
let sy = getRandomInt(400, 700);
Object.defineProperty(MouseEvent.prototype, 'screenX', { value: sx });
Object.defineProperty(MouseEvent.prototype, 'screenY', { value: sy });
                            """
                        )
                    except Exception:
                        pass
                    try:
                        body_sr = iframe.ele("tag:body").shadow_root
                        btn = body_sr.ele("tag:input")
                        if btn:
                            btn.click()
                    except Exception:
                        pass
            else:
                # 兜底：尝试触发页面上可见的 Turnstile 容器
                page.run_js(
                    """
const nodes = Array.from(document.querySelectorAll('div,span,iframe')).filter((n) => {
  const txt = (n.className || '') + ' ' + (n.id || '') + ' ' + (n.getAttribute?.('src') || '');
  return String(txt).toLowerCase().includes('turnstile');
});
if (nodes.length && typeof nodes[0].click === 'function') nodes[0].click();
                    """
                )
        except Exception:
            pass
        sleep_with_cancel(1, cancel_callback)

    raise Exception("Turnstile 获取 token 失败")


def build_profile():
    given_name_pool = [
        "Neo", "Ethan", "Liam", "Noah", "Lucas", "Mason", "Ryan", "Leo",
        "Owen", "Aiden", "Elio", "Aron", "Ivan", "Nolan", "Evan", "Kai",
        "Caleb", "Adam", "Ezra", "Miles", "Logan", "Carter", "Hunter", "Jason",
        "Brian", "Dylan", "Alex", "Colin", "Blake", "Gavin", "Henry", "Julian",
        "Kevin", "Louis", "Marcus", "Nathan", "Oscar", "Peter", "Quinn", "Robin",
        "Simon", "Tristan", "Victor", "Wesley", "Xavier", "Yuri", "Zane", "Felix",
        "Aaron", "Damian",
    ]
    family_name_pool = [
        "Lin", "Wang", "Zhao", "Liu", "Chen", "Zhang", "Xu", "Sun",
        "Guo", "He", "Yang", "Wu", "Zhou", "Tang", "Qin", "Shi",
        "Fang", "Peng", "Cao", "Deng", "Fan", "Fu", "Gao", "Han",
        "Hu", "Jiang", "Kong", "Lu", "Ma", "Nie", "Pan", "Qiao",
        "Ren", "Shao", "Tian", "Xie", "Yan", "Yao", "Yu", "Zeng",
        "Bai", "Duan", "Hou", "Jin", "Kang", "Luo", "Mao", "Song",
        "Wei", "Xiong",
    ]
    given_name = random.choice(given_name_pool)
    family_name = random.choice(family_name_pool)
    password = "N" + secrets.token_hex(4) + "!a7#" + secrets.token_urlsafe(6)
    return given_name, family_name, password


def fill_profile_and_submit(timeout=120, log_callback=None, cancel_callback=None):
    given_name, family_name, password = build_profile()
    deadline = monotonic_now() + timeout
    form_filled_once = False
    wait_cf_since = None
    last_cf_retry_at = 0.0

    while monotonic_now() < deadline:
        raise_if_cancelled(cancel_callback)
        if not form_filled_once:
            filled = page.run_js(
                """
const givenName = arguments[0];
const familyName = arguments[1];
const password = arguments[2];

function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

function pickInput(selector) {
    return Array.from(document.querySelectorAll(selector)).find((node) => {
        return isVisible(node) && !node.disabled && !node.readOnly;
    }) || null;
}

function setInputValue(input, value) {
    if (!input) return false;
    input.focus();
    input.click();
    const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    const tracker = input._valueTracker;
    if (tracker) tracker.setValue('');
    if (nativeSetter) nativeSetter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new InputEvent('input', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
    input.blur();
    return String(input.value || '').trim() === String(value || '').trim();
}

const givenInput = pickInput('input[data-testid="givenName"], input[name="givenName"], input[autocomplete="given-name"], input[aria-label*="名"]');
const familyInput = pickInput('input[data-testid="familyName"], input[name="familyName"], input[autocomplete="family-name"], input[aria-label*="姓"]');
const passwordInput = pickInput('input[data-testid="password"], input[name="password"], input[type="password"], input[autocomplete="new-password"]');

if (!givenInput || !familyInput || !passwordInput) return 'not-ready';

const ok1 = setInputValue(givenInput, givenName);
const ok2 = setInputValue(familyInput, familyName);
const ok3 = setInputValue(passwordInput, password);

if (!ok1 || !ok2 || !ok3) return 'fill-failed';

const buttons = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], input[type="submit"]')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});
const submitBtn = buttons.find((node) => {
    const t = (node.innerText || node.textContent || '').replace(/\\s+/g, '').toLowerCase();
    return t.includes('完成注册') || t.includes('创建账户') || t.includes('signup') || t.includes('createaccount');
});

// 必须等待 Cloudflare 校验通过后再提交
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const cfPresent = !!cfInput
  || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]');
if (cfPresent) {
    const token = String((cfInput && cfInput.value) || '').trim();
    const solvedByToken = token.length >= 80;
    if (!solvedByToken) return 'wait-cloudflare:' + token.length;
}

if (submitBtn) {
    return 'ready-to-submit';
}
return 'filled-no-submit';
            """,
                given_name,
                family_name,
                password,
            )

            if isinstance(filled, str) and filled.startswith("wait-cloudflare"):
                form_filled_once = True
                status = probe_turnstile_status(page, use_cache=True, scene=SCENE_REGISTER)
                bag = {"token_good_since": 0.0}
                update_token_stability(bag, status)
                classified = classify_cf_status(status, scene=SCENE_REGISTER, token_good_since=bag.get("token_good_since") or 0)
                log_turnstile_status("资料已填写，检测 Cloudflare", status, log_callback=log_callback, classified=classified)
                if status.get("page_advanced"):
                    if log_callback:
                        log_callback("[*] 注册页已无资料表单，尝试直接提交（不等待 Turnstile）")
                    form_filled_once = True
                    profile = submit_profile_after_turnstile(
                        page, given_name, family_name, password,
                        log_callback=log_callback, cancel_callback=cancel_callback,
                        turnstile_status={"solved": False, "present": False},
                    )
                    if not profile:
                        result = attempt_profile_submit(page, log_callback=log_callback)
                        if result.get("state") == "submitted":
                            return {"given_name": given_name, "family_name": family_name, "password": password}
                    elif profile:
                        return profile
                    sleep_with_cancel(0.5, cancel_callback)
                    continue
                elif classified.get("ready") or status.get("solved") or status.get("success_mark"):
                    if log_callback:
                        log_callback(f"[*] Cloudflare 已判定通过，进入提交阶段 | state={classified.get('state')}")
                else:
                    token_len = status.get("token_len", 0)
                    if token_len == 0:
                        pause_seconds = random.uniform(0.8, 2.0)
                        if log_callback:
                            log_callback(f"[*] Cloudflare token 仍为空，暂停 {pause_seconds:.1f}s 后复测")
                        sleep_with_cancel(pause_seconds, cancel_callback)
                    now = monotonic_now()
                    if wait_cf_since is None:
                        wait_cf_since = now
                    if now - wait_cf_since >= 10 and now - last_cf_retry_at >= 6:
                        if log_callback:
                            log_callback("[*] Cloudflare 验证卡住，开始二次复用 Turnstile...")
                        try:
                            status = retry_turnstile_and_sync(
                                page,
                                log_callback=log_callback,
                                cancel_callback=cancel_callback,
                                scene=SCENE_REGISTER,
                                reset=False,
                            )
                            log_turnstile_status("Turnstile 二次复用后", status, log_callback=log_callback)
                            if status.get("solved") or status.get("success_mark") or is_cf_ready(status, scene=SCENE_REGISTER, token_good_since=monotonic_now()):
                                wait_cf_since = None
                                profile = submit_profile_after_turnstile(
                                    page, given_name, family_name, password,
                                    log_callback=log_callback, cancel_callback=cancel_callback,
                                    turnstile_status=status,
                                )
                                if profile:
                                    return profile
                                continue
                        except Exception as cf_exc:
                            if log_callback:
                                log_callback(f"[Debug] Turnstile 二次复用失败: {cf_exc}")
                        last_cf_retry_at = now
                    sleep_with_cancel(0.6, cancel_callback)
                    continue

            if filled in ("ready-to-submit", "filled-no-submit"):
                form_filled_once = True
            elif filled == "fill-failed" and log_callback:
                log_callback("[Debug] 资料输入失败，重试中...")
                sleep_with_cancel(0.5, cancel_callback)
                continue
            elif filled == "not-ready":
                sleep_with_cancel(0.5, cancel_callback)
                continue

        submit_result = attempt_profile_submit(page, log_callback=log_callback)
        submit_state = submit_result.get("state") if isinstance(submit_result, dict) else str(submit_result)

        if submit_state == "wait-cloudflare":
            status = probe_turnstile_status(page, use_cache=True, scene=SCENE_REGISTER)
            bag = {"token_good_since": 0.0}
            update_token_stability(bag, status)
            classified = classify_cf_status(status, scene=SCENE_REGISTER, token_good_since=bag.get("token_good_since") or monotonic_now())
            log_turnstile_status("提交前检测 Cloudflare", status, log_callback=log_callback, classified=classified)
            if classified.get("ready") or status.get("solved") or status.get("success_mark"):
                if log_callback:
                    log_callback(f"[*] Cloudflare 已通过(增强判定)，立即重试提交 | state={classified.get('state')}")
                profile = submit_profile_after_turnstile(
                    page, given_name, family_name, password,
                    log_callback=log_callback, cancel_callback=cancel_callback,
                )
                if profile:
                    return profile
            now = monotonic_now()
            if wait_cf_since is None:
                wait_cf_since = now
            if now - wait_cf_since >= 10 and now - last_cf_retry_at >= 6:
                if log_callback:
                    log_callback("[*] 提交前仍卡住，自动再次复用 Turnstile...")
                try:
                    status = retry_turnstile_and_sync(
                        page,
                        log_callback=log_callback,
                        cancel_callback=cancel_callback,
                    )
                    log_turnstile_status("提交前 Turnstile 复用后", status, log_callback=log_callback)
                    if status.get("solved"):
                        wait_cf_since = None
                        profile = submit_profile_after_turnstile(
                            page, given_name, family_name, password,
                            log_callback=log_callback, cancel_callback=cancel_callback,
                            turnstile_status=status,
                        )
                        if profile:
                            return profile
                        if log_callback:
                            log_callback("[!] Turnstile 已 solved 但提交未成功，下一轮继续尝试", )
                        continue
                except Exception as cf_exc:
                    if log_callback:
                        log_callback(f"[Debug] Turnstile 二次复用失败: {cf_exc}")
                last_cf_retry_at = now
            sleep_with_cancel(0.6, cancel_callback)
            continue

        if submit_state == "submitted":
            if log_callback:
                log_callback(f"[*] 已填写注册资料并提交: {given_name} {family_name}")
            return {"given_name": given_name, "family_name": family_name, "password": password}
        wait_cf_since = None
        if submit_state == "no-submit-button" and log_callback:
            visible_buttons = submit_result.get("buttons") if isinstance(submit_result, dict) else []
            suffix = f" 可见按钮: {visible_buttons}" if visible_buttons else ""
            log_callback(f"[Debug] 未找到提交按钮，继续等待页面稳定...{suffix}")

        sleep_with_cancel(0.5, cancel_callback)

    raise Exception("最终注册页资料填写失败")


def wait_for_sso_cookie(timeout=150, log_callback=None, cancel_callback=None):
    deadline = monotonic_now() + timeout
    last_seen_names = set()
    last_submit_retry = 0.0
    last_cf_retry_at = 0.0
    final_no_submit_state = ""
    final_no_submit_since = None
    final_no_submit_timeout = 25

    while monotonic_now() < deadline:
        raise_if_cancelled(cancel_callback)
        try:
            refresh_active_page()
            if page is None:
                sleep_with_cancel(1, cancel_callback)
                continue

            # 超时检查
            if monotonic_now() >= deadline:
                raise AccountRetryNeeded(f"等待 SSO cookie 超时({timeout}s)")

            # 仍停留在“完成注册”页时，若 Cloudflare 已通过，周期性重试点击提交
            now = monotonic_now()
            if now - last_submit_retry >= 2.5:
                retried = page.run_js(
                    r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
const titleHit = !!Array.from(document.querySelectorAll('h1,h2,div,span')).find((el) => {
    const t = (el.textContent || '').replace(/\s+/g, '');
    const lower = t.toLowerCase();
    return t.includes('完成注册') || lower.includes('completeyoursignup') || lower.includes('completesignup');
});
if (!titleHit) return 'not-final-page';

const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const cfPresent = !!cfInput
  || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]');
if (cfPresent) {
    const token = String((cfInput && cfInput.value) || '').trim();
    const solved = token.length >= 80;
    if (!solved) return 'final-page-wait-cf:' + token.length;
}

function buttonText(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('value'),
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], input[type="submit"]')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});
const submitBtn = buttons.find((node) => {
    const t = buttonText(node).replace(/\s+/g, '').toLowerCase();
    return t.includes('完成注册') || t.includes('创建账户') || t.includes('signup') || t.includes('createaccount');
});
if (!submitBtn) {
    const visibleTexts = buttons.map(buttonText).filter(Boolean).slice(0, 8).join(' | ');
    return 'final-page-no-submit:' + visibleTexts;
}
submitBtn.focus();
submitBtn.click();
return 'final-page-clicked-submit';
                    """
                )
                last_submit_retry = now
                if log_callback and (retried == "final-page-clicked-submit" or (isinstance(retried, str) and retried.startswith("final-page-no-submit"))):
                    log_callback(f"[Debug] 最终页状态: {retried}")
                if isinstance(retried, str) and retried.startswith("final-page-no-submit"):
                    if retried != final_no_submit_state:
                        final_no_submit_state = retried
                        final_no_submit_since = now
                    elif final_no_submit_since and now - final_no_submit_since >= final_no_submit_timeout:
                        raise AccountRetryNeeded(
                            f"最终注册页状态 {final_no_submit_timeout}s 未变化且未找到提交按钮，重试当前账号: {retried}"
                        )
                else:
                    final_no_submit_state = ""
                    final_no_submit_since = None
                if log_callback and isinstance(retried, str) and retried.startswith("final-page-wait-cf"):
                    token_len = retried.split(":", 1)[1] if ":" in retried else "0"
                    status = probe_turnstile_status(page, use_cache=True, scene=SCENE_FINAL)
                    log_turnstile_status(
                        f"最终页状态 final-page-wait-cf token长度={token_len}",
                        status,
                        log_callback=log_callback,
                    )
                    if now - last_cf_retry_at >= 10:
                        if log_callback:
                            log_callback("[*] 最终页 Cloudflare 卡住，自动二次复用 Turnstile...")
                        try:
                            status = ensure_cf_token(
                                page,
                                scene=SCENE_FINAL,
                                get_token_fn=getTurnstileToken,
                                reset=False,
                                log_callback=log_callback,
                                cancel_callback=cancel_callback,
                            )
                            if log_callback:
                                log_callback(
                                    f"[*] 最终页 Turnstile 二次复用完成 | solved={status.get('solved')} tokenLen={status.get('token_len')} input={status.get('input_len')}"
                                )
                        except Exception as cf_exc:
                            if log_callback:
                                log_callback(f"[Debug] 最终页 Turnstile 二次复用失败: {cf_exc}")
                        last_cf_retry_at = now

            cookies = page.cookies(all_domains=True, all_info=True) or []
            for item in cookies:
                if isinstance(item, dict):
                    name = str(item.get("name", "")).strip()
                    value = str(item.get("value", "")).strip()
                else:
                    name = str(getattr(item, "name", "")).strip()
                    value = str(getattr(item, "value", "")).strip()

                if name:
                    last_seen_names.add(name)

                if name == "sso" and value:
                    if log_callback:
                        log_callback("[*] 已获取到 sso cookie")
                    return value
        except PageDisconnectedError:
            refresh_active_page()
        except AccountRetryNeeded:
            raise
        except Exception:
            pass

        sleep_with_cancel(1, cancel_callback)

    raise AccountRetryNeeded(
        f"等待 sso cookie 超时({timeout}s)：未获取到 sso cookie。已看到 cookies: {sorted(last_seen_names)}"
    )



def run_single_account(
    *,
    log_callback,
    cancel_callback,
    accounts_output_file,
    state_callback=None,
    on_success=None,
    on_failure=None,
    on_retry=None,
    append_result=None,
    global_stats=False,
):
    def emit_state(**fields):
        if state_callback:
            try:
                state_callback(**fields)
            except Exception:
                pass

    email = ""
    dev_token = ""
    code = ""
    mail_ok = False
    current_email = ""
    max_mail_retry = 3

    emit_state(phase="account_begin", current_email="", last_error="")
    for mail_try in range(1, max_mail_retry + 1):
        emit_state(phase="open_signup", current_email=current_email, mail_try=mail_try)
        log_callback(f"[*] 1. 打开注册页 (尝试 {mail_try}/{max_mail_retry})")
        open_signup_page(log_callback=log_callback, cancel_callback=cancel_callback)

        emit_state(phase="submit_email", current_email=current_email, mail_try=mail_try)
        log_callback("[*] 2. 创建邮箱并提交")
        email, dev_token = fill_email_and_submit(
            log_callback=log_callback, cancel_callback=cancel_callback
        )
        current_email = email
        emit_state(phase="fetch_code", current_email=current_email, mail_try=mail_try)
        log_callback(f"[*] 邮箱: {email}")
        log_callback(f"[Debug] 邮箱credential(jwt): {dev_token}")
        try:
            with open(
                os.path.join(os.path.dirname(__file__), "mail_credentials.txt"),
                "a",
                encoding="utf-8",
            ) as f:
                f.write(f"{email}\t{dev_token}\n")
        except Exception:
            pass

        log_callback("[*] 3. 拉取验证码")
        try:
            code = fill_code_and_submit(
                email,
                dev_token,
                log_callback=log_callback,
                cancel_callback=cancel_callback,
            )
            mail_ok = True
            break
        except Exception as mail_exc:
            msg = str(mail_exc)
            if ("未收到验证码" in msg or "验证码" in msg) and mail_try < max_mail_retry:
                emit_state(phase="mail_retry", current_email=current_email, last_error=msg, mail_try=mail_try)
                if on_retry:
                    try:
                        on_retry(stage="mail", email=current_email, error=msg, mail_try=mail_try)
                    except Exception:
                        pass
                log_callback(f"[!] 本邮箱未取到验证码，自动更换新邮箱重试: {msg}")
                restart_browser(log_callback=log_callback)
                sleep_with_cancel(1, cancel_callback)
                continue
            raise

    if not mail_ok:
        raise Exception("验证码阶段失败，已达到最大重试次数")

    log_callback(f"[*] 验证码: {code}")
    emit_state(phase="fill_profile", current_email=current_email)
    log_callback("[*] 4. 填写资料")
    profile = fill_profile_and_submit(
        log_callback=log_callback, cancel_callback=cancel_callback
    )
    log_callback(f"[*] 资料已填: {profile.get('given_name')} {profile.get('family_name')}")

    emit_state(phase="wait_sso", current_email=current_email)
    log_callback("[*] 5. 等待 sso cookie")
    sso = wait_for_sso_cookie(log_callback=log_callback, cancel_callback=cancel_callback)

    emit_state(phase="oauth", current_email=current_email)
    try_xai_oauth_after_sso(
        email,
        profile.get("password", ""),
        mail_token=dev_token,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )

    if config.get("enable_nsfw", True):
        emit_state(phase="nsfw", current_email=current_email)
        log_callback("[*] 7. 开启 NSFW")
        nsfw_ok, nsfw_msg = enable_nsfw_for_token(sso, log_callback=log_callback)
        if nsfw_ok:
            log_callback(f"[+] NSFW 开启成功: {nsfw_msg}")
        else:
            log_callback(f"[!] NSFW 未开启，继续保存账号: {nsfw_msg}")

    try:
        line = f"{email}----{profile.get('password','')}----{sso}\n"
        with open(accounts_output_file, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as file_exc:
        log_callback(f"[Debug] 保存账号文件失败: {file_exc}")

    add_token_to_grok2api_pools(sso, email=email, log_callback=log_callback)
    if append_result:
        append_result({"email": email, "sso": sso, "profile": profile})

    if global_stats:
        stat_succ, stat_fail = update_global_stats(success=True)
    else:
        stat_succ = stat_fail = None

    emit_state(phase="account_done", current_email=current_email, last_error="")
    if on_success:
        try:
            on_success(email=email, profile=profile, sso=sso, stat_success=stat_succ, stat_fail=stat_fail)
        except TypeError:
            on_success(email, profile, sso)
    result = {
        "email": email,
        "dev_token": dev_token,
        "code": code,
        "profile": profile,
        "sso": sso,
        "stat_success": stat_succ,
        "stat_fail": stat_fail,
    }
    return result


class GrokRegisterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Grok 注册机")
        self.root.geometry("1120x900")
        self.root.minsize(960, 700)
        self.is_running = False
        self.batch_count = 0
        self.success_count = 0
        self.fail_count = 0
        self.results = []
        self.stop_requested = False
        self.ui_queue = queue.Queue()
        self.accounts_output_file = ""
        self.setup_ui()

    def setup_ui(self):
        load_config()
        main_frame = tk.Frame(self.root, bg=UI_BG, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(3, weight=1)

        config_frame = tk.LabelFrame(
            main_frame,
            text="配置",
            bg=UI_PANEL_BG,
            fg=UI_FG,
            padx=10,
            pady=10,
            relief=tk.GROOVE,
            borderwidth=1,
        )
        config_frame.grid(row=0, column=0, sticky=tk.EW, pady=(0, 8))
        config_frame.grid_columnconfigure(1, weight=1, minsize=260)
        config_frame.grid_columnconfigure(3, weight=1, minsize=260)

        def add_label(row, column, text):
            tk_label(config_frame, text=text, bg=UI_PANEL_BG).grid(
                row=row,
                column=column,
                sticky=tk.W,
                padx=(0, 6),
                pady=3,
            )

        def add_field(widget, row, column, columnspan=1, sticky=tk.EW):
            widget.grid(
                row=row,
                column=column,
                columnspan=columnspan,
                sticky=sticky,
                padx=(0, 14),
                pady=3,
            )

        add_label(0, 0, "邮箱服务商:")
        self.email_provider_var = tk.StringVar(value=config.get("email_provider", "duckmail"))
        self.email_provider_combo = tk_option_menu(config_frame, self.email_provider_var, ["duckmail", "yyds", "cloudflare"], width=12)
        add_field(self.email_provider_combo, 0, 1, sticky=tk.W)

        add_label(0, 2, "注册数量:")
        self.count_var = tk.StringVar(value=str(config.get("register_count", 1)))
        self.concurrent_workers_var = tk.StringVar(value=str(config.get("concurrent_workers", 1)))
        self.count_spinbox = tk.Spinbox(
            config_frame,
            from_=1,
            to=2500,
            width=8,
            textvariable=self.count_var,
            bg=UI_ENTRY_BG,
            fg=UI_FG,
            insertbackground=UI_FG,
            buttonbackground=UI_BUTTON_BG,
            disabledbackground="#2f2f2f",
            disabledforeground=UI_MUTED_FG,
            relief=tk.SOLID,
        )
        add_field(self.count_spinbox, 0, 3, sticky=tk.W)

        add_label(0, 4, "并发数:")
        self.workers_spinbox = tk.Spinbox(
            config_frame,
            from_=1,
            to=20,
            width=6,
            textvariable=self.concurrent_workers_var,
            bg=UI_ENTRY_BG,
            fg=UI_FG,
            insertbackground=UI_FG,
            buttonbackground=UI_BUTTON_BG,
            disabledbackground="#2f2f2f",
            disabledforeground=UI_MUTED_FG,
            relief=tk.SOLID,
        )
        add_field(self.workers_spinbox, 0, 5, sticky=tk.W)

        add_label(1, 0, "注册选项:")
        self.nsfw_var = tk.BooleanVar(value=config.get("enable_nsfw", True))
        self.nsfw_check = tk_checkbutton(config_frame, text="注册后开启 NSFW", variable=self.nsfw_var)
        add_field(self.nsfw_check, 1, 1, sticky=tk.W)

        add_label(1, 2, "代理池(可多条):")
        _proxy_init = config.get("proxy", "")
        if isinstance(config.get("proxies"), list) and config.get("proxies"):
            _proxy_init = "\n".join(str(x) for x in config.get("proxies") if str(x).strip()) or _proxy_init
        self.proxy_var = tk.StringVar(value=_proxy_init)
        self.proxy_entry = tk_entry(config_frame, textvariable=self.proxy_var, width=34)
        add_field(self.proxy_entry, 1, 3)

        add_label(2, 0, "DuckMail API Key:")
        self.api_key_var = tk.StringVar(value=config.get("duckmail_api_key", ""))
        self.api_key_entry = tk_entry(config_frame, textvariable=self.api_key_var, width=34)
        add_field(self.api_key_entry, 2, 1)

        add_label(2, 2, "Cloudflare 鉴权模式:")
        self.cloudflare_auth_mode_var = tk.StringVar(value=config.get("cloudflare_auth_mode", "none"))
        self.cloudflare_auth_mode_combo = tk_option_menu(
            config_frame, self.cloudflare_auth_mode_var, ["query-key", "bearer", "x-api-key", "x-admin-auth", "none"], width=12
        )
        add_field(self.cloudflare_auth_mode_combo, 2, 3, sticky=tk.W)

        add_label(3, 0, "Cloudflare API Base:")
        self.cloudflare_api_base_var = tk.StringVar(value=config.get("cloudflare_api_base", ""))
        self.cloudflare_api_base_entry = tk_entry(config_frame, textvariable=self.cloudflare_api_base_var, width=72)
        add_field(self.cloudflare_api_base_entry, 3, 1, columnspan=3)

        add_label(4, 0, "Cloudflare API Key:")
        self.cloudflare_api_key_var = tk.StringVar(value=config.get("cloudflare_api_key", ""))
        self.cloudflare_api_key_entry = tk_entry(config_frame, textvariable=self.cloudflare_api_key_var, width=34)
        add_field(self.cloudflare_api_key_entry, 4, 1)

        add_label(4, 2, "CF 路径:")
        self.cloudflare_paths_var = tk.StringVar(
            value=",".join(
                [
                    config.get("cloudflare_path_domains", "/api/domains"),
                    config.get("cloudflare_path_accounts", "/api/new_address"),
                    config.get("cloudflare_path_token", "/api/token"),
                    config.get("cloudflare_path_messages", "/api/mails"),
                ]
            )
        )
        self.cloudflare_paths_entry = tk_entry(config_frame, textvariable=self.cloudflare_paths_var, width=34)
        add_field(self.cloudflare_paths_entry, 4, 3)

        add_label(5, 0, "grok2api 本地入池:")
        self.grok2api_local_auto_var = tk.BooleanVar(value=bool(config.get("grok2api_auto_add_local", True)))
        self.grok2api_local_auto_check = tk_checkbutton(config_frame, variable=self.grok2api_local_auto_var)
        add_field(self.grok2api_local_auto_check, 5, 1, sticky=tk.W)

        add_label(5, 2, "grok2api 池名:")
        self.grok2api_pool_name_var = tk.StringVar(value=str(config.get("grok2api_pool_name", "ssoBasic")))
        self.grok2api_pool_name_combo = tk_option_menu(
            config_frame, self.grok2api_pool_name_var, ["ssoBasic", "ssoSuper"], width=12
        )
        add_field(self.grok2api_pool_name_combo, 5, 3, sticky=tk.W)

        add_label(6, 0, "本地 token.json:")
        self.grok2api_local_file_var = tk.StringVar(value=str(config.get("grok2api_local_token_file", "")))
        self.grok2api_local_file_entry = tk_entry(config_frame, textvariable=self.grok2api_local_file_var, width=72)
        add_field(self.grok2api_local_file_entry, 6, 1, columnspan=3)

        add_label(7, 0, "grok2api 远端入池:")
        self.grok2api_remote_auto_var = tk.BooleanVar(value=bool(config.get("grok2api_auto_add_remote", False)))
        self.grok2api_remote_auto_check = tk_checkbutton(config_frame, variable=self.grok2api_remote_auto_var)
        add_field(self.grok2api_remote_auto_check, 7, 1, sticky=tk.W)

        add_label(8, 0, "grok2api 远端 Base:")
        self.grok2api_remote_base_var = tk.StringVar(value=str(config.get("grok2api_remote_base", "")))
        self.grok2api_remote_base_entry = tk_entry(config_frame, textvariable=self.grok2api_remote_base_var, width=72)
        add_field(self.grok2api_remote_base_entry, 8, 1, columnspan=3)

        add_label(9, 0, "grok2api 远端 app_key:")
        self.grok2api_remote_key_var = tk.StringVar(value=str(config.get("grok2api_remote_app_key", "")))
        self.grok2api_remote_key_entry = tk_entry(config_frame, textvariable=self.grok2api_remote_key_var, width=72)
        add_field(self.grok2api_remote_key_entry, 9, 1, columnspan=3)

        btn_frame = tk.Frame(main_frame, bg=UI_BG)
        btn_frame.grid(row=1, column=0, sticky=tk.EW, pady=(0, 6))
        self.start_btn = tk_button(btn_frame, text="开始注册", command=self.start_registration)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = tk_button(btn_frame, text="停止", command=self.stop_registration, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.clear_btn = tk_button(btn_frame, text="清空日志", command=self.clear_log)
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        status_frame = tk.Frame(main_frame, bg=UI_BG)
        status_frame.grid(row=2, column=0, sticky=tk.EW, pady=(0, 6))
        self.status_var = tk.StringVar(value="就绪")
        tk_label(status_frame, text="状态: ").pack(side=tk.LEFT)
        self.status_label = tk.Label(status_frame, textvariable=self.status_var, bg=UI_BG, fg="green")
        self.status_label.pack(side=tk.LEFT)
        self.stats_var = tk.StringVar(value="成功: 0 | 失败: 0")
        tk.Label(status_frame, textvariable=self.stats_var, bg=UI_BG, fg=UI_FG).pack(side=tk.RIGHT)
        log_frame = tk.LabelFrame(
            main_frame,
            text="日志",
            bg=UI_PANEL_BG,
            fg=UI_FG,
            padx=5,
            pady=5,
            relief=tk.GROOVE,
            borderwidth=1,
        )
        log_frame.grid(row=3, column=0, sticky=tk.NSEW)
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=18,
            width=60,
            bg="#111111",
            fg="#f5f5f5",
            insertbackground="#f5f5f5",
            selectbackground="#345a8a",
            selectforeground="#ffffff",
            relief=tk.SOLID,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground="#555555",
        )
        self.log_text.grid(row=0, column=0, sticky=tk.NSEW)
        self.log("[*] GUI 已就绪，配置已加载")
        self.log(f"[*] 当前邮箱服务商: {self.email_provider_var.get()} | 注册数量: {self.count_var.get()}")

    def log(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}"
        print(line, flush=True)
        self.log_text.insert(tk.END, f"{line}\n")
        self.log_text.see(tk.END)

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)

    def update_stats(self):
        self.stats_var.set(f"成功: {self.success_count} | 失败: {self.fail_count}")

    def _set_running_ui(self, running):
        self.is_running = running
        self.start_btn.config(state=tk.DISABLED if running else tk.NORMAL)
        self.stop_btn.config(state=tk.NORMAL if running else tk.DISABLED)
        self.status_var.set("运行中..." if running else "就绪")
        self.status_label.config(foreground="blue" if running else "green")

    def should_stop(self):
        return self.stop_requested or not self.is_running

    def start_registration(self):
        if self.is_running:
            self.log("[!] 当前已有任务在运行")
            return

        config["email_provider"] = self.email_provider_var.get().strip() or "duckmail"
        config["enable_nsfw"] = bool(self.nsfw_var.get())
        proxy_raw = self.proxy_var.get().strip()
        pool = _split_proxy_entries(proxy_raw)
        if len(pool) > 1:
            config["proxy"] = proxy_raw
            config["proxies"] = pool
        elif len(pool) == 1:
            config["proxy"] = normalize_proxy_config(pool[0]) or pool[0]
            config["proxies"] = [config["proxy"]]
        else:
            config["proxy"] = ""
            config["proxies"] = []
        config["duckmail_api_key"] = self.api_key_var.get().strip()
        config["cloudflare_api_base"] = self.cloudflare_api_base_var.get().strip()
        config["cloudflare_api_key"] = self.cloudflare_api_key_var.get().strip()
        config["cloudflare_auth_mode"] = self.cloudflare_auth_mode_var.get().strip() or "none"
        config["grok2api_auto_add_local"] = bool(self.grok2api_local_auto_var.get())
        config["grok2api_local_token_file"] = self.grok2api_local_file_var.get().strip()
        config["grok2api_pool_name"] = self.grok2api_pool_name_var.get().strip() or "ssoBasic"
        config["grok2api_auto_add_remote"] = bool(self.grok2api_remote_auto_var.get())
        config["grok2api_remote_base"] = self.grok2api_remote_base_var.get().strip()
        config["grok2api_remote_app_key"] = self.grok2api_remote_key_var.get().strip()
        raw_paths = [x.strip() for x in self.cloudflare_paths_var.get().split(",") if x.strip()]
        if len(raw_paths) >= 4:
            config["cloudflare_path_domains"] = raw_paths[0] if raw_paths[0].startswith("/") else ("/" + raw_paths[0])
            config["cloudflare_path_accounts"] = raw_paths[1] if raw_paths[1].startswith("/") else ("/" + raw_paths[1])
            config["cloudflare_path_token"] = raw_paths[2] if raw_paths[2].startswith("/") else ("/" + raw_paths[2])
            config["cloudflare_path_messages"] = raw_paths[3] if raw_paths[3].startswith("/") else ("/" + raw_paths[3])
        save_config()
        if config["email_provider"] == "cloudflare" and not config["cloudflare_api_base"]:
            self.log("[!] Cloudflare 模式需要先填写 Cloudflare API Base")
            return
        try:
            count = int(self.count_var.get())
        except Exception:
            self.log("[!] 注册数量无效")
            return
        config["register_count"] = count
        try:
            config["concurrent_workers"] = max(1, int(self.concurrent_workers_var.get()))
        except Exception:
            config["concurrent_workers"] = max(1, int(config.get("concurrent_workers", 1) or 1))
        save_config()
        self.stop_requested = False
        self.success_count = 0
        self.fail_count = 0
        self.results = []
        now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.accounts_output_file = os.path.join(
            os.path.dirname(__file__), f"accounts_{now}.txt"
        )
        self.update_stats()
        self._set_running_ui(True)
        self.log(f"[*] 配置已保存，开始执行。目标数量: {count} | 并发: {config.get('concurrent_workers', 1)}")
        self.log(f"[*] 成功账号将实时保存到: {self.accounts_output_file}")
        threading.Thread(
            target=self.run_registration,
            args=(count,),
            daemon=True,
        ).start()

    def stop_registration(self):
        self.stop_requested = True
        self.log("[!] 用户停止注册")

    def run_registration(self, count):
        try:
            workers = max(1, int(config.get("concurrent_workers", 1) or 1))
            if workers > 1:
                self.log(f"[*] GUI 并发模式 workers={workers}（多进程，各自独立浏览器）")
                run_registration_concurrent(count, workers=workers)
                return
            start_browser(log_callback=self.log)
            self.log("[*] 浏览器已启动")
            i = 0
            retry_count_for_slot = 0
            max_slot_retry = 3
            while i < count:
                if self.should_stop():
                    break
                account_success = False
                self.log(f"--- 开始第 {i + 1}/{count} 个账号 ---")
                try:
                    run_single_account(
                        log_callback=self.log,
                        cancel_callback=self.should_stop,
                        accounts_output_file=self.accounts_output_file,
                        append_result=self.results.append,
                        on_success=lambda **kw: self.log(f"[+] 注册成功: {kw['email']}"),
                    )
                    self.success_count += 1
                    account_success = True
                    retry_count_for_slot = 0
                    i += 1
                    if (
                        self.success_count > 0
                        and self.success_count % MEMORY_CLEANUP_INTERVAL == 0
                        and i < count
                    ):
                        cleanup_runtime_memory(
                            log_callback=self.log,
                            reason=f"已成功 {self.success_count} 个账号，执行定期清理",
                        )
                except RegistrationCancelled:
                    self.log("[!] 注册被用户停止")
                    break
                except AccountRetryNeeded as exc:
                    retry_count_for_slot += 1
                    if retry_count_for_slot <= max_slot_retry:
                        self.log(
                            f"[!] 当前账号流程卡住，重试第 {retry_count_for_slot}/{max_slot_retry} 次: {exc}"
                        )
                    else:
                        self.fail_count += 1
                        self.log(f"[-] 当前账号已达到最大重试次数，跳过: {exc}")
                        retry_count_for_slot = 0
                        i += 1
                except Exception as exc:
                    self.fail_count += 1
                    retry_count_for_slot = 0
                    i += 1
                    self.log(f"[-] 注册失败: {exc}")
                finally:
                    self.update_stats()
                    if self.should_stop():
                        break
                    finish_account_browser_cycle(
                        success=account_success,
                        completed_count=i,
                        log_callback=self.log,
                        cancel_callback=self.should_stop,
                    )
        except Exception as exc:
            self.log(f"[!] 任务异常: {exc}")
        finally:
            stop_browser()
            reconcile_registration_outputs(
                self.accounts_output_file,
                expected_success=self.success_count,
                log_callback=self.log,
            )
            self._set_running_ui(False)
            self.log("[*] 任务结束")


class CliStopController:
    def __init__(self):
        self.stop_requested = False

    def should_stop(self):
        return self.stop_requested

    def stop(self):
        self.stop_requested = True


def cli_log(message):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}", flush=True)


def run_registration_cli(count):
    controller = CliStopController()
    retry_count_for_slot = 0
    max_slot_retry = 3
    success_count = 0
    fail_count = 0
    accounts_output_file = os.path.join(
        os.path.dirname(__file__),
        f"accounts_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
    )
    cli_log(f"[*] 终端模式启动，目标数量: {count}")
    cli_log(f"[*] 成功账号将实时保存到: {accounts_output_file}")
    try:
        start_browser(log_callback=cli_log)
        cli_log("[*] 浏览器已启动")
        i = 0
        while i < count:
            if controller.should_stop():
                break
            account_success = False
            cli_log(f"--- 开始第 {i + 1}/{count} 个账号 ---")
            try:
                run_single_account(
                    log_callback=cli_log,
                    cancel_callback=controller.should_stop,
                    accounts_output_file=accounts_output_file,
                    on_success=lambda **kw: cli_log(f"[+] 注册成功: {kw['email']}"),
                )
                success_count += 1
                account_success = True
                retry_count_for_slot = 0
                i += 1
                cli_log(f"[*] 当前统计: 成功 {success_count} | 失败 {fail_count}")
                if (
                    success_count > 0
                    and success_count % MEMORY_CLEANUP_INTERVAL == 0
                    and i < count
                ):
                    cleanup_runtime_memory(
                        log_callback=cli_log,
                        reason=f"已成功 {success_count} 个账号，执行定期清理",
                    )
            except RegistrationCancelled:
                cli_log("[!] 注册被停止")
                break
            except AccountRetryNeeded as exc:
                retry_count_for_slot += 1
                if retry_count_for_slot <= max_slot_retry:
                    cli_log(f"[!] 当前账号流程卡住，重试第 {retry_count_for_slot}/{max_slot_retry} 次: {exc}")
                else:
                    fail_count += 1
                    retry_count_for_slot = 0
                    i += 1
                    cli_log(f"[-] 当前账号已达到最大重试次数，跳过: {exc}")
            except Exception as exc:
                fail_count += 1
                retry_count_for_slot = 0
                i += 1
                cli_log(f"[-] 注册失败: {exc}")
            finally:
                if controller.should_stop():
                    break
                finish_account_browser_cycle(
                    success=account_success,
                    completed_count=i,
                    log_callback=cli_log,
                    cancel_callback=controller.should_stop,
                )
    except KeyboardInterrupt:
        controller.stop()
        cli_log("[!] 收到 Ctrl+C，正在停止并清理")
    finally:
        cleanup_runtime_memory(log_callback=cli_log, reason="任务结束")
        reconcile_registration_outputs(
            accounts_output_file,
            expected_success=success_count,
            log_callback=cli_log,
        )
        cli_log(f"[*] 任务结束。成功 {success_count} | 失败 {fail_count}")



def _split_counts(total, workers):
    total = max(0, int(total or 0))
    workers = max(1, int(workers or 1))
    if total <= 0:
        return []
    workers = min(workers, total)
    base = total // workers
    rem = total % workers
    out = []
    for i in range(workers):
        out.append(base + (1 if i < rem else 0))
    return [x for x in out if x > 0]


def _spawn_worker_process(script, worker_id, count, out_file):
    import subprocess

    cmd = [
        sys.executable,
        script,
        "worker",
        "--id",
        str(worker_id),
        "--count",
        str(count),
        "--out",
        out_file,
    ]
    return subprocess.Popen(cmd, cwd=os.path.dirname(script) or ".")


def run_registration_concurrent(count, workers=None):
    """Run multiple isolated processes, each with its own browser/proxy/oauth ports."""
    reset_global_stats()
    reset_worker_states()
    total = max(1, int(count or 1))
    workers = max(1, int(workers if workers is not None else config.get("concurrent_workers", 1) or 1))
    workers = min(workers, total)
    if workers <= 1:
        return run_registration_cli(total)

    parts = _split_counts(total, workers)
    now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(os.path.dirname(__file__), f"accounts_{now}.txt")
    # ensure empty shared output file
    try:
        with open(out_file, "a", encoding="utf-8"):
            pass
    except Exception:
        pass

    cli_log(f"[*] 并发模式启动: workers={len(parts)} | 目标数量={total} | 分配={parts}")
    cli_log(f"[*] 成功账号将实时保存到: {out_file}")
    cli_log("[*] 每个 worker 独立进程/浏览器/代理转发/OAuth 回调端口")

    script = os.path.abspath(__file__)
    worker_hang_timeout = max(120, int(config.get("concurrent_worker_hang_timeout", 420) or 420))
    account_hard_timeout = max(180, int(config.get("concurrent_account_hard_timeout", 900) or 900))
    restart_cfg = config.get("concurrent_worker_restart_limit", 1)
    if restart_cfg in (None, ""):
        restart_cfg = 1
    worker_restart_limit = max(0, int(restart_cfg))
    heartbeat_log_interval = max(5, int(config.get("concurrent_heartbeat_log_interval", 15) or 15))
    def start_worker(idx, assigned, restarts=0):
        cli_log(f"[*] 启动 worker-{idx}: count={assigned}")
        return {
            "proc": _spawn_worker_process(script, idx, assigned, out_file),
            "assigned": assigned,
            "restarts": restarts,
            "started_at": time.time(),
            "started_mono": monotonic_now(),
            "run_id": None,
        }

    active = {idx: start_worker(idx, n, 0) for idx, n in enumerate(parts, start=1)}

    success_like = 0
    last_heartbeat_log = 0.0
    try:
        while active:
            now_mono = monotonic_now()
            if now_mono - last_heartbeat_log >= heartbeat_log_interval:
                g_succ, g_fail = get_global_stats()
                worker_summaries = []
                for idx in sorted(active):
                    meta = active[idx]
                    expected_run_id = meta.get("run_id")
                    st = read_worker_state(idx, run_id=expected_run_id)
                    if not expected_run_id and st.get("run_id"):
                        meta["run_id"] = st.get("run_id")
                        expected_run_id = meta.get("run_id")
                        st = read_worker_state(idx, run_id=expected_run_id) or st
                    completed = int(st.get("completed", 0) or 0)
                    assigned = int(meta.get("assigned", 0) or 0)
                    phase = str(st.get("phase", "starting") or "starting")
                    worker_summaries.append(f"W{idx}:{completed}/{assigned}:{phase}")
                cli_log(
                    f"[*] 并发心跳 | 全局统计: 成功 {g_succ} | 失败 {g_fail} | active={len(active)} | "
                    + " ; ".join(worker_summaries)
                )
                last_heartbeat_log = now_mono

            for idx in list(sorted(active)):
                meta = active[idx]
                proc = meta["proc"]
                rc = proc.poll()
                expected_run_id = meta.get("run_id")
                st = read_worker_state(idx, run_id=expected_run_id)
                if not expected_run_id and st.get("run_id"):
                    meta["run_id"] = st.get("run_id")
                    expected_run_id = meta.get("run_id")
                    st = read_worker_state(idx, run_id=expected_run_id) or st
                completed = int(st.get("completed", 0) or 0)
                assigned = int(meta.get("assigned", 0) or 0)
                remaining = max(0, assigned - completed)

                if rc is not None:
                    cli_log(f"[*] worker-{idx} 退出码={rc} | completed={completed}/{assigned}")
                    if remaining > 0 and meta["restarts"] < worker_restart_limit:
                        restart_no = meta["restarts"] + 1
                        cli_log(
                            f"[!] worker-{idx} 提前退出，自动重启 | remain={remaining} | "
                            f"restart={restart_no}/{worker_restart_limit}"
                        )
                        remove_worker_state(idx, run_id=meta.get("run_id"))
                        active[idx] = start_worker(idx, remaining, restart_no)
                    else:
                        if remaining > 0:
                            g_succ, g_fail = update_global_stats_batch(fail_inc=remaining)
                            cli_log(
                                f"[!] worker-{idx} 未完成剩余任务，记失败 {remaining} 个 | "
                                f"全局统计: 成功 {g_succ} | 失败 {g_fail}"
                            )
                        elif rc == 0:
                            success_like += 1
                        remove_worker_state(idx, run_id=meta.get("run_id"))
                        active.pop(idx, None)
                    continue

                hb_mono = float(st.get("heartbeat_mono") or meta.get("started_mono") or now_mono)
                slot_started_mono = float(st.get("slot_started_mono") or hb_mono or now_mono)
                hb_age = max(0, now_mono - hb_mono)
                slot_age = max(0, now_mono - slot_started_mono)
                phase = str(st.get("phase", "starting") or "starting")
                completed_all = completed >= assigned > 0
                stale = hb_age >= worker_hang_timeout or slot_age >= account_hard_timeout
                if stale:
                    reason_bits = []
                    if hb_age >= worker_hang_timeout:
                        reason_bits.append(f"heartbeat {int(hb_age)}s>={worker_hang_timeout}s")
                    if slot_age >= account_hard_timeout:
                        reason_bits.append(f"slot {int(slot_age)}s>={account_hard_timeout}s")
                    cli_log(
                        f"[!] worker-{idx} 超时保护触发 | phase={phase} | "
                        f"completed={completed}/{assigned} | {'; '.join(reason_bits)}"
                    )
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                    if remaining > 0 and not completed_all and meta["restarts"] < worker_restart_limit:
                        restart_no = meta["restarts"] + 1
                        cli_log(
                            f"[!] worker-{idx} 超时后自动重启 | remain={remaining} | "
                            f"restart={restart_no}/{worker_restart_limit}"
                        )
                        remove_worker_state(idx, run_id=meta.get("run_id"))
                        active[idx] = start_worker(idx, remaining, restart_no)
                    else:
                        if remaining > 0 and not completed_all:
                            g_succ, g_fail = update_global_stats_batch(fail_inc=remaining)
                            cli_log(
                                f"[!] worker-{idx} 超时且重启次数耗尽，剩余 {remaining} 个账号记失败 | "
                                f"全局统计: 成功 {g_succ} | 失败 {g_fail}"
                            )
                        remove_worker_state(idx, run_id=meta.get("run_id"))
                        active.pop(idx, None)
            time.sleep(2)
    except KeyboardInterrupt:
        cli_log("[!] 收到 Ctrl+C，正在终止全部 worker")
        for idx, meta in active.items():
            p = meta["proc"]
            try:
                p.terminate()
            except Exception:
                pass
        for idx, meta in active.items():
            p = meta["proc"]
            try:
                p.wait(timeout=5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        raise
    g_succ, g_fail = get_global_stats()
    cli_log(
        f"[*] 并发任务结束 | 全局统计: 成功 {g_succ} | 失败 {g_fail} | "
        f"worker完成={success_like}/{len(parts)} | 输出={out_file}"
    )
    reconcile_registration_outputs(out_file, expected_success=g_succ, log_callback=cli_log)
    return out_file


def run_registration_worker(worker_id, count, out_file):
    """Single concurrent worker process entry."""
    worker_id = max(1, int(worker_id or 1))
    count = max(1, int(count or 1))
    run_id = f"{int(time.time())}-{os.getpid()}-{secrets.token_hex(4)}"
    config["_worker_id"] = worker_id
    config["_worker_run_id"] = run_id
    # unique oauth/proxy ports for this process
    base_proxy = int(config.get("local_proxy_port", 17890) or 17890)
    base_oauth = int(config.get("xai_oauth_callback_port", 56121) or 56121)
    config["local_proxy_port"] = base_proxy + worker_id
    config["xai_oauth_callback_port"] = base_oauth + worker_id
    local_success = 0
    local_fail = 0

    def wlog(message):
        msg = str(message or "")
        tag = f"[W{worker_id}]"
        if not msg.startswith(tag):
            msg = f"{tag} {msg}"
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {msg}", flush=True)
        try:
            write_worker_state(worker_id, run_id=run_id, last_log=msg)
        except Exception:
            pass

    def wstate(**fields):
        base = {
            "pid": os.getpid(),
            "assigned_count": count,
            "completed": local_success + local_fail,
            "success_local": local_success,
            "fail_local": local_fail,
        }
        base.update(fields)
        write_worker_state(worker_id, run_id=run_id, **base)

    controller = CliStopController()
    retry_count_for_slot = 0
    max_slot_retry = 3
    accounts_output_file = str(out_file or "").strip() or os.path.join(
        os.path.dirname(__file__),
        f"accounts_w{worker_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
    )
    wlog(f"[*] worker 启动 | count={count} | proxyPort={config.get('local_proxy_port')} | oauthPort={config.get('xai_oauth_callback_port')} | run_id={run_id}")
    wlog(f"[*] 成功账号保存到: {accounts_output_file}")
    wstate(
        phase="starting",
        started_mono=monotonic_now(),
        started_at=time.time(),
        slot_started_mono=0.0,
        slot_started_at=0.0,
        current_index=0,
        current_email="",
        output_file=accounts_output_file,
    )
    try:
        start_browser(log_callback=wlog)
        wlog("[*] 浏览器已启动")
        i = 0
        while i < count:
            if controller.should_stop():
                break
            slot_started_mono = monotonic_now()
            slot_started_at = time.time()
            current_email = ""
            account_success = False
            wstate(
                phase="account_begin",
                current_index=i + 1,
                slot_started_mono=slot_started_mono,
                slot_started_at=slot_started_at,
                current_email="",
                last_error="",
            )
            wlog(f"--- 开始第 {i + 1}/{count} 个账号 ---")
            try:
                def _state_callback(**fields):
                    nonlocal current_email
                    if fields.get("current_email"):
                        current_email = fields.get("current_email") or current_email
                    payload = {
                        "current_index": i + 1,
                        "slot_started_mono": slot_started_mono,
                        "slot_started_at": slot_started_at,
                        "current_email": current_email,
                    }
                    payload.update(fields)
                    wstate(**payload)

                def _on_success(**kw):
                    nonlocal local_success
                    local_success += 1
                    email = kw.get("email", "")
                    stat_success = kw.get("stat_success")
                    stat_fail = kw.get("stat_fail")
                    wlog(f"[+] 注册成功: {email}")
                    wlog(f"[*] 全局统计: 成功 {stat_success} | 失败 {stat_fail}")

                run_single_account(
                    log_callback=wlog,
                    cancel_callback=controller.should_stop,
                    accounts_output_file=accounts_output_file,
                    state_callback=_state_callback,
                    on_success=_on_success,
                    global_stats=True,
                )
                retry_count_for_slot = 0
                i += 1
                account_success = True
                wstate(
                    phase="account_done",
                    current_index=i,
                    slot_started_mono=0.0,
                    slot_started_at=0.0,
                    current_email=current_email,
                    last_error="",
                )
            except RegistrationCancelled:
                wstate(
                    phase="cancelled",
                    current_index=i + 1,
                    slot_started_mono=slot_started_mono,
                    slot_started_at=slot_started_at,
                    current_email=current_email,
                )
                wlog("[!] 注册被停止")
                break
            except AccountRetryNeeded as exc:
                retry_count_for_slot += 1
                wstate(
                    phase="retrying",
                    current_index=i + 1,
                    slot_started_mono=slot_started_mono,
                    slot_started_at=slot_started_at,
                    current_email=current_email,
                    last_error=str(exc),
                    retry_count=retry_count_for_slot,
                )
                if retry_count_for_slot <= max_slot_retry:
                    wlog(f"[!] 当前账号流程卡住，重试第 {retry_count_for_slot}/{max_slot_retry} 次: {exc}")
                else:
                    local_fail += 1
                    g_succ, g_fail = update_global_stats(success=False)
                    retry_count_for_slot = 0
                    i += 1
                    wstate(
                        phase="account_failed",
                        current_index=i,
                        slot_started_mono=0.0,
                        slot_started_at=0.0,
                        current_email=current_email,
                        last_error=str(exc),
                    )
                    wlog(f"[-] 当前账号已达到最大重试次数，跳过: {exc} | 全局统计: 成功 {g_succ} | 失败 {g_fail}")
            except Exception as exc:
                local_fail += 1
                g_succ, g_fail = update_global_stats(success=False)
                retry_count_for_slot = 0
                i += 1
                wstate(
                    phase="account_failed",
                    current_index=i,
                    slot_started_mono=0.0,
                    slot_started_at=0.0,
                    current_email=current_email,
                    last_error=str(exc),
                )
                wlog(f"[-] 注册失败: {exc} | 全局统计: 成功 {g_succ} | 失败 {g_fail}")
            finally:
                if controller.should_stop():
                    break
                wstate(
                    phase="restarting_browser",
                    current_index=i,
                    slot_started_mono=0.0,
                    slot_started_at=0.0,
                    current_email=current_email,
                )
                finish_account_browser_cycle(
                    success=account_success,
                    completed_count=i,
                    log_callback=wlog,
                    cancel_callback=controller.should_stop,
                )
    except KeyboardInterrupt:
        controller.stop()
        wstate(phase="keyboard_interrupt", slot_started_mono=0.0, slot_started_at=0.0)
        wlog("[!] 收到 Ctrl+C，正在停止并清理")
    except Exception as exc:
        wstate(phase="worker_exception", last_error=str(exc), slot_started_mono=0.0, slot_started_at=0.0)
        wlog(f"[!] 任务异常: {exc}")
        raise
    finally:
        wstate(phase="cleanup", slot_started_mono=0.0, slot_started_at=0.0)
        cleanup_runtime_memory(log_callback=wlog, reason="worker任务结束")
        try:
            stop_local_forwarder()
        except Exception:
            pass
        wstate(phase="exited", slot_started_mono=0.0, slot_started_at=0.0)
        g_succ, g_fail = get_global_stats()
        wlog(f"[*] worker 结束 | 全局统计: 成功 {g_succ} | 失败 {g_fail}")
        remove_worker_state(worker_id, run_id=run_id)
    return 0  # 退出码


def main_cli():
    load_config()
    count = int(config.get("register_count", 1) or 1)
    workers = max(1, int(config.get("concurrent_workers", 1) or 1))
    cli_log("[*] CLI 已加载配置")
    cli_log(
        f"[*] 当前邮箱服务商: {config.get('email_provider', 'duckmail')} | 注册数量: {count} | 并发: {workers}"
    )
    cli_log("[*] 输入 start 后开始；按 Ctrl+C 可强制停止")
    try:
        command = input("> ").strip().lower()
    except KeyboardInterrupt:
        cli_log("[!] 已取消")
        return
    if command != "start":
        cli_log("[!] 未输入 start，已退出")
        return
    if workers > 1:
        run_registration_concurrent(count, workers=workers)
    else:
        run_registration_cli(count)


def main():
    args = [a.strip() for a in sys.argv[1:]]
    if args:
        cmd = args[0].lower()
        if cmd in ("start", "cli", "--cli"):
            # optional: python grok_register_ttk.py cli --workers 3
            if "--workers" in args:
                try:
                    wi = args.index("--workers")
                    load_config()
                    config["concurrent_workers"] = max(1, int(args[wi + 1]))
                except Exception:
                    pass
            main_cli()
            return
        if cmd == "worker":
            # python grok_register_ttk.py worker --id 1 --count 2 --out accounts.txt
            load_config()
            worker_id = 1
            count = int(config.get("register_count", 1) or 1)
            out_file = ""
            i = 1
            while i < len(args):
                a = args[i]
                if a == "--id" and i + 1 < len(args):
                    worker_id = int(args[i + 1]); i += 2; continue
                if a == "--count" and i + 1 < len(args):
                    count = int(args[i + 1]); i += 2; continue
                if a == "--out" and i + 1 < len(args):
                    out_file = args[i + 1]; i += 2; continue
                i += 1
            try:
                run_registration_worker(worker_id, count, out_file)
            except Exception as exc:
                print(f"[W{worker_id}] worker fatal: {exc}", flush=True)
                raise SystemExit(1)
            return
    root = tk.Tk()
    setup_light_theme(root)
    app = GrokRegisterGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

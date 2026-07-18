# -*- coding: utf-8 -*-
"""Browserless xAI registration and OAuth credential flow.

This module deliberately contains no browser automation dependency.  It talks to
the same HTTP, gRPC-Web, and Next Server Action endpoints used by accounts.x.ai.

Cloudflare Turnstile and Castle are anti-abuse systems.  This client does not
attempt to fabricate either signal.  Callers must provide fresh, legitimately
obtained verification results for the exact account session and proxy in use.
That keeps the HTTP workflow usable in approved test environments while making
the verification boundary explicit instead of silently falling back to Chrome.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import concurrent.futures
import functools
import html as html_lib
import imaplib
import json
import os
import random
import re
import secrets
import string
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from email import policy as email_policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, quote, unquote, urljoin, urlparse

from curl_cffi import requests

from cross_process_lock import (
    CrossProcessFileLock,
    CrossProcessLockTimeout,
    atomic_write_private_lines,
    atomic_write_private_text,
    configured_lock_timeout,
    ensure_private_file,
)
from project_browser_registry import register_project_browser, unregister_project_browser
from local_paths import ACCOUNTS_DIR, CONFIG_PATH, CREDENTIALS_DIR, STATE_DIR

from turnstile_broker import (
    FingerprintProfile,
    SolveRequest,
    SolveResult,
    TokenLease,
    TokenLeaseError,
    TurnstileBroker,
    build_canonical_fingerprint_profile,
    get_shared_broker,
)

from xai_oauth import (
    XAI_REDIRECT_HOST,
    XAI_REDIRECT_PATH,
    XAI_SCOPE,
    build_authorize_url,
    build_credential_document,
    discover_endpoints,
    exchange_code_for_tokens,
    generate_pkce_codes,
    generate_random_token,
    save_credential_file,
)


ACCOUNT_ORIGIN = "https://accounts.x.ai"
SIGNUP_URL = f"{ACCOUNT_ORIGIN}/sign-up?redirect=grok-com"
SIGNIN_URL = f"{ACCOUNT_ORIGIN}/sign-in"
API_RPC_URL = f"{ACCOUNT_ORIGIN}/api/rpc"
DEFAULT_TIMEOUT = 30
DEFAULT_FINGERPRINT = build_canonical_fingerprint_profile()


def build_runtime_fingerprint_profile(
    *,
    browser_path: str = "",
    browser_major: object = None,
) -> FingerprintProfile:
    """Build HTTP/local shared fingerprint aligned to installed Chrome when possible."""
    major = str(browser_major or "").strip()
    path = str(browser_path or "").strip()
    if not major:
        try:
            from turnstile_solver.src.config import (
                detect_chrome_major,
                detect_system_chrome_path,
            )

            path = path or detect_system_chrome_path()
            major = detect_chrome_major(path) if path else ""
        except Exception:
            major = ""
    if major:
        return build_canonical_fingerprint_profile(browser_major=major)
    return DEFAULT_FINGERPRINT


def _is_tls_transport_error(exc: BaseException) -> bool:
    """Identify handshake/transport failures that can use another TLS profile."""

    text = str(exc or "").lower()
    markers = (
        "curl: (35)",
        "tls connect error",
        "ssl connect error",
        "openssl_internal",
        "wrong version number",
        "schannel",
        "handshake failure",
    )
    return any(marker in text for marker in markers)


def _impersonate_fallback_chain(primary: str) -> List[str]:
    """Return a bounded, installed curl_cffi impersonation fallback chain."""

    from turnstile_broker import _impersonate_for_browser_major, _impersonate_is_usable

    selected = str(primary or "").strip()
    candidates: List[str] = []
    for name in (
        selected,
        _impersonate_for_browser_major("136"),
        "chrome136",
        "chrome131",
        "chrome124",
        "chrome120",
        "chrome",
    ):
        normalized = str(name or "").strip()
        if not normalized or normalized in candidates:
            continue
        if normalized != selected and not _impersonate_is_usable(normalized):
            continue
        candidates.append(normalized)
    return candidates


def _rebuild_session_with_impersonate(client: Any, impersonate: str) -> None:
    """Replace a client session while retaining its headers and cookie jar."""

    previous = getattr(client, "session", None)
    session = requests.Session(impersonate=str(impersonate or "chrome"))
    previous_headers = getattr(previous, "headers", None)
    if previous_headers is not None:
        try:
            session.headers.update(dict(previous_headers))
        except Exception:
            pass
    previous_cookies = getattr(previous, "cookies", None)
    if previous_cookies is not None:
        try:
            session.cookies.update(previous_cookies)
        except Exception:
            try:
                jar = getattr(previous_cookies, "jar", None)
                if jar is not None:
                    session.cookies.update(jar)
            except Exception:
                pass
    try:
        setattr(session, "_xai_impersonate", str(impersonate or "chrome"))
    except Exception:
        pass
    client.session = session



def _session_with_impersonate_fallback(impersonate: str, *, log_callback: LogFn = None) -> Any:
    """Create curl_cffi Session, falling back when impersonate target is unsupported."""
    primary = str(impersonate or "").strip()
    candidates = _impersonate_fallback_chain(primary)

    last_error: Optional[Exception] = None
    for name in candidates:
        try:
            session = requests.Session(impersonate=name)
            # Force-materialize impersonate support on versions that fail lazily.
            try:
                session.request("GET", "http://127.0.0.1:9/", timeout=0.05)
            except Exception as exc:
                msg = str(exc or "").lower()
                if "impersonat" in msg and "not supported" in msg:
                    raise
            if name != primary:
                _log(log_callback, f"[HTTP][warn] impersonate 回退: {primary or '-'} -> {name}")
            try:
                setattr(session, "_xai_impersonate", name)
            except Exception:
                pass
            return session
        except Exception as exc:
            last_error = exc
            continue
    if last_error is not None:
        raise last_error
    return requests.Session(impersonate="chrome")


DEFAULT_ACCEPT_LANGUAGE = DEFAULT_FINGERPRINT.accept_language
CHROME136_SEC_CH_UA = DEFAULT_FINGERPRINT.sec_ch_ua
DEFAULT_USER_AGENT = DEFAULT_FINGERPRINT.user_agent

# These are fallbacks only.  The client obtains the current action IDs from the
# loaded scripts first, because a Next deployment can rotate them at any time.
KNOWN_SIGNUP_ACTION_ID = "7f50061dd2f5b389a530e4a048d5fdf0c48d1d9259"
KNOWN_CONSENT_ACTION_ID = "4005315a1d7e426de592990bb54bb37471f39dd6d2"

LogFn = Optional[Callable[[str], None]]


class XAIHttpFlowError(RuntimeError):
    """Base error for the browserless flow."""


class VerificationRequiredError(XAIHttpFlowError):
    """Raised when a fresh anti-abuse or Cloudflare verification is required."""


class ProtocolError(XAIHttpFlowError):
    """Raised when xAI changes a wire/API response shape."""


def is_email_domain_rejected_error(exc: BaseException | str) -> bool:
    text_value = str(exc or "").lower()
    return (
        "email domain has been rejected" in text_value
        or "email-domain-rejected" in text_value
        or "account:email-domain-rejected" in text_value
    )


class MailboxError(XAIHttpFlowError):
    """Raised by the optional Cloudflare temporary mailbox adapter."""


class MailboxPoolLockTimeout(MailboxError):
    """Raised when a mailbox pool transaction cannot acquire its lock."""


@dataclass
class SsoCookies:
    sso: str
    sso_rw: str = ""


@dataclass
class RegistrationResult:
    email: str
    password: str
    sso: str
    credential_path: str = ""
    account_path: str = ""
    sso_path: str = ""


def _log(callback: LogFn, message: str) -> None:
    if callback:
        callback(message)


def mask_email(email: str) -> str:
    email = str(email or "").strip()
    if "@" not in email:
        return "***" if email else "(empty)"
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        local = local[:1] + "***"
    else:
        local = local[:2] + "***" + local[-1:]
    return f"{local}@{domain}"


_ERROR_SAFE_FIELD_SUFFIXES = (
    "_count",
    "_enabled",
    "_length",
    "_len",
    "_name",
    "_present",
    "_status",
    "_type",
)
_ERROR_SENSITIVE_KEYS = {
    "access_token",
    "apikey",
    "api_key",
    "authorization",
    "bearer",
    "clientkey",
    "client_key",
    "client_secret",
    "cookie",
    "cookies",
    "cookie_jar",
    "credential",
    "credentials",
    "id_token",
    "password",
    "passwd",
    "proxy_authorization",
    "pwd",
    "refresh_token",
    "secret",
    "session_token",
    "set_cookie",
    "sso",
    "sso_rw",
    "token",
}
_ERROR_AUTHENTICATED_URL_RE = re.compile(
    r"(?i)\b(?P<scheme>https?|socks4|socks5h?)://"
    r"[^@\s/'\"<>]+@"
    r"(?P<host>\[[^\]\s]+\]|[^:/\s,'\"<>]+)"
    r"(?::(?P<port>\d+))?"
)
_ERROR_AUTH_SCHEME_RE = re.compile(
    r"(?i)\b(?P<scheme>bearer|basic)\s+(?P<value>[A-Za-z0-9._~+/=-]{8,})"
)
_ERROR_QUOTED_PAIR_RE = re.compile(
    r"(?P<key_quote>['\"])(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P=key_quote)(?P<separator>\s*:\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^,\s}\]]+)"
)
_ERROR_KEY_VALUE_RE = re.compile(
    r"(?i)\b(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P<separator>\s*[=:]\s*)"
    r"(?P<value>(?:(?i:bearer|basic)\s+"
    r"(?:<redacted>|[A-Za-z0-9._~+/=-]{8,}))|"
    r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;}\]]+)"
)


def _normalized_error_key(key: Any) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(key or ""))
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _is_sensitive_error_key(key: Any) -> bool:
    normalized = _normalized_error_key(key)
    if not normalized or normalized.endswith(_ERROR_SAFE_FIELD_SUFFIXES):
        return False
    compact = normalized.replace("_", "")
    if normalized in _ERROR_SENSITIVE_KEYS or compact in {
        item.replace("_", "") for item in _ERROR_SENSITIVE_KEYS
    }:
        return True
    if normalized.endswith("_token"):
        return True
    if any(
        marker in normalized
        for marker in ("authorization", "cookie", "credential", "password", "passwd", "secret")
    ):
        return True
    if "proxy" in normalized and any(
        marker in compact
        for marker in (
            "auth",
            "credential",
            "login",
            "password",
            "passwd",
            "pwd",
            "user",
            "username",
        )
    ):
        return True
    return False


def _is_proxy_error_key(key: Any) -> bool:
    return "proxy" in _normalized_error_key(key)


def _strip_error_url_userinfo(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        scheme = str(match.group("scheme") or "").lower()
        host = str(match.group("host") or "")
        port = str(match.group("port") or "")
        return f"{scheme}://{host}{f':{port}' if port else ''}"

    return _ERROR_AUTHENTICATED_URL_RE.sub(replace, str(text or ""))


def _is_authorization_error_key(key: Any) -> bool:
    return _normalized_error_key(key) in {"authorization", "proxy_authorization"}


def _redacted_pair_value(raw_value: str, key: Any = "") -> str:
    value = str(raw_value or "")
    quote_char = ""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        quote_char = value[0]
        value = value[1:-1]
    if _is_authorization_error_key(key):
        auth_match = re.match(r"(?i)^\s*(bearer|basic)\s+", value)
        if auth_match:
            redacted = f"{auth_match.group(1)} <redacted>"
            return f"{quote_char}{redacted}{quote_char}" if quote_char else redacted
    if quote_char:
        return f"{quote_char}<redacted>{quote_char}"
    return "<redacted>"


def _sanitize_proxy_field_value(raw_value: str) -> str:
    value = str(raw_value or "")
    quote_char = ""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        quote_char = value[0]
        value = value[1:-1]
    value = _strip_error_url_userinfo(value)
    if "://" not in value:
        legacy = re.fullmatch(r"([^:\s]+):(\d+):[^:\s]+:.+", value)
        if legacy:
            value = f"{legacy.group(1)}:{legacy.group(2)}"
    return f"{quote_char}{value}{quote_char}" if quote_char else value


def _sanitize_error_string(value: str) -> str:
    text = str(value or "")
    stripped = text.strip()
    if stripped and stripped[:1] in "{[(" and stripped[-1:] in "}])":
        parsed: Any = None
        for parser in (json.loads, ast.literal_eval):
            try:
                candidate = parser(stripped)
            except (TypeError, ValueError, SyntaxError):
                continue
            if isinstance(candidate, (dict, list, tuple)):
                parsed = candidate
                break
        if parsed is not None:
            return json.dumps(
                _clean_error_value(parsed),
                ensure_ascii=False,
                separators=(", ", ": "),
            )

    text = _strip_error_url_userinfo(text)
    text = _ERROR_AUTH_SCHEME_RE.sub(
        lambda match: f"{match.group('scheme')} <redacted>",
        text,
    )

    def replace_pair(match: re.Match[str]) -> str:
        key = match.group("key")
        value_text = match.group("value")
        if _is_sensitive_error_key(key):
            value_text = _redacted_pair_value(value_text, key)
        elif _is_proxy_error_key(key):
            value_text = _sanitize_proxy_field_value(value_text)
        return (
            f"{match.groupdict().get('key_quote') or ''}{key}"
            f"{match.groupdict().get('key_quote') or ''}"
            f"{match.group('separator')}{value_text}"
        )

    text = _ERROR_QUOTED_PAIR_RE.sub(replace_pair, text)

    def replace_key_value(match: re.Match[str]) -> str:
        key = match.group("key")
        value_text = match.group("value")
        if _is_sensitive_error_key(key):
            value_text = _redacted_pair_value(value_text, key)
        elif _is_proxy_error_key(key):
            value_text = _sanitize_proxy_field_value(value_text)
        return f"{key}{match.group('separator')}{value_text}"

    return _ERROR_KEY_VALUE_RE.sub(replace_key_value, text)


def _clean_error_value(
    value: Any,
    *,
    key_hint: Any = "",
    seen: Optional[set[int]] = None,
) -> Any:
    if _is_sensitive_error_key(key_hint):
        if isinstance(value, str):
            return _redacted_pair_value(value, key_hint)
        return "<redacted>"
    seen = seen if seen is not None else set()
    if isinstance(value, dict):
        identity = id(value)
        if identity in seen:
            return "<recursive>"
        seen.add(identity)
        try:
            return {
                key: _clean_error_value(item, key_hint=key, seen=seen)
                for key, item in value.items()
            }
        finally:
            seen.discard(identity)
    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in seen:
            return "<recursive>"
        seen.add(identity)
        try:
            cleaned = [
                _clean_error_value(item, key_hint=key_hint, seen=seen)
                for item in value
            ]
            return tuple(cleaned) if isinstance(value, tuple) else cleaned
        finally:
            seen.discard(identity)
    if isinstance(value, str):
        text = _sanitize_error_string(value)
        return _sanitize_proxy_field_value(text) if _is_proxy_error_key(key_hint) else text
    return value


def _safe_error_text(value: Any, limit: int = 360) -> str:
    """Keep server diagnostics useful without leaking opaque credentials."""
    cleaned = _clean_error_value(value)
    if isinstance(cleaned, (dict, list, tuple)):
        text = json.dumps(cleaned, ensure_ascii=False, separators=(", ", ": "))
    else:
        text = str(cleaned or "")
    text = re.sub(r"\s+", " ", text).strip()
    return text[: max(0, int(limit))]


def normalize_proxy(raw: str) -> str:
    """Normalize a direct HTTP proxy or `host:port:user:password` pool line."""
    raw = str(raw or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        parts = raw.split(":")
        if len(parts) >= 4 and parts[1].isdigit():
            host, port, username = parts[0], parts[1], parts[2]
            password = ":".join(parts[3:])
            if host:
                from urllib.parse import quote as urlquote

                return (
                    f"http://{urlquote(username, safe='')}:{urlquote(password, safe='')}"
                    f"@{host}:{port}"
                )
        return "http://" + raw
    return raw


def choose_proxy(
    proxy: str = "",
    proxy_file: str = "",
    random_pick: bool = False,
    index: int = 0,
) -> str:
    """Select one direct proxy; HTTP clients do not need the browser forwarder."""
    if str(proxy or "").strip():
        return normalize_proxy(proxy)
    path = Path(str(proxy_file or "").strip())
    if not path.is_file():
        return ""
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return ""
    selected = random.choice(lines) if random_pick else lines[int(index or 0) % len(lines)]
    return normalize_proxy(selected)


def _proxy_dict(proxy: str) -> Dict[str, str]:
    proxy = normalize_proxy(proxy)
    return {"http": proxy, "https": proxy} if proxy else {}


def _parse_headers(raw: Any) -> Dict[str, str]:
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    return {}


def _cookie_pairs(value: str) -> Dict[str, str]:
    pairs: Dict[str, str] = {}
    for item in str(value or "").split(";"):
        if "=" not in item:
            continue
        key, cookie_value = item.strip().split("=", 1)
        if key:
            pairs[key] = cookie_value
    return pairs


def extract_trace_sso(trace_path: str) -> SsoCookies:
    """Extract only SSO cookies from a Recorder JSON export.

    The supplied capture can contain passwords and mailbox JWTs.  This function
    intentionally reads neither and returns no raw request/body text.
    """
    try:
        data = json.loads(Path(trace_path).read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - exercised through CLI errors
        raise XAIHttpFlowError(f"无法读取 Recorder JSON: {exc}") from exc
    if not isinstance(data, list):
        raise XAIHttpFlowError("Recorder JSON 顶层必须是事件数组")
    ordered = sorted(
        (item for item in data if isinstance(item, dict)),
        key=lambda item: int(item.get("sequence") or 0),
        reverse=True,
    )
    for event in ordered:
        headers = _parse_headers(event.get("request_headers"))
        cookie_header = next((v for k, v in headers.items() if k.lower() == "cookie"), "")
        cookies = _cookie_pairs(cookie_header)
        sso = str(cookies.get("sso") or "").strip()
        if sso:
            return SsoCookies(sso=sso, sso_rw=str(cookies.get("sso-rw") or "").strip())
    raise XAIHttpFlowError("Recorder JSON 中未找到可用 sso cookie")


def _encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("protobuf varint cannot be negative")
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _pb_string(field: int, value: str) -> bytes:
    raw = str(value or "").encode("utf-8")
    return _encode_varint((int(field) << 3) | 2) + _encode_varint(len(raw)) + raw


def _grpc_frame(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(4, "big") + payload


def parse_grpc_web_response(raw: bytes) -> Tuple[List[bytes], Dict[str, str]]:
    """Decode uncompressed gRPC-Web data/trailer frames."""
    frames: List[bytes] = []
    trailers: Dict[str, str] = {}
    offset = 0
    raw = bytes(raw or b"")
    while offset < len(raw):
        if len(raw) - offset < 5:
            raise ProtocolError("gRPC-Web 响应帧长度不足")
        flags = raw[offset]
        length = int.from_bytes(raw[offset + 1 : offset + 5], "big")
        offset += 5
        if len(raw) - offset < length:
            raise ProtocolError("gRPC-Web 响应帧被截断")
        payload = raw[offset : offset + length]
        offset += length
        if flags & 0x80:
            for line in payload.decode("utf-8", errors="replace").replace("\r", "").split("\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    trailers[key.strip().lower()] = value.strip()
        elif flags & 0x01:
            raise ProtocolError("暂不支持压缩的 gRPC-Web 响应")
        else:
            frames.append(payload)
    return frames, trailers


def _response_json(response: Any) -> Dict[str, Any]:
    try:
        data = response.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _is_loopback_url(url: str) -> bool:
    """True for localhost/loopback broker endpoints."""
    try:
        host = str(urlparse(str(url or "")).hostname or "").strip().lower()
    except Exception:
        host = ""
    return host in {"127.0.0.1", "localhost", "::1"}


def _http_post_json(
    url: str,
    *,
    json_body: Optional[Dict[str, Any]] = None,
    timeout: float = 30,
    impersonate: str = "",
) -> Any:
    """POST JSON.

    Local Turnstile broker calls must NOT use curl_cffi browser impersonation:
    chrome impersonation may send HTTP/2 upgrade headers and drop the JSON body,
    which FastAPI then rejects as 422 "Field required".
    """
    timeout = max(1.0, float(timeout or 30))
    if _is_loopback_url(url):
        import requests as std_requests

        return std_requests.post(url, json=json_body, timeout=timeout)
    kwargs: Dict[str, Any] = {"timeout": timeout}
    if json_body is not None:
        kwargs["json"] = json_body
    if impersonate:
        kwargs["impersonate"] = impersonate
    return requests.post(url, **kwargs)


def _broker_http_error(stage: str, response: Any) -> VerificationRequiredError:
    status = int(getattr(response, "status_code", 0) or 0)
    data = _response_json(response)
    detail = data.get("detail") if isinstance(data, dict) else None
    if detail is not None:
        body = _safe_error_text(detail)
    else:
        body = _safe_error_text(data or getattr(response, "text", "") or "")
    return VerificationRequiredError(f"Turnstile broker {stage} HTTP {status}: {body}")



def _is_cf_interstitial(response: Any) -> bool:
    text = str(getattr(response, "text", "") or "").lower()
    title_or_marker = (
        "just a moment" in text
        or "attention required! | cloudflare" in text
        or "cf-chl-" in text
        or "cf-error-code" in text
    )
    return bool(title_or_marker)


def _router_state(route: str) -> str:
    tree = [
        "",
        {
            "children": [
                "(app)",
                {
                    "children": [
                        "(auth)",
                        {
                            "children": [
                                route,
                                {"children": ["__PAGE__", {}, None, None, 0]},
                                None,
                                None,
                                0,
                            ]
                        },
                        None,
                        None,
                        0,
                    ]
                },
                None,
                None,
                0,
            ]
        },
        None,
        None,
        16,
    ]
    return quote(json.dumps(tree, separators=(",", ":")), safe="")


def _script_urls(page_url: str, page_html: str) -> List[str]:
    urls: List[str] = []
    for source in re.findall(r"<script[^>]+src=[\"']([^\"']+)", str(page_html or ""), flags=re.I):
        url = urljoin(page_url, source)
        if url not in urls:
            urls.append(url)
    return urls


def _extract_rsc_object(text: str, marker: str) -> Dict[str, Any]:
    """Find an object in an RSC response without assuming its line number."""
    decoder = json.JSONDecoder()
    undefined_candidates: List[Dict[str, Any]] = []

    def choose(obj: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(obj, dict) or marker not in obj:
            return None
        # The surrounding RSC tree contains many unrelated props such as
        # `{"error":"$undefined"}`.  The Server Action result itself carries
        # a concrete value later in the stream, so prefer that one.
        if obj.get(marker) == "$undefined":
            undefined_candidates.append(obj)
            return None
        return obj

    for match in re.finditer(r"\{", str(text or "")):
        try:
            obj, _ = decoder.raw_decode(text[match.start() :])
        except (json.JSONDecodeError, ValueError):
            continue
        selected = choose(obj)
        if selected is not None:
            return selected
    # Some RSC versions quote nested JSON.  Decode the escaped form once.
    escaped = str(text or "").replace(r'\"', '"').replace(r"\\", "\\")
    if escaped != text:
        for match in re.finditer(r"\{", escaped):
            try:
                obj, _ = decoder.raw_decode(escaped[match.start() :])
            except (json.JSONDecodeError, ValueError):
                continue
            selected = choose(obj)
            if selected is not None:
                return selected
    return undefined_candidates[0] if undefined_candidates else {}


_COOKIE_SETTER_HOST = (
    r"auth\.(?:grokipedia\.com|grokusercontent\.com|grok\.com|x\.ai)"
)


def _extract_cookie_setter_url(text: str) -> str:
    """Pull the multi-domain cookie-setter URL out of an RSC / JSON payload.

    Live signup Server Actions embed the URL as a React Flight typed string::

        18:T9d5,https://auth.grokipedia.com/set-cookie?q=<JWT>

    where ``9d5`` is the hex length of the following payload.  A naive
    ``[^\\s]+`` match overruns into the next chunk (e.g. ``1:\"$18\"``) and the
    setter endpoint then answers HTTP 400.  Prefer exact typed length, then a
    JWT-shaped ``q=`` value.

    Hosts observed live: auth.grokipedia.com, auth.grokusercontent.com,
    auth.grok.com, auth.x.ai.
    """
    normalized = (
        str(text or "")
        .replace(r"\u0026", "&")
        .replace(r"\/", "/")
        .replace(r"\"", '"')
    )
    # React Flight typed text: <id>:T<hex_len>,<payload>
    typed = re.search(
        rf"\d+:T([0-9a-fA-F]+),(https://{_COOKIE_SETTER_HOST}/set-cookie\?)",
        normalized,
    )
    if typed:
        try:
            length = int(typed.group(1), 16)
        except ValueError:
            length = 0
        start = typed.start(2)
        if length > 0 and start + length <= len(normalized):
            candidate = normalized[start : start + length]
            if candidate.startswith("https://") and "set-cookie" in candidate:
                return candidate
    # JWT q= token is three base64url segments; stop before trailing RSC junk.
    match = re.search(
        rf"https://{_COOKIE_SETTER_HOST}/set-cookie\?q="
        r"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)",
        normalized,
    )
    if match:
        return match.group(0)
    match = re.search(
        rf"https://{_COOKIE_SETTER_HOST}/set-cookie\?q=[A-Za-z0-9_\-.=]+",
        normalized,
    )
    return match.group(0) if match else ""


def _secret_from(value: str, file_path: str, env_name: str = "") -> str:
    value = str(value or "").strip()
    if value:
        return value
    if file_path:
        try:
            return Path(file_path).read_text(encoding="utf-8").strip()
        except Exception as exc:
            raise XAIHttpFlowError(f"无法读取 token 文件 {file_path}: {exc}") from exc
    return str(os.environ.get(env_name, "") or "").strip() if env_name else ""


def _parse_proxy_components(proxy: str) -> Dict[str, str]:
    """Split a normalized proxy URL into host/port/user/pass for captcha task APIs."""
    proxy = normalize_proxy(proxy)
    if not proxy:
        return {}
    parsed = urlparse(proxy)
    return {
        "scheme": (parsed.scheme or "http").lower(),
        "host": str(parsed.hostname or ""),
        "port": str(parsed.port or ""),
        "username": unquote(parsed.username or ""),
        "password": unquote(parsed.password or ""),
    }


def _proxy_has_embedded_auth(proxy: str) -> bool:
    """Return True when the proxy URL embeds username/password credentials."""
    parts = _parse_proxy_components(proxy)
    return bool(parts.get("username") or parts.get("password"))


def _prepare_browser_proxy(
    proxy: str = "",
    *,
    preferred_local_port: int = 0,
    instance_key: str = "",
    log_callback: LogFn = None,
) -> Tuple[str, str]:
    """Resolve a proxy URL that Chromium/DrissionPage can actually consume.

    Chrome rejects ``http://user:pass@host:port`` with ``ERR_NO_SUPPORTED_PROXIES``.
    When credentials are present, expose a local no-auth forwarder on
    ``127.0.0.1`` and inject ``Proxy-Authorization`` upstream.

    Returns ``(browser_proxy_url, forwarder_instance_key)``.
    """
    proxy = str(proxy or "").strip()
    if not proxy:
        return "", ""

    # Local no-auth endpoints are already browser-safe.
    parts = _parse_proxy_components(proxy)
    host = str(parts.get("host") or "").lower()
    if host in {"127.0.0.1", "localhost", "::1"} and not _proxy_has_embedded_auth(proxy):
        return normalize_proxy(proxy), ""

    needs_forwarder = _proxy_has_embedded_auth(proxy)
    if not needs_forwarder:
        return normalize_proxy(proxy), ""

    from local_proxy_forwarder import ensure_local_forwarder

    key = str(instance_key or "").strip() or f"xai-ts-{os.getpid()}-{secrets.token_hex(3)}"
    try:
        browser_proxy, used = ensure_local_forwarder(
            proxy,
            preferred_local_port=int(preferred_local_port or 0),
            instance_key=key,
        )
    except Exception as exc:
        raise XAIHttpFlowError(f"本地代理转发启动失败: {exc}") from exc

    browser_proxy = str(browser_proxy or "").strip()
    if used:
        up_desc = f"{parts.get('host')}:{parts.get('port')}" if parts.get("host") else "upstream"
        _log(
            log_callback,
            f"[Turnstile] 账号密码代理已转本机无鉴权转发: {browser_proxy} -> {up_desc}",
        )
    elif _proxy_has_embedded_auth(browser_proxy):
        # Safety net: never hand Chromium a credentialed URL.
        raise XAIHttpFlowError(
            "浏览器代理仍包含账号密码，无法设置；请检查 local_proxy_forwarder"
        )
    return browser_proxy, key if used else ""


def _normalize_turnstile_provider(provider: str) -> str:
    """Normalize documented captcha-provider aliases to stable internal names."""
    provider = str(provider or "").strip().lower()
    aliases = {
        "cap-solver": "capsolver",
        "cap_solver": "capsolver",
        "twocaptcha": "2captcha",
        "two-captcha": "2captcha",
        "two_captcha": "2captcha",
        "yes-captcha": "yescaptcha",
        "yes_captcha": "yescaptcha",
        "local": "local",
        "browser": "local",
        "chrome": "local",
        "drission": "local",
        "turnstile-capture": "local",
        "turnstile_capture": "local",
    }
    return aliases.get(provider, provider)


def _default_turnstile_provider() -> str:
    if os.environ.get("CAPSOLVER_API_KEY"):
        return "capsolver"
    if os.environ.get("TWOCAPTCHA_API_KEY") or os.environ.get("TWO_CAPTCHA_API_KEY"):
        return "2captcha"
    if os.environ.get("YESCAPTCHA_API_KEY"):
        return "yescaptcha"
    # Preserve the existing default for callers that provide only a generic API key.
    return "capsolver"


def _turnstile_api_key(provider: str, explicit_key: str = "") -> str:
    """Resolve a generic key first, then the key dedicated to the selected provider."""
    key = str(explicit_key or "").strip()
    if key:
        return key
    for env_name in ("XAI_TURNSTILE_API_KEY", "TURNSTILE_API_KEY"):
        key = str(os.environ.get(env_name) or "").strip()
        if key:
            return key
    provider_envs = {
        "capsolver": ("CAPSOLVER_API_KEY",),
        "2captcha": ("TWOCAPTCHA_API_KEY", "TWO_CAPTCHA_API_KEY"),
        "yescaptcha": ("YESCAPTCHA_API_KEY",),
    }
    for env_name in provider_envs.get(provider, ()):
        key = str(os.environ.get(env_name) or "").strip()
        if key:
            return key
    return ""


def solve_turnstile_token(
    *,
    sitekey: str,
    page_url: str = SIGNUP_URL,
    provider: str = "",
    api_key: str = "",
    proxy: str = "",
    action: str = "",
    cdata: str = "",
    timeout: int = 180,
    headless: bool = False,
    log_callback: LogFn = None,
) -> str:
    """Obtain a real Turnstile token via captcha API or local browser capture.

    This does not forge Cloudflare results.  Remote providers submit the official
    sitekey/page URL to a solving service.  The ``local`` provider opens Chrome
    and captures the native widget token on the signup page.
    """
    sitekey = str(sitekey or "").strip()
    page_url = str(page_url or SIGNUP_URL).strip() or SIGNUP_URL
    provider = _normalize_turnstile_provider(
        provider
        or os.environ.get("XAI_TURNSTILE_PROVIDER")
        or os.environ.get("TURNSTILE_PROVIDER")
        or ""
    )
    provider = provider or _default_turnstile_provider()
    if provider not in {"capsolver", "2captcha", "yescaptcha", "local"}:
        raise XAIHttpFlowError(
            f"不支持的 Turnstile provider: {provider}（支持 capsolver / 2captcha / yescaptcha / local）"
        )
    api_key = _turnstile_api_key(provider, api_key)
    action = str(action or "").strip()
    cdata = str(cdata or "").strip()
    timeout = max(5, int(timeout or 30))

    if provider == "local":
        _log(
            log_callback,
            f"[HTTP] 请求 Turnstile 本地浏览器求解 | page={page_url} "
            f"sitekey={'yes' if sitekey else 'no'} proxy={'yes' if proxy else 'no'} "
            f"headless={'yes' if headless else 'no'}",
        )
        token = _solve_turnstile_local(
            page_url=page_url,
            proxy=proxy,
            timeout=timeout,
            headless=bool(headless),
            log_callback=log_callback,
            sitekey=sitekey,
            action=action,
            cdata=cdata,
        )
    else:
        if not sitekey:
            raise VerificationRequiredError("Turnstile sitekey 为空，无法请求求解服务")
        if not api_key:
            raise VerificationRequiredError(
                "未提供 Turnstile token，且未配置 captcha API key。"
                "请传 --turnstile-token(--file)，或配置 --turnstile-provider + --turnstile-api-key "
                "(capsolver|2captcha|yescaptcha|local)。"
            )
        # Captcha workers cannot reach the operator's localhost forwarder/Clash.
        proxy_parts = _parse_proxy_components(proxy)
        if proxy_parts.get("host") in {"127.0.0.1", "localhost", "::1"}:
            _log(log_callback, "[HTTP][warn] Turnstile 求解忽略本机代理（改用 proxyless）")
            proxy = ""
        if provider == "capsolver" and proxy:
            _log(
                log_callback,
                "[HTTP][warn] CapSolver Turnstile 使用官方 AntiTurnstileTaskProxyLess，已忽略自定义代理",
            )
            proxy = ""
        _log(
            log_callback,
            f"[HTTP] 请求 Turnstile 求解 | provider={provider} sitekey={sitekey[:12]}… "
            f"proxy={'yes' if proxy else 'no'}",
        )
        if provider == "capsolver":
            token = _solve_turnstile_capsolver(
                api_key=api_key,
                sitekey=sitekey,
                page_url=page_url,
                proxy=proxy,
                action=action,
                cdata=cdata,
                timeout=timeout,
                log_callback=log_callback,
            )
        elif provider == "2captcha":
            token = _solve_turnstile_2captcha(
                api_key=api_key,
                sitekey=sitekey,
                page_url=page_url,
                proxy=proxy,
                timeout=timeout,
                log_callback=log_callback,
            )
        elif provider == "yescaptcha":
            token = _solve_turnstile_yescaptcha(
                api_key=api_key,
                sitekey=sitekey,
                page_url=page_url,
                proxy=proxy,
                timeout=timeout,
                log_callback=log_callback,
            )
    token = str(token or "").strip()
    if len(token) < 80:
        raise VerificationRequiredError(f"{provider} 返回的 Turnstile token 无效 (len={len(token)})")
    _log(log_callback, f"[HTTP] Turnstile 求解完成 | provider={provider} len={len(token)}")
    return token




def _solve_turnstile_local(
    *,
    page_url: str,
    proxy: str,
    timeout: int,
    headless: bool = False,
    log_callback: LogFn,
    sitekey: str = "",
    action: str = "",
    cdata: str = "",
    user_agent: str = "",
    accept_language: str = DEFAULT_ACCEPT_LANGUAGE,
    expected_platform: str = "",
    expected_client_hint_platform: str = "",
    expected_browser_major: str = "",
    return_result: bool = False,
) -> Any:
    """Capture a real Turnstile token with local Chrome/DrissionPage.

    Drop-in alternative to third-party captcha APIs for low-concurrency research.
    When sitekey is known from the HTTP session, prefer injecting/rendering the
    official Turnstile widget on accounts.x.ai instead of clicking through the
    multi-step signup UI (email OTP page has no widget).
    """
    captured = capture_turnstile_token(
        proxy=proxy,
        output="",
        proxy_used_file="",
        selected_proxy_raw=proxy,
        timeout=timeout,
        headless=bool(headless),
        page_url=page_url,
        log_callback=log_callback,
        sitekey=sitekey,
        action=action,
        cdata=cdata,
        user_agent=user_agent,
        accept_language=accept_language,
        expected_platform=expected_platform,
        expected_client_hint_platform=expected_client_hint_platform,
        expected_browser_major=expected_browser_major,
        return_result=return_result,
        # With an explicit sitekey, stay on the origin and render the widget.
        # Do not drive the email-registration UI.
        click_email_signup=not bool(str(sitekey or "").strip()),
    )
    token = str(captured.token if isinstance(captured, SolveResult) else captured or "").strip()
    if len(token) < 80:
        raise VerificationRequiredError(
            f"local browser Turnstile token 无效 (len={len(token)})"
        )
    return captured if return_result and isinstance(captured, SolveResult) else token


def _solve_turnstile_capsolver(
    *,
    api_key: str,
    sitekey: str,
    page_url: str,
    proxy: str,
    action: str,
    cdata: str,
    timeout: int,
    log_callback: LogFn,
) -> str:
    create_url = "https://api.capsolver.com/createTask"
    result_url = "https://api.capsolver.com/getTaskResult"
    # CapSolver's current Turnstile API documents only the proxyless task type.
    # The public solver, not the caller's xAI transport proxy, supplies the egress.
    del proxy
    task: Dict[str, Any] = {
        "type": "AntiTurnstileTaskProxyLess",
        "websiteURL": page_url,
        "websiteKey": sitekey,
    }
    metadata = {key: value for key, value in {"action": action, "cdata": cdata}.items() if value}
    if metadata:
        task["metadata"] = metadata
    try:
        create = requests.post(
            create_url,
            json={"clientKey": api_key, "task": task},
            timeout=30,
            impersonate="chrome136",
        )
    except Exception as exc:
        raise VerificationRequiredError(f"capsolver createTask 请求失败: {_safe_error_text(exc)}") from exc
    create_data = _response_json(create)
    create_status = int(getattr(create, "status_code", 0) or 0)
    if not create_data:
        raise VerificationRequiredError(
            f"capsolver createTask 返回非 JSON（HTTP {create_status or 'unknown'}）: "
            f"{_safe_error_text(getattr(create, 'text', ''))}"
        )
    if create_status and not 200 <= create_status < 300:
        raise VerificationRequiredError(
            f"capsolver createTask HTTP {create_status}: {_capsolver_error_text(create_data)}"
        )
    if create_data.get("errorId") not in (0, None, "0") and create_data.get("errorId"):
        raise VerificationRequiredError(
            f"capsolver createTask 失败: {_capsolver_error_text(create_data)}"
        )
    task_id = str(create_data.get("taskId") or "").strip()
    if not task_id:
        raise VerificationRequiredError(
            f"capsolver createTask 未返回 taskId: {_safe_error_text(create_data)}"
        )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(2.0)
        try:
            poll = requests.post(
                result_url,
                json={"clientKey": api_key, "taskId": task_id},
                timeout=30,
                impersonate="chrome136",
            )
        except Exception as exc:
            raise VerificationRequiredError(f"capsolver getTaskResult 请求失败: {_safe_error_text(exc)}") from exc
        data = _response_json(poll)
        poll_status = int(getattr(poll, "status_code", 0) or 0)
        if not data:
            raise VerificationRequiredError(
                f"capsolver getTaskResult 返回非 JSON（HTTP {poll_status or 'unknown'}）: "
                f"{_safe_error_text(getattr(poll, 'text', ''))}"
            )
        if poll_status and not 200 <= poll_status < 300:
            raise VerificationRequiredError(
                f"capsolver getTaskResult HTTP {poll_status}: {_capsolver_error_text(data)}"
            )
        if data.get("errorId") not in (0, None, "0") and data.get("errorId"):
            raise VerificationRequiredError(
                f"capsolver getTaskResult 失败: {_capsolver_error_text(data)}"
            )
        status = str(data.get("status") or "").lower()
        if status == "ready":
            solution = data.get("solution") if isinstance(data.get("solution"), dict) else {}
            return str(solution.get("token") or solution.get("gRecaptchaResponse") or "")
        if status in {"failed", "error"}:
            raise VerificationRequiredError(f"capsolver 任务失败: {_safe_error_text(data)}")
    raise VerificationRequiredError(f"capsolver 求解超时 ({timeout}s)")


def _capsolver_error_text(data: Dict[str, Any]) -> str:
    """Prefer CapSolver's stable error code while retaining a safe diagnostic."""
    error_code = str(data.get("errorCode") or "").strip()
    description = str(data.get("errorDescription") or "").strip()
    message = " | ".join(part for part in (error_code, description) if part)
    return _safe_error_text(message or data)


def _solve_turnstile_2captcha(
    *,
    api_key: str,
    sitekey: str,
    page_url: str,
    proxy: str,
    timeout: int,
    log_callback: LogFn,
) -> str:
    create_url = "https://api.2captcha.com/createTask"
    result_url = "https://api.2captcha.com/getTaskResult"
    parts = _parse_proxy_components(proxy)
    if parts.get("host") and parts.get("port"):
        task: Dict[str, Any] = {
            "type": "TurnstileTask",
            "websiteURL": page_url,
            "websiteKey": sitekey,
            "proxyType": "http" if parts["scheme"] in {"http", "https"} else parts["scheme"],
            "proxyAddress": parts["host"],
            "proxyPort": int(parts["port"]),
        }
        if parts.get("username"):
            task["proxyLogin"] = parts["username"]
            task["proxyPassword"] = parts.get("password") or ""
    else:
        task = {
            "type": "TurnstileTaskProxyless",
            "websiteURL": page_url,
            "websiteKey": sitekey,
        }
    create = requests.post(
        create_url,
        json={"clientKey": api_key, "task": task},
        timeout=30,
        impersonate="chrome136",
    )
    create_data = _response_json(create)
    if int(create_data.get("errorId") or 0) != 0:
        raise VerificationRequiredError(
            f"2captcha createTask 失败: {_safe_error_text(create_data.get('errorDescription') or create_data)}"
        )
    task_id = create_data.get("taskId")
    if task_id is None or str(task_id) == "":
        raise VerificationRequiredError(f"2captcha createTask 未返回 taskId: {_safe_error_text(create_data)}")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(3.0)
        poll = requests.post(
            result_url,
            json={"clientKey": api_key, "taskId": task_id},
            timeout=30,
            impersonate="chrome136",
        )
        data = _response_json(poll)
        if int(data.get("errorId") or 0) != 0:
            raise VerificationRequiredError(
                f"2captcha getTaskResult 失败: {_safe_error_text(data.get('errorDescription') or data)}"
            )
        if str(data.get("status") or "").lower() == "ready":
            solution = data.get("solution") if isinstance(data.get("solution"), dict) else {}
            return str(solution.get("token") or solution.get("gRecaptchaResponse") or "")
    raise VerificationRequiredError(f"2captcha 求解超时 ({timeout}s)")


def _solve_turnstile_yescaptcha(
    *,
    api_key: str,
    sitekey: str,
    page_url: str,
    proxy: str,
    timeout: int,
    log_callback: LogFn,
) -> str:
    # YesCaptcha uses the CapSolver-compatible createTask/getTaskResult shape.
    create_url = "https://api.yescaptcha.com/createTask"
    result_url = "https://api.yescaptcha.com/getTaskResult"
    parts = _parse_proxy_components(proxy)
    if parts.get("host") and parts.get("port"):
        proxy_str = (
            f"{parts.get('username')}:{parts.get('password')}@{parts['host']}:{parts['port']}"
            if parts.get("username")
            else f"{parts['host']}:{parts['port']}"
        )
        task = {
            "type": "TurnstileTaskProxylessM1",
            "websiteURL": page_url,
            "websiteKey": sitekey,
            # Some YesCaptcha plans accept proxy as a side field; keep proxyless type for widest compatibility.
            "proxy": proxy_str,
        }
    else:
        task = {
            "type": "TurnstileTaskProxylessM1",
            "websiteURL": page_url,
            "websiteKey": sitekey,
        }
    create = requests.post(
        create_url,
        json={"clientKey": api_key, "task": task},
        timeout=30,
        impersonate="chrome136",
    )
    create_data = _response_json(create)
    if create_data.get("errorId") not in (0, None, "0") and create_data.get("errorId"):
        raise VerificationRequiredError(
            f"yescaptcha createTask 失败: {_safe_error_text(create_data.get('errorDescription') or create_data)}"
        )
    task_id = str(create_data.get("taskId") or "").strip()
    if not task_id:
        raise VerificationRequiredError(
            f"yescaptcha createTask 未返回 taskId: {_safe_error_text(create_data)}"
        )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(2.0)
        poll = requests.post(
            result_url,
            json={"clientKey": api_key, "taskId": task_id},
            timeout=30,
            impersonate="chrome136",
        )
        data = _response_json(poll)
        if data.get("errorId") not in (0, None, "0") and data.get("errorId"):
            raise VerificationRequiredError(
                f"yescaptcha getTaskResult 失败: {_safe_error_text(data.get('errorDescription') or data)}"
            )
        if str(data.get("status") or "").lower() == "ready":
            solution = data.get("solution") if isinstance(data.get("solution"), dict) else {}
            return str(solution.get("token") or solution.get("gRecaptchaResponse") or "")
    raise VerificationRequiredError(f"yescaptcha 求解超时 ({timeout}s)")


def _validate_local_fingerprint(
    *,
    expected_user_agent: str,
    observed_user_agent: str,
    expected_language: str,
    observed_language: str,
    expected_platform: str = "",
    observed_platform: str = "",
    expected_client_hint_platform: str = "",
    observed_client_hint_platform: str = "",
    expected_browser_major: str = "",
    observed_browser_major: str = "",
) -> None:
    expected_user_agent = str(expected_user_agent or "").strip()
    observed_user_agent = str(observed_user_agent or "").strip()
    if expected_user_agent and observed_user_agent != expected_user_agent:
        raise VerificationRequiredError(
            "local Turnstile 浏览器 UA 与 HTTP 会话指纹不一致"
        )
    expected_primary = str(expected_language or "").split(",", 1)[0].split(";", 1)[0].strip().lower()
    observed_primary = str(observed_language or "").strip().lower()
    # Only compare when the browser actually reported a value. Some startup/error
    # pages transiently return empty language/platform fields.
    if expected_primary and observed_primary and observed_primary != expected_primary:
        raise VerificationRequiredError(
            "local Turnstile 浏览器语言与 HTTP 会话指纹不一致"
        )
    if (
        str(expected_platform or "").strip()
        and str(observed_platform or "").strip()
        and str(observed_platform or "").strip() != str(expected_platform).strip()
    ):
        raise VerificationRequiredError(
            "local Turnstile navigator.platform 与 HTTP 会话指纹不一致"
        )
    if (
        str(expected_client_hint_platform or "").strip()
        and str(observed_client_hint_platform or "").strip()
        and str(observed_client_hint_platform or "").strip()
        != str(expected_client_hint_platform).strip()
    ):
        raise VerificationRequiredError(
            "local Turnstile Client Hint platform 与 HTTP 会话指纹不一致"
        )
    if (
        str(expected_browser_major or "").strip()
        and str(observed_browser_major or "").strip()
        and str(observed_browser_major or "").strip()
        != str(expected_browser_major).strip()
    ):
        raise VerificationRequiredError(
            "local Turnstile 浏览器主版本与 HTTP 会话指纹不一致"
        )


async def _solve_request_async(request: SolveRequest, _sleep: Callable[[float], Any]) -> SolveResult:
    """Run legacy provider adapters off-loop while retaining one broker boundary."""
    started = time.monotonic()
    fingerprint = request.fingerprint or DEFAULT_FINGERPRINT

    if request.broker_url:
        endpoint = request.broker_url.rstrip("/") + "/v1/solve"
        try:
            expected_major = int(str(fingerprint.browser_major or "0").strip() or "0")
        except ValueError:
            expected_major = 0
        payload = {
            "provider": request.provider,
            "api_key": request.api_key,
            "sitekey": request.sitekey,
            "page_url": request.page_url,
            "proxy": request.proxy,
            "action": request.action,
            "cdata": request.cdata,
            "timeout_sec": request.timeout_sec,
            "headless": request.headless,
            "user_agent": fingerprint.user_agent,
            "accept_language": fingerprint.accept_language,
            "expected_platform": fingerprint.navigator_platform,
            "expected_client_hint_platform": fingerprint.client_hint_platform,
            # Solver API expects int; string works on some pydantic versions but keep strict.
            "expected_browser_major": expected_major,
        }
        response = await asyncio.to_thread(
            _http_post_json,
            endpoint,
            json_body=payload,
            timeout=max(5, request.timeout_sec + 5),
            impersonate=fingerprint.impersonate,
        )
        status = int(getattr(response, "status_code", 0) or 0)
        data = _response_json(response)
        if not 200 <= status < 300:
            raise _broker_http_error("solve", response)
        if data.get("ok") is False:
            raise VerificationRequiredError(
                f"Turnstile broker 求解失败: {_safe_error_text(data.get('error') or data)}"
            )
        token = str(data.get("token") or "").strip()
        remote_lease_preview = data.get("lease") if isinstance(data.get("lease"), dict) else {}
        # Local solver keeps token behind lease consume; empty token is normal when lease exists.
        if (
            request.provider == "local"
            and len(token) < 80
            and not str(remote_lease_preview.get("lease_id") or "").strip()
        ):
            raise VerificationRequiredError(
                "Turnstile broker 未返回 token/lease；"
                f"status={status} body={_safe_error_text(data or getattr(response, 'text', ''))}"
            )
        observed_user_agent = str(data.get("user_agent") or "").strip()
        fingerprint_data = data.get("fingerprint") if isinstance(data.get("fingerprint"), dict) else {}
        response_extras = data.get("extras") if isinstance(data.get("extras"), dict) else {}
        observed_language = str(
            fingerprint_data.get("navigator_language")
            or response_extras.get("language")
            or ""
        ).strip()
        user_agent_data = (
            fingerprint_data.get("user_agent_data")
            if isinstance(fingerprint_data.get("user_agent_data"), dict)
            else {}
        )
        observed_platform = str(fingerprint_data.get("platform") or "").strip()
        observed_client_hint_platform = str(
            fingerprint_data.get("client_hint_platform")
            or user_agent_data.get("platform")
            or ""
        ).strip()
        observed_browser_major = str(
            fingerprint_data.get("browser_major") or ""
        ).strip()
        if request.provider == "local":
            _validate_local_fingerprint(
                expected_user_agent=fingerprint.user_agent,
                observed_user_agent=observed_user_agent,
                expected_language=fingerprint.accept_language,
                observed_language=observed_language,
                expected_platform=fingerprint.navigator_platform,
                observed_platform=observed_platform,
                expected_client_hint_platform=fingerprint.client_hint_platform,
                observed_client_hint_platform=observed_client_hint_platform,
                expected_browser_major=fingerprint.browser_major,
                observed_browser_major=observed_browser_major,
            )
        extras = dict(response_extras)
        if fingerprint_data:
            extras["fingerprint"] = dict(fingerprint_data)
        if observed_language:
            extras["language"] = observed_language
        remote_lease = data.get("lease") if isinstance(data.get("lease"), dict) else {}
        if remote_lease.get("lease_id"):
            extras.update(
                {
                    "broker_url": request.broker_url.rstrip("/"),
                    "lease_id": str(remote_lease.get("lease_id") or ""),
                    "issued_at_ms": remote_lease.get("issued_at_ms"),
                    "expires_at_ms": remote_lease.get("expires_at_ms"),
                    "affinity_id": remote_lease.get("affinity_id"),
                }
            )
        raw_token_length = (
            remote_lease.get("token_length")
            or response_extras.get("token_length")
            or response_extras.get("token_len")
            or len(token)
        )
        try:
            extras["token_length"] = max(0, int(raw_token_length or 0))
        except (TypeError, ValueError):
            extras["token_length"] = len(token)
        return SolveResult(
            token=token,
            provider=request.provider,
            received_at=time.monotonic(),
            elapsed_ms=int((time.monotonic() - started) * 1000),
            user_agent=observed_user_agent,
            user_agent_authoritative=request.provider == "local",
            proxy=request.proxy,
            action=request.action,
            cdata=request.cdata,
            extras=extras,
        )

    if request.provider == "local":
        captured = await asyncio.to_thread(
            _solve_turnstile_local,
            page_url=request.page_url,
            proxy=request.proxy,
            timeout=request.timeout_sec,
            headless=request.headless,
            log_callback=None,
            sitekey=request.sitekey,
            action=request.action,
            cdata=request.cdata,
            user_agent=fingerprint.user_agent,
            accept_language=fingerprint.accept_language,
            expected_platform=fingerprint.navigator_platform,
            expected_client_hint_platform=fingerprint.client_hint_platform,
            expected_browser_major=fingerprint.browser_major,
            return_result=True,
        )
        if isinstance(captured, SolveResult):
            return captured
        token = str(captured or "").strip()
    else:
        token = await asyncio.to_thread(
            solve_turnstile_token,
            sitekey=request.sitekey,
            page_url=request.page_url,
            provider=request.provider,
            api_key=request.api_key,
            proxy=request.proxy,
            action=request.action,
            cdata=request.cdata,
            timeout=request.timeout_sec,
            headless=request.headless,
        )
    return SolveResult(
        token=token,
        provider=request.provider,
        received_at=time.monotonic(),
        elapsed_ms=int((time.monotonic() - started) * 1000),
        user_agent="",
        user_agent_authoritative=False,
        proxy=request.proxy,
        action=request.action,
        cdata=request.cdata,
    )


def solve_turnstile_result(
    *,
    sitekey: str,
    page_url: str = SIGNUP_URL,
    provider: str = "",
    api_key: str = "",
    proxy: str = "",
    action: str = "",
    cdata: str = "",
    timeout: int = 30,
    headless: bool = False,
    fingerprint: Optional[FingerprintProfile] = None,
    broker: Optional[TurnstileBroker] = None,
    broker_url: str = "",
    workers: int = 0,
    queue_size: int = 64,
) -> SolveResult:
    normalized_provider = _normalize_turnstile_provider(provider) or _default_turnstile_provider()
    resolved_key = _turnstile_api_key(normalized_provider, api_key)
    request = SolveRequest(
        provider=normalized_provider,
        sitekey=str(sitekey or "").strip(),
        page_url=str(page_url or SIGNUP_URL).strip() or SIGNUP_URL,
        api_key=resolved_key,
        proxy=str(proxy or "").strip(),
        action=str(action or "").strip(),
        cdata=str(cdata or "").strip(),
        timeout_sec=max(5, int(timeout or 30)),
        headless=bool(headless),
        fingerprint=fingerprint or DEFAULT_FINGERPRINT,
        broker_url=str(broker_url or "").strip(),
    )
    if normalized_provider != "local" and not request.api_key and not request.broker_url:
        raise VerificationRequiredError("Turnstile 求解缺少 API key")
    # Remote broker already owns admission control; avoid a second local queue.
    if request.broker_url and broker is None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            result = asyncio.run(_solve_request_async(request, asyncio.sleep))
        else:
            # Already on an event loop (rare for CLI registration); fall back to a worker thread.
            result = concurrent.futures.ThreadPoolExecutor(max_workers=1).submit(
                lambda: asyncio.run(_solve_request_async(request, asyncio.sleep))
            ).result()
    else:
        selected_workers = max(1, int(workers or (3 if normalized_provider == "local" else 16)))
        selected_broker = broker or get_shared_broker(
            provider=normalized_provider,
            workers=selected_workers,
            queue_limit=max(1, int(queue_size or 64)),
        )
        result = selected_broker.solve_sync(request, _solve_request_async)
    token_length = len(str(result.token or "").strip())
    result_extras = result.extras if isinstance(result.extras, dict) else {}
    lease_id = str(result_extras.get("lease_id") or "").strip()
    try:
        reported_token_length = int(
            result_extras.get("token_length") or result_extras.get("token_len") or 0
        )
    except (TypeError, ValueError):
        reported_token_length = 0
    # A lease-only response must report a plausible server-side token length;
    # a bare lease id cannot prove that /consume has a usable token.
    lease_ok = bool(lease_id) and reported_token_length >= 80
    if token_length < 80 and not lease_ok:
        raise VerificationRequiredError(
            f"{normalized_provider} 返回的 Turnstile token 无效 "
            f"(len={token_length}, reported_len={reported_token_length}, "
            f"lease={'yes' if lease_id else 'no'})"
        )
    return result


def _consume_remote_turnstile_lease(
    result: SolveResult,
    *,
    fingerprint: FingerprintProfile,
) -> str:
    extras = result.extras if isinstance(result.extras, dict) else {}
    broker_url = str(extras.get("broker_url") or "").rstrip("/")
    lease_id = str(extras.get("lease_id") or "").strip()
    if not broker_url or not lease_id:
        return str(result.token or "").strip()
    try:
        response = _http_post_json(
            f"{broker_url}/v1/leases/{quote(lease_id, safe='')}/consume",
            timeout=15,
            impersonate=fingerprint.impersonate,
        )
    except Exception as exc:
        raise VerificationRequiredError(
            f"Turnstile broker lease consume 请求失败: {_safe_error_text(exc)}"
        ) from exc
    status = int(getattr(response, "status_code", 0) or 0)
    data = _response_json(response)
    if status == 409:
        raise VerificationRequiredError("Turnstile broker lease 已重复消费、过期或不存在")
    if not 200 <= status < 300:
        raise VerificationRequiredError(
            f"Turnstile broker lease consume HTTP {status}: {_safe_error_text(data or getattr(response, 'text', ''))}"
        )
    token = str(data.get("token") or "").strip()
    if len(token) < 80:
        raise VerificationRequiredError("Turnstile broker lease consume 未返回有效 token")
    if result.token and token != str(result.token).strip():
        raise VerificationRequiredError("Turnstile broker lease token 与求解结果不一致")
    return token


def _acquire_remote_submit_permit(
    broker_url: str,
    *,
    timeout_sec: int,
    lease_sec: int,
    fingerprint: FingerprintProfile,
) -> str:
    try:
        response = _http_post_json(
            broker_url.rstrip("/") + "/v1/permits/submit/acquire",
            json_body={
                "timeout_sec": max(1, int(timeout_sec or 30)),
                "lease_sec": max(1, int(lease_sec or 60)),
            },
            timeout=max(5, int(timeout_sec or 30) + 5),
            impersonate=fingerprint.impersonate,
        )
    except Exception as exc:
        raise XAIHttpFlowError(
            f"Turnstile broker submit permit 获取失败: {_safe_error_text(exc)}"
        ) from exc
    status = int(getattr(response, "status_code", 0) or 0)
    data = _response_json(response)
    if not 200 <= status < 300:
        raise XAIHttpFlowError(
            f"Turnstile broker submit permit HTTP {status}: {_safe_error_text(data or getattr(response, 'text', ''))}"
        )
    permit_id = str(data.get("permit_id") or "").strip()
    if not permit_id:
        raise XAIHttpFlowError("Turnstile broker submit permit 响应缺少 permit_id")
    return permit_id


def _release_remote_submit_permit(
    broker_url: str,
    permit_id: str,
    *,
    fingerprint: FingerprintProfile,
) -> None:
    response = _http_post_json(
        broker_url.rstrip("/")
        + f"/v1/permits/submit/{quote(str(permit_id or ''), safe='')}/release",
        timeout=15,
        impersonate=fingerprint.impersonate,
    )
    status = int(getattr(response, "status_code", 0) or 0)
    if not 200 <= status < 300:
        raise XAIHttpFlowError(
            f"Turnstile broker submit permit release HTTP {status}"
        )


_LOCAL_SUBMIT_SEMAPHORES: Dict[int, threading.BoundedSemaphore] = {}
_LOCAL_SUBMIT_SEMAPHORES_LOCK = threading.Lock()


@contextmanager
def _submit_permit(
    *,
    broker_url: str,
    submit_workers: int,
    timeout_sec: int,
    fingerprint: FingerprintProfile,
    log_callback: LogFn = None,
):
    permit_id = ""
    local_semaphore: Optional[threading.BoundedSemaphore] = None
    if broker_url:
        lease_sec = max(60, min(300, int(timeout_sec or 60)))
        permit_id = _acquire_remote_submit_permit(
            broker_url,
            timeout_sec=timeout_sec,
            lease_sec=lease_sec,
            fingerprint=fingerprint,
        )
    else:
        limit = max(1, int(submit_workers or 1))
        with _LOCAL_SUBMIT_SEMAPHORES_LOCK:
            local_semaphore = _LOCAL_SUBMIT_SEMAPHORES.get(limit)
            if local_semaphore is None:
                local_semaphore = threading.BoundedSemaphore(limit)
                _LOCAL_SUBMIT_SEMAPHORES[limit] = local_semaphore
        if not local_semaphore.acquire(timeout=max(1, int(timeout_sec or 30))):
            raise XAIHttpFlowError("等待注册提交并发槽超时")
    try:
        yield permit_id
    finally:
        if permit_id:
            try:
                _release_remote_submit_permit(
                    broker_url,
                    permit_id,
                    fingerprint=fingerprint,
                )
            except Exception as exc:
                _log(log_callback, f"[HTTP][warn] submit permit release 失败: {_safe_error_text(exc)}")
        elif local_semaphore is not None:
            local_semaphore.release()


class BrowserlessXAIClient:
    """Stateful xAI HTTP client with a real cross-domain cookie jar."""

    def __init__(
        self,
        *,
        proxy: str = "",
        timeout: int = DEFAULT_TIMEOUT,
        user_agent: str = "",
        fingerprint: Optional[FingerprintProfile] = None,
        session: Any = None,
        log_callback: LogFn = None,
    ):
        self.proxy = normalize_proxy(proxy)
        self.proxies = _proxy_dict(self.proxy)
        self.timeout = max(5, int(timeout or DEFAULT_TIMEOUT))
        if fingerprint is None:
            runtime = build_runtime_fingerprint_profile()
            # Empty user_agent means "follow runtime Chrome major".
            selected_user_agent = str(user_agent or "").strip() or runtime.user_agent
            if selected_user_agent == runtime.user_agent:
                fingerprint = runtime
            else:
                # Explicit UA override keeps runtime platform/major alignment fields.
                fingerprint = FingerprintProfile(
                    profile_id=runtime.profile_id,
                    impersonate=runtime.impersonate,
                    user_agent=selected_user_agent,
                    accept_language=runtime.accept_language,
                    navigator_platform=runtime.navigator_platform,
                    client_hint_platform=runtime.client_hint_platform,
                    browser_major=runtime.browser_major,
                    sec_ch_ua=runtime.sec_ch_ua,
                )
        self.fingerprint = fingerprint
        self.user_agent = fingerprint.user_agent
        self.accept_language = fingerprint.accept_language
        self.log_callback = log_callback
        self.session = session or _session_with_impersonate_fallback(
            fingerprint.impersonate,
            log_callback=log_callback,
        )
        headers = getattr(self.session, "headers", None)
        if headers is not None:
            headers.update(
                {
                    "user-agent": self.user_agent,
                    "accept-language": self.accept_language,
                    "sec-ch-ua": fingerprint.sec_ch_ua,
                    "sec-ch-ua-platform": f'"{fingerprint.client_hint_platform}"',
                }
            )
        self.signup_page_url = ""
        self.signup_page_html = ""

    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        kwargs.setdefault("timeout", self.timeout)
        if self.proxies and "proxies" not in kwargs:
            kwargs["proxies"] = self.proxies
        fn = getattr(self.session, method.lower())
        try:
            return fn(url, **kwargs)
        except Exception as exc:
            if not _is_tls_transport_error(exc):
                raise
            fingerprint = getattr(self, "fingerprint", None)
            primary = str(getattr(fingerprint, "impersonate", "") or "").strip()
            active = str(vars(self).get("_active_impersonate") or "").strip()
            if not active:
                active = str(getattr(self.session, "_xai_impersonate", "") or "").strip()
            active = active or primary
            candidates = _impersonate_fallback_chain(primary)
            try:
                start_index = candidates.index(active)
            except ValueError:
                try:
                    start_index = candidates.index(primary)
                except ValueError:
                    start_index = -1
            last_error: Exception = exc
            for candidate in candidates[start_index + 1 :]:
                _log(
                    self.log_callback,
                    f"[HTTP][warn] TLS transport 失败，impersonate 重试: "
                    f"{active or '-'} -> {candidate}",
                )
                try:
                    _rebuild_session_with_impersonate(self, candidate)
                    self._active_impersonate = candidate
                    fn = getattr(self.session, method.lower())
                    return fn(url, **kwargs)
                except Exception as retry_exc:
                    if not _is_tls_transport_error(retry_exc):
                        raise
                    last_error = retry_exc
                    active = candidate
            raise last_error

    def _assert_normal_page(self, response: Any, stage: str) -> None:
        if _is_cf_interstitial(response):
            raise VerificationRequiredError(
                f"{stage} 被 Cloudflare 整页验证拦截；请更换已获许可的网络/验证方式。"
            )
        code = int(getattr(response, "status_code", 0) or 0)
        if not 200 <= code < 400:
            raise XAIHttpFlowError(f"{stage} HTTP {code}: {_safe_error_text(getattr(response, 'text', ''))}")

    def import_sso(self, sso: str, sso_rw: str = "") -> None:
        sso = str(sso or "").strip()
        if not sso:
            raise XAIHttpFlowError("sso cookie 为空")
        cookies = getattr(self.session, "cookies", None)
        if cookies is None:
            raise XAIHttpFlowError("HTTP session 不支持 cookie jar")
        # xAI uses a parent-domain session cookie; do not duplicate it over
        # several domains because duplicate Cookie headers can be rejected.
        cookies.set("sso", sso, domain=".x.ai", path="/")
        cookies.set("sso-rw", str(sso_rw or sso), domain=".x.ai", path="/")
        cookies.set("last-logged-in-with", "EMAIL", domain=".x.ai", path="/")

    def _get_sso(self) -> str:
        cookies = getattr(self.session, "cookies", None)
        if cookies is None:
            return ""
        # curl_cffi Cookies iterates cookie *names* (str), not Cookie objects.
        try:
            value = cookies.get("sso")
            if value:
                return str(value).strip()
        except Exception:
            pass
        try:
            for item in cookies:
                name = str(getattr(item, "name", item) or "")
                if name != "sso":
                    continue
                if hasattr(item, "value"):
                    return str(item.value or "").strip()
                got = cookies.get("sso")
                return str(got or "").strip()
        except Exception:
            pass
        try:
            jar = getattr(cookies, "jar", None)
            if jar is not None:
                values = [c.value for c in jar if str(getattr(c, "name", "")) == "sso"]
                if values:
                    return str(values[-1] or "").strip()
        except Exception:
            pass
        return ""

    def open_signup(self) -> Dict[str, str]:
        response = self._request("get", SIGNUP_URL, allow_redirects=True)
        self._assert_normal_page(response, "打开注册页")
        self.signup_page_url = str(getattr(response, "url", "") or SIGNUP_URL)
        self.signup_page_html = str(getattr(response, "text", "") or "")
        if "/sign-up" not in urlparse(self.signup_page_url).path:
            raise XAIHttpFlowError(f"注册页被重定向到 {urlparse(self.signup_page_url).path or '/'}")
        metadata = self.challenge_metadata(self.signup_page_html)
        _log(
            self.log_callback,
            "[HTTP] 注册页已建立会话 | "
            f"turnstileSitekey={'yes' if metadata.get('turnstile_sitekey') else 'no'} "
            f"castle={'enabled' if metadata.get('castle_enabled') else 'off'}",
        )
        return metadata

    @staticmethod
    def challenge_metadata(page_html: str) -> Dict[str, str]:
        text = html_lib.unescape(str(page_html or "").replace(r'\"', '"'))
        explicit_sitekeys = [
            html_lib.unescape(match.group(2)).strip()
            for match in re.finditer(
                r'\bdata-sitekey\s*=\s*([\'\"])(.*?)\1',
                text,
                flags=re.I | re.S,
            )
            if str(match.group(2) or "").strip()
        ]
        json_sitekey_matches = list(
            re.finditer(
                r'"sitekey"\s*:\s*"([^"\\]+)"',
                text,
                flags=re.I,
            )
        )
        json_sitekeys = [
            html_lib.unescape(match.group(1).replace(r"\/", "/")).strip()
            for match in json_sitekey_matches
            if str(match.group(1) or "").strip()
        ]

        # A rendered widget attribute is authoritative over serialized/script
        # copies.  Within the selected source, however, conflicting values are
        # unsafe: never silently pick the first candidate.
        selected_candidates = explicit_sitekeys if explicit_sitekeys else json_sitekeys
        unique_sitekeys: List[str] = []
        for candidate in selected_candidates:
            if candidate not in unique_sitekeys:
                unique_sitekeys.append(candidate)
        sitekey_conflict = len(unique_sitekeys) > 1
        sitekey_value = unique_sitekeys[0] if len(unique_sitekeys) == 1 else ""
        sitekey_anchor = json_sitekey_matches[0] if json_sitekey_matches else None
        turnstile_tag = re.search(
            r"<[^>]+(?:\bcf-turnstile\b|\bdata-sitekey\b)[^>]*>",
            text,
            flags=re.I | re.S,
        )

        def _tag_attribute(name: str) -> str:
            if not turnstile_tag:
                return ""
            match = re.search(
                rf"\b{re.escape(name)}\s*=\s*(['\"])(.*?)\1",
                turnstile_tag.group(0),
                flags=re.I | re.S,
            )
            return html_lib.unescape(match.group(2)).strip() if match else ""

        def _near_sitekey_json(name: str) -> str:
            if not sitekey_anchor:
                return ""
            start = max(0, sitekey_anchor.start() - 260)
            end = min(len(text), sitekey_anchor.end() + 520)
            match = re.search(
                rf'"{re.escape(name)}"\s*:\s*"((?:\\.|[^"\\])*)"',
                text[start:end],
                flags=re.I,
            )
            if not match:
                return ""
            return html_lib.unescape(match.group(1).replace(r"\/", "/")).strip()

        castle_pk = re.search(r'"castlePk"\s*:\s*"([^"\\]+)"', text)
        enabled = re.search(r'"enableCastle"\s*:\s*(true|false)', text, flags=re.I)
        return {
            "turnstile_sitekey": sitekey_value,
            "turnstile_sitekey_conflict": "true" if sitekey_conflict else "",
            "turnstile_action": _tag_attribute("data-action") or _near_sitekey_json("action"),
            "turnstile_cdata": _tag_attribute("data-cdata") or _near_sitekey_json("cdata"),
            "castle_pk": castle_pk.group(1) if castle_pk else "",
            "castle_enabled": (enabled.group(1).lower() if enabled else ""),
        }

    def _grpc_unary(self, method: str, payload: bytes, *, referer: str) -> List[bytes]:
        response = self._request(
            "post",
            f"{ACCOUNT_ORIGIN}/auth_mgmt.AuthManagement/{method}",
            data=_grpc_frame(payload),
            headers={
                "accept": "*/*",
                "content-type": "application/grpc-web+proto",
                "origin": ACCOUNT_ORIGIN,
                "referer": referer,
                "x-grpc-web": "1",
                "x-user-agent": "connect-es/2.1.1",
            },
        )
        code = int(getattr(response, "status_code", 0) or 0)
        if not 200 <= code < 300:
            raise XAIHttpFlowError(
                f"{method} HTTP {code}: {_safe_error_text(getattr(response, 'text', ''))}"
            )
        raw = bytes(getattr(response, "content", b"") or b"")
        frames: List[bytes] = []
        trailers: Dict[str, str] = {}
        if raw:
            frames, trailers = parse_grpc_web_response(raw)
        # Connect/gRPC-Web may place status only in HTTP headers when the body is empty.
        headers = getattr(response, "headers", None) or {}
        header_status = ""
        header_message = ""
        try:
            header_status = str(headers.get("grpc-status") or headers.get("Grpc-Status") or "")
            header_message = str(headers.get("grpc-message") or headers.get("Grpc-Message") or "")
        except Exception:
            pass
        if header_status and "grpc-status" not in trailers:
            trailers["grpc-status"] = header_status
        if header_message and "grpc-message" not in trailers:
            trailers["grpc-message"] = header_message
        grpc_status = str(trailers.get("grpc-status", ""))
        if not raw and grpc_status == "":
            raise ProtocolError(f"{method} 返回空 gRPC-Web 响应")
        if grpc_status != "0":
            message = unquote(trailers.get("grpc-message", "未知 gRPC 错误"))
            if "turnstile" in message.lower() or "castle" in message.lower():
                raise VerificationRequiredError(f"{method} 验证失败: {_safe_error_text(message)}")
            raise XAIHttpFlowError(f"{method} gRPC {grpc_status}: {_safe_error_text(message)}")
        return frames

    def request_email_validation_code(self, email: str, castle_request_token: str) -> None:
        if not self.signup_page_url:
            self.open_signup()
        email = str(email or "").strip()
        if not email or "@" not in email:
            raise XAIHttpFlowError("注册邮箱无效")
        castle_request_token = str(castle_request_token or "").strip()
        # CreateEmailValidationCodeRequest: email=1, castle_request_token=3.
        payload = _pb_string(1, email)
        if castle_request_token:
            payload += _pb_string(3, castle_request_token)
        else:
            _log(self.log_callback, "[HTTP][warn] 未提供 Castle token，按服务端可选字段直接请求邮箱验证码")
        self._grpc_unary("CreateEmailValidationCode", payload, referer=self.signup_page_url)
        _log(self.log_callback, f"[HTTP] 已请求 xAI 邮箱验证码 | email={mask_email(email)}")

    def verify_email_validation_code(self, email: str, email_validation_code: str) -> str:
        """Mirror the browser verifyEmailValidationCode step before final signup submit.

        Live observation: invalid codes return HTTP 200 with empty body and
        grpc-status/grpc-message headers (not trailer frames).
        """
        if not self.signup_page_url:
            self.open_signup()
        email = str(email or "").strip()
        code = re.sub(r"[^A-Za-z0-9]", "", str(email_validation_code or "").upper())
        if not email or "@" not in email:
            raise XAIHttpFlowError("注册邮箱无效")
        if len(code) < 6:
            raise XAIHttpFlowError("xAI 邮箱验证码格式无效")
        # VerifyEmailValidationCodeRequest: email=1, email_validation_code=2.
        payload = _pb_string(1, email) + _pb_string(2, code)
        self._grpc_unary("VerifyEmailValidationCode", payload, referer=self.signup_page_url)
        _log(self.log_callback, f"[HTTP] 邮箱验证码已通过校验 | email={mask_email(email)}")
        return code

    def _find_action_id(
        self,
        *,
        page_url: str,
        page_html: str,
        marker: str,
        fallback: str,
    ) -> str:
        candidates = _script_urls(page_url, page_html)
        for script_url in candidates:
            try:
                body = str(getattr(self._request("get", script_url), "text", "") or "")
            except Exception:
                continue
            marker_at = body.find(marker)
            if marker_at < 0:
                continue
            refs = list(
                re.finditer(
                    # Turbopack emits `(0,i.createServerReference)("id", …)`;
                    # non-minified builds can use `createServerReference("id", …)`.
                    r'createServerReference\)?\(\s*"([a-f0-9]{32,64})"', body, flags=re.I
                )
            )
            if refs:
                return min(refs, key=lambda item: abs(item.start() - marker_at)).group(1)
        _log(self.log_callback, f"[HTTP][warn] 未能从脚本提取 {marker} action id，使用兼容回退")
        return fallback

    def _call_server_action(
        self,
        *,
        page_url: str,
        route: str,
        action_id: str,
        argument: Dict[str, Any],
    ) -> str:
        response = self._request(
            "post",
            page_url,
            data=json.dumps([argument], ensure_ascii=False, separators=(",", ":")),
            headers={
                "accept": "text/x-component",
                "content-type": "text/plain;charset=UTF-8",
                "origin": ACCOUNT_ORIGIN,
                "referer": page_url,
                "next-action": action_id,
                "next-router-state-tree": _router_state(route),
            },
        )
        self._assert_normal_page(response, f"{route} Server Action")
        return str(getattr(response, "text", "") or "")

    def _follow_cookie_setter(self, cookie_setter_url: str) -> str:
        if not cookie_setter_url.startswith("https://"):
            raise ProtocolError("cookieSetterUrl 不是 HTTPS URL")
        # Follow the 4-hop chain hop-by-hop so intermediate Set-Cookie headers
        # (auth.grokipedia → grokusercontent → grok.com → auth.x.ai) are kept.
        url = cookie_setter_url
        last_response = None
        for hop in range(8):
            response = self._request("get", url, allow_redirects=False)
            last_response = response
            code = int(getattr(response, "status_code", 0) or 0)
            headers = getattr(response, "headers", None) or {}
            location = ""
            try:
                location = str(headers.get("location") or headers.get("Location") or "").strip()
            except Exception:
                location = ""
            if code in {301, 302, 303, 307, 308} and location:
                url = urljoin(url, location)
                continue
            if code >= 400:
                raise XAIHttpFlowError(
                    f"设置登录 cookie HTTP {code} hop={hop} url_host={urlparse(url).netloc} "
                    f"q_len={len(urlparse(url).query)}: {_safe_error_text(getattr(response, 'text', ''))}"
                )
            break
        if last_response is not None and not (200 <= int(getattr(last_response, "status_code", 0) or 0) < 400):
            self._assert_normal_page(last_response, "设置登录 cookie")
        sso = self._get_sso()
        if not sso:
            # One more allow-redirects pass as a fallback for clients that only
            # expose cookies after the final hop is consumed by the adapter.
            response = self._request("get", cookie_setter_url, allow_redirects=True)
            self._assert_normal_page(response, "设置登录 cookie")
            sso = self._get_sso()
        if not sso:
            raise ProtocolError("cookie setter 跳转完成后仍未获得 sso cookie")
        return sso

    def login_with_password(
        self,
        *,
        email: str,
        password: str,
        turnstile_token: str,
        castle_request_token: str,
    ) -> str:
        email = str(email or "").strip()
        password = str(password or "")
        turnstile_token = str(turnstile_token or "").strip()
        castle_request_token = str(castle_request_token or "").strip()
        if not email or not password:
            raise XAIHttpFlowError("邮箱或密码为空")
        if not turnstile_token:
            raise VerificationRequiredError(
                "密码登录需要同一 HTTP 会话中生成的新鲜 Turnstile token；"
                "请通过获授权的验证渠道提供它。"
            )
        page = self._request("get", SIGNIN_URL, allow_redirects=True)
        self._assert_normal_page(page, "打开登录页")
        request_data = {
            "createSessionRequest": {
                "credentials": {
                    "case": "emailAndPassword",
                    "value": {
                        "email": email,
                        "clearTextPassword": password,
                    },
                }
            },
            "turnstileToken": turnstile_token,
        }
        if castle_request_token:
            request_data["castleRequestToken"] = castle_request_token
        else:
            _log(self.log_callback, "[HTTP][warn] 未提供 Castle token，按服务端可选字段尝试密码登录")
        response = self._request(
            "post",
            API_RPC_URL,
            json={
                "rpc": "createSession",
                "req": request_data,
            },
            headers={
                "accept": "*/*",
                "content-type": "application/json",
                "origin": ACCOUNT_ORIGIN,
                "referer": str(getattr(page, "url", "") or SIGNIN_URL),
            },
        )
        data = _response_json(response)
        if int(getattr(response, "status_code", 0) or 0) != 200:
            message = _safe_error_text(data.get("error") or getattr(response, "text", ""))
            if "turnstile" in message.lower() or "castle" in message.lower() or int(getattr(response, "status_code", 0) or 0) == 403:
                raise VerificationRequiredError(f"密码登录验证被拒绝: {message}")
            raise XAIHttpFlowError(f"密码登录失败 HTTP {getattr(response, 'status_code', 0)}: {message}")
        cookie_setter_url = str(data.get("cookieSetterUrl") or "").strip()
        if not cookie_setter_url:
            raise ProtocolError("createSession 成功响应缺少 cookieSetterUrl")
        sso = self._follow_cookie_setter(cookie_setter_url)
        _log(self.log_callback, f"[HTTP] 密码登录成功 | email={mask_email(email)}")
        return sso

    def submit_registration(
        self,
        *,
        email: str,
        email_validation_code: str,
        given_name: str,
        family_name: str,
        password: str,
        turnstile_token: str,
        castle_request_token: str,
    ) -> str:
        if not self.signup_page_url:
            self.open_signup()
        turnstile_token = str(turnstile_token or "").strip()
        castle_request_token = str(castle_request_token or "").strip()
        if not turnstile_token:
            raise VerificationRequiredError(
                "提交注册需要同一会话的新鲜 Turnstile token；"
                "纯 HTTP 模式不会生成或复用过期 token。"
            )
        action_id = self._find_action_id(
            page_url=self.signup_page_url,
            page_html=self.signup_page_html,
            marker="createUserAndSessionRequest",
            fallback=KNOWN_SIGNUP_ACTION_ID,
        )
        code = re.sub(r"[^A-Za-z0-9]", "", str(email_validation_code or "").upper())
        if len(code) < 6:
            raise XAIHttpFlowError("xAI 邮箱验证码格式无效")
        argument = {
            "emailValidationCode": code,
            "createUserAndSessionRequest": {
                "email": str(email or "").strip(),
                "givenName": str(given_name or "").strip(),
                "familyName": str(family_name or "").strip(),
                "clearTextPassword": str(password or ""),
                "tosAcceptedVersion": 1,
            },
            "turnstileToken": turnstile_token,
            "conversionId": str(uuid.uuid4()),
        }
        if castle_request_token:
            argument["castleRequestToken"] = castle_request_token
        else:
            _log(self.log_callback, "[HTTP][warn] 未提供 Castle token，按服务端可选字段尝试提交注册")
        if not all(
            [
                argument["createUserAndSessionRequest"]["email"],
                argument["createUserAndSessionRequest"]["givenName"],
                argument["createUserAndSessionRequest"]["familyName"],
                argument["createUserAndSessionRequest"]["clearTextPassword"],
            ]
        ):
            raise XAIHttpFlowError("注册资料不完整")
        payload = self._call_server_action(
            page_url=self.signup_page_url,
            route="sign-up",
            action_id=action_id,
            argument=argument,
        )
        result = _extract_rsc_object(payload, "error")
        if result.get("error"):
            message = _safe_error_text(result.get("error"))
            if "turnstile" in message.lower() or "castle" in message.lower():
                raise VerificationRequiredError(f"注册验证被拒绝: {message}")
            raise XAIHttpFlowError(f"注册被服务端拒绝: {message}")
        if result.get("signInMethods"):
            raise XAIHttpFlowError(
                f"邮箱已存在账号，signInMethods={_safe_error_text(result.get('signInMethods'))}"
            )
        # A successful action can either return a setter URL in its RSC value or
        # have already committed cookies in the response.  Live client does
        # `window.location.href = e` when the action result is a string URL.
        sso = self._get_sso()
        if sso:
            _log(self.log_callback, f"[HTTP] 注册成功 | email={mask_email(email)}")
            return sso
        cookie_setter_url = _extract_cookie_setter_url(payload)
        if not cookie_setter_url:
            # Plain RSC string result: 1:"https://auth.../set-cookie?q=..."
            for match in re.finditer(
                r'\d+:"(https://auth\.(?:grokipedia|grokusercontent|grok|x)\.ai/set-cookie\?[^"]+)"',
                str(payload or "").replace(r"\/", "/").replace(r"\u0026", "&"),
            ):
                cookie_setter_url = match.group(1)
                break
        if not cookie_setter_url:
            # Full-page RSC re-render usually means the Server Action was not
            # accepted (bad next-action / turnstile / payload).
            snippet = re.sub(r"\s+", " ", str(payload or ""))[:240]
            raise ProtocolError(
                "注册响应中未找到 cookieSetterUrl 或 sso cookie；"
                f"payload_len={len(payload or '')} snippet={snippet}"
            )
        _log(
            self.log_callback,
            f"[HTTP] 跟随 cookie setter | host={urlparse(cookie_setter_url).netloc} "
            f"q_len={len(urlparse(cookie_setter_url).query)}",
        )
        sso = self._follow_cookie_setter(cookie_setter_url)
        _log(self.log_callback, f"[HTTP] 注册成功 | email={mask_email(email)}")
        return sso

    def obtain_oauth_credential(self, *, output_dir: str, email_hint: str = "") -> str:
        """Authorize the fixed CLI client and write a CLIProxyAPI-compatible JSON."""
        verifier, challenge = generate_pkce_codes()
        state = generate_random_token(32)
        nonce = generate_random_token(32)
        auth_endpoint, token_endpoint = discover_endpoints(proxies=self.proxies)
        redirect_uri = f"http://{XAI_REDIRECT_HOST}:56121{XAI_REDIRECT_PATH}"
        auth_url = build_authorize_url(auth_endpoint, redirect_uri, challenge, state, nonce)
        page = self._request("get", auth_url, allow_redirects=True)
        self._assert_normal_page(page, "打开 OAuth 授权页")
        consent_url = str(getattr(page, "url", "") or "")
        if urlparse(consent_url).path != "/oauth2/consent":
            raise XAIHttpFlowError(
                "OAuth 未进入 consent 页面；当前会话可能未登录或已过期 "
                f"(path={urlparse(consent_url).path or '/'})"
            )
        params = parse_qs(urlparse(consent_url).query)
        required = (
            "client_id",
            "redirect_uri",
            "scope",
            "state",
            "code_challenge",
            "code_challenge_method",
            "nonce",
        )
        if any(not params.get(name) for name in required):
            raise ProtocolError("OAuth consent URL 缺少必要参数")
        action_id = self._find_action_id(
            page_url=consent_url,
            page_html=str(getattr(page, "text", "") or ""),
            marker="submitOAuth2Consent",
            fallback=KNOWN_CONSENT_ACTION_ID,
        )
        consent = {
            "action": "allow",
            "clientId": params["client_id"][0],
            "redirectUri": params["redirect_uri"][0],
            "scope": params["scope"][0],
            "state": params["state"][0],
            "codeChallenge": params["code_challenge"][0],
            "codeChallengeMethod": params["code_challenge_method"][0],
            "nonce": params["nonce"][0],
            "principalType": "User",
            "principalId": "",
            "referrer": params.get("referrer", ["cli-proxy-api"])[0],
        }
        payload = self._call_server_action(
            page_url=consent_url,
            route="consent",
            action_id=action_id,
            argument=consent,
        )
        result = _extract_rsc_object(payload, "success")
        if result.get("success") is not True or str(result.get("action") or "") != "allow":
            raise XAIHttpFlowError(
                f"OAuth consent 被拒绝: {_safe_error_text(result.get('error') or payload)}"
            )
        code = str(result.get("code") or "").strip()
        if not code:
            raise ProtocolError("OAuth consent 成功但缺少授权 code")
        token_data = exchange_code_for_tokens(
            code,
            redirect_uri,
            verifier,
            token_endpoint,
            proxies=self.proxies,
        )
        token_email = str(token_data.get("email") or "").strip()
        if email_hint and not token_email:
            token_data["email"] = str(email_hint).strip()
        elif email_hint and token_email and token_email.lower() != str(email_hint).strip().lower():
            raise ProtocolError(
                f"OAuth 账号与期望邮箱不一致: oauth={mask_email(token_email)} hint={mask_email(email_hint)}"
            )
        doc = build_credential_document(token_data, redirect_uri, token_endpoint)
        path = save_credential_file(doc, output_dir)
        _log(self.log_callback, f"[HTTP] OAuth 凭证已保存 | email={mask_email(doc.get('email', ''))} | {path}")
        return path


def _pick_list_payload(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("results", "hydra:member", "data", "messages"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        nested = data.get("data")
        if isinstance(nested, dict) and isinstance(nested.get("messages"), list):
            return [item for item in nested["messages"] if isinstance(item, dict)]
    return []


def _looks_like_xai_mail(subject: str = "", body: str = "", sender: str = "") -> bool:
    blob = f"{subject}\n{body}\n{sender}".lower()
    return any(
        marker in blob
        for marker in (
            "x.ai",
            "xai",
            "accounts.x.ai",
            "validate your email",
            "creating an xai account",
            "xai confirmation",
            "xai account",
        )
    )


def extract_xai_email_code(text: str, subject: str = "", *, sender: str = "") -> str:
    """Extract the xAI signup code (live format: ``MWM-AME`` / ``MWMAME``).

    Avoids false positives from other services' 6-digit OTP mails in the same
    inbox (OpenAI/ChatGPT/etc.).
    """
    subject = str(subject or "")
    text = str(text or "")
    sender = str(sender or "")
    xaiish = _looks_like_xai_mail(subject, text, sender)

    def _from(source: str, *, require_separator: bool) -> str:
        if require_separator:
            match = re.search(r"\b([A-Z0-9]{3})-([A-Z0-9]{3})\b", source, re.I)
        else:
            # Only accept unseparated forms on already-identified xAI mail.
            match = re.search(r"\b([A-Z0-9]{3})[-\s]?([A-Z0-9]{3})\b", source, re.I)
        if not match:
            return ""
        return (match.group(1) + match.group(2)).upper()

    # Prefer dashed codes everywhere; they are distinctive (MWM-AME).
    for source in (subject, text):
        code = _from(source, require_separator=True)
        if code:
            return code
    if not xaiish:
        return ""
    for source in (subject, text):
        code = _from(source, require_separator=False)
        if code:
            return code
    return ""


def _flatten_mail_bodies(*sources: Any) -> Tuple[str, str]:
    """Collect subject + plain text from heterogeneous mailbox payloads."""
    combined: List[str] = []
    subject = ""
    for source in sources:
        if not isinstance(source, dict):
            continue
        if not subject:
            subject = str(source.get("subject") or "").strip()
        for key in ("text", "raw", "content", "intro", "body", "snippet", "bodyPreview"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                combined.append(value)
            elif isinstance(value, dict):
                content = value.get("content")
                if isinstance(content, str) and content.strip():
                    combined.append(re.sub(r"<[^>]+>", " ", content) if value.get("contentType") == "html" else content)
        html_value = source.get("html") or []
        if isinstance(html_value, str):
            html_value = [html_value]
        if isinstance(html_value, list):
            combined.extend(re.sub(r"<[^>]+>", " ", str(item)) for item in html_value)
    return subject, "\n".join(combined)


class CloudflareTempMailbox:
    """Minimal adapter for the project's cloudflare_temp_email-compatible API."""

    def __init__(self, config: Dict[str, Any], *, proxy: str = "", timeout: int = DEFAULT_TIMEOUT):
        self.config = dict(config or {})
        self.base = str(self.config.get("cloudflare_api_base") or "").rstrip("/")
        if not self.base or "example.com" in self.base:
            raise MailboxError("cloudflare_api_base 未配置为真实临时邮箱 API 地址")
        self.timeout = max(5, int(timeout or DEFAULT_TIMEOUT))
        self.proxies = _proxy_dict(proxy)
        self.session = requests.Session(impersonate="chrome136")

    def _path(self, key: str, default: str) -> str:
        value = str(self.config.get(key, default) or default).strip()
        return value if value.startswith("/") else "/" + value

    def _auth_mode(self) -> str:
        return str(self.config.get("cloudflare_auth_mode", "none") or "none").lower()

    def _api_key(self) -> str:
        return str(self.config.get("cloudflare_api_key") or "")

    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        kwargs.setdefault("timeout", self.timeout)
        if self.proxies and "proxies" not in kwargs:
            kwargs["proxies"] = self.proxies
        return getattr(self.session, method.lower())(url, **kwargs)

    def _admin_headers(self, content_type: bool = False) -> Dict[str, str]:
        headers: Dict[str, str] = {"content-type": "application/json"} if content_type else {}
        key = self._api_key()
        mode = self._auth_mode()
        if key and mode == "x-admin-auth":
            headers["x-admin-auth"] = key
        elif key and mode == "x-api-key":
            headers["x-api-key"] = key
        elif key and mode not in ("none", "query-key"):
            headers["authorization"] = f"Bearer {key}"
        return headers

    def _params(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = dict(params or {})
        if self._api_key() and self._auth_mode() == "query-key":
            params["key"] = self._api_key()
        return params

    def create(self) -> Tuple[str, str]:
        path = self._path("cloudflare_path_accounts", "/api/new_address")
        domains = [
            item.strip()
            for item in str(self.config.get("defaultDomains") or "").split(",")
            if item.strip() and item.strip().lower() != "example.com"
        ]
        admin = path.rstrip("/").lower() == "/admin/new_address"
        payload: Dict[str, Any] = {}
        if admin:
            payload = {
                "name": "xai" + "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(10)),
                "enablePrefix": True,
            }
        if domains:
            payload["domain"] = domains[0]
        headers = self._admin_headers(content_type=True) if admin else {"content-type": "application/json"}
        response = self._request("post", self.base + path, json=payload, headers=headers, params=self._params())
        if not 200 <= int(getattr(response, "status_code", 0) or 0) < 300:
            raise MailboxError(f"临时邮箱创建 HTTP {getattr(response, 'status_code', 0)}")
        data = _response_json(response)
        address = str(data.get("address") or "").strip()
        token = str(data.get("jwt") or "").strip()
        if not address or not token:
            raise MailboxError("临时邮箱接口未返回 address/jwt")
        return address, token

    def _messages(self, token: str) -> List[Dict[str, Any]]:
        path = self._path("cloudflare_path_messages", "/api/mails")
        response = self._request(
            "get",
            self.base + path,
            headers={"authorization": f"Bearer {token}"},
            params=self._params({"limit": 20, "offset": 0}),
        )
        if not 200 <= int(getattr(response, "status_code", 0) or 0) < 300:
            raise MailboxError(f"临时邮箱收件列表 HTTP {getattr(response, 'status_code', 0)}")
        try:
            return _pick_list_payload(response.json())
        except Exception as exc:
            raise MailboxError("临时邮箱收件列表不是 JSON") from exc

    def _message_detail(self, token: str, message_id: str) -> Dict[str, Any]:
        candidates = [
            f"{self.base}/api/mail/{message_id}",
            f"{self.base}{self._path('cloudflare_path_messages', '/api/mails')}/{message_id}",
        ]
        for url in candidates:
            try:
                response = self._request(
                    "get",
                    url,
                    headers={"authorization": f"Bearer {token}"},
                    params=self._params(),
                )
                if not 200 <= int(getattr(response, "status_code", 0) or 0) < 300:
                    continue
                data = _response_json(response)
                if isinstance(data.get("data"), dict):
                    return data["data"]
                return data
            except Exception:
                continue
        return {}

    def wait_for_xai_code(
        self,
        email: str,
        token: str,
        *,
        timeout: int = 45,
        poll_interval: int = 2,
        received_after_epoch: float = 0.0,
    ) -> str:
        deadline = time.monotonic() + max(5, int(timeout or 45))
        attempts: Dict[str, int] = {}
        while time.monotonic() < deadline:
            try:
                messages = self._messages(token)
            except Exception:
                time.sleep(max(1, int(poll_interval or 3)))
                continue
            for message in messages:
                message_id = str(message.get("id") or message.get("msgid") or "")
                if not message_id or attempts.get(message_id, 0) >= 5:
                    continue
                attempts[message_id] = attempts.get(message_id, 0) + 1
                detail = self._message_detail(token, message_id)
                subject, body = _flatten_mail_bodies(message, detail)
                code = extract_xai_email_code(body, subject)
                if code:
                    return code
            time.sleep(max(1, int(poll_interval or 3)))
        raise MailboxError(f"在 {timeout}s 内未收到 {mask_email(email)} 的 xAI 验证码")



# Cross-process local Turnstile browser limiter.
# Each register worker is a separate process; without this, 4 workers open 4
# Chrome processes at once and thrash each other (disconnect / empty timeout).
_LOCAL_TURNSTILE_LOCK_PATH = Path(
    os.environ.get("XAI_LOCAL_TURNSTILE_LOCK_PATH")
    or (Path(tempfile.gettempdir()) / "xai-local-turnstile.lock")
)
_LOCAL_TURNSTILE_SLOT_DIR = Path(
    os.environ.get("XAI_LOCAL_TURNSTILE_SLOT_DIR")
    or (Path(tempfile.gettempdir()) / "xai-local-turnstile-slots")
)
DEFAULT_LOCAL_TURNSTILE_MAX_INFLIGHT = 2
MIN_LOCAL_TURNSTILE_MAX_INFLIGHT = 1
MAX_LOCAL_TURNSTILE_MAX_INFLIGHT = 12
LOCAL_TURNSTILE_LOCK_TIMEOUT_SEC = configured_lock_timeout(
    "XAI_LOCAL_TURNSTILE_LOCK_TIMEOUT_SEC",
    default=120.0,
)


def _load_turnstile_inflight_config_fallback() -> Dict[str, Any]:
    """Best-effort read of the active local config for cross-process slot limits."""
    candidates = []
    env_cfg = str(os.environ.get("XAI_CONFIG_PATH") or os.environ.get("XAI_MAIL_CONFIG") or "").strip()
    if env_cfg:
        candidates.append(Path(env_cfg))
    candidates.append(CONFIG_PATH)
    for path in candidates:
        try:
            if path.is_file():
                import json
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception:
            continue
    return {}


def resolve_local_turnstile_max_inflight(
    config: Optional[Dict[str, Any]] = None,
    *,
    strict: bool = False,
) -> int:
    """Max concurrent local Chrome Turnstile captures across all processes.

    Priority:
      1) env XAI_LOCAL_TURNSTILE_MAX_INFLIGHT
      2) config.local_turnstile_max_inflight
      3) config.local_turnstile_max_workers (legacy alias)
      4) default 2
    """
    env_raw = str(os.environ.get("XAI_LOCAL_TURNSTILE_MAX_INFLIGHT") or "").strip()
    cfg = config if isinstance(config, dict) else None
    if cfg is None:
        cfg = _load_turnstile_inflight_config_fallback()
    cfg_raw = None
    if isinstance(cfg, dict):
        if "local_turnstile_max_inflight" in cfg and str(cfg.get("local_turnstile_max_inflight") or "").strip() != "":
            cfg_raw = cfg.get("local_turnstile_max_inflight")
        elif "local_turnstile_max_workers" in cfg and str(cfg.get("local_turnstile_max_workers") or "").strip() != "":
            # legacy key: treat as desired inflight when dedicated key missing
            cfg_raw = cfg.get("local_turnstile_max_workers")
    raw = env_raw if env_raw != "" else ("" if cfg_raw is None else str(cfg_raw).strip())
    if raw == "":
        return DEFAULT_LOCAL_TURNSTILE_MAX_INFLIGHT
    try:
        value = int(float(raw))
    except (TypeError, ValueError) as exc:
        if strict:
            raise ValueError("local Turnstile 并发上限必须是整数") from exc
        return DEFAULT_LOCAL_TURNSTILE_MAX_INFLIGHT
    if not (MIN_LOCAL_TURNSTILE_MAX_INFLIGHT <= value <= MAX_LOCAL_TURNSTILE_MAX_INFLIGHT):
        if strict:
            raise ValueError(
                "local Turnstile 并发上限必须介于 "
                f"{MIN_LOCAL_TURNSTILE_MAX_INFLIGHT} 到 {MAX_LOCAL_TURNSTILE_MAX_INFLIGHT}"
            )
        return max(
            MIN_LOCAL_TURNSTILE_MAX_INFLIGHT,
            min(MAX_LOCAL_TURNSTILE_MAX_INFLIGHT, value),
        )
    return value


@contextmanager
def _local_turnstile_slot(*, max_inflight: Optional[int] = None, log_callback: LogFn = None):
    """Cross-process semaphore for local browser Turnstile captures."""
    limit = int(max_inflight or 0)
    if limit <= 0:
        # env > config.json > default；不再无脑硬压回 2
        limit = resolve_local_turnstile_max_inflight(strict=False)
    limit = max(MIN_LOCAL_TURNSTILE_MAX_INFLIGHT, min(MAX_LOCAL_TURNSTILE_MAX_INFLIGHT, limit))

    slot_dir = _LOCAL_TURNSTILE_SLOT_DIR
    slot_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(slot_dir, 0o700)
    except OSError:
        pass
    gate_path = _LOCAL_TURNSTILE_LOCK_PATH
    gate_path.parent.mkdir(parents=True, exist_ok=True)
    slot_lock: Optional[CrossProcessFileLock] = None
    slot_idx = None
    waited = False
    started_wait = time.monotonic()
    deadline = started_wait + LOCAL_TURNSTILE_LOCK_TIMEOUT_SEC
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CrossProcessLockTimeout(
                    gate_path,
                    LOCAL_TURNSTILE_LOCK_TIMEOUT_SEC,
                )
            try:
                with CrossProcessFileLock(
                    gate_path,
                    timeout=min(1.0, remaining),
                ):
                    for i in range(limit):
                        candidate = CrossProcessFileLock(
                            slot_dir / f"slot-{i}.lock",
                            timeout=0.0,
                        )
                        try:
                            candidate.acquire()
                        except CrossProcessLockTimeout:
                            continue
                        slot_lock = candidate
                        slot_idx = i
                        break
            except CrossProcessLockTimeout:
                # Another worker is scanning the small slot set.  Retry within
                # the overall bounded wait rather than failing on the gate.
                pass
            if slot_lock is not None:
                break
            if not waited:
                waited = True
                _log(
                    log_callback,
                    f"[Turnstile] 本地求解排队中（全局限流 {limit} 路浏览器，避免 4 并发互挤）",
                )
            time.sleep(min(0.35, max(0.01, deadline - time.monotonic())))
        wait_ms = int((time.monotonic() - started_wait) * 1000)
        if waited:
            _log(
                log_callback,
                f"[Turnstile] 获得本地求解槽位 slot={slot_idx}/{limit} wait_ms={wait_ms}",
            )
        yield {"slot": slot_idx, "limit": limit, "wait_ms": wait_ms}
    finally:
        if slot_lock is not None:
            slot_lock.release()


# Cross-process YYDS account-create limiter.

# Multi-worker TUI spawns one process per registration, so a pure threading.Lock
# only serializes within a single process and still bursts the provider.
_YYDS_CREATE_LOCK_PATH = Path(
    os.environ.get("XAI_YYDS_CREATE_LOCK_PATH")
    or (Path(tempfile.gettempdir()) / "xai-yyds-create.lock")
)
_YYDS_CREATE_STATE_PATH = Path(
    os.environ.get("XAI_YYDS_CREATE_STATE_PATH")
    or (Path(tempfile.gettempdir()) / "xai-yyds-create-state.json")
)
_YYDS_DOMAIN_RR_LOCK_PATH = Path(
    os.environ.get("XAI_YYDS_DOMAIN_RR_LOCK_PATH")
    or (Path(tempfile.gettempdir()) / "xai-yyds-domain-rr.lock")
)
_YYDS_DOMAIN_RR_STATE_PATH = Path(
    os.environ.get("XAI_YYDS_DOMAIN_RR_STATE_PATH")
    or (Path(tempfile.gettempdir()) / "xai-yyds-domain-rr-state.json")
)
YYDS_FILE_LOCK_TIMEOUT_SEC = configured_lock_timeout(
    "XAI_YYDS_FILE_LOCK_TIMEOUT_SEC",
    default=120.0,
)


DEFAULT_YYDS_CREATE_SPACING_SEC = 1.5
MIN_YYDS_CREATE_SPACING_SEC = 0.0
MAX_YYDS_CREATE_SPACING_SEC = 60.0


def resolve_yyds_create_spacing_sec(
    config: Optional[Dict[str, Any]] = None,
    *,
    strict: bool = False,
) -> float:
    """Return YYDS account-create spacing seconds.

    Priority:
      1) env XAI_YYDS_CREATE_SPACING_SEC
      2) config.yyds_create_spacing_sec
      3) DEFAULT_YYDS_CREATE_SPACING_SEC (1.5)

    This only paces /accounts create calls. Other YYDS endpoints are unaffected.
    """
    env_raw = str(os.environ.get("XAI_YYDS_CREATE_SPACING_SEC") or "").strip()
    cfg_raw = None
    if isinstance(config, dict) and "yyds_create_spacing_sec" in config:
        cfg_raw = config.get("yyds_create_spacing_sec")
    raw = env_raw if env_raw != "" else ("" if cfg_raw is None else str(cfg_raw).strip())
    if raw == "":
        return DEFAULT_YYDS_CREATE_SPACING_SEC
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        if strict:
            raise ValueError("YYDS 建邮间隔必须是数字（秒）") from exc
        return DEFAULT_YYDS_CREATE_SPACING_SEC
    if not (MIN_YYDS_CREATE_SPACING_SEC <= value <= MAX_YYDS_CREATE_SPACING_SEC):
        if strict:
            raise ValueError(
                "YYDS 建邮间隔必须介于 "
                f"{MIN_YYDS_CREATE_SPACING_SEC} 到 {MAX_YYDS_CREATE_SPACING_SEC} 秒之间"
            )
        return DEFAULT_YYDS_CREATE_SPACING_SEC
    return value


def _yyds_create_spacing_sec(config: Optional[Dict[str, Any]] = None) -> float:
    """Backward-compatible helper used by tests and internal callers."""
    return resolve_yyds_create_spacing_sec(config, strict=False)


@contextmanager
def _yyds_create_file_lock():
    """Exclusive cross-process lock around YYDS create pacing + request."""
    lock_path = _YYDS_CREATE_LOCK_PATH
    with CrossProcessFileLock(
        lock_path,
        timeout=YYDS_FILE_LOCK_TIMEOUT_SEC,
    ) as lock:
        yield lock


def _yyds_read_last_create_at() -> float:
    path = _YYDS_CREATE_STATE_PATH
    try:
        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            return 0.0
        data = json.loads(raw)
        return float(data.get("last_create_at") or 0.0)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return 0.0


def _yyds_write_last_create_at(ts: float) -> None:
    path = _YYDS_CREATE_STATE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"last_create_at": float(ts)}, ensure_ascii=False)
    try:
        atomic_write_private_text(path, payload)
    except OSError:
        # Keep the last complete timestamp rather than publishing a partial
        # fallback file after an interrupted atomic replace.
        pass


def _yyds_wait_create_slot() -> None:
    """Hold the global create lock while sleeping the remaining spacing window.

    Caller must keep the lock until the HTTP create returns, otherwise another
    worker can race through and still burst YYDS.
    """
    # Backward-compatible helper for tests/call sites that only need pacing.
    # Prefer _yyds_create_guard() for the real request path.
    with _yyds_create_file_lock():
        spacing = _yyds_create_spacing_sec()
        now = time.time()
        last = _yyds_read_last_create_at()
        wait = spacing - (now - float(last or 0.0))
        if wait > 0:
            time.sleep(wait)
        _yyds_write_last_create_at(time.time())


@contextmanager
def _yyds_create_guard(*, spacing_sec: Optional[float] = None, config: Optional[Dict[str, Any]] = None):
    """Serialize and pace YYDS /accounts creates across concurrent workers."""
    with _yyds_create_file_lock():
        if spacing_sec is None:
            spacing = resolve_yyds_create_spacing_sec(config, strict=False)
        else:
            try:
                spacing = max(0.0, float(spacing_sec))
            except (TypeError, ValueError):
                spacing = resolve_yyds_create_spacing_sec(config, strict=False)
        now = time.time()
        last = _yyds_read_last_create_at()
        wait = spacing - (now - float(last or 0.0))
        if wait > 0:
            time.sleep(wait)
        # Stamp before the request so a slow/hung create still occupies the slot.
        _yyds_write_last_create_at(time.time())
        yield


DEFAULT_YYDS_API_BASE = "https://maliapi.215.im/v1"


def _yyds_normalize_domain_list(raw: Any) -> List[str]:
    """Accept list/tuple/csv/string and return unique domains preserving order."""
    items: List[str] = []
    if raw is None:
        return items
    if isinstance(raw, (list, tuple, set)):
        seq = [str(x) for x in raw]
    else:
        text_value = str(raw or "").strip()
        if not text_value:
            return items
        seq = []
        for part in text_value.replace("\n", ",").replace(";", ",").split(","):
            part = part.strip()
            if part:
                seq.append(part)
    seen = set()
    for item in seq:
        domain = str(item or "").strip().lower().lstrip("@")
        if not domain or domain in seen:
            continue
        seen.add(domain)
        items.append(domain)
    return items


@contextmanager
def _yyds_domain_rr_lock():
    lock_path = _YYDS_DOMAIN_RR_LOCK_PATH
    with CrossProcessFileLock(
        lock_path,
        timeout=YYDS_FILE_LOCK_TIMEOUT_SEC,
    ) as lock:
        yield lock


def _yyds_read_domain_rr_state() -> Dict[str, Any]:
    path = _YYDS_DOMAIN_RR_STATE_PATH
    try:
        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            return {"index": 0, "rejected": []}
        data = json.loads(raw)
        if not isinstance(data, dict):
            return {"index": 0, "rejected": []}
        rejected = data.get("rejected") if isinstance(data.get("rejected"), list) else []
        return {
            "index": int(data.get("index") or 0),
            "rejected": [str(x).strip().lower() for x in rejected if str(x or "").strip()],
        }
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {"index": 0, "rejected": []}


def _yyds_write_domain_rr_state(*, index: int, rejected: Optional[List[str]] = None) -> None:
    path = _YYDS_DOMAIN_RR_STATE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    rejected_list = []
    seen = set()
    for item in list(rejected or []):
        domain = str(item or "").strip().lower().lstrip("@")
        if not domain or domain in seen:
            continue
        seen.add(domain)
        rejected_list.append(domain)
        if len(rejected_list) >= 500:
            break
    payload = json.dumps(
        {
            "index": int(index),
            "rejected": rejected_list,
            "updated_at": time.time(),
        },
        ensure_ascii=False,
    )
    try:
        atomic_write_private_text(path, payload)
    except OSError:
        # Preserve the previous complete round-robin state.
        pass


def _yyds_read_domain_rr_index() -> int:
    return int(_yyds_read_domain_rr_state().get("index") or 0)


def _yyds_write_domain_rr_index(index: int) -> None:
    state = _yyds_read_domain_rr_state()
    _yyds_write_domain_rr_state(index=index, rejected=list(state.get("rejected") or []))


def _yyds_mark_domain_rejected(domain: str) -> None:
    domain = str(domain or "").strip().lower().lstrip("@")
    if not domain:
        return
    with _yyds_domain_rr_lock():
        state = _yyds_read_domain_rr_state()
        rejected = list(state.get("rejected") or [])
        if domain not in rejected:
            rejected.append(domain)
        _yyds_write_domain_rr_state(index=int(state.get("index") or 0), rejected=rejected)


def _yyds_next_round_robin_domain(domains: List[str], *, exclude: Optional[set] = None) -> str:
    """Pick next domain from list with cross-process round-robin state."""
    cleaned = [str(d or "").strip() for d in domains if str(d or "").strip()]
    if not cleaned:
        raise MailboxError("YYDS 域名池为空")
    blocked = {str(x or "").strip().lower() for x in (exclude or set()) if str(x or "").strip()}
    with _yyds_domain_rr_lock():
        state = _yyds_read_domain_rr_state()
        rejected = set(state.get("rejected") or [])
        blocked |= rejected
        pool = [d for d in cleaned if d.lower() not in blocked] or list(cleaned)
        if len(pool) == 1:
            pick = pool[0]
            # still advance index for stability
            idx = int(state.get("index") or 0)
            if idx < 0:
                idx = 0
            _yyds_write_domain_rr_state(index=idx + 1, rejected=list(state.get("rejected") or []))
            return pick
        idx = int(state.get("index") or 0)
        if idx < 0:
            idx = 0
        pick = pool[idx % len(pool)]
        _yyds_write_domain_rr_state(index=idx + 1, rejected=list(state.get("rejected") or []))
        return pick


class YydsTempMailbox:
    """Adapter for the YYDS temporary-mail HTTP API used by the browser flow."""

    def __init__(self, config: Dict[str, Any], *, proxy: str = "", timeout: int = DEFAULT_TIMEOUT):
        self.config = dict(config or {})
        self.base = str(self.config.get("yyds_api_base") or DEFAULT_YYDS_API_BASE).rstrip("/")
        self.api_key = str(self.config.get("yyds_api_key") or "").strip()
        self.jwt = str(self.config.get("yyds_jwt") or "").strip()
        if not self.api_key and not self.jwt:
            raise MailboxError("YYDS 需要配置 yyds_api_key 或 yyds_jwt")
        self.timeout = max(5, int(timeout or DEFAULT_TIMEOUT))
        self.proxies = _proxy_dict(proxy)
        self.session = requests.Session(impersonate="chrome136")

    def _headers(self, *, content_type: bool = False, bearer: str = "") -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if content_type:
            headers["content-type"] = "application/json"
        token = str(bearer or self.jwt or "").strip()
        if token:
            headers["authorization"] = f"Bearer {token}"
        elif self.api_key:
            headers["x-api-key"] = self.api_key
        return headers

    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        kwargs.setdefault("timeout", self.timeout)
        if self.proxies and "proxies" not in kwargs:
            kwargs["proxies"] = self.proxies
        return getattr(self.session, method.lower())(url, **kwargs)

    def _json_ok(self, response: Any, action: str) -> Dict[str, Any]:
        code = int(getattr(response, "status_code", 0) or 0)
        if not 200 <= code < 300:
            raise MailboxError(f"YYDS {action} HTTP {code}: {_safe_error_text(getattr(response, 'text', ''))}")
        data = _response_json(response)
        if data.get("success") is False:
            raise MailboxError(f"YYDS {action} 失败: {_safe_error_text(data)}")
        payload = data.get("data")
        return payload if isinstance(payload, dict) else data

    def _domains(self) -> List[Dict[str, Any]]:
        response = self._request("get", f"{self.base}/domains", headers=self._headers())
        code = int(getattr(response, "status_code", 0) or 0)
        if not 200 <= code < 300:
            raise MailboxError(f"YYDS domains HTTP {code}: {_safe_error_text(getattr(response, 'text', ''))}")
        data = _response_json(response)
        if data.get("success") is False:
            raise MailboxError(f"YYDS domains 失败: {_safe_error_text(data)}")
        raw = data.get("data")
        if isinstance(raw, list):
            return [item for item in raw if isinstance(item, dict)]
        return []

    def _domain_candidates(self) -> List[str]:
        """Build ordered domain pool, then callers round-robin over it.

        Priority group:
          1) verified private
          2) verified public
          3) verified any
          4) all returned domains
        Optional config.yyds_domains / yyds_domain_whitelist filters the pool.
        """
        rows = self._domains()
        if not rows:
            raise MailboxError("YYDS 没有返回任何可用域名")

        def _names(group: List[Dict[str, Any]]) -> List[str]:
            out: List[str] = []
            seen = set()
            for item in group:
                domain = str(item.get("domain") or "").strip()
                if not domain:
                    continue
                key = domain.lower()
                if key in seen:
                    continue
                seen.add(key)
                out.append(domain)
            return out

        private = [d for d in rows if d.get("isVerified") and not d.get("isPublic")]
        public = [d for d in rows if d.get("isVerified") and d.get("isPublic")]
        verified = [d for d in rows if d.get("isVerified")]
        pool: List[str] = []
        for group in (private, public, verified, rows):
            names = _names(group)
            if names:
                pool = names
                break
        if not pool:
            raise MailboxError("YYDS 无已验证域名可用")

        preferred = _yyds_normalize_domain_list(
            self.config.get("yyds_domains")
            if self.config.get("yyds_domains") is not None
            else self.config.get("yyds_domain_whitelist")
        )
        if preferred:
            allow = set(preferred)
            filtered = [d for d in pool if d.lower() in allow]
            # Keep whitelist order if API order is sparse.
            if filtered:
                # re-order by whitelist order for stable RR
                rank = {name: i for i, name in enumerate(preferred)}
                filtered.sort(key=lambda d: rank.get(d.lower(), 10**9))
                return filtered
            # Whitelist provided but no overlap: fail loudly instead of silently
            # falling back to a single unintended domain.
            raise MailboxError(
                "YYDS 配置的 yyds_domains 与接口返回域名无交集: "
                + ",".join(preferred[:8])
            )
        return pool

    def _pick_domain(self, *, exclude: Optional[set] = None) -> str:
        pool = self._domain_candidates()
        blocked = {str(x or "").strip().lower() for x in (exclude or set()) if str(x or "").strip()}
        if blocked:
            filtered = [d for d in pool if d.lower() not in blocked]
            if filtered:
                pool = filtered
        return _yyds_next_round_robin_domain(pool, exclude=blocked)

    def create(self) -> Tuple[str, str]:
        last_error: Optional[Exception] = None
        used_domains: set = set()
        # YYDS rate-limits account creation aggressively under multi-worker bursts.
        for attempt in range(1, 6):
            domain = self._pick_domain(exclude=used_domains)
            used_domains.add(domain.lower())
            username = "xai" + "".join(
                secrets.choice(string.ascii_lowercase + string.digits) for _ in range(10)
            )
            payload = {
                "address": username,
                "domain": domain,
                "autoDomainStrategy": "prefer_owned",
            }
            with _yyds_create_guard(config=self.config):
                response = self._request(
                    "post",
                    f"{self.base}/accounts",
                    json=payload,
                    headers=self._headers(content_type=True),
                )
            code = int(getattr(response, "status_code", 0) or 0)
            body_text = str(getattr(response, "text", "") or "")
            if code == 429 or "too many account creation requests" in body_text.lower():
                last_error = MailboxError(
                    f"YYDS create HTTP {code or 429}: {_safe_error_text(body_text)}"
                )
                # Exponential-ish backoff for provider-side create limits.
                time.sleep(min(12.0, 1.2 * attempt + (attempt - 1) * 0.8))
                continue
            try:
                data = self._json_ok(response, "create")
            except MailboxError as exc:
                msg = str(exc).lower()
                if "429" in msg or "too many" in msg:
                    last_error = exc
                    time.sleep(min(12.0, 1.2 * attempt + (attempt - 1) * 0.8))
                    continue
                raise
            address = str(data.get("address") or f"{username}@{domain}").strip()
            token = str(data.get("token") or "").strip()
            if not token:
                token_resp = self._request(
                    "post",
                    f"{self.base}/token",
                    json={"address": address},
                    headers=self._headers(content_type=True),
                )
                token = str(self._json_ok(token_resp, "token").get("token") or "").strip()
            if not address or "@" not in address or not token:
                raise MailboxError("YYDS 未返回有效 address/token")
            return address, token
        raise MailboxError(str(last_error or "YYDS create 被限流，请降低并发后重试"))

    def _messages(self, address: str, token: str) -> List[Dict[str, Any]]:
        response = self._request(
            "get",
            f"{self.base}/messages",
            headers=self._headers(bearer=token),
            params={"address": address},
        )
        code = int(getattr(response, "status_code", 0) or 0)
        if not 200 <= code < 300:
            raise MailboxError(f"YYDS messages HTTP {code}")
        data = _response_json(response)
        if data.get("success") is False:
            return []
        payload = data.get("data") if isinstance(data.get("data"), dict) else data
        messages = payload.get("messages") if isinstance(payload, dict) else None
        if isinstance(messages, list):
            return [item for item in messages if isinstance(item, dict)]
        return _pick_list_payload(data)

    def _message_detail(self, message_id: str, token: str) -> Dict[str, Any]:
        response = self._request(
            "get",
            f"{self.base}/messages/{message_id}",
            headers=self._headers(bearer=token),
        )
        code = int(getattr(response, "status_code", 0) or 0)
        if not 200 <= code < 300:
            return {}
        data = _response_json(response)
        payload = data.get("data") if isinstance(data.get("data"), dict) else data
        return payload if isinstance(payload, dict) else {}

    def wait_for_xai_code(
        self,
        email: str,
        token: str,
        *,
        timeout: int = 45,
        poll_interval: int = 2,
        received_after_epoch: float = 0.0,
    ) -> str:
        deadline = time.monotonic() + max(5, int(timeout or 45))
        seen: set = set()
        while time.monotonic() < deadline:
            try:
                messages = self._messages(email, token)
            except Exception:
                time.sleep(max(1, int(poll_interval or 3)))
                continue
            for message in messages:
                message_id = str(message.get("id") or "")
                if not message_id or message_id in seen:
                    continue
                to_addrs = [
                    str(item.get("address") or "").lower()
                    for item in (message.get("to") or [])
                    if isinstance(item, dict)
                ]
                if to_addrs and email.lower() not in to_addrs:
                    continue
                seen.add(message_id)
                detail = self._message_detail(message_id, token)
                subject, body = _flatten_mail_bodies(message, detail)
                code = extract_xai_email_code(body, subject)
                if code:
                    return code
            time.sleep(max(1, int(poll_interval or 3)))
        raise MailboxError(f"在 {timeout}s 内未收到 {mask_email(email)} 的 xAI 验证码")


# Microsoft OAuth profiles used by Outlook mailbox exports.  Thunderbird tokens
# are issued for the Outlook/IMAP resource, while other public clients in the
# four-field format historically used Microsoft Graph Mail.Read.
MS_GRAPH_TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
MS_GRAPH_SCOPE = "https://graph.microsoft.com/Mail.Read offline_access"
MS_GRAPH_MESSAGES_URL = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages"
MS_THUNDERBIRD_CLIENT_ID = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"
MS_IMAP_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
MS_IMAP_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
MS_IMAP_HOST = "outlook.office365.com"
MS_IMAP_PORT = 993
MS_MAIL_POOL_LOCK_TIMEOUT_SEC = configured_lock_timeout(
    "XAI_MS_MAIL_POOL_LOCK_TIMEOUT_SEC",
    default=60.0,
)
_MS_CLIENT_ID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def parse_ms_mail_line(line: str) -> Dict[str, str]:
    """Parse `email----password----client_id----refresh_token` Outlook dumps."""
    raw = str(line or "").strip()
    if not raw or raw.startswith("#"):
        raise MailboxError("空的微软邮箱行")
    parts = raw.split("----")
    if len(parts) < 4:
        raise MailboxError(
            "微软邮箱行格式应为 email----password----client_id----refresh_token "
            f"(当前字段数={len(parts)})"
        )
    email, password, client_id = parts[0].strip(), parts[1].strip(), parts[2].strip()
    refresh_token = "----".join(parts[3:]).strip()
    if "@" not in email or not client_id or not refresh_token:
        raise MailboxError(f"微软邮箱行字段不完整: {mask_email(email)}")
    if not _MS_CLIENT_ID_PATTERN.fullmatch(client_id):
        raise MailboxError("client_id 格式错误（应为 UUID）")
    return {
        "email": email,
        "password": password,
        "client_id": client_id,
        "refresh_token": refresh_token,
        "raw": raw,
    }


def serialize_ms_mail_line(account: Dict[str, str]) -> str:
    return "----".join(
        [
            str(account.get("email") or ""),
            str(account.get("password") or ""),
            str(account.get("client_id") or ""),
            str(account.get("refresh_token") or ""),
        ]
    )


def _atomic_write_utf8_lines(path: Path, lines: Sequence[str]) -> None:
    """Compatibility wrapper for atomic private mailbox/state line writes."""

    atomic_write_private_lines(path, lines)


class MicrosoftGraphMailbox:
    """Claim an Outlook/Hotmail line and poll its matching OAuth mail backend.

    File format (one account per line):
      email----password----client_id----refresh_token

    Field meanings:
      1. mailbox address used for xAI signup
      2. account password (not needed for Graph mail read when refresh token works)
      3. Azure public client_id used when the refresh token was issued
      4. MSA refresh token (usually starts with M.C...) for Graph or IMAP mail read
    """

    def __init__(
        self,
        mail_file: str,
        *,
        proxy: str = "",
        timeout: int = DEFAULT_TIMEOUT,
        mark_used: bool = True,
        lock_timeout: Optional[float] = None,
    ):
        self.path = Path(str(mail_file or "")).expanduser().resolve(strict=False)
        if not self.path.is_file():
            raise MailboxError("微软邮箱文件不存在")
        self.used_path = self.path.with_suffix(self.path.suffix + ".used")
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        ensure_private_file(self.path)
        ensure_private_file(self.used_path)
        self.timeout = max(5, int(timeout or DEFAULT_TIMEOUT))
        self.lock_timeout = (
            MS_MAIL_POOL_LOCK_TIMEOUT_SEC
            if lock_timeout is None
            else max(0.0, float(lock_timeout))
        )
        self.proxies = _proxy_dict(proxy)
        self.mark_used = bool(mark_used)
        self.session = requests.Session(impersonate="chrome136")
        self.account: Dict[str, str] = {}
        self.access_token = ""
        self.access_expires_at = 0.0
        self.mail_backend = "graph"
        self._imap_client: Any = None
        self._imap_access_token = ""
        self._imap_message_cache: Dict[str, Dict[str, Any]] = {}
        self._claimed_for_return = False
        self._claim_committed = False

    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        kwargs.setdefault("timeout", self.timeout)
        if self.proxies and "proxies" not in kwargs:
            kwargs["proxies"] = self.proxies
        return getattr(self.session, method.lower())(url, **kwargs)

    def _claim_account(self) -> Dict[str, str]:
        """Reserve one unique pool record under the durable ``.used`` ledger."""

        try:
            with CrossProcessFileLock(
                self.lock_path,
                timeout=self.lock_timeout,
            ):
                claimed = self._claim_account_locked()
        except CrossProcessLockTimeout as exc:
            raise MailboxPoolLockTimeout("微软邮箱池锁等待超时") from exc
        except MailboxError:
            raise
        except Exception as exc:
            raise MailboxError("微软邮箱池领取事务失败") from exc

        self.account = dict(claimed)
        self._claimed_for_return = bool(self.mark_used)
        self._claim_committed = False
        return claimed

    def _claim_account_locked(self) -> Dict[str, str]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except Exception as exc:
            raise MailboxError("微软邮箱池读取失败") from exc
        try:
            used_lines = (
                self.used_path.read_text(encoding="utf-8").splitlines()
                if self.used_path.is_file()
                else []
            )
        except Exception as exc:
            raise MailboxError("微软邮箱已用记录读取失败") from exc

        used_emails = set()
        for used_line in used_lines:
            try:
                used_emails.add(
                    parse_ms_mail_line(used_line)["email"].strip().lower()
                )
            except MailboxError:
                continue

        remaining: List[str] = []
        claimed: Optional[Dict[str, str]] = None
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                remaining.append(line)
                continue
            try:
                account = parse_ms_mail_line(stripped)
            except MailboxError:
                remaining.append(line)
                continue
            email_key = account["email"].strip().lower()
            if self.mark_used and email_key in used_emails:
                # The durable ledger wins if a previous writer stopped after
                # publishing .used but before removing the source row.
                continue
            if claimed is None:
                claimed = account
                if self.mark_used:
                    used_emails.add(email_key)
                    continue
            remaining.append(line)
        if claimed is None:
            raise MailboxError("微软邮箱文件没有可用账号")
        if self.mark_used:
            # Commit the claim ledger first.  If publishing the source snapshot
            # is interrupted, the next claimant filters the stale source row.
            _atomic_write_utf8_lines(
                self.used_path,
                [*used_lines, serialize_ms_mail_line(claimed)],
            )
            try:
                _atomic_write_utf8_lines(self.path, remaining)
            except OSError:
                # The reservation is already durable and remains unique.  A
                # later claimant will clean the stale source entry.
                pass
        return claimed

    def reserve(self) -> Dict[str, str]:
        """Public reservation operation used by batch/supervisor integrations."""

        return self._claim_account()

    @staticmethod
    def _rewrite_matching_account(
        lines: Sequence[str],
        account: Dict[str, str],
        *,
        append_if_missing: bool,
    ) -> Tuple[List[str], bool]:
        email_key = str(account.get("email") or "").strip().lower()
        rewritten: List[str] = []
        replaced = False
        for line in lines:
            try:
                parsed = parse_ms_mail_line(line)
            except MailboxError:
                rewritten.append(line)
                continue
            if parsed["email"].strip().lower() == email_key:
                if not replaced:
                    rewritten.append(serialize_ms_mail_line(account))
                    replaced = True
                continue
            rewritten.append(line)
        if append_if_missing and not replaced:
            rewritten.append(serialize_ms_mail_line(account))
            replaced = True
        return rewritten, replaced

    def _update_account_record(self, account: Dict[str, str]) -> None:
        """Persist a rotated token in whichever file currently owns the row."""

        try:
            with CrossProcessFileLock(
                self.lock_path,
                timeout=self.lock_timeout,
            ):
                used_lines = (
                    self.used_path.read_text(encoding="utf-8").splitlines()
                    if self.used_path.is_file()
                    else []
                )
                pool_lines = self.path.read_text(encoding="utf-8").splitlines()
                email_key = str(account.get("email") or "").strip().lower()
                owned_by_used = False
                for line in used_lines:
                    try:
                        if parse_ms_mail_line(line)["email"].strip().lower() == email_key:
                            owned_by_used = True
                            break
                    except MailboxError:
                        continue
                if owned_by_used:
                    rewritten, _ = self._rewrite_matching_account(
                        used_lines,
                        account,
                        append_if_missing=True,
                    )
                    _atomic_write_utf8_lines(self.used_path, rewritten)
                else:
                    rewritten, replaced = self._rewrite_matching_account(
                        pool_lines,
                        account,
                        append_if_missing=False,
                    )
                    if not replaced:
                        raise MailboxError("微软邮箱轮换令牌对应记录已不存在")
                    _atomic_write_utf8_lines(self.path, rewritten)
        except CrossProcessLockTimeout as exc:
            raise MailboxPoolLockTimeout("微软邮箱池锁等待超时") from exc
        except MailboxError:
            raise
        except Exception as exc:
            raise MailboxError("微软邮箱轮换令牌持久化失败") from exc

    # Kept as a narrow compatibility hook for the old reference tests.
    def _update_used_account(self, account: Dict[str, str]) -> None:
        self._update_account_record(account)

    @staticmethod
    def _oauth_profile(account: Dict[str, str]) -> Tuple[str, str, str]:
        """Return ``(backend, token_url, scope)`` for an imported token."""

        client_id = str(account.get("client_id") or "").strip().lower()
        if client_id == MS_THUNDERBIRD_CLIENT_ID:
            return "imap", MS_IMAP_TOKEN_URL, MS_IMAP_SCOPE
        return "graph", MS_GRAPH_TOKEN_URL, MS_GRAPH_SCOPE

    def _refresh_access_token(self, account: Dict[str, str]) -> str:
        backend, token_url, scope = self._oauth_profile(account)
        response = self._request(
            "post",
            token_url,
            data={
                "client_id": account["client_id"],
                "grant_type": "refresh_token",
                "refresh_token": account["refresh_token"],
                "scope": scope,
            },
        )
        code = int(getattr(response, "status_code", 0) or 0)
        data = _response_json(response)
        if not 200 <= code < 300:
            raise MailboxError(
                f"微软 refresh_token 换票失败 HTTP {code}: {_safe_error_text(data or getattr(response, 'text', ''))}"
            )
        access = str(data.get("access_token") or "").strip()
        if not access:
            raise MailboxError("微软 token 响应缺少 access_token")
        if backend != self.mail_backend:
            self._close_imap()
        self.mail_backend = backend
        new_refresh = str(data.get("refresh_token") or "").strip()
        if new_refresh and new_refresh != account.get("refresh_token"):
            account["refresh_token"] = new_refresh
            self._update_account_record(account)
        expires_in = int(data.get("expires_in") or 3600)
        self.access_token = access
        self.access_expires_at = time.monotonic() + max(60, expires_in - 60)
        return access

    def create(self) -> Tuple[str, str]:
        # Skip dead refresh tokens instead of aborting the whole pool on first miss.
        last_error: Optional[Exception] = None
        for _ in range(32):
            try:
                self.account = self._claim_account()
            except MailboxError as exc:
                if last_error is not None:
                    raise MailboxError(
                        f"微软邮箱池无可用账号；最后换票错误: {_safe_error_text(last_error)}"
                    ) from last_error
                raise
            try:
                token = self._refresh_access_token(self.account)
                return self.account["email"], token
            except MailboxError as exc:
                last_error = exc
                if not self.mark_used:
                    # A non-consuming probe always sees the same first source
                    # row, so advancing would repeat the same failed request.
                    self.account = {}
                    raise
                print(
                    f"[HTTP][warn] 微软邮箱换票失败，跳过 {mask_email(self.account.get('email', ''))}: "
                    f"{_safe_error_text(exc)}",
                    flush=True,
                )
                # This record produced a mailbox-specific token failure and is
                # intentionally retained in the used ledger.
                self.commit_success()
                self.account = {}
                continue
        raise MailboxError(f"微软邮箱池连续换票失败: {_safe_error_text(last_error)}")

    def release_to_pool(self, *, reason: str = "") -> bool:
        """Return the current uncommitted reservation exactly once."""

        del reason  # Failure categories are intentionally not persisted here.
        self._close_imap()
        if (
            not self.mark_used
            or not self._claimed_for_return
            or self._claim_committed
            or not self.account
        ):
            return False
        account = dict(self.account)
        email_key = str(account.get("email") or "").strip().lower()
        try:
            with CrossProcessFileLock(
                self.lock_path,
                timeout=self.lock_timeout,
            ):
                pool_lines = self.path.read_text(encoding="utf-8").splitlines()
                used_lines = (
                    self.used_path.read_text(encoding="utf-8").splitlines()
                    if self.used_path.is_file()
                    else []
                )
                authoritative = account
                kept_used: List[str] = []
                found_used = False
                for line in used_lines:
                    try:
                        parsed = parse_ms_mail_line(line)
                    except MailboxError:
                        kept_used.append(line)
                        continue
                    if parsed["email"].strip().lower() == email_key:
                        if not found_used:
                            authoritative = parsed
                            found_used = True
                        continue
                    kept_used.append(line)

                # Deduplicate a prior partially completed release, then publish
                # the available row before removing the authoritative ledger.
                kept_pool: List[str] = []
                for line in pool_lines:
                    try:
                        parsed = parse_ms_mail_line(line)
                    except MailboxError:
                        kept_pool.append(line)
                        continue
                    if parsed["email"].strip().lower() == email_key:
                        continue
                    kept_pool.append(line)
                _atomic_write_utf8_lines(
                    self.path,
                    [serialize_ms_mail_line(authoritative), *kept_pool],
                )
                _atomic_write_utf8_lines(self.used_path, kept_used)
        except CrossProcessLockTimeout as exc:
            raise MailboxPoolLockTimeout("微软邮箱池锁等待超时") from exc
        except MailboxError:
            raise
        except Exception as exc:
            raise MailboxError("微软邮箱池归还事务失败") from exc
        self.account = authoritative
        self._claimed_for_return = False
        return True

    def release(self, *, reason: str = "") -> bool:
        """Alias for supervisor lifecycle integrations."""

        return self.release_to_pool(reason=reason)

    def commit_success(self) -> bool:
        """Mark the current reservation consumed so later release is a no-op."""

        self._close_imap()
        if not self._claimed_for_return or self._claim_committed:
            return False
        self._claim_committed = True
        self._claimed_for_return = False
        return True

    def _ensure_access_token(self, token: str = "") -> str:
        if self.access_token and time.monotonic() < self.access_expires_at:
            return self.access_token
        if self.account:
            return self._refresh_access_token(self.account)
        token = str(token or "").strip()
        if token:
            self.access_token = token
            self.access_expires_at = time.monotonic() + 600
            return token
        raise MailboxError("Microsoft OAuth 访问令牌不可用")

    def _close_imap(self) -> None:
        client = self._imap_client
        self._imap_client = None
        self._imap_access_token = ""
        self._imap_message_cache = {}
        if client is None:
            return
        try:
            client.logout()
        except Exception:
            try:
                client.shutdown()
            except Exception:
                pass

    @staticmethod
    def _imap_auth_payload(email: str, access_token: str) -> bytes:
        return (
            f"user={str(email or '').strip()}\x01"
            f"auth=Bearer {str(access_token or '').strip()}\x01\x01"
        ).encode("utf-8")

    def _open_imap(self, access_token: str) -> Any:
        if not self.account:
            raise MailboxError("IMAP 邮箱账号未绑定")
        client = imaplib.IMAP4_SSL(
            MS_IMAP_HOST,
            MS_IMAP_PORT,
            timeout=self.timeout,
        )
        try:
            payload = self._imap_auth_payload(self.account.get("email", ""), access_token)
            status, _ = client.authenticate("XOAUTH2", lambda _challenge: payload)
            if str(status or "").upper() != "OK":
                raise imaplib.IMAP4.error("XOAUTH2 rejected")
            status, _ = client.select("INBOX", readonly=True)
            if str(status or "").upper() != "OK":
                raise imaplib.IMAP4.error("INBOX select rejected")
        except Exception:
            try:
                client.logout()
            except Exception:
                try:
                    client.shutdown()
                except Exception:
                    pass
            raise
        self._imap_client = client
        self._imap_access_token = access_token
        return client

    def _ensure_imap(self, access_token: str, *, refresh_on_auth_error: bool = True) -> Any:
        if self._imap_client is not None and self._imap_access_token == access_token:
            return self._imap_client
        self._close_imap()
        try:
            return self._open_imap(access_token)
        except imaplib.IMAP4.error as exc:
            if refresh_on_auth_error and self.account:
                refreshed = self._refresh_access_token(self.account)
                try:
                    return self._open_imap(refreshed)
                except Exception as retry_exc:
                    raise MailboxError("Outlook IMAP XOAUTH2 登录失败") from retry_exc
            raise MailboxError("Outlook IMAP XOAUTH2 登录失败") from exc
        except Exception as exc:
            raise MailboxError("Outlook IMAP 连接失败") from exc

    @staticmethod
    def _imap_raw_message(payload: Any) -> bytes:
        if not isinstance(payload, (list, tuple)):
            return b""
        for item in payload:
            if isinstance(item, tuple):
                for value in reversed(item):
                    if isinstance(value, bytes) and value:
                        return value
        return b""

    @staticmethod
    def _imap_message(uid: bytes, raw: bytes) -> Dict[str, Any]:
        parsed = BytesParser(policy=email_policy.default).parsebytes(raw)
        subject = str(parsed.get("subject") or "")
        sender = parseaddr(str(parsed.get("from") or ""))[1]
        received = ""
        try:
            from datetime import timezone

            received_dt = parsedate_to_datetime(str(parsed.get("date") or ""))
            if received_dt is not None:
                if received_dt.tzinfo is None:
                    received_dt = received_dt.replace(tzinfo=timezone.utc)
                received = received_dt.astimezone(timezone.utc).isoformat()
        except Exception:
            received = ""

        bodies: List[str] = []
        parts = parsed.walk() if parsed.is_multipart() else (parsed,)
        for part in parts:
            if part.is_multipart():
                continue
            if str(part.get_content_disposition() or "").lower() == "attachment":
                continue
            if part.get_content_type() not in {"text/plain", "text/html"}:
                continue
            try:
                value = part.get_content()
            except Exception:
                payload_bytes = part.get_payload(decode=True) or b""
                value = payload_bytes.decode(part.get_content_charset() or "utf-8", errors="replace")
            if isinstance(value, str) and value.strip():
                if part.get_content_type() == "text/html":
                    value = re.sub(r"<[^>]+>", " ", value)
                bodies.append(value)
        body = "\n".join(bodies)
        message_id = f"imap:{uid.decode('ascii', errors='ignore')}"
        return {
            "id": message_id,
            "subject": subject,
            "bodyPreview": body[:4096],
            "body": {"contentType": "text", "content": body},
            "receivedDateTime": received,
            "from": {"emailAddress": {"address": sender}},
        }

    def _imap_messages_once(self, access_token: str) -> List[Dict[str, Any]]:
        client = self._ensure_imap(access_token)
        status, data = client.uid("search", None, "ALL")
        if str(status or "").upper() != "OK":
            raise MailboxError("Outlook IMAP SEARCH 失败")
        raw_ids = data[0] if isinstance(data, (list, tuple)) and data else b""
        uids = raw_ids.split()[-15:] if isinstance(raw_ids, bytes) else []
        messages: List[Dict[str, Any]] = []
        cache: Dict[str, Dict[str, Any]] = {}
        for uid in reversed(uids):
            status, payload = client.uid("fetch", uid, "(BODY.PEEK[])")
            if str(status or "").upper() != "OK":
                continue
            raw = self._imap_raw_message(payload)
            if not raw:
                continue
            message = self._imap_message(uid, raw)
            messages.append(message)
            cache[str(message.get("id") or "")] = message
        self._imap_message_cache = cache
        return messages

    def _imap_messages(self, token: str) -> List[Dict[str, Any]]:
        access = self._ensure_access_token(token)
        try:
            return self._imap_messages_once(access)
        except (imaplib.IMAP4.abort, OSError) as exc:
            self._close_imap()
            try:
                return self._imap_messages_once(access)
            except Exception as retry_exc:
                raise MailboxError("Outlook IMAP 收件箱读取失败") from retry_exc
        except MailboxError:
            raise
        except Exception as exc:
            raise MailboxError("Outlook IMAP 收件箱读取失败") from exc

    def _messages(self, token: str) -> List[Dict[str, Any]]:
        if self.mail_backend == "imap":
            return self._imap_messages(token)
        access = self._ensure_access_token(token)
        response = self._request(
            "get",
            MS_GRAPH_MESSAGES_URL,
            headers={"authorization": f"Bearer {access}"},
            params={
                "$top": "15",
                "$orderby": "receivedDateTime desc",
                "$select": "id,subject,bodyPreview,receivedDateTime,from",
            },
        )
        code = int(getattr(response, "status_code", 0) or 0)
        if code == 401 and self.account:
            access = self._refresh_access_token(self.account)
            response = self._request(
                "get",
                MS_GRAPH_MESSAGES_URL,
                headers={"authorization": f"Bearer {access}"},
                params={
                    "$top": "15",
                    "$orderby": "receivedDateTime desc",
                    "$select": "id,subject,bodyPreview,receivedDateTime,from",
                },
            )
            code = int(getattr(response, "status_code", 0) or 0)
        if not 200 <= code < 300:
            raise MailboxError(f"Graph inbox HTTP {code}: {_safe_error_text(getattr(response, 'text', ''))}")
        data = _response_json(response)
        values = data.get("value") if isinstance(data, dict) else None
        if isinstance(values, list):
            return [item for item in values if isinstance(item, dict)]
        return []

    def _message_detail(self, message_id: str, token: str) -> Dict[str, Any]:
        if self.mail_backend == "imap":
            return dict(self._imap_message_cache.get(str(message_id or ""), {}))
        access = self._ensure_access_token(token)
        response = self._request(
            "get",
            f"https://graph.microsoft.com/v1.0/me/messages/{message_id}",
            headers={"authorization": f"Bearer {access}"},
            params={"$select": "id,subject,body,bodyPreview"},
        )
        code = int(getattr(response, "status_code", 0) or 0)
        if not 200 <= code < 300:
            return {}
        data = _response_json(response)
        return data if isinstance(data, dict) else {}

    def wait_for_xai_code(
        self,
        email: str,
        token: str,
        *,
        timeout: int = 45,
        poll_interval: int = 2,
        received_after_epoch: float = 0.0,
    ) -> str:
        deadline = time.monotonic() + max(5, int(timeout or 45))
        seen: set = set()
        # Graph timestamps are UTC; allow a small clock skew window.
        min_received = float(received_after_epoch or 0.0) - 5.0
        while time.monotonic() < deadline:
            try:
                messages = self._messages(token)
            except Exception:
                time.sleep(max(1, int(poll_interval or 3)))
                continue
            for message in messages:
                message_id = str(message.get("id") or "")
                if not message_id or message_id in seen:
                    continue
                subject_hint = str(message.get("subject") or "")
                preview_hint = str(message.get("bodyPreview") or "")
                from_obj = message.get("from") if isinstance(message.get("from"), dict) else {}
                sender = ""
                try:
                    sender = str(
                        ((from_obj.get("emailAddress") or {}).get("address"))
                        or from_obj.get("address")
                        or ""
                    )
                except Exception:
                    sender = ""
                # Skip obvious non-xAI mails before fetching full bodies.
                if not _looks_like_xai_mail(subject_hint, preview_hint, sender):
                    continue
                if min_received > 0:
                    received_raw = str(message.get("receivedDateTime") or "")
                    try:
                        from datetime import datetime, timezone

                        received_ts = datetime.strptime(
                            received_raw[:19], "%Y-%m-%dT%H:%M:%S"
                        ).replace(tzinfo=timezone.utc).timestamp()
                    except Exception:
                        received_ts = 0.0
                    if received_ts and received_ts < min_received:
                        seen.add(message_id)
                        continue
                seen.add(message_id)
                detail = self._message_detail(message_id, token)
                subject, body = _flatten_mail_bodies(message, detail)
                code = extract_xai_email_code(body, subject, sender=sender)
                if code:
                    return code
            time.sleep(max(1, int(poll_interval or 3)))
        raise MailboxError(f"在 {timeout}s 内未收到 {mask_email(email)} 的 xAI 验证码")


MailboxAdapter = Any


def build_mailbox(
    *,
    config: Optional[Dict[str, Any]] = None,
    mail_file: str = "",
    proxy: str = "",
    timeout: int = DEFAULT_TIMEOUT,
) -> MailboxAdapter:
    """Build a mailbox adapter from provider config and/or an Outlook dump file."""
    mail_file = str(mail_file or "").strip()
    if mail_file:
        return MicrosoftGraphMailbox(mail_file, proxy=proxy, timeout=timeout)
    config = dict(config or {})
    provider = str(config.get("email_provider") or "cloudflare").strip().lower()
    if provider in {"msgraph", "microsoft", "hotmail", "outlook"}:
        path = str(config.get("ms_mail_file") or config.get("mail_file") or "").strip()
        if not path:
            raise MailboxError("email_provider=msgraph 时需要 config.ms_mail_file 或 --mail-file")
        return MicrosoftGraphMailbox(path, proxy=proxy, timeout=timeout)
    if provider == "yyds":
        return YydsTempMailbox(config, proxy=proxy, timeout=timeout)
    if provider in {"cloudflare", "cf", "cloudflare_temp_email"}:
        return CloudflareTempMailbox(config, proxy=proxy, timeout=timeout)
    raise MailboxError(
        f"不支持的 email_provider={provider!r}；可选 cloudflare / yyds / msgraph，"
        "或直接传 --mail-file / --email + --email-code"
    )


def default_profile() -> Tuple[str, str, str]:
    given = random.choice(["Alex", "Jordan", "Taylor", "Casey", "Morgan", "Riley"])
    family = random.choice(["Lee", "Wang", "Chen", "Lin", "Smith", "Taylor"])
    password = "N" + secrets.token_hex(6) + "!a7#" + secrets.token_urlsafe(6)
    return given, family, password


def save_sso_record(
    output_dir: str,
    *,
    email: str = "",
    sso: str,
    subject: str = "",
) -> str:
    """Save one SSO cookie file next to OAuth credentials.

    Default naming matches credential files:
      credential: xai-{email}.json
      sso file  : xai-{email}.sso
    """
    output_dir = str(output_dir or "").strip()
    sso = str(sso or "").strip()
    if not output_dir or not sso:
        return ""
    if "\n" in sso or "\r" in sso:
        raise XAIHttpFlowError("SSO 输出字段无效")
    try:
        from sso_to_auth_json import sso_file_name, write_sso_file
    except Exception:
        def _sanitize(value: str) -> str:
            value = str(value or "").strip()
            out = []
            for ch in value:
                if ch.isalnum() or ch in "@._-":
                    out.append(ch)
                else:
                    out.append("-")
            return "".join(out).strip("-")

        def sso_file_name(email: str = "", subject: str = "") -> str:  # type: ignore
            email = _sanitize(email)
            if email:
                return f"xai-{email}.sso"
            subject = _sanitize(subject)
            if subject:
                return f"xai-{subject}.sso"
            return f"xai-{int(time.time() * 1000)}.sso"

        def write_sso_file(path, value: str):  # type: ignore
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(str(value).strip() + "\n", encoding="utf-8")
            try:
                if os.name != "nt":
                    os.chmod(path, 0o600)
            except OSError:
                pass
            return path

    target = Path(output_dir).expanduser().resolve() / sso_file_name(email, subject)
    write_sso_file(target, sso)
    return str(target)


def save_account_record(path: str, *, email: str, password: str, sso: str) -> str:
    """Append the legacy-compatible `email----password----sso` account row."""
    path = str(path or "").strip()
    if not path:
        return ""
    values = (str(email or ""), str(password or ""), str(sso or ""))
    if not all(values) or any("\n" in value or "\r" in value for value in values):
        raise XAIHttpFlowError("账号输出字段无效")
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write("----".join(values) + "\n")
    try:
        if os.name != "nt":
            os.chmod(target, 0o600)
    except OSError:
        pass
    return str(target)


class _MailboxReservationLifecycle:
    """Own one mailbox reservation across a complete registration attempt."""

    def __init__(self) -> None:
        self.mailbox: Optional[MailboxAdapter] = None

    def bind(self, mailbox: Optional[MailboxAdapter]) -> None:
        self.mailbox = mailbox

    def release(self, reason: str) -> bool:
        mailbox = self.mailbox
        release = getattr(mailbox, "release", None)
        if not callable(release):
            release = getattr(mailbox, "release_to_pool", None)
        if not callable(release):
            return False
        return bool(release(reason=str(reason or "registration_failed")))

    def commit(self) -> bool:
        commit = getattr(self.mailbox, "commit_success", None)
        if not callable(commit):
            return False
        return bool(commit())


def _run_registration_impl(
    *,
    client: BrowserlessXAIClient,
    email: str = "",
    email_code: str = "",
    mail_config_path: str = "",
    mail_file: str = "",
    castle_email_token: str = "",
    castle_register_token: str = "",
    turnstile_token: str = "",
    turnstile_provider: str = "",
    turnstile_api_key: str = "",
    turnstile_solve_timeout: int = 60,
    turnstile_solve_retries: int = 1,
    turnstile_proxy: str = "",
    turnstile_headless: bool = False,
    turnstile_broker_url: str = "",
    turnstile_workers: int = 0,
    turnstile_queue_size: int = 64,
    submit_workers: int = 4,
    given_name: str = "",
    family_name: str = "",
    password: str = "",
    output_dir: str = "",
    accounts_output: str = "",
    _mailbox_lifecycle: Optional[_MailboxReservationLifecycle] = None,
) -> RegistrationResult:
    lifecycle = _mailbox_lifecycle or _MailboxReservationLifecycle()
    mailbox: Optional[MailboxAdapter] = None
    mail_token = ""
    config: Dict[str, Any] = {}
    if mail_config_path:
        try:
            config = json.loads(Path(mail_config_path).read_text(encoding="utf-8"))
        except Exception as exc:
            raise MailboxError(f"无法读取邮箱配置: {exc}") from exc
    if not email:
        if not mail_config_path and not mail_file:
            raise XAIHttpFlowError(
                "注册必须提供 --email，或 --mail-config / --mail-file 自动取邮箱并轮询验证码"
            )
        mailbox = build_mailbox(
            config=config,
            mail_file=mail_file,
            proxy=client.proxy,
            timeout=client.timeout,
        )
        lifecycle.bind(mailbox)
        email, mail_token = mailbox.create()
        provider = "mail-file" if mail_file else str(config.get("email_provider") or "cloudflare")
        _log(client.log_callback, f"[HTTP] 已就绪邮箱 provider={provider} | email={mask_email(email)}")
    elif not email_code and (mail_config_path or mail_file):
        # Explicit email plus mailbox credentials/file for OTP polling.
        if mail_file:
            mailbox = MicrosoftGraphMailbox(mail_file, proxy=client.proxy, timeout=client.timeout, mark_used=False)
            lifecycle.bind(mailbox)
            # Bind to provided email if the file contains it; otherwise claim is not used.
            # For explicit email mode with Graph, require matching line kept in file.
            try:
                lines = Path(mail_file).read_text(encoding="utf-8").splitlines()
            except Exception as exc:
                raise MailboxError(f"无法读取 --mail-file: {exc}") from exc
            matched = None
            for line in lines:
                try:
                    parsed = parse_ms_mail_line(line)
                except MailboxError:
                    continue
                if parsed["email"].lower() == email.lower():
                    matched = parsed
                    break
            if matched is None:
                raise MailboxError(f"--mail-file 中找不到邮箱 {mask_email(email)}")
            mailbox.account = matched
            mail_token = mailbox._refresh_access_token(matched)
        else:
            # For API providers, create() would mint a new address; only Graph file
            # supports binding an existing address here.
            raise MailboxError("指定 --email 自动收码时请使用 --mail-file（Outlook 四段格式）或直接传 --email-code")
    if not given_name or not family_name or not password:
        auto_given, auto_family, auto_password = default_profile()
        given_name = given_name or auto_given
        family_name = family_name or auto_family
        password = password or auto_password
    metadata = client.open_signup()
    if not email_code:
        # Auto-mailbox mode: if xAI rejects the domain, mint another address and retry.
        max_domain_tries = 5 if mailbox is not None else 1
        last_domain_error: Optional[Exception] = None
        for domain_try in range(1, max_domain_tries + 1):
            requested_at = time.time()
            try:
                client.request_email_validation_code(email, castle_email_token)
                last_domain_error = None
                break
            except Exception as exc:
                last_domain_error = exc
                if mailbox is None or not is_email_domain_rejected_error(exc):
                    raise
                rejected_domain = ""
                if "@" in str(email):
                    rejected_domain = str(email).split("@", 1)[1].strip().lower()
                if rejected_domain:
                    try:
                        _yyds_mark_domain_rejected(rejected_domain)
                    except Exception:
                        pass
                _log(
                    client.log_callback,
                    (
                        f"[HTTP][warn] xAI 拒绝邮箱域名，自动换号重试 "
                        f"{domain_try}/{max_domain_tries} | email={mask_email(email)} "
                        f"domain={rejected_domain or '-'}"
                    ),
                )
                if domain_try >= max_domain_tries:
                    break
                # Mint a new temporary mailbox address and continue.
                lifecycle.release("domain_rejected")
                email, mail_token = mailbox.create()
                provider = "mail-file" if mail_file else str(config.get("email_provider") or "cloudflare")
                _log(
                    client.log_callback,
                    f"[HTTP] 已换号重建邮箱 provider={provider} | email={mask_email(email)}",
                )
                # Refresh signup session so cookies/challenge stay coherent.
                metadata = client.open_signup()
        if last_domain_error is not None:
            raise last_domain_error
        if mailbox is None:
            raise XAIHttpFlowError(
                "验证码已发送；请用 --email-code 重新运行提交注册，或配置 --mail-config/--mail-file 自动轮询"
            )
        # Keep mail wait short so dead mailboxes don't occupy concurrency slots.
        mail_wait = max(15, min(120, int(getattr(client, "timeout", 30) or 30) * 2 if int(getattr(client, "timeout", 30) or 30) < 40 else int(getattr(client, "timeout", 45) or 45)))
        # Prefer explicit config/env when present.
        try:
            cfg_wait = int(float((config or {}).get("mail_code_timeout_sec") or 0))
            if cfg_wait > 0:
                mail_wait = max(10, min(180, cfg_wait))
        except Exception:
            pass
        try:
            email_code = mailbox.wait_for_xai_code(
                email,
                mail_token,
                timeout=mail_wait,
                received_after_epoch=requested_at,
            )
        except TypeError:
            # Older/other mailbox adapters may not accept the freshness kwarg.
            try:
                email_code = mailbox.wait_for_xai_code(email, mail_token, timeout=mail_wait)
            except TypeError:
                email_code = mailbox.wait_for_xai_code(email, mail_token)
        _log(
            client.log_callback,
            f"[HTTP] 已收到 xAI 邮箱验证码 | email={mask_email(email)} code={str(email_code)[:3]}***",
        )
    # Browser flow always verifies the OTP via gRPC before the Server Action submit.
    email_code = client.verify_email_validation_code(email, email_code)
    turnstile_token = str(turnstile_token or "").strip()
    solve_result: Optional[SolveResult] = None
    effective_broker_url = str(
        turnstile_broker_url or config.get("turnstile_broker_url") or ""
    ).strip()
    if not turnstile_token:
        turnstile_metadata = metadata
        sitekey = str(turnstile_metadata.get("turnstile_sitekey") or "").strip()
        if not sitekey:
            # Re-parse page HTML in case open_signup metadata was sparse.
            turnstile_metadata = client.challenge_metadata(client.signup_page_html)
            sitekey = str(turnstile_metadata.get("turnstile_sitekey") or "").strip()
        provider = str(turnstile_provider or config.get("turnstile_provider") or "").strip()
        api_key = str(turnstile_api_key or config.get("turnstile_api_key") or "").strip()
        # For providers which support a caller proxy, prefer the real upstream.
        # CapSolver's documented Turnstile task remains proxyless in the solver.
        solve_proxy = str(turnstile_proxy or client.proxy or "").strip()
        if turnstile_headless:
            use_headless = True
        else:
            raw_headless = config.get("turnstile_headless", False)
            if isinstance(raw_headless, bool):
                use_headless = raw_headless
            else:
                use_headless = str(raw_headless or "").strip().lower() in {"1", "true", "yes", "on"}
        max_attempts = max(1, int(turnstile_solve_retries or 1))
        per_try_timeout = max(5, int(turnstile_solve_timeout or 90))
        last_exc: Optional[Exception] = None
        solve_result = None
        for attempt in range(1, max_attempts + 1):
            _log(
                client.log_callback,
                (
                    f"[HTTP] 请求 Turnstile 求解 | provider={provider or 'local'} "
                    f"headless={use_headless} broker={'yes' if effective_broker_url else 'no'} "
                    f"sitekey={(sitekey[:12] + '…') if sitekey else '-'} "
                    f"timeout={per_try_timeout}s attempt={attempt}/{max_attempts}"
                ),
            )
            solve_started = time.monotonic()
            try:
                solve_result = solve_turnstile_result(
                    sitekey=sitekey,
                    page_url=client.signup_page_url or SIGNUP_URL,
                    provider=provider,
                    api_key=api_key,
                    proxy=solve_proxy,
                    action=str(turnstile_metadata.get("turnstile_action") or ""),
                    cdata=str(turnstile_metadata.get("turnstile_cdata") or ""),
                    timeout=per_try_timeout,
                    headless=use_headless,
                    fingerprint=client.fingerprint,
                    broker_url=effective_broker_url,
                    workers=int(turnstile_workers or config.get("turnstile_workers") or 0),
                    queue_size=int(turnstile_queue_size or config.get("turnstile_queue_size") or 64),
                )
                elapsed_ms = int((time.monotonic() - solve_started) * 1000)
                token_len = len(str(getattr(solve_result, "token", "") or "").strip())
                extras = getattr(solve_result, "extras", None)
                lease_id = ""
                reported_token_length = 0
                if isinstance(extras, dict):
                    lease_id = str(extras.get("lease_id") or "").strip()
                    try:
                        reported_token_length = int(
                            extras.get("token_length")
                            or extras.get("token_len")
                            or 0
                        )
                    except (TypeError, ValueError):
                        reported_token_length = 0
                # Local broker keeps the real token behind a lease; empty body token
                # with a verified server-reported length is consumed later.
                lease_ok = bool(lease_id) and reported_token_length >= 80
                _log(
                    client.log_callback,
                    (
                        f"[HTTP] Turnstile 求解返回 | elapsed_ms={elapsed_ms} "
                        f"token_len={token_len} reported_len={reported_token_length} "
                        f"lease={'yes' if lease_id else 'no'} "
                        f"attempt={attempt}/{max_attempts}"
                    ),
                )
                if token_len >= 80 or lease_ok:
                    last_exc = None
                    break
                last_exc = VerificationRequiredError(
                    f"Turnstile 返回空 token (len={token_len}, reported_len={reported_token_length}, "
                    f"lease={'yes' if lease_id else 'no'})"
                )
                _log(
                    client.log_callback,
                    f"[HTTP][warn] Turnstile 空 token，准备重试 | attempt={attempt}/{max_attempts}",
                )
            except Exception as exc:
                elapsed_ms = int((time.monotonic() - solve_started) * 1000)
                last_exc = exc
                _log(
                    client.log_callback,
                    (
                        f"[HTTP][error] Turnstile 求解失败 | elapsed_ms={elapsed_ms} "
                        f"attempt={attempt}/{max_attempts} err={_safe_error_text(exc)}"
                    ),
                )
                if attempt >= max_attempts:
                    raise
                continue
            if attempt >= max_attempts and last_exc is not None:
                raise last_exc
        if solve_result is None:
            if last_exc is not None:
                raise last_exc
            raise VerificationRequiredError("Turnstile 求解失败：无结果")
    if solve_result is None:
        solve_result = SolveResult(
            token=turnstile_token,
            provider="provided",
            received_at=time.monotonic(),
            elapsed_ms=0,
            user_agent=client.user_agent,
            user_agent_authoritative=False,
            proxy=client.proxy,
        )
    lease = TokenLease(solve_result, ttl_sec=240.0)
    with _submit_permit(
        broker_url=effective_broker_url,
        submit_workers=submit_workers,
        timeout_sec=turnstile_solve_timeout,
        fingerprint=client.fingerprint,
        log_callback=client.log_callback,
    ):
        try:
            turnstile_token = lease.consume()
        except TokenLeaseError as exc:
            raise VerificationRequiredError(str(exc)) from exc
        turnstile_token = _consume_remote_turnstile_lease(
            solve_result,
            fingerprint=client.fingerprint,
        )
        _log(
            client.log_callback,
            f"[HTTP] Turnstile lease 已消费 | age_ms={int(lease.age() * 1000)}",
        )
        sso = client.submit_registration(
            email=email,
            email_validation_code=email_code,
            given_name=given_name,
            family_name=family_name,
            password=password,
            turnstile_token=turnstile_token,
            castle_request_token=castle_register_token,
        )
    # Once xAI accepted the registration, the imported mailbox must remain
    # consumed even if a later local artifact/OAuth write fails.
    lifecycle.commit()
    credential_path = ""
    sso_path = ""
    if output_dir:
        sso_path = save_sso_record(output_dir, email=email, sso=sso)
        if sso_path:
            _log(client.log_callback, f"[HTTP] SSO 已单独保存 | email={mask_email(email)} | {sso_path}")
        credential_path = client.obtain_oauth_credential(output_dir=output_dir, email_hint=email)
    account_path = save_account_record(
        accounts_output,
        email=email,
        password=password,
        sso=sso,
    )
    return RegistrationResult(
        email=email,
        password=password,
        sso=sso,
        credential_path=credential_path,
        account_path=account_path,
        sso_path=sso_path,
    )


@functools.wraps(_run_registration_impl)
def run_registration(*args: Any, **kwargs: Any) -> RegistrationResult:
    """Run registration and return an uncommitted Graph row on failure."""

    lifecycle = _MailboxReservationLifecycle()
    kwargs["_mailbox_lifecycle"] = lifecycle
    try:
        result = _run_registration_impl(*args, **kwargs)
    except BaseException:
        try:
            lifecycle.release("registration_failed")
        except Exception:
            # Preserve the primary flow failure.  A lock/write error leaves the
            # row in the authoritative .used ledger for deterministic restart.
            pass
        raise
    lifecycle.commit()
    return result


def _add_proxy_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--proxy", default="", help="直连 HTTP/SOCKS 代理 URL，或 host:port:user:password")
    parser.add_argument("--proxy-file", default="", help="代理池文件；每行一个代理")
    parser.add_argument("--proxy-random", action="store_true", help="从代理池随机选择一条")
    parser.add_argument("--proxy-index", type=int, default=0, help="代理池固定索引（默认 0）")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)


def _add_token_options(parser: argparse.ArgumentParser, *, registration: bool = False) -> None:
    parser.add_argument("--turnstile-token", default="", help="本会话新鲜 Turnstile token")
    parser.add_argument("--turnstile-token-file", default="", help="包含 Turnstile token 的 UTF-8 文件")
    parser.add_argument(
        "--turnstile-provider",
        default="",
        help="Turnstile 求解服务：capsolver | 2captcha | yescaptcha | local（无 token 时使用；local=本机 Chrome 捕获）",
    )
    parser.add_argument(
        "--turnstile-headless",
        action="store_true",
        help="local 浏览器求解时使用无头模式（成功率通常更低）",
    )
    parser.add_argument(
        "--turnstile-api-key",
        default="",
        help=(
            "Turnstile 求解服务 API key；也可用环境变量 XAI_TURNSTILE_API_KEY / "
            "CAPSOLVER_API_KEY / TWOCAPTCHA_API_KEY / YESCAPTCHA_API_KEY"
        ),
    )
    parser.add_argument(
        "--turnstile-solve-timeout",
        type=int,
        default=90,
        help="单次 Turnstile 求解等待秒数（默认 90）",
    )
    parser.add_argument(
        "--turnstile-solve-retries",
        type=int,
        default=1,
        help="Turnstile 求解失败重试次数（默认 1，含首次）",
    )
    parser.add_argument(
        "--turnstile-proxy",
        default="",
        help="Turnstile 求解专用代理（优先于注册出口代理；空=回退注册代理）",
    )
    parser.add_argument("--turnstile-broker-url", default="", help="共享 Turnstile broker 地址")
    parser.add_argument("--turnstile-workers", type=int, default=0, help="独立 Turnstile 并发槽")
    parser.add_argument("--turnstile-queue-size", type=int, default=64, help="Turnstile broker 排队上限")
    parser.add_argument("--submit-workers", type=int, default=4, help="注册提交并发槽")
    if registration:
        parser.add_argument("--castle-email-token", default="", help="发送邮箱验证码时的 fresh Castle token")
        parser.add_argument("--castle-email-token-file", default="")
        parser.add_argument("--castle-register-token", default="", help="提交注册时的 fresh Castle token")
        parser.add_argument("--castle-register-token-file", default="")
    else:
        parser.add_argument("--castle-token", default="", help="密码登录时的 fresh Castle token")
        parser.add_argument("--castle-token-file", default="")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="xAI HTTP 注册与 OAuth 凭证获取（仅 local Turnstile 启动 Chrome）",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    credential = sub.add_parser("credential", help="从已有 SSO 或邮箱密码获取 OAuth 凭证")
    _add_proxy_options(credential)
    credential.add_argument("--output-dir", default=str(CREDENTIALS_DIR))
    credential.add_argument("--email", default="", help="密码登录邮箱或 OAuth 邮箱提示")
    credential.add_argument("--password", default="", help="密码登录密码（建议改用环境变量包装调用）")
    credential.add_argument("--sso", default="", help="已有 sso cookie")
    credential.add_argument("--sso-file", default="", help="包含已有 sso cookie 的 UTF-8 文件")
    credential.add_argument("--trace-session", default="", help="从 Recorder JSON 提取 sso（仅适合短期测试）")
    _add_token_options(credential, registration=False)

    register = sub.add_parser("register", help="直接 HTTP 注册、取得 SSO 并写 OAuth 凭证")
    _add_proxy_options(register)
    register.add_argument("--output-dir", default=str(CREDENTIALS_DIR))
    register.add_argument("--email", default="")
    register.add_argument("--email-code", default="", help="已收到的 xAI 6 位邮箱验证码")
    register.add_argument(
        "--mail-config",
        default="",
        help="邮箱配置 JSON（email_provider=yyds|cloudflare|msgraph）；无 email/code 时自动创建和轮询",
    )
    register.add_argument(
        "--mail-file",
        default="",
        help="Outlook/Hotmail 四段账号文件 email----password----client_id----refresh_token；优先于 mail-config 建箱",
    )
    register.add_argument("--given-name", default="")
    register.add_argument("--family-name", default="")
    register.add_argument("--password", default="")
    register.add_argument(
        "--accounts-output",
        default="",
        help="账号输出文件；默认 accounts_http_时间戳.txt（包含密码和 sso）",
    )
    _add_token_options(register, registration=True)

    mail_probe = sub.add_parser("mail-probe", help="探测临时邮箱/微软邮箱是否可创建或读信（不触达 xAI 注册）")
    _add_proxy_options(mail_probe)
    mail_probe.add_argument("--mail-config", default="")
    mail_probe.add_argument("--mail-file", default="")
    mail_probe.add_argument("--mark-used", action="store_true", help="msgraph 探测时也消费一行账号")

    capture = sub.add_parser(
        "turnstile-capture",
        help="用真实浏览器在同一出口代理上打开注册页，捕获新鲜 Turnstile token（会启动 Chrome）",
    )
    _add_proxy_options(capture)
    capture.add_argument(
        "--output",
        default=str(STATE_DIR / "turnstile.txt"),
        help="写入 token 的 UTF-8 文件",
    )
    capture.add_argument(
        "--proxy-used-file",
        default=str(STATE_DIR / "turnstile.proxy.txt"),
        help="写入本次实际使用的代理，便于 register 粘性复用",
    )
    capture.add_argument("--wait-seconds", type=int, default=180, help="等待原生 Turnstile 通过的秒数")
    capture.add_argument("--headless", action="store_true", help="无头模式（成功率通常更低）")
    return parser


def _resolve_runtime_proxy(args: argparse.Namespace) -> Tuple[str, str]:
    """Return (effective_proxy_url, selected_upstream_raw)."""
    selected_raw = str(getattr(args, "proxy", "") or "").strip()
    if not selected_raw and str(getattr(args, "proxy_file", "") or "").strip():
        path = Path(str(args.proxy_file).strip())
        if path.is_file():
            lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            if lines:
                if getattr(args, "proxy_random", False):
                    selected_raw = random.choice(lines)
                else:
                    selected_raw = lines[int(getattr(args, "proxy_index", 0) or 0) % len(lines)]
    selected = normalize_proxy(selected_raw) if selected_raw else ""
    return selected, selected_raw or selected


def _safe_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None



def _resolve_local_browser_mode(*, want_headless: bool) -> Tuple[str, bool]:
    """Map the setting directly to headed or native Chrome headless-new."""

    return ("headless-new", True) if want_headless else ("headed", False)


def _build_turnstile_browser_options(
    *,
    options: Any = None,
    proxy: str = "",
    headless: bool = False,
    user_agent: str = "",
    log_callback: LogFn = None,
) -> Any:
    """Build Chromium launch options for local Turnstile capture.

    Keep the profile close to a normal headed Chrome session.  Over-tuning
    launch flags / forced UA has been observed to make accounts.x.ai serve a
    Cloudflare hard-block page even when direct headed browsing works.
    """
    if options is None:
        from DrissionPage import ChromiumOptions

        options = ChromiumOptions()

    # Pick an explicit free debugging port.  DrissionPage.auto_port() only stores
    # a range; if launch fails early the default address stays 127.0.0.1:9222 and
    # the error message becomes misleading.
    import socket

    def _free_port() -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])
        finally:
            sock.close()

    port = _free_port()
    set_local_port = getattr(options, "set_local_port", None)
    if callable(set_local_port):
        _safe_call(set_local_port, port)
    else:
        _safe_call(getattr(options, "auto_port", None))
        _safe_call(getattr(options, "set_argument", None), f"--remote-debugging-port={port}")
    _log(log_callback, f"[Turnstile] 调试端口: 127.0.0.1:{port}")
    try:
        import tempfile

        profile_dir = tempfile.mkdtemp(prefix="xai-ts-chrome-")
        set_user_data = getattr(options, "set_user_data_path", None)
        if callable(set_user_data):
            set_user_data(profile_dir)
        else:
            _safe_call(getattr(options, "set_argument", None), f"--user-data-dir={profile_dir}")
        # Stash for cleanup by caller if needed.
        try:
            options._xai_profile_dir = profile_dir  # type: ignore[attr-defined]
        except Exception:
            pass
        _log(log_callback, f"[Turnstile] 使用独立用户目录: {Path(profile_dir).name}")
    except Exception as exc:
        _log(log_callback, f"[Turnstile][warn] 创建独立用户目录失败: {exc}")

    # Minimal, stable flags.  Avoid broad "stealth" bundles that change browser
    # behavior enough for CF to treat the session as automation.
    # Do not pass --disable-blink-features=AutomationControlled:
    # current Chrome shows an unsupported-flag warning banner for it, which is
    # itself an automation smell and does not help Turnstile capture.
    args = [
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-dev-shm-usage",
        "--no-sandbox",
        "--window-size=1365,900",
    ]
    for arg in args:
        _safe_call(getattr(options, "set_argument", None), arg)

    prefs = {
        "credentials_enable_service": False,
        "profile.password_manager_enabled": False,
    }
    set_pref = getattr(options, "set_pref", None)
    if callable(set_pref):
        for key, value in prefs.items():
            _safe_call(set_pref, key, value)

    # Only override UA when the caller explicitly asks.  Default to the real
    # installed Chrome UA so headed direct sessions match manual browsing.
    ua = str(user_agent or "").strip()
    if ua:
        set_ua = getattr(options, "set_user_agent", None)
        if callable(set_ua):
            _safe_call(set_ua, ua)
        else:
            _safe_call(getattr(options, "set_argument", None), f"--user-agent={ua}")
        _log(log_callback, f"[Turnstile] 使用自定义 UA: {ua[:48]}{'…' if len(ua) > 48 else ''}")
    else:
        _log(log_callback, "[Turnstile] 使用浏览器默认 UA（不强制覆盖）")

    if headless:
        # Prefer Chrome's new headless.  Also set explicit args because some
        # DrissionPage builds only flip an internal flag and still look "old headless".
        headless_fn = getattr(options, "headless", None)
        if callable(headless_fn):
            _safe_call(headless_fn, True)
        for arg in (
            "--headless=new",
            "--hide-scrollbars",
            "--mute-audio",
            "--disable-gpu",
        ):
            _safe_call(getattr(options, "set_argument", None), arg)
        _log(
            log_callback,
            "[Turnstile] 已启用原生 Chrome --headless=new",
        )

    proxy = str(proxy or "").strip()
    if proxy:
        # Chrome rejects credentialed proxy URLs (ERR_NO_SUPPORTED_PROXIES).
        # Callers must pass a browser-safe endpoint (local forwarder) already.
        if _proxy_has_embedded_auth(proxy):
            _log(
                log_callback,
                "你似乎在设置使用账号密码的代理，暂时不支持这种代理，可自行用插件实现需求。",
            )
            raise XAIHttpFlowError(
                "浏览器不支持带账号密码的代理 URL（ERR_NO_SUPPORTED_PROXIES）；"
                "请先经 local_proxy_forwarder 转成本机无鉴权代理"
            )
        set_proxy = getattr(options, "set_proxy", None)
        if not callable(set_proxy):
            raise XAIHttpFlowError("当前 ChromiumOptions 不支持 set_proxy，无法配置浏览器代理")
        try:
            set_proxy(proxy)
        except Exception as exc:
            raise XAIHttpFlowError(f"无法设置浏览器代理: {exc}") from exc
        _log(log_callback, f"[Turnstile] 浏览器代理: {proxy}")
    else:
        _log(log_callback, "[Turnstile] 浏览器直连（无代理）")

    return options


def _classify_turnstile_page_state(diag: Any) -> Dict[str, Any]:
    """Classify local browser page state for Turnstile capture diagnostics."""
    data = diag if isinstance(diag, dict) else {}
    title = str(data.get("title") or "").strip()
    body = str(data.get("bodySnippet") or data.get("htmlSnippet") or data.get("body") or "").strip()
    url = str(data.get("url") or "").strip()
    text = f"{title}\n{body}\n{url}".lower()

    sitekey_count = int(data.get("sitekeyCount") or 0)
    ts_iframes = int(data.get("turnstileIframeCount") or 0)
    token_len = int(data.get("tokenLen") or 0)
    has_cf_input = bool(data.get("hasCfInput"))
    challenge_like = bool(data.get("challengeLike"))

    hard_block_markers = (
        "you have been blocked",
        "unable to access x.ai",
        "why have i been blocked",
        "access denied",
        "error code 1020",
        "cf-error-code",
    )
    challenge_markers = (
        "just a moment",
        "checking your browser",
        "attention required",
        "verify you are human",
        "cf-browser-verification",
        "enable javascript and cookies",
    )
    email_verify_markers = (
        "验证您的邮箱",
        "验证你的邮箱",
        "确认邮箱",
        "verify your email",
        "check your email",
        "one-time",
        "一次性安全代码",
        "一次性代码",
        "security code",
    )

    hard_hit = any(marker in text for marker in hard_block_markers)
    challenge_hit = challenge_like or any(marker in text for marker in challenge_markers)
    hard_title = "attention required" in title.lower() and "cloudflare" in title.lower()
    # Title-only "Attention Required" is ambiguous; require hard body markers or no waiting copy.
    hard_title_confirmed = hard_title and (
        hard_hit
        or "blocked" in body.lower()
        or "unable to access" in body.lower()
        or (not any(m in text for m in ("just a moment", "checking your browser")) and token_len < 80 and sitekey_count == 0)
    )

    if hard_hit or hard_title_confirmed:
        message = (
            "本地浏览器打开 accounts.x.ai 时被 Cloudflare 硬拦截(blocked)"
            f"（title={title or '-'}；url={url or '-'}）。"
            "当前启动模式将在本次捕获中保持不变；请让上层有界重试或更换出口。"
        )
        return {
            "blocked": True,
            "kind": "cloudflare_hard_block",
            "message": message,
            "title": title,
            "url": url,
            "sitekey_count": sitekey_count,
            "has_cf_input": has_cf_input,
            "turnstile_iframe_count": ts_iframes,
            "token_len": token_len,
        }

    email_verify_hit = any(marker in text for marker in email_verify_markers)
    # Local capture only wants a Turnstile token.  Landing on the email OTP page
    # means we advanced the signup UI too far with a disposable address.
    if (
        email_verify_hit
        and sitekey_count == 0
        and not has_cf_input
        and ts_iframes == 0
        and token_len < 80
    ):
        message = (
            "本地浏览器已进入“验证邮箱/确认邮箱”页，而不是 Turnstile widget"
            f"（title={title or '-'}；url={url or '-'}）。"
            "这说明求解器误提交了注册表单；请只停留在含 Turnstile 的注册页。"
        )
        return {
            "blocked": True,
            "kind": "email_verification_deadend",
            "message": message,
            "title": title,
            "url": url,
            "sitekey_count": sitekey_count,
            "has_cf_input": has_cf_input,
            "turnstile_iframe_count": ts_iframes,
            "token_len": token_len,
        }

    # Challenge interstitial without any Turnstile widget mounted.
    if challenge_hit and sitekey_count == 0 and not has_cf_input and ts_iframes == 0 and token_len < 80:
        message = (
            "本地浏览器停留在 Cloudflare 人机/等待页，尚未进入真实注册页"
            f"（title={title or '-'}；url={url or '-'}）。"
            "请改用有头模式、减少异常启动参数，必要时再换出口或远程 captcha provider。"
        )
        return {
            "blocked": True,
            "kind": "cloudflare_challenge",
            "message": message,
            "title": title,
            "url": url,
            "sitekey_count": sitekey_count,
            "has_cf_input": has_cf_input,
            "turnstile_iframe_count": ts_iframes,
            "token_len": token_len,
        }

    return {
        "blocked": False,
        "kind": "ok" if (sitekey_count or has_cf_input or ts_iframes or token_len >= 80) else "waiting",
        "message": "",
        "title": title,
        "url": url,
        "sitekey_count": sitekey_count,
        "has_cf_input": has_cf_input,
        "turnstile_iframe_count": ts_iframes,
        "token_len": token_len,
    }


def _raise_if_turnstile_page_blocked(
    diag: Any,
    *,
    log_callback: LogFn = None,
    stage: str = "Turnstile capture",
    kinds: Optional[set] = None,
) -> Dict[str, Any]:
    classified = _classify_turnstile_page_state(diag)
    if not classified.get("blocked"):
        return classified
    kind = str(classified.get("kind") or "")
    if kinds is not None and kind not in kinds:
        return classified
    message = str(classified.get("message") or "Cloudflare blocked local browser")
    _log(
        log_callback,
        f"[Turnstile][error] {stage} 检测到拦截 | kind={kind} | {message}",
    )
    raise VerificationRequiredError(message)


def _click_email_signup_entry(page: Any, *, log_callback: LogFn = None, timeout: int = 12) -> bool:
    """Click the email signup entry on accounts.x.ai landing page if present."""
    deadline = time.monotonic() + max(3, int(timeout or 12))
    js = r"""
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
if (!target) return false;
target.click();
return candidates[0].text || true;
"""
    while time.monotonic() < deadline:
        try:
            clicked = page.run_js(js)
        except Exception:
            clicked = False
        if clicked:
            detail = f": {clicked}" if isinstance(clicked, str) else ""
            _log(log_callback, f"[Turnstile] 已点击邮箱注册入口{detail}")
            time.sleep(1.5)
            return True
        time.sleep(0.8)
    return False


def _read_turnstile_token_js(page: Any) -> str:
    try:
        value = page.run_js(
            r"""
let token = '';
try {
  if (window.__xaiTsToken) token = String(window.__xaiTsToken || '').trim();
} catch (e) {}
if (!token) {
  const cf = document.querySelector('input[name="cf-turnstile-response"]');
  if (cf) token = String(cf.value || '').trim();
}
try {
  if ((!token || token.length < 80) && window.turnstile && typeof turnstile.getResponse === 'function') {
    const api = String(turnstile.getResponse(window.__xaiTsWidgetId) || turnstile.getResponse() || '').trim();
    if (api) token = api;
  }
} catch (e) {}
return token;
"""
        )
    except Exception:
        return ""
    return str(value or "").strip()



def _diagnose_turnstile_page(page: Any) -> Dict[str, Any]:
    try:
        data = page.run_js(
            """
const html = document.documentElement ? document.documentElement.innerHTML : '';
const bodyText = (document.body && document.body.innerText) ? document.body.innerText : '';
const cf = document.querySelector('input[name="cf-turnstile-response"]');
const token = cf ? String(cf.value || '').trim() : '';
let turnstileResp = '';
try {
  if (window.turnstile && typeof turnstile.getResponse === 'function') {
    turnstileResp = String(turnstile.getResponse() || '').trim();
  }
} catch (e) {}
const sitekeys = [];
const pushKey = (k) => {
  k = String(k || '').trim();
  if (k && !sitekeys.includes(k)) sitekeys.push(k);
};
document.querySelectorAll('[data-sitekey]').forEach((el) => pushKey(el.getAttribute('data-sitekey')));
const m1 = html.match(/data-sitekey=["']([^"']+)["']/ig) || [];
m1.forEach((s) => {
  const mm = s.match(/data-sitekey=["']([^"']+)["']/i);
  if (mm) pushKey(mm[1]);
});
const m2 = html.match(/"sitekey"\\s*:\\s*"([^"\\\\]+)"/i);
if (m2) pushKey(m2[1]);
const iframes = [...document.querySelectorAll('iframe')].map((f) => {
  const src = String(f.src || '');
  return {
    src: src.slice(0, 180),
    title: String(f.title || ''),
    id: String(f.id || ''),
    name: String(f.name || ''),
    isTurnstile: /turnstile|challenges\\.cloudflare\\.com|cf-chl|cloudflare/i.test(
      src + ' ' + (f.title || '') + ' ' + (f.name || '')
    ),
  };
}).slice(0, 20);
const inputs = {
  email: !!document.querySelector('input[type="email"], input[name*="email" i], input[autocomplete="email"]'),
  password: !!document.querySelector('input[type="password"], input[name*="password" i]'),
  givenName: !!document.querySelector('input[name="givenName"], input[autocomplete="given-name"], input[data-testid="givenName"]'),
  familyName: !!document.querySelector('input[name="familyName"], input[autocomplete="family-name"], input[data-testid="familyName"]'),
};
return {
  url: location.href,
  title: document.title || '',
  readyState: document.readyState || '',
  hasCfInput: !!cf,
  tokenLen: token.length,
  turnstileApiType: typeof window.turnstile,
  turnstileRespLen: turnstileResp.length,
  turnstileError: String(window.__xaiTsLastError || ''),
  sitekeys,
  sitekeyCount: sitekeys.length,
  iframeCount: iframes.length,
  turnstileIframeCount: iframes.filter((x) => x.isTurnstile).length,
  iframes,
  inputs,
  widgetLikeCount: document.querySelectorAll('.cf-turnstile, [data-sitekey], #cf-turnstile, #turnstile-wrapper, iframe[src*="turnstile"], iframe[src*="challenges.cloudflare"]').length,
  challengeLike: /(just a moment|checking your browser|cf-browser-verification|attention required|verify you are human|you have been blocked|unable to access x\\.ai|access denied|cf-error-code|error code 1020)/i.test(html + ' ' + bodyText),
  bodySnippet: bodyText.replace(/\\s+/g, ' ').trim().slice(0, 280),
  htmlSnippet: html.replace(/\\s+/g, ' ').trim().slice(0, 280),
};
"""
        )
    except Exception as exc:
        return {"error": f"diagnose failed: {exc}"}
    return data if isinstance(data, dict) else {"error": "diagnose returned non-object", "raw": str(data)}


def _prime_signup_form_fields(page: Any, *, log_callback: LogFn = None) -> Dict[str, Any]:
    """Fill minimal visible signup fields so the page can mount Turnstile."""
    try:
        result = page.run_js(
            r"""
function setNativeValue(input, value) {
  if (!input) return false;
  const proto = window.HTMLInputElement && window.HTMLInputElement.prototype;
  const desc = proto ? Object.getOwnPropertyDescriptor(proto, 'value') : null;
  if (desc && desc.set) desc.set.call(input, value);
  else input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
}
function visible(el) {
  if (!el) return false;
  const st = getComputedStyle(el);
  if (st.display === 'none' || st.visibility === 'hidden' || st.opacity === '0') return false;
  const r = el.getBoundingClientRect();
  return r.width > 0 && r.height > 0;
}
const email = document.querySelector('input[type="email"], input[name*="email" i], input[autocomplete="email"], input[data-testid*="email" i]');
const given = document.querySelector('input[name="givenName"], input[autocomplete="given-name"], input[data-testid="givenName"]');
const family = document.querySelector('input[name="familyName"], input[autocomplete="family-name"], input[data-testid="familyName"]');
const password = document.querySelector('input[type="password"], input[name*="password" i], input[data-testid="password"]');
const out = { email: false, given: false, family: false, password: false, skippedEmail: false };
// Never fill a disposable email here. Submitting it lands on the OTP page and
// abandons the Turnstile capture surface used by the HTTP protocol flow.
if (visible(email)) {
  out.skippedEmail = true;
}
if (visible(given) && !String(given.value || '').trim()) {
  out.given = setNativeValue(given, 'Local');
}
if (visible(family) && !String(family.value || '').trim()) {
  out.family = setNativeValue(family, 'Solver');
}
if (visible(password) && !String(password.value || '').trim()) {
  // Only for pages that already expose password + Turnstile together.
  out.password = setNativeValue(password, 'Aa1!' + Date.now().toString(36) + 'xY');
}
return out;
"""
        )
    except Exception as exc:
        _log(log_callback, f"[Turnstile][diag] 预填表单失败: {exc}")
        return {}
    if isinstance(result, dict):
        filled = ",".join(k for k, v in result.items() if v and k != "skippedEmail")
        if filled:
            _log(log_callback, f"[Turnstile] 已预填可见表单字段: {filled}")
        if result.get("skippedEmail"):
            _log(log_callback, "[Turnstile] 跳过邮箱预填，避免误进验证邮箱页")
    return result if isinstance(result, dict) else {}




def _click_signup_continue(page: Any, *, log_callback: LogFn = None) -> str:
    """Click continue/register on the email-only intermediate page if present."""
    try:
        clicked = page.run_js(
            r"""
function isVisible(node) {
  if (!node) return false;
  const st = getComputedStyle(node);
  if (st.display === 'none' || st.visibility === 'hidden' || st.opacity === '0') return false;
  const r = node.getBoundingClientRect();
  return r.width > 0 && r.height > 0;
}
function textOf(node) {
  return [node.innerText, node.textContent, node.getAttribute('aria-label'), node.value]
    .filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
function score(node) {
  const t = textOf(node).replace(/\s+/g, ' ').trim();
  const compact = t.replace(/\s+/g, '');
  const lower = t.toLowerCase();
  if (!t) return 0;
  // Never advance into X / Twitter OAuth from the email signup path.
  if (
    compact.includes('使用X') ||
    compact.includes('用X注册') ||
    compact.includes('用X登录') ||
    lower.includes('sign in with x') ||
    lower.includes('sign up with x') ||
    lower.includes('continue with x') ||
    lower.includes('continue with twitter') ||
    lower.includes('sign in with twitter') ||
    lower.includes('oauth') ||
    /(?:^|[^a-z])x(?:[^a-z]|$)/i.test(t) && (lower.includes('sign') || lower.includes('注册') || lower.includes('登录') || lower.includes('continue'))
  ) {
    return 0;
  }
  // Never click email-verification actions. Local capture only needs Turnstile.
  if (
    compact.includes('确认邮箱') ||
    compact.includes('验证邮箱') ||
    compact.includes('验证您的邮箱') ||
    compact.includes('验证你的邮箱') ||
    lower.includes('verify email') ||
    lower.includes('confirm email') ||
    lower.includes('verify your email') ||
    lower.includes('confirm your email')
  ) {
    return 0;
  }
  // Avoid generic "注册" submit when it would leave the page that mounts Turnstile.
  // Prefer only explicit continue/next on the email-entry intermediate step.
  if (lower === 'continue' || lower.includes('continue') || compact.includes('继续')) return 85;
  if (lower.includes('next') || compact.includes('下一步')) return 80;
  // Bare "注册" is too aggressive on current xAI UI: it submits the disposable
  // email and lands on the OTP page without a Turnstile token.
  if (compact === '注册') return 0;
  if (compact.includes('注册') && !compact.includes('使用邮箱') && !compact.includes('邮箱注册')) return 0;
  if (lower.includes('submit') || compact.includes('提交')) return 40;
  if (node.getAttribute('type') === 'submit') return 30;
  return 0;
}
const nodes = Array.from(document.querySelectorAll('button, input[type="submit"], [role="button"]'))
  .filter((n) => isVisible(n) && !n.disabled && n.getAttribute('aria-disabled') !== 'true')
  .map((n) => ({n, s: score(n), t: textOf(n)}))
  .filter((x) => x.s > 0)
  .sort((a,b) => b.s - a.s);
if (!nodes.length) return false;
nodes[0].n.click();
return nodes[0].t || true;
"""
        )
    except Exception as exc:
        _log(log_callback, f"[Turnstile][diag] 点击继续失败: {exc}")
        return ""
    if clicked:
        detail = f": {clicked}" if isinstance(clicked, str) else ""
        _log(log_callback, f"[Turnstile] 已点击继续/注册{detail}")
        return str(clicked)
    return ""

def _nudge_turnstile_widget(page: Any, *, log_callback: LogFn = None) -> str:
    """Best-effort interaction with Turnstile host/iframe/shadow checkbox."""
    actions: list[str] = []

    # Read the explicit widget response without repeatedly calling execute().
    try:
        api_hit = page.run_js(
            """
let out = {tokenLen:0, error:''};
try {
  if (window.turnstile && window.__xaiTsWidgetId != null) {
    try {
      const cur = String(turnstile.getResponse(window.__xaiTsWidgetId) || '').trim();
      out.tokenLen = cur.length;
      if (cur) {
        window.__xaiTsToken = cur;
        const input = document.querySelector('input[name="cf-turnstile-response"]');
        if (input) input.value = cur;
      }
    } catch (e) {}
  }
} catch (e) { out.error = String(e); }
return out;
"""
        )
        if isinstance(api_hit, dict):
            if int(api_hit.get("tokenLen") or 0) >= 80:
                actions.append(f"api-token:{api_hit.get('tokenLen')}")
    except Exception:
        pass

    # 2) DrissionPage shadow/iframe path used by the legacy browser flow
    try:
        challenge_input = None
        try:
            challenge_input = page.ele("@name=cf-turnstile-response", timeout=0.2)
        except Exception:
            challenge_input = None
        if challenge_input is not None:
            wrapper = None
            try:
                wrapper = challenge_input.parent()
            except Exception:
                wrapper = None
            iframe = None
            if wrapper is not None:
                try:
                    iframe = wrapper.shadow_root.ele("tag:iframe", timeout=0.2)
                except Exception:
                    iframe = None
            if iframe is None:
                try:
                    iframe = page.ele("tag:iframe@src:turnstile", timeout=0.2)
                except Exception:
                    iframe = None
            if iframe is not None:
                clicked_shadow = False
                try:
                    body_sr = iframe.ele("tag:body", timeout=0.2).shadow_root
                    btn = body_sr.ele("tag:input", timeout=0.2) or body_sr.ele("css:input[type=checkbox]", timeout=0.2)
                    if btn:
                        btn.click()
                        clicked_shadow = True
                except Exception:
                    pass
                if not clicked_shadow:
                    try:
                        iframe.click()
                        clicked_shadow = True
                    except Exception:
                        pass
                if clicked_shadow:
                    actions.append("shadow-iframe")
    except Exception:
        pass

    if actions:
        _log(log_callback, f"[Turnstile] 尝试触发 widget: {'/'.join(actions)}")
        return ",".join(actions)
    return ""



def _inject_turnstile_widget_js(
    *,
    sitekey: str,
    action: str = "",
    cdata: str = "",
) -> str:
    """Build JS that explicitly renders an official Turnstile widget on-page."""
    sitekey_js = json.dumps(str(sitekey or "").strip())
    action_js = json.dumps(str(action or "").strip())
    cdata_js = json.dumps(str(cdata or "").strip())
    return f"""
const sitekey = {sitekey_js};
const action = {action_js};
const cdata = {cdata_js};
if (!sitekey) return {{ok:false, reason:'empty-sitekey'}};
window.__xaiTsToken = window.__xaiTsToken || '';
window.__xaiTsMeta = {{sitekey, action, cdata}};
let host = document.getElementById('xai-local-ts-host');
if (!host) {{
  host = document.createElement('div');
  host.id = 'xai-local-ts-host';
  host.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:2147483647;background:#fff;padding:12px;border:1px solid #d0d7de;border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.12);width:320px;min-height:70px';
  document.documentElement.appendChild(host);
}}
function ensureHiddenInput() {{
  let input = document.querySelector('input[name="cf-turnstile-response"]');
  if (!input) {{
    input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'cf-turnstile-response';
    document.documentElement.appendChild(input);
  }}
  return input;
}}
function onToken(token) {{
  token = String(token || '').trim();
  window.__xaiTsToken = token;
  try {{ ensureHiddenInput().value = token; }} catch (e) {{}}
}}
function doRender() {{
  if (!window.turnstile || typeof turnstile.render !== 'function') {{
    return {{ok:false, reason:'turnstile-api-missing'}};
  }}
  if (window.__xaiTsWidgetId != null) {{
    try {{
      const existing = String(turnstile.getResponse(window.__xaiTsWidgetId) || '').trim();
      if (existing) onToken(existing);
    }} catch (e) {{}}
    return {{ok:true, reason:'already-rendered', widgetId: window.__xaiTsWidgetId, tokenLen: (window.__xaiTsToken||'').length}};
  }}
  const opts = {{
    sitekey,
    callback: onToken,
    'error-callback': function(code){{ window.__xaiTsLastError = String(code || 'error'); return true; }},
    'expired-callback': function(){{ window.__xaiTsToken = ''; }},
    'timeout-callback': function(){{ window.__xaiTsLastError = 'timeout'; }},
    size: 'normal',
    theme: 'light',
    retry: 'auto',
  }};
  if (action) opts.action = action;
  if (cdata) opts.cData = cdata;
  try {{
    window.__xaiTsWidgetId = turnstile.render(host, opts);
    return {{ok:true, reason:'rendered', widgetId: window.__xaiTsWidgetId, tokenLen: (window.__xaiTsToken||'').length}};
  }} catch (e) {{
    return {{ok:false, reason:'render-error', error: String(e)}};
  }}
}}
const existingScript = document.querySelector('script[src*="challenges.cloudflare.com/turnstile"], script[src*="turnstile/v0/api.js"]');
if (!existingScript) {{
  const s = document.createElement('script');
  s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
  s.async = true;
  s.defer = true;
  s.onload = function() {{ try {{ doRender(); }} catch (e) {{}} }};
  document.head.appendChild(s);
  return {{ok:true, reason:'script-loading'}};
}}
return doRender();
"""


def _ensure_injected_turnstile_widget(
    page: Any,
    *,
    sitekey: str,
    action: str = "",
    cdata: str = "",
    log_callback: LogFn = None,
    wait_api_sec: float = 3.0,
) -> Dict[str, Any]:
    """Inject/render Turnstile and wait briefly for api.js to become ready."""
    sitekey = str(sitekey or "").strip()
    if not sitekey:
        return {"ok": False, "reason": "empty-sitekey"}

    deadline = time.monotonic() + max(0.5, float(wait_api_sec or 0))
    last: Dict[str, Any] = {"ok": False, "reason": "not-started"}
    attempt = 0
    while True:
        attempt += 1
        try:
            result = page.run_js(
                _inject_turnstile_widget_js(sitekey=sitekey, action=action, cdata=cdata)
            )
        except Exception as exc:
            _log(log_callback, f"[Turnstile][diag] 注入 widget 失败: {exc}")
            return {"ok": False, "reason": f"inject-exception:{exc}"}
        data = result if isinstance(result, dict) else {"ok": False, "reason": "non-object", "raw": str(result)}
        last = data
        reason = str(data.get("reason") or "")
        token_len = int(data.get("tokenLen") or 0)
        if data.get("ok") and reason in {"rendered", "already-rendered"}:
            _log(
                log_callback,
                "[Turnstile] 已注入/渲染 Turnstile widget | "
                f"reason={reason} tokenLen={token_len} attempt={attempt}",
            )
            return data
        if data.get("ok") and reason == "script-loading" and time.monotonic() < deadline:
            time.sleep(0.35)
            continue
        if (not data.get("ok")) and reason in {"turnstile-api-missing", "render-error"} and time.monotonic() < deadline:
            time.sleep(0.35)
            continue
        break

    if last.get("ok"):
        _log(
            log_callback,
            "[Turnstile] 已注入/渲染 Turnstile widget | "
            f"reason={last.get('reason')} tokenLen={last.get('tokenLen') or 0} attempt={attempt}",
        )
    else:
        _log(
            log_callback,
            f"[Turnstile][warn] widget 注入未完成: {last.get('reason') or last} attempt={attempt}",
        )
    return last



def _launch_turnstile_browser(options: Any, *, log_callback: LogFn = None) -> Any:
    """Launch Chromium with actionable errors for common Linux/profile failures."""
    from DrissionPage import Chromium

    try:
        browser = Chromium(options)
    except Exception as exc:
        msg = str(exc)
        low = msg.lower()
        if (
            "maximum number of clients reached" in low
            or "missing x server" in low
            or "cannot open display" in low
            or "inotify_init" in low
            or "too many open files" in low
        ):
            hint = (
                "有界面 Chrome 拉不起：当前图形会话资源耗尽（X11 clients / inotify / 打开文件过多）。"
                "请先清理本项目残留浏览器，或显式启用原生 headless=new。"
                f" 原始错误: {msg}"
            )
        else:
            hint = (
                "浏览器启动/连接失败。"
                "常见原因：用户目录冲突、调试端口占用、Linux 缺 --no-sandbox、无界面环境未开 headless、"
                "X11 客户端数打满。"
                f" 原始错误: {msg}"
            )
        _log(log_callback, f"[Turnstile][error] {hint}")
        raise XAIHttpFlowError(hint) from exc
    return browser


def _turnstile_browser_pid(browser: Any) -> int:
    if browser is None:
        return 0
    for name in ("process_id", "pid", "_process_id"):
        try:
            value = getattr(browser, name, 0)
            value = value() if callable(value) else value
            pid = int(value or 0)
        except Exception:
            pid = 0
        if pid > 1:
            return pid
    return 0


def _quit_turnstile_browser(browser: Any, options: Any = None) -> None:
    browser_pid = _turnstile_browser_pid(browser)
    try:
        if browser is not None:
            browser.quit()
    except Exception:
        pass
    profile = None
    try:
        profile = getattr(options, "_xai_profile_dir", None) if options is not None else None
    except Exception:
        profile = None
    if browser_pid > 1:
        try:
            from turnstile_solver.src.browser_runtime import _reap_chrome_process_tree

            _reap_chrome_process_tree(browser_pid, timeout_sec=2.0)
        except Exception:
            pass
    try:
        unregister_project_browser(browser_pid, profile or "")
    except Exception:
        pass
    if profile:
        try:
            import shutil

            shutil.rmtree(profile, ignore_errors=True)
        except Exception:
            pass


def capture_turnstile_token(
    *,
    proxy: str = "",
    output: str = str(STATE_DIR / "turnstile.txt"),
    proxy_used_file: str = "",
    selected_proxy_raw: str = "",
    timeout: int = 30,
    headless: bool = False,
    page_url: str = "",
    click_email_signup: bool = True,
    sitekey: str = "",
    action: str = "",
    cdata: str = "",
    user_agent: str = "",
    accept_language: str = DEFAULT_ACCEPT_LANGUAGE,
    expected_platform: str = "",
    expected_client_hint_platform: str = "",
    expected_browser_major: str = "",
    return_result: bool = False,
    log_callback: LogFn = None,
) -> Any:
    """Public entry: rate-limit concurrent local Chrome captures, then solve."""
    with _local_turnstile_slot(log_callback=log_callback):
        return _capture_turnstile_token_impl(
            proxy=proxy,
            output=output,
            proxy_used_file=proxy_used_file,
            selected_proxy_raw=selected_proxy_raw,
            timeout=timeout,
            headless=headless,
            page_url=page_url,
            click_email_signup=click_email_signup,
            sitekey=sitekey,
            action=action,
            cdata=cdata,
            user_agent=user_agent,
            accept_language=accept_language,
            expected_platform=expected_platform,
            expected_client_hint_platform=expected_client_hint_platform,
            expected_browser_major=expected_browser_major,
            return_result=return_result,
            log_callback=log_callback,
        )


def _capture_turnstile_token_impl(
    *,
    proxy: str = "",
    output: str = str(STATE_DIR / "turnstile.txt"),
    proxy_used_file: str = "",
    selected_proxy_raw: str = "",
    timeout: int = 30,
    headless: bool = False,
    page_url: str = "",
    click_email_signup: bool = True,
    sitekey: str = "",
    action: str = "",
    cdata: str = "",
    user_agent: str = "",
    accept_language: str = DEFAULT_ACCEPT_LANGUAGE,
    expected_platform: str = "",
    expected_client_hint_platform: str = "",
    expected_browser_major: str = "",
    return_result: bool = False,
    log_callback: LogFn = None,
) -> Any:
    """Open accounts.x.ai/sign-up in Chrome and capture a native Turnstile token.

    This intentionally uses a real browser.  It does not solve, forge, or bypass
    Turnstile.  The captured token should be consumed promptly with the same
    egress proxy (sticky residential session recommended).

    Enhancements over the minimal capture path:
      - click email-signup entry
      - prime visible form fields
      - nudge Turnstile host / shadow checkbox
      - periodic diagnostics for empty-token failures
    """
    try:
        from DrissionPage import Chromium, ChromiumOptions
    except Exception as exc:  # pragma: no cover - depends on local install
        raise XAIHttpFlowError(f"turnstile-capture 需要 DrissionPage/Chrome: {exc}") from exc

    # Chromium cannot consume user:pass@host proxies.  Always resolve to a
    # browser-safe endpoint first (local no-auth forwarder when needed).
    selected_proxy_raw = str(selected_proxy_raw or proxy or "").strip()
    browser_proxy = ""
    forwarder_instance = ""
    options = None
    browser = None
    page = None
    diag_samples: list[Dict[str, Any]] = []
    capture_started = time.monotonic()
    try:
        browser_proxy, forwarder_instance = _prepare_browser_proxy(
            proxy,
            log_callback=log_callback,
        )
        proxy = browser_proxy

        want_headless = bool(headless)
        mode, use_headless = _resolve_local_browser_mode(want_headless=want_headless)
        if mode == "headless-new":
            _log(
                log_callback,
                "[Turnstile] 已启用原生 headless=new（无虚拟显示、无可见窗口、无有头回退）",
            )

        if use_headless and not str(user_agent or "").strip():
            runtime_fingerprint = build_runtime_fingerprint_profile()
            user_agent = runtime_fingerprint.user_agent
            accept_language = runtime_fingerprint.accept_language
            expected_platform = runtime_fingerprint.navigator_platform
            expected_client_hint_platform = runtime_fingerprint.client_hint_platform
            expected_browser_major = runtime_fingerprint.browser_major

        options = _build_turnstile_browser_options(
            options=ChromiumOptions(),
            proxy=proxy,
            headless=bool(use_headless),
            user_agent=user_agent,
            log_callback=log_callback,
        )
        _log(log_callback, f"[Turnstile] 正在启动浏览器 mode={mode} headless={use_headless}")
        browser = _launch_turnstile_browser(options, log_callback=log_callback)
        register_project_browser(
            _turnstile_browser_pid(browser),
            getattr(options, "_xai_profile_dir", ""),
        )
        tabs = getattr(browser, "get_tabs", lambda: [])()
        page = tabs[-1] if tabs else browser.new_tab()
        if str(user_agent or "").strip():
            from turnstile_solver.src.browser_worker import apply_cdp_fingerprint_override
            from turnstile_solver.src.models import SolveRequest as LocalSolveRequest

            version_info = page.run_cdp("Browser.getVersion") or {}
            product = str(version_info.get("product") or "")
            match = re.search(r"(?:Headless)?Chrome/(\d+\.\d+\.\d+\.\d+)", product)
            if not match:
                raise XAIHttpFlowError(f"未识别 Chrome 完整版本: {product or '-'}")
            local_request = LocalSolveRequest(
                headless=bool(use_headless),
                user_agent=str(user_agent or ""),
                accept_language=str(accept_language or ""),
                expected_platform=str(expected_platform or ""),
                expected_client_hint_platform=str(expected_client_hint_platform or ""),
                expected_browser_major=int(str(expected_browser_major or "0") or "0"),
            )
            apply_cdp_fingerprint_override(
                page,
                local_request,
                browser_version=match.group(1),
                strict=True,
            )
            _log(
                log_callback,
                f"[Turnstile] CDP 指纹已对齐 Chrome/{match.group(1).split('.', 1)[0]}",
            )
        target_url = str(page_url or SIGNUP_URL).strip() or SIGNUP_URL
        page.get(target_url)
        _log(log_callback, f"[Turnstile] 已打开注册页: {target_url}")
        try:
            page.wait.doc_loaded()
        except Exception:
            pass
        time.sleep(1.0)

        sitekey = str(sitekey or "").strip()
        action = str(action or "").strip()
        cdata = str(cdata or "").strip()
        inject_mode = bool(sitekey)
        if inject_mode:
            _log(
                log_callback,
                "[Turnstile] 使用 sitekey 注入模式 | sitekey=yes "
                f"action={'yes' if action else 'no'} cdata={'yes' if cdata else 'no'} "
                f"headless={'yes' if headless else 'no'}",
            )
            _ensure_injected_turnstile_widget(
                page,
                sitekey=sitekey,
                action=action,
                cdata=cdata,
                log_callback=log_callback,
                wait_api_sec=5.0 if headless else 3.0,
            )
            # Headless often needs a short settle before the checkbox is interactable.
            time.sleep(1.2 if headless else 0.8)
        elif click_email_signup:
            clicked = _click_email_signup_entry(page, log_callback=log_callback, timeout=12)
            if clicked:
                _log(log_callback, "[Turnstile] 已进入邮箱注册入口，等待 Turnstile widget…")
                time.sleep(1.2)
            else:
                _log(log_callback, "[Turnstile][warn] 未点到邮箱注册入口，继续在当前页等待 token")

        # First diagnostics + form priming.
        first_diag = _diagnose_turnstile_page(page)
        if isinstance(first_diag, dict):
            first_diag["_t"] = 0
            diag_samples.append(first_diag)
            _log(
                log_callback,
                "[Turnstile][diag] "
                f"t=0s tokenLen={first_diag.get('tokenLen')} "
                f"sitekeys={first_diag.get('sitekeyCount')} "
                f"cfInput={first_diag.get('hasCfInput')} "
                f"tsIframes={first_diag.get('turnstileIframeCount')} "
                f"inputs={first_diag.get('inputs')} "
                f"title={first_diag.get('title')}",
            )
            # Hard Cloudflare block will never mount Turnstile; fail fast.
            # Soft challenge pages may clear themselves in headed mode, so wait.
            classified0 = _classify_turnstile_page_state(first_diag)
            if classified0.get("kind") == "email_verification_deadend":
                _raise_if_turnstile_page_blocked(
                    first_diag,
                    log_callback=log_callback,
                    stage="打开注册页后",
                    kinds={"email_verification_deadend"},
                )
            if classified0.get("kind") == "cloudflare_hard_block":
                _raise_if_turnstile_page_blocked(
                    first_diag,
                    log_callback=log_callback,
                    stage="打开注册页后",
                    kinds={"cloudflare_hard_block"},
                )
            elif classified0.get("blocked"):
                _log(
                    log_callback,
                    f"[Turnstile][warn] 打开后处于 {classified0.get('kind')}，先继续等待是否自动放行",
                )
        # Only interact with signup UI when we are not in explicit sitekey inject mode.
        # Never auto-submit a disposable email into the real signup OTP page.
        if not inject_mode:
            snap0 = first_diag if isinstance(first_diag, dict) else _diagnose_turnstile_page(page)
            has_widget0 = isinstance(snap0, dict) and (
                int(snap0.get('sitekeyCount') or 0) > 0
                or bool(snap0.get('hasCfInput'))
                or int(snap0.get('turnstileIframeCount') or 0) > 0
                or int(snap0.get('tokenLen') or 0) >= 80
            )
            if not has_widget0:
                _prime_signup_form_fields(page, log_callback=log_callback)
                # Prefer email-entry continue only; scoring already blocks OTP confirm.
                _click_signup_continue(page, log_callback=log_callback)
                time.sleep(1.5)

        timeout = max(30, int(timeout or 180))
        deadline = time.monotonic() + timeout
        started = time.monotonic()
        token = ""
        next_diag_at = started + 5
        next_prime_at = started + 8
        next_nudge_at = started + 18
        next_inject_at = started + 4
        challenge_since: Optional[float] = None
        while time.monotonic() < deadline:
            now = time.monotonic()
            token = _read_turnstile_token_js(page)
            if len(token) >= 80:
                break

            if inject_mode and now >= next_inject_at:
                _ensure_injected_turnstile_widget(
                    page,
                    sitekey=sitekey,
                    action=action,
                    cdata=cdata,
                    log_callback=log_callback,
                    wait_api_sec=2.5 if headless else 1.5,
                )
                next_inject_at = now + 8

            if now >= next_nudge_at:
                _nudge_turnstile_widget(page, log_callback=log_callback)
                next_nudge_at = now + 12

            if (not inject_mode) and now >= next_prime_at:
                snap_now = _diagnose_turnstile_page(page)
                classified_now = _classify_turnstile_page_state(snap_now)
                if classified_now.get("kind") == "email_verification_deadend":
                    _raise_if_turnstile_page_blocked(
                        snap_now,
                        log_callback=log_callback,
                        stage=f"等待 token {int(now - started)}s",
                        kinds={"email_verification_deadend"},
                    )
                has_widget = isinstance(snap_now, dict) and (
                    int(snap_now.get('sitekeyCount') or 0) > 0
                    or bool(snap_now.get('hasCfInput'))
                    or int(snap_now.get('turnstileIframeCount') or 0) > 0
                    or int(snap_now.get('tokenLen') or 0) >= 80
                )
                if not has_widget:
                    # Soft nudge only. Do not keep submitting forms once we already
                    # advanced past the email-entry step.
                    body = str((snap_now or {}).get('bodySnippet') or '')
                    title = str((snap_now or {}).get('title') or '')
                    if ('验证您的邮箱' in body) or ('确认邮箱' in body) or ('verify your email' in body.lower()):
                        next_prime_at = now + 12
                    else:
                        _prime_signup_form_fields(page, log_callback=log_callback)
                        # At most one cautious continue; scoring blocks OTP buttons.
                        if int(now - started) <= 12:
                            _click_signup_continue(page, log_callback=log_callback)
                next_prime_at = now + 12

            if now >= next_diag_at:
                snap = _diagnose_turnstile_page(page)
                if isinstance(snap, dict):
                    snap["_t"] = int(now - started)
                    diag_samples.append(snap)
                    classified = _classify_turnstile_page_state(snap)
                    _log(
                        log_callback,
                        "[Turnstile][diag] "
                        f"t={snap.get('_t')}s tokenLen={snap.get('tokenLen')} "
                        f"sitekeys={snap.get('sitekeyCount')} "
                        f"cfInput={snap.get('hasCfInput')} "
                        f"tsIframes={snap.get('turnstileIframeCount')} "
                        f"challenge={snap.get('challengeLike')} "
                        f"tsError={snap.get('turnstileError') or '-'} "
                        f"state={classified.get('kind')} "
                        f"title={snap.get('title')}",
                    )
                    challenge_error = str(snap.get("turnstileError") or "").strip()
                    if challenge_error.startswith(("300", "600")):
                        raise VerificationRequiredError(
                            f"Turnstile challenge error {challenge_error}"
                        )
                    if classified.get("kind") in {"cloudflare_hard_block", "email_verification_deadend"}:
                        _raise_if_turnstile_page_blocked(
                            snap,
                            log_callback=log_callback,
                            stage=f"等待 token {snap.get('_t')}s",
                            kinds={"cloudflare_hard_block", "email_verification_deadend"},
                        )
                    elif classified.get("kind") == "cloudflare_challenge":
                        if challenge_since is None:
                            challenge_since = now
                        # Headed direct sessions may clear a brief interstitial.
                        if now - float(challenge_since) >= 25:
                            _raise_if_turnstile_page_blocked(
                                snap,
                                log_callback=log_callback,
                                stage=f"等待 token {snap.get('_t')}s",
                                kinds={"cloudflare_challenge"},
                            )
                    else:
                        challenge_since = None
                next_diag_at = now + 10

            time.sleep(1.0)

        if len(token) < 80:
            final_diag = _diagnose_turnstile_page(page)
            if isinstance(final_diag, dict):
                final_diag["_t"] = int(time.monotonic() - started)
                diag_samples.append(final_diag)
            summary = {
                "samples": len(diag_samples),
                "token_len_max": max([int(s.get("tokenLen") or 0) for s in diag_samples] or [0]),
                "sitekey_count_max": max([int(s.get("sitekeyCount") or 0) for s in diag_samples] or [0]),
                "has_cf_input_any": any(bool(s.get("hasCfInput")) for s in diag_samples),
                "turnstile_iframe_any": any(int(s.get("turnstileIframeCount") or 0) > 0 for s in diag_samples),
                "challenge_like_any": any(bool(s.get("challengeLike")) for s in diag_samples),
                "turnstile_error_last": str(
                    (diag_samples[-1] if diag_samples else {}).get("turnstileError") or ""
                ),
                "last": diag_samples[-1] if diag_samples else {},
            }
            _log(
                log_callback,
                "[Turnstile][diag] 失败摘要: "
                f"samples={summary['samples']} token_len_max={summary['token_len_max']} "
                f"sitekey_count_max={summary['sitekey_count_max']} "
                f"cf_input={summary['has_cf_input_any']} "
                f"ts_iframe={summary['turnstile_iframe_any']} "
                f"challenge={summary['challenge_like_any']} "
                f"ts_error={summary['turnstile_error_last'] or '-'}",
            )
            last_state = _classify_turnstile_page_state(diag_samples[-1] if diag_samples else {})
            challenge_error = str(summary.get("turnstile_error_last") or "").strip()
            if challenge_error:
                raise VerificationRequiredError(
                    f"Turnstile challenge error {challenge_error}"
                )
            if last_state.get("blocked"):
                raise VerificationRequiredError(str(last_state.get("message") or "Cloudflare blocked"))
            raise VerificationRequiredError(
                f"在 {timeout}s 内未捕获到可用 Turnstile token；"
                f"diag(sitekeys={summary.get('sitekey_count_max')}, "
                f"cfInput={summary.get('has_cf_input_any')}, "
                f"tsIframe={summary.get('turnstile_iframe_any')}, "
                f"challenge={summary.get('challenge_like_any')}, "
                f"state={last_state.get('kind')}, "
                f"title={(diag_samples[-1] or {}).get('title') if diag_samples else ''})"
            )

        observed_user_agent = ""
        observed_language = ""
        observed_platform = ""
        observed_client_hint_platform = ""
        observed_browser_major = ""
        try:
            observed = page.run_js(
                """
return (async () => {
  const uaData = navigator.userAgentData || null;
  let high = {};
  try {
    if (uaData && typeof uaData.getHighEntropyValues === 'function') {
      high = await uaData.getHighEntropyValues(['fullVersionList', 'platformVersion']);
    }
  } catch (_) {}
  return {
    userAgent: String(navigator.userAgent || ''),
    language: String(navigator.language || ''),
    platform: String(navigator.platform || ''),
    clientHintPlatform: String((uaData && uaData.platform) || ''),
    brands: (uaData && uaData.brands) || [],
    fullVersionList: high.fullVersionList || []
  };
})();
                """
            ) or {}
            if isinstance(observed, dict):
                observed_user_agent = str(observed.get("userAgent") or "").strip()
                observed_language = str(observed.get("language") or "").strip()
                observed_platform = str(observed.get("platform") or "").strip()
                observed_client_hint_platform = str(
                    observed.get("clientHintPlatform") or ""
                ).strip()
                version_match = re.search(r"Chrome/(\d+)", observed_user_agent)
                observed_browser_major = version_match.group(1) if version_match else ""
        except Exception:
            observed = {}
        if user_agent:
            _validate_local_fingerprint(
                expected_user_agent=user_agent,
                observed_user_agent=observed_user_agent,
                expected_language=accept_language,
                observed_language=observed_language,
                expected_platform=expected_platform,
                observed_platform=observed_platform,
                expected_client_hint_platform=expected_client_hint_platform,
                observed_client_hint_platform=observed_client_hint_platform,
                expected_browser_major=expected_browser_major,
                observed_browser_major=observed_browser_major,
            )

        if str(output or "").strip():
            out = Path(str(output).strip()).expanduser()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(token + "\n", encoding="utf-8")
            try:
                if os.name != "nt":
                    os.chmod(out, 0o600)
            except OSError:
                pass
            _log(log_callback, f"[Turnstile] token 已写入 {out} (len={len(token)})")
        else:
            _log(log_callback, f"[Turnstile] token 已捕获 (len={len(token)})")
        if proxy_used_file:
            proxy_out = Path(str(proxy_used_file)).expanduser()
            proxy_out.parent.mkdir(parents=True, exist_ok=True)
            proxy_out.write_text((selected_proxy_raw or proxy or "") + "\n", encoding="utf-8")
        if return_result:
            return SolveResult(
                token=token,
                provider="local",
                received_at=time.monotonic(),
                elapsed_ms=int((time.monotonic() - capture_started) * 1000),
                user_agent=observed_user_agent,
                user_agent_authoritative=True,
                proxy=proxy,
                action=action,
                cdata=cdata,
                extras={
                    "language": observed_language,
                    "platform": observed_platform,
                    "client_hint_platform": observed_client_hint_platform,
                    "browser_major": observed_browser_major,
                },
            )
        return token
    finally:
        _quit_turnstile_browser(browser, options)
        if forwarder_instance:
            try:
                from local_proxy_forwarder import stop_local_forwarder

                stop_local_forwarder(instance_key=forwarder_instance)
            except Exception:
                pass


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    previous_config_env = os.environ.get("XAI_CONFIG_PATH")
    config_env_overridden = False

    def logger(message: str) -> None:
        print(message, flush=True)

    try:
        proxy, selected_raw = _resolve_runtime_proxy(args)
        config: Dict[str, Any] = {}
        mail_config_value = str(getattr(args, "mail_config", "") or "").strip()
        if mail_config_value:
            mail_config_path = Path(mail_config_value).expanduser().resolve()
            config = json.loads(mail_config_path.read_text(encoding="utf-8"))
            os.environ["XAI_CONFIG_PATH"] = str(mail_config_path)
            config_env_overridden = True

        if args.command == "mail-probe":
            if args.mail_file:
                mailbox = MicrosoftGraphMailbox(
                    args.mail_file,
                    proxy=proxy,
                    timeout=args.timeout,
                    mark_used=bool(args.mark_used),
                )
            else:
                if not args.mail_config:
                    raise XAIHttpFlowError("mail-probe 需要 --mail-config 或 --mail-file")
                mailbox = build_mailbox(config=config, proxy=proxy, timeout=args.timeout)
            try:
                email, token = mailbox.create()
            except BaseException:
                if bool(getattr(args, "mark_used", False)):
                    try:
                        mailbox.release(reason="mail_probe_failed")
                    except Exception:
                        pass
                raise
            count = -1
            inbox_probe_ok = True
            try:
                if isinstance(mailbox, YydsTempMailbox):
                    messages = mailbox._messages(email, token)
                else:
                    messages = mailbox._messages(token)
                count = len(messages) if isinstance(messages, list) else 0
            except Exception as exc:
                inbox_probe_ok = False
                logger(f"[mail-probe] 收件箱探测警告: {_safe_error_text(exc)}")
            if bool(getattr(args, "mark_used", False)):
                if inbox_probe_ok:
                    commit = getattr(mailbox, "commit_success", None)
                    if callable(commit):
                        commit()
                else:
                    release = getattr(mailbox, "release", None)
                    if callable(release):
                        release(reason="mail_probe_inbox_failed")
            print(f"[+] mail-probe ok email={mask_email(email)} inbox_messages={count} token_len={len(token)}")
            return 0

        if args.command == "turnstile-capture":
            capture_turnstile_token(
                proxy=proxy,
                output=args.output,
                proxy_used_file=args.proxy_used_file,
                selected_proxy_raw=selected_raw,
                timeout=int(getattr(args, "wait_seconds", 0) or args.timeout or 180),
                headless=bool(args.headless),
                log_callback=logger,
            )
            print(
                "[+] Turnstile 已捕获。"
                "请尽快用同一代理执行 register，例如:\n"
                f'  python xai_http_flow.py register --proxy "{selected_raw or proxy}" '
                f"--turnstile-token-file {args.output} --mail-config "
                f"{Path(os.environ.get('XAI_CONFIG_PATH') or CONFIG_PATH).expanduser().resolve()} "
                f"--output-dir {CREDENTIALS_DIR}"
            )
            return 0

        client = BrowserlessXAIClient(proxy=proxy, timeout=args.timeout, log_callback=logger)
        # Prefer independent Turnstile proxy when provided; else reuse register upstream.
        dedicated_ts = str(getattr(args, "turnstile_proxy", "") or "").strip()
        if not dedicated_ts:
            try:
                from http_batch_service import pick_turnstile_proxy
                base_dir = None
                try:
                    mail_cfg = str(getattr(args, "mail_config", "") or "").strip()
                    if mail_cfg:
                        base_dir = Path(mail_cfg).expanduser().resolve().parent
                except Exception:
                    base_dir = None
                dedicated_ts = pick_turnstile_proxy(
                    config if isinstance(config, dict) else {},
                    base_dir=base_dir,
                )
            except Exception:
                dedicated_ts = ""
        if dedicated_ts:
            captcha_proxy = normalize_proxy(dedicated_ts) or dedicated_ts
            logger("[HTTP] Turnstile 使用独立求解代理")
        else:
            captcha_proxy = normalize_proxy(selected_raw) if selected_raw else proxy
        if args.command == "credential":
            sso = _secret_from(args.sso, args.sso_file, "XAI_SSO")
            sso_rw = ""
            if args.trace_session:
                trace = extract_trace_sso(args.trace_session)
                sso, sso_rw = trace.sso, trace.sso_rw
            if sso:
                client.import_sso(sso, sso_rw)
            else:
                turnstile = _secret_from(args.turnstile_token, args.turnstile_token_file, "XAI_TURNSTILE_TOKEN")
                castle = _secret_from(args.castle_token, args.castle_token_file, "XAI_CASTLE_TOKEN")
                if not turnstile:
                    page = client._request("get", SIGNIN_URL, allow_redirects=True)
                    client._assert_normal_page(page, "打开登录页")
                    metadata = client.challenge_metadata(str(getattr(page, "text", "") or ""))
                    sitekey = str(metadata.get("turnstile_sitekey") or "").strip()
                    turnstile = solve_turnstile_token(
                        sitekey=sitekey,
                        page_url=str(getattr(page, "url", "") or SIGNIN_URL),
                        provider=getattr(args, "turnstile_provider", "") or "",
                        api_key=getattr(args, "turnstile_api_key", "") or "",
                        proxy=captcha_proxy,
                        action=str(metadata.get("turnstile_action") or ""),
                        cdata=str(metadata.get("turnstile_cdata") or ""),
                        timeout=int(getattr(args, "turnstile_solve_timeout", 0) or 90),
                        headless=bool(getattr(args, "turnstile_headless", False)),
                        log_callback=logger,
                    )
                client.login_with_password(
                    email=args.email,
                    password=args.password or os.environ.get("XAI_PASSWORD", ""),
                    turnstile_token=turnstile,
                    castle_request_token=castle,
                )
            path = client.obtain_oauth_credential(output_dir=args.output_dir, email_hint=args.email)
            print(f"[+] 凭证已保存: {path}")
            return 0

        turnstile = _secret_from(args.turnstile_token, args.turnstile_token_file, "XAI_TURNSTILE_TOKEN")
        castle_email = _secret_from(
            args.castle_email_token,
            args.castle_email_token_file,
            "XAI_CASTLE_EMAIL_TOKEN",
        )
        castle_register = _secret_from(
            args.castle_register_token,
            args.castle_register_token_file,
            "XAI_CASTLE_REGISTER_TOKEN",
        )
        result = run_registration(
            client=client,
            email=args.email,
            email_code=args.email_code,
            mail_config_path=args.mail_config,
            mail_file=getattr(args, "mail_file", "") or "",
            castle_email_token=castle_email,
            castle_register_token=castle_register,
            turnstile_token=turnstile,
            turnstile_provider=getattr(args, "turnstile_provider", "") or "",
            turnstile_api_key=getattr(args, "turnstile_api_key", "") or "",
            turnstile_solve_timeout=int(getattr(args, "turnstile_solve_timeout", 0) or 90),
            turnstile_solve_retries=int(getattr(args, "turnstile_solve_retries", 0) or 1),
            turnstile_proxy=captcha_proxy,
            turnstile_headless=bool(getattr(args, "turnstile_headless", False)),
            turnstile_broker_url=getattr(args, "turnstile_broker_url", "") or "",
            turnstile_workers=int(getattr(args, "turnstile_workers", 0) or 0),
            turnstile_queue_size=int(getattr(args, "turnstile_queue_size", 64) or 64),
            submit_workers=int(getattr(args, "submit_workers", 4) or 4),
            given_name=args.given_name,
            family_name=args.family_name,
            password=args.password or os.environ.get("XAI_PASSWORD", ""),
            output_dir=args.output_dir,
            accounts_output=(
                args.accounts_output
                or str(ACCOUNTS_DIR / f"accounts_http_{time.strftime('%Y%m%d_%H%M%S')}.txt")
            ),
        )
        print(
            "[+] 注册与凭证获取完成: "
            f"email={mask_email(result.email)} cred={result.credential_path} accounts={result.account_path}"
        )
        return 0
    except XAIHttpFlowError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - CLI last-resort guard
        print(f"[!] 未处理异常: {_safe_error_text(exc)}", file=sys.stderr)
        return 3
    finally:
        if config_env_overridden:
            if previous_config_env is None:
                os.environ.pop("XAI_CONFIG_PATH", None)
            else:
                os.environ["XAI_CONFIG_PATH"] = previous_config_env


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

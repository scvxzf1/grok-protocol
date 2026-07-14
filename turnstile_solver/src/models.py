from __future__ import annotations

import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit


_COOKIE_KEYS = {"cookies", "browser_cookies", "cookie_jar"}
_PROXY_SECRET_KEYS = {
    "login",
    "password",
    "pass",
    "passwd",
    "pwd",
    "user",
    "username",
    "userinfo",
}
_AUTHENTICATED_PROXY_URL = re.compile(
    r"(?i)\b(?P<scheme>https?|socks4|socks5h?)://"
    r"[^@\s/'\"<>]+@"
    r"(?P<host>\[[^\]\s]+\]|[^:/\s,'\"<>]+)"
    r"(?::(?P<port>\d+))?"
)


def _proxy_endpoint(value: Any) -> str:
    """Return only scheme/host/port for a proxy URL, including bracketed IPv6."""

    text = str(value or "").strip()
    if not text:
        return ""
    if "://" not in text:
        parts = text.split(":")
        if len(parts) == 2:
            text = f"http://{text}"
        elif len(parts) == 4:
            text = f"http://{parts[0]}:{parts[1]}"
        else:
            return ""
    try:
        parsed = urlsplit(text)
        host = str(parsed.hostname or "")
        port = parsed.port
    except (TypeError, ValueError):
        return ""
    scheme = str(parsed.scheme or "").lower()
    if scheme not in {"http", "https", "socks4", "socks5", "socks5h"} or not host:
        return ""
    host_display = f"[{host}]" if ":" in host else host
    return f"{scheme}://{host_display}{f':{port}' if port is not None else ''}"


def _strip_authenticated_proxy_urls(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        scheme = str(match.group("scheme") or "").lower()
        host = str(match.group("host") or "")
        port = str(match.group("port") or "")
        return f"{scheme}://{host}{f':{port}' if port else ''}"

    return _AUTHENTICATED_PROXY_URL.sub(replace, str(value or ""))


def sanitize_public_payload(value: Any, *, proxy_context: bool = False) -> Any:
    """Remove browser cookies and proxy credentials from public solver payloads."""

    if isinstance(value, dict):
        payload: Dict[Any, Any] = {}
        for key, item in value.items():
            normalized_key = str(key).strip().lower().replace("-", "_")
            if normalized_key in _COOKIE_KEYS:
                continue
            child_proxy_context = proxy_context or "proxy" in normalized_key
            compact_key = normalized_key.replace("_", "")
            if child_proxy_context and any(
                secret in compact_key for secret in _PROXY_SECRET_KEYS
            ):
                continue
            payload[key] = sanitize_public_payload(
                item,
                proxy_context=child_proxy_context,
            )
        return payload
    if isinstance(value, list):
        return [sanitize_public_payload(item, proxy_context=proxy_context) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_public_payload(item, proxy_context=proxy_context) for item in value)
    if isinstance(value, str):
        cleaned = _strip_authenticated_proxy_urls(value)
        if proxy_context:
            endpoint = _proxy_endpoint(cleaned)
            if endpoint:
                return endpoint
        return cleaned
    return value


@dataclass(frozen=True)
class FingerprintSnapshot:
    """Browser-observed values that the HTTP submitter can keep aligned."""

    user_agent: str = ""
    user_agent_data: Dict[str, Any] = field(default_factory=dict)
    accept_language: str = ""
    navigator_language: str = ""
    navigator_languages: Tuple[str, ...] = ()
    platform: str = ""
    timezone: str = ""
    viewport: Dict[str, Any] = field(default_factory=dict)
    device_scale_factor: float = 1.0
    webdriver: Optional[bool] = None
    browser_major: Optional[int] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FingerprintSnapshot":
        data = data if isinstance(data, dict) else {}
        languages = tuple(str(x) for x in (data.get("navigator_languages") or []) if str(x))
        ua = str(data.get("user_agent") or "")
        major: Optional[int] = None
        try:
            marker = ua.split("Chrome/", 1)[1].split(".", 1)[0]
            major = int(marker)
        except (IndexError, TypeError, ValueError):
            pass
        webdriver = data.get("webdriver")
        return cls(
            user_agent=ua,
            user_agent_data=dict(data.get("user_agent_data") or {}),
            accept_language=str(data.get("accept_language") or ""),
            navigator_language=str(data.get("navigator_language") or ""),
            navigator_languages=languages,
            platform=str(data.get("platform") or ""),
            timezone=str(data.get("timezone") or ""),
            viewport=dict(data.get("viewport") or {}),
            device_scale_factor=float(data.get("device_scale_factor") or 1.0),
            webdriver=webdriver if isinstance(webdriver, bool) else None,
            browser_major=major,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_agent": self.user_agent,
            "user_agent_data": dict(self.user_agent_data),
            "accept_language": self.accept_language,
            "navigator_language": self.navigator_language,
            "navigator_languages": list(self.navigator_languages),
            "platform": self.platform,
            "timezone": self.timezone,
            "viewport": dict(self.viewport),
            "device_scale_factor": self.device_scale_factor,
            "webdriver": self.webdriver,
            "browser_major": self.browser_major,
        }


class TokenLeaseError(RuntimeError):
    pass


@dataclass
class TokenLease:
    """A short-lived, single-consumer lease for one successful token."""

    lease_id: str
    token: str
    issued_at_ms: int
    expires_at_ms: int
    proxy: str = ""
    affinity_id: str = ""
    fingerprint: FingerprintSnapshot = field(default_factory=FingerprintSnapshot)
    consumed_at_ms: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    @classmethod
    def issue(
        cls,
        token: str,
        *,
        ttl_sec: int = 240,
        proxy: str = "",
        affinity_id: str = "",
        fingerprint: Optional[FingerprintSnapshot] = None,
    ) -> "TokenLease":
        issued_at_ms = int(time.time() * 1000)
        return cls(
            lease_id=uuid.uuid4().hex,
            token=str(token or ""),
            issued_at_ms=issued_at_ms,
            expires_at_ms=issued_at_ms + max(1, int(ttl_sec)) * 1000,
            proxy=str(proxy or ""),
            affinity_id=str(affinity_id or ""),
            fingerprint=fingerprint or FingerprintSnapshot(),
        )

    def is_expired(self, now_ms: Optional[int] = None) -> bool:
        now = int(now_ms if now_ms is not None else time.time() * 1000)
        return now >= self.expires_at_ms

    def consume(self, now_ms: Optional[int] = None) -> str:
        now = int(now_ms if now_ms is not None else time.time() * 1000)
        with self._lock:
            if self.consumed_at_ms:
                raise TokenLeaseError("token lease already consumed")
            if now >= self.expires_at_ms:
                raise TokenLeaseError("token lease expired")
            self.consumed_at_ms = now
            return self.token

    def to_dict(self, *, include_token: bool = False) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "lease_id": self.lease_id,
            "issued_at_ms": self.issued_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "consumed_at_ms": self.consumed_at_ms,
            "proxy": self.proxy,
            "affinity_id": self.affinity_id,
            "fingerprint": self.fingerprint.to_dict(),
        }
        if include_token:
            payload["token"] = self.token
        return sanitize_public_payload(payload)


@dataclass
class SolveRequest:
    provider: str = "local"
    api_key: str = field(default="", repr=False)
    proxy: str = ""
    page_url: str = ""
    timeout_sec: int = 30
    headless: bool = False
    user_agent: str = ""
    accept_language: str = ""
    expected_platform: str = ""
    expected_client_hint_platform: str = ""
    expected_browser_major: int = 0
    sitekey: str = ""
    action: str = ""
    cdata: str = ""
    diagnose: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SolveResult:
    ok: bool
    provider: str = "local"
    token: str = ""
    proxy: str = ""
    page_url: str = ""
    user_agent: str = ""
    elapsed_ms: int = 0
    error: str = ""
    extras: Dict[str, Any] = field(default_factory=dict)
    fingerprint: Optional[FingerprintSnapshot] = None
    lease: Optional[TokenLease] = None

    def to_dict(self, *, include_token: bool = True) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "ok": self.ok,
            "provider": self.provider,
            "token": self.token if include_token else "",
            "proxy": self.proxy,
            "page_url": self.page_url,
            "user_agent": self.user_agent,
            "elapsed_ms": self.elapsed_ms,
        }
        if self.error:
            payload["error"] = self.error
        if self.extras:
            payload["extras"] = self.extras
        if self.fingerprint is not None:
            payload["fingerprint"] = self.fingerprint.to_dict()
        if self.lease is not None:
            payload["lease"] = self.lease.to_dict(include_token=False)
        return sanitize_public_payload(payload)


@dataclass
class PoolStats:
    max_concurrency: int = 1
    active_workers: int = 0
    completed: int = 0
    failed: int = 0
    last_error: str = ""
    ready_slots: int = 0
    busy_slots: int = 0
    starting_slots: int = 0
    recycling_slots: int = 0
    queue_depth: int = 0
    affinity_count: int = 0
    browser_starts: int = 0
    browser_restarts: int = 0
    recycle_reasons: Dict[str, int] = field(default_factory=dict)
    retry_attempts: int = 0
    retry_successes: int = 0
    failure_categories: Dict[str, int] = field(default_factory=dict)
    last_failure_category: str = ""
    last_error_code: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_public_payload({
            "max_concurrency": self.max_concurrency,
            "active_workers": self.active_workers,
            "completed": self.completed,
            "failed": self.failed,
            "last_error": self.last_error,
            "ready_slots": self.ready_slots,
            "busy_slots": self.busy_slots,
            "starting_slots": self.starting_slots,
            "recycling_slots": self.recycling_slots,
            "queue_depth": self.queue_depth,
            "affinity_count": self.affinity_count,
            "browser_starts": self.browser_starts,
            "browser_restarts": self.browser_restarts,
            "recycle_reasons": dict(self.recycle_reasons),
            "retry_attempts": self.retry_attempts,
            "retry_successes": self.retry_successes,
            "failure_categories": dict(self.failure_categories),
            "last_failure_category": self.last_failure_category,
            "last_error_code": self.last_error_code,
        })

"""Shared asynchronous Turnstile scheduling primitives.

The broker owns a background event loop so synchronous registration callers can
share provider limits without blocking that loop.  Solver adapters remain
injectable; async adapters should use the supplied sleep callable while polling.
"""

from __future__ import annotations

import atexit
import asyncio
import concurrent.futures
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional

# Local browser solves also wait on a cross-process Chrome slot.  That admission
# wait must not be cancelled by the per-solve budget, otherwise high concurrency
# surfaces as an empty asyncio.TimeoutError right at the configured timeout.


def _local_solve_admission_grace_sec() -> int:
    raw = str(os.environ.get("XAI_LOCAL_TURNSTILE_LOCK_TIMEOUT_SEC") or "120").strip()
    try:
        value = int(float(raw))
    except (TypeError, ValueError):
        value = 120
    return max(30, value)


_LOCAL_SOLVE_ADMISSION_GRACE_SEC = _local_solve_admission_grace_sec()


@dataclass(frozen=True)
class FingerprintProfile:
    profile_id: str
    impersonate: str
    user_agent: str
    accept_language: str = "zh-CN,zh;q=0.9,en;q=0.8"
    navigator_platform: str = ""
    client_hint_platform: str = ""
    browser_major: str = "136"
    sec_ch_ua: str = (
        '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"'
    )


def _normalize_browser_major(value: object, *, default: str = "136") -> str:
    text = str(value or "").strip()
    if not text:
        return str(default)
    if "." in text:
        text = text.split(".", 1)[0]
    if not text.isdigit():
        return str(default)
    major = int(text)
    if major <= 0:
        return str(default)
    return str(major)


def build_chrome_brand_version_list(
    browser_version: object,
    *,
    full_version: bool = False,
    product_brand: str = "Google Chrome",
) -> list[tuple[str, str]]:
    """Reproduce Chromium's major-seeded UA-CH GREASE/list ordering."""

    raw = str(browser_version or "").strip()
    if not raw:
        raise ValueError("browser_version is required")
    try:
        major = int(raw.split(".", 1)[0])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid browser_version: {raw!r}") from exc
    if major <= 0:
        raise ValueError(f"invalid browser_version: {raw!r}")

    grease_chars = (" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_")
    grease_versions = ("8", "99", "24")
    grease_brand = (
        f"Not{grease_chars[major % len(grease_chars)]}"
        f"A{grease_chars[(major + 1) % len(grease_chars)]}Brand"
    )
    grease_version = grease_versions[major % len(grease_versions)]
    if full_version:
        grease_version = f"{grease_version}.0.0.0"
        chrome_version = raw if raw.count(".") == 3 else f"{major}.0.0.0"
    else:
        chrome_version = str(major)

    values = [(grease_brand, grease_version), ("Chromium", chrome_version)]
    brand = str(product_brand or "").strip()
    if brand:
        values.append((brand, chrome_version))

    if len(values) == 2:
        order = (major % 2, (major + 1) % 2)
    else:
        orders = (
            (0, 1, 2),
            (0, 2, 1),
            (1, 0, 2),
            (1, 2, 0),
            (2, 0, 1),
            (2, 1, 0),
        )
        order = orders[major % len(orders)]
    shuffled: list[tuple[str, str]] = [("", "")] * len(values)
    for index, target in enumerate(order):
        shuffled[target] = values[index]
    return shuffled


def serialize_sec_ch_ua(browser_version: object) -> str:
    return ", ".join(
        f'"{brand}";v="{version}"'
        for brand, version in build_chrome_brand_version_list(browser_version)
    )


def _supported_curl_cffi_impersonate_names() -> list[str]:
    """Return impersonate targets actually supported by the installed curl_cffi."""
    names: list[str] = []
    try:
        from curl_cffi.requests.impersonate import BrowserType, DEFAULT_CHROME

        for member in BrowserType:
            value = str(getattr(member, "value", member)).strip()
            # Skip aliases like plain "chrome" until the end.
            if value and value not in names and value not in {"chrome", "edge", "safari", "firefox"}:
                names.append(value)
        default = str(DEFAULT_CHROME or "").strip()
        if default and default not in names:
            names.append(default)
        for alias in ("chrome", "chrome136", "chrome142"):
            if alias not in names:
                names.append(alias)
    except Exception:
        names = ["chrome142", "chrome136", "chrome131", "chrome124", "chrome120", "chrome"]
    return names


def _impersonate_is_usable(name: str) -> bool:
    """True only if curl_cffi can actually apply this impersonate target.

    Important: some curl_cffi builds accept Curl.impersonate("chrome142") but
    still raise ImpersonateError when Session(...).get/post runs. Probe both.
    """
    target = str(name or "").strip()
    if not target:
        return False
    try:
        from curl_cffi import Curl
        from curl_cffi.requests import Session
        from curl_cffi.requests.impersonate import normalize_browser_type

        normalized = normalize_browser_type(target)
        curl = Curl()
        try:
            curl.impersonate(normalized)
        finally:
            try:
                curl.close()
            except Exception:
                pass

        # Session construction alone is not enough on some versions; force the
        # impersonate path to materialize by creating a session and performing a
        # no-network prepare/open cycle when possible.
        session = Session(impersonate=target)
        try:
            # Prefer a cheap internal check if available.
            impersonate_attr = getattr(session, "impersonate", None)
            if impersonate_attr is not None and str(impersonate_attr).strip() == "":
                return False
            # Trigger the same code path used by real HTTP calls without network
            # when curl_cffi exposes request preparation helpers; otherwise do a
            # localhost connection that fails fast if impersonate is invalid.
            request = getattr(session, "request", None)
            if callable(request):
                try:
                    request("GET", "http://127.0.0.1:9/", timeout=0.05)
                except Exception as exc:
                    msg = str(exc or "").lower()
                    if "impersonat" in msg and "not supported" in msg:
                        return False
                    # Connection errors mean impersonate was accepted.
            return True
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass
    except Exception as exc:
        msg = str(exc or "").lower()
        if "impersonat" in msg:
            return False
        return False


def _impersonate_for_browser_major(major: str) -> str:
    """Pick a curl_cffi impersonate target closest to the real Chrome major."""
    try:
        major_i = int(str(major).strip() or "136")
    except ValueError:
        major_i = 136

    # Map installed Chrome major -> preferred impersonate ladder.
    # Names must exist in the installed curl_cffi BrowserType set.
    preferred_by_bucket = (
        (148, ("chrome142", "chrome136", "chrome133a", "chrome131")),
        (142, ("chrome142", "chrome136", "chrome133a", "chrome131")),
        (136, ("chrome136", "chrome133a", "chrome131", "chrome124")),
        (133, ("chrome133a", "chrome131", "chrome124", "chrome120")),
        (131, ("chrome131", "chrome124", "chrome120")),
        (124, ("chrome124", "chrome120", "chrome116")),
        (120, ("chrome120", "chrome116", "chrome")),
    )
    candidates: list[str] = []
    for bucket, names in preferred_by_bucket:
        if bucket <= major_i:
            candidates.extend(names)
    if not candidates:
        candidates = list(preferred_by_bucket[-1][1])

    supported = set(_supported_curl_cffi_impersonate_names())
    # Prefer preferred names that are both listed and actually usable.
    seen = set()
    ordered: list[str] = []
    for name in candidates:
        if name in seen:
            continue
        seen.add(name)
        ordered.append(name)
    # Then any remaining supported chrome* profiles as a last resort.
    for name in sorted(supported, reverse=True):
        if name.startswith("chrome") and name not in seen:
            ordered.append(name)
            seen.add(name)

    for name in ordered:
        if name in supported or name == "chrome":
            if _impersonate_is_usable(name):
                return name
    # Absolute fallback: never return an unsupported chrome148-like value.
    for name in ("chrome136", "chrome131", "chrome124", "chrome120", "chrome142", "chrome"):
        if _impersonate_is_usable(name):
            return name
    return "chrome"


def build_canonical_fingerprint_profile(
    platform_name: str = "",
    *,
    browser_major: object = None,
) -> FingerprintProfile:
    """Return the Chrome profile shared by HTTP and local solver paths.

    browser_major: optional major version (e.g. 148). Defaults to 136 for a
    stable unit-test/default profile. Runtime callers should pass the installed
    Chrome major so local Turnstile and HTTP session stay aligned.
    """

    runtime = str(platform_name or sys.platform or "").strip().lower()
    if runtime.startswith("linux"):
        profile_suffix = "linux"
        ua_platform = "X11; Linux x86_64"
        navigator_platform = "Linux x86_64"
        client_hint_platform = "Linux"
    elif runtime.startswith("win") or runtime in {"cygwin", "msys"}:
        profile_suffix = "windows"
        ua_platform = "Windows NT 10.0; Win64; x64"
        navigator_platform = "Win32"
        client_hint_platform = "Windows"
    elif runtime == "darwin":
        profile_suffix = "macos"
        ua_platform = "Macintosh; Intel Mac OS X 10_15_7"
        navigator_platform = "MacIntel"
        client_hint_platform = "macOS"
    else:
        raise RuntimeError(f"canonical Chrome fingerprint does not support platform: {runtime!r}")
    major = _normalize_browser_major(browser_major, default="136")
    impersonate = _impersonate_for_browser_major(major)
    return FingerprintProfile(
        profile_id=f"curl-{impersonate}-{profile_suffix}",
        impersonate=impersonate,
        user_agent=(
            f"Mozilla/5.0 ({ua_platform}) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{major}.0.0.0 Safari/537.36"
        ),
        accept_language="zh-CN,zh;q=0.9,en;q=0.8",
        navigator_platform=navigator_platform,
        client_hint_platform=client_hint_platform,
        browser_major=major,
        sec_ch_ua=serialize_sec_ch_ua(major),
    )


@dataclass(frozen=True)
class SolveRequest:
    provider: str
    sitekey: str
    page_url: str
    api_key: str = field(default="", repr=False)
    proxy: str = ""
    action: str = ""
    cdata: str = ""
    timeout_sec: int = 30
    headless: bool = False
    fingerprint: Optional[FingerprintProfile] = None
    broker_url: str = ""


@dataclass
class SolveResult:
    token: str
    provider: str
    received_at: float
    elapsed_ms: int
    user_agent: str = ""
    user_agent_authoritative: bool = False
    proxy: str = ""
    action: str = ""
    cdata: str = ""
    extras: Dict[str, Any] = field(default_factory=dict)


class TokenLeaseError(RuntimeError):
    pass


@dataclass
class TokenLease:
    result: SolveResult
    ttl_sec: float = 240.0
    consumed: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    @property
    def expires_at(self) -> float:
        return float(self.result.received_at) + float(self.ttl_sec)

    def age(self, now: Optional[float] = None) -> float:
        current = time.monotonic() if now is None else float(now)
        return max(0.0, current - float(self.result.received_at))

    def consume(self, now: Optional[float] = None) -> str:
        current = time.monotonic() if now is None else float(now)
        with self._lock:
            if self.consumed:
                raise TokenLeaseError("Turnstile token lease has already been consumed")
            if current >= self.expires_at:
                raise TokenLeaseError("Turnstile token lease has expired")
            self.consumed = True
            return str(self.result.token or "").strip()


AsyncSleep = Callable[[float], Awaitable[None]]
AsyncSolver = Callable[[SolveRequest, AsyncSleep], Awaitable[SolveResult]]


class BrokerQueueFull(RuntimeError):
    pass


class TurnstileBroker:
    """Provider-scoped concurrency and bounded admission on one async loop."""

    def __init__(
        self,
        *,
        provider_limits: Optional[Dict[str, int]] = None,
        queue_limit: int = 64,
        sleep: AsyncSleep = asyncio.sleep,
    ) -> None:
        self.provider_limits = {
            str(key): max(1, int(value))
            for key, value in (provider_limits or {}).items()
        }
        self.queue_limit = max(1, int(queue_limit))
        self.sleep = sleep
        self._thread_lock = threading.Lock()
        self._ready = threading.Event()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        # Retain the loop published for the current startup generation until a
        # later generation begins. close() may clear _loop while a concurrent
        # _ensure_loop() caller is still waking from _ready.
        self._published_loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._provider_slots: Dict[str, asyncio.Semaphore] = {}
        self._pending = 0
        self._pending_lock: Optional[asyncio.Lock] = None
        self._closed = False

    @property
    def closed(self) -> bool:
        with self._thread_lock:
            return self._closed

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        with self._thread_lock:
            if self._closed:
                raise RuntimeError("Turnstile broker is closed")
            if self._loop is not None and self._loop.is_running():
                return self._loop
            if self._thread is None or not self._thread.is_alive():
                self._ready.clear()
                self._published_loop = None

                def run() -> None:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    with self._thread_lock:
                        if self._closed:
                            self._ready.set()
                            loop.close()
                            return
                        self._loop = loop
                        self._published_loop = loop
                        self._pending_lock = asyncio.Lock()
                        self._ready.set()
                    try:
                        loop.run_forever()
                    finally:
                        pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
                        for task in pending:
                            task.cancel()
                        if pending:
                            loop.run_until_complete(
                                asyncio.gather(*pending, return_exceptions=True)
                            )
                        loop.close()
                        with self._thread_lock:
                            if self._loop is loop:
                                self._loop = None
                            if self._thread is threading.current_thread():
                                self._thread = None

                self._thread = threading.Thread(
                    target=run,
                    name="turnstile-broker",
                    daemon=True,
                )
                self._thread.start()
        self._ready.wait(timeout=5.0)
        with self._thread_lock:
            loop = self._loop or self._published_loop
            closed = self._closed
        if loop is None:
            if closed:
                raise RuntimeError("Turnstile broker is closed")
            raise RuntimeError("Turnstile broker event loop failed to start")
        # _submit() performs the final closed check while holding the same lock
        # used by close(), which makes scheduling linearizable.
        return loop

    async def _solve_on_loop(
        self,
        request: SolveRequest,
        solver: AsyncSolver,
        deadline: float,
    ) -> SolveResult:
        assert self._pending_lock is not None
        async with self._pending_lock:
            if self._pending >= self.queue_limit:
                raise BrokerQueueFull(
                    f"Turnstile broker queue is full ({self.queue_limit})"
                )
            self._pending += 1
        semaphore: Optional[asyncio.Semaphore] = None
        acquired = False
        try:
            provider = str(request.provider or "").strip().lower()
            semaphore = self._provider_slots.get(provider)
            if semaphore is None:
                semaphore = asyncio.Semaphore(self.provider_limits.get(provider, 1))
                self._provider_slots[provider] = semaphore
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError(
                    "Turnstile broker 排队超时（deadline expired in queue）"
                )
            try:
                await asyncio.wait_for(semaphore.acquire(), timeout=remaining)
            except asyncio.TimeoutError as exc:
                raise asyncio.TimeoutError(
                    "Turnstile broker 排队超时（waiting for provider slot）"
                ) from exc
            acquired = True
            current_task = asyncio.current_task()
            cancelling = getattr(current_task, "cancelling", None)
            if callable(cancelling) and cancelling():
                raise asyncio.CancelledError
            # Local browser capture enforces its own token-wait timeout and may
            # first block on the cross-process Chrome slot.  Do not wrap it in a
            # second wait_for equal only to timeout_sec — that cancels slot wait
            # with an empty TimeoutError under concurrency.
            if provider == "local":
                return await solver(request, self.sleep)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError(
                    "Turnstile broker 求解超时（deadline expired before solve）"
                )
            try:
                return await asyncio.wait_for(
                    solver(request, self.sleep),
                    timeout=remaining,
                )
            except asyncio.TimeoutError as exc:
                budget = max(1, int(request.timeout_sec or 0) or int(remaining) or 1)
                raise asyncio.TimeoutError(
                    f"Turnstile broker 求解超时（{budget}s budget exhausted during solve）"
                ) from exc
        finally:
            if acquired and semaphore is not None:
                semaphore.release()
            async with self._pending_lock:
                self._pending = max(0, self._pending - 1)

    def _submit(self, request: SolveRequest, solver: AsyncSolver) -> concurrent.futures.Future[SolveResult]:
        loop = self._ensure_loop()
        # Admission/queue deadline stays tied to timeout_sec. Local browser
        # execution after the provider slot is acquired is intentionally not
        # cancelled by this same deadline (see _solve_on_loop).
        deadline = time.monotonic() + max(1, int(request.timeout_sec or 180))
        coroutine = self._solve_on_loop(request, solver, deadline)
        with self._thread_lock:
            if self._closed:
                coroutine.close()
                raise RuntimeError("Turnstile broker is closed")
            try:
                return asyncio.run_coroutine_threadsafe(coroutine, loop)
            except Exception:
                coroutine.close()
                raise

    async def solve(self, request: SolveRequest, solver: AsyncSolver) -> SolveResult:
        return await asyncio.wrap_future(self._submit(request, solver))

    def solve_sync(self, request: SolveRequest, solver: AsyncSolver) -> SolveResult:
        future = self._submit(request, solver)
        budget = max(1, int(request.timeout_sec or 180))
        provider = str(request.provider or "").strip().lower()
        # Local path may spend up to the cross-process slot grace waiting for a
        # browser seat before the actual token wait begins.
        if provider == "local":
            outer_timeout = max(6, budget + _LOCAL_SOLVE_ADMISSION_GRACE_SEC + 15)
        else:
            outer_timeout = max(6, budget + 5)
        try:
            return future.result(timeout=outer_timeout)
        except concurrent.futures.TimeoutError as exc:
            future.cancel()
            raise TimeoutError(
                f"Turnstile broker 同步等待超时（{outer_timeout}s）"
            ) from exc

    def close(self) -> None:
        with self._thread_lock:
            self._closed = True
            loop = self._loop
            thread = self._thread

        if loop is not None:
            if loop.is_running() and thread is not threading.current_thread():
                async def cancel_pending() -> None:
                    current = asyncio.current_task()
                    pending = [
                        task
                        for task in asyncio.all_tasks()
                        if task is not current and not task.done()
                    ]
                    for task in pending:
                        task.cancel()
                    if pending:
                        await asyncio.gather(*pending, return_exceptions=True)

                shutdown = asyncio.run_coroutine_threadsafe(cancel_pending(), loop)
                try:
                    shutdown.result(timeout=5.0)
                except Exception:
                    shutdown.cancel()
            # Queue stop even after ready was published but before run_forever()
            # entered. call_soon_threadsafe is safe in both states and makes a
            # repeated close retry useful if a previous join timed out.
            try:
                loop.call_soon_threadsafe(loop.stop)
            except RuntimeError:
                pass
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5.0)


_SHARED: Dict[tuple, TurnstileBroker] = {}
_SHARED_LOCK = threading.Lock()


def get_shared_broker(*, provider: str, workers: int, queue_limit: int) -> TurnstileBroker:
    key = (str(provider or "").lower(), max(1, int(workers)), max(1, int(queue_limit)))
    with _SHARED_LOCK:
        broker = _SHARED.get(key)
        if broker is None or broker.closed:
            broker = TurnstileBroker(
                provider_limits={key[0]: key[1]},
                queue_limit=key[2],
            )
            _SHARED[key] = broker
        return broker


def close_shared_brokers() -> None:
    with _SHARED_LOCK:
        brokers = list(_SHARED.values())
        _SHARED.clear()
    for broker in brokers:
        broker.close()


atexit.register(close_shared_brokers)

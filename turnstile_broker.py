"""Shared asynchronous Turnstile scheduling primitives.

The broker owns a background event loop so synchronous registration callers can
share provider limits without blocking that loop.  Solver adapters remain
injectable; async adapters should use the supplied sleep callable while polling.
"""

from __future__ import annotations

import atexit
import asyncio
import concurrent.futures
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional


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
        '"Not.A/Brand";v="99", "Chromium";v="136"'
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


def _impersonate_for_browser_major(major: str) -> str:
    """Pick a curl_cffi impersonate target closest to the real Chrome major."""
    try:
        major_i = int(str(major).strip() or "136")
    except ValueError:
        major_i = 136
    # Prefer exact-ish profiles available in modern curl_cffi builds.
    ordered = (
        (148, ("chrome148", "chrome142", "chrome136")),
        (142, ("chrome142", "chrome136", "chrome133a")),
        (136, ("chrome136", "chrome133a", "chrome131")),
        (133, ("chrome133a", "chrome131", "chrome124")),
        (131, ("chrome131", "chrome124", "chrome120")),
        (124, ("chrome124", "chrome120")),
        (120, ("chrome120", "chrome116", "chrome")),
    )
    # Choose the nearest profile bucket not newer than major when possible.
    candidates = []
    for bucket, names in ordered:
        if bucket <= major_i:
            candidates.extend(names)
    if not candidates:
        candidates = list(ordered[-1][1])
    # Deduplicate while preserving order.
    seen = set()
    uniq = []
    for name in candidates:
        if name in seen:
            continue
        seen.add(name)
        uniq.append(name)
    # Validate against installed curl_cffi if possible; fall back gracefully.
    try:
        from curl_cffi.requests import Session

        for name in uniq:
            try:
                Session(impersonate=name)
                return name
            except Exception:
                continue
    except Exception:
        pass
    return uniq[0] if uniq else "chrome136"


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
        sec_ch_ua=f'"Not.A/Brand";v="99", "Chromium";v="{major}"',
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
    timeout_sec: int = 180
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

                def run() -> None:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    with self._thread_lock:
                        if self._closed:
                            self._ready.set()
                            loop.close()
                            return
                        self._loop = loop
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
            loop = self._loop
            closed = self._closed
        if closed:
            raise RuntimeError("Turnstile broker is closed")
        if loop is None:
            raise RuntimeError("Turnstile broker event loop failed to start")
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
                raise asyncio.TimeoutError("Turnstile broker deadline expired in queue")
            await asyncio.wait_for(semaphore.acquire(), timeout=remaining)
            acquired = True
            current_task = asyncio.current_task()
            cancelling = getattr(current_task, "cancelling", None)
            if callable(cancelling) and cancelling():
                raise asyncio.CancelledError
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError("Turnstile broker deadline expired before solve")
            return await asyncio.wait_for(
                solver(request, self.sleep),
                timeout=remaining,
            )
        finally:
            if acquired and semaphore is not None:
                semaphore.release()
            async with self._pending_lock:
                self._pending = max(0, self._pending - 1)

    def _submit(self, request: SolveRequest, solver: AsyncSolver) -> concurrent.futures.Future[SolveResult]:
        loop = self._ensure_loop()
        deadline = time.monotonic() + max(1, int(request.timeout_sec or 180))
        return asyncio.run_coroutine_threadsafe(
            self._solve_on_loop(request, solver, deadline),
            loop,
        )

    async def solve(self, request: SolveRequest, solver: AsyncSolver) -> SolveResult:
        return await asyncio.wrap_future(self._submit(request, solver))

    def solve_sync(self, request: SolveRequest, solver: AsyncSolver) -> SolveResult:
        future = self._submit(request, solver)
        try:
            return future.result(timeout=max(6, int(request.timeout_sec or 180) + 5))
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise

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

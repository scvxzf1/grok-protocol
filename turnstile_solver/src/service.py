from __future__ import annotations

import threading
import time
from typing import Optional

from .config import SolverConfig, load_config
from .external_providers import solve_external
from .models import SolveRequest, SolveResult, TokenLease, TokenLeaseError
from .pool import WorkerPool
from .submit_permits import SubmitPermit, SubmitPermitRegistry


def _close_root_shared_brokers() -> None:
    """The solver package also runs standalone, so the root broker is optional."""
    try:
        from turnstile_broker import close_shared_brokers
    except (ImportError, AttributeError):
        return
    try:
        close_shared_brokers()
    except Exception:
        # Shutdown must continue even when an optional root integration is absent/broken.
        pass


class SolverService:
    def __init__(self, config: Optional[SolverConfig] = None):
        self.config = config or SolverConfig()
        self.pool = WorkerPool(self.config)
        self._lease_lock = threading.Lock()
        self._leases: dict[str, TokenLease] = {}
        self.submit_permits = SubmitPermitRegistry(
            self.config.submit_workers,
            lease_sec=self.config.submit_permit_lease_sec,
        )
        self._close_lock = threading.Lock()
        self._closed = False

    @classmethod
    def from_config_path(cls, path: Optional[str] = None) -> "SolverService":
        return cls(load_config(path))

    def health(self) -> dict:
        self._sweep_leases()
        with self._lease_lock:
            active_leases = sum(1 for lease in self._leases.values() if not lease.consumed_at_ms)
        return {
            "ok": True,
            "service": "turnstile_solver",
            "version": "0.1.0",
            "config": {
                "host": self.config.host,
                "port": self.config.port,
                "max_concurrency": self.config.max_concurrency,
                "headless": self.config.headless,
                "signup_url": self.config.signup_url,
                "browser_solve_max_attempts": self.config.browser_solve_max_attempts,
                "browser_retry_backoff_sec": self.config.browser_retry_backoff_sec,
            },
            "pool": self.pool.stats.to_dict(),
            "leases": {
                "active": active_leases,
                "tracked": len(self._leases),
                "ttl_sec": self.config.lease_ttl_sec,
            },
            "submit_permits": self.submit_permits.stats(),
        }

    def start(self) -> None:
        self.pool.start()

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        try:
            self.submit_permits.close()
        finally:
            try:
                self.pool.close()
            finally:
                _close_root_shared_brokers()

    def acquire_submit_permit(self, timeout_sec: int, lease_sec: int = 0) -> SubmitPermit:
        return self.submit_permits.acquire(timeout_sec, lease_sec)

    def release_submit_permit(self, permit_id: str) -> dict:
        return self.submit_permits.release(permit_id)

    def _sweep_leases(self) -> None:
        now_ms = int(time.time() * 1000)
        with self._lease_lock:
            stale = [
                lease_id
                for lease_id, lease in self._leases.items()
                if lease.is_expired(now_ms) or bool(lease.consumed_at_ms)
            ]
            for lease_id in stale:
                self._leases.pop(lease_id, None)

    def consume_lease(self, lease_id: str) -> TokenLease:
        with self._lease_lock:
            lease = self._leases.get(str(lease_id or ""))
        if lease is None:
            raise TokenLeaseError("token lease not found")
        lease.consume()
        return lease

    def solve(self, request: SolveRequest) -> SolveResult:
        if not request.page_url:
            request.page_url = self.config.signup_url
        if request.timeout_sec <= 0:
            request.timeout_sec = self.config.browser_timeout_sec
        provider = str(request.provider or "local").strip().lower() or "local"
        if provider == "local":
            result = self.pool.solve(request)
            result.provider = "local"
        else:
            result = solve_external(request, self.config)
        if result.ok:
            result.extras = dict(result.extras or {})
            result.extras.pop("token_len", None)
            result.extras.pop("cookies", None)
            result.extras["token_length"] = len(result.token)
            lease = TokenLease.issue(
                result.token,
                ttl_sec=self.config.lease_ttl_sec,
                proxy=result.proxy,
                affinity_id=str((result.extras or {}).get("affinity_id") or ""),
                fingerprint=result.fingerprint,
            )
            result.lease = lease
            with self._lease_lock:
                self._leases[lease.lease_id] = lease
            self._sweep_leases()
        return result

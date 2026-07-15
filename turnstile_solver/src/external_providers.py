from __future__ import annotations

import asyncio
import ipaddress
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .config import SolverConfig
from .models import SolveRequest, SolveResult
from .proxy import ProxySpec, parse_proxy

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from turnstile_broker import (  # noqa: E402
    SolveRequest as BrokerSolveRequest,
    SolveResult as BrokerSolveResult,
    get_shared_broker,
)


class ExternalProviderError(RuntimeError):
    pass


_PROVIDERS: Dict[str, Dict[str, str]] = {
    "capsolver": {
        "base_url": "https://api.capsolver.com",
        "proxyless_task_type": "AntiTurnstileTaskProxyLess",
        "proxy_task_type": "AntiTurnstileTask",
    },
    "2captcha": {
        "base_url": "https://api.2captcha.com",
        "proxyless_task_type": "TurnstileTaskProxyless",
        "proxy_task_type": "TurnstileTask",
    },
    "yescaptcha": {
        "base_url": "https://api.yescaptcha.com",
        "proxyless_task_type": "TurnstileTaskProxyless",
        "proxy_task_type": "TurnstileTaskProxylessM1",
    },
}


def _is_local_proxy_host(host: str) -> bool:
    value = str(host or "").strip().strip("[]").rstrip(".").lower()
    if value in {"localhost", "localhost.localdomain"}:
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_unspecified
    )


def _resolve_provider_proxy(proxy: str, provider: str) -> Tuple[Optional[ProxySpec], str]:
    """Return an externally reachable provider proxy without exposing it in errors."""

    if not str(proxy or "").strip():
        return None, "proxyless"
    try:
        spec = parse_proxy(proxy)
    except (TypeError, ValueError) as exc:
        raise ExternalProviderError("external provider proxy is invalid") from exc
    if not spec.enabled or not spec.host or not spec.port:
        raise ExternalProviderError("external provider proxy is invalid")
    try:
        port = int(spec.port)
    except (TypeError, ValueError) as exc:
        raise ExternalProviderError("external provider proxy is invalid") from exc
    if not 1 <= port <= 65535:
        raise ExternalProviderError("external provider proxy is invalid")
    if _is_local_proxy_host(spec.host):
        return None, "proxyless_local_ignored"

    allowed_schemes = {
        "capsolver": {"http", "https", "socks4", "socks5"},
        "2captcha": {"http", "https", "socks4", "socks5"},
        "yescaptcha": {"http", "https", "socks5"},
    }
    if spec.scheme not in allowed_schemes.get(provider, set()):
        raise ExternalProviderError(f"{provider} proxy scheme is unsupported")
    if provider == "yescaptcha" and spec.scheme == "socks5" and (
        spec.username or spec.password
    ):
        raise ExternalProviderError("yescaptcha authenticated socks5 proxy is unsupported")
    return spec, "provider"


def _proxy_display(spec: Optional[ProxySpec]) -> str:
    if spec is None:
        return ""
    host = f"[{spec.host}]" if ":" in spec.host else spec.host
    return f"{spec.scheme}://{host}:{spec.port}"


def _safe_external_error(exc: Exception) -> str:
    if isinstance(exc, ExternalProviderError):
        return str(exc) or "external provider request failed"
    return f"external provider solve failed ({type(exc).__name__})"


def _post_json(url: str, payload: Dict[str, Any], timeout_sec: int) -> Dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=max(5, min(30, int(timeout_sec)))) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        raise ExternalProviderError(
            f"external provider HTTP request failed ({type(exc).__name__})"
        ) from exc
    if not isinstance(data, dict):
        raise ExternalProviderError("external provider returned a non-object response")
    if int(data.get("errorId") or 0):
        code = str(data.get("errorCode") or "provider_error")
        # Provider descriptions are untrusted and may echo submitted proxy data.
        raise ExternalProviderError(f"external provider error: {code}")
    return data


def _build_task(request: BrokerSolveRequest, provider: str) -> Dict[str, Any]:
    spec = _PROVIDERS[provider]
    provider_proxy, _proxy_mode = _resolve_provider_proxy(request.proxy, provider)
    task: Dict[str, Any] = {
        "type": spec["proxyless_task_type"],
        "websiteURL": request.page_url,
        "websiteKey": request.sitekey,
    }
    # CapSolver's current integration stays on its proxyless task contract;
    # forwarding registration proxy credentials here would widen secret scope.
    if provider != "capsolver" and provider_proxy is not None and spec.get("proxy_task_type"):
        task["type"] = spec["proxy_task_type"]
        if provider in {"2captcha", "capsolver"}:
            task.update(
                {
                    "proxyType": (
                        "http"
                        if provider_proxy.scheme in {"http", "https"}
                        else provider_proxy.scheme
                    ),
                    "proxyAddress": provider_proxy.host,
                    "proxyPort": int(provider_proxy.port),
                }
            )
            if provider_proxy.username:
                task["proxyLogin"] = provider_proxy.username
            if provider_proxy.password:
                task["proxyPassword"] = provider_proxy.password
        elif provider == "yescaptcha":
            # YesCaptcha's M1 task accepts its documented proxy URL field.
            task["proxy"] = provider_proxy.url
    if provider == "capsolver":
        metadata: Dict[str, str] = {}
        if request.action:
            metadata["action"] = request.action
        if request.cdata:
            metadata["cdata"] = request.cdata
        if metadata:
            task["metadata"] = metadata
    else:
        if request.action:
            task["action"] = request.action
        if request.cdata:
            task["data"] = request.cdata
    return task


async def _task_api_solver(request: BrokerSolveRequest, sleep) -> BrokerSolveResult:
    provider = str(request.provider or "").strip().lower()
    spec = _PROVIDERS.get(provider)
    if spec is None:
        raise ExternalProviderError(f"unsupported external provider: {provider}")
    if not str(request.api_key or "").strip():
        raise ExternalProviderError(f"{provider} api_key is required")
    if not str(request.sitekey or "").strip():
        raise ExternalProviderError(f"{provider} sitekey is required")
    provider_proxy, proxy_mode = _resolve_provider_proxy(request.proxy, provider)

    started = time.monotonic()
    create = await asyncio.to_thread(
        _post_json,
        f"{spec['base_url']}/createTask",
        {"clientKey": request.api_key, "task": _build_task(request, provider)},
        request.timeout_sec,
    )
    task_id = create.get("taskId")
    if not task_id:
        raise ExternalProviderError(f"{provider} createTask returned no taskId")

    while True:
        await sleep(2.0)
        result = await asyncio.to_thread(
            _post_json,
            f"{spec['base_url']}/getTaskResult",
            {"clientKey": request.api_key, "taskId": task_id},
            request.timeout_sec,
        )
        status = str(result.get("status") or "").strip().lower()
        if status in {"processing", "idle"}:
            continue
        if status != "ready":
            raise ExternalProviderError(f"{provider} unexpected task status: {status or 'empty'}")
        solution = result.get("solution") if isinstance(result.get("solution"), dict) else {}
        token = str(solution.get("token") or solution.get("gRecaptchaResponse") or "").strip()
        if not token:
            raise ExternalProviderError(f"{provider} ready result contained no token")
        user_agent = str(solution.get("userAgent") or "").strip()
        return BrokerSolveResult(
            token=token,
            provider=provider,
            received_at=time.monotonic(),
            elapsed_ms=int((time.monotonic() - started) * 1000),
            user_agent=user_agent,
            user_agent_authoritative=False,
            proxy=_proxy_display(provider_proxy),
            action=request.action,
            cdata=request.cdata,
            extras={"task_id": str(task_id), "proxy_mode": proxy_mode},
        )


def solve_external(request: SolveRequest, config: SolverConfig) -> SolveResult:
    provider = str(request.provider or "").strip().lower()
    if provider not in _PROVIDERS:
        return SolveResult(ok=False, provider=provider, error=f"unsupported provider: {provider}")
    try:
        provider_proxy, proxy_mode = _resolve_provider_proxy(request.proxy, provider)
    except ExternalProviderError as exc:
        return SolveResult(ok=False, provider=provider, error=_safe_external_error(exc))
    broker = get_shared_broker(
        provider=provider,
        workers=config.external_provider_workers,
        queue_limit=config.external_queue_limit,
    )
    broker_request = BrokerSolveRequest(
        provider=provider,
        sitekey=str(request.sitekey or "").strip(),
        page_url=str(request.page_url or config.signup_url).strip(),
        api_key=str(request.api_key or "").strip(),
        proxy=provider_proxy.url if provider_proxy is not None else "",
        action=str(request.action or "").strip(),
        cdata=str(request.cdata or "").strip(),
        timeout_sec=max(1, int(request.timeout_sec or config.browser_timeout_sec)),
        headless=False,
    )
    try:
        result = broker.solve_sync(broker_request, _task_api_solver)
    except Exception as exc:
        return SolveResult(
            ok=False,
            provider=provider,
            proxy=_proxy_display(provider_proxy),
            page_url=broker_request.page_url,
            error=_safe_external_error(exc),
        )
    return SolveResult(
        ok=True,
        provider=provider,
        token=result.token,
        proxy=_proxy_display(provider_proxy),
        page_url=broker_request.page_url,
        user_agent=result.user_agent,
        elapsed_ms=result.elapsed_ms,
        extras={
            "provider": provider,
            "provider_task_id": str((result.extras or {}).get("task_id") or ""),
            "proxy_mode": proxy_mode,
            "user_agent_authoritative": False,
            "accept_language": str(request.accept_language or ""),
            "language": str(request.accept_language or "").split(",", 1)[0].split(";", 1)[0],
            "action": result.action,
            "cdata": result.cdata,
        },
    )

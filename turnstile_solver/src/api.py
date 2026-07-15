from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

from .models import SolveRequest, TokenLeaseError, sanitize_public_payload
from .service import SolverService
from .submit_permits import SubmitPermitError

try:
    from fastapi import Body, FastAPI, HTTPException
    from pydantic import BaseModel
except Exception:  # pragma: no cover - optional until deps installed
    FastAPI = None  # type: ignore
    HTTPException = RuntimeError  # type: ignore
    Body = None  # type: ignore
    BaseModel = object  # type: ignore


class SolveBody(BaseModel):  # type: ignore[misc,valid-type]
    provider: str = "local"
    api_key: str = ""
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


class PermitAcquireBody(BaseModel):  # type: ignore[misc,valid-type]
    timeout_sec: int = 30
    lease_sec: int = 0


def create_app(service: Optional[SolverService] = None):
    if FastAPI is None:
        raise RuntimeError(
            "fastapi is not installed. Install turnstile_solver/requirements.txt first."
        )

    service = service or SolverService()
    @asynccontextmanager
    async def lifespan(_app):
        service.start()
        try:
            yield
        finally:
            service.close()

    app = FastAPI(title="Turnstile Solver", version="0.3.0", lifespan=lifespan)

    @app.get("/health")
    def health() -> Dict[str, Any]:
        return sanitize_public_payload(service.health())

    @app.post("/v1/solve")
    def solve(body: SolveBody = Body(...)) -> Dict[str, Any]:
        result = service.solve(
            SolveRequest(
                provider=body.provider,
                api_key=body.api_key,
                proxy=body.proxy,
                page_url=body.page_url,
                timeout_sec=body.timeout_sec,
                headless=body.headless,
                user_agent=body.user_agent,
                accept_language=body.accept_language,
                expected_platform=body.expected_platform,
                expected_client_hint_platform=body.expected_client_hint_platform,
                expected_browser_major=body.expected_browser_major,
                sitekey=body.sitekey,
                action=body.action,
                cdata=body.cdata,
                diagnose=body.diagnose,
            )
        )
        # Tokens are single-consumer secrets. They leave the service only via consume.
        return sanitize_public_payload(result.to_dict(include_token=False))

    @app.post("/v1/leases/{lease_id}/consume")
    def consume_lease(lease_id: str) -> Dict[str, Any]:
        try:
            lease = service.consume_lease(lease_id)
        except TokenLeaseError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return sanitize_public_payload(lease.to_dict(include_token=True))

    @app.post("/v1/permits/submit/acquire")
    def acquire_submit_permit(body: PermitAcquireBody = Body(...)) -> Dict[str, Any]:
        try:
            return sanitize_public_payload(
                service.acquire_submit_permit(body.timeout_sec, body.lease_sec).to_dict()
            )
        except SubmitPermitError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/permits/submit/{permit_id}/release")
    def release_submit_permit(permit_id: str) -> Dict[str, Any]:
        try:
            return sanitize_public_payload(service.release_submit_permit(permit_id))
        except SubmitPermitError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    return app

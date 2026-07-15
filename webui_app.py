# -*- coding: utf-8 -*-
"""Localhost WebUI for HTTP batch registration (default 127.0.0.1:33844)."""

from __future__ import annotations

import argparse
import contextlib
import asyncio
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from http_batch_service import (
    DEFAULT_CONFIG_PATH,
    ROOT_DIR,
    BatchBusyError,
    BatchService,
    TuiConfigError,
    _redact_sensitive_runtime_text,
    browser_health_status,
    cleanup_browser_residues,
    format_browser_health,
    format_cleanup_result,
    get_run_detail,
    list_runs,
    resolve_run_file,
)

DEFAULT_WEBUI_HOST = "127.0.0.1"
DEFAULT_WEBUI_PORT = 33844

_APP_SERVICE: Optional[BatchService] = None
_POLL_THREAD: Optional[threading.Thread] = None
_POLL_STOP = threading.Event()


def get_service() -> BatchService:
    global _APP_SERVICE
    if _APP_SERVICE is None:
        _APP_SERVICE = BatchService()
    return _APP_SERVICE


def _compact_embedded_proxy_status(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Keep run-console / health payloads small."""
    if not isinstance(data, dict):
        return {
            "enabled": False,
            "running": False,
            "phase": "error",
            "message": "invalid status",
            "healthy": 0,
            "total": 0,
            "leases": 0,
            "nodes": [],
        }
    nodes = data.get("nodes") if isinstance(data.get("nodes"), list) else []
    slim_nodes = []
    for n in nodes[:8]:
        if not isinstance(n, dict):
            continue
        slim_nodes.append(
            {
                "id": n.get("id"),
                "name": n.get("name"),
                "healthy": n.get("healthy"),
                "success_count": n.get("success_count"),
                "fail_count": n.get("fail_count"),
                "ref_count": n.get("ref_count"),
                "local_http": n.get("local_http"),
            }
        )
    return {
        "enabled": data.get("enabled"),
        "running": data.get("running"),
        "phase": data.get("phase"),
        "message": data.get("message"),
        "healthy": data.get("healthy"),
        "total": data.get("total"),
        "leases": data.get("leases"),
        "last_error": data.get("last_error"),
        "nodes": slim_nodes,
    }


def _slim_run_snapshot(snap: Optional[Dict[str, Any]], *, worker_limit: int = 16) -> Dict[str, Any]:
    """UI-facing snapshot: counters + a small ranked worker sample."""
    if not isinstance(snap, dict):
        return {"done": True, "workers": [], "failure_counts": {}}

    workers = snap.get("workers") if isinstance(snap.get("workers"), list) else []
    ranked = []
    for w in workers:
        if not isinstance(w, dict):
            continue
        status = str(w.get("status") or "")
        if status in {"running", "active", "converting"}:
            rank = 0
        elif status == "failed":
            rank = 1
        elif status == "queued":
            rank = 2
        elif status == "succeeded":
            rank = 3
        else:
            rank = 4
        ranked.append((rank, int(w.get("index") or 0), w))
    ranked.sort(key=lambda item: (item[0], item[1]))

    slim_workers = []
    limit = max(0, int(worker_limit or 0))
    for _, _, w in ranked[:limit]:
        last_log = str(w.get("last_log") or "")
        last_log = _redact_sensitive_runtime_text(last_log)
        if len(last_log) > 120:
            last_log = last_log[:120]
        slim_workers.append(
            {
                "index": w.get("index"),
                "status": w.get("status"),
                "last_log": last_log,
                "return_code": w.get("return_code"),
            }
        )

    return {
        "run_id": snap.get("run_id"),
        "started": snap.get("started"),
        "done": snap.get("done"),
        "stopping": snap.get("stopping"),
        "count": snap.get("count"),
        "completed": snap.get("completed"),
        "succeeded": snap.get("succeeded"),
        "failed": snap.get("failed"),
        "stopped": snap.get("stopped"),
        "active": snap.get("active"),
        "phase": snap.get("phase"),
        "target_mode": snap.get("target_mode"),
        "target_success": snap.get("target_success"),
        "started_tasks": snap.get("started_tasks"),
        "elapsed_sec": snap.get("elapsed_sec"),
        "avg_success_per_min": snap.get("avg_success_per_min"),
        "success_rate": snap.get("success_rate"),
        "failure_counts": snap.get("failure_counts") or {},
        "refill_paused": snap.get("refill_paused"),
        "refill_pause_reason": _redact_sensitive_runtime_text(
            snap.get("refill_pause_reason") or ""
        ),
        "pause_reason": _redact_sensitive_runtime_text(
            snap.get("pause_reason") or snap.get("refill_pause_reason") or ""
        ),
        "circuit_open": snap.get("circuit_open"),
        "proxy_unhealthy": snap.get("proxy_unhealthy"),
        "recent_fail_count": snap.get("recent_fail_count"),
        "recent_total": snap.get("recent_total"),
        "recent_fail_rate": snap.get("recent_fail_rate"),
        "worker_total": len(workers),
        "workers_truncated": max(0, len(workers) - len(slim_workers)),
        "workers": slim_workers,
    }


def _public_run_file_name(value: object) -> bool:
    """Limit ordinary run downloads to redacted logs and aggregate summary."""

    raw = str(value or "").strip()
    if not raw or "/" in raw or "\\" in raw:
        return False
    return raw.startswith("worker_") and raw.endswith(".log")


def _public_run_detail(detail: Dict[str, Any]) -> Dict[str, Any]:
    public = _slim_run_snapshot(detail)
    public["started_at"] = detail.get("started_at")
    public["account_count"] = int(detail.get("account_count") or 0)
    public["files"] = [
        {"name": str(item.get("name") or ""), "size": int(item.get("size") or 0)}
        for item in (detail.get("files") or [])
        if isinstance(item, dict) and _public_run_file_name(item.get("name"))
    ]
    return public


def _ensure_poller(service: BatchService) -> None:
    global _POLL_THREAD
    if _POLL_THREAD is not None and _POLL_THREAD.is_alive():
        return

    def _loop() -> None:
        while not _POLL_STOP.is_set():
            try:
                service.poll()
            except Exception:
                # Keep the poller alive; a single tick failure must not freeze the batch.
                pass
            time.sleep(0.4)

    _POLL_STOP.clear()
    _POLL_THREAD = threading.Thread(target=_loop, name="batch-poller", daemon=True)
    _POLL_THREAD.start()


def _poll_and_snapshot(service: BatchService | None = None) -> Optional[Dict[str, Any]]:
    """Ensure poller is running, advance one tick, then return current snapshot."""
    svc = service or get_service()
    _ensure_poller(svc)
    try:
        svc.poll()
    except Exception:
        pass
    return svc.current_snapshot()


def create_app(service: Optional[BatchService] = None) -> FastAPI:
    global _APP_SERVICE
    if service is not None:
        _APP_SERVICE = service

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        svc = get_service()
        # Fire-and-forget autostart so UI can poll phase/status immediately.
        try:
            svc.maybe_autostart_embedded_proxy(force=False)
        except Exception:
            pass
        yield

    app = FastAPI(title="xAI HTTP WebUI", docs_url=None, redoc_url=None, lifespan=lifespan)
    static_dir = ROOT_DIR / "webui" / "static"
    templates_dir = ROOT_DIR / "webui" / "templates"
    static_dir.mkdir(parents=True, exist_ok=True)
    templates_dir.mkdir(parents=True, exist_ok=True)

    # 先挂更具体的 /static/cpa，再挂通用 /static，避免被前缀吞掉
    try:
        from cpa_inspector.web.app import attach_cpa

        attach_cpa(app)
    except Exception as exc:  # pragma: no cover - 启动期兜底，避免巡检模块拖垮主 UI
        print(f"[!] CPA 巡检模块未挂载: {exc}")

    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    class NoCacheStaticMiddleware:
        """Avoid sticky browser caches for local config-center JS/CSS during iteration."""

        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope.get("type") == "http" and str(scope.get("path") or "").startswith("/static/"):
                async def send_wrapper(message):
                    if message.get("type") == "http.response.start":
                        headers = list(message.get("headers") or [])
                        headers = [h for h in headers if h[0].lower() not in {b"cache-control", b"pragma", b"expires"}]
                        headers.append((b"cache-control", b"no-store, max-age=0"))
                        headers.append((b"pragma", b"no-cache"))
                        message = {**message, "headers": headers}
                    await send(message)
                await self.app(scope, receive, send_wrapper)
                return
            await self.app(scope, receive, send)

    app.add_middleware(NoCacheStaticMiddleware)
    templates = Jinja2Templates(directory=str(templates_dir))

    def _err(exc: Exception, status: int = 400) -> HTTPException:
        return HTTPException(status_code=status, detail=str(exc))

    def _page(request: Request, name: str, active: str) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            name,
            {
                "host": DEFAULT_WEBUI_HOST,
                "port": DEFAULT_WEBUI_PORT,
                "active": active,
            },
        )

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        return _page(request, "index.html", "run")

    @app.get("/config", response_class=HTMLResponse)
    def config_page(request: Request) -> HTMLResponse:
        return _page(request, "config.html", "config")

    @app.get("/config/mail", response_class=HTMLResponse)
    def config_mail_page(request: Request) -> HTMLResponse:
        return _page(request, "config_mail.html", "config")

    @app.get("/config/output", response_class=HTMLResponse)
    def config_output_page(request: Request) -> HTMLResponse:
        return _page(request, "config_output.html", "config")

    @app.get("/config/proxy", response_class=HTMLResponse)
    def config_proxy_page(request: Request) -> HTMLResponse:
        return _page(request, "config_proxy.html", "config")

    @app.get("/config/turnstile", response_class=HTMLResponse)
    def config_turnstile_page(request: Request) -> HTMLResponse:
        return _page(request, "config_turnstile.html", "config")

    @app.get("/credentials", response_class=HTMLResponse)
    def credentials_page(request: Request) -> HTMLResponse:
        return _page(request, "credentials.html", "credentials")

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon_ico() -> FileResponse:
        """Browsers probe /favicon.ico by default; serve the project icon."""
        path = ROOT_DIR / "webui" / "static" / "favicon.ico"
        return FileResponse(path, media_type="image/x-icon")

    @app.get("/api/health")
    def health() -> Dict[str, Any]:
        svc = get_service()
        if svc.is_busy():
            _ensure_poller(svc)
            try:
                svc.poll()
            except Exception:
                pass
        snap = svc.current_snapshot()
        try:
            emb = _compact_embedded_proxy_status(svc.get_embedded_proxy_status())
        except Exception as exc:
            emb = {"enabled": False, "phase": "error", "message": str(exc), "nodes": []}
        return {
            "ok": True,
            "host": DEFAULT_WEBUI_HOST,
            "port": DEFAULT_WEBUI_PORT,
            "busy": svc.is_busy(),
            "run_id": (snap or {}).get("run_id"),
            "embedded_proxy": emb,
        }

    @app.get("/api/settings")
    def settings_get() -> Dict[str, Any]:
        return get_service().public_settings()

    @app.put("/api/settings")
    def settings_put(payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            get_service().update_settings_from_mapping(payload, persist=True)
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        return get_service().public_settings()

    @app.post("/api/settings/reload")
    def settings_reload() -> Dict[str, Any]:
        get_service().reload_settings()
        return get_service().public_settings()

    @app.get("/api/config-center")
    def config_center_get() -> Dict[str, Any]:
        try:
            return get_service().get_config_center()
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc

    @app.put("/api/config-center")
    def config_center_put(payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return get_service().update_config_center(payload or {})
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc

    @app.post("/api/cpa-push/test")
    def cpa_push_test(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Test CPA management connectivity with saved or override credentials."""
        try:
            return get_service().check_cpa_connection(payload or {})
        except TuiConfigError as exc:
            raise _err(exc) from exc

    @app.post("/api/cpa-push/upload")
    def cpa_push_upload(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Push local OAuth credential JSON files to CPA."""
        try:
            return get_service().push_cpa_credentials(payload or {})
        except TuiConfigError as exc:
            raise _err(exc) from exc

    @app.get("/api/credentials")
    def credentials_list(
        page: int = Query(1, ge=1),
        page_size: int = Query(1000, ge=1, le=1000),
    ) -> Dict[str, Any]:
        """Plaintext credential browser for config-center right panel."""
        try:
            return get_service().list_credentials(page=page, page_size=page_size)
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        except Exception as exc:
            raise _err(exc, 400) from exc

    @app.post("/api/credentials/export-page")
    def credentials_export_page(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Export current credentials page to grok+timestamp.txt, then delete local pairs."""
        data = dict(payload or {})
        page = int(data.get("page") or 1)
        page_size = int(data.get("page_size") or 1000)
        page = max(1, page)
        page_size = max(1, min(1000, page_size))
        try:
            return get_service().export_credentials_page(page=page, page_size=page_size)
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        except Exception as exc:
            raise _err(exc, 400) from exc


    @app.get("/api/credential-exports")
    def credential_exports_list() -> Dict[str, Any]:
        try:
            return get_service().list_export_files()
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        except Exception as exc:
            raise _err(exc, 400) from exc

    @app.get("/api/credential-exports/preview")
    def credential_exports_preview(
        name: str = Query(..., min_length=1),
        max_chars: int = Query(300000, ge=1000, le=2000000),
    ) -> Dict[str, Any]:
        """Return export txt content for in-page historical viewing."""
        try:
            path = get_service().resolve_export_file(name)
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        except Exception as exc:
            raise _err(exc, 400) from exc
        if not path.is_file():
            raise _err(TuiConfigError("导出文件不存在"), 404)
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise _err(TuiConfigError(f"读取导出文件失败: {exc}"), 400) from exc
        limit = max(1000, min(int(max_chars or 300000), 2000000))
        truncated = len(raw) > limit
        text = raw[:limit]
        line_count = raw.count("\n") + (0 if raw.endswith("\n") or not raw else 1)
        return {
            "ok": True,
            "name": path.name,
            "path": str(path),
            "size": path.stat().st_size,
            "line_count": line_count,
            "truncated": truncated,
            "max_chars": limit,
            "text": text,
        }

    @app.get("/api/credential-exports/download")
    def credential_exports_download(name: str = Query(..., min_length=1)) -> FileResponse:
        try:
            path = get_service().resolve_export_file(name)
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        except Exception as exc:
            raise _err(exc, 400) from exc
        if not path.is_file():
            raise _err(TuiConfigError("导出文件不存在"), 404)
        return FileResponse(
            path=str(path),
            filename=path.name,
            media_type="text/plain; charset=utf-8",
        )

    @app.delete("/api/credential-exports")
    def credential_exports_delete(name: str = Query(..., min_length=1)) -> Dict[str, Any]:
        try:
            return get_service().delete_export_file(name)
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        except Exception as exc:
            raise _err(exc, 400) from exc

    @app.get("/api/proxy-pool")
    def proxy_pool_get() -> Dict[str, Any]:
        try:
            return get_service().get_proxy_pool()
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc

    @app.put("/api/proxy-pool")
    def proxy_pool_put(payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            text_value = ""
            if isinstance(payload, dict):
                text_value = str(payload.get("text") if "text" in payload else payload.get("proxy_pool_text") or "")
            return get_service().set_proxy_pool(text_value)
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc

    @app.get("/api/ms-mail-pool")
    def ms_mail_pool_get() -> Dict[str, Any]:
        try:
            return get_service().get_ms_mail_pool()
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        except Exception as exc:
            raise _err(exc, 400) from exc

    @app.put("/api/ms-mail-pool")
    def ms_mail_pool_put(payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            text_value = ""
            if isinstance(payload, dict):
                text_value = str(
                    payload.get("text")
                    if "text" in payload
                    else payload.get("ms_mail_pool_text") or ""
                )
            return get_service().set_ms_mail_pool(text_value)
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        except Exception as exc:
            raise _err(exc, 400) from exc

    @app.post("/api/proxy-pool/import-subscription")
    def proxy_pool_import_subscription(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = dict(payload or {})
        url = str(data.get("url") or data.get("proxy_subscription_url") or "").strip()
        urls = data.get("urls")
        if urls is None:
            urls = data.get("proxy_subscription_urls")
        write_pool = True if data.get("write_pool") is None else bool(data.get("write_pool"))
        timeout = float(data.get("timeout") or 20)
        use_local = True if data.get("use_local_http_if_empty") is None else bool(data.get("use_local_http_if_empty"))
        local_http = str(
            data.get("local_http")
            or data.get("proxy_subscription_local_http")
            or ""
        ).strip()
        try:
            return get_service().import_proxy_subscription(
                url=url,
                urls=urls,
                write_pool=write_pool,
                timeout=timeout,
                use_local_http_if_empty=use_local,
                local_http=local_http,
            )
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        except Exception as exc:
            raise _err(exc, 400) from exc

    @app.post("/api/proxy-pool/import-clean-embedded")
    def proxy_pool_import_clean_embedded(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = dict(payload or {})
        write_pool = bool(data.get("write_pool") or False)
        try:
            return get_service().import_clean_embedded_proxy_list(write_pool=write_pool)
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        except Exception as exc:
            raise _err(exc, 400) from exc

    @app.post("/api/embedded-proxy/export-to-pool")
    def embedded_proxy_export_to_pool(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = dict(payload or {})
        healthy_only = True if data.get("healthy_only") is None else bool(data.get("healthy_only"))
        switch_to_manual = True if data.get("switch_to_manual") is None else bool(data.get("switch_to_manual"))
        set_proxy_mode = str(data.get("set_proxy_mode") or "pool")
        keep_embedded = True if data.get("keep_embedded_enabled") is None else bool(data.get("keep_embedded_enabled"))
        try:
            return get_service().export_embedded_nodes_to_proxy_pool(
                healthy_only=healthy_only,
                switch_to_manual=switch_to_manual,
                set_proxy_mode=set_proxy_mode,
                keep_embedded_enabled=keep_embedded,
            )
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        except Exception as exc:
            raise _err(exc, 400) from exc

    @app.post("/api/proxy-pool/test")
    def proxy_pool_test(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = dict(payload or {})
        count = int(data.get("count") or 5)
        timeout = float(data.get("timeout") or 12)
        text_value = data.get("text")
        if text_value is None:
            text_value = data.get("proxy_pool_text")
        # None => read file; string => test editor content (may be unsaved)
        try:
            return get_service().test_proxy_pool(
                count=count,
                text_value=None if text_value is None else str(text_value),
                timeout=timeout,
            )
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc


    @app.get("/api/turnstile-proxy-pool")
    def turnstile_proxy_pool_get() -> Dict[str, Any]:
        try:
            return get_service().get_turnstile_proxy_pool()
        except svc.TuiConfigError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.put("/api/turnstile-proxy-pool")
    def turnstile_proxy_pool_put(payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            text_value = ""
            if isinstance(payload, dict):
                text_value = str(payload.get("text") if "text" in payload else payload.get("turnstile_proxy_pool_text") or "")
            return get_service().set_turnstile_proxy_pool(text_value)
        except svc.TuiConfigError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/turnstile-proxy-pool/test")
    def turnstile_proxy_pool_test(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = payload or {}
        try:
            count = int(data.get("count") or 5)
            timeout = float(data.get("timeout") or 12)
            text_value = data.get("text")
            if text_value is None:
                text_value = data.get("turnstile_proxy_pool_text")
            return get_service().test_turnstile_proxy_pool(
                count=count,
                text_value=text_value,
                timeout=timeout,
            )
        except svc.TuiConfigError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


    @app.get("/api/embedded-proxy/status")
    def embedded_proxy_status(compact: bool = Query(False)) -> Dict[str, Any]:
        try:
            data = get_service().get_embedded_proxy_status()
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        if compact:
            return _compact_embedded_proxy_status(data if isinstance(data, dict) else None)
        return data

    @app.post("/api/embedded-proxy/start")
    def embedded_proxy_start(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = dict(payload or {})
        force = bool(data.get("force") or data.get("force_reload") or False)
        try:
            # ensure already probes nodes; keep an explicit probe when already running.
            out = get_service().ensure_embedded_proxy(force_reload=force)
            if out.get("enabled") and out.get("running"):
                try:
                    probe = get_service().probe_embedded_proxy()
                    if isinstance(probe, dict):
                        out = dict(out)
                        out["probe"] = probe
                        if probe.get("healthy") is not None:
                            out["healthy"] = probe.get("healthy")
                        if probe.get("total") is not None:
                            out["total"] = probe.get("total")
                except TuiConfigError:
                    # ensure may have already probed; status still useful
                    pass
            return out
        except BatchBusyError as exc:
            raise _err(exc, 409) from exc
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc

    @app.post("/api/embedded-proxy/probe")
    def embedded_proxy_probe(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            return get_service().probe_embedded_proxy()
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc

    @app.post("/api/embedded-proxy/stop")
    def embedded_proxy_stop(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            return get_service().stop_embedded_proxy()
        except BatchBusyError as exc:
            raise _err(exc, 409) from exc
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc

    @app.post("/api/embedded-proxy/reload")
    def embedded_proxy_reload(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            return get_service().reload_embedded_proxy()
        except BatchBusyError as exc:
            raise _err(exc, 409) from exc
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc

    @app.get("/api/embedded-proxy/node-cache")
    def embedded_proxy_node_cache_get() -> Dict[str, Any]:
        try:
            return get_service().get_embedded_node_cache_text()
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        except Exception as exc:
            raise _err(exc, 400) from exc

    @app.put("/api/embedded-proxy/node-cache")
    def embedded_proxy_node_cache_put(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = dict(payload or {})
        text_value = str(data.get("text") if "text" in data else data.get("node_cache_text") or "")
        try:
            return get_service().set_embedded_node_cache_text(text_value)
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        except Exception as exc:
            raise _err(exc, 400) from exc

    @app.delete("/api/embedded-proxy/node-cache")
    def embedded_proxy_node_cache_delete() -> Dict[str, Any]:
        try:
            return get_service().clear_embedded_node_cache()
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        except Exception as exc:
            raise _err(exc, 400) from exc

    @app.post("/api/embedded-proxy/fetch-subscription")
    def embedded_proxy_fetch_subscription(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = dict(payload or {})
        url = str(data.get("url") or data.get("proxy_subscription_url") or "").strip()
        urls = data.get("urls")
        if urls is None:
            urls = data.get("proxy_subscription_urls")
        timeout = float(data.get("timeout") or 20)
        try:
            return get_service().fetch_embedded_subscription_nodes(
                url=url,
                urls=urls,
                timeout=timeout,
            )
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        except Exception as exc:
            raise _err(exc, 400) from exc

    @app.get("/api/browser/health")
    def browser_health() -> Dict[str, Any]:
        status = browser_health_status()
        return {"status": status, "summary": format_browser_health(status)}

    @app.post("/api/browser/cleanup")
    def browser_cleanup() -> Dict[str, Any]:
        result = cleanup_browser_residues(kill_playwright=True, kill_all_chrome=False)
        return {"result": result, "summary": format_cleanup_result(result)}

    @app.post("/api/runs")
    def runs_start(payload: Optional[Dict[str, Any]] = None) -> JSONResponse:
        svc = get_service()
        try:
            snap = svc.start_run(payload or {})
        except BatchBusyError as exc:
            raise _err(exc, 409) from exc
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc
        _ensure_poller(svc)
        return JSONResponse(status_code=202, content=_slim_run_snapshot(snap))

    @app.post("/api/runs/current/stop")
    def runs_stop() -> Dict[str, Any]:
        try:
            return _slim_run_snapshot(get_service().stop_run())
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc

    @app.get("/api/runs/current")
    def runs_current() -> Dict[str, Any]:
        snap = _poll_and_snapshot()
        if snap is None:
            return {"run": None}
        return {"run": _slim_run_snapshot(snap)}

    @app.get("/api/runs/current/events")
    async def runs_events(
        logs: bool = Query(False),
        worker_limit: int = Query(12, ge=0, le=64),
    ) -> StreamingResponse:
        """SSE for run console.

        By default only snapshots are pushed. Pass logs=1 only when the UI
        checkbox is enabled, otherwise browser/server still spend CPU on logs.
        """
        svc = get_service()
        _ensure_poller(svc)
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=32 if logs else 8)
        loop = asyncio.get_running_loop()
        closed = {"v": False}
        want_logs = bool(logs)
        snap_interval = 2.0
        worker_cap = max(0, min(64, int(worker_limit or 0)))

        def _ui_snapshot(snap: Optional[Dict[str, Any]]) -> Dict[str, Any]:
            return _slim_run_snapshot(snap, worker_limit=worker_cap)

        log_budget = {"window_start": time.monotonic(), "sent": 0, "dropped": 0}
        log_rate_per_sec = 6

        def on_log(line: str) -> None:
            if closed["v"] or not want_logs:
                return
            now = time.monotonic()
            if now - float(log_budget["window_start"]) >= 1.0:
                dropped = int(log_budget["dropped"] or 0)
                log_budget["window_start"] = now
                log_budget["sent"] = 0
                log_budget["dropped"] = 0
                if dropped > 0:
                    notice = json.dumps(
                        {"line": f"[UI] 日志过快，已省略 {dropped} 行"},
                        ensure_ascii=False,
                    )
                    notice_msg = "event: log\ndata: " + notice + "\n\n"
                    try:
                        loop.call_soon_threadsafe(queue.put_nowait, notice_msg)
                    except Exception:
                        pass
            if int(log_budget["sent"] or 0) >= log_rate_per_sec:
                log_budget["dropped"] = int(log_budget["dropped"] or 0) + 1
                return
            log_budget["sent"] = int(log_budget["sent"] or 0) + 1
            payload = json.dumps(
                {"line": _redact_sensitive_runtime_text(line)},
                ensure_ascii=False,
            )
            msg = "event: log\ndata: " + payload + "\n\n"

            def _put() -> None:
                if closed["v"]:
                    return
                try:
                    queue.put_nowait(msg)
                except asyncio.QueueFull:
                    try:
                        queue.get_nowait()
                    except Exception:
                        return
                    try:
                        queue.put_nowait(msg)
                    except Exception:
                        pass

            try:
                loop.call_soon_threadsafe(_put)
            except Exception:
                pass

        if want_logs:
            svc.attach_log_listener(on_log)

        async def gen():
            try:
                snap = _ui_snapshot(svc.current_snapshot())
                yield "event: snapshot\ndata: " + json.dumps(snap, ensure_ascii=False) + "\n\n"
                last_snap = time.monotonic()
                while True:
                    try:
                        msg = await asyncio.wait_for(queue.get(), timeout=0.8)
                        yield msg
                        for _ in range(20):
                            try:
                                yield queue.get_nowait()
                            except asyncio.QueueEmpty:
                                break
                    except asyncio.TimeoutError:
                        pass
                    now = time.monotonic()
                    if now - last_snap >= snap_interval:
                        snap = _ui_snapshot(svc.current_snapshot())
                        yield "event: snapshot\ndata: " + json.dumps(snap, ensure_ascii=False) + "\n\n"
                        if snap.get("done"):
                            yield "event: done\ndata: " + json.dumps(snap, ensure_ascii=False) + "\n\n"
                            break
                        last_snap = now
            finally:
                closed["v"] = True
                if want_logs:
                    try:
                        svc.detach_log_listener(on_log)
                    except Exception:
                        pass

        return StreamingResponse(gen(), media_type="text/event-stream")


    @app.get("/api/runs")
    def runs_list(limit: int = Query(50, ge=1, le=200)) -> Dict[str, Any]:
        return {
            "runs": [_public_run_detail(item) for item in list_runs(limit=limit)]
        }

    @app.get("/api/runs/{run_id}")
    def runs_detail(run_id: str) -> Dict[str, Any]:
        try:
            return _public_run_detail(get_run_detail(run_id))
        except TuiConfigError as exc:
            raise _err(exc, 404) from exc

    @app.get("/api/runs/{run_id}/logs")
    def runs_logs(run_id: str, worker: Optional[int] = None) -> PlainTextResponse:
        try:
            if worker is not None:
                path = resolve_run_file(run_id, f"worker_{int(worker):03d}.log")
                return PlainTextResponse(
                    _redact_sensitive_runtime_text(
                        path.read_text(encoding="utf-8", errors="replace")
                    )
                )
            detail = get_run_detail(run_id)
            chunks = []
            for item in detail.get("files") or []:
                name = str(item.get("name") or "")
                if name.startswith("worker_") and name.endswith(".log"):
                    path = resolve_run_file(run_id, name)
                    chunks.append(f"===== {name} =====\n")
                    chunks.append(
                        _redact_sensitive_runtime_text(
                            path.read_text(encoding="utf-8", errors="replace")
                        )
                    )
                    chunks.append("\n")
            return PlainTextResponse("".join(chunks) if chunks else "")
        except TuiConfigError as exc:
            raise _err(exc, 404) from exc

    @app.get("/api/runs/{run_id}/files")
    def runs_file(run_id: str, path: str = Query(..., min_length=1)) -> PlainTextResponse:
        if not _public_run_file_name(path):
            raise HTTPException(status_code=403, detail="该运行文件包含私有数据")
        try:
            file_path = resolve_run_file(run_id, path)
        except TuiConfigError as exc:
            code = 403 if "非法" in str(exc) else 404
            raise _err(exc, code) from exc
        return PlainTextResponse(
            _redact_sensitive_runtime_text(
                file_path.read_text(encoding="utf-8", errors="replace")
            )
        )

    return app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="xAI HTTP 协议 WebUI（仅本机）")
    parser.add_argument(
        "--config",
        default=os.environ.get("XAI_CONFIG_PATH") or str(DEFAULT_CONFIG_PATH),
        help="配置文件路径（默认 .local/config.json，也可用 XAI_CONFIG_PATH）",
    )
    parser.add_argument("--host", default=os.environ.get("XAI_WEBUI_HOST", DEFAULT_WEBUI_HOST))
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("XAI_WEBUI_PORT", str(DEFAULT_WEBUI_PORT))),
    )
    parser.add_argument("--open", action="store_true", help="启动后尝试打开本机浏览器")
    return parser


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    host = str(args.host or DEFAULT_WEBUI_HOST).strip() or DEFAULT_WEBUI_HOST
    if host not in {"127.0.0.1", "localhost", "::1"}:
        # Soft guard: still allow override but warn loudly.
        print(f"[!] 警告: 绑定 {host} 会超出本机 loopback；规格默认仅 127.0.0.1")
    port = int(args.port or DEFAULT_WEBUI_PORT)
    config_path = Path(
        str(args.config or DEFAULT_CONFIG_PATH)
    ).expanduser().resolve()
    service = BatchService(config_path=config_path, root_dir=ROOT_DIR)
    app = create_app(service=service)
    print(f"xAI HTTP WebUI -> http://{host}:{port}")
    if args.open:
        try:
            import webbrowser

            webbrowser.open(f"http://{host}:{port}")
        except Exception:
            pass
    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

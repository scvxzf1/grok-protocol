# -*- coding: utf-8 -*-
"""Localhost WebUI for HTTP batch registration (default 127.0.0.1:33843)."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from http_batch_service import (
    ROOT_DIR,
    BatchBusyError,
    BatchService,
    TuiConfigError,
    browser_health_status,
    cleanup_browser_residues,
    format_browser_health,
    format_cleanup_result,
    get_run_detail,
    list_runs,
    resolve_run_file,
)

DEFAULT_WEBUI_HOST = "127.0.0.1"
DEFAULT_WEBUI_PORT = 33843

_APP_SERVICE: Optional[BatchService] = None
_POLL_THREAD: Optional[threading.Thread] = None
_POLL_STOP = threading.Event()


def get_service() -> BatchService:
    global _APP_SERVICE
    if _APP_SERVICE is None:
        _APP_SERVICE = BatchService()
    return _APP_SERVICE


def _ensure_poller(service: BatchService) -> None:
    global _POLL_THREAD
    if _POLL_THREAD is not None and _POLL_THREAD.is_alive():
        return

    def _loop() -> None:
        while not _POLL_STOP.is_set():
            try:
                service.poll()
            except Exception:
                pass
            time.sleep(0.15)

    _POLL_STOP.clear()
    _POLL_THREAD = threading.Thread(target=_loop, name="batch-poller", daemon=True)
    _POLL_THREAD.start()


def create_app(service: Optional[BatchService] = None) -> FastAPI:
    global _APP_SERVICE
    if service is not None:
        _APP_SERVICE = service

    app = FastAPI(title="xAI HTTP WebUI", docs_url=None, redoc_url=None)
    static_dir = ROOT_DIR / "webui" / "static"
    templates_dir = ROOT_DIR / "webui" / "templates"
    static_dir.mkdir(parents=True, exist_ok=True)
    templates_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
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

    @app.get("/api/health")
    def health() -> Dict[str, Any]:
        svc = get_service()
        snap = svc.current_snapshot()
        return {
            "ok": True,
            "host": DEFAULT_WEBUI_HOST,
            "port": DEFAULT_WEBUI_PORT,
            "busy": svc.is_busy(),
            "run_id": (snap or {}).get("run_id"),
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
        return JSONResponse(status_code=202, content=snap)

    @app.post("/api/runs/current/stop")
    def runs_stop() -> Dict[str, Any]:
        try:
            return get_service().stop_run()
        except TuiConfigError as exc:
            raise _err(exc, 400) from exc

    @app.get("/api/runs/current")
    def runs_current() -> Dict[str, Any]:
        snap = get_service().current_snapshot()
        if snap is None:
            return {"run": None}
        return {"run": snap}

    @app.get("/api/runs/current/events")
    async def runs_events() -> StreamingResponse:
        svc = get_service()
        _ensure_poller(svc)
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=500)
        loop = asyncio.get_running_loop()

        def on_log(line: str) -> None:
            payload = json.dumps({"line": line}, ensure_ascii=False)
            msg = f"event: log\ndata: {payload}\n\n"
            try:
                loop.call_soon_threadsafe(queue.put_nowait, msg)
            except Exception:
                pass

        svc.attach_log_listener(on_log)

        async def gen():
            snap = svc.current_snapshot() or {"done": True, "workers": [], "failure_counts": {}}
            yield f"event: snapshot\ndata: {json.dumps(snap, ensure_ascii=False)}\n\n"
            last_snap = time.monotonic()
            while True:
                if queue.empty():
                    await asyncio.sleep(0.2)
                else:
                    try:
                        while True:
                            yield queue.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                now = time.monotonic()
                if now - last_snap >= 0.4:
                    snap = svc.current_snapshot()
                    if snap is not None:
                        yield f"event: snapshot\ndata: {json.dumps(snap, ensure_ascii=False)}\n\n"
                        if snap.get("done"):
                            yield f"event: done\ndata: {json.dumps(snap, ensure_ascii=False)}\n\n"
                            break
                    last_snap = now

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.get("/api/runs")
    def runs_list(limit: int = Query(50, ge=1, le=200)) -> Dict[str, Any]:
        return {"runs": list_runs(limit=limit)}

    @app.get("/api/runs/{run_id}")
    def runs_detail(run_id: str) -> Dict[str, Any]:
        try:
            return get_run_detail(run_id)
        except TuiConfigError as exc:
            raise _err(exc, 404) from exc

    @app.get("/api/runs/{run_id}/logs")
    def runs_logs(run_id: str, worker: Optional[int] = None) -> PlainTextResponse:
        try:
            if worker is not None:
                path = resolve_run_file(run_id, f"worker_{int(worker):03d}.log")
                return PlainTextResponse(path.read_text(encoding="utf-8", errors="replace"))
            detail = get_run_detail(run_id)
            chunks = []
            for item in detail.get("files") or []:
                name = str(item.get("name") or "")
                if name.startswith("worker_") and name.endswith(".log"):
                    path = resolve_run_file(run_id, name)
                    chunks.append(f"===== {name} =====\n")
                    chunks.append(path.read_text(encoding="utf-8", errors="replace"))
                    chunks.append("\n")
            return PlainTextResponse("".join(chunks) if chunks else "")
        except TuiConfigError as exc:
            raise _err(exc, 404) from exc

    @app.get("/api/runs/{run_id}/files")
    def runs_file(run_id: str, path: str = Query(..., min_length=1)) -> PlainTextResponse:
        try:
            file_path = resolve_run_file(run_id, path)
        except TuiConfigError as exc:
            code = 403 if "非法" in str(exc) else 404
            raise _err(exc, code) from exc
        return PlainTextResponse(file_path.read_text(encoding="utf-8", errors="replace"))

    return app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="xAI HTTP 协议 WebUI（仅本机）")
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
    app = create_app()
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

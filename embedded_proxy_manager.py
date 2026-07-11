from __future__ import annotations

import logging
import os
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, unquote, urlparse

try:
    import yaml
except ImportError:  # pragma: no cover - fallback for environments without PyYAML
    yaml = None  # type: ignore


@dataclass
class NodeSlot:
    id: str
    name: str
    server: str
    port: int
    protocol: str
    local_http: str
    raw: str = ""
    params: Dict[str, str] = field(default_factory=dict)
    uuid: str = ""
    healthy: bool = False
    ref_count: int = 0
    success_count: int = 0
    fail_count: int = 0
    last_latency_ms: Optional[float] = None
    cooldown_until: float = 0.0
    last_error: str = ""



logger = logging.getLogger(__name__)


def parse_vless_node(raw: str) -> Optional[dict]:
    """Parse a vless:// share link into structured fields for NodeSlot/mihomo."""
    line = str(raw or "").strip()
    if not line:
        return None
    if not line.lower().startswith("vless://"):
        return None

    try:
        # Keep fragment as name; urlparse handles userinfo/host/port/query.
        parsed = urlparse(line)
    except Exception:
        return None

    uuid = unquote(parsed.username or "")
    host = parsed.hostname or ""
    try:
        port = int(parsed.port or 0)
    except (TypeError, ValueError):
        port = 0
    if not uuid or not host or port <= 0:
        return None

    qs = parse_qs(parsed.query or "", keep_blank_values=True)
    params: Dict[str, str] = {}
    for key, values in qs.items():
        if not values:
            continue
        params[key] = unquote(values[0])

    name = unquote(parsed.fragment or "") or f"{host}:{port}"
    return {
        "protocol": "vless",
        "uuid": uuid,
        "server": host,
        "port": port,
        "name": name,
        "params": params,
        "raw": line,
    }


def _proxy_name(node: NodeSlot, used: Set[str]) -> str:
    base = (node.name or node.id or f"{node.server}:{node.port}").strip() or "node"
    # mihomo proxy names should be unique and reasonably safe
    safe = base.replace("\n", " ").replace("\r", " ").strip()
    candidate = safe
    n = 2
    while candidate in used:
        candidate = f"{safe}-{n}"
        n += 1
    used.add(candidate)
    return candidate


def _node_to_vless_proxy(node: NodeSlot, proxy_name: str) -> Optional[Dict[str, Any]]:
    protocol = (node.protocol or "").lower().strip()
    if protocol and protocol != "vless":
        logger.warning("skip unsupported protocol %r for node %s", node.protocol, node.id)
        return None
    if not node.server or not node.port or not node.uuid:
        logger.warning("skip incomplete vless node %s (server/port/uuid required)", node.id)
        return None

    params = dict(node.params or {})
    security = (params.get("security") or "").lower()
    network = (params.get("type") or params.get("network") or "tcp").lower()
    sni = params.get("sni") or params.get("servername") or ""
    fp = params.get("fp") or params.get("fingerprint") or ""
    flow = params.get("flow") or ""
    alpn_raw = params.get("alpn") or ""
    client_fp = fp

    proxy: Dict[str, Any] = {
        "name": proxy_name,
        "type": "vless",
        "server": node.server,
        "port": int(node.port),
        "uuid": node.uuid,
        "udp": True,
        "network": network if network else "tcp",
    }
    if flow:
        proxy["flow"] = flow

    if security in {"tls", "reality"}:
        proxy["tls"] = True
        if sni:
            proxy["servername"] = sni
        if client_fp:
            proxy["client-fingerprint"] = client_fp
        if alpn_raw:
            proxy["alpn"] = [x.strip() for x in alpn_raw.split(",") if x.strip()]
        if security == "reality":
            reality_opts: Dict[str, Any] = {}
            if params.get("pbk"):
                reality_opts["public-key"] = params["pbk"]
            if params.get("sid"):
                reality_opts["short-id"] = params["sid"]
            if params.get("spx"):
                reality_opts["spider-x"] = params["spx"]
            if reality_opts:
                proxy["reality-opts"] = reality_opts
    elif security in {"", "none"}:
        proxy["tls"] = False
    else:
        # Unknown security: still emit basic proxy, leave tls false
        proxy["tls"] = False
        logger.warning("node %s has unknown security=%r; tls disabled", node.id, security)

    # Transport opts
    if network == "ws":
        ws_opts: Dict[str, Any] = {}
        path = params.get("path") or "/"
        host_header = params.get("host") or sni or node.server
        ws_opts["path"] = path
        if host_header:
            ws_opts["headers"] = {"Host": host_header}
        proxy["ws-opts"] = ws_opts
    elif network == "grpc":
        grpc_opts: Dict[str, Any] = {}
        service_name = params.get("serviceName") or params.get("service-name") or ""
        if service_name:
            grpc_opts["grpc-service-name"] = service_name
        if grpc_opts:
            proxy["grpc-opts"] = grpc_opts
    elif network in {"h2", "http"}:
        h2_opts: Dict[str, Any] = {}
        path = params.get("path") or "/"
        host_header = params.get("host") or sni or node.server
        h2_opts["path"] = path
        if host_header:
            h2_opts["host"] = [host_header]
        proxy["h2-opts"] = h2_opts
    # tcp / raw / empty: no extra opts

    return proxy


def build_mihomo_config(
    nodes: List[NodeSlot],
    *,
    listen_host: str,
    base_port: int,
) -> dict:
    """Build a multi-port mihomo config: one HTTP listener per VLESS node."""
    host = (listen_host or "127.0.0.1").strip() or "127.0.0.1"
    port_base = int(base_port)

    proxies: List[Dict[str, Any]] = []
    listeners: List[Dict[str, Any]] = []
    used_names: Set[str] = set()
    mapped_index = 0

    for node in nodes:
        name = _proxy_name(node, used_names)
        proxy = _node_to_vless_proxy(node, name)
        if proxy is None:
            continue
        listen_port = port_base + mapped_index
        listener = {
            "name": f"http-in-{listen_port}",
            "type": "http",
            "port": listen_port,
            "proxy": proxy["name"],
        }
        # bind only when non-default; keep listen_host for local_http always
        if host not in {"", "0.0.0.0"}:
            listener["listen"] = host
        proxies.append(proxy)
        listeners.append(listener)
        node.local_http = f"http://{host}:{listen_port}"
        mapped_index += 1

    return {
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "proxies": proxies,
        "listeners": listeners,
        "rules": ["MATCH,DIRECT"],
    }


def render_mihomo_yaml(config: dict) -> str:
    """Serialize mihomo config dict to YAML string."""
    if yaml is None:
        raise RuntimeError("PyYAML is required to render mihomo config")
    return yaml.safe_dump(
        config,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )


DEFAULT_PROBE_HOST = "accounts.x.ai"
DEFAULT_PROBE_PORT = 443
DEFAULT_BASE_PORT = 28000
DEFAULT_MAX_NODES = 50
DEFAULT_MAX_NODE_RETRIES = 3
DEFAULT_PROBE_TIMEOUT_SEC = 5.0
DEFAULT_LISTEN_HOST = "127.0.0.1"
COMMON_MIHOMO_PATHS = (
    "/usr/bin/mihomo",
    "/usr/local/bin/mihomo",
    "/usr/bin/verge-mihomo",
    "/usr/local/bin/verge-mihomo",
)


def find_mihomo_binary(explicit: str = "") -> str:
    """Resolve mihomo/verge-mihomo executable path."""
    cand = str(explicit or "").strip()
    if cand:
        path = Path(cand).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path.resolve())
        # allow absolute/explicit path even if resolve fails later; still validate
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
        raise FileNotFoundError(f"mihomo binary not executable: {cand}")

    for name in ("mihomo", "verge-mihomo"):
        found = shutil.which(name)
        if found and os.access(found, os.X_OK):
            return found

    for p in COMMON_MIHOMO_PATHS:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p

    raise FileNotFoundError(
        "mihomo binary not found; set embedded_proxy_binary or install mihomo/verge-mihomo"
    )


@dataclass
class EmbeddedProxyConfig:
    """Runtime config for embedded mihomo process + probe."""

    binary_path: str = ""
    base_port: int = DEFAULT_BASE_PORT
    max_nodes: int = DEFAULT_MAX_NODES
    health_interval_sec: float = 30.0
    fail_cooldown_sec: float = 30.0
    listen_host: str = DEFAULT_LISTEN_HOST
    probe_host: str = DEFAULT_PROBE_HOST
    probe_port: int = DEFAULT_PROBE_PORT
    probe_timeout_sec: float = DEFAULT_PROBE_TIMEOUT_SEC
    max_node_retries: int = DEFAULT_MAX_NODE_RETRIES
    start_timeout_sec: float = 8.0


class EmbeddedProxyManager:
    """Lease scheduler + mihomo process lifecycle and node probes."""

    def __init__(self, config: Optional[EmbeddedProxyConfig] = None) -> None:
        self.config = config or EmbeddedProxyConfig()
        self._lock = threading.RLock()
        self._nodes: Dict[str, NodeSlot] = {}
        self._running = False
        self._proc: Optional[subprocess.Popen] = None
        self._runtime_dir: Optional[Path] = None
        self._config_path: Optional[Path] = None
        self._log_fp = None

    def acquire(self, exclude_ids: Optional[Set[str]] = None) -> Optional[NodeSlot]:
        exclude = exclude_ids or set()
        now = time.time()
        with self._lock:
            candidates = [
                node
                for node in self._nodes.values()
                if node.healthy
                and now >= node.cooldown_until
                and node.id not in exclude
            ]
            if not candidates:
                return None

            def sort_key(node: NodeSlot):
                latency = node.last_latency_ms
                # None latency sorts last
                latency_key = (latency is None, latency if latency is not None else 0.0)
                return (node.ref_count, latency_key)

            selected = sorted(candidates, key=sort_key)[0]
            selected.ref_count += 1
            return copy(selected)

    def release(self, node_id: str, *, failed: bool = False) -> None:
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                return
            node.ref_count = max(0, node.ref_count - 1)
            if failed:
                node.fail_count += 1
                node.healthy = False
                cooldown = getattr(self, "config", None)
                seconds = 30.0
                if cooldown is not None and hasattr(cooldown, "fail_cooldown_sec"):
                    seconds = float(cooldown.fail_cooldown_sec or 30.0)
                node.cooldown_until = time.time() + seconds

    def status(self) -> dict:
        with self._lock:
            nodes = list(self._nodes.values())
            healthy = sum(1 for n in nodes if n.healthy)
            leases = sum(n.ref_count for n in nodes)
            sample = [
                {
                    "id": n.id,
                    "name": n.name,
                    "healthy": n.healthy,
                    "ref_count": n.ref_count,
                    "fail_count": n.fail_count,
                    "last_latency_ms": n.last_latency_ms,
                    "cooldown_until": n.cooldown_until,
                    "local_http": n.local_http,
                }
                for n in nodes[:20]
            ]
            return {
                "running": bool(getattr(self, "_running", False)),
                "total": len(nodes),
                "healthy": healthy,
                "leases": leases,
                "nodes": sample,
            }

    def _project_root(self) -> Path:
        return Path(__file__).resolve().parent

    def _runtime_paths(self) -> tuple[Path, Path, Path]:
        runtime_dir = self._project_root() / ".embedded_mihomo"
        runtime_dir.mkdir(parents=True, exist_ok=True)
        config_path = runtime_dir / "config.yaml"
        log_path = runtime_dir / "mihomo.log"
        return runtime_dir, config_path, log_path

    def _wait_port_open(self, host: str, port: int, timeout_sec: float) -> bool:
        deadline = time.time() + max(0.1, float(timeout_sec))
        while time.time() < deadline:
            try:
                with socket.create_connection((host, int(port)), timeout=0.3):
                    return True
            except OSError:
                time.sleep(0.05)
        return False

    def start(self, nodes: List[NodeSlot], config: Optional[EmbeddedProxyConfig] = None) -> dict:
        """Write multi-port config, spawn mihomo, wait first listener, store nodes."""
        if config is not None:
            self.config = config
        cfg = self.config

        binary = find_mihomo_binary(cfg.binary_path or "")
        listen_host = (cfg.listen_host or DEFAULT_LISTEN_HOST).strip() or DEFAULT_LISTEN_HOST
        base_port = int(cfg.base_port or DEFAULT_BASE_PORT)
        max_nodes = int(cfg.max_nodes or DEFAULT_MAX_NODES)
        selected = list(nodes)[:max_nodes] if max_nodes > 0 else list(nodes)
        if not selected:
            raise ValueError("no nodes to start embedded mihomo")

        if self._running or self._proc is not None:
            self.stop()

        mihomo_cfg = build_mihomo_config(
            selected,
            listen_host=listen_host,
            base_port=base_port,
        )
        if not mihomo_cfg.get("listeners"):
            raise ValueError("no usable vless nodes for mihomo config")

        runtime_dir, config_path, log_path = self._runtime_paths()
        config_path.write_text(render_mihomo_yaml(mihomo_cfg), encoding="utf-8")

        log_fp = open(log_path, "ab", buffering=0)
        try:
            proc = subprocess.Popen(
                [binary, "-f", str(config_path), "-d", str(runtime_dir)],
                stdout=log_fp,
                stderr=subprocess.STDOUT,
                cwd=str(runtime_dir),
            )
        except Exception:
            log_fp.close()
            raise

        first = mihomo_cfg["listeners"][0]
        wait_host = first.get("listen") or listen_host or "127.0.0.1"
        wait_port = int(first["port"])
        ready = self._wait_port_open(wait_host, wait_port, float(cfg.start_timeout_sec or 8.0))
        if (not ready) or (proc.poll() is not None):
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except Exception:
                        proc.kill()
            finally:
                try:
                    log_fp.close()
                except Exception:
                    pass
            raise RuntimeError(
                f"mihomo failed to open listener {wait_host}:{wait_port}; see {log_path}"
            )

        with self._lock:
            self._proc = proc
            self._log_fp = log_fp
            self._runtime_dir = runtime_dir
            self._config_path = config_path
            self._nodes = {n.id: n for n in selected}
            for n in self._nodes.values():
                n.healthy = False
                n.ref_count = 0
            self._running = True

        return {
            "running": True,
            "pid": proc.pid,
            "binary": binary,
            "config_path": str(config_path),
            "runtime_dir": str(runtime_dir),
            "total": len(selected),
            "listeners": len(mihomo_cfg["listeners"]),
            "base_port": base_port,
        }

    def stop(self) -> None:
        """Terminate mihomo process if running."""
        with self._lock:
            proc = self._proc
            log_fp = self._log_fp
            self._proc = None
            self._log_fp = None
            self._running = False
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
            except Exception as exc:
                logger.warning("stop mihomo failed: %s", exc)
        if log_fp is not None:
            try:
                log_fp.close()
            except Exception:
                pass

    def probe_one(self, node_id: str) -> dict:
        """Probe one node via local HTTP proxy to configured host:port."""
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                return {"id": node_id, "healthy": False, "error": "unknown node"}
            local_http = node.local_http
            cfg = self.config

        host = (cfg.probe_host or DEFAULT_PROBE_HOST).strip() or DEFAULT_PROBE_HOST
        port = int(cfg.probe_port or DEFAULT_PROBE_PORT)
        timeout = float(cfg.probe_timeout_sec or DEFAULT_PROBE_TIMEOUT_SEC)
        if not local_http:
            err = "missing local_http"
            with self._lock:
                node = self._nodes.get(node_id)
                if node is not None:
                    node.healthy = False
                    node.last_error = err
            return {"id": node_id, "healthy": False, "error": err}

        url = f"https://{host}/" if int(port) == 443 else f"https://{host}:{port}/"
        # Use a local opener only. Never install_opener globally — that can poison
        # later localhost health checks (e.g. Turnstile broker /health).
        proxy_handler = urllib.request.ProxyHandler(
            {"http": local_http, "https": local_http}
        )
        opener = urllib.request.build_opener(proxy_handler)
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"User-Agent": "embedded-proxy-probe/1.0"},
        )

        started = time.time()
        healthy = False
        err = ""
        try:
            with opener.open(req, timeout=timeout) as resp:
                _ = resp.read(64)
            healthy = True
        except urllib.error.HTTPError:
            # Any HTTP response means the proxy path reached the target.
            healthy = True
        except Exception as exc:
            err = str(exc) or repr(exc)
            healthy = False

        latency_ms = (time.time() - started) * 1000.0
        with self._lock:
            node = self._nodes.get(node_id)
            if node is not None:
                node.healthy = healthy
                if healthy:
                    node.last_latency_ms = latency_ms
                    node.last_error = ""
                    node.success_count += 1
                else:
                    node.last_error = err
                    node.fail_count += 1
                    node.cooldown_until = time.time() + float(cfg.fail_cooldown_sec or 30.0)
        return {
            "id": node_id,
            "healthy": healthy,
            "latency_ms": latency_ms if healthy else None,
            "error": err,
            "local_http": local_http,
            "target": f"{host}:{port}",
        }

    def probe_all(self, max_workers: int = 8) -> dict:
        """Probe all nodes with limited concurrency."""
        with self._lock:
            ids = list(self._nodes.keys())
        if not ids:
            return {"total": 0, "healthy": 0, "results": []}

        workers = max(1, min(int(max_workers or 8), len(ids)))
        results: List[dict] = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(self.probe_one, nid): nid for nid in ids}
            for fut in as_completed(futs):
                try:
                    results.append(fut.result())
                except Exception as exc:
                    nid = futs[fut]
                    results.append({"id": nid, "healthy": False, "error": str(exc)})

        healthy = sum(1 for r in results if r.get("healthy"))
        return {
            "total": len(results),
            "healthy": healthy,
            "results": results,
        }


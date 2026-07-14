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


def _preferred_local_ports() -> list[str]:
    """Optional allowlist of verified clean local endpoints.

    File format: one proxy per line, e.g. http://127.0.0.1:28019
    """
    import os
    from pathlib import Path
    candidates = []
    env = str(os.environ.get("XAI_GOOD_PROXIES_FILE") or "").strip()
    if env:
        candidates.append(Path(env))
    candidates.extend(
        [
            Path("/tmp/xai_good_proxies.txt"),
            Path(__file__).resolve().parent / "proxies.clean_embedded.txt",
        ]
    )
    ports: list[str] = []
    seen = set()
    for path in candidates:
        try:
            if not path.is_file():
                continue
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                key = s
                if key not in seen:
                    ports.append(key)
                    seen.add(key)
            if ports:
                break
        except Exception:
            continue
    return ports


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
    password: str = ""
    healthy: bool = False
    ref_count: int = 0
    success_count: int = 0
    fail_count: int = 0
    consecutive_tls_fails: int = 0
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
        "password": "",
        "server": host,
        "port": port,
        "name": name,
        "params": params,
        "raw": line,
    }


def parse_hysteria2_node(raw: str) -> Optional[dict]:
    """Parse hy2:// or hysteria2:// share link for mihomo hysteria2 proxy."""
    line = str(raw or "").strip()
    if not line:
        return None
    lower = line.lower()
    if not (lower.startswith("hy2://") or lower.startswith("hysteria2://")):
        return None
    try:
        # Normalize scheme so urlparse accepts hy2
        normalized = "hysteria2://" + line.split("://", 1)[1]
        parsed = urlparse(normalized)
    except Exception:
        return None

    password = unquote(parsed.username or "")
    host = parsed.hostname or ""
    try:
        port = int(parsed.port or 0)
    except (TypeError, ValueError):
        port = 0
    if not password or not host or port <= 0:
        return None

    qs = parse_qs(parsed.query or "", keep_blank_values=True)
    params: Dict[str, str] = {}
    for key, values in qs.items():
        if not values:
            continue
        params[key] = unquote(values[0])

    name = unquote(parsed.fragment or "") or f"{host}:{port}"
    return {
        "protocol": "hysteria2",
        "uuid": "",
        "password": password,
        "server": host,
        "port": port,
        "name": name,
        "params": params,
        "raw": line,
    }


def parse_anytls_node(raw: str) -> Optional[dict]:
    """Parse anytls://password@host:port?params#name for mihomo anytls proxy."""
    line = str(raw or "").strip()
    if not line:
        return None
    if not line.lower().startswith("anytls://"):
        return None
    try:
        parsed = urlparse(line)
    except Exception:
        return None

    password = unquote(parsed.username or "")
    host = parsed.hostname or ""
    try:
        port = int(parsed.port or 0)
    except (TypeError, ValueError):
        port = 0
    if not password or not host or port <= 0:
        return None

    qs = parse_qs(parsed.query or "", keep_blank_values=True)
    params: Dict[str, str] = {}
    for key, values in qs.items():
        if not values:
            continue
        params[key] = unquote(values[0])

    name = unquote(parsed.fragment or "") or f"{host}:{port}"
    return {
        "protocol": "anytls",
        "uuid": "",
        "password": password,
        "server": host,
        "port": port,
        "name": name,
        "params": params,
        "raw": line,
    }


def parse_trojan_node(raw: str) -> Optional[dict]:
    """Parse trojan://password@host:port?params#name for mihomo."""
    line = str(raw or "").strip()
    if not line or not line.lower().startswith("trojan://"):
        return None
    try:
        parsed = urlparse(line)
    except Exception:
        return None

    password = unquote(parsed.username or "")
    host = parsed.hostname or ""
    try:
        port = int(parsed.port or 0)
    except (TypeError, ValueError):
        port = 0
    if not password or not host or port <= 0:
        return None

    qs = parse_qs(parsed.query or "", keep_blank_values=True)
    params: Dict[str, str] = {}
    for key, values in qs.items():
        if values:
            params[key] = unquote(values[0])

    name = unquote(parsed.fragment or "") or f"{host}:{port}"
    return {
        "protocol": "trojan",
        "uuid": "",
        "password": password,
        "server": host,
        "port": port,
        "name": name,
        "params": params,
        "raw": line,
    }


# Protocols the embedded mihomo pool can run (share-link schemes → mihomo type).
EMBEDDED_PROTOCOLS = ("vless", "hysteria2", "anytls", "trojan")
EMBEDDED_LINK_PREFIXES = (
    "vless://",
    "hy2://",
    "hysteria2://",
    "anytls://",
    "trojan://",
)


def parse_embedded_node(raw: str) -> Optional[dict]:
    """Parse any supported embedded share link (vless / hy2 / anytls / trojan)."""
    line = str(raw or "").strip()
    if not line:
        return None
    lower = line.lower()
    if lower.startswith("vless://"):
        return parse_vless_node(line)
    if lower.startswith("hy2://") or lower.startswith("hysteria2://"):
        return parse_hysteria2_node(line)
    if lower.startswith("anytls://"):
        return parse_anytls_node(line)
    if lower.startswith("trojan://"):
        return parse_trojan_node(line)
    return None


def is_embedded_share_link(raw: str) -> bool:
    lower = str(raw or "").strip().lower()
    return any(lower.startswith(p) for p in EMBEDDED_LINK_PREFIXES)


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


def _as_bool_param(value: object) -> bool:
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "on"}


def _node_to_vless_proxy(node: NodeSlot, proxy_name: str) -> Optional[Dict[str, Any]]:
    protocol = (node.protocol or "").lower().strip()
    if protocol and protocol != "vless":
        logger.warning("skip non-vless protocol %r for node %s", node.protocol, node.id)
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


def _node_to_hysteria2_proxy(node: NodeSlot, proxy_name: str) -> Optional[Dict[str, Any]]:
    protocol = (node.protocol or "").lower().strip()
    if protocol and protocol not in {"hysteria2", "hy2"}:
        return None
    password = str(node.password or node.uuid or "").strip()
    if not node.server or not node.port or not password:
        logger.warning("skip incomplete hysteria2 node %s (server/port/password required)", node.id)
        return None

    params = dict(node.params or {})
    sni = params.get("sni") or params.get("servername") or params.get("peer") or ""
    alpn_raw = params.get("alpn") or ""
    obfs = params.get("obfs") or ""
    obfs_password = params.get("obfs-password") or params.get("obfs_password") or ""
    # Common share-link aliases
    if not obfs_password:
        obfs_password = params.get("obfsPassword") or ""
    insecure = _as_bool_param(params.get("insecure") or params.get("skip-cert-verify") or "")
    fingerprint = params.get("pinSHA256") or params.get("pin-sha256") or params.get("fingerprint") or ""
    up = params.get("up") or params.get("upmbps") or ""
    down = params.get("down") or params.get("downmbps") or ""

    proxy: Dict[str, Any] = {
        "name": proxy_name,
        "type": "hysteria2",
        "server": node.server,
        "port": int(node.port),
        "password": password,
    }
    if sni:
        proxy["sni"] = sni
    if alpn_raw:
        proxy["alpn"] = [x.strip() for x in alpn_raw.split(",") if x.strip()]
    if insecure:
        proxy["skip-cert-verify"] = True
    if fingerprint:
        proxy["fingerprint"] = fingerprint
    if obfs:
        proxy["obfs"] = obfs
    if obfs_password:
        proxy["obfs-password"] = obfs_password
    if up:
        proxy["up"] = up
    if down:
        proxy["down"] = down
    return proxy


def _node_to_anytls_proxy(node: NodeSlot, proxy_name: str) -> Optional[Dict[str, Any]]:
    protocol = (node.protocol or "").lower().strip()
    if protocol and protocol != "anytls":
        return None
    password = str(node.password or node.uuid or "").strip()
    if not node.server or not node.port or not password:
        logger.warning("skip incomplete anytls node %s (server/port/password required)", node.id)
        return None

    params = dict(node.params or {})
    sni = params.get("sni") or params.get("servername") or params.get("peer") or ""
    alpn_raw = params.get("alpn") or ""
    fp = params.get("fp") or params.get("client-fingerprint") or params.get("fingerprint") or ""
    insecure = _as_bool_param(params.get("insecure") or params.get("skip-cert-verify") or "")
    udp = params.get("udp")
    idle_session_check_interval = params.get("idle-session-check-interval") or params.get(
        "idle_session_check_interval"
    )
    idle_session_timeout = params.get("idle-session-timeout") or params.get("idle_session_timeout")
    min_idle_session = params.get("min-idle-session") or params.get("min_idle_session")

    proxy: Dict[str, Any] = {
        "name": proxy_name,
        "type": "anytls",
        "server": node.server,
        "port": int(node.port),
        "password": password,
    }
    if sni:
        proxy["sni"] = sni
    if alpn_raw:
        proxy["alpn"] = [x.strip() for x in alpn_raw.split(",") if x.strip()]
    if fp:
        proxy["client-fingerprint"] = fp
    if insecure:
        proxy["skip-cert-verify"] = True
    if udp is not None and str(udp).strip() != "":
        proxy["udp"] = _as_bool_param(udp)
    if idle_session_check_interval:
        proxy["idle-session-check-interval"] = idle_session_check_interval
    if idle_session_timeout:
        proxy["idle-session-timeout"] = idle_session_timeout
    if min_idle_session:
        try:
            proxy["min-idle-session"] = int(min_idle_session)
        except (TypeError, ValueError):
            proxy["min-idle-session"] = min_idle_session
    return proxy


def _node_to_trojan_proxy(node: NodeSlot, proxy_name: str) -> Optional[Dict[str, Any]]:
    protocol = (node.protocol or "").lower().strip()
    if protocol and protocol != "trojan":
        return None
    password = str(node.password or node.uuid or "").strip()
    if not node.server or not node.port or not password:
        logger.warning("skip incomplete trojan node (server/port/password required)")
        return None

    params = dict(node.params or {})
    network = str(params.get("type") or params.get("network") or "tcp").lower()
    sni = params.get("sni") or params.get("servername") or params.get("peer") or ""
    alpn_raw = params.get("alpn") or ""
    client_fp = (
        params.get("client-fingerprint")
        or params.get("client_fingerprint")
        or params.get("fp")
        or params.get("fingerprint")
        or ""
    )
    insecure = _as_bool_param(
        params.get("insecure")
        or params.get("allowInsecure")
        or params.get("allow_insecure")
        or params.get("skip-cert-verify")
        or ""
    )

    proxy: Dict[str, Any] = {
        "name": proxy_name,
        "type": "trojan",
        "server": node.server,
        "port": int(node.port),
        "password": password,
    }
    if sni:
        proxy["sni"] = sni
    if alpn_raw:
        proxy["alpn"] = [x.strip() for x in str(alpn_raw).split(",") if x.strip()]
    if client_fp:
        proxy["client-fingerprint"] = client_fp
    if insecure:
        proxy["skip-cert-verify"] = True
    if "udp" in params and str(params.get("udp") or "").strip() != "":
        proxy["udp"] = _as_bool_param(params.get("udp"))
    ip_version = params.get("ip-version") or params.get("ip_version") or ""
    if ip_version:
        proxy["ip-version"] = ip_version

    if network in {"ws", "grpc"}:
        proxy["network"] = network
    if network == "ws":
        ws_opts: Dict[str, Any] = {"path": params.get("path") or "/"}
        host_header = params.get("host") or sni or node.server
        if host_header:
            ws_opts["headers"] = {"Host": host_header}
        proxy["ws-opts"] = ws_opts
    elif network == "grpc":
        service_name = params.get("serviceName") or params.get("service-name") or ""
        if service_name:
            proxy["grpc-opts"] = {"grpc-service-name": service_name}
    return proxy


def _node_to_mihomo_proxy(node: NodeSlot, proxy_name: str) -> Optional[Dict[str, Any]]:
    protocol = (node.protocol or "").lower().strip()
    if not protocol and node.raw:
        parsed = parse_embedded_node(node.raw)
        if parsed:
            protocol = str(parsed.get("protocol") or "")
    if protocol == "vless":
        return _node_to_vless_proxy(node, proxy_name)
    if protocol in {"hysteria2", "hy2"}:
        return _node_to_hysteria2_proxy(node, proxy_name)
    if protocol == "anytls":
        return _node_to_anytls_proxy(node, proxy_name)
    if protocol == "trojan":
        return _node_to_trojan_proxy(node, proxy_name)
    logger.warning("skip unsupported protocol %r for node %s", node.protocol, node.id)
    return None


def build_mihomo_config(
    nodes: List[NodeSlot],
    *,
    listen_host: str,
    base_port: int,
) -> dict:
    """Build a multi-port mihomo config: one HTTP listener per supported node."""
    host = (listen_host or "127.0.0.1").strip() or "127.0.0.1"
    port_base = int(base_port)

    proxies: List[Dict[str, Any]] = []
    listeners: List[Dict[str, Any]] = []
    used_names: Set[str] = set()
    mapped_index = 0

    for node in nodes:
        name = _proxy_name(node, used_names)
        proxy = _node_to_mihomo_proxy(node, name)
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
    # Extra cooldown multiplier path for consecutive TLS handshake failures.
    tls_fail_cooldown_sec: float = 60.0
    tls_fail_cooldown_cap_sec: float = 600.0
    listen_host: str = DEFAULT_LISTEN_HOST
    probe_host: str = DEFAULT_PROBE_HOST
    probe_port: int = DEFAULT_PROBE_PORT
    probe_timeout_sec: float = DEFAULT_PROBE_TIMEOUT_SEC
    # Concurrent HTTPS probes through local listeners. 8 was too low for 100+ nodes.
    probe_max_workers: int = 32
    max_node_retries: int = DEFAULT_MAX_NODE_RETRIES
    start_timeout_sec: float = 8.0



def _is_tls_failure_text(text: str) -> bool:
    lower = str(text or "").lower()
    markers = (
        "curl: (35)",
        "tls connect error",
        "openssl_internal",
        "invalid library",
        "ssl connect error",
        "ssl_error",
        "ssl routines",
    )
    return any(m in lower for m in markers)


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

    def revive_cooled_nodes(self) -> int:
        """Re-admit nodes whose cooldown has expired.

        Failed nodes are marked healthy=False and given a future cooldown_until.
        After that timestamp passes, revive them for another lease attempt.
        Nodes with healthy=False and cooldown_until<=0 stay out until probe/start.
        Returns how many nodes were revived.
        """
        now = time.time()
        revived = 0
        with self._lock:
            for node in self._nodes.values():
                if node.healthy:
                    continue
                cd = float(node.cooldown_until or 0.0)
                # Only revive nodes that actually entered a timed cooldown.
                if cd <= 0.0 or cd > now:
                    continue
                node.healthy = True
                node.cooldown_until = 0.0
                if getattr(node, "last_error", None):
                    node.last_error = ""
                revived += 1
        return revived

    def acquire(self, exclude_ids: Optional[Set[str]] = None) -> Optional[NodeSlot]:
        exclude = exclude_ids or set()
        # Always re-admit cooled-down nodes before leasing.
        self.revive_cooled_nodes()
        now = time.time()
        with self._lock:
            candidates = [
                node
                for node in self._nodes.values()
                if node.healthy
                and now >= float(node.cooldown_until or 0.0)
                and node.id not in exclude
            ]
            if not candidates:
                return None

            preferred = _preferred_local_ports()
            preferred_rank = {p: i for i, p in enumerate(preferred)}

            def sort_key(node: NodeSlot):
                # Prefer historically good, lightly loaded, low-latency nodes.
                # Also deprioritize nodes with recent consecutive TLS failures.
                # If a verified clean proxy list exists, prefer those local endpoints first,
                # but ALWAYS load-balance within that preferred group so 4 concurrent
                # workers do not all pile onto the same clean port (e.g. 28019).
                latency = node.last_latency_ms
                latency_key = (latency is None, latency if latency is not None else 0.0)
                local_http = str(getattr(node, "local_http", "") or "").strip()
                pref = preferred_rank.get(local_http, 10_000)
                preferred_group = 0 if pref < 10_000 else 1
                return (
                    preferred_group,
                    int(node.ref_count or 0),
                    pref,
                    int(getattr(node, "consecutive_tls_fails", 0) or 0),
                    -int(getattr(node, "success_count", 0) or 0),
                    int(getattr(node, "fail_count", 0) or 0),
                    latency_key,
                    str(node.id),
                )

            selected = sorted(candidates, key=sort_key)[0]
            selected.ref_count += 1
            return copy(selected)

    def release(
        self,
        node_id: str,
        *,
        failed: bool = False,
        reason: str = "",
    ) -> None:
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                return
            node.ref_count = max(0, node.ref_count - 1)
            if not failed:
                # Successful completion resets TLS consecutive counter.
                node.consecutive_tls_fails = 0
                if reason:
                    node.last_error = ""
                return

            node.fail_count += 1
            node.healthy = False
            reason_text = str(reason or node.last_error or "")
            node.last_error = reason_text[:240]
            cfg = getattr(self, "config", None)
            base = 30.0
            if cfg is not None and hasattr(cfg, "fail_cooldown_sec"):
                base = float(cfg.fail_cooldown_sec or 30.0)

            tls_hit = _is_tls_failure_text(reason_text)
            if tls_hit:
                node.consecutive_tls_fails = int(node.consecutive_tls_fails or 0) + 1
                tls_base = 60.0
                tls_cap = 600.0
                if cfg is not None:
                    tls_base = float(getattr(cfg, "tls_fail_cooldown_sec", 60.0) or 60.0)
                    tls_cap = float(getattr(cfg, "tls_fail_cooldown_cap_sec", 600.0) or 600.0)
                # 1st TLS: tls_base, then 2x/4x/8x ... capped.
                mult = 2 ** max(0, min(int(node.consecutive_tls_fails or 1) - 1, 4))
                seconds = min(tls_cap, tls_base * mult)
            else:
                # Non-TLS failure: do not accumulate TLS streak.
                node.consecutive_tls_fails = 0
                # Progressive cooldown: 1st fail ~base, then 2x/3x/4x (cap).
                mult = max(1, min(int(node.fail_count or 1), 4))
                seconds = base * mult
            node.cooldown_until = time.time() + float(seconds)

    def status(self) -> dict:
        # Status should reflect post-cooldown availability, not sticky dead flags.
        self.revive_cooled_nodes()
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
                    "consecutive_tls_fails": int(getattr(n, "consecutive_tls_fails", 0) or 0),
                    "success_count": n.success_count,
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


    def _cleanup_stale_project_mihomo(self) -> None:
        """Best-effort kill leftover project-local mihomo processes."""
        runtime_dir = str((self._project_root() / ".embedded_mihomo").resolve())
        marker = runtime_dir
        if os.name == "nt" or not Path("/proc").is_dir():
            return
        try:
            import signal
            import os as _os
            # Scan /proc for matching command lines without shelling out.
            for pid_name in _os.listdir("/proc"):
                if not pid_name.isdigit():
                    continue
                pid = int(pid_name)
                if pid == _os.getpid():
                    continue
                cmdline_path = f"/proc/{pid}/cmdline"
                try:
                    raw = Path(cmdline_path).read_bytes()
                except OSError:
                    continue
                cmd = raw.replace(b"\x00", b" ").decode("utf-8", "ignore")
                if "verge-mihomo" not in cmd and "/mihomo" not in cmd and " mihomo " not in f" {cmd} ":
                    # keep narrow: only our binary names
                    if "mihomo" not in cmd:
                        continue
                if marker not in cmd:
                    continue
                try:
                    _os.kill(pid, signal.SIGTERM)
                except OSError:
                    continue
            time.sleep(0.2)
            for pid_name in _os.listdir("/proc"):
                if not pid_name.isdigit():
                    continue
                pid = int(pid_name)
                cmdline_path = f"/proc/{pid}/cmdline"
                try:
                    raw = Path(cmdline_path).read_bytes()
                except OSError:
                    continue
                cmd = raw.replace(b"\x00", b" ").decode("utf-8", "ignore")
                if marker in cmd and "mihomo" in cmd:
                    try:
                        _os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass
        except Exception:
            # Never block start on cleanup failure.
            logger.exception("stale mihomo cleanup failed")

    def start(self, nodes: List[NodeSlot], config: Optional[EmbeddedProxyConfig] = None) -> dict:
        """Write multi-port config, spawn mihomo, wait first listener, store nodes."""
        if config is not None:
            self.config = config
        cfg = self.config

        binary = find_mihomo_binary(cfg.binary_path or "")
        listen_host = (cfg.listen_host or DEFAULT_LISTEN_HOST).strip() or DEFAULT_LISTEN_HOST
        base_port = int(cfg.base_port or DEFAULT_BASE_PORT)
        # 0 means unlimited; do not fall back via `or` because 0 is falsy.
        try:
            max_nodes = int(cfg.max_nodes) if cfg.max_nodes is not None else DEFAULT_MAX_NODES
        except (TypeError, ValueError):
            max_nodes = DEFAULT_MAX_NODES
        selected = list(nodes)[:max_nodes] if max_nodes > 0 else list(nodes)
        if not selected:
            raise ValueError("no nodes to start embedded mihomo")

        if self._running or self._proc is not None:
            self.stop()
        self._cleanup_stale_project_mihomo()

        mihomo_cfg = build_mihomo_config(
            selected,
            listen_host=listen_host,
            base_port=base_port,
        )
        if not mihomo_cfg.get("listeners"):
            raise ValueError(
                "no usable embedded nodes (vless/hysteria2/anytls/trojan) for mihomo config"
            )

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

    def probe_one(self, node_id: str, *, timeout_sec: Optional[float] = None) -> dict:
        """Probe one node via local HTTP proxy to configured host:port."""
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                return {"id": node_id, "healthy": False, "error": "unknown node"}
            local_http = node.local_http
            cfg = self.config

        host = (cfg.probe_host or DEFAULT_PROBE_HOST).strip() or DEFAULT_PROBE_HOST
        port = int(cfg.probe_port or DEFAULT_PROBE_PORT)
        if timeout_sec is None:
            timeout = float(cfg.probe_timeout_sec or DEFAULT_PROBE_TIMEOUT_SEC)
        else:
            timeout = max(0.3, float(timeout_sec))
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
                    node.consecutive_tls_fails = 0
                    node.last_latency_ms = latency_ms
                    node.last_error = ""
                    node.cooldown_until = 0.0
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

    def _default_probe_workers(self, total: int) -> int:
        cfg_workers = int(getattr(self.config, "probe_max_workers", 0) or 0)
        if cfg_workers > 0:
            base = cfg_workers
        else:
            # Scale with pool size; keep a useful floor/ceiling.
            base = 32 if total >= 40 else 16 if total >= 16 else 8
        return max(1, min(int(base), int(total), 64))

    def probe_all(
        self,
        max_workers: int = 0,
        *,
        timeout_sec: Optional[float] = None,
        min_healthy: int = 0,
        ready_wait_sec: Optional[float] = None,
        continue_in_background: bool = False,
    ) -> dict:
        """Probe nodes with higher concurrency and optional early-ready.

        When ``continue_in_background`` is true and ``min_healthy`` is reached,
        return immediately while remaining probes keep running in a daemon thread.
        """
        with self._lock:
            ids = list(self._nodes.keys())
        if not ids:
            return {"total": 0, "healthy": 0, "results": [], "partial": False}

        workers = int(max_workers or 0)
        if workers <= 0:
            workers = self._default_probe_workers(len(ids))
        workers = max(1, min(workers, len(ids), 64))
        min_h = max(0, int(min_healthy or 0))
        started = time.time()
        ready_deadline = None
        if ready_wait_sec is not None and min_h > 0:
            ready_deadline = started + max(0.2, float(ready_wait_sec))

        # Full synchronous path (manual re-probe / second chance).
        if not continue_in_background or min_h <= 0:
            results: List[dict] = []
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futs = {
                    pool.submit(self.probe_one, nid, timeout_sec=timeout_sec): nid
                    for nid in ids
                }
                for fut in as_completed(futs):
                    nid = futs[fut]
                    try:
                        results.append(fut.result())
                    except Exception as exc:
                        results.append({"id": nid, "healthy": False, "error": str(exc)})
            healthy = sum(1 for r in results if r.get("healthy"))
            return {
                "total": len(results),
                "healthy": healthy,
                "results": results,
                "partial": False,
                "workers": workers,
                "elapsed_ms": int((time.time() - started) * 1000),
            }

        # Early-ready path: fire all probes in a background pool, wait only until
        # min_healthy or deadline, then return without waiting for the rest.
        self._start_background_probe(ids, max_workers=workers, timeout_sec=timeout_sec)

        while True:
            with self._lock:
                healthy = sum(1 for n in self._nodes.values() if n.healthy)
                total = len(self._nodes)
            if healthy >= min_h:
                break
            if ready_deadline is not None and time.time() >= ready_deadline:
                break
            # If background finished early, stop waiting.
            # We cannot easily know thread state; just sleep briefly.
            if time.time() - started > max(30.0, float(timeout_sec or 5) * 3 + 5):
                break
            time.sleep(0.05)

        with self._lock:
            healthy = sum(1 for n in self._nodes.values() if n.healthy)
            total = len(self._nodes)
            # Snapshot current results for UI without blocking remaining probes.
            results = [
                {
                    "id": n.id,
                    "healthy": bool(n.healthy),
                    "latency_ms": n.last_latency_ms if n.healthy else None,
                    "error": n.last_error,
                    "local_http": n.local_http,
                }
                for n in self._nodes.values()
            ]
        return {
            "total": total,
            "healthy": healthy,
            "results": results,
            "partial": bool(healthy < total),
            "workers": workers,
            "elapsed_ms": int((time.time() - started) * 1000),
        }

    def _start_background_probe(
        self,
        node_ids: List[str],
        *,
        max_workers: int,
        timeout_sec: Optional[float],
    ) -> None:
        ids = [str(x) for x in (node_ids or []) if str(x)]
        if not ids:
            return

        def _job() -> None:
            try:
                workers = max(1, min(int(max_workers or 8), len(ids), 64))
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futs = [
                        pool.submit(self.probe_one, nid, timeout_sec=timeout_sec)
                        for nid in ids
                    ]
                    for fut in as_completed(futs):
                        try:
                            fut.result()
                        except Exception:
                            pass
            except Exception:
                logger.exception("background probe failed")

        thread = threading.Thread(
            target=_job,
            name="embedded-proxy-bg-probe",
            daemon=True,
        )
        thread.start()

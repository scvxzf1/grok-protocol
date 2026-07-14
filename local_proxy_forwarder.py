# -*- coding: utf-8 -*-
"""Local no-auth HTTP proxy that forwards to an authenticated upstream proxy.

Why:
  Chrome/DrissionPage does not reliably support http://user:pass@host:port.
  This module listens on 127.0.0.1:<port> without auth, and injects
  Proxy-Authorization when talking to the real upstream.

Supports:
  - HTTP CONNECT (HTTPS sites)
  - plain HTTP proxy requests
"""

from __future__ import annotations

import base64
import os
import select
import socket
import socketserver
import threading
import time
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlparse


DEFAULT_LOCAL_HOST = "127.0.0.1"
DEFAULT_LOCAL_PORT = 17890
BUFFER_SIZE = 65536
CONNECT_TIMEOUT = 20


class LocalProxyBindError(OSError):
    """Raised only when the requested local listening address cannot bind."""


@dataclass
class UpstreamProxy:
    scheme: str
    host: str
    port: int
    username: str = ""
    password: str = ""

    @property
    def has_auth(self) -> bool:
        return bool(self.username or self.password)

    @property
    def proxy_auth_header(self) -> str:
        if not self.has_auth:
            return ""
        token = f"{self.username}:{self.password}".encode("utf-8")
        return "Basic " + base64.b64encode(token).decode("ascii")

    def as_url(self) -> str:
        auth = ""
        if self.has_auth:
            from urllib.parse import quote
            auth = f"{quote(self.username, safe='')}:{quote(self.password, safe='')}@"
        return f"{self.scheme}://{auth}{self.host}:{self.port}"


def parse_proxy_string(raw: str) -> Optional[UpstreamProxy]:
    """Parse common proxy formats into UpstreamProxy.

    Supported:
      - http://user:pass@host:port
      - socks5://... (rejected for this forwarder; HTTP upstream only)
      - host:port:user:pass
      - host:port
      - user:pass@host:port
    """
    raw = str(raw or "").strip()
    if not raw:
        return None

    # host:port:user:pass  (exactly 4 colon-separated parts, host has no scheme)
    if "://" not in raw and raw.count(":") >= 3:
        # split from right carefully: host may be domain without port confusion
        # format gate.kookeey.info:1000:user:pass
        parts = raw.split(":")
        if len(parts) >= 4:
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                host = None
                port = None
            if host and port:
                user = parts[2]
                password = ":".join(parts[3:])
                return UpstreamProxy("http", host, port, user, password)

    # user:pass@host:port
    if "://" not in raw and "@" in raw:
        raw = "http://" + raw

    if "://" not in raw and raw.count(":") == 1:
        host, port_s = raw.split(":", 1)
        return UpstreamProxy("http", host.strip(), int(port_s), "", "")

    parsed = urlparse(raw if "://" in raw else ("http://" + raw))
    scheme = (parsed.scheme or "http").lower()
    if scheme not in ("http", "https"):
        # this forwarder is an HTTP proxy client to upstream HTTP proxy
        # socks not supported here
        raise ValueError(f"local forwarder only supports http upstream, got scheme={scheme}")
    host = parsed.hostname or ""
    port = int(parsed.port or (443 if scheme == "https" else 80))
    if not host:
        raise ValueError("proxy host is empty")
    username = parsed.username or ""
    password = parsed.password or ""
    # urlparse may leave percent-encoding
    from urllib.parse import unquote
    username = unquote(username)
    password = unquote(password)
    # For proxy URLs, scheme in config is usually http even for HTTPS browsing
    return UpstreamProxy("http", host, port, username, password)


def _recv_until(sock: socket.socket, marker: bytes = b"\r\n\r\n", max_bytes: int = 1024 * 256) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) >= max_bytes:
            break
    return data


def _parse_request_head(head: bytes) -> Tuple[str, str, str, dict]:
    text = head.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        raise ValueError("empty request")
    parts = lines[0].split(" ")
    if len(parts) < 3:
        raise ValueError(f"bad request line: {lines[0]!r}")
    method, target, version = parts[0], parts[1], parts[2]
    headers = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return method.upper(), target, version, headers


class _ProxyHandler(socketserver.BaseRequestHandler):
    upstream: UpstreamProxy = None  # type: ignore

    def handle(self):
        client: socket.socket = self.request
        client.settimeout(CONNECT_TIMEOUT)
        try:
            head = _recv_until(client)
            if not head:
                return
            method, target, version, headers = _parse_request_head(head)
            if method == "CONNECT":
                self._handle_connect(client, target, version)
            else:
                self._handle_http(client, method, target, version, headers, head)
        except Exception:
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            except Exception:
                pass
        finally:
            try:
                client.close()
            except Exception:
                pass

    def _open_upstream(self) -> socket.socket:
        """Open a direct socket to the authenticated upstream proxy."""
        up = self.upstream
        sock = socket.create_connection((up.host, up.port), timeout=CONNECT_TIMEOUT)
        sock.settimeout(CONNECT_TIMEOUT)
        return sock

    @staticmethod
    def _auth_header_lines(proxy: Optional[UpstreamProxy] = None) -> str:
        """Return a Proxy-Authorization header for one proxy hop, if needed."""
        if proxy is None or not proxy.has_auth:
            return ""
        return f"Proxy-Authorization: {proxy.proxy_auth_header}\r\n"

    def _handle_connect(self, client: socket.socket, target: str, version: str):
        # target = host:port
        upstream = self._open_upstream()
        try:
            req = (
                f"CONNECT {target} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"{self._auth_header_lines(self.upstream)}"
                f"Proxy-Connection: keep-alive\r\n"
                f"\r\n"
            )
            upstream.sendall(req.encode("iso-8859-1"))
            resp = _recv_until(upstream)
            # pass status line judgment
            status_line = resp.split(b"\r\n", 1)[0]
            if b" 200 " not in status_line and not status_line.endswith(b" 200"):
                # forward error body if any
                try:
                    client.sendall(resp if resp else b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                except Exception:
                    pass
                return
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            # if upstream sent extra after header, rare; ignore for CONNECT
            self._pipe(client, upstream)
        finally:
            try:
                upstream.close()
            except Exception:
                pass

    def _handle_http(self, client: socket.socket, method: str, target: str, version: str, headers: dict, raw_head: bytes):
        # absolute-form or origin-form
        upstream = self._open_upstream()
        try:
            # Rebuild request to upstream proxy with auth
            # Keep original request line target (absolute URL preferred)
            # Strip hop-by-hop + client proxy-auth
            body = b""
            if b"\r\n\r\n" in raw_head:
                head_part, maybe_body = raw_head.split(b"\r\n\r\n", 1)
                body = maybe_body
            else:
                head_part = raw_head

            text = head_part.decode("iso-8859-1", errors="replace")
            lines = text.split("\r\n")
            out_lines = [lines[0]]
            for line in lines[1:]:
                if not line or ":" not in line:
                    continue
                k = line.split(":", 1)[0].strip().lower()
                if k in (
                    "proxy-connection",
                    "connection",
                    "proxy-authorization",
                    "keep-alive",
                    "te",
                    "trailers",
                    "transfer-encoding",
                    "upgrade",
                ):
                    continue
                out_lines.append(line)
            auth = self._auth_header_lines(self.upstream).rstrip("\r\n")
            if auth:
                out_lines.append(auth)
            out_lines.append("Connection: close")
            out_lines.append("Proxy-Connection: close")
            new_head = ("\r\n".join(out_lines) + "\r\n\r\n").encode("iso-8859-1")
            upstream.sendall(new_head + body)
            self._pipe(client, upstream)
        finally:
            try:
                upstream.close()
            except Exception:
                pass

    def _pipe(self, a: socket.socket, b: socket.socket):
        sockets = [a, b]
        try:
            a.settimeout(None)
            b.settimeout(None)
        except Exception:
            pass
        while True:
            try:
                r, _, er = select.select(sockets, [], sockets, 300)
            except Exception:
                break
            if er:
                break
            if not r:
                break
            for src in r:
                dst = b if src is a else a
                try:
                    data = src.recv(BUFFER_SIZE)
                except Exception:
                    return
                if not data:
                    return
                try:
                    dst.sendall(data)
                except Exception:
                    return


class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    # A worker port is a lease.  Reuse would allow two processes to believe
    # they own the same endpoint during a fast restart, especially on Windows.
    allow_reuse_address = False
    allow_reuse_port = False
    daemon_threads = True

    def server_bind(self):
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_EXCLUSIVEADDRUSE,
                1,
            )
        super().server_bind()


class LocalProxyForwarder:
    """Expose an upstream HTTP proxy on a local no-auth HTTP proxy endpoint.

    Args:
        upstream: The proxy that receives the browser/API CONNECT and HTTP
            proxy requests.  Its optional credentials are injected locally.
        local_host: Bind host for the no-auth local endpoint.
        local_port: Bind port (``0`` chooses a free port).
    """

    def __init__(
        self,
        upstream: UpstreamProxy,
        local_host: str = DEFAULT_LOCAL_HOST,
        local_port: int = 0,
    ):
        self.upstream = upstream
        self.local_host = local_host
        self.local_port = int(local_port or 0)
        self._server: Optional[ThreadingTCPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    @property
    def local_url(self) -> str:
        port = self.local_port
        if self._server is not None:
            port = self._server.server_address[1]
        return f"http://{self.local_host}:{port}"

    @property
    def is_running(self) -> bool:
        with self._lock:
            return bool(
                self._server is not None
                and self._thread is not None
                and self._thread.is_alive()
            )

    def start(self) -> str:
        with self._lock:
            if self._server is not None:
                if self._thread is not None and self._thread.is_alive():
                    return self.local_url
                stale_server = self._server
                self._server = None
                self._thread = None
                try:
                    stale_server.server_close()
                except Exception:
                    pass

            handler = type(
                "BoundProxyHandler",
                (_ProxyHandler,),
                {"upstream": self.upstream},
            )
            try:
                server = ThreadingTCPServer((self.local_host, self.local_port), handler)
            except OSError as exc:
                raise LocalProxyBindError(str(exc)) from exc
            t = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.05},
                name="local-proxy-forwarder",
                daemon=True,
            )
            self._server = server
            self._thread = t
            self.local_port = int(server.server_address[1])
            thread_started = False
            try:
                t.start()
                thread_started = True
                ready = False
                deadline = time.monotonic() + 3.0
                while time.monotonic() < deadline:
                    try:
                        with socket.create_connection(
                            (self.local_host, self.local_port), timeout=0.3
                        ):
                            ready = True
                            break
                    except OSError:
                        time.sleep(0.05)
                if ready and not t.is_alive():
                    ready = False
                if not ready:
                    raise OSError(
                        f"local proxy forwarder did not become ready on "
                        f"{self.local_host}:{self.local_port}"
                    )
                return self.local_url
            except BaseException:
                self._server = None
                self._thread = None
                if thread_started:
                    try:
                        server.shutdown()
                    except Exception:
                        pass
                try:
                    server.server_close()
                except Exception:
                    pass
                if t.is_alive():
                    t.join(timeout=1.0)
                raise

    def stop(self, timeout: float = 2.0):
        with self._lock:
            server = self._server
            serve_thread = self._thread
            if not server:
                return
            wait = max(0.2, float(timeout or 2.0))
            deadline = time.monotonic() + wait

            def _shutdown():
                try:
                    server.shutdown()
                except Exception:
                    pass

            shutdown_thread = threading.Thread(
                target=_shutdown,
                name="local-proxy-forwarder-shutdown",
                daemon=True,
            )
            shutdown_thread.start()
            shutdown_thread.join(timeout=max(0.0, deadline - time.monotonic()))
            try:
                server.server_close()
            except Exception:
                pass
            if serve_thread is not None and serve_thread is not threading.current_thread():
                serve_thread.join(timeout=max(0.0, deadline - time.monotonic()))
            self._server = None
            self._thread = None


# process-level forwarder pool (supports concurrent workers)
_FORWARDERS: dict = {}  # instance_key -> LocalProxyForwarder
_FORWARDER_UPSTREAM_KEYS: dict = {}  # instance_key -> upstream route key
_FORWARDER_LOCK = threading.Lock()
_DEFAULT_INSTANCE = "default"


def normalize_proxy_config(raw: str) -> str:
    """Return a normalized proxy URL string, preserving empty."""
    raw = str(raw or "").strip()
    if not raw:
        return ""
    try:
        up = parse_proxy_string(raw)
    except Exception:
        return raw
    if not up:
        return ""
    return up.as_url()


def ensure_local_forwarder(
    proxy_raw: str,
    preferred_local_port: int = DEFAULT_LOCAL_PORT,
    instance_key: str = _DEFAULT_INSTANCE,
) -> Tuple[str, bool]:
    """Ensure a local forwarder for an authenticated HTTP proxy.

    Returns: (effective_proxy_url, used_forwarder)
      - if proxy empty: ("", False)
      - if proxy has no auth: (normalized upstream url, False)
      - if proxy has auth: (http://127.0.0.1:port, True)

    instance_key: concurrent workers should pass distinct keys (e.g. worker-0)
    so they do not stomp each other's forwarders.
    """
    raw = str(proxy_raw or "").strip()
    ikey = str(instance_key or _DEFAULT_INSTANCE)
    if not raw:
        stop_local_forwarder(instance_key=ikey)
        return "", False

    up = parse_proxy_string(raw)
    if not up:
        stop_local_forwarder(instance_key=ikey)
        return "", False

    if not up.has_auth:
        # no auth needed; browser can use upstream directly
        stop_local_forwarder(instance_key=ikey)
        return f"http://{up.host}:{up.port}", False

    key = (
        up.host,
        up.port,
        up.username,
        up.password,
    )
    with _FORWARDER_LOCK:
        existing = _FORWARDERS.get(ikey)
        if (
            existing is not None
            and _FORWARDER_UPSTREAM_KEYS.get(ikey) == key
            and existing.is_running
        ):
            return existing.local_url, True
        # recreate this instance only
        if existing is not None:
            try:
                existing.stop()
            except Exception:
                pass
            _FORWARDERS.pop(ikey, None)
            _FORWARDER_UPSTREAM_KEYS.pop(ikey, None)

        # prefer fixed port for default instance; workers use preferred+offset or free port
        # ``0`` explicitly requests an OS-assigned exclusive port.
        port = (
            DEFAULT_LOCAL_PORT
            if preferred_local_port is None
            else int(preferred_local_port)
        )
        try:
            fwd = LocalProxyForwarder(
                up,
                local_host=DEFAULT_LOCAL_HOST,
                local_port=port,
            )
            url = fwd.start()
        except LocalProxyBindError:
            fwd = LocalProxyForwarder(
                up,
                local_host=DEFAULT_LOCAL_HOST,
                local_port=0,
            )
            url = fwd.start()
        _FORWARDERS[ikey] = fwd
        _FORWARDER_UPSTREAM_KEYS[ikey] = key
        return url, True


def stop_local_forwarder(instance_key: Optional[str] = None):
    """Stop one forwarder instance, or all if instance_key is None."""
    with _FORWARDER_LOCK:
        if instance_key is None:
            items = list(_FORWARDERS.items())
            _FORWARDERS.clear()
            _FORWARDER_UPSTREAM_KEYS.clear()
        else:
            ikey = str(instance_key or _DEFAULT_INSTANCE)
            fwd = _FORWARDERS.pop(ikey, None)
            _FORWARDER_UPSTREAM_KEYS.pop(ikey, None)
            items = [(ikey, fwd)] if fwd is not None else []
    for _, fwd in items:
        if not fwd:
            continue
        try:
            fwd.stop()
        except Exception:
            pass


def get_active_local_proxy_url(instance_key: str = _DEFAULT_INSTANCE) -> str:
    with _FORWARDER_LOCK:
        fwd = _FORWARDERS.get(str(instance_key or _DEFAULT_INSTANCE))
        if fwd is None:
            return ""
        return fwd.local_url

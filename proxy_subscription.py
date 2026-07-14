# -*- coding: utf-8 -*-
"""Fetch and parse proxy subscription links into local proxy pool lines.

Supports:
  - base64 / plain text subscription bodies
  - Clash YAML (`proxies:` list) including type=http/socks5/vless/hysteria2/anytls/trojan/...
  - http(s)://user:pass@host:port
  - socks5://user:pass@host:port
  - host:port:user:pass
  - ss:// / vless:// / vmess:// / trojan:// / hy2:// / hysteria2:// / anytls://
    (non-HTTP schemes are inventory / embedded-mihomo candidates; only HTTP
    becomes usable pool entries for this project's curl-based registration flow)
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse
from urllib.request import Request, urlopen

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


@dataclass
class ParsedNode:
    raw: str
    scheme: str
    host: str = ""
    port: int = 0
    username: str = ""
    password: str = ""
    name: str = ""
    usable_http: bool = False
    pool_line: str = ""
    note: str = ""


@dataclass
class SubscriptionImportResult:
    url: str
    total_lines: int = 0
    nodes: List[ParsedNode] = field(default_factory=list)
    pool_lines: List[str] = field(default_factory=list)
    usable_pool_lines: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    body_kind: str = ""  # base64 / plain / clash-yaml
    urls: List[str] = field(default_factory=list)
    per_url: List[Dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        scheme_counts: Dict[str, int] = {}
        for node in self.nodes:
            scheme_counts[node.scheme] = scheme_counts.get(node.scheme, 0) + 1
        urls = list(self.urls) if self.urls else ([self.url] if self.url else [])
        return {
            "url": self.url or (urls[0] if urls else ""),
            "urls": urls,
            "body_kind": self.body_kind,
            "total_lines": self.total_lines,
            "node_count": len(self.nodes),
            "usable_http_count": sum(1 for n in self.nodes if n.usable_http),
            "skipped_count": len(self.skipped),
            "scheme_counts": scheme_counts,
            "pool_lines": list(self.pool_lines),
            "usable_pool_lines": list(self.usable_pool_lines),
            "warnings": list(self.warnings),
            "per_url": list(self.per_url),
            "sample_nodes": [
                {
                    "scheme": n.scheme,
                    "host": n.host,
                    "port": n.port,
                    "name": n.name,
                    "usable_http": n.usable_http,
                    "pool_line": n.pool_line,
                    "note": n.note,
                }
                for n in self.nodes[:12]
            ],
        }


def normalize_subscription_urls(
    value: Union[None, str, Sequence[object]] = None,
    *extra: object,
) -> List[str]:
    """Normalize subscription URL input into a de-duplicated ordered list.

    Accepts a single string (multi-line or comma/semicolon separated), a sequence
    of strings, and optional extra args. Empty entries are dropped. Relative
    paths without http(s):// are kept only if they already look like URLs; caller
    may further validate.
    """
    chunks: List[str] = []

    def _push(item: object) -> None:
        if item is None:
            return
        if isinstance(item, (list, tuple, set)):
            for sub in item:
                _push(sub)
            return
        text = str(item or "").replace("\r\n", "\n").replace("\r", "\n")
        if not text.strip():
            return
        # Prefer line splits; also allow comma/semicolon on a single line.
        for part in text.split("\n"):
            part = part.strip()
            if not part or part.startswith("#"):
                continue
            if ("," in part or ";" in part) and "://" not in part.split(",")[0]:
                # Rare: bare host list — still split.
                for piece in re.split(r"[,;]+", part):
                    piece = piece.strip()
                    if piece:
                        chunks.append(piece)
                continue
            # Full URLs rarely contain unencoded commas in the scheme host; keep whole line
            # unless it clearly has multiple http(s) tokens.
            if re.search(r"https?://", part) and len(re.findall(r"https?://", part)) > 1:
                for m in re.finditer(r"https?://\S+", part):
                    chunks.append(m.group(0).rstrip(",;"))
            else:
                chunks.append(part.rstrip(",;"))

    _push(value)
    for item in extra:
        _push(item)

    seen = set()
    out: List[str] = []
    for url in chunks:
        u = str(url or "").strip()
        if not u or u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


def resolve_subscription_urls_from_config(config: object) -> List[str]:
    """Read proxy_subscription_urls (+ legacy proxy_subscription_url) from config dict."""
    cfg = dict(config or {}) if not isinstance(config, dict) else config
    urls_raw = cfg.get("proxy_subscription_urls")
    urls = normalize_subscription_urls(urls_raw)
    if not urls:
        urls = normalize_subscription_urls(cfg.get("proxy_subscription_url"))
    return urls


def _node_dedupe_key(node: ParsedNode) -> str:
    if node.usable_http and node.pool_line:
        return f"http:{node.pool_line}"
    raw = str(node.raw or "").strip()
    if raw:
        return f"raw:{raw}"
    return f"{node.scheme}:{node.username}@{node.host}:{node.port}:{node.name}"


def _safe_b64_decode(text: str) -> Optional[str]:
    raw = re.sub(r"\s+", "", str(text or "").strip())
    if not raw:
        return None
    # URL-safe / standard
    padded = raw + ("=" * ((4 - len(raw) % 4) % 4))
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            data = decoder(padded.encode("ascii", errors="ignore"))
            if not data:
                continue
            # Prefer utf-8 text payloads.
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data.decode("latin-1", errors="replace")
        except Exception:
            continue
    return None


def fetch_subscription_body(url: str, *, timeout: float = 20.0) -> Tuple[str, str]:
    """Return (decoded_or_plain_text, body_kind)."""
    url = str(url or "").strip()
    if not url:
        raise ValueError("订阅链接为空")
    if not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("订阅链接必须以 http:// 或 https:// 开头")
    req = Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; grok-protocol-proxy-sub/1.0)",
            "Accept": "*/*",
        },
        method="GET",
    )
    with urlopen(req, timeout=max(3.0, float(timeout or 20.0))) as resp:
        raw = resp.read()
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        raise ValueError("订阅内容为空")
    # Clash YAML detection (parser will try proxies list later)
    head = text[:3000]
    if (
        text.lstrip().startswith("proxies:")
        or "\nproxies:" in head
        or text.lstrip().startswith("mixed-port:")
        or ("\nproxy-groups:" in head and "\nproxies:" in head)
    ):
        return text, "clash-yaml"
    # Many providers return pure base64 without newlines.
    decoded = _safe_b64_decode(text)
    if decoded and (
        "://" in decoded
        or "\n" in decoded
        or decoded.lstrip().startswith("proxies:")
    ):
        return decoded, "base64"
    # Sometimes body is base64 of multi-line share links already almost plain.
    if "://" in text or "host:port" in text.lower():
        return text, "plain"
    if decoded:
        return decoded, "base64"
    return text, "plain"


def _node_name_from_fragment(raw: str) -> str:
    if "#" not in raw:
        return ""
    return unquote(raw.split("#", 1)[1].strip())


def _http_pool_line(host: str, port: int, username: str = "", password: str = "", scheme: str = "http") -> str:
    host = str(host or "").strip()
    port_i = int(port or 0)
    if not host or port_i <= 0:
        return ""
    user = str(username or "").strip()
    pwd = str(password or "").strip()
    scheme = (scheme or "http").lower()
    if scheme in {"socks5", "socks5h", "socks4"}:
        # Keep URL form for socks; local_proxy_forwarder/http flow may still reject socks.
        auth = f"{user}:{pwd}@" if (user or pwd) else ""
        return f"{scheme}://{auth}{host}:{port_i}"
    if user or pwd:
        return f"{host}:{port_i}:{user}:{pwd}"
    return f"http://{host}:{port_i}"


def parse_share_link(raw: str) -> Optional[ParsedNode]:
    line = str(raw or "").strip()
    if not line or line.startswith("#"):
        return None
    # host:port:user:pass
    # Strict: avoid Clash YAML list/group lines being misread as proxies.
    if "://" not in line and not line.lstrip().startswith("-") and line.count(":") >= 3:
        parts = line.split(":")
        host, port_s, user = parts[0].strip(), parts[1].strip(), parts[2]
        password = ":".join(parts[3:])
        if (
            host
            and " " not in host
            and not host.startswith("#")
            and re.fullmatch(r"\d{1,5}", port_s or "")
            and re.fullmatch(r"[A-Za-z0-9._\[\]-]+", host)
        ):
            try:
                port = int(port_s)
            except ValueError:
                port = 0
            if 1 <= port <= 65535:
                pool = _http_pool_line(host, port, user, password, "http")
                if pool:
                    return ParsedNode(
                        raw=line,
                        scheme="http",
                        host=host,
                        port=port,
                        username=user,
                        password=password,
                        name="",
                        usable_http=True,
                        pool_line=pool,
                    )

    lower = line.lower()
    name = _node_name_from_fragment(line)
    if lower.startswith("http://") or lower.startswith("https://") or lower.startswith("socks5://") or lower.startswith("socks5h://") or lower.startswith("socks4://"):
        parsed = urlparse(line)
        host = parsed.hostname or ""
        port = int(parsed.port or (443 if parsed.scheme == "https" else 80))
        user = unquote(parsed.username or "")
        pwd = unquote(parsed.password or "")
        scheme = "socks5" if parsed.scheme.startswith("socks") else "http"
        pool = _http_pool_line(host, port, user, pwd, scheme)
        usable = bool(pool) and scheme == "http"
        note = "" if usable else "socks 节点已解析，但当前注册链路优先支持 HTTP 代理"
        return ParsedNode(
            raw=line,
            scheme=parsed.scheme,
            host=host,
            port=port,
            username=user,
            password=pwd,
            name=name,
            usable_http=usable,
            pool_line=pool if usable else "",
            note=note,
        )

    if lower.startswith("vless://"):
        # vless://uuid@host:port?params#name
        body = line[len("vless://"):]
        main, _, _frag = body.partition("#")
        cred, _, hostport = main.partition("@")
        host = hostport
        port = 0
        if ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            # query may follow port if malformed; strip
            port_s = port_s.split("?", 1)[0]
            try:
                port = int(port_s)
            except ValueError:
                port = 0
        if "?" in host:
            host = host.split("?", 1)[0]
        return ParsedNode(
            raw=line,
            scheme="vless",
            host=host,
            port=port,
            username=cred,
            name=name,
            usable_http=False,
            note="VLESS 需本地客户端/内嵌 mihomo 承接，不能直接写入 HTTP 代理池",
        )

    if lower.startswith("hy2://") or lower.startswith("hysteria2://"):
        # hy2://password@host:port?params#name  (also hysteria2://)
        scheme = "hysteria2"
        prefix = "hy2://" if lower.startswith("hy2://") else "hysteria2://"
        body = line[len(prefix):]
        main, _, _frag = body.partition("#")
        cred, _, hostport = main.partition("@")
        # password may be URL-encoded
        password = unquote(cred.split("?", 1)[0])
        host = hostport
        port = 0
        if ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            port_s = port_s.split("?", 1)[0]
            try:
                port = int(port_s)
            except ValueError:
                port = 0
        if "?" in host:
            host = host.split("?", 1)[0]
        return ParsedNode(
            raw=line,
            scheme=scheme,
            host=host,
            port=port,
            password=password,
            name=name,
            usable_http=False,
            note="Hysteria2 需内嵌 mihomo / 本地客户端承接，不能直接写入 HTTP 代理池",
        )

    if lower.startswith("anytls://"):
        # anytls://password@host:port?params#name
        body = line[len("anytls://"):]
        main, _, _frag = body.partition("#")
        cred, _, hostport = main.partition("@")
        password = unquote(cred.split("?", 1)[0])
        host = hostport
        port = 0
        if ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            port_s = port_s.split("?", 1)[0]
            try:
                port = int(port_s)
            except ValueError:
                port = 0
        if "?" in host:
            host = host.split("?", 1)[0]
        return ParsedNode(
            raw=line,
            scheme="anytls",
            host=host,
            port=port,
            password=password,
            name=name,
            usable_http=False,
            note="AnyTLS 需内嵌 mihomo / 本地客户端承接，不能直接写入 HTTP 代理池",
        )

    if lower.startswith("trojan://"):
        body = line[len("trojan://"):]
        main, _, _frag = body.partition("#")
        cred, _, hostport = main.partition("@")
        password = unquote(cred.split("?", 1)[0])
        host, port = hostport, 0
        if ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            port_s = port_s.split("?", 1)[0]
            try:
                port = int(port_s)
            except ValueError:
                port = 0
        return ParsedNode(
            raw=line,
            scheme="trojan",
            host=host,
            port=port,
            password=password,
            name=name,
            usable_http=False,
            note="Trojan 需内嵌 mihomo / 本地客户端承接，不能直接写入 HTTP 代理池",
        )

    if lower.startswith("ss://"):
        return ParsedNode(
            raw=line,
            scheme="ss",
            name=name,
            usable_http=False,
            note="Shadowsocks 需本地客户端承接，不能直接写入 HTTP 代理池",
        )

    if lower.startswith("vmess://"):
        payload = line[len("vmess://"):].strip()
        decoded = _safe_b64_decode(payload) or ""
        host = ""
        port = 0
        try:
            data = json.loads(decoded) if decoded else {}
            if isinstance(data, dict):
                host = str(data.get("add") or data.get("host") or "")
                try:
                    port = int(data.get("port") or 0)
                except Exception:
                    port = 0
                name = str(data.get("ps") or name or "")
        except Exception:
            pass
        return ParsedNode(
            raw=line,
            scheme="vmess",
            host=host,
            port=port,
            name=name,
            usable_http=False,
            note="VMess 需本地客户端承接，不能直接写入 HTTP 代理池",
        )

    return None


def _as_text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return int(default)


def _as_boolish(value: object) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "on"}


def _clash_query(params: Dict[str, object]) -> str:
    items = []
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, bool):
            value = "1" if value else "0"
        text = str(value).strip()
        if text == "":
            continue
        items.append((key, text))
    return urlencode(items, doseq=False, quote_via=quote)


def _share_link_authority_host(value: object) -> str:
    """Bracket IPv6 literals for URL authorities without double wrapping."""
    host = _as_text(value)
    if host.startswith("[") and host.endswith("]"):
        return host
    if ":" in host:
        return f"[{host}]"
    return host


def _clash_proxy_to_node(item: object) -> Optional[ParsedNode]:
    """Convert one Clash `proxies:` entry into ParsedNode."""
    if not isinstance(item, dict):
        return None
    ptype = _as_text(item.get("type")).lower()
    if not ptype:
        return None
    name = _as_text(item.get("name") or item.get("ps") or "")
    server = _as_text(item.get("server") or "")
    port = _as_int(item.get("port") or 0)
    username = _as_text(item.get("username") or item.get("user") or "")
    password = _as_text(item.get("password") or item.get("passwd") or "")
    uuid = _as_text(item.get("uuid") or item.get("id") or "")

    if ptype in {"http", "https"}:
        if not server or port <= 0:
            return None
        pool = _http_pool_line(server, port, username, password, "http")
        if not pool:
            return None
        raw = pool if not name else f"{pool}#{name}"
        return ParsedNode(
            raw=raw,
            scheme="http",
            host=server,
            port=port,
            username=username,
            password=password,
            name=name,
            usable_http=True,
            pool_line=pool,
            note="from clash yaml",
        )

    if ptype in {"socks5", "socks5h", "socks4", "socks"}:
        if not server or port <= 0:
            return None
        auth = f"{username}:{password}@" if (username or password) else ""
        raw = f"socks5://{auth}{server}:{port}"
        if name:
            raw = f"{raw}#{name}"
        return ParsedNode(
            raw=raw,
            scheme="socks5",
            host=server,
            port=port,
            username=username,
            password=password,
            name=name,
            usable_http=False,
            pool_line="",
            note="socks 节点已解析，但当前注册链路优先支持 HTTP 代理",
        )

    if ptype == "vless":
        if not server or port <= 0 or not uuid:
            return None
        network = _as_text(item.get("network") or "tcp") or "tcp"
        security = "tls" if _as_boolish(item.get("tls")) else "none"
        if item.get("reality-opts") or item.get("reality_opts"):
            security = "reality"
        params: Dict[str, object] = {
            "encryption": _as_text(item.get("encryption") or "none") or "none",
            "type": network,
            "security": security,
        }
        sni = _as_text(item.get("servername") or item.get("sni") or "")
        if sni:
            params["sni"] = sni
            params["servername"] = sni
        fp = _as_text(
            item.get("client-fingerprint")
            or item.get("client_fingerprint")
            or item.get("fp")
            or ""
        )
        if fp:
            params["fp"] = fp
        flow = _as_text(item.get("flow") or "")
        if flow:
            params["flow"] = flow
        alpn = item.get("alpn")
        if isinstance(alpn, (list, tuple)):
            alpn_text = ",".join(str(x).strip() for x in alpn if str(x).strip())
        else:
            alpn_text = _as_text(alpn)
        if alpn_text:
            params["alpn"] = alpn_text
        if network == "ws":
            ws = item.get("ws-opts") or item.get("ws_opts") or {}
            if isinstance(ws, dict):
                path = _as_text(ws.get("path") or item.get("path") or "/")
                headers = ws.get("headers") if isinstance(ws.get("headers"), dict) else {}
                host_header = _as_text(
                    (headers or {}).get("Host")
                    or (headers or {}).get("host")
                    or item.get("host")
                    or ""
                )
            else:
                path = _as_text(item.get("path") or "/")
                host_header = _as_text(item.get("host") or "")
            params["path"] = path or "/"
            if host_header:
                params["host"] = host_header
        elif network == "grpc":
            grpc = item.get("grpc-opts") or item.get("grpc_opts") or {}
            service = ""
            if isinstance(grpc, dict):
                service = _as_text(
                    grpc.get("grpc-service-name") or grpc.get("serviceName") or ""
                )
            if service:
                params["serviceName"] = service
        reality = item.get("reality-opts") or item.get("reality_opts") or {}
        if isinstance(reality, dict):
            if reality.get("public-key") or reality.get("public_key"):
                params["pbk"] = _as_text(reality.get("public-key") or reality.get("public_key"))
            if reality.get("short-id") or reality.get("short_id"):
                params["sid"] = _as_text(reality.get("short-id") or reality.get("short_id"))
            if reality.get("spider-x") or reality.get("spider_x"):
                params["spx"] = _as_text(reality.get("spider-x") or reality.get("spider_x"))
        query = _clash_query(params)
        raw = f"vless://{quote(uuid, safe='')}@{server}:{port}"
        if query:
            raw = f"{raw}?{query}"
        if name:
            raw = f"{raw}#{quote(name, safe='')}"
        return ParsedNode(
            raw=raw,
            scheme="vless",
            host=server,
            port=port,
            username=uuid,
            name=name,
            usable_http=False,
            note="VLESS 需本地客户端/内嵌 mihomo 承接，不能直接写入 HTTP 代理池",
        )

    if ptype in {"hysteria2", "hy2"}:
        if not server or port <= 0:
            return None
        secret = password or uuid
        if not secret:
            return None
        params: Dict[str, object] = {}
        sni = _as_text(item.get("sni") or item.get("servername") or "")
        if sni:
            params["sni"] = sni
        if "skip-cert-verify" in item or "skip_cert_verify" in item:
            params["insecure"] = (
                "1"
                if _as_boolish(item.get("skip-cert-verify", item.get("skip_cert_verify")))
                else "0"
            )
        obfs = _as_text(item.get("obfs") or "")
        if obfs:
            params["obfs"] = obfs
        obfs_password = _as_text(item.get("obfs-password") or item.get("obfs_password") or "")
        if obfs_password:
            params["obfs-password"] = obfs_password
        query = _clash_query(params)
        raw = f"hysteria2://{quote(secret, safe='')}@{server}:{port}/"
        if query:
            raw = f"{raw}?{query}"
        if name:
            raw = f"{raw}#{quote(name, safe='')}"
        return ParsedNode(
            raw=raw,
            scheme="hysteria2",
            host=server,
            port=port,
            password=secret,
            name=name,
            usable_http=False,
            note="Hysteria2 需内嵌 mihomo / 本地客户端承接，不能直接写入 HTTP 代理池",
        )

    if ptype == "trojan":
        if not server or port <= 0:
            return None
        secret = password or uuid
        if not secret:
            return None
        params: Dict[str, object] = {}
        sni = _as_text(item.get("sni") or item.get("servername") or "")
        if sni:
            params["sni"] = sni
        network = _as_text(item.get("network") or "")
        if network:
            params["type"] = network
        if "skip-cert-verify" in item or "skip_cert_verify" in item or "insecure" in item:
            insecure = item.get(
                "insecure", item.get("skip-cert-verify", item.get("skip_cert_verify"))
            )
            params["skip-cert-verify"] = _as_boolish(insecure)
        if "udp" in item:
            params["udp"] = _as_boolish(item.get("udp"))
        ip_version = _as_text(item.get("ip-version") or item.get("ip_version") or "")
        if ip_version:
            params["ip-version"] = ip_version
        alpn = item.get("alpn")
        if isinstance(alpn, (list, tuple)):
            alpn_text = ",".join(str(x).strip() for x in alpn if str(x).strip())
        else:
            alpn_text = _as_text(alpn)
        if alpn_text:
            params["alpn"] = alpn_text
        client_fp = _as_text(
            item.get("client-fingerprint")
            or item.get("client_fingerprint")
            or item.get("fp")
            or ""
        )
        if client_fp:
            params["client-fingerprint"] = client_fp
        if network == "ws":
            ws = item.get("ws-opts") or item.get("ws_opts") or {}
            if isinstance(ws, dict):
                params["path"] = _as_text(ws.get("path") or item.get("path") or "/") or "/"
                headers = ws.get("headers") if isinstance(ws.get("headers"), dict) else {}
                host_header = _as_text(
                    (headers or {}).get("Host")
                    or (headers or {}).get("host")
                    or item.get("host")
                    or ""
                )
                if host_header:
                    params["host"] = host_header
        elif network == "grpc":
            grpc = item.get("grpc-opts") or item.get("grpc_opts") or {}
            if isinstance(grpc, dict):
                service = _as_text(
                    grpc.get("grpc-service-name") or grpc.get("serviceName") or ""
                )
                if service:
                    params["serviceName"] = service
        query = _clash_query(params)
        authority_host = _share_link_authority_host(server)
        raw = f"trojan://{quote(secret, safe='')}@{authority_host}:{port}"
        if query:
            raw = f"{raw}?{query}"
        if name:
            raw = f"{raw}#{quote(name, safe='')}"
        return ParsedNode(
            raw=raw,
            scheme="trojan",
            host=server,
            port=port,
            password=secret,
            name=name,
            usable_http=False,
            note="Trojan 需内嵌 mihomo / 本地客户端承接，不能直接写入 HTTP 代理池",
        )

    if ptype == "anytls":
        if not server or port <= 0:
            return None
        secret = password or uuid
        if not secret:
            return None
        params: Dict[str, object] = {}
        sni = _as_text(item.get("sni") or item.get("servername") or "")
        if sni:
            params["sni"] = sni
        fp = _as_text(item.get("client-fingerprint") or item.get("fp") or "")
        if fp:
            params["fp"] = fp
        if "skip-cert-verify" in item or "skip_cert_verify" in item or "insecure" in item:
            insecure = item.get(
                "insecure", item.get("skip-cert-verify", item.get("skip_cert_verify"))
            )
            params["insecure"] = "1" if _as_boolish(insecure) else "0"
        query = _clash_query(params)
        raw = f"anytls://{quote(secret, safe='')}@{server}:{port}"
        if query:
            raw = f"{raw}?{query}"
        if name:
            raw = f"{raw}#{quote(name, safe='')}"
        return ParsedNode(
            raw=raw,
            scheme="anytls",
            host=server,
            port=port,
            password=secret,
            name=name,
            usable_http=False,
            note="AnyTLS 需内嵌 mihomo / 本地客户端承接，不能直接写入 HTTP 代理池",
        )

    if server and port > 0:
        return ParsedNode(
            raw=f"{ptype}://{server}:{port}" + (f"#{name}" if name else ""),
            scheme=ptype,
            host=server,
            port=port,
            username=username,
            password=password or uuid,
            name=name,
            usable_http=False,
            note=f"{ptype} 需本地客户端承接，不能直接写入 HTTP 代理池",
        )
    return None


def parse_clash_yaml_text(text: str) -> List[ParsedNode]:
    """Parse Clash-like YAML subscription bodies into nodes."""
    raw = str(text or "").strip()
    if not raw:
        return []
    data = None
    if yaml is not None:
        try:
            data = yaml.safe_load(raw)
        except Exception:
            data = None
    nodes: List[ParsedNode] = []
    if isinstance(data, dict):
        proxies = data.get("proxies")
        if isinstance(proxies, list):
            for item in proxies:
                node = _clash_proxy_to_node(item)
                if node is not None:
                    nodes.append(node)
            return nodes
    if isinstance(data, list):
        for item in data:
            node = _clash_proxy_to_node(item)
            if node is not None:
                nodes.append(node)
        if nodes:
            return nodes

    # Fallback without PyYAML / on parse failure: only real share links.
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- "):
            maybe = stripped[2:].strip().strip("'\"")
            if "://" in maybe:
                node = parse_share_link(maybe)
                if node is not None:
                    nodes.append(node)
            continue
        if "://" in stripped:
            node = parse_share_link(stripped)
            if node is not None:
                nodes.append(node)
    return nodes


def parse_subscription_text(text: str) -> List[ParsedNode]:
    raw = str(text or "")
    stripped = raw.lstrip()
    looks_clash = (
        stripped.startswith("proxies:")
        or "\nproxies:" in raw[:3000]
        or stripped.startswith("mixed-port:")
        or stripped.startswith("socks-port:")
        or ("\nproxy-groups:" in raw[:4000] and "\nproxies:" in raw[:4000])
    )
    if looks_clash:
        nodes = parse_clash_yaml_text(raw)
        if nodes:
            return nodes

    nodes: List[ParsedNode] = []
    for line in raw.splitlines():
        node = parse_share_link(line.strip())
        if node is not None:
            nodes.append(node)
    return nodes


def import_proxy_subscription(
    url: str,
    *,
    timeout: float = 20.0,
    include_inventory_comments: bool = True,
) -> SubscriptionImportResult:
    """Fetch a single subscription URL. Prefer import_proxy_subscriptions for multi-URL."""
    return import_proxy_subscriptions(
        [url],
        timeout=timeout,
        include_inventory_comments=include_inventory_comments,
    )


def import_proxy_subscriptions(
    urls: Union[str, Sequence[object], None],
    *,
    timeout: float = 20.0,
    include_inventory_comments: bool = True,
) -> SubscriptionImportResult:
    """Fetch one or more subscription URLs and merge nodes into one result.

    Per-URL failures are recorded in warnings/per_url and do not abort siblings.
    Raises ValueError only when no valid URL is provided, or every URL fails.
    """
    url_list = normalize_subscription_urls(urls)
    if not url_list:
        raise ValueError("订阅链接为空")

    for u in url_list:
        if not (u.startswith("http://") or u.startswith("https://")):
            raise ValueError(f"订阅链接必须以 http:// 或 https:// 开头: {u}")

    merged = SubscriptionImportResult(url=url_list[0], urls=list(url_list))
    kinds: List[str] = []
    node_seen: set = set()
    pool: List[str] = []
    pool_seen: set = set()
    any_ok = False
    fatal_errors: List[str] = []

    for sub_url in url_list:
        entry: Dict[str, object] = {
            "url": sub_url,
            "ok": False,
            "node_count": 0,
            "usable_http": 0,
            "body_kind": "",
            "error": "",
        }
        try:
            body, kind = fetch_subscription_body(sub_url, timeout=timeout)
            nodes = parse_subscription_text(body)
            lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
            usable = 0
            for node in nodes:
                key = _node_dedupe_key(node)
                if key not in node_seen:
                    node_seen.add(key)
                    merged.nodes.append(node)
                if node.usable_http and node.pool_line:
                    if node.pool_line not in pool_seen:
                        pool_seen.add(node.pool_line)
                        pool.append(node.pool_line)
                        usable += 1
                elif not node.usable_http:
                    merged.skipped.append(
                        f"{node.scheme}://{node.host}:{node.port} {node.name}".strip()
                    )
            merged.total_lines += len(lines)
            kinds.append(kind)
            entry.update(
                {
                    "ok": True,
                    "node_count": len(nodes),
                    "usable_http": usable,
                    "body_kind": kind,
                }
            )
            any_ok = True
        except Exception as exc:
            err = str(exc) or exc.__class__.__name__
            entry["error"] = err
            fatal_errors.append(f"{sub_url}: {err}")
            merged.warnings.append(f"订阅拉取失败: {sub_url} → {err}")
        merged.per_url.append(entry)

    if not any_ok:
        raise ValueError("全部订阅链接拉取失败: " + "; ".join(fatal_errors[:5]))

    merged.body_kind = "+".join(dict.fromkeys(kinds)) if kinds else ""
    header: List[str] = [
        f"# subscription imported from {len(url_list)} url(s)",
        f"# urls={', '.join(url_list)}",
        f"# body_kind={merged.body_kind} nodes={len(merged.nodes)} usable_http={len(pool)}",
    ]
    if include_inventory_comments:
        for node in merged.nodes[:80]:
            label = node.name or f"{node.host}:{node.port}"
            flag = "http" if node.usable_http else "need-client"
            header.append(
                f"# [{flag}] {node.scheme} {label} {node.host}:{node.port}".rstrip(":")
            )
        if len(merged.nodes) > 80:
            header.append(f"# ... {len(merged.nodes) - 80} more nodes omitted")

    if not pool:
        merged.warnings.append(
            "订阅已拉取，但没有可直接用于注册机的 HTTP 代理节点。"
            "当前节点多为 VLESS/Hysteria2/AnyTLS/VMess/SS/Trojan，"
            "可走内嵌 mihomo（VLESS/Hysteria2/AnyTLS/Trojan）或本地客户端 HTTP 入口。"
        )
    merged.usable_pool_lines = list(pool)
    merged.pool_lines = header + pool
    return merged

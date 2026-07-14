# -*- coding: utf-8 -*-
"""Fetch and parse proxy subscription links into local proxy pool lines.

Supports:
  - base64 / plain text subscription bodies
  - http(s)://user:pass@host:port
  - socks5://user:pass@host:port
  - host:port:user:pass
  - ss:// / vless:// / vmess:// / trojan://  (parsed for inventory; only HTTP/SOCKS
    become usable pool entries for this project's curl-based registration flow)
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import Request, urlopen


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
    body_kind: str = ""  # base64 / plain / clash-yaml-ish

    def to_dict(self) -> Dict[str, object]:
        scheme_counts: Dict[str, int] = {}
        for node in self.nodes:
            scheme_counts[node.scheme] = scheme_counts.get(node.scheme, 0) + 1
        return {
            "url": self.url,
            "body_kind": self.body_kind,
            "total_lines": self.total_lines,
            "node_count": len(self.nodes),
            "usable_http_count": sum(1 for n in self.nodes if n.usable_http),
            "skipped_count": len(self.skipped),
            "scheme_counts": scheme_counts,
            "pool_lines": list(self.pool_lines),
            "usable_pool_lines": list(self.usable_pool_lines),
            "warnings": list(self.warnings),
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
    # Clash YAML detection (keep as plain; parser will try lines / proxies list later)
    if text.lstrip().startswith("proxies:") or "\nproxies:" in text[:1000]:
        return text, "clash-yaml-ish"
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
    if "://" not in line and line.count(":") >= 3:
        parts = line.split(":")
        host, port_s, user = parts[0], parts[1], parts[2]
        password = ":".join(parts[3:])
        try:
            port = int(port_s)
        except ValueError:
            return None
        pool = _http_pool_line(host, port, user, password, "http")
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
            note="VLESS 由项目内置 mihomo 承接，不直接写入 HTTP 代理池",
        )

    if lower.startswith("trojan://"):
        body = line[len("trojan://"):]
        main, _, _frag = body.partition("#")
        cred, _, hostport = main.partition("@")
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
            password=cred,
            name=name,
            usable_http=False,
            note="Trojan 需本地客户端承接，不能直接写入 HTTP 代理池",
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


def parse_subscription_text(text: str) -> List[ParsedNode]:
    nodes: List[ParsedNode] = []
    for line in str(text or "").splitlines():
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
    body, kind = fetch_subscription_body(url, timeout=timeout)
    result = SubscriptionImportResult(url=str(url).strip(), body_kind=kind)
    lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
    result.total_lines = len(lines)
    nodes = parse_subscription_text(body)
    result.nodes = nodes

    pool: List[str] = []
    seen = set()
    for node in nodes:
        if node.usable_http and node.pool_line:
            if node.pool_line not in seen:
                seen.add(node.pool_line)
                pool.append(node.pool_line)
        elif not node.usable_http:
            result.skipped.append(f"{node.scheme}://{node.host}:{node.port} {node.name}".strip())

    # Keep a short inventory header so operators see what was pulled.
    header: List[str] = [
        f"# subscription imported from {result.url}",
        f"# body_kind={result.body_kind} nodes={len(nodes)} usable_http={len(pool)}",
    ]
    if include_inventory_comments:
        for node in nodes[:80]:
            label = node.name or f"{node.host}:{node.port}"
            flag = "http" if node.usable_http else "need-client"
            header.append(
                f"# [{flag}] {node.scheme} {label} {node.host}:{node.port}".rstrip(":")
            )
        if len(nodes) > 80:
            header.append(f"# ... {len(nodes) - 80} more nodes omitted")

    if not pool:
        result.warnings.append(
            "订阅已拉取，但没有可直接用于注册机的 HTTP 代理节点。"
            "当前节点多为 VLESS/VMess/SS/Trojan，请启用项目内置 mihomo 节点池。"
        )
    result.usable_pool_lines = list(pool)
    result.pool_lines = header + pool
    return result

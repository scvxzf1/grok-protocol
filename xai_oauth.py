# -*- coding: utf-8 -*-
"""xAI OAuth (CLIProxyAPI-compatible) after SSO registration."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import string
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from curl_cffi import requests

from local_paths import CONFIG_PATH
import turnstile_flow as _tf
from turnstile_flow import (
    SCENE_OAUTH,
    clear_cf_for_scene,
    classify_cf_status,
    ensure_cf_token,
    is_cf_ready,
    log_turnstile_status,
    probe_turnstile_status,
    sync_turnstile_token_to_page,
    update_token_stability,
    wait_cf_ready,
)

XAI_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
XAI_SCOPE = "openid profile email offline_access grok-cli:access api:access"
XAI_DISCOVERY_URL = "https://auth.x.ai/.well-known/openid-configuration"
XAI_DEFAULT_API_BASE = "https://api.x.ai/v1"
XAI_REDIRECT_HOST = "127.0.0.1"
XAI_REDIRECT_PATH = "/callback"
XAI_OAUTH_TIMEOUT = 300
# Soft-reset protection when a single stage stalls (Cloudflare / sign-in / consent)
XAI_OAUTH_PHASE_STUCK_SEC = 50
XAI_OAUTH_NO_PROGRESS_SEC = 75
XAI_OAUTH_MAX_SOFT_RESETS = 2
XAI_OAUTH_EXTERNAL_TS_MAX = 2
XAI_OAUTH_EXTERNAL_TS_TIMEOUT = 12
# OAuth login: only click after native "成功!" is stable; never trust inject-only tokens
XAI_OAUTH_SUCCESS_STABLE_SEC = 1.8
XAI_OAUTH_POST_FAIL_COOLDOWN_SEC = 6.0


def _mono_now():
    return time.monotonic()


def _oauth_log(log_callback, message, level="info"):
    if not log_callback:
        return
    prefix = "[xAI-OAuth]"
    if level == "debug":
        line = f"{prefix}[Debug] {message}"
    elif level == "warn":
        line = f"{prefix}[!] {message}"
    elif level == "ok":
        line = f"{prefix}[+] {message}"
    else:
        line = f"{prefix} {message}"
    log_callback(line)


def _mask_email(email):
    email = str(email or "").strip()
    if "@" not in email:
        return email or "(empty)"
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked_local = local[:1] + "***"
    else:
        masked_local = local[:2] + "***" + local[-1:]
    return f"{masked_local}@{domain}"


def _short_url(url, max_len=120):
    url = str(url or "").strip()
    if len(url) <= max_len:
        return url or "(empty)"
    return url[: max_len - 3] + "..."


def _short_token(token, head=6, tail=4):
    token = str(token or "").strip()
    if not token:
        return "(empty)"
    if len(token) <= head + tail + 3:
        return token[:3] + "..."
    return f"{token[:head]}...{token[-tail:]}(len={len(token)})"


def _utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _add_duration_iso(seconds):
    return datetime.fromtimestamp(
        datetime.now(timezone.utc).timestamp() + max(int(seconds or 0), 0),
        tz=timezone.utc,
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def generate_pkce_codes():
    verifier = _b64url_no_pad(secrets.token_bytes(96))
    challenge = _b64url_no_pad(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def generate_random_token(length=32):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _validate_xai_https_url(raw_url, field_name):
    raw_url = str(raw_url or "").strip()
    if not raw_url:
        raise ValueError(f"xai discovery {field_name} is empty")
    parsed = urlparse(raw_url)
    if parsed.scheme != "https":
        raise ValueError(f"xai discovery {field_name} must use https")
    host = (parsed.hostname or "").lower()
    if host != "x.ai" and not host.endswith(".x.ai"):
        raise ValueError(f"xai discovery {field_name} host not on x.ai")
    return raw_url


def discover_endpoints(proxies=None):
    resp = requests.get(
        XAI_DISCOVERY_URL,
        headers={"Accept": "application/json"},
        timeout=20,
        proxies=proxies or {},
    )
    resp.raise_for_status()
    data = resp.json()
    auth_ep = _validate_xai_https_url(data.get("authorization_endpoint"), "authorization_endpoint")
    token_ep = _validate_xai_https_url(data.get("token_endpoint"), "token_endpoint")
    return auth_ep, token_ep


def build_authorize_url(authorization_endpoint, redirect_uri, code_challenge, state, nonce):
    params = {
        "response_type": "code",
        "client_id": XAI_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": XAI_SCOPE,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "nonce": nonce,
        "plan": "generic",
        "referrer": "cli-proxy-api",
    }
    return authorization_endpoint + "?" + urlencode(params)


def exchange_code_for_tokens(code, redirect_uri, code_verifier, token_endpoint, proxies=None):
    form = {
        "grant_type": "authorization_code",
        "code": code.strip(),
        "redirect_uri": redirect_uri,
        "client_id": XAI_CLIENT_ID,
        "code_verifier": code_verifier,
    }
    resp = requests.post(
        token_endpoint,
        data=form,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        timeout=30,
        proxies=proxies or {},
    )
    if resp.status_code != 200:
        raise RuntimeError(f"xai token exchange HTTP {resp.status_code}: {resp.text[:300]}")
    payload = resp.json()
    access = str(payload.get("access_token") or "").strip()
    if not access:
        raise RuntimeError("xai token exchange missing access_token")
    expires_in = int(payload.get("expires_in") or 0)
    email, subject = parse_jwt_identity(payload.get("id_token") or "")
    return {
        "access_token": access,
        "refresh_token": str(payload.get("refresh_token") or "").strip(),
        "id_token": str(payload.get("id_token") or "").strip(),
        "token_type": str(payload.get("token_type") or "Bearer").strip() or "Bearer",
        "expires_in": expires_in,
        "expired": _add_duration_iso(expires_in),
        "email": email,
        "sub": subject,
    }


def parse_jwt_identity(id_token):
    token = str(id_token or "").strip()
    if not token:
        return "", ""
    parts = token.split(".")
    if len(parts) < 2:
        return "", ""
    payload = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload.encode("ascii"))
        claims = json.loads(raw.decode("utf-8"))
    except Exception:
        return "", ""
    email = str(claims.get("email") or "").strip()
    subject = str(claims.get("sub") or "").strip()
    return email, subject


def sanitize_file_segment(value):
    value = str(value or "").strip()
    if not value:
        return ""
    out = []
    for ch in value:
        if ch.isalnum() or ch in "@._-":
            out.append(ch)
        else:
            out.append("-")
    return "".join(out).strip("-")


def credential_file_name(email="", subject=""):
    email = sanitize_file_segment(email)
    if email:
        return f"xai-{email}.json"
    subject = sanitize_file_segment(subject)
    if subject:
        return f"xai-{subject}.json"
    return f"xai-{int(time.time() * 1000)}.json"


def build_credential_document(token_data, redirect_uri, token_endpoint):
    email = str(token_data.get("email") or "").strip()
    subject = str(token_data.get("sub") or "").strip()
    doc = {
        "access_token": token_data.get("access_token", ""),
        "auth_kind": "oauth",
        "base_url": XAI_DEFAULT_API_BASE,
        "disabled": False,
        "expires_in": token_data.get("expires_in", 0),
        "expired": token_data.get("expired", ""),
        "id_token": token_data.get("id_token", ""),
        "last_refresh": _utc_now_iso(),
        "redirect_uri": redirect_uri,
        "refresh_token": token_data.get("refresh_token", ""),
        "token_endpoint": token_endpoint,
        "token_type": token_data.get("token_type", "Bearer"),
        "type": "xai",
    }
    if email:
        doc["email"] = email
    if subject:
        doc["sub"] = subject
    return doc


def save_credential_file(doc, output_dir):
    output_dir = os.path.abspath(str(output_dir or "").strip() or os.getcwd())
    os.makedirs(output_dir, mode=0o700, exist_ok=True)
    file_name = credential_file_name(doc.get("email", ""), doc.get("sub", ""))
    path = os.path.join(output_dir, file_name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
    # Best-effort CPA auto push (config-driven). Never break credential write.
    try:
        import cpa_push
        cfg_path = Path(os.environ.get("XAI_CONFIG_PATH") or CONFIG_PATH).expanduser().resolve()
        cfg = {}
        if cfg_path.is_file():
            try:
                cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            except Exception:
                cfg = {}
        if isinstance(cfg, dict) and cfg.get("cpa_auto_upload"):
            cpa_push.auto_push_credential_file(config=cfg, credential_path=path)
    except Exception:
        pass
    return path


class _CallbackHandler(BaseHTTPRequestHandler):
    result = None

    def log_message(self, format, *args):
        return

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != XAI_REDIRECT_PATH:
            self.send_response(404)
            self.end_headers()
            return
        qs = parse_qs(parsed.query)
        _CallbackHandler.result = {
            "code": (qs.get("code") or [""])[0].strip(),
            "state": (qs.get("state") or [""])[0].strip(),
            "error": (qs.get("error") or [""])[0].strip(),
        }
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        if _CallbackHandler.result.get("code") and not _CallbackHandler.result.get("error"):
            body = "<h1>Login successful</h1><p>You can close this window.</p>"
        else:
            body = "<h1>Login failed</h1><p>Please check the CLI output.</p>"
        self.wfile.write(body.encode("utf-8"))


def _start_callback_server(port):
    _CallbackHandler.result = None
    server = HTTPServer((XAI_REDIRECT_HOST, port), _CallbackHandler)
    # poll_interval 越小，shutdown 越快响应
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.2),
        name="xai-oauth-callback",
        daemon=True,
    )
    thread.start()
    return server, thread


def _shutdown_server(server, log_callback=None, timeout=2.0):
    """关闭本机回调服务；shutdown() 在部分环境下会卡住，必须限时。"""
    if server is None:
        return

    def _stop():
        try:
            server.shutdown()
        except Exception:
            pass

    t = threading.Thread(target=_stop, name="xai-oauth-shutdown", daemon=True)
    t.start()
    t.join(timeout=max(0.2, float(timeout or 2.0)))
    if t.is_alive():
        _oauth_log(
            log_callback,
            f"回调服务 shutdown 超时({timeout}s)，强制关闭 socket",
            level="warn",
        )
    try:
        server.server_close()
    except Exception:
        pass
    try:
        # 再兜底关底层 socket，避免残留占用端口
        sock = getattr(server, "socket", None)
        if sock is not None:
            sock.close()
    except Exception:
        pass


def _wait_oauth_callback(server, expected_state, cancel_callback=None, timeout=XAI_OAUTH_TIMEOUT):
    deadline = _mono_now() + timeout
    while _mono_now() < deadline:
        if cancel_callback and cancel_callback():
            raise RuntimeError("xai oauth cancelled")
        result = _CallbackHandler.result
        if result is not None:
            if result.get("error"):
                raise RuntimeError(f"xai oauth error: {result['error']}")
            if result.get("state") and result["state"] != expected_state:
                raise RuntimeError("xai oauth invalid state")
            if not result.get("code"):
                raise RuntimeError("xai oauth missing authorization code")
            return result["code"]
        time.sleep(0.2)
    raise RuntimeError("xai oauth callback timeout")


def _extract_code_from_url(url, expected_state):
    parsed = urlparse(str(url or "").strip())
    qs = parse_qs(parsed.query)
    code = (qs.get("code") or [""])[0].strip()
    state = (qs.get("state") or [""])[0].strip()
    err = (qs.get("error") or [""])[0].strip()
    if err:
        raise RuntimeError(f"xai oauth error: {err}")
    if state and state != expected_state:
        raise RuntimeError("xai oauth invalid state from browser url")
    return code



def _looks_like_oauth_code(token: str) -> bool:
    token = str(token or "").strip()
    if not token:
        return False
    if "://" in token or "?" in token or "code=" in token.lower():
        return False
    if len(token) < 40:
        return False
    # xAI callback token: url-safe-ish, often starts with underscore or alnum
    if not re.fullmatch(r"[A-Za-z0-9_\-~.]{40,}", token):
        return False
    return True


def _extract_displayed_callback_token(page):
    """从 xAI “输入此代码以完成登录 / Paste the callback Token” 页提取 code。"""
    data = _run_js_json(
        page,
        r"""function() {
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
const body = (document.body && document.body.innerText) ? document.body.innerText : '';
const lower = body.toLowerCase();
const pageHit = lower.includes('输入此代码')
  || lower.includes('复制到 grok build')
  || lower.includes('paste the')
  || lower.includes('callback token')
  || lower.includes('完成登录')
  || lower.includes('copy the code')
  || lower.includes('to complete');
const candidates = [];
// input / code blocks
for (const n of Array.from(document.querySelectorAll('input, textarea, code, pre, [data-testid], [class*="code"], [class*="token"]'))) {
  if (!isVisible(n)) continue;
  const val = String(n.value || n.textContent || n.innerText || '').replace(/\s+/g, '').trim();
  if (val.length >= 40) candidates.push(val);
}
// button/copy adjacent text
for (const n of Array.from(document.querySelectorAll('div, span, p'))) {
  if (!isVisible(n)) continue;
  const val = String(n.innerText || n.textContent || '').replace(/\s+/g, ' ').trim();
  if (!val || val.length < 40 || val.length > 300) continue;
  // 排除整页大段文案
  if (val.includes(' ') && val.split(' ').length > 3) continue;
  const compact = val.replace(/\s+/g, '');
  if (compact.length >= 40) candidates.push(compact);
}
// regex from body
const re = /[_A-Za-z0-9\-~.]{40,}/g;
let m;
while ((m = re.exec(body)) !== null) {
  candidates.push(m[0]);
}
const uniq = [];
const seen = new Set();
for (const c of candidates) {
  const t = String(c || '').trim();
  if (!t || seen.has(t)) continue;
  seen.add(t);
  uniq.push(t);
}
// rank: prefer underscore-leading long tokens similar to screenshot
uniq.sort((a, b) => {
  const sa = (a.startsWith('_') ? 20 : 0) + Math.min(a.length, 200);
  const sb = (b.startsWith('_') ? 20 : 0) + Math.min(b.length, 200);
  return sb - sa;
});
return {
  pageHit,
  url: location.href,
  token: uniq[0] || '',
  candidates: uniq.slice(0, 5),
  bodySnippet: body.replace(/\s+/g, ' ').trim().slice(0, 180),
};
}""",
        default={"pageHit": False, "token": ""},
    )
    if not isinstance(data, dict):
        return ""
    token = str(data.get("token") or "").strip()
    if _looks_like_oauth_code(token):
        data["ok"] = True
        return token
    # try candidates
    for c in data.get("candidates") or []:
        c = str(c or "").strip()
        if _looks_like_oauth_code(c):
            return c
    return ""


def _dismiss_browser_popups(page):
    """尽量关掉 Chrome 保存密码 / 权限气泡，避免挡住授权页。"""
    return _run_js_json(
        page,
        r"""function() {
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
function label(node) {
  return (node.innerText || node.textContent || node.getAttribute('aria-label') || node.value || '').replace(/\s+/g, ' ').trim();
}
const clicked = [];
const buttons = Array.from(document.querySelectorAll('button, [role="button"]')).filter(isVisible);
for (const n of buttons) {
  const raw = label(n);
  const compact = raw.replace(/\s+/g, '');
  // 密码管理：一律不 / 不用了
  if (compact === '一律不' || compact === '不用了' || compact === '稍后' || compact.toLowerCase() === 'never' || compact.toLowerCase() === 'not now') {
    n.click(); clicked.push(raw); continue;
  }
  // 权限气泡：屏蔽（不要点允许，避免给浏览器权限；OAuth 允许另处理）
  if (compact === '屏蔽' || compact === '阻止' || compact.toLowerCase() === 'block') {
    n.click(); clicked.push(raw); continue;
  }
}
return { clicked };
}""",
        default={"clicked": []},
    )



def _page_body_text(page, limit=1200):
    try:
        raw = page.run_js(
            "return ((document.body && (document.body.innerText || document.body.textContent)) || '').replace(/\\s+/g, ' ').trim().slice(0, arguments[0]);",
            int(limit),
        )
        return str(raw or "").strip()
    except Exception:
        return ""


def _is_cloudflare_interstitial(page):
    """Detect Cloudflare full-page 'Just a moment...' / 确认您是真人 challenge."""
    url = (_page_url(page) or "").lower()
    body = (_page_body_text(page, 800) or "").lower()
    title = ""
    try:
        title = str(getattr(page, "title", "") or "").lower()
        if not title:
            title = str(page.run_js("return document.title || '';") or "").lower()
    except Exception:
        title = ""
    hay = f"{url} {title} {body}"
    markers = (
        "just a moment",
        "确认您是真人",
        "请完成以下操作",
        "needs to review the security",
        "checking your browser",
        "enable javascript and cookies",
        "cf-browser-verification",
        "challenges.cloudflare.com",
        "cdn-cgi/challenge",
    )
    if any(m in hay for m in markers):
        return True
    if ("ray id" in hay) and ("cloudflare" in hay) and ("password" not in body):
        return True
    return False


def _click_cloudflare_interstitial(page):
    """Best-effort click on CF interstitial checkbox / verify control."""
    return _run_js_json(
        page,
        r"""function() {
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
function label(node) {
  return (node.innerText || node.textContent || node.getAttribute('aria-label') || node.value || '').replace(/\s+/g, ' ').trim();
}
const out = { clicked: false, method: '', label: '', candidates: [] };
const buttons = Array.from(document.querySelectorAll('button, input[type="button"], input[type="submit"], [role="button"]'))
  .filter((n) => isVisible(n) && !n.disabled);
for (const n of buttons) {
  const t = label(n).toLowerCase();
  const c = t.replace(/\s+/g, '');
  out.candidates.push(label(n));
  if (c.includes('确认您是真人') || c.includes('验证') || t.includes('verify') || t.includes('continue') || c.includes('继续')) {
    n.focus(); n.click();
    out.clicked = true; out.method = 'button'; out.label = label(n);
    return out;
  }
}
const checks = Array.from(document.querySelectorAll('input[type="checkbox"], [role="checkbox"]')).filter(isVisible);
for (const n of checks) {
  try { n.click(); out.clicked = true; out.method = 'checkbox'; out.label = label(n) || 'checkbox'; return out; } catch (e) {}
}
const boxes = Array.from(document.querySelectorAll('.cf-turnstile, [data-sitekey], iframe, div, label, span')).filter(isVisible).slice(0, 40);
for (const n of boxes) {
  const meta = ((n.className || '') + ' ' + (n.id || '') + ' ' + (n.getAttribute && (n.getAttribute('src') || n.getAttribute('aria-label') || '') || '')).toLowerCase();
  const t = label(n).toLowerCase();
  if (meta.includes('turnstile') || meta.includes('challenge') || meta.includes('cf-') || t.includes('确认您是真人') || t.includes('verify you are human') || t.includes('human')) {
    try { n.click(); out.clicked = true; out.method = 'container'; out.label = label(n) || meta.slice(0, 40); return out; } catch (e) {}
  }
}
return out;
}""",
        default={"clicked": False},
    )


def _browser_from_page(page):
    for attr in ("browser", "tab", "_browser"):
        try:
            obj = getattr(page, attr, None)
        except Exception:
            obj = None
        if obj is None:
            continue
        try:
            b = getattr(obj, "browser", None)
            if b is not None and hasattr(b, "get_tabs"):
                return b
        except Exception:
            pass
        if hasattr(obj, "get_tabs"):
            return obj
    try:
        if hasattr(page, "get_tabs"):
            return page
    except Exception:
        pass
    return None


def _focus_best_oauth_tab(page, log_callback=None):
    """Focus Cloudflare challenge tab or keep the main OAuth tab."""
    browser = _browser_from_page(page)
    if browser is None:
        return page
    try:
        tabs = list(browser.get_tabs() or [])
    except Exception:
        return page
    if not tabs:
        return page

    def tab_url(t):
        try:
            return str(getattr(t, "url", "") or "")
        except Exception:
            return ""

    def tab_title(t):
        try:
            return str(getattr(t, "title", "") or "")
        except Exception:
            return ""

    scored = []
    for t in tabs:
        u = tab_url(t).lower()
        title = tab_title(t).lower()
        score = 0
        kind = "other"
        if "challenges.cloudflare.com" in u or "cdn-cgi/challenge" in u:
            score, kind = 100, "cf-challenge"
        elif "just a moment" in title or "确认您是真人" in title:
            score, kind = 95, "cf-challenge"
        elif "127.0.0.1" in u and "callback" in u:
            score, kind = 90, "callback"
        elif "accounts.x.ai" in u or "auth.x.ai" in u:
            score, kind = 80, "xai"
        elif "about:blank" in u or u in ("", "chrome://newtab/"):
            score, kind = 1, "blank"
        scored.append((score, kind, t, u, title))
    scored.sort(key=lambda x: x[0], reverse=True)
    challenge_tabs = [x for x in scored if x[1] == "cf-challenge"]
    if challenge_tabs:
        score, kind, target, u, title = challenge_tabs[0]
    else:
        score, kind, target, u, title = scored[0]
        if score <= 0:
            return page
    try:
        if hasattr(target, "set") and hasattr(target.set, "activate"):
            target.set.activate()
        elif hasattr(browser, "activate_tab"):
            browser.activate_tab(target)
    except Exception:
        pass
    if log_callback and target is not page:
        _oauth_log(
            log_callback,
            f"检测到多标签，切换到 {kind} | tabs={len(tabs)} | url={_short_url(u)}",
            level="warn",
        )
    return target


def _page_url(page):
    try:
        return str(getattr(page, "url", "") or "")
    except Exception:
        return ""


def _run_js(page, script, *args):
    if args:
        return page.run_js(script, *args)
    return page.run_js(script)


def _run_js_json(page, script_body, *args, default=None):
    """执行 JS 并通过 JSON 字符串取回对象，避免 DrissionPage 复杂对象解析失败。"""
    body = (script_body or "").strip()
    # 统一成 function(){ ... } 形态
    if body.startswith("function"):
        fn_src = body
    elif body.startswith("(function"):
        fn_src = body
        if fn_src.endswith("()"):
            fn_src = fn_src[:-2]
        if fn_src.startswith("(") and fn_src.endswith(")"):
            fn_src = fn_src[1:-1]
    else:
        fn_src = "function(){" + body + "}"
    # 只返回字符串，DrissionPage 对 string 最稳
    wrapped = (
        "function(){ try { const __fn = " + fn_src + "; "
        "const __ret = __fn.apply(null, arguments); "
        "return typeof __ret === 'string' ? __ret : JSON.stringify(__ret); "
        "} catch(e) { return JSON.stringify({ok:false, error:String(e && e.message ? e.message : e)}); } }"
    )
    try:
        if args:
            raw = page.run_js(wrapped, *args)
        else:
            raw = page.run_js(wrapped)
    except Exception as exc:
        if default is not None:
            out = dict(default)
            out["error"] = str(exc)
            return out
        return {"ok": False, "error": str(exc)}
    if isinstance(raw, dict):
        return raw
    s = str(raw or "").strip()
    if not s:
        return default if default is not None else {}
    # 有些版本会多包一层引号
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        try:
            s2 = json.loads(s)
            if isinstance(s2, str):
                s = s2
            elif isinstance(s2, dict):
                return s2
        except Exception:
            pass
    try:
        data = json.loads(s)
        if isinstance(data, dict):
            return data
        return {"value": data}
    except Exception:
        if default is not None:
            out = dict(default)
            out["raw"] = s[:300]
            return out
        return {"raw": s[:300]}


def _phase_from_url(page):
    url = _page_url(page)
    lower = url.lower()
    path = ""
    try:
        path = urlparse(url).path.lower()
    except Exception:
        path = lower
    if "challenges.cloudflare.com" in lower or "cdn-cgi/challenge" in lower:
        return {"phase": "cf_challenge", "url": url, "source": "url-fallback"}
    if "/callback" in lower and "code=" in lower:
        return {"phase": "callback", "url": url, "source": "url-fallback"}
    if path == "/oauth2/consent" or path.startswith("/oauth2/consent/"):
        return {"phase": "consent", "url": url, "source": "url-fallback"}
    if "/sign-in" in path or "/login" in path:
        # 入口页 / 邮箱 / 密码由 DOM 再细分；URL 兜底先当入口
        if "email=true" in lower:
            return {"phase": "signin_email", "url": url, "source": "url-fallback"}
        return {"phase": "signin_entry", "url": url, "source": "url-fallback"}
    return {"phase": "unknown", "url": url, "source": "url-fallback"}


def _detect_oauth_phase(page):
    data = _run_js_json(
        page,
        r"""function() {
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
function inputMeta(node) {
  return [
    `type=${node.getAttribute('type') || ''}`,
    `name=${node.getAttribute('name') || ''}`,
    `ph=${node.getAttribute('placeholder') || ''}`,
    `testid=${node.getAttribute('data-testid') || ''}`,
  ].join(' ');
}
function textOf(node) {
  return [
    node.innerText, node.textContent, node.getAttribute('aria-label'), node.getAttribute('placeholder'), node.getAttribute('name')
  ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim().toLowerCase();
}
function findEmailInput() {
  const all = Array.from(document.querySelectorAll('input, textarea')).filter((n) => isVisible(n) && !n.disabled && !n.readOnly);
  const direct = all.find((n) => {
    const type = (n.type || '').toLowerCase();
    const name = (n.name || '').toLowerCase();
    const testid = (n.getAttribute('data-testid') || '').toLowerCase();
    const ac = (n.autocomplete || '').toLowerCase();
    const meta = textOf(n);
    return type === 'email' || name === 'email' || testid === 'email' || ac === 'email' || meta.includes('邮箱') || meta.includes('email') || meta.includes('e-mail');
  });
  return direct || null;
}
function findPasswordInput() {
  const all = Array.from(document.querySelectorAll('input')).filter((n) => isVisible(n) && !n.disabled && !n.readOnly);
  return all.find((n) => {
    const type = (n.type || '').toLowerCase();
    const name = (n.name || '').toLowerCase();
    const testid = (n.getAttribute('data-testid') || '').toLowerCase();
    const meta = textOf(n);
    return type === 'password' || name === 'password' || testid === 'password' || meta.includes('密码') || meta.includes('password');
  }) || null;
}
const url = location.href;
const path = (location.pathname || '').toLowerCase();
const lowerUrl = url.toLowerCase();
const bodyText = (document.body && document.body.innerText) ? document.body.innerText.toLowerCase() : '';
const titleText = (document.title || '').toLowerCase();
const emailInput = findEmailInput();
const passwordInput = findPasswordInput();
const hasEmail = !!emailInput;
const hasPassword = !!passwordInput;
const visibleInputs = Array.from(document.querySelectorAll('input, textarea')).filter((n) => isVisible(n)).map(inputMeta).slice(0, 8);
const otpInputs = Array.from(document.querySelectorAll('input')).filter((n) => {
  if (!isVisible(n)) return false;
  const im = (n.getAttribute('inputmode') || '').toLowerCase();
  const ac = (n.getAttribute('autocomplete') || '').toLowerCase();
  const dt = (n.getAttribute('data-testid') || '').toLowerCase();
  return im === 'numeric' || ac === 'one-time-code' || dt.includes('otp') || n.getAttribute('data-input-otp') === 'true';
});
const onSignInUrl = path.includes('/sign-in') || path.includes('/login') || lowerUrl.includes('email=true');
const consentHit = (path === '/oauth2/consent' || path.startsWith('/oauth2/consent/')) || (bodyText.includes('allow cli-proxy-api') || bodyText.includes('cli-proxy-api 想要') || bodyText.includes('授权 grok build') || bodyText.includes('authorize') || (bodyText.includes('允许') && bodyText.includes('拒绝') && (bodyText.includes('grok') || bodyText.includes('xai') || bodyText.includes('api'))));
const cfChallenge = lowerUrl.includes('challenges.cloudflare.com')
  || lowerUrl.includes('cdn-cgi/challenge')
  || titleText.includes('just a moment')
  || bodyText.includes('just a moment')
  || bodyText.includes('确认您是真人')
  || bodyText.includes('请完成以下操作，以验证您是真人')
  || bodyText.includes('checking your browser')
  || (bodyText.includes('cloudflare') && bodyText.includes('ray id') && !hasPassword && !hasEmail);
if (cfChallenge) return { phase: 'cf_challenge', url, title: document.title || '', visibleInputs };
if (lowerUrl.includes('/callback') && lowerUrl.includes('code=')) return { phase: 'callback', url, visibleInputs };
if (otpInputs.length > 0) return { phase: 'otp', count: otpInputs.length, url, visibleInputs };
const codePage = bodyText.includes('输入此代码')
  || bodyText.includes('复制到 grok build')
  || bodyText.includes('callback token')
  || bodyText.includes('paste the')
  || bodyText.includes('to complete sign')
  || bodyText.includes('完成登录')
  || bodyText.includes('请勿刷新此页面')
  || bodyText.includes('它将自动检测成功完成')
  || /[_A-Za-z0-9\-~.]{60,}/.test((document.body && document.body.innerText) ? document.body.innerText : '');
// 代码展示页优先于 consent（URL 仍可能是 /oauth2/consent）
if (codePage) return { phase: 'code_display', url, visibleInputs };
if (consentHit && !onSignInUrl) return { phase: 'consent', url, visibleInputs };
if (onSignInUrl) {
  if (hasPassword) return { phase: 'signin_password', url, hasEmail, hasPassword, visibleInputs };
  if (hasEmail) return { phase: 'signin_email', url, hasEmail, hasPassword, visibleInputs };
  return { phase: 'signin_entry', url, hasEmail, hasPassword, visibleInputs };
}
return { phase: 'unknown', url, hasEmail, hasPassword, otpCount: otpInputs.length, visibleInputs };
}""",
        default={"phase": "unknown"},
    )
    if not isinstance(data, dict):
        data = {"phase": "unknown"}
    phase = str(data.get("phase") or "unknown")
    # JS 失败或只返回 unknown 时，用 URL 兜底（登录入口页最常见）
    if phase == "unknown" or data.get("error") or data.get("ok") is False:
        fb = _phase_from_url(page)
        if fb.get("phase") and fb.get("phase") != "unknown":
            fb["js_meta"] = data
            return fb
    if not data.get("url"):
        data["url"] = _page_url(page)
    return data


def _click_email_signin_entry(page):
    return _run_js_json(
        page,
        r"""function() {
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
function nodeText(node) {
  return [
    node.innerText,
    node.textContent,
    node.getAttribute('aria-label'),
    node.getAttribute('title'),
    node.getAttribute('href'),
  ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
function scoreEntry(node) {
  const compact = nodeText(node).replace(/\s+/g, '');
  const lower = compact.toLowerCase();
  if (compact.includes('使用邮箱登录')) return 100;
  if (compact.includes('使用电子邮件登录')) return 98;
  if (lower.includes('signinwithemail') || lower.includes('loginwithemail')) return 95;
  if (lower.includes('continuewithemail')) return 90;
  if (compact.includes('邮箱登录') || compact.includes('邮件登录')) return 85;
  if (lower.includes('email') && (lower.includes('sign') || lower.includes('log') || lower.includes('continue') || lower.includes('use') || lower.includes('with'))) return 80;
  if (lower === 'email' || lower.includes('邮箱')) return 70;
  return 0;
}
const candidates = Array.from(document.querySelectorAll('button, a, [role="button"]'))
  .filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true')
  .map((node) => ({ node, score: scoreEntry(node), text: nodeText(node) }))
  .filter((item) => item.score > 0)
  .sort((a, b) => b.score - a.score);
const target = candidates[0]?.node || null;
if (!target) return { clicked: false, reason: 'no-button', samples: candidates.slice(0, 5).map((x) => x.text) };
target.focus();
target.click();
return { clicked: true, text: candidates[0].text || '', score: candidates[0].score };
}""",
    )


def _page_has_turnstile(page):
    data = _run_js(
        page,
        r"""
const cf = document.querySelector('input[name="cf-turnstile-response"]');
const cfLen = cf ? String(cf.value || '').trim().length : 0;
const present = !!cf || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey]');
return { present, cfLen };
""",
    )
    return data if isinstance(data, dict) else {"present": False, "cfLen": 0}



def _oauth_set_input_value(page, script, *args):
    wrapped = 'function(){' + script.strip() + '}'
    return _run_js_json(page, wrapped, *args, default={"state": "js-error"})


def _fill_signin_email_only(page, email):
    email = str(email or "").strip()
    if not email:
        return "missing-email"
    return _oauth_set_input_value(
        page,
        r"""
const email = String(arguments[0] || '').trim();
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
function textOf(node) {
  return [node.placeholder, node.name, node.getAttribute('aria-label'), node.getAttribute('data-testid')].filter(Boolean).join(' ').toLowerCase();
}
function setValue(input, value) {
  if (!input) return false;
  input.focus(); input.click();
  const proto = input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
  if (setter) setter.call(input, value); else input.value = value;
  input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: value, inputType: 'insertText' }));
  input.dispatchEvent(new InputEvent('input', { bubbles: true, data: value, inputType: 'insertText' }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
  input.blur();
  return String(input.value || '').trim() === value;
}
const candidates = Array.from(document.querySelectorAll('input, textarea')).filter((n) => isVisible(n) && !n.disabled && !n.readOnly);
const emailInput = candidates.find((n) => {
  const type = (n.type || '').toLowerCase();
  const name = (n.name || '').toLowerCase();
  const testid = (n.getAttribute('data-testid') || '').toLowerCase();
  const meta = textOf(n);
  return type === 'email' || name === 'email' || testid === 'email' || (n.autocomplete || '').toLowerCase() === 'email' || meta.includes('邮箱') || meta.includes('email');
});
if (!emailInput) return { state: 'no-email-input', inputs: candidates.map((n) => textOf(n)).slice(0, 6) };
const ok = setValue(emailInput, email);
return ok ? { state: 'filled', value: emailInput.value } : { state: 'fill-failed', value: emailInput.value };
""",
        email,
    )


def _fill_signin_password_only(page, password):
    password = str(password or "").strip()
    if not password:
        return "missing-password"
    return _oauth_set_input_value(
        page,
        r"""
const password = String(arguments[0] || '').trim();
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
function setValue(input, value) {
  if (!input) return false;
  input.focus(); input.click();
  const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
  if (setter) setter.call(input, value); else input.value = value;
  input.dispatchEvent(new InputEvent('input', { bubbles: true, data: value, inputType: 'insertText' }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
  return String(input.value || '').trim() === value;
}
const passwordInput = Array.from(document.querySelectorAll('input')).find((n) => {
  if (!isVisible(n)) return false;
  const type = (n.type || '').toLowerCase();
  const name = (n.name || '').toLowerCase();
  return type === 'password' || name === 'password' || (n.getAttribute('data-testid') || '').toLowerCase() === 'password';
});
if (!passwordInput) return { state: 'no-password-input' };
const ok = setValue(passwordInput, password);
return ok ? { state: 'filled' } : { state: 'fill-failed' };
""",
        password,
    )


def _normalize_fill_result(result):
    if isinstance(result, dict):
        return str(result.get("state") or "unknown"), result
    return str(result or ""), {"raw": result}




def _oauth_probe_turnstile(page):
    try:
        return probe_turnstile_status(page, use_cache=False, scene=SCENE_OAUTH)
    except Exception:
        return _page_has_turnstile(page)


def _oauth_reset_turnstile_widget(page, log_callback=None):
    """Reset on-page Turnstile widget and clear response input. No external token inject."""
    data = _run_js_json(
        page,
        r"""function() {
const out = { reset: false, cleared: 0, error: '' };
try {
  if (window.turnstile && typeof turnstile.reset === 'function') {
    try { turnstile.reset(); out.reset = true; } catch (e1) { out.error = String(e1 && e1.message ? e1.message : e1); }
  }
} catch (e) { out.error = String(e && e.message ? e.message : e); }
try {
  const nodes = Array.from(document.querySelectorAll('input[name="cf-turnstile-response"], input[name="cf_challenge_response"], textarea[name="cf-turnstile-response"]'));
  for (const n of nodes) {
    try {
      const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set
        || Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value')?.set;
      if (nativeSetter) nativeSetter.call(n, '');
      else n.value = '';
      n.dispatchEvent(new Event('input', { bubbles: true }));
      n.dispatchEvent(new Event('change', { bubbles: true }));
      out.cleared += 1;
    } catch (e2) {}
  }
} catch (e3) {}
return out;
}""",
        default={"reset": False, "cleared": 0},
    )
    if log_callback:
        _oauth_log(
            log_callback,
            f"已重置 OAuth 页 Turnstile 组件 | reset={data.get('reset')} cleared={data.get('cleared')} err={data.get('error') or '-'}",
            level="debug",
        )
    return data


def _oauth_success_token_fingerprint(ts_status):
    token = str((ts_status or {}).get("token") or "").strip()
    if len(token) < 20:
        return ""
    # short fingerprint only for change detection, not for reinject
    return f"{len(token)}:{token[:10]}:{token[-10:]}"


def _oauth_sync_turnstile(page, token, log_callback=None):
    try:
        return sync_turnstile_token_to_page(page, token, log_callback=log_callback)
    except Exception:
        return _inject_turnstile_token(page, token)


def _call_turnstile_with_timeout(get_turnstile, log_callback=None, cancel_callback=None, skip_reset=False, timeout=XAI_OAUTH_EXTERNAL_TS_TIMEOUT):
    """Run external turnstile solver with a hard wall-clock timeout (threaded)."""
    if not get_turnstile:
        raise RuntimeError("no turnstile solver")
    timeout = float(timeout or XAI_OAUTH_EXTERNAL_TS_TIMEOUT)
    box = {"token": None, "error": None}

    def _runner():
        try:
            # prefer kwargs; fall back gradually
            try:
                box["token"] = get_turnstile(
                    log_callback=log_callback,
                    cancel_callback=cancel_callback,
                    skip_reset=skip_reset,
                )
            except TypeError:
                try:
                    box["token"] = get_turnstile(
                        log_callback=log_callback,
                        cancel_callback=cancel_callback,
                    )
                except TypeError:
                    box["token"] = get_turnstile()
        except Exception as exc:
            box["error"] = exc

    t = threading.Thread(target=_runner, name="oauth-turnstile-solver", daemon=True)
    t.start()
    # honor caller timeout strictly; floor only when non-positive
    wait_s = timeout if timeout > 0 else float(XAI_OAUTH_EXTERNAL_TS_TIMEOUT)
    t.join(timeout=wait_s)
    if t.is_alive():
        raise TimeoutError(f"Turnstile 外部求解超时({wait_s:.1f}s)")
    if box["error"] is not None:
        raise box["error"]
    token = str(box.get("token") or "").strip()
    if len(token) < 80:
        raise RuntimeError("Turnstile 外部求解未返回有效 token")
    return token


def _oauth_retry_turnstile(page, get_turnstile, log_callback=None, cancel_callback=None, skip_reset=True, timeout=XAI_OAUTH_EXTERNAL_TS_TIMEOUT):
    def _timed_get_token(log_callback=None, cancel_callback=None, skip_reset=False):
        return _call_turnstile_with_timeout(
            get_turnstile,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            skip_reset=skip_reset,
            timeout=timeout,
        )

    return ensure_cf_token(
        page,
        scene=SCENE_OAUTH,
        get_token_fn=_timed_get_token,
        reset=not bool(skip_reset),
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )


def _oauth_cf_ready(status, require_success_mark=True, token_stable=False):
    """Compatibility wrapper over unified classifier."""
    status = status if isinstance(status, dict) else {}
    # emulate old token_stable gate via synthetic token_good_since
    now = _mono_now()
    token_good_since = now - 2.0 if token_stable else 0.0
    classified = classify_cf_status(
        status,
        scene=SCENE_OAUTH,
        token_good_since=token_good_since,
        now=now,
        require_stable_sec=1.0 if require_success_mark else 0.0,
    )
    if status.get("error_mark") or status.get("checkbox_mode"):
        return False
    if classified.get("ready"):
        return True
    if not status.get("present"):
        return True
    if token_stable and max(int(status.get("token_len") or 0), int(status.get("input_len") or 0), int(status.get("api_len") or 0)) >= 80:
        return not status.get("error_mark")
    return False


def _oauth_detect_login_error(page):
    data = _run_js_json(
        page,
        r"""function() {
const body = (document.body && document.body.innerText) ? document.body.innerText : '';
const lower = body.toLowerCase();
const hit = /failed to verify|verify cloudflare|turnstile token|验证失败|人机验证失败|无法验证|incorrect password|密码错误|invalid email or password/.test(lower)
  || lower.includes('trace id');
const checkbox = /确认您是真人|verify you are human|请完成以下验证|请完成验证/.test(body)
  || !!document.querySelector('label[for*="cf-"], input[type="checkbox"][id*="cf"], input[type="checkbox"][name*="cf"]');
const success = /成功[!！]?/.test(body) || !!document.querySelector('[aria-label*="success" i], [aria-label*="成功"]');
return {
  error: hit,
  checkbox,
  success,
  snippet: body.replace(/\s+/g, ' ').trim().slice(0, 180),
};
}""",
        default={"error": False},
    )
    return data if isinstance(data, dict) else {"error": False}


def _click_login_button(page):
    """点击密码页真正的「登录」按钮；严禁点到右上角「您正在登录/账户管理」。"""
    body = r"""
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
function label(node) {
  if (!node) return '';
  const parts = [
    node.getAttribute && node.getAttribute('aria-label'),
    node.getAttribute && node.getAttribute('value'),
    node.value,
  ];
  // 优先取按钮自身文本节点，避免吞进整段导航文案
  let own = '';
  try {
    for (const child of Array.from(node.childNodes || [])) {
      if (child.nodeType === Node.TEXT_NODE) own += child.textContent || '';
    }
  } catch (e) {}
  parts.push(own);
  parts.push(node.innerText);
  parts.push(node.textContent);
  return parts.filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
function compactLabel(raw) {
  return String(raw || '').replace(/\s+/g, '');
}
function isHeaderAccount(node, raw) {
  const compact = compactLabel(raw);
  const lower = compact.toLowerCase();
  if (!compact) return false;
  if (compact.includes('您正在登录') || compact.includes('账户管理') || lower.includes('accountmanagement')) return true;
  if (compact.includes('正在登录') && compact.includes('账户')) return true;
  // 右上角导航：通常 y 很小且文案偏长
  try {
    const rect = node.getBoundingClientRect();
    if (rect.top < 96 && rect.left > (window.innerWidth * 0.45) && compact.length >= 6) {
      if (compact.includes('登录') && (compact.includes('账户') || compact.includes('管理') || compact.includes('您'))) return true;
    }
  } catch (e) {}
  return false;
}
function findPasswordInput() {
  const all = Array.from(document.querySelectorAll('input')).filter((n) => isVisible(n) && !n.disabled);
  return all.find((n) => {
    const type = (n.type || '').toLowerCase();
    const name = (n.name || '').toLowerCase();
    const testid = (n.getAttribute('data-testid') || '').toLowerCase();
    return type === 'password' || name === 'password' || testid === 'password';
  }) || null;
}
function scoreLogin(node, pwd) {
  const raw = label(node);
  const compact = compactLabel(raw);
  const lower = compact.toLowerCase();
  if (!raw) return -100;
  if (isHeaderAccount(node, raw)) return -1000;
  if (compact.includes('忘记密码') || lower.includes('forgot')) return -1000;
  if (compact.includes('返回') || lower === 'back' || lower.includes('go back')) return -1000;
  if (compact.includes('下一步') || lower === 'next') return -200;
  if (compact.includes('使用邮箱登录') || compact.includes('使用google') || compact.includes('使用apple')) return -200;
  if (compact.includes('拒绝') || lower === 'deny') return -1000;
  if (compact.includes('允许') || lower === 'allow') return -50;

  let score = 0;
  if (compact === '登录' || lower === 'signin' || lower === 'login' || lower === 'signin' ) score = 300;
  else if (lower === 'sign in' || lower === 'log in') score = 290;
  else if ((node.type === 'submit' || node.getAttribute('type') === 'submit') && compact.length <= 12 && (compact.includes('登录') || lower.includes('sign') || lower.includes('log'))) score = 260;
  else if (compact.includes('登录') && compact.length <= 6 && !compact.includes('正在') && !compact.includes('账户')) score = 240;
  else if ((lower.includes('sign in') || lower.includes('log in')) && compact.length <= 16) score = 220;
  else if (node.type === 'submit' || node.getAttribute('type') === 'submit') score = 80;
  else return 0;

  // 密码表单内的按钮大幅加权
  if (pwd) {
    const form = pwd.closest('form');
    if (form && form.contains(node)) score += 120;
    try {
      const pr = pwd.getBoundingClientRect();
      const br = node.getBoundingClientRect();
      const dy = br.top - pr.top;
      const dx = Math.abs((br.left + br.width / 2) - (pr.left + pr.width / 2));
      if (dy >= -20 && dy <= 260 && dx <= 360) score += 80;
      if (br.top > pr.top) score += 20;
    } catch (e) {}
  }
  // 惩罚长文案
  if (compact.length > 10) score -= 40;
  if (compact.length > 16) score -= 80;
  return score;
}
function fireClick(node) {
  try { node.scrollIntoView({ block: 'center', inline: 'nearest' }); } catch (e) {}
  try { node.focus(); } catch (e) {}
  const opts = { bubbles: true, cancelable: true, view: window };
  try { node.dispatchEvent(new PointerEvent('pointerdown', opts)); } catch (e) {}
  try { node.dispatchEvent(new MouseEvent('mousedown', opts)); } catch (e) {}
  try { node.dispatchEvent(new PointerEvent('pointerup', opts)); } catch (e) {}
  try { node.dispatchEvent(new MouseEvent('mouseup', opts)); } catch (e) {}
  try { node.click(); } catch (e) {}
  try { node.dispatchEvent(new MouseEvent('click', opts)); } catch (e) {}
}
const pwd = findPasswordInput();
const allVisible = Array.from(document.querySelectorAll('button, [role="button"], input[type="submit"], input[type="button"]'))
  .filter((n) => isVisible(n) && !n.disabled && n.getAttribute('aria-disabled') !== 'true');
const ranked = allVisible
  .map((n) => ({ node: n, score: scoreLogin(n, pwd), label: label(n) }))
  .filter((x) => x.score > 0)
  .sort((a, b) => b.score - a.score);
const candDump = ranked.slice(0, 8).map((x) => ({ label: x.label, score: x.score }));
const allDump = allVisible.slice(0, 12).map((n) => label(n)).filter(Boolean);

if (ranked.length) {
  const best = ranked[0];
  // 最终保险：绝不点账户菜单
  if (isHeaderAccount(best.node, best.label) || compactLabel(best.label).includes('您正在登录') || compactLabel(best.label).includes('账户管理')) {
    // fall through to enter/submit
  } else {
    fireClick(best.node);
    return { clicked: true, label: best.label, score: best.score, method: 'click', candidates: candDump, allVisible: allDump };
  }
}

// 兜底1：密码框所在 form 提交
if (pwd) {
  const form = pwd.closest('form');
  if (form) {
    try {
      if (typeof form.requestSubmit === 'function') {
        form.requestSubmit();
        return { clicked: true, label: 'form-requestSubmit', method: 'requestSubmit', candidates: candDump, allVisible: allDump };
      }
    } catch (e) {}
    try {
      form.submit();
      return { clicked: true, label: 'form-submit', method: 'submit', candidates: candDump, allVisible: allDump };
    } catch (e) {}
  }
  // 兜底2：密码框 Enter
  try {
    pwd.focus();
    const opts = { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true, cancelable: true };
    pwd.dispatchEvent(new KeyboardEvent('keydown', opts));
    pwd.dispatchEvent(new KeyboardEvent('keypress', opts));
    pwd.dispatchEvent(new KeyboardEvent('keyup', opts));
    return { clicked: true, label: 'enter-on-password', method: 'enter', candidates: candDump, allVisible: allDump };
  } catch (e) {}
}
return { clicked: false, candidates: candDump, allVisible: allDump };
"""
    result = _run_js_json(page, "function(){" + body + "}", default={"clicked": False, "error": "js-failed"})
    if not isinstance(result, dict):
        return {"clicked": False, "error": "bad-result", "raw": str(result)[:200]}
    # 二次拦截错误目标
    label = str(result.get("label") or "")
    compact = re.sub(r"\s+", "", label)
    if result.get("clicked") and (
        "您正在登录" in compact
        or "账户管理" in compact
        or "accountmanagement" in compact.lower()
    ):
        result["clicked"] = False
        result["rejected"] = "header-account-menu"
    return result



def _inject_turnstile_token(page, token):
    token = str(token or "").strip()
    if not token:
        return 0
    synced = _run_js(
        page,
        r"""
const token = String(arguments[0] || '').trim();
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
if (!cfInput || !token) return 0;
const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
if (nativeSetter) nativeSetter.call(cfInput, token); else cfInput.value = token;
cfInput.dispatchEvent(new Event('input', { bubbles: true }));
cfInput.dispatchEvent(new Event('change', { bubbles: true }));
return String(cfInput.value || '').trim().length;
""",
        token,
    )
    return int(synced or 0)


def _click_signin_submit(page):
    """兼容旧合并登录/OTP 提交；同样排除账户菜单。"""
    data = _click_login_button(page)
    if isinstance(data, dict) and data.get("clicked"):
        return "clicked"
    # 再尝试宽松 continue/next（仅非账户菜单）
    result = _run_js_json(
        page,
        r"""function() {
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
function label(node) {
  return (node.innerText || node.textContent || node.value || node.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim();
}
const buttons = Array.from(document.querySelectorAll('button, [role="button"], input[type="submit"]'))
  .filter((n) => isVisible(n) && !n.disabled && n.getAttribute('aria-disabled') !== 'true');
for (const n of buttons) {
  const raw = label(n);
  const compact = raw.replace(/\s+/g, '');
  const lower = compact.toLowerCase();
  if (!raw) continue;
  if (compact.includes('您正在登录') || compact.includes('账户管理')) continue;
  if (compact.includes('忘记密码') || compact.includes('返回')) continue;
  if (compact === '登录' || lower === 'sign in' || lower === 'log in' || compact.includes('继续') || lower.includes('continue') || compact === '下一步' || lower === 'next') {
    n.focus(); n.click();
    return { clicked: true, label: raw };
  }
}
return { clicked: false };
}""",
        default={"clicked": False},
    )
    if isinstance(result, dict) and result.get("clicked"):
        return "clicked"
    return "no-button"


def _click_signin_continue(page):
    return _run_js_json(
        page,
        r"""function() {
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
function label(node) {
  return (node.innerText || node.textContent || node.value || node.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim();
}
function scoreNextButton(node) {
  const raw = label(node);
  const compact = raw.replace(/\s+/g, '');
  const lower = compact.toLowerCase();
  if (!raw) return -100;
  if (compact.includes('您正在登录') || compact.includes('账户管理') || lower.includes('accountmanagement')) return -100;
  if (compact.includes('返回') || lower === 'back' || lower.includes('go back')) return -100;
  if (compact.includes('使用邮箱登录') || lower.includes('signupwithemail')) return -50;
  if (compact === '下一步' || compact.includes('下一步')) return 120;
  if (lower === 'next' || lower.includes('next')) return 110;
  if (lower === 'continue' || (lower.includes('continue') && !lower.includes('signin'))) return 100;
  if (compact.includes('继续')) return 95;
  if (node.type === 'submit') return 60;
  if (lower.includes('signin') || lower.includes('login') || compact.includes('登录')) return 20;
  return 0;
}
const buttons = Array.from(document.querySelectorAll('button, [role="button"], input[type="submit"]'))
  .filter((n) => isVisible(n) && !n.disabled && n.getAttribute('aria-disabled') !== 'true')
  .map((n) => ({ node: n, score: scoreNextButton(n), label: label(n) }))
  .filter((x) => x.score > 0)
  .sort((a, b) => b.score - a.score);
const target = buttons[0]?.node || null;
if (!target) {
  const emailInput = document.querySelector('input[type="email"], input[name="email"], input[autocomplete="email"]');
  if (emailInput) {
    emailInput.focus();
    emailInput.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }));
    emailInput.dispatchEvent(new KeyboardEvent('keyup', { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }));
    return { clicked: true, label: 'enter-on-email', method: 'enter', candidates: buttons.slice(0, 5) };
  }
  return { clicked: false, labels: buttons.slice(0, 8).map((x) => x.label), candidates: buttons.slice(0, 5) };
}
target.focus();
target.click();
return { clicked: true, label: buttons[0].label, score: buttons[0].score, method: 'click' };
}""",
        default={"clicked": False},
    )


def _fill_otp_code(page, code):
    code = re.sub(r"\D", "", str(code or ""))
    if not code:
        return "empty-code"
    return _run_js(
        page,
        r"""
const code = String(arguments[0] || '').trim();
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
const boxes = Array.from(document.querySelectorAll('input')).filter((n) => {
  if (!isVisible(n)) return false;
  const im = (n.getAttribute('inputmode') || '').toLowerCase();
  const ac = (n.getAttribute('autocomplete') || '').toLowerCase();
  const dt = (n.getAttribute('data-testid') || '').toLowerCase();
  return im === 'numeric' || ac === 'one-time-code' || dt.includes('otp') || n.getAttribute('data-input-otp') === 'true';
});
if (!boxes.length) return 'no-otp';
if (boxes.length === 1) {
  const box = boxes[0];
  box.focus();
  const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
  if (setter) setter.call(box, code); else box.value = code;
  box.dispatchEvent(new Event('input', { bubbles: true }));
  box.dispatchEvent(new Event('change', { bubbles: true }));
  return 'filled-single';
}
for (let i = 0; i < code.length && i < boxes.length; i++) {
  const box = boxes[i];
  box.focus();
  const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
  if (setter) setter.call(box, code[i]); else box.value = code[i];
  box.dispatchEvent(new Event('input', { bubbles: true }));
}
return 'filled-multi';
""",
        code,
    )


def _click_consent_allow(page):
    return _run_js_json(
        page,
        r"""function() {
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
function label(node) {
  if (!node) return '';
  const parts = [
    node.getAttribute && node.getAttribute('aria-label'),
    node.getAttribute && node.getAttribute('value'),
    node.value,
  ];
  let own = '';
  try {
    for (const child of Array.from(node.childNodes || [])) {
      if (child.nodeType === Node.TEXT_NODE) own += child.textContent || '';
    }
  } catch (e) {}
  parts.push(own, node.innerText, node.textContent);
  return parts.filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
function scoreAllow(node) {
  const raw = label(node);
  const compact = raw.replace(/\s+/g, '');
  const lower = compact.toLowerCase();
  if (!raw) return -100;
  if (compact.includes('您正在登录') || compact.includes('账户管理')) return -1000;
  if (compact === '拒绝' || lower === 'deny' || lower === 'reject' || compact.includes('拒绝')) return -1000;
  if (compact === '屏蔽' || compact === '阻止' || compact === '一律不' || compact === '不用了' || compact === '保存') return -1000;
  if (compact === '允许' || lower === 'allow') return 200;
  if (compact.includes('允许') && compact.length <= 8) return 180;
  if (lower.includes('authorize') || compact.includes('授权') || compact.includes('同意')) return 140;
  if (lower.includes('allow') && compact.length <= 16) return 120;
  return 0;
}
function fireClick(node) {
  try { node.scrollIntoView({ block: 'center', inline: 'nearest' }); } catch (e) {}
  try { node.focus(); } catch (e) {}
  const opts = { bubbles: true, cancelable: true, view: window };
  try { node.dispatchEvent(new PointerEvent('pointerdown', opts)); } catch (e) {}
  try { node.dispatchEvent(new MouseEvent('mousedown', opts)); } catch (e) {}
  try { node.dispatchEvent(new PointerEvent('pointerup', opts)); } catch (e) {}
  try { node.dispatchEvent(new MouseEvent('mouseup', opts)); } catch (e) {}
  try { node.click(); } catch (e) {}
  try { node.dispatchEvent(new MouseEvent('click', opts)); } catch (e) {}
}
const selector = 'button, [role="button"], input[type="submit"], input[type="button"], a';
const allVisible = Array.from(document.querySelectorAll(selector))
  .filter((n) => isVisible(n) && !n.disabled && n.getAttribute('aria-disabled') !== 'true');
const ranked = allVisible
  .map((n) => ({ node: n, score: scoreAllow(n), label: label(n) }))
  .filter((x) => x.score > 0)
  .sort((a, b) => b.score - a.score);
const dumpAll = allVisible.slice(0, 12).map((n) => label(n)).filter(Boolean);
if (!ranked.length) {
  // 文本精确匹配兜底
  const exact = allVisible.find((n) => {
    const c = label(n).replace(/\s+/g, '');
    return c === '允许' || c.toLowerCase() === 'allow';
  });
  if (exact) {
    fireClick(exact);
    return { clicked: true, label: label(exact), score: 200, method: 'exact', allVisible: dumpAll };
  }
  return { clicked: false, reason: 'no-button', candidates: [], allVisible: dumpAll };
}
fireClick(ranked[0].node);
return {
  clicked: true,
  label: ranked[0].label,
  score: ranked[0].score,
  method: 'click',
  candidates: ranked.slice(0, 5).map((x) => ({ label: x.label, score: x.score })),
  allVisible: dumpAll,
};
}""",
        default={"clicked": False, "reason": "js-failed"},
    )


def _reset_oauth_flow_state(state, reason="", keep_counters=False):
    """Clear per-attempt OAuth UI state so a soft reset can re-drive login."""
    if not isinstance(state, dict):
        return
    preserve = {
        "auth_url": state.get("auth_url"),
        "oauth_started_at": state.get("oauth_started_at"),
        "soft_reset_count": state.get("soft_reset_count", 0),
        "last_progress_at": state.get("last_progress_at"),
        "displayed_code": state.get("displayed_code"),
        "code_source": state.get("code_source"),
        "_active_page": state.get("_active_page"),
    }
    if keep_counters:
        preserve["soft_reset_count"] = state.get("soft_reset_count", 0)
    state.clear()
    state.update({k: v for k, v in preserve.items() if v is not None})
    state["need_soft_reset"] = False
    state["soft_reset_reason"] = str(reason or "")
    state["last_progress_at"] = _mono_now()


def _mark_oauth_progress(state, note=""):
    if not isinstance(state, dict):
        return
    state["last_progress_at"] = _mono_now()
    if note:
        state["last_progress_note"] = note


def _oauth_soft_reset(page, state, log_callback=None, reason=""):
    """Reload authorize URL and clear stuck UI state. Limited attempts."""
    if not isinstance(state, dict):
        return False
    count = int(state.get("soft_reset_count") or 0)
    if count >= XAI_OAUTH_MAX_SOFT_RESETS:
        _oauth_log(
            log_callback,
            f"OAuth 软复位次数已达上限({count}/{XAI_OAUTH_MAX_SOFT_RESETS})，不再复位 | reason={reason}",
            level="warn",
        )
        return False
    auth_url = str(state.get("auth_url") or "").strip()
    count += 1
    state["soft_reset_count"] = count
    _oauth_log(
        log_callback,
        f"OAuth 超时复位 ({count}/{XAI_OAUTH_MAX_SOFT_RESETS}) | reason={reason}",
        level="warn",
    )
    _reset_oauth_flow_state(state, reason=reason)
    state["soft_reset_count"] = count
    try:
        clear_cf_for_scene(SCENE_OAUTH, log_callback=None)
    except Exception:
        pass
    if auth_url:
        try:
            page.get(auth_url)
            state["auth_url"] = auth_url
            _mark_oauth_progress(state, "soft-reset-reload")
            _oauth_log(log_callback, f"已重新打开授权页 | url={_short_url(auth_url)}", level="debug")
            return True
        except Exception as exc:
            _oauth_log(log_callback, f"重新打开授权页失败: {exc}", level="warn")
    # fallback refresh/back
    try:
        page.refresh()
        _mark_oauth_progress(state, "soft-reset-refresh")
        return True
    except Exception:
        try:
            page.back()
            _mark_oauth_progress(state, "soft-reset-back")
            return True
        except Exception as exc:
            _oauth_log(log_callback, f"OAuth 软复位失败: {exc}", level="warn")
            return False


def _maybe_oauth_timeout_reset(page, state, phase, log_callback=None):
    """If password/cf/unknown phase stalls too long, soft-reset the OAuth drive."""
    if not isinstance(state, dict):
        return False
    now = _mono_now()
    if not state.get("oauth_started_at"):
        state["oauth_started_at"] = now
    if not state.get("last_progress_at"):
        state["last_progress_at"] = now
    # track phase dwell
    if state.get("_stuck_phase") != phase:
        state["_stuck_phase"] = phase
        state["_stuck_phase_since"] = now
        # phase change is progress (except looping unknown/cf without exit)
        if phase not in ("unknown",):
            _mark_oauth_progress(state, f"phase:{phase}")

    phase_since = float(state.get("_stuck_phase_since") or now)
    progress_at = float(state.get("last_progress_at") or now)
    phase_age = now - phase_since
    no_progress = now - progress_at

    # terminal-ish phases: don't reset
    if phase in ("callback", "code_display", "consent") and phase != "consent":
        return False
    if phase == "consent" and state.get("displayed_code"):
        return False

    reason = ""
    if state.get("need_soft_reset"):
        reason = str(state.get("soft_reset_reason") or "need_soft_reset")
    if phase in ("signin_password", "cf_challenge", "signin", "unknown") and phase_age >= XAI_OAUTH_PHASE_STUCK_SEC:
        reason = reason or f"phase={phase} stuck {phase_age:.0f}s>={XAI_OAUTH_PHASE_STUCK_SEC}s"
    elif no_progress >= XAI_OAUTH_NO_PROGRESS_SEC and phase not in ("callback", "code_display"):
        reason = f"no-progress {no_progress:.0f}s>={XAI_OAUTH_NO_PROGRESS_SEC}s phase={phase}"
    # password page: external solve budget exhausted + still not ready
    if (
        not reason
        and phase == "signin_password"
        and int(state.get("external_ts_attempts") or 0) >= XAI_OAUTH_EXTERNAL_TS_MAX
        and phase_age >= 35
    ):
        reason = f"external-turnstile-exhausted attempts={state.get('external_ts_attempts')} age={phase_age:.0f}s"

    if not reason:
        return False
    # throttle reset attempts
    if now - float(state.get("last_soft_reset_at") or 0) < 8:
        return False
    state["last_soft_reset_at"] = now
    return _oauth_soft_reset(page, state, log_callback=log_callback, reason=reason)


def _oauth_browser_step(
    page,
    email,
    password,
    state,
    fetch_otp=None,
    get_turnstile=None,
    log_callback=None,
    cancel_callback=None,
):
    if cancel_callback and cancel_callback():
        raise RuntimeError("xai oauth cancelled")
    # Cloudflare 有时会新开标签显示 Just a moment，先切到正确标签
    try:
        focused = _focus_best_oauth_tab(page, log_callback=log_callback)
        if focused is not None:
            page = focused
            state["_active_page"] = page
    except Exception as exc:
        _oauth_log(log_callback, f"多标签检查失败: {exc}", level="debug")

    phase_info = _detect_oauth_phase(page)
    phase = str(phase_info.get("phase") or "unknown")
    url = _page_url(page) or str(phase_info.get("url") or "")
    if phase == "unknown" and _is_cloudflare_interstitial(page):
        phase = "cf_challenge"
        phase_info = dict(phase_info or {})
        phase_info["phase"] = phase
        phase_info["forced"] = "cf-interstitial"
    # URL 已明确是登录流时，unknown 直接归到入口，避免空等
    if phase == "unknown" and ("/sign-in" in url or "/login" in url or "sign-in" in url):
        phase = "signin_entry"
        phase_info = dict(phase_info or {})
        phase_info["phase"] = phase
        phase_info["forced"] = "url-signin"
    prev_phase = state.get("_last_phase")
    if phase != prev_phase:
        state["_last_phase"] = phase
        _oauth_log(
            log_callback,
            f"阶段切换 -> {phase} | url={_short_url(url)} | meta={phase_info}",
            level="debug",
        )
        _mark_oauth_progress(state, f"phase-switch:{phase}")

    # 阶段卡死 / 无进展 / 外部求解耗尽：软复位（重新打开授权页）
    if _maybe_oauth_timeout_reset(page, state, phase, log_callback=log_callback):
        state["_last_phase"] = "reset"
        return "reset", state

    if phase == "cf_challenge":
        now = _mono_now()
        state["cf_challenge_hits"] = state.get("cf_challenge_hits", 0) + 1
        state["cf_interstitial_pending"] = True
        if state.get("_last_cf_challenge_log_at", 0) + 5 < now:
            _oauth_log(
                log_callback,
                "检测到 Cloudflare 人机验证整页(Just a moment / 确认您是真人)，等待通过后回到登录流 | "
                f"url={_short_url(url)} | hit={state['cf_challenge_hits']}",
                level="warn",
            )
            state["_last_cf_challenge_log_at"] = now
        # 不要在这里跑外部 Turnstile 求解器：乱点 shadow DOM 容易再开陌生页
        if now - float(state.get("cf_challenge_click_at") or 0) >= 4:
            click = _click_cloudflare_interstitial(page)
            state["cf_challenge_click_at"] = now
            if isinstance(click, dict) and click.get("clicked"):
                _oauth_log(
                    log_callback,
                    f"已尝试点击 Cloudflare 验证控件 | method={click.get('method')} label={click.get('label')!r}",
                    level="debug",
                )
            else:
                _oauth_log(log_callback, f"Cloudflare 整页暂无到可点控件，继续等待 | detail={click}", level="debug")
        if state.get("cf_challenge_hits", 0) >= 25 and now - float(state.get("cf_challenge_reload_at") or 0) >= 30:
            state["cf_challenge_reload_at"] = now
            state["cf_challenge_hits"] = 0
            _oauth_log(log_callback, "Cloudflare 整页停留过久，尝试返回上一页/刷新授权流", level="warn")
            try:
                page.back()
            except Exception:
                try:
                    page.refresh()
                except Exception:
                    pass
        state["_last_phase"] = phase
        return phase, state
    if phase == "callback" or ("/callback" in url and "code=" in url):
        return phase, state
    # 关掉密码保存/权限气泡，避免挡住授权按钮
    if not state.get("_popup_dismiss_at") or (_mono_now() - float(state.get("_popup_dismiss_at") or 0) >= 3):
        try:
            pop = _dismiss_browser_popups(page)
            if isinstance(pop, dict) and pop.get("clicked"):
                _oauth_log(log_callback, f"已关闭浏览器弹层: {pop.get('clicked')}", level="debug")
            state["_popup_dismiss_at"] = _mono_now()
        except Exception:
            pass
    if phase == "code_display":
        token = _extract_displayed_callback_token(page)
        if token:
            state["displayed_code"] = token
            state["code_source"] = "page-display"
            _mark_oauth_progress(state, "code-display")
            _oauth_log(log_callback, f"从授权完成页提取 callback token={_short_token(token)}", level="ok")
        else:
            if state.get("_code_display_log_at", 0) + 5 < _mono_now():
                _oauth_log(log_callback, "已进入代码展示页，等待提取 callback token...", level="debug")
                state["_code_display_log_at"] = _mono_now()
        return phase, state
    if phase in ("signin_entry", "unknown") and ("/sign-in" in url or "/login" in url or "sign-in" in url):
        phase = "signin_entry"
        state["_last_phase"] = phase
        if state.get("email_entry_clicks", 0) < 8:
            result = _click_email_signin_entry(page)
            if isinstance(result, dict) and result.get("clicked"):
                state["email_entry_clicks"] = state.get("email_entry_clicks", 0) + 1
                _mark_oauth_progress(state, "email-entry-click")
                _oauth_log(
                    log_callback,
                    f"已点击「使用邮箱登录」 score={result.get('score')} text={result.get('text', '')[:80]}",
                )
                state["_await_form_since"] = _mono_now()
            else:
                _oauth_log(
                    log_callback,
                    f"未找到「使用邮箱登录」按钮 | detail={result}",
                    level="debug",
                )
    elif phase == "signin_email":
        if state.get("email_fill_attempts", 0) < 20:
            raw = _fill_signin_email_only(page, email)
            status, detail = _normalize_fill_result(raw)
            if not state.get("email_filled_logged") and status == "filled":
                _oauth_log(log_callback, f"邮箱步骤填表={status} | detail={detail}", level="debug")
                state["email_filled_logged"] = True
            elif status != "filled":
                _oauth_log(log_callback, f"邮箱步骤填表={status} | detail={detail}", level="debug")
            if status == "filled":
                state["email_filled"] = True
                if not state.get("email_continue_done"):
                    click = _click_signin_continue(page)
                    _oauth_log(log_callback, f"邮箱步骤点击下一步={click}", level="debug")
                    if isinstance(click, dict) and click.get("clicked"):
                        state["email_continue_done"] = True
                        state["email_continue_at"] = _mono_now()
                    state["email_fill_attempts"] = state.get("email_fill_attempts", 0) + 1
                else:
                    waited = _mono_now() - float(state.get("email_continue_at") or 0)
                    if waited >= 8 and state.get("email_continue_retries", 0) < 3:
                        state["email_continue_retries"] = state.get("email_continue_retries", 0) + 1
                        state["email_continue_done"] = False
                        _oauth_log(log_callback, f"邮箱下一步后 {waited:.0f}s 仍未进入密码页，重试点击下一步 (retry={state['email_continue_retries']})", level="debug")
            else:
                state["email_fill_attempts"] = state.get("email_fill_attempts", 0) + 1
    elif phase == "signin_password":
        now = _mono_now()
        if not state.get("password_phase_entered_at"):
            state["password_phase_entered_at"] = now
            try:
                clear_cf_for_scene(SCENE_OAUTH, log_callback=log_callback)
            except Exception:
                pass
        if not state.get("password_filled_once"):
            raw = _fill_signin_password_only(page, password)
            status, detail = _normalize_fill_result(raw)
            _oauth_log(log_callback, f"密码步骤填表={status} | detail={detail}", level="debug")
            if status == "filled":
                state["password_filled_once"] = True
                state["password_filled_at"] = now
                _mark_oauth_progress(state, "password-filled")

        ts_status = _oauth_probe_turnstile(page)
        err_info = _oauth_detect_login_error(page)
        if err_info.get("success") and not ts_status.get("success_mark"):
            ts_status = dict(ts_status or {})
            ts_status["success_mark"] = True
            ts_status["solved"] = True
        if err_info.get("error") and not ts_status.get("error_mark"):
            ts_status = dict(ts_status or {})
            ts_status["error_mark"] = True
        if err_info.get("checkbox") and not ts_status.get("checkbox_mode"):
            ts_status = dict(ts_status or {})
            ts_status["checkbox_mode"] = True

        ts_present = bool(ts_status.get("present"))
        token_len_now = max(
            int(ts_status.get("token_len") or 0),
            int(ts_status.get("input_len") or 0),
            int(ts_status.get("api_len") or 0),
        )
        input_len = int(ts_status.get("input_len") or 0)
        api_len = int(ts_status.get("api_len") or 0)
        success_now = bool(ts_status.get("success_mark") or err_info.get("success"))
        from_retry = bool(ts_status.get("from_retry") or state.get("last_token_from_retry"))
        # dual token without "成功!" is NOT trusted on OAuth (often Failed to verify)
        dual_token = input_len >= 80 and api_len >= 80
        native_pass = bool(success_now)  # hard rule: only green success counts

        # track success fingerprint; if token changes after success, re-arm stability
        fp = _oauth_success_token_fingerprint(ts_status)
        if success_now and not ts_status.get("error_mark") and not ts_status.get("checkbox_mode") and not err_info.get("error"):
            prev_fp = str(state.get("success_token_fp") or "")
            if not state.get("token_good_since") or (fp and prev_fp and fp != prev_fp):
                state["token_good_since"] = now
                if fp:
                    state["success_token_fp"] = fp
                _oauth_log(
                    log_callback,
                    f"OAuth 检测到原生 Turnstile「成功!」| 等待稳定 {XAI_OAUTH_SUCCESS_STABLE_SEC}s | input={input_len} api={api_len} fp={fp or '-'}",
                    level="debug",
                )
            elif fp and not prev_fp:
                state["success_token_fp"] = fp
        else:
            # lost success / error / checkbox => clear stability
            if not success_now or ts_status.get("error_mark") or err_info.get("error") or ts_status.get("checkbox_mode"):
                state["token_good_since"] = 0.0
                if not success_now:
                    state["success_token_fp"] = ""

        token_good_since = float(state.get("token_good_since") or 0)
        token_stable = bool(success_now and token_good_since and (now - token_good_since >= XAI_OAUTH_SUCCESS_STABLE_SEC))
        classified = classify_cf_status(
            ts_status,
            scene=SCENE_OAUTH,
            token_good_since=token_good_since,
            now=now,
            require_stable_sec=XAI_OAUTH_SUCCESS_STABLE_SEC,
        )
        # OAuth 硬规则：
        # 1) 必须页面显示「成功!」
        # 2) 成功状态稳定一小段时间
        # 3) 禁止仅靠 input/api 双 token 或外部注入
        # 4) 校验失败冷却期内不可点
        post_fail_at = float(state.get("post_verify_fail_at") or 0)
        in_fail_cooldown = bool(post_fail_at and (now - post_fail_at) < XAI_OAUTH_POST_FAIL_COOLDOWN_SEC)
        ts_ready = False
        if success_now and token_stable and not err_info.get("error") and not ts_status.get("checkbox_mode") and not in_fail_cooldown:
            ts_ready = True
        elif not ts_present:
            # no widget: allow login (rare)
            ts_ready = not in_fail_cooldown

        # 即使 DOM 仍残留「成功!」，Failed to verify 也必须按失败处理
        if err_info.get("error") and (not success_now or "failed to verify" in str(err_info.get("snippet") or "").lower()):
            if "failed to verify" in str(err_info.get("snippet") or "").lower():
                success_now = False
                native_pass = False
            last_err_log = float(state.get("_login_err_logged_at") or 0)
            snippet = str(err_info.get("snippet") or "")
            is_verify_fail = ("failed to verify" in snippet.lower()) or ("turnstile" in snippet.lower()) or ("cloudflare" in snippet.lower())
            if (not last_err_log) or (now - last_err_log >= 8):
                _oauth_log(
                    log_callback,
                    f"登录页检测到验证/错误文案 | checkbox={err_info.get('checkbox')} | {snippet[:120]}",
                    level="warn",
                )
                state["_login_err_logged_at"] = now
            state["login_submit_done"] = False
            state["cf_ready_latched"] = False
            state["need_cf_reset"] = True
            state["token_good_since"] = 0.0
            state["success_token_fp"] = ""
            state["last_token_from_retry"] = False
            state["post_verify_fail_at"] = now
            ts_ready = False
            # Failed to verify: UI 可能仍短暂显示成功，但 token 已作废；必须 reset 等新的原生成功
            if is_verify_fail and now - float(state.get("last_widget_reset_at") or 0) >= 3:
                try:
                    _oauth_reset_turnstile_widget(page, log_callback=log_callback)
                    state["last_widget_reset_at"] = now
                    state["verify_fail_resets"] = int(state.get("verify_fail_resets") or 0) + 1
                except Exception as exc:
                    _oauth_log(log_callback, f"Turnstile 组件 reset 失败: {exc}", level="debug")
            # Failed to verify 后可能弹出整页验证；先检查标签，避免立刻外部求解再开陌生页
            try:
                focused = _focus_best_oauth_tab(page, log_callback=log_callback)
                if focused is not None:
                    page = focused
                    state["_active_page"] = page
                if _is_cloudflare_interstitial(page):
                    state["cf_interstitial_pending"] = True
                    _oauth_log(log_callback, "登录失败后进入 Cloudflare 整页验证，暂停外部 Turnstile 求解", level="warn")
            except Exception:
                pass
            try:
                clear_cf_for_scene(SCENE_OAUTH, log_callback=None)
            except Exception:
                pass
            # 多次 verify fail 后走软复位，而不是继续点登录
            if int(state.get("verify_fail_resets") or 0) >= 3:
                state["need_soft_reset"] = True
                state["soft_reset_reason"] = f"verify-fail-x{state.get('verify_fail_resets')}"

        if ts_present and not ts_ready:
            if state.get("_last_cf_log_at", 0) + 3 < now:
                _oauth_log(
                    log_callback,
                    "OAuth 登录等待 Cloudflare | "
                    f"state={classified.get('state')} ready={ts_ready} native={native_pass} "
                    f"success={success_now} tokenLen={token_len_now} input={input_len} api={api_len} "
                    f"from_retry={from_retry} error={bool(ts_status.get('error_mark') or err_info.get('error'))}",
                    level="debug",
                )
                state["_last_cf_log_at"] = now

            waited_on_pwd = now - float(state.get("password_filled_at") or state.get("password_phase_entered_at") or now)
            force_external = bool(
                state.get("need_cf_reset")
                or ts_status.get("error_mark")
                or ts_status.get("checkbox_mode")
                or err_info.get("error")
                or err_info.get("checkbox")
            )
            # 整页 Cloudflare 验证期间禁止外部求解（会点 shadow DOM，容易再开陌生页）
            if state.get("cf_interstitial_pending") or _is_cloudflare_interstitial(page):
                force_external = False
                if state.get("_last_cf_block_log_at", 0) + 8 < now:
                    _oauth_log(log_callback, "OAuth 暂停外部 Turnstile：当前处于 Cloudflare 整页验证", level="debug")
                    state["_last_cf_block_log_at"] = now
                if not _is_cloudflare_interstitial(page):
                    state["cf_interstitial_pending"] = False
            # 先等原生；只有 ERROR/CHECKBOX 或长时间 WAITING 才外部 reset 求解
            min_wait = 6 if force_external else 14
            external_attempts = int(state.get("external_ts_attempts") or 0)
            if (
                (not success_now)
                and (not native_pass)
                and waited_on_pwd >= min_wait
                and now - float(state.get("last_turnstile_at") or 0) >= 12
                and not state.get("cf_interstitial_pending")
                and not _is_cloudflare_interstitial(page)
                and not in_fail_cooldown
                and external_attempts < XAI_OAUTH_EXTERNAL_TS_MAX
                and get_turnstile
            ):
                do_reset = bool(force_external or waited_on_pwd >= 14)
                _oauth_log(
                    log_callback,
                    f"OAuth 登录页 Cloudflare 未就绪({waited_on_pwd:.0f}s)，外部求解 Turnstile | reset={do_reset} | attempt={external_attempts + 1}/{XAI_OAUTH_EXTERNAL_TS_MAX} | timeout={XAI_OAUTH_EXTERNAL_TS_TIMEOUT}s",
                    level="debug",
                )
                state["external_ts_attempts"] = external_attempts + 1
                try:
                    ts_status = _oauth_retry_turnstile(
                        page,
                        get_turnstile,
                        log_callback=log_callback,
                        cancel_callback=cancel_callback,
                        skip_reset=not do_reset,
                        timeout=XAI_OAUTH_EXTERNAL_TS_TIMEOUT,
                    )
                except Exception as exc:
                    _oauth_log(log_callback, f"OAuth Turnstile 外部求解失败/超时: {exc}", level="warn")
                    ts_status = _oauth_probe_turnstile(page)
                    # if solver blocked too long / exhausted, request soft reset
                    if state["external_ts_attempts"] >= XAI_OAUTH_EXTERNAL_TS_MAX or isinstance(exc, TimeoutError):
                        state["need_soft_reset"] = True
                        state["soft_reset_reason"] = f"external-ts-fail:{exc}"
                state["last_turnstile_at"] = now
                state["need_cf_reset"] = False
                state["external_token_at"] = now
                state["last_token_from_retry"] = True
                _oauth_log(
                    log_callback,
                    "OAuth Turnstile 外部求解后 | "
                    f"success={ts_status.get('success_mark')} input={ts_status.get('input_len')} api={ts_status.get('api_len')} "
                    f"（注入 token 不可直接点登录；必须重新出现原生「成功!」）",
                    level="debug",
                )
                # 外部注入后强制不可点，继续等原生成功文案
                state["token_good_since"] = 0.0
                state["success_token_fp"] = ""
                state["cf_ready_latched"] = False
                ts_ready = False
                time.sleep(1.0)
                ts_status = _oauth_probe_turnstile(page)
                err_info = _oauth_detect_login_error(page)
                if err_info.get("success") or ts_status.get("success_mark"):
                    ts_status = dict(ts_status or {})
                    ts_status["success_mark"] = True
                    ts_status["solved"] = True
                    state["last_token_from_retry"] = False
                    state["token_good_since"] = _mono_now()
                    state["success_token_fp"] = _oauth_success_token_fingerprint(ts_status)
                    success_now = True
                    native_pass = True
                else:
                    success_now = False
                    native_pass = False
                input_len = int(ts_status.get("input_len") or 0)
                api_len = int(ts_status.get("api_len") or 0)

        if ts_ready and not state.get("cf_ready_latched"):
            state["cf_ready_latched"] = True
            state["cf_ready_at"] = now
            _mark_oauth_progress(state, "cf-ready")
            _oauth_log(
                log_callback,
                "OAuth Cloudflare 已就绪，准备点击登录 | "
                f"success={success_now} stable={token_stable} input={input_len} api={api_len} fp={state.get('success_token_fp') or '-'}",
            )

        can_login = bool(state.get("password_filled_once")) and ts_ready
        if can_login and state.get("cf_ready_latched"):
            can_login = (now - float(state.get("cf_ready_at") or 0)) >= 0.3
        elif can_login and not state.get("cf_ready_latched"):
            state["cf_ready_latched"] = True
            state["cf_ready_at"] = now
            can_login = False

        # 仅当仍有原生成功信号时，才允许登录后重试点击；禁止 input-only 连点
        last_at = float(state.get("login_submit_at") or 0)
        if (
            state.get("password_filled_once")
            and state.get("login_submit_clicks", 0) > 0
            and last_at > 0
            and now - last_at >= 12
            and state.get("login_submit_clicks", 0) < 3
            and success_now
            and token_stable
            and not err_info.get("error")
            and not in_fail_cooldown
        ):
            can_login = True
            state["login_submit_done"] = False
            state["cf_ready_latched"] = True
            state["cf_ready_at"] = now - 1.0
            _oauth_log(
                log_callback,
                f"登录后仍在密码页({now - last_at:.0f}s)，且仍显示成功，准备再次点击登录",
                level="debug",
            )

        if can_login and state.get("login_submit_clicks", 0) < 3:
            last_at = float(state.get("login_submit_at") or 0)
            allow_click = False
            if not state.get("login_submit_done"):
                allow_click = True
            elif success_now and now - last_at >= 12:
                allow_click = True
                state["login_submit_done"] = False
            if allow_click and (now - last_at >= 1.5 or last_at <= 0):
                # 关键：页面已显示「成功!」时禁止再次写入/注入 token。
                # 二次 sync 会破坏 Cloudflare 已签发 token，表现为 UI 成功但提交 Failed to verify。
                abort_click = False
                try:
                    live = _oauth_probe_turnstile(page)
                    live_err = _oauth_detect_login_error(page)
                    live_success = bool(live.get("success_mark") or live_err.get("success"))
                    live_error = bool(live.get("error_mark") or live_err.get("error"))
                    if live_error and not live_success:
                        _oauth_log(log_callback, "点击前复查：页面已有验证错误，取消登录点击并重置组件", level="warn")
                        abort_click = True
                        state["post_verify_fail_at"] = now
                        state["cf_ready_latched"] = False
                        state["token_good_since"] = 0.0
                        try:
                            _oauth_reset_turnstile_widget(page, log_callback=log_callback)
                        except Exception:
                            pass
                    elif not live_success:
                        _oauth_log(log_callback, "点击前复查：成功状态已消失，取消本次登录点击", level="warn")
                        abort_click = True
                        state["cf_ready_latched"] = False
                        state["token_good_since"] = 0.0
                except Exception:
                    live_success = success_now
                    abort_click = not bool(live_success)

                if not abort_click:
                    click = _click_login_button(page)
                    state["login_submit_clicks"] = state.get("login_submit_clicks", 0) + 1
                    state["login_submit_at"] = now
                    if isinstance(click, dict) and click.get("clicked"):
                        label = str(click.get("label") or "")
                        compact = re.sub(r"\s+", "", label)
                        if "您正在登录" in compact or "账户管理" in compact:
                            _oauth_log(
                                log_callback,
                                f"登录点击被拒绝（账户菜单）| detail={click}",
                                level="warn",
                            )
                            state["login_submit_done"] = False
                        else:
                            state["login_submit_done"] = True
                            state["last_login_token_fp"] = str(state.get("success_token_fp") or "")
                            _mark_oauth_progress(state, "login-clicked")
                            _oauth_log(
                                log_callback,
                                f"已点击「登录」按钮 | label={label!r} score={click.get('score')} method={click.get('method')} success={success_now} stable={token_stable} (no-token-reinject)",
                            )
                    else:
                        _oauth_log(log_callback, f"未点到「登录」按钮 | detail={click}", level="debug")
        elif not state.get("password_filled_once"):
            _oauth_log(log_callback, "密码未填好，等待填表", level="debug")

    elif phase == "signin":
        # 兼容旧合并表单
        if state.get("signin_attempts", 0) < 12:
            e_raw = _fill_signin_email_only(page, email)
            e_status, _ = _normalize_fill_result(e_raw)
            p_raw = _fill_signin_password_only(page, password)
            p_status, _ = _normalize_fill_result(p_raw)
            _oauth_log(log_callback, f"合并登录填表 email={e_status} password={p_status}", level="debug")
            if e_status == "filled" and p_status == "filled":
                ts_info = _page_has_turnstile(page)
                now = _mono_now()
                if get_turnstile and ts_info.get("present") and int(ts_info.get("cfLen") or 0) < 80 and now - state.get("last_turnstile_at", 0.0) >= 8:
                    try:
                        token = get_turnstile(log_callback=log_callback, cancel_callback=cancel_callback)
                        _inject_turnstile_token(page, token)
                    except Exception as exc:
                        _oauth_log(log_callback, f"Turnstile 失败: {exc}", level="debug")
                    state["last_turnstile_at"] = now
                if _click_signin_submit(page) == "clicked":
                    state["signin_attempts"] = state.get("signin_attempts", 0) + 1
    elif phase == "otp":
        if fetch_otp and state.get("otp_attempts", 0) < 6:
            try:
                code = fetch_otp(log_callback=log_callback, cancel_callback=cancel_callback)
                if code:
                    result = _fill_otp_code(page, code)
                    _oauth_log(log_callback, f"OTP 填写结果={result} | code={code}")
                    state["otp_attempts"] = state.get("otp_attempts", 0) + 1
                    _click_signin_submit(page)
            except Exception as exc:
                _oauth_log(log_callback, f"OTP 拉取/填写失败: {exc}", level="debug")
    elif phase == "consent":
        # 有些情况下 URL 仍是 /oauth2/consent，但页面已变成代码展示
        token = _extract_displayed_callback_token(page)
        if token:
            state["displayed_code"] = token
            state["code_source"] = "consent-page-scan"
            _oauth_log(log_callback, f"授权 URL 上扫到 callback token={_short_token(token)}", level="ok")
            return "code_display", state
        if state.get("consent_attempts", 0) < 8:
            if not state.get("consent_page_logged"):
                _oauth_log(log_callback, "OAuth 授权页：请点击「允许」完成 Grok Build 授权", level="debug")
                state["consent_page_logged"] = True
            clicked = _click_consent_allow(page)
            if isinstance(clicked, dict) and clicked.get("clicked"):
                state["consent_allow_done"] = True
                _oauth_log(log_callback, f"已点击「允许」| detail={clicked}", level="ok")
            else:
                # 只剩“退出登录”时，说明不是真正的允许页，别刷屏
                visibles = []
                if isinstance(clicked, dict):
                    visibles = clicked.get("allVisible") or []
                only_signout = visibles and all(("退出" in str(x) or "sign out" in str(x).lower()) for x in visibles)
                if only_signout:
                    if state.get("consent_attempts", 0) == 0:
                        _oauth_log(log_callback, f"授权页无「允许」按钮，可能已进入代码页 | detail={clicked}", level="debug")
                    state["consent_attempts"] = 8
                else:
                    _oauth_log(log_callback, f"授权页点击结果={clicked} | consent_attempt={state.get('consent_attempts', 0)}", level="debug")
                    state["consent_attempts"] = state.get("consent_attempts", 0) + 1
    state["_last_phase"] = phase
    return phase, state


def run_xai_oauth_after_sso(
    page,
    email_hint="",
    password="",
    mail_token="",
    output_dir="",
    callback_port=56121,
    proxy="",
    fetch_otp=None,
    get_turnstile=None,
    log_callback=None,
    cancel_callback=None,
):
    if page is None:
        raise RuntimeError("xai oauth: browser page is required")

    output_dir = str(output_dir or "").strip()
    if not output_dir:
        raise RuntimeError("xai_oauth_output_dir is not configured")

    port = int(callback_port or 56121)
    proxies = {"http": proxy, "https": proxy} if str(proxy or "").strip() else {}

    _oauth_log(log_callback, "6. 开始获取 CLIProxyAPI 凭证")
    _oauth_log(
        log_callback,
        f"参数 email={_mask_email(email_hint)} | hasMailToken={bool(str(mail_token or '').strip())} | callbackPort={port} | outDir={output_dir}",
        level="debug",
    )

    code_verifier, code_challenge = generate_pkce_codes()
    state = generate_random_token(32)
    nonce = generate_random_token(32)
    auth_endpoint, token_endpoint = discover_endpoints(proxies=proxies)
    redirect_uri = f"http://{XAI_REDIRECT_HOST}:{port}{XAI_REDIRECT_PATH}"
    auth_url = build_authorize_url(
        auth_endpoint, redirect_uri, code_challenge, state, nonce
    )

    server, _thread = _start_callback_server(port)
    try:
        _oauth_log(log_callback, f"本机回调监听 redirect_uri={redirect_uri}")
        page.get(auth_url)
        _oauth_log(log_callback, f"OIDC auth_ep={_short_url(auth_endpoint, 80)} token_ep={_short_url(token_endpoint, 80)}")
        _oauth_log(log_callback, f"PKCE ready | oauth_state={_short_token(state)} nonce={_short_token(nonce)}")
        _oauth_log(log_callback, f"打开授权页 auth_url={_short_url(auth_url, 160)}")
        if not str(password or "").strip():
            raise RuntimeError("xai oauth: registration password is required for sign-in")

        code = None
        deadline = _mono_now() + XAI_OAUTH_TIMEOUT
        last_drive = 0.0
        oauth_state = {
            "auth_url": auth_url,
            "oauth_started_at": _mono_now(),
            "last_progress_at": _mono_now(),
            "soft_reset_count": 0,
        }
        last_heartbeat = 0.0
        while _mono_now() < deadline:
            if cancel_callback and cancel_callback():
                raise RuntimeError("xai oauth cancelled")
            if _mono_now() - last_drive >= 0.8:
                if not isinstance(oauth_state, dict):
                    oauth_state = {
                        "auth_url": auth_url,
                        "oauth_started_at": _mono_now(),
                        "last_progress_at": _mono_now(),
                    }
                else:
                    oauth_state.setdefault("auth_url", auth_url)
                _oauth_browser_step(
                    page,
                    email_hint,
                    password,
                    oauth_state,
                    fetch_otp=fetch_otp,
                    get_turnstile=get_turnstile,
                    log_callback=log_callback,
                    cancel_callback=cancel_callback,
                )
                if isinstance(oauth_state, dict) and oauth_state.get("_active_page") is not None:
                    page = oauth_state.get("_active_page")
                if (
                    isinstance(oauth_state, dict)
                    and int(oauth_state.get("soft_reset_count") or 0) >= XAI_OAUTH_MAX_SOFT_RESETS
                    and (_mono_now() - float(oauth_state.get("last_progress_at") or _mono_now())) >= XAI_OAUTH_PHASE_STUCK_SEC
                    and str(oauth_state.get("_last_phase") or "") in ("signin_password", "cf_challenge", "unknown", "reset", "signin")
                ):
                    raise RuntimeError(
                        "xai oauth stalled after soft resets: "
                        f"phase={oauth_state.get('_last_phase')} resets={oauth_state.get('soft_reset_count')}"
                    )
                last_drive = _mono_now()
            now = _mono_now()
            if now - last_heartbeat >= 15:
                last_heartbeat = now
                st = oauth_state or {}
                stuck_for = int(max(0, now - float(st.get('_stuck_phase_since') or st.get('last_progress_at') or now)))
                _oauth_log(
                    log_callback,
                    "等待回调心跳 | "
                    f"phase={st.get('_last_phase', 'n/a')} stuck={stuck_for}s | "
                    f"entry={st.get('email_entry_clicks', 0)} login={st.get('login_submit_clicks', 0)} otp={st.get('otp_attempts', 0)} consent={st.get('consent_attempts', 0)} | "
                    f"extTS={st.get('external_ts_attempts', 0)}/{XAI_OAUTH_EXTERNAL_TS_MAX} reset={st.get('soft_reset_count', 0)}/{XAI_OAUTH_MAX_SOFT_RESETS} | "
                    f"url={_short_url(_page_url(page))} | remain={int(max(0, deadline - now))}s",
                    level="debug",
                )
                # 超时强制退出检查
                if now >= deadline:
                    _oauth_log(log_callback, f"OAuth 等待回调超时({XAI_OAUTH_TIMEOUT}s)，强制退出", level="warning")
                    raise RuntimeError(f"xai oauth timeout after {XAI_OAUTH_TIMEOUT}s")
            cb = _CallbackHandler.result
            if cb and cb.get("code"):
                if cb.get("state") and cb["state"] != state:
                    raise RuntimeError("xai oauth invalid state")
                code = cb["code"].strip()
                _oauth_log(log_callback, f"收到本机回调 code={_short_token(code)}", level="ok")
                break
            # xAI 有时不跳 127.0.0.1，而是展示 callback token 页面（CLIProxyAPI 手动粘贴模式）
            st = oauth_state or {}
            if st.get("displayed_code"):
                code = str(st.get("displayed_code") or "").strip()
                _oauth_log(
                    log_callback,
                    f"使用页面展示的 callback token 换凭证 | source={st.get('code_source')} code={_short_token(code)}",
                    level="ok",
                )
                break
            try:
                current_url = str(getattr(page, "url", "") or "")
                if "/callback" in current_url and "code=" in current_url:
                    code = _extract_code_from_url(current_url, state)
                    _oauth_log(log_callback, f"从浏览器 URL 解析 code={_short_token(code)}", level="ok")
                    break
                # 即使 phase 未识别，也尝试扫页面 token
                maybe = _extract_displayed_callback_token(page)
                if maybe:
                    code = maybe
                    _oauth_log(log_callback, f"扫描页面得到 callback token={_short_token(code)}", level="ok")
                    break
            except Exception:
                pass
            time.sleep(0.5)

        if not code:
            code = _wait_oauth_callback(
                server, state, cancel_callback=cancel_callback, timeout=max(1, int(deadline - _mono_now()))
            )

        _oauth_log(log_callback, "开始 token 交换")
        token_data = exchange_code_for_tokens(
            code, redirect_uri, code_verifier, token_endpoint, proxies=proxies
        )
        _oauth_log(
            log_callback,
            f"token 交换成功 | email={_mask_email(token_data.get('email', ''))} | sub={_short_token(token_data.get('sub', ''))} | expires_in={token_data.get('expires_in')} | refresh={_short_token(token_data.get('refresh_token', ''))}",
            level="debug",
        )
        if email_hint and token_data.get("email"):
            if token_data["email"].lower() != str(email_hint).lower():
                if log_callback:
                    log_callback(
                        f"[!] xAI OAuth 邮箱与注册邮箱不一致: oauth={token_data['email']} register={email_hint}"
                    )
        elif email_hint and not token_data.get("email"):
            token_data["email"] = str(email_hint).strip()

        doc = build_credential_document(token_data, redirect_uri, token_endpoint)
        path = save_credential_file(doc, output_dir)
        _oauth_log(log_callback, f"凭证已保存 path={path}", level="ok")
        _oauth_log(log_callback, "OAuth 完成，正在关闭回调服务并返回主流程...", level="debug")
        return path
    finally:
        _shutdown_server(server, log_callback=log_callback, timeout=2.0)
        _oauth_log(log_callback, "OAuth 回调服务已清理", level="debug")

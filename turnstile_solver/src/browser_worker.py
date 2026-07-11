from __future__ import annotations

import json
import os
import secrets
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import SolverConfig
from .models import FingerprintSnapshot, SolveRequest, SolveResult
from .proxy import normalize_proxy, parse_proxy

LogFn = Optional[Callable[[str], None]]

# Parent repo root: .../grok协议
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


CLICK_EMAIL_JS = r"""
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
    if (compact.includes('使用邮箱注册')) return 100;
    if (lower.includes('signupwithemail')) return 95;
    if (lower.includes('continuewithemail')) return 90;
    if (lower.includes('email') && (lower.includes('sign') || lower.includes('continue') || lower.includes('use') || lower.includes('with'))) return 80;
    if (lower === 'email' || lower.includes('邮箱')) return 70;
    return 0;
}
const candidates = Array.from(document.querySelectorAll('button, a, [role="button"]'))
    .filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true')
    .map((node) => ({ node, score: scoreEntry(node), text: nodeText(node) }))
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score);
const target = candidates[0]?.node || null;
if (!target) return false;
target.click();
return candidates[0].text || true;
"""


def click_email_signup_entry(page: Any, *, log_callback: LogFn = None, timeout: int = 12) -> bool:
    deadline = time.monotonic() + max(3, int(timeout or 12))
    while time.monotonic() < deadline:
        try:
            clicked = page.run_js(CLICK_EMAIL_JS)
        except Exception:
            clicked = False
        if clicked:
            detail = f": {clicked}" if isinstance(clicked, str) else ""
            _log(log_callback, f"[Turnstile] 已点击邮箱注册入口{detail}")
            time.sleep(1.5)
            return True
        time.sleep(0.8)
    return False

TOKEN_READ_JS = """
const cf = document.querySelector('input[name="cf-turnstile-response"]');
let v = cf ? String(cf.value || '').trim() : '';
if ((!v || v.length < 20) && window.turnstile && typeof turnstile.getResponse === 'function') {
  try { v = String(turnstile.getResponse() || '').trim(); } catch (e) {}
}
return v;
"""

FINGERPRINT_READ_JS = """
const uaData = navigator.userAgentData;
let uaJson = {};
try {
  if (uaData && typeof uaData.toJSON === 'function') {
    uaJson = uaData.toJSON() || {};
  }
} catch (e) {
  uaJson = {};
}
// toJSON() 在部分上下文会丢字段；低熵属性直接补齐。
if (uaData) {
  if (!uaJson || typeof uaJson !== 'object') uaJson = {};
  if (uaJson.platform == null || uaJson.platform === '') {
    try { uaJson.platform = String(uaData.platform || ''); } catch (e) {}
  }
  if (!Array.isArray(uaJson.brands)) {
    try { uaJson.brands = Array.isArray(uaData.brands) ? uaData.brands : []; } catch (e) { uaJson.brands = []; }
  }
  if (typeof uaJson.mobile !== 'boolean') {
    try { uaJson.mobile = !!uaData.mobile; } catch (e) { uaJson.mobile = false; }
  }
}
const languages = Array.isArray(navigator.languages) ? navigator.languages.map(String) : [];
let timezone = '';
try { timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) {}
return {
  user_agent: String(navigator.userAgent || ''),
  user_agent_data: uaJson || {},
  accept_language: languages.join(', '),
  navigator_language: String(navigator.language || ''),
  navigator_languages: languages,
  platform: String(navigator.platform || ''),
  timezone: String(timezone || ''),
  is_secure_context: typeof window.isSecureContext === 'boolean' ? window.isSecureContext : null,
  has_user_agent_data: !!uaData,
  href: String(location.href || ''),
  viewport: {
    inner_width: Number(window.innerWidth || 0),
    inner_height: Number(window.innerHeight || 0),
    screen_width: Number(screen.width || 0),
    screen_height: Number(screen.height || 0),
  },
  device_scale_factor: Number(window.devicePixelRatio || 1),
  webdriver: typeof navigator.webdriver === 'boolean' ? navigator.webdriver : null,
};
"""

UA_HIGH_ENTROPY_CDP_EXPRESSION = """
(() => {
  if (!navigator.userAgentData || typeof navigator.userAgentData.getHighEntropyValues !== 'function') {
    return Promise.reject(new Error('navigator.userAgentData.getHighEntropyValues unavailable'));
  }
  return navigator.userAgentData.getHighEntropyValues([
    'platform',
    'fullVersionList',
    'platformVersion',
    'architecture',
    'bitness'
  ]);
})()
"""

PAGE_DIAG_JS = """
const html = document.documentElement ? document.documentElement.innerHTML : '';
const bodyText = (document.body && document.body.innerText) ? document.body.innerText : '';
const cf = document.querySelector('input[name="cf-turnstile-response"]');
const token = cf ? String(cf.value || '').trim() : '';
let turnstileResp = '';
try {
  if (window.turnstile && typeof turnstile.getResponse === 'function') {
    turnstileResp = String(turnstile.getResponse() || '').trim();
  }
} catch (e) {}
const sitekeys = [];
const pushKey = (k) => {
  k = String(k || '').trim();
  if (k && !sitekeys.includes(k)) sitekeys.push(k);
};
document.querySelectorAll('[data-sitekey]').forEach(el => pushKey(el.getAttribute('data-sitekey')));
const m1 = html.match(/data-sitekey=[\"']([^\"']+)[\"']/ig) || [];
m1.forEach(s => {
  const mm = s.match(/data-sitekey=[\"']([^\"']+)[\"']/i);
  if (mm) pushKey(mm[1]);
});
const m2 = html.match(/sitekey[\"']?\\s*[:=]\\s*[\"']([^\"']+)[\"']/ig) || [];
m2.forEach(s => {
  const mm = s.match(/[\"']([^\"']+)[\"']\\s*$/i) || s.match(/[:=]\\s*[\"']([^\"']+)[\"']/i);
  if (mm) pushKey(mm[1]);
});
const iframes = [...document.querySelectorAll('iframe')].map(f => {
  const src = String(f.src || '');
  return {
    src: src.slice(0, 180),
    title: String(f.title || ''),
    id: String(f.id || ''),
    name: String(f.name || ''),
    isTurnstile: /turnstile|challenges\\.cloudflare\\.com|cf-chl|cloudflare/i.test(src + ' ' + (f.title||'') + ' ' + (f.name||'')),
  };
}).slice(0, 20);
const widgets = [...document.querySelectorAll('.cf-turnstile, [data-sitekey], #cf-turnstile, #turnstile-wrapper, iframe[src*="turnstile"], iframe[src*="challenges.cloudflare"]')].length;
return {
  url: location.href,
  title: document.title || '',
  readyState: document.readyState || '',
  hasCfInput: !!cf,
  tokenLen: token.length,
  turnstileApiType: typeof window.turnstile,
  turnstileRespLen: turnstileResp.length,
  sitekeys,
  sitekeyCount: sitekeys.length,
  iframeCount: iframes.length,
  turnstileIframeCount: iframes.filter(x => x.isTurnstile).length,
  iframes,
  widgetLikeCount: widgets,
  challengeLike: /(just a moment|checking your browser|cf-browser-verification|attention required|verify you are human)/i.test(html + ' ' + bodyText),
  bodySnippet: bodyText.replace(/\\s+/g, ' ').trim().slice(0, 220),
};
"""


def _inject_turnstile_widget_js(*, sitekey: str, action: str = "", cdata: str = "") -> str:
    sitekey_js = json.dumps(str(sitekey or "").strip())
    action_js = json.dumps(str(action or "").strip())
    cdata_js = json.dumps(str(cdata or "").strip())
    return f"""
const sitekey = {sitekey_js};
const action = {action_js};
const cdata = {cdata_js};
if (!sitekey) return {{ok:false, reason:'empty-sitekey'}};
window.__xaiTsToken = window.__xaiTsToken || '';
window.__xaiTsMeta = {{sitekey, action, cdata}};
let host = document.getElementById('xai-local-ts-host');
if (!host) {{
  host = document.createElement('div');
  host.id = 'xai-local-ts-host';
  host.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:2147483647;background:#fff;padding:12px;border:1px solid #d0d7de;border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.12);width:320px;min-height:70px';
  document.documentElement.appendChild(host);
}}
function ensureHiddenInput() {{
  let input = document.querySelector('input[name="cf-turnstile-response"]');
  if (!input) {{
    input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'cf-turnstile-response';
    document.documentElement.appendChild(input);
  }}
  return input;
}}
function onToken(token) {{
  token = String(token || '').trim();
  window.__xaiTsToken = token;
  try {{ ensureHiddenInput().value = token; }} catch (e) {{}}
}}
function doRender() {{
  if (!window.turnstile || typeof turnstile.render !== 'function') {{
    return {{ok:false, reason:'turnstile-api-missing'}};
  }}
  if (window.__xaiTsWidgetId != null) {{
    try {{
      const existing = String(turnstile.getResponse(window.__xaiTsWidgetId) || '').trim();
      if (existing) onToken(existing);
    }} catch (e) {{}}
    return {{ok:true, reason:'already-rendered', widgetId:window.__xaiTsWidgetId, tokenLen:(window.__xaiTsToken||'').length}};
  }}
  const opts = {{
    sitekey,
    callback:onToken,
    'error-callback':function(code){{ window.__xaiTsLastError = String(code || 'error'); }},
    'expired-callback':function(){{ window.__xaiTsToken = ''; try {{ ensureHiddenInput().value = ''; }} catch (e) {{}} }},
    'timeout-callback':function(){{ window.__xaiTsLastError = 'timeout'; }},
    size:'normal',
    theme:'light',
    retry:'auto'
  }};
  if (action) opts.action = action;
  if (cdata) opts.cData = cdata;
  try {{
    window.__xaiTsWidgetId = turnstile.render(host, opts);
    try {{ if (typeof turnstile.execute === 'function') turnstile.execute(window.__xaiTsWidgetId); }} catch (e) {{}}
    return {{ok:true, reason:'rendered', widgetId:window.__xaiTsWidgetId, tokenLen:(window.__xaiTsToken||'').length}};
  }} catch (e) {{
    return {{ok:false, reason:'render-error', error:String(e)}};
  }}
}}
const existingScript = document.querySelector('script[src*="challenges.cloudflare.com/turnstile"], script[src*="turnstile/v0/api.js"]');
if (!existingScript) {{
  const script = document.createElement('script');
  script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
  script.async = true;
  script.defer = true;
  script.onload = function() {{ try {{ doRender(); }} catch (e) {{}} }};
  document.head.appendChild(script);
  return {{ok:true, reason:'script-loading'}};
}}
return doRender();
"""


def _ensure_injected_turnstile_widget(
    page: Any,
    *,
    sitekey: str,
    action: str = "",
    cdata: str = "",
    deadline: float,
    log_callback: LogFn = None,
    wait_api_sec: float = 3.0,
) -> Dict[str, Any]:
    sitekey = str(sitekey or "").strip()
    if not sitekey:
        return {"ok": False, "reason": "empty-sitekey"}
    local_deadline = min(
        float(deadline),
        time.monotonic() + max(0.0, float(wait_api_sec or 0)),
    )
    last: Dict[str, Any] = {"ok": False, "reason": "not-started"}
    attempt = 0
    while time.monotonic() < float(deadline):
        attempt += 1
        try:
            result = page.run_js(
                _inject_turnstile_widget_js(sitekey=sitekey, action=action, cdata=cdata)
            )
        except Exception as exc:
            return {"ok": False, "reason": f"inject-exception:{exc}"}
        last = result if isinstance(result, dict) else {
            "ok": False,
            "reason": "non-object",
            "raw": str(result),
        }
        reason = str(last.get("reason") or "")
        if last.get("ok") and reason in {"rendered", "already-rendered"}:
            _log(
                log_callback,
                f"[Turnstile] explicit widget ready reason={reason} attempt={attempt}",
            )
            return last
        retryable = (
            (last.get("ok") and reason == "script-loading")
            or ((not last.get("ok")) and reason in {"turnstile-api-missing", "render-error"})
        )
        now = time.monotonic()
        if not retryable or now >= local_deadline or now >= float(deadline):
            break
        time.sleep(min(0.35, local_deadline - now, float(deadline) - now))
    return last


def _nudge_turnstile_widget(page: Any, *, log_callback: LogFn = None) -> str:
    actions: List[str] = []
    try:
        clicked = page.run_js(
            """
const nodes = Array.from(document.querySelectorAll(
  '#xai-local-ts-host, #xai-local-ts-host iframe, .cf-turnstile, [data-sitekey], #cf-turnstile, #turnstile-wrapper, iframe[src*="turnstile"], iframe[src*="challenges.cloudflare"]'
));
let count = 0;
for (const node of nodes) {
  try { node.scrollIntoView({block:'center', inline:'center'}); } catch (e) {}
  try { node.click(); count += 1; } catch (e) {}
  try {
    const rect = node.getBoundingClientRect();
    const x = rect.left + Math.min(Math.max(rect.width * 0.2, 8), 40);
    const y = rect.top + rect.height / 2;
    for (const type of ['pointerdown', 'mousedown', 'mouseup', 'click']) {
      node.dispatchEvent(new MouseEvent(type, {bubbles:true, clientX:x, clientY:y, view:window}));
    }
  } catch (e) {}
}
return count;
"""
        )
        if int(clicked or 0) > 0:
            actions.append(f"dom:{clicked}")
    except Exception:
        pass
    try:
        api_result = page.run_js(
            """
const out = {executed:false, tokenLen:0, error:''};
try {
  if (window.turnstile && window.__xaiTsWidgetId != null) {
    try {
      const token = String(turnstile.getResponse(window.__xaiTsWidgetId) || '').trim();
      out.tokenLen = token.length;
      if (token) {
        window.__xaiTsToken = token;
        const input = document.querySelector('input[name="cf-turnstile-response"]');
        if (input) input.value = token;
      }
    } catch (e) {}
    try {
      if (typeof turnstile.execute === 'function') {
        turnstile.execute(window.__xaiTsWidgetId);
        out.executed = true;
      }
    } catch (e) { out.error = String(e); }
  }
} catch (e) { out.error = String(e); }
return out;
"""
        )
        if isinstance(api_result, dict):
            if api_result.get("executed"):
                actions.append("api-execute")
            if int(api_result.get("tokenLen") or 0) >= 80:
                actions.append(f"api-token:{api_result.get('tokenLen')}")
    except Exception:
        pass
    try:
        challenge_input = page.ele("@name=cf-turnstile-response", timeout=0.2)
        if challenge_input is not None:
            try:
                wrapper = challenge_input.parent()
            except Exception:
                wrapper = None
            iframe = None
            if wrapper is not None:
                try:
                    iframe = wrapper.shadow_root.ele("tag:iframe", timeout=0.2)
                except Exception:
                    pass
            if iframe is None:
                try:
                    iframe = page.ele("tag:iframe@src:turnstile", timeout=0.2)
                except Exception:
                    pass
            if iframe is not None:
                clicked_shadow = False
                try:
                    body_shadow = iframe.ele("tag:body", timeout=0.2).shadow_root
                    button = body_shadow.ele("tag:input", timeout=0.2) or body_shadow.ele(
                        "css:input[type=checkbox]", timeout=0.2
                    )
                    if button:
                        button.click()
                        clicked_shadow = True
                except Exception:
                    pass
                if not clicked_shadow:
                    try:
                        iframe.click()
                        clicked_shadow = True
                    except Exception:
                        pass
                if clicked_shadow:
                    actions.append("shadow-iframe")
    except Exception:
        pass
    if actions:
        _log(log_callback, f"[Turnstile] widget nudge: {'/'.join(actions)}")
    return ",".join(actions)


def _log(log_callback: LogFn, message: str) -> None:
    if log_callback:
        log_callback(message)


def prepare_browser_proxy(
    proxy: str = "",
    *,
    parent_proxy: str = "",
    preferred_local_port: int = 0,
    instance_key: str = "",
) -> Tuple[str, str, str]:
    """Return (browser_proxy_url, upstream_proxy_url, forwarder_instance_key)."""
    upstream = normalize_proxy(proxy)
    parent = normalize_proxy(parent_proxy)
    if not upstream and not parent:
        return "", "", ""
    if parent and not upstream:
        raise RuntimeError("设置 parent_proxy 时必须同时提供 proxy 上游")

    parsed = parse_proxy(upstream)
    needs_forwarder = bool(parent) or bool(parsed.username or parsed.password)
    if not needs_forwarder:
        return upstream, upstream, ""

    from local_proxy_forwarder import ensure_local_forwarder

    key = instance_key or f"turnstile-solver-{os.getpid()}-{secrets.token_hex(3)}"
    browser_proxy, _used = ensure_local_forwarder(
        upstream,
        preferred_local_port=int(preferred_local_port or 0),
        instance_key=key,
        parent_proxy_raw=parent,
    )
    return str(browser_proxy or ""), upstream, key


def stop_browser_proxy(forwarder_instance: str = "") -> None:
    if not forwarder_instance:
        return
    try:
        from local_proxy_forwarder import stop_local_forwarder

        stop_local_forwarder(forwarder_instance)
    except Exception:
        pass


def read_turnstile_token_from_page(page: Any) -> str:
    try:
        value = page.run_js(TOKEN_READ_JS)
    except Exception:
        return ""
    return str(value or "").strip()


def read_browser_fingerprint(page: Any) -> FingerprintSnapshot:
    try:
        value = page.run_js(FINGERPRINT_READ_JS)
    except Exception:
        value = {}
    data = dict(value) if isinstance(value, dict) else {}
    ua_data = dict(data.get("user_agent_data") or {})
    run_cdp = getattr(page, "run_cdp", None)
    if not callable(run_cdp):
        ua_data["_high_entropy_error"] = "page.run_cdp is unavailable"
    else:
        try:
            response = run_cdp(
                "Runtime.evaluate",
                expression=UA_HIGH_ENTROPY_CDP_EXPRESSION,
                awaitPromise=True,
                returnByValue=True,
            )
            ua_data.update(_parse_high_entropy_cdp_response(response))
        except Exception as exc:
            ua_data["_high_entropy_error"] = f"CDP Runtime.evaluate failed: {exc}"
    data["user_agent_data"] = ua_data
    return FingerprintSnapshot.from_dict(data)




def _client_hint_platform(user_agent_data: Dict[str, Any]) -> str:
    data = user_agent_data if isinstance(user_agent_data, dict) else {}
    return str(data.get("platform") or "").strip()


def _fingerprint_context_note(fingerprint: FingerprintSnapshot) -> str:
    extras = []
    ua_data = fingerprint.user_agent_data if isinstance(fingerprint.user_agent_data, dict) else {}
    high_err = str(ua_data.get("_high_entropy_error") or "").strip()
    if high_err:
        extras.append(high_err)
    # Best-effort context from raw page read fields stored only if present in ua_data/meta.
    return "; ".join(extras)


def validate_strict_fingerprint(
    fingerprint: FingerprintSnapshot,
    *,
    requested_ua: str = "",
    requested_language: str = "",
    expected_platform: str = "",
    expected_client_hint_platform: str = "",
    expected_browser_major: int = 0,
) -> None:
    """Raise RuntimeError when observed browser fingerprint diverges from the request."""
    if not fingerprint.user_agent:
        raise RuntimeError("严格指纹模式无法读取浏览器实际 UA")
    if requested_ua and fingerprint.user_agent != requested_ua:
        raise RuntimeError(
            "严格指纹模式 UA 不一致: "
            f"requested={requested_ua!r}, observed={fingerprint.user_agent!r}"
        )
    requested_primary_language = requested_language.split(",", 1)[0].split(";", 1)[0].strip()
    if (
        requested_primary_language
        and fingerprint.navigator_language.lower() != requested_primary_language.lower()
    ):
        raise RuntimeError(
            "严格指纹模式语言不一致: "
            f"requested={requested_primary_language!r}, "
            f"observed={fingerprint.navigator_language!r}"
        )
    if not expected_platform:
        raise RuntimeError("严格指纹模式缺少 expected_platform")
    if not fingerprint.platform or fingerprint.platform != expected_platform:
        raise RuntimeError(
            "严格指纹模式 navigator.platform 不一致: "
            f"expected={expected_platform!r}, observed={fingerprint.platform!r}"
        )
    observed_ch_platform = _client_hint_platform(fingerprint.user_agent_data)
    if not expected_client_hint_platform:
        raise RuntimeError("严格指纹模式缺少 expected_client_hint_platform")
    if not observed_ch_platform:
        note = _fingerprint_context_note(fingerprint)
        suffix = f" ({note})" if note else ""
        raise RuntimeError(
            "严格指纹模式 UAData platform 不可用: "
            f"expected={expected_client_hint_platform!r}, observed=''"
            f"{suffix}；通常表示当前页无 navigator.userAgentData（about:blank/错误页/非安全上下文）"
        )
    if observed_ch_platform != expected_client_hint_platform:
        raise RuntimeError(
            "严格指纹模式 UAData platform 不一致: "
            f"expected={expected_client_hint_platform!r}, observed={observed_ch_platform!r}"
        )
    if expected_browser_major <= 0:
        raise RuntimeError("严格指纹模式缺少 expected_browser_major")
    brand_majors, full_version_majors = _client_hint_browser_majors(fingerprint.user_agent_data)
    if not brand_majors:
        raise RuntimeError("严格指纹模式 UAData brands 缺少 Chromium 主版本")
    if not full_version_majors:
        high_entropy_error = str(
            fingerprint.user_agent_data.get("_high_entropy_error") or ""
        ).strip()
        suffix = f": {high_entropy_error}" if high_entropy_error else ""
        raise RuntimeError(
            "严格指纹模式 UAData fullVersionList 缺少 Chromium 主版本" + suffix
        )
    if any(major != expected_browser_major for major in brand_majors + full_version_majors):
        raise RuntimeError(
            "严格指纹模式浏览器主版本不一致: "
            f"expected={expected_browser_major}, brands={brand_majors}, "
            f"fullVersionList={full_version_majors}"
        )

def _parse_high_entropy_cdp_response(response: Any) -> Dict[str, Any]:
    if not isinstance(response, dict):
        raise ValueError("CDP response is not an object")
    if response.get("exceptionDetails"):
        details = response.get("exceptionDetails")
        raise ValueError(f"CDP Runtime.evaluate exception: {details}")
    result = response.get("result")
    if not isinstance(result, dict):
        raise ValueError("CDP response missing result object")
    value = result.get("value")
    if not isinstance(value, dict):
        raise ValueError("CDP response result.value is not an object")
    return dict(value)


def _client_hint_browser_majors(user_agent_data: Dict[str, Any]) -> Tuple[List[int], List[int]]:
    def collect(entries: Any) -> List[int]:
        majors: List[int] = []
        if not isinstance(entries, list):
            return majors
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            brand = str(entry.get("brand") or "").lower()
            if "chrom" not in brand and "google chrome" not in brand:
                continue
            try:
                major = int(str(entry.get("version") or "").split(".", 1)[0])
            except (TypeError, ValueError):
                continue
            if major not in majors:
                majors.append(major)
        return majors

    return collect(user_agent_data.get("brands")), collect(user_agent_data.get("fullVersionList"))


def _default_platform_version(client_hint_platform: str) -> str:
    platform = str(client_hint_platform or "").strip().lower()
    if platform == "windows":
        return "10.0.0"
    if platform in {"macos", "mac os", "macintosh"}:
        return "10.15.7"
    if platform == "android":
        return "10.0.0"
    return "0.0.0"


def build_cdp_user_agent_metadata(
    *,
    browser_version: str,
    client_hint_platform: str,
) -> Dict[str, Any]:
    full_version = str(browser_version or "").strip()
    try:
        major = int(full_version.split(".", 1)[0])
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"无效的完整 Chrome 版本: {full_version!r}") from exc
    if not full_version or full_version.count(".") != 3 or major <= 0:
        raise RuntimeError(f"无效的完整 Chrome 版本: {full_version!r}")
    platform = str(client_hint_platform or "").strip()
    if not platform:
        raise RuntimeError("缺少 expected_client_hint_platform")
    return {
        "brands": [
            {"brand": "Not.A/Brand", "version": "99"},
            {"brand": "Chromium", "version": str(major)},
        ],
        "fullVersionList": [
            {"brand": "Not.A/Brand", "version": "99.0.0.0"},
            {"brand": "Chromium", "version": full_version},
        ],
        "platform": platform,
        "platformVersion": _default_platform_version(platform),
        "architecture": "x86",
        "bitness": "64",
        "model": "",
        "mobile": False,
        "wow64": False,
    }


def apply_cdp_fingerprint_override(
    page: Any,
    request: SolveRequest,
    *,
    browser_version: str,
    strict: bool,
) -> Dict[str, Any]:
    user_agent = str(request.user_agent or "").strip()
    accept_language = str(request.accept_language or "").strip()
    navigator_platform = str(request.expected_platform or "").strip()
    client_hint_platform = str(request.expected_client_hint_platform or "").strip()
    expected_major = max(0, int(request.expected_browser_major or 0))
    missing = [
        name
        for name, value in (
            ("user_agent", user_agent),
            ("accept_language", accept_language),
            ("expected_platform", navigator_platform),
            ("expected_client_hint_platform", client_hint_platform),
            ("expected_browser_major", expected_major),
            ("browser_version", browser_version),
        )
        if not value
    ]
    if missing:
        message = "CDP 指纹覆盖缺少字段: " + ", ".join(missing)
        if strict:
            raise RuntimeError(message)
        return {"error": message}

    metadata = build_cdp_user_agent_metadata(
        browser_version=browser_version,
        client_hint_platform=client_hint_platform,
    )
    actual_major = int(str(browser_version).split(".", 1)[0])
    if actual_major != expected_major:
        raise RuntimeError(
            "CDP 指纹覆盖浏览器主版本不一致: "
            f"expected={expected_major}, actual={actual_major}"
        )
    run_cdp = getattr(page, "run_cdp", None)
    if not callable(run_cdp):
        message = "page.run_cdp is unavailable for Emulation.setUserAgentOverride"
        if strict:
            raise RuntimeError(message)
        return {"error": message}
    try:
        run_cdp(
            "Emulation.setUserAgentOverride",
            userAgent=user_agent,
            acceptLanguage=accept_language,
            platform=navigator_platform,
            userAgentMetadata=metadata,
        )
    except Exception as exc:
        if strict:
            raise RuntimeError(f"Emulation.setUserAgentOverride failed: {exc}") from exc
        return {"error": f"Emulation.setUserAgentOverride failed: {exc}"}
    return metadata


def diagnose_page(page: Any) -> Dict[str, Any]:
    try:
        data = page.run_js(PAGE_DIAG_JS)
    except Exception as exc:
        return {"error": f"diagnose failed: {exc}"}
    return data if isinstance(data, dict) else {"error": "diagnose returned non-object", "raw": str(data)}


def _summarize_diag(samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not samples:
        return {}
    token_lens = [int(s.get("tokenLen") or 0) for s in samples if isinstance(s, dict)]
    resp_lens = [int(s.get("turnstileRespLen") or 0) for s in samples if isinstance(s, dict)]
    sitekeys: List[str] = []
    for s in samples:
        for k in s.get("sitekeys") or []:
            k = str(k or "").strip()
            if k and k not in sitekeys:
                sitekeys.append(k)
    last = samples[-1] if samples else {}
    return {
        "samples": len(samples),
        "token_len_max": max(token_lens) if token_lens else 0,
        "token_len_last": token_lens[-1] if token_lens else 0,
        "token_seen_nonzero": any(x > 0 for x in token_lens),
        "turnstile_resp_len_max": max(resp_lens) if resp_lens else 0,
        "sitekeys": sitekeys,
        "sitekey_count": len(sitekeys),
        "has_cf_input_last": bool(last.get("hasCfInput")),
        "turnstile_api_type_last": last.get("turnstileApiType"),
        "iframe_count_last": last.get("iframeCount"),
        "turnstile_iframe_count_last": last.get("turnstileIframeCount"),
        "challenge_like_last": bool(last.get("challengeLike")),
        "title_last": last.get("title"),
        "url_last": last.get("url"),
        "body_snippet_last": last.get("bodySnippet"),
        "iframes_last": last.get("iframes") or [],
        "timeline": [
            {
                "t": s.get("_t"),
                "tokenLen": s.get("tokenLen"),
                "turnstileRespLen": s.get("turnstileRespLen"),
                "hasCfInput": s.get("hasCfInput"),
                "turnstileIframeCount": s.get("turnstileIframeCount"),
                "sitekeyCount": s.get("sitekeyCount"),
                "challengeLike": s.get("challengeLike"),
            }
            for s in samples
        ],
    }


class BrowserWorker:
    """Capture a real Turnstile token from the signup page via Chromium."""

    def __init__(self, config: SolverConfig, log_callback: LogFn = None):
        self.config = config
        self.log_callback = log_callback

    def solve(self, request: SolveRequest) -> SolveResult:
        started = time.monotonic()
        page_url = (request.page_url or self.config.signup_url).strip()
        upstream_raw = (request.proxy or self.config.proxy or "").strip()
        parent_proxy = (
            str((request.metadata or {}).get("parent_proxy") or "")
            or self.config.parent_proxy
            or ""
        ).strip()
        timeout = max(30, int(request.timeout_sec or self.config.browser_timeout_sec))
        headless = bool(request.headless) or bool(self.config.headless)
        min_len = max(20, int(self.config.token_min_length or 80))
        user_agent = (request.user_agent or self.config.user_agent or "").strip()
        diagnose = bool((request.metadata or {}).get("diagnose"))

        forwarder_instance = ""
        try:
            browser_proxy, upstream_proxy, forwarder_instance = prepare_browser_proxy(
                upstream_raw,
                parent_proxy=parent_proxy,
                preferred_local_port=int(self.config.local_proxy_port or 0),
                instance_key=f"ts-worker-{uuid.uuid4().hex[:10]}",
            )
            token, effective_ua, diag = self._capture_with_browser(
                page_url=page_url,
                browser_proxy=browser_proxy,
                timeout=timeout,
                headless=headless,
                user_agent=user_agent,
                min_len=min_len,
                diagnose=diagnose or True,  # keep diagnostics on for Phase1 live debugging
            )
            elapsed_ms = int((time.monotonic() - started) * 1000)
            extras = {
                "browser_proxy": browser_proxy,
                "parent_proxy": normalize_proxy(parent_proxy),
                "forwarder_instance": forwarder_instance,
                "diagnostics": diag,
            }
            if len(token) < min_len:
                return SolveResult(
                    ok=False,
                    token=token,
                    proxy=upstream_proxy or normalize_proxy(upstream_raw),
                    page_url=page_url,
                    user_agent=effective_ua,
                    elapsed_ms=elapsed_ms,
                    error=(
                        f"在 {timeout}s 内未捕获到可用 Turnstile token "
                        f"(len={len(token)}, min={min_len})"
                    ),
                    extras=extras,
                )
            extras["token_len"] = len(token)
            return SolveResult(
                ok=True,
                token=token,
                proxy=upstream_proxy or normalize_proxy(upstream_raw),
                page_url=page_url,
                user_agent=effective_ua,
                elapsed_ms=elapsed_ms,
                extras=extras,
            )
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            return SolveResult(
                ok=False,
                token="",
                proxy=normalize_proxy(upstream_raw),
                page_url=page_url,
                user_agent=user_agent,
                elapsed_ms=elapsed_ms,
                error=str(exc),
                extras={
                    "parent_proxy": normalize_proxy(parent_proxy),
                    "forwarder_instance": forwarder_instance,
                },
            )
        finally:
            stop_browser_proxy(forwarder_instance)

    def solve_on_page(
        self,
        page: Any,
        request: SolveRequest,
        *,
        browser_proxy: str = "",
        upstream_proxy: str = "",
        affinity_id: str = "",
        browser_version: str = "",
    ) -> SolveResult:
        """Capture on an already-running Chromium fresh context."""
        started = time.monotonic()
        page_url = (request.page_url or self.config.signup_url).strip()
        timeout = max(1, int(request.timeout_sec or self.config.browser_timeout_sec))
        deadline = started + timeout
        min_len = max(20, int(self.config.token_min_length or 80))
        diagnose = bool(request.diagnose or (request.metadata or {}).get("diagnose"))
        requested_ua = (request.user_agent or self.config.user_agent or "").strip()
        requested_language = (
            request.accept_language or self.config.accept_language or self.config.locale or ""
        ).strip()
        expected_platform = str(request.expected_platform or "").strip()
        expected_ch_platform = str(request.expected_client_hint_platform or "").strip()
        expected_browser_major = max(0, int(request.expected_browser_major or 0))
        strict = bool((request.metadata or {}).get("strict_fingerprint", self.config.strict_fingerprint))
        samples: List[Dict[str, Any]] = []
        token = ""
        fingerprint = FingerprintSnapshot()
        try:
            cdp_metadata = apply_cdp_fingerprint_override(
                page,
                request,
                browser_version=browser_version,
                strict=strict,
            )
            page.get(page_url)
            try:
                page.wait.doc_loaded()
            except Exception:
                pass
            _log(self.log_callback, f"[Turnstile] 常驻浏览器已打开注册页: {page_url}")

            sitekey = str(request.sitekey or "").strip()
            if sitekey:
                _ensure_injected_turnstile_widget(
                    page,
                    sitekey=sitekey,
                    action=str(request.action or "").strip(),
                    cdata=str(request.cdata or "").strip(),
                    deadline=deadline,
                    log_callback=self.log_callback,
                    wait_api_sec=min(3.0, max(0.0, deadline - time.monotonic())),
                )
            else:
                remaining = max(0, int(deadline - time.monotonic()))
                if remaining > 0:
                    click_email_signup_entry(
                        page,
                        log_callback=self.log_callback,
                        timeout=min(12, remaining),
                    )

            next_diag_at = 0.0
            next_inject_at = time.monotonic() + 4.0
            next_nudge_at = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                now = time.monotonic()
                token = read_turnstile_token_from_page(page)
                if len(token) >= min_len:
                    break
                if sitekey and now >= next_inject_at:
                    _ensure_injected_turnstile_widget(
                        page,
                        sitekey=sitekey,
                        action=str(request.action or "").strip(),
                        cdata=str(request.cdata or "").strip(),
                        deadline=deadline,
                        log_callback=self.log_callback,
                        wait_api_sec=min(1.5, max(0.0, deadline - now)),
                    )
                    next_inject_at = now + 4.0
                if now >= next_nudge_at:
                    _nudge_turnstile_widget(page, log_callback=self.log_callback)
                    next_nudge_at = now + 3.0
                if diagnose and now >= next_diag_at:
                    snap = diagnose_page(page)
                    if isinstance(snap, dict):
                        snap["_t"] = int((now - started))
                        samples.append(snap)
                    next_diag_at = now + 10
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    time.sleep(min(1.0, remaining))

            fingerprint = read_browser_fingerprint(page)
            # 若 Client Hints 读不到，先重放一次 CDP 覆盖再读；about:blank/错误页仍可能为空。
            if strict and not _client_hint_platform(fingerprint.user_agent_data):
                try:
                    cdp_metadata = apply_cdp_fingerprint_override(
                        page,
                        request,
                        browser_version=browser_version,
                        strict=False,
                    )
                    fingerprint = read_browser_fingerprint(page)
                except Exception as exc:
                    _log(self.log_callback, f"[Turnstile][warn] 指纹重读失败: {exc}")

            elapsed_ms = int((time.monotonic() - started) * 1000)
            extras: Dict[str, Any] = {
                "browser_proxy": browser_proxy,
                "affinity_id": affinity_id,
                "diagnostics": _summarize_diag(samples),
                "sitekey": str(request.sitekey or ""),
                "action": str(request.action or ""),
                "cdata": str(request.cdata or ""),
                "accept_language": fingerprint.accept_language,
                "language": fingerprint.navigator_language,
                "cdp_user_agent_metadata": cdp_metadata,
                "browser_version": browser_version,
            }
            if len(token) < min_len:
                # 超时/空 token 时，空 UAData 往往只是错误页副作用，不要盖住真正原因。
                if strict:
                    try:
                        validate_strict_fingerprint(
                            fingerprint,
                            requested_ua=requested_ua,
                            requested_language=requested_language,
                            expected_platform=expected_platform,
                            expected_client_hint_platform=expected_ch_platform,
                            expected_browser_major=expected_browser_major,
                        )
                    except RuntimeError as fp_exc:
                        extras["fingerprint_warning"] = str(fp_exc)
                return SolveResult(
                    ok=False,
                    token=token,
                    proxy=upstream_proxy,
                    page_url=page_url,
                    user_agent=fingerprint.user_agent,
                    elapsed_ms=elapsed_ms,
                    error=f"在 {timeout}s 内未捕获到可用 Turnstile token (len={len(token)}, min={min_len})",
                    extras=extras,
                    fingerprint=fingerprint,
                )
            if strict:
                validate_strict_fingerprint(
                    fingerprint,
                    requested_ua=requested_ua,
                    requested_language=requested_language,
                    expected_platform=expected_platform,
                    expected_client_hint_platform=expected_ch_platform,
                    expected_browser_major=expected_browser_major,
                )
            extras["token_len"] = len(token)
            return SolveResult(
                ok=True,
                token=token,
                proxy=upstream_proxy,
                page_url=page_url,
                user_agent=fingerprint.user_agent,
                elapsed_ms=elapsed_ms,
                extras=extras,
                fingerprint=fingerprint,
            )
        except Exception as exc:
            return SolveResult(
                ok=False,
                token="",
                proxy=upstream_proxy,
                page_url=page_url,
                user_agent=fingerprint.user_agent,
                elapsed_ms=int((time.monotonic() - started) * 1000),
                error=str(exc),
                extras={"browser_proxy": browser_proxy, "affinity_id": affinity_id},
                fingerprint=fingerprint if fingerprint.user_agent else None,
            )

    def _capture_with_browser(
        self,
        *,
        page_url: str,
        browser_proxy: str,
        timeout: int,
        headless: bool,
        user_agent: str,
        min_len: int,
        diagnose: bool,
    ) -> Tuple[str, str, Dict[str, Any]]:
        """Prefer parent-project enhanced capture, then fall back to local loop."""
        # 1) Parent enhanced capture (click email + prime + shadow nudge + diagnostics)
        try:
            from xai_http_flow import capture_turnstile_token as parent_capture

            logs: List[str] = []

            def _cb(msg: str) -> None:
                logs.append(str(msg))
                _log(self.log_callback, msg)

            token = parent_capture(
                proxy=browser_proxy,
                output="",
                proxy_used_file="",
                selected_proxy_raw=browser_proxy,
                timeout=timeout,
                headless=headless,
                page_url=page_url,
                click_email_signup=True,
                log_callback=_cb,
            )
            token = str(token or "").strip()
            diag = {
                "source": "xai_http_flow.capture_turnstile_token",
                "logs_tail": logs[-12:],
                "token_len": len(token),
            }
            return token, user_agent, diag
        except Exception as parent_exc:
            _log(self.log_callback, f"[Turnstile][warn] parent capture failed, fallback local: {parent_exc}")

        # 2) Local fallback path
        try:
            from DrissionPage import Chromium, ChromiumOptions
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(f"Turnstile capture 需要 DrissionPage/Chrome: {exc}") from exc

        try:
            from xai_http_flow import _build_turnstile_browser_options as build_opts
        except Exception:
            build_opts = None

        if build_opts is not None:
            options = build_opts(
                options=ChromiumOptions(),
                proxy=browser_proxy,
                headless=headless,
                user_agent=user_agent,
                log_callback=self.log_callback,
            )
        else:
            options = ChromiumOptions()
            try:
                options.auto_port()
            except Exception:
                pass
            try:
                options.set_argument("--no-first-run")
                options.set_argument("--no-default-browser-check")
                options.set_argument("--disable-dev-shm-usage")
            except Exception:
                pass
            if headless:
                try:
                    options.headless(True)
                except Exception:
                    pass
            if user_agent:
                try:
                    options.set_user_agent(user_agent)
                except Exception:
                    try:
                        options.set_argument(f"--user-agent={user_agent}")
                    except Exception:
                        pass
            if browser_proxy:
                try:
                    options.set_proxy(browser_proxy)
                    _log(self.log_callback, f"[Turnstile] 浏览器代理: {browser_proxy}")
                except Exception as exc:
                    raise RuntimeError(f"无法设置浏览器代理: {exc}") from exc

        browser = Chromium(options)
        samples: List[Dict[str, Any]] = []
        try:
            tabs = getattr(browser, "get_tabs", lambda: [])()
            page = tabs[-1] if tabs else browser.new_tab()
            page.get(page_url)
            _log(self.log_callback, f"[Turnstile] 已打开注册页: {page_url}")
            clicked = click_email_signup_entry(page, log_callback=self.log_callback, timeout=12)
            if clicked:
                _log(self.log_callback, "[Turnstile] 已进入邮箱注册入口，等待 Turnstile widget…")
            else:
                _log(self.log_callback, "[Turnstile][warn] 未点到邮箱注册入口，继续在当前页等待 token")
            deadline = time.monotonic() + timeout
            started = time.monotonic()
            token = ""
            next_diag_at = 0.0
            while time.monotonic() < deadline:
                now = time.monotonic()
                token = read_turnstile_token_from_page(page)
                if diagnose and now >= next_diag_at:
                    snap = diagnose_page(page)
                    if isinstance(snap, dict):
                        snap["_t"] = int(now - started)
                        samples.append(snap)
                        _log(
                            self.log_callback,
                            "[Turnstile][diag] "
                            f"t={snap.get('_t')}s tokenLen={snap.get('tokenLen')} "
                            f"sitekeys={snap.get('sitekeyCount')} "
                            f"cfInput={snap.get('hasCfInput')} "
                            f"tsIframes={snap.get('turnstileIframeCount')} "
                            f"challenge={snap.get('challengeLike')}",
                        )
                    next_diag_at = now + (5 if len(samples) <= 1 else 10)
                if len(token) >= min_len:
                    break
                try:
                    page.run_js(
                        """
const nodes = Array.from(document.querySelectorAll('.cf-turnstile, [data-sitekey], iframe[src*="turnstile"], iframe[src*="challenges.cloudflare"]'));
for (const n of nodes) {
  try { n.scrollIntoView({block:'center', inline:'center'}); } catch (e) {}
  try { n.click(); } catch (e) {}
}
"""
                    )
                except Exception:
                    pass
                time.sleep(1.0)

            if diagnose:
                snap = diagnose_page(page)
                if isinstance(snap, dict):
                    snap["_t"] = int(time.monotonic() - started)
                    samples.append(snap)

            effective_ua = user_agent
            if not effective_ua:
                try:
                    effective_ua = str(page.run_js("return navigator.userAgent;") or "").strip()
                except Exception:
                    effective_ua = ""
            diag = _summarize_diag(samples)
            diag["source"] = "local_fallback"
            _log(
                self.log_callback,
                f"[Turnstile] 捕获结束 token_len={len(token)} ua={'yes' if effective_ua else 'no'} "
                f"sitekeys={diag.get('sitekey_count')} ts_iframes={diag.get('turnstile_iframe_count_last')}",
            )
            return token, effective_ua, diag
        finally:
            try:
                browser.quit()
            except Exception:
                pass

#!/usr/bin/env python3
"""
SSO / Token → .local/credentials

模式:
  auth   : SSO cookie 走 Device Flow 鉴权后写出 xai-*.json（默认）
  noauth : 不鉴权，仅把已有 token/凭证格式转换为 xai-*.json

用法:
  # 鉴权（并发）
  python3 sso_to_auth_json.py --mode auth --sso sso_list.txt --out-dir .local/credentials --workers 10

  # 不鉴权：输入已是 access_token / JSON 凭证 / grok auth 片段
  python3 sso_to_auth_json.py --mode noauth --sso tokens.txt --out-dir .local/credentials --workers 20
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from curl_cffi import requests
from local_paths import CONFIG_PATH, CREDENTIALS_DIR

CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
OIDC_ISSUER = "https://auth.x.ai"
XAI_API_BASE = "https://api.x.ai/v1"
SCOPES = (
    "openid profile email offline_access grok-cli:access "
    "api:access conversations:read conversations:write"
)

_print_lock = threading.Lock()
_write_lock = threading.Lock()


def log(msg: str) -> None:
    with _print_lock:
        print(msg, flush=True)


def b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def decode_jwt_payload(token: str) -> dict:
    try:
        return json.loads(b64url_decode(token.split(".")[1]))
    except Exception:
        return {}


def utc_iso_z(ts: float | None = None) -> str:
    if ts is None:
        ts = time.time()
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize_file_segment(value: str) -> str:
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


def credential_file_name(email: str = "", subject: str = "") -> str:
    email = sanitize_file_segment(email)
    if email:
        return f"xai-{email}.json"
    subject = sanitize_file_segment(subject)
    if subject:
        return f"xai-{subject}.json"
    return f"xai-{int(time.time() * 1000)}.json"


def sso_file_name(email: str = "", subject: str = "") -> str:
    """Same basename as credential JSON, with .sso extension."""
    name = credential_file_name(email=email, subject=subject)
    if name.endswith(".json"):
        return name[:-5] + ".sso"
    return name + ".sso"


def write_sso_file(path: Path, sso: str) -> Path:
    """Write a single-account SSO cookie file next to credential JSON."""
    sso = str(sso or "").strip()
    if not sso:
        raise ValueError("empty sso")
    if "\n" in sso or "\r" in sso:
        raise ValueError("sso must be a single line")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".{os.getpid()}.{threading.get_ident()}.tmp")
    payload = sso + "\n"
    with _write_lock:
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, path)
    try:
        if os.name != "nt":
            os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".{os.getpid()}.{threading.get_ident()}.tmp")
    payload = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    with _write_lock:
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, path)


def request_device_code() -> dict | None:
    data = urllib.parse.urlencode({"client_id": CLIENT_ID, "scope": SCOPES}).encode()
    req = urllib.request.Request(
        f"{OIDC_ISSUER}/oauth2/device/code",
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        log(f"  ❌ device/code HTTP {e.code}: {e.read().decode()[:200]}")
        return None
    except Exception as e:
        log(f"  ❌ device/code 异常: {e}")
        return None


def poll_token(
    device_code: str,
    interval: int,
    expires_in: int,
    timeout: int = 45,
) -> dict | None:
    deadline = time.time() + min(expires_in, timeout)
    wait = 0.0
    while time.time() < deadline:
        if wait > 0:
            time.sleep(wait)
        data = urllib.parse.urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": CLIENT_ID,
                "device_code": device_code,
            }
        ).encode()
        req = urllib.request.Request(
            f"{OIDC_ISSUER}/oauth2/token",
            data=data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                err = json.loads(body)
            except Exception:
                log(f"  ❌ token HTTP {e.code}: {body[:200]!r}")
                return None
            error = err.get("error", "")
            if error == "authorization_pending":
                wait = max(1, int(interval or 5))
                continue
            if error == "slow_down":
                wait = max(1, int(interval or 5)) + 3
                continue
            log(f"  ❌ token: {error}")
            return None
        except Exception as e:
            log(f"  ❌ token 异常: {e}")
            return None
    log("  ❌ 轮询超时")
    return None


def sso_to_token(sso_cookie: str, quiet: bool = False) -> dict | None:
    s = requests.Session()
    s.cookies.set("sso", sso_cookie, domain=".x.ai")

    try:
        r = s.get("https://accounts.x.ai/", impersonate="chrome", timeout=20)
    except Exception as e:
        if not quiet:
            log(f"  ❌ 网络错误: {e}")
        return None
    if "sign-in" in r.url or "sign-up" in r.url:
        if not quiet:
            log("  ❌ sso 无效")
        return None

    dc = request_device_code()
    if not dc:
        return None

    try:
        s.get(dc["verification_uri_complete"], impersonate="chrome", timeout=20)
        r = s.post(
            f"{OIDC_ISSUER}/oauth2/device/verify",
            data={"user_code": dc["user_code"]},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            impersonate="chrome",
            timeout=20,
            allow_redirects=True,
        )
        if "consent" not in r.url:
            if not quiet:
                log(f"  ❌ verify 失败: {r.url}")
            return None
    except Exception as e:
        if not quiet:
            log(f"  ❌ verify 异常: {e}")
        return None

    try:
        r = s.post(
            f"{OIDC_ISSUER}/oauth2/device/approve",
            data={
                "user_code": dc["user_code"],
                "action": "allow",
                "principal_type": "User",
                "principal_id": "",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            impersonate="chrome",
            timeout=20,
            allow_redirects=True,
        )
        if "done" not in r.url:
            if not quiet:
                log(f"  ❌ approve 失败: {r.url}")
            return None
    except Exception as e:
        if not quiet:
            log(f"  ❌ approve 异常: {e}")
        return None

    return poll_token(
        dc["device_code"],
        int(dc.get("interval", 5) or 5),
        int(dc.get("expires_in", 1800) or 1800),
    )


def build_xai_credential(token: dict, email: str = "") -> dict:
    access = token.get("access_token") or token.get("key") or ""
    refresh = token.get("refresh_token") or ""
    id_token = token.get("id_token") or ""
    expires_in = int(token.get("expires_in") or 21600)

    access_payload = decode_jwt_payload(access)
    id_payload = decode_jwt_payload(id_token) if id_token else {}

    sub = (
        str(access_payload.get("sub") or "")
        or str(access_payload.get("principal_id") or "")
        or str(id_payload.get("sub") or "")
        or str(token.get("sub") or "")
        or str(token.get("user_id") or "")
    )
    email_val = (
        str(email or "").strip()
        or str(id_payload.get("email") or "").strip()
        or str(token.get("email") or "").strip()
    )

    if "exp" in access_payload:
        expired = utc_iso_z(float(access_payload["exp"]))
        # 尽量用真实剩余秒数
        left = int(float(access_payload["exp"]) - time.time())
        if left > 0:
            expires_in = left
    elif token.get("expired"):
        expired = str(token.get("expired"))
    elif token.get("expires_at"):
        s = str(token.get("expires_at"))
        expired = s.replace(".000000000Z", "Z") if s.endswith("Z") else s
    else:
        expired = utc_iso_z(time.time() + expires_in)

    doc = {
        "access_token": access,
        "auth_kind": "oauth",
        "base_url": XAI_API_BASE,
        "disabled": bool(token.get("disabled", False)),
        "expires_in": expires_in,
        "expired": expired,
        "id_token": id_token,
        "last_refresh": str(token.get("last_refresh") or utc_iso_z()),
        "redirect_uri": str(token.get("redirect_uri") or ""),
        "refresh_token": refresh,
        "token_endpoint": str(token.get("token_endpoint") or f"{OIDC_ISSUER}/oauth2/token"),
        "token_type": str(token.get("token_type") or "Bearer"),
        "type": "xai",
    }
    if email_val:
        doc["email"] = email_val
    if sub:
        doc["sub"] = sub
    return doc


def normalize_sso_line(line: str) -> str | None:
    line = line.strip().lstrip("\ufeff")
    if not line or line.startswith("#"):
        return None
    if "----" in line:
        # 邮箱----密码----sso 或 其它多段，默认取最后一段
        line = line.split("----")[-1].strip()
    line = re.sub(
        r"^\s*(?:#?\s*)?\d+\s*[\.\)\]、:：\-–—]\s*",
        "",
        line,
        count=1,
    ).strip()
    m = re.search(r"(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", line)
    if m:
        return m.group(1)
    return line or None


def extract_jwts(text: str) -> list[str]:
    # 先按 ---- 分段，避免 refresh 粘进 JWT 第三段（第三段字符集含 -）
    out: list[str] = []
    for chunk in re.split(r"-{2,}", text or ""):
        out.extend(
            re.findall(
                r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
                chunk,
            )
        )
    return out


def looks_like_session_sso(token: str) -> bool:
    payload = decode_jwt_payload(token)
    if not payload:
        return False
    # 典型 SSO session cookie: 只有 session_id，没有 OAuth sub/scope
    if "session_id" in payload and "sub" not in payload and "scope" not in payload:
        return True
    return False


def is_oauth_access_token(token: str) -> bool:
    """真正的 xAI access_token 通常含 sub/scope/iss，长度也远大于 session cookie。"""
    token = str(token or "").strip()
    if not token or token.count(".") != 2:
        return False
    payload = decode_jwt_payload(token)
    if not payload:
        return False
    if looks_like_session_sso(token):
        return False
    if payload.get("sub") or payload.get("scope") or payload.get("principal_id"):
        return True
    # id_token 有 email 也不是 access，但可接受作为凭证一部分；这里要求 access 至少有 sub/scope
    return False


def parse_noauth_line(line: str, default_email: str = "") -> dict | None:
    """
    不鉴权模式：把一行文本解析成 token dict。
    支持:
      - 纯 access_token JWT
      - access----refresh 或 access----refresh----id
      - 邮箱----密码----access
      - 一整行 JSON（xai / grok 结构）
    """
    raw = line.strip().lstrip("\ufeff")
    if not raw or raw.startswith("#"):
        return None

    # JSON 行 / 片段
    if raw[0] in "{[":
        try:
            obj = json.loads(raw)
        except Exception:
            obj = None
        if isinstance(obj, dict):
            # grok auth.json: { "issuer::client": {key, refresh_token, ...} }
            if any(isinstance(v, dict) and ("key" in v or "access_token" in v) for v in obj.values()):
                for v in obj.values():
                    if isinstance(v, dict) and (v.get("key") or v.get("access_token")):
                        return {
                            "access_token": v.get("access_token") or v.get("key") or "",
                            "refresh_token": v.get("refresh_token") or "",
                            "id_token": v.get("id_token") or "",
                            "email": v.get("email") or default_email,
                            "sub": v.get("sub") or v.get("user_id") or "",
                            "expires_in": v.get("expires_in") or 21600,
                            "expires_at": v.get("expires_at") or "",
                            "expired": v.get("expired") or "",
                            "token_type": v.get("token_type") or "Bearer",
                            "redirect_uri": v.get("redirect_uri") or "",
                            "token_endpoint": v.get("token_endpoint") or "",
                            "disabled": v.get("disabled", False),
                            "last_refresh": v.get("last_refresh") or "",
                        }
            # 已是 xai credential
            if obj.get("access_token") or obj.get("key") or obj.get("refresh_token"):
                return {
                    "access_token": obj.get("access_token") or obj.get("key") or "",
                    "refresh_token": obj.get("refresh_token") or "",
                    "id_token": obj.get("id_token") or "",
                    "email": obj.get("email") or default_email,
                    "sub": obj.get("sub") or obj.get("user_id") or "",
                    "expires_in": obj.get("expires_in") or 21600,
                    "expires_at": obj.get("expires_at") or "",
                    "expired": obj.get("expired") or "",
                    "token_type": obj.get("token_type") or "Bearer",
                    "redirect_uri": obj.get("redirect_uri") or "",
                    "token_endpoint": obj.get("token_endpoint") or "",
                    "disabled": obj.get("disabled", False),
                    "last_refresh": obj.get("last_refresh") or "",
                }

    # 去序号
    text = re.sub(
        r"^\s*(?:#?\s*)?\d+\s*[\.\)\]、:：\-–—]\s*",
        "",
        raw,
        count=1,
    ).strip()

    email_hint = default_email
    parts = [p.strip() for p in text.split("----") if p.strip()]
    if len(parts) >= 3 and "@" in parts[0]:
        email_hint = parts[0]
        text = "----".join(parts[2:]) if len(parts) > 2 else parts[-1]
        parts = [p.strip() for p in text.split("----") if p.strip()]

    # 优先按 ---- 分段，避免 JWT 与 refresh 粘连
    if len(parts) >= 1:
        access = ""
        refresh = ""
        id_token = ""
        # 每段优先提取 JWT，否则保留原文
        seg_vals = []
        for p in parts:
            js = extract_jwts(p)
            seg_vals.append(js[0] if js else p)
        access = seg_vals[0]
        if len(seg_vals) >= 2:
            refresh = seg_vals[1]
        if len(seg_vals) >= 3:
            id_token = seg_vals[2]
        # 若只有一段但含多个 JWT
        if len(parts) == 1:
            js = extract_jwts(parts[0])
            if js:
                access = js[0]
                if len(js) >= 2:
                    p1 = decode_jwt_payload(js[1])
                    if p1.get("email") or p1.get("nonce") or p1.get("given_name"):
                        id_token = js[1]
                    else:
                        refresh = js[1]
                if len(js) >= 3:
                    id_token = js[2]
        if access:
            return {
                "access_token": access,
                "refresh_token": refresh if refresh != access else "",
                "id_token": id_token,
                "email": email_hint,
            }

    jwts = extract_jwts(text)
    if not jwts:
        return None
    access = jwts[0]
    refresh = jwts[1] if len(jwts) >= 2 else ""
    id_token = jwts[2] if len(jwts) >= 3 else ""
    if len(jwts) == 2:
        p1 = decode_jwt_payload(jwts[1])
        if p1.get("email") or p1.get("nonce") or p1.get("given_name"):
            id_token = jwts[1]
            refresh = ""
    return {
        "access_token": access,
        "refresh_token": refresh if refresh != access else "",
        "id_token": id_token,
        "email": email_hint,
    }


def load_input_lines(path: str | None, single: str | None) -> list[str]:
    if single:
        s = single.strip()
        return [s] if s else []
    if not path:
        return []
    out: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def load_sso_list(path: str | None, single: str | None) -> list[str]:
    if single:
        s = normalize_sso_line(single)
        return [s] if s else []
    if not path:
        return []
    out: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        s = normalize_sso_line(line)
        if s:
            out.append(s)
    return out


def _maybe_auto_push_cpa(path: Path, *, prefix: str = "") -> None:
    """Best-effort CPA auto push after a credential JSON is written."""
    try:
        import cpa_push

        cfg_path = CONFIG_PATH
        cfg = {}
        if cfg_path.is_file():
            try:
                cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            except Exception:
                cfg = {}
        if not (isinstance(cfg, dict) and cfg.get("cpa_auto_upload")):
            return

        def _cpa_log(msg: str) -> None:
            head = f"{prefix} " if prefix else ""
            log(f"{head}[CPA] {msg}")

        cpa_push.auto_push_credential_file(
            config=cfg,
            credential_path=path,
            log=_cpa_log,
        )
    except Exception as exc:
        head = f"{prefix} " if prefix else ""
        log(f"{head}[CPA] 自动推送异常: {exc}")


def process_auth_one(idx: int, total: int, sso: str, out_dir: Path, email: str) -> bool:
    prefix = f"[{idx}/{total}]"
    try:
        token = sso_to_token(sso, quiet=True)
        if not token:
            log(f"{prefix} ❌ 鉴权失败")
            return False
        doc = build_xai_credential(token, email=email)
        label = str(doc.get("email") or doc.get("sub") or secrets.token_hex(4))
        email_for_name = str(doc.get("email") or email or "")
        subject_for_name = str(doc.get("sub") or "")
        path = out_dir / credential_file_name(email_for_name, subject_for_name)
        write_json(path, doc)
        _maybe_auto_push_cpa(path, prefix=prefix)
        sso_path = out_dir / sso_file_name(email_for_name, subject_for_name)
        try:
            write_sso_file(sso_path, sso)
            log(f"{prefix} ✅ {label} → {path.name} ({path.stat().st_size}B), {sso_path.name}")
        except Exception as sso_exc:
            log(f"{prefix} ✅ {label} → {path.name} ({path.stat().st_size}B); SSO旁路写入失败: {sso_exc}")
        return True
    except Exception as e:
        log(f"{prefix} ❌ 异常: {e}")
        return False


def process_noauth_one(idx: int, total: int, line: str, out_dir: Path, email: str) -> bool:
    prefix = f"[{idx}/{total}]"
    try:
        token = parse_noauth_line(line, default_email=email)
        if not token or not (token.get("access_token") or token.get("refresh_token")):
            log(f"{prefix} ❌ 无法解析（不鉴权模式需要 OAuth access_token / JSON 凭证）")
            return False
        access = str(token.get("access_token") or "")
        if access and looks_like_session_sso(access):
            log(f"{prefix} ❌ 这是 SSO session cookie，不是 OAuth token；请改用【鉴权模式】")
            return False
        if access and not is_oauth_access_token(access) and not token.get("refresh_token"):
            log(f"{prefix} ❌ access_token 不像有效 OAuth token（缺 sub/scope）")
            return False
        doc = build_xai_credential(token, email=email)
        if not doc.get("access_token") and not doc.get("refresh_token"):
            log(f"{prefix} ❌ 空凭证")
            return False
        # 不鉴权写出的文件至少要有 sub 或 email，否则文件名会退化成时间戳且基本不可用
        if not doc.get("sub") and not doc.get("email") and not doc.get("refresh_token"):
            log(f"{prefix} ❌ 缺 sub/email/refresh，拒绝写出残缺文件")
            return False
        label = str(doc.get("email") or doc.get("sub") or secrets.token_hex(4))
        path = out_dir / credential_file_name(str(doc.get("email") or ""), str(doc.get("sub") or ""))
        write_json(path, doc)
        _maybe_auto_push_cpa(path, prefix=prefix)
        size = path.stat().st_size
        log(f"{prefix} ✅ {label} → {path.name} ({size}B)")
        return True
    except Exception as e:
        log(f"{prefix} ❌ 异常: {e}")
        return False


def run_pool(items: list, worker_fn, workers: int, out_dir: Path, email: str) -> tuple[int, int]:
    total = len(items)
    ok = 0
    fail = 0
    workers = max(1, min(int(workers or 1), 64))

    if workers == 1 or total == 1:
        for i, item in enumerate(items, 1):
            if worker_fn(i, total, item, out_dir, email):
                ok += 1
            else:
                fail += 1
        return ok, fail

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [
            ex.submit(worker_fn, i, total, item, out_dir, email)
            for i, item in enumerate(items, 1)
        ]
        for fut in as_completed(futs):
            if fut.result():
                ok += 1
            else:
                fail += 1
    return ok, fail


def main() -> int:
    ap = argparse.ArgumentParser(description="SSO/Token → .local/credentials（鉴权/不鉴权）")
    ap.add_argument("--mode", choices=["auth", "noauth"], default="auth", help="auth=鉴权, noauth=不鉴权仅转换")
    ap.add_argument("--sso", metavar="FILE", help="输入列表文件")
    ap.add_argument("--sso-cookie", metavar="TEXT", help="单行输入")
    ap.add_argument("--out-dir", default=None, help="输出目录（默认 .local/credentials）")
    ap.add_argument("--out", default=None, help="兼容旧参数")
    ap.add_argument("--workers", type=int, default=8, help="并发数（默认 8）")
    ap.add_argument("--email", default="", help="统一 email（可选）")
    ap.add_argument("--delay", type=int, default=0, help="兼容旧参数，忽略")
    args = ap.parse_args()

    if args.out_dir:
        out_dir = Path(args.out_dir)
    elif args.out:
        p = Path(args.out)
        out_dir = p if p.suffix == "" else p.parent
    else:
        out_dir = CREDENTIALS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    mode = args.mode
    if mode == "auth":
        items = load_sso_list(args.sso, args.sso_cookie)
        worker = process_auth_one
        title = "鉴权模式 SSO → .local/credentials"
    else:
        items = load_input_lines(args.sso, args.sso_cookie)
        worker = process_noauth_one
        title = "不鉴权模式 格式转换 → .local/credentials"

    if not items:
        ap.error("需要 --sso 或 --sso-cookie")

    workers = max(1, min(int(args.workers or 1), 64))
    log(f"🚀 {title}")
    log(f"📦 条目: {len(items)} | workers={workers}")
    log(f"📁 输出: {out_dir}")

    t0 = time.time()
    ok, fail = run_pool(items, worker, workers, out_dir, args.email)
    elapsed = time.time() - t0
    log("=" * 50)
    log(f"📊 完成: {ok}/{len(items)} 成功, {fail} 失败, 耗时 {elapsed:.1f}s")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

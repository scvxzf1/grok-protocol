# -*- coding: utf-8 -*-
"""CLIProxyAPI (CPA) credential push helpers.

Adapted from GPT注册机 web_app CPA upload flow, tailored for xAI OAuth
credential JSON files under the local OAuth output directory.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from local_paths import iter_readable_files

LogFn = Callable[[str], None]


def _noop_log(_msg: str) -> None:
    return None


def normalize_cpa_base_url(raw: Any) -> str:
    text = str(raw or "").strip().rstrip("/")
    if not text:
        return ""
    # Accept accidental management path paste.
    for suffix in (
        "/v0/management/auth-files",
        "/v0/management",
        "/management/auth-files",
    ):
        if text.lower().endswith(suffix):
            text = text[: -len(suffix)].rstrip("/")
            break
    return text


def mask_secret(value: Any, keep: int = 4) -> str:
    text = str(value or "").strip()
    if not text:
        return "(空)"
    if len(text) <= keep * 2:
        return "*" * len(text)
    return f"{text[:keep]}…{text[-keep:]}"


def safe_email_filename(email: str) -> str:
    text = str(email or "").strip().lower() or "unknown"
    text = re.sub(r"[^a-z0-9._@+-]+", "_", text)
    return text[:180]


def build_cpa_remote_name(
    email: str,
    *,
    use_local_name: bool = False,
    source_path: str = "",
    prefix: str = "xai",
) -> str:
    if use_local_name and source_path:
        file_name = os.path.basename(str(source_path).strip())
        if file_name.lower().endswith(".json"):
            return file_name
    safe = safe_email_filename(email)
    return f"{prefix}-{safe}.json"


def serialize_cpa_payload(token_data: Dict[str, Any]) -> bytes:
    return json.dumps(token_data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def validate_cpa_payload(payload: Dict[str, Any]) -> str:
    """Return empty string when payload is pushable, else a human-readable reason."""
    if not isinstance(payload, dict):
        return "凭证不是对象"
    token_type = str(payload.get("type") or "").strip().lower()
    quality = str(payload.get("token_quality") or "").strip().lower()
    if quality in {"web_only", "account_created_no_token"} or token_type in {
        "chatgpt_web",
        "web_only",
    }:
        return (
            f"跳过推送: token_quality={quality or 'web_only'} "
            f"(type={token_type or '-'}，无完整 OAuth)"
        )
    required = ("type", "access_token", "refresh_token", "id_token", "email", "expired")
    missing = [name for name in required if not str(payload.get(name, "")).strip()]
    if missing:
        return f"缺少字段: {', '.join(missing)}"
    return ""


def cpa_request(
    method: str,
    base_url: str,
    api_key: str,
    path: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    raw_body: Optional[bytes] = None,
    json_body: Optional[Dict[str, Any]] = None,
    expect_json: bool = True,
    timeout: int = 30,
    retries: int = 1,
    log: Optional[LogFn] = None,
) -> Any:
    log = log or _noop_log
    base = normalize_cpa_base_url(base_url)
    if not base:
        raise ValueError("请先填写 CPA 接口地址")
    if not str(api_key or "").strip():
        raise ValueError("请先填写 CPA 管理密钥")

    url = f"{base}/{path.lstrip('/')}"
    if params:
        clean = {k: str(v) for k, v in params.items() if v is not None and str(v).strip()}
        if clean:
            url += "?" + urllib.parse.urlencode(clean)

    headers = {
        "Authorization": f"Bearer {str(api_key).strip()}",
        "User-Agent": "xAI-WebUI-CPA-Push/1.0",
        "Accept": "application/json",
    }
    body = raw_body
    if json_body is not None:
        body = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif raw_body is not None:
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=body, method=method.upper(), headers=headers)
    raw = b""
    for attempt in range(1 + max(0, int(retries))):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
            break
        except urllib.error.HTTPError as exc:
            err_raw = exc.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(err_raw) if err_raw else {}
            except Exception:
                payload = {}
            message = ""
            if isinstance(payload, dict):
                message = str(payload.get("error") or payload.get("message") or "").strip()
            if exc.code in (401, 403):
                raise RuntimeError(f"CPA 鉴权失败: {message or err_raw or exc.reason}") from exc
            raise RuntimeError(
                f"CPA 接口错误 HTTP {exc.code}: {message or err_raw or exc.reason}"
            ) from exc
        except urllib.error.URLError as exc:
            if attempt < retries:
                log(f"CPA 请求失败(尝试 {attempt + 1}/{1 + retries}): {exc}，重试中...")
                time.sleep(1.5)
                continue
            raise RuntimeError(f"CPA 网络异常: {exc}") from exc

    if not expect_json:
        return raw
    try:
        text = raw.decode("utf-8", errors="replace")
        return json.loads(text) if text else {}
    except Exception as exc:
        raise RuntimeError("CPA 接口返回的不是合法 JSON") from exc


def fetch_cpa_credentials(
    base_url: str,
    api_key: str,
    *,
    log: Optional[LogFn] = None,
) -> List[Dict[str, Any]]:
    payload = cpa_request("GET", base_url, api_key, "/v0/management/auth-files", log=log)
    files = payload.get("files", []) if isinstance(payload, dict) else []
    return [item for item in files if isinstance(item, dict)]


def check_cpa_connection(
    base_url: str,
    api_key: str,
    *,
    log: Optional[LogFn] = None,
) -> Dict[str, Any]:
    credentials = fetch_cpa_credentials(base_url, api_key, log=log)
    active = 0
    disabled = 0
    providers: Dict[str, int] = {}
    for item in credentials:
        if item.get("disabled"):
            disabled += 1
        else:
            active += 1
        provider = (
            str(item.get("provider") or item.get("type") or "unknown").strip().lower()
            or "unknown"
        )
        providers[provider] = providers.get(provider, 0) + 1
    return {
        "ok": True,
        "target": "cpa",
        "total": len(credentials),
        "active": active,
        "disabled": disabled,
        "providers": providers,
        "base_url": normalize_cpa_base_url(base_url),
        "api_key_masked": mask_secret(api_key),
        "message": f"CPA 连接正常，当前共有 {len(credentials)} 条凭证",
    }


def classify_cpa_duplicate(
    target_name: str,
    payload: Dict[str, Any],
    existing_credentials: Sequence[Dict[str, Any]],
) -> str:
    provider = str(payload.get("type", "") or "unknown").strip().lower()
    email = str(payload.get("email", "")).strip().lower()
    account_id = str(
        payload.get("account_id") or payload.get("sub") or payload.get("user_id") or ""
    ).strip()

    for credential in existing_credentials:
        if str(credential.get("name", "")).strip() == target_name:
            return "name"
    if provider and email:
        for credential in existing_credentials:
            remote_provider = (
                str(credential.get("provider") or credential.get("type") or "unknown")
                .strip()
                .lower()
            )
            remote_email = str(credential.get("email", "")).strip().lower()
            if remote_provider == provider and remote_email and remote_email == email:
                return "provider_email"
    if provider and account_id:
        for credential in existing_credentials:
            remote_provider = (
                str(credential.get("provider") or credential.get("type") or "unknown")
                .strip()
                .lower()
            )
            remote_account_id = str(
                credential.get("account_id")
                or credential.get("sub")
                or credential.get("user_id")
                or ""
            ).strip()
            if remote_provider == provider and remote_account_id and remote_account_id == account_id:
                return "provider_account_id"
    return ""


def collect_local_cpa_items(
    output_dir: Path | str,
    *,
    use_local_name: bool = True,
    names: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    directory = Path(output_dir).expanduser()
    try:
        directory = directory.resolve(strict=False)
    except OSError:
        directory = Path(output_dir).expanduser()

    wanted: Optional[set[str]] = None
    if names is not None:
        wanted = {str(n).strip() for n in names if str(n).strip()}
        if not wanted:
            return []

    items: List[Dict[str, Any]] = []
    seen_emails: set[str] = set()
    try:
        if not directory.is_dir():
            return items
    except OSError:
        return items

    # Skip ghost/corrupt FS entries that still appear in readdir.
    json_files, _skipped = iter_readable_files(
        directory,
        suffixes=(".json",),
        sort_by_mtime=True,
    )
    for path in json_files:
        if wanted is not None and path.name not in wanted and path.stem not in wanted:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        email = str(payload.get("email", "")).strip().lower()
        if email and email in seen_emails:
            continue
        target_name = build_cpa_remote_name(
            email,
            use_local_name=use_local_name,
            source_path=str(path),
        )
        items.append(
            {
                "email": email,
                "target_name": target_name,
                "raw_content": serialize_cpa_payload(payload),
                "payload": payload,
                "source": str(path),
                "json_name": path.name,
            }
        )
        if email:
            seen_emails.add(email)
    return items


def upload_cpa_items(
    base_url: str,
    api_key: str,
    items: Sequence[Dict[str, Any]],
    *,
    log: Optional[LogFn] = None,
    skip_duplicates: bool = True,
) -> Dict[str, Any]:
    log = log or _noop_log
    if not items:
        raise ValueError("当前没有可推送的本地凭证")

    existing = fetch_cpa_credentials(base_url, api_key, log=log)
    log(
        f"准备推送 {len(items)} 条，接口: {normalize_cpa_base_url(base_url)}，"
        f"Key: {mask_secret(api_key)}"
    )
    log(f"远端当前已有 {len(existing)} 条凭证")

    summary_items: List[Dict[str, Any]] = []
    success = 0
    failed = 0
    skipped = 0

    for index, item in enumerate(items, start=1):
        email = str(item.get("email", "")).strip().lower()
        target_name = str(item.get("target_name", "")).strip()
        payload = item.get("payload")
        raw_content = item.get("raw_content")
        source = str(item.get("source") or item.get("json_name") or "")

        if not isinstance(payload, dict) or not isinstance(raw_content, (bytes, bytearray)) or not target_name:
            failed += 1
            entry = {"ok": False, "message": "本地待上传凭证格式不对", "target_name": target_name}
            summary_items.append({"email": email or f"item-{index}", "source": source, "result": entry})
            continue

        validate_error = validate_cpa_payload(payload)
        if validate_error:
            failed += 1
            skipped += 1
            log(f"{index}/{len(items)} {email or '-'} 跳过: {validate_error}")
            entry = {"ok": False, "message": validate_error, "target_name": target_name, "skipped": True}
            summary_items.append({"email": email or f"item-{index}", "source": source, "result": entry})
            continue

        if skip_duplicates:
            duplicate_type = classify_cpa_duplicate(target_name, payload, existing)
            if duplicate_type:
                failed += 1
                skipped += 1
                duplicate_map = {
                    "name": "云端已有同名凭证",
                    "provider_email": "云端已有同 provider + email 凭证",
                    "provider_account_id": "云端已有同 provider + account_id 凭证",
                }
                message = duplicate_map.get(duplicate_type, "云端已存在重复凭证")
                log(f"{index}/{len(items)} {email or '-'} 跳过: {message}")
                entry = {
                    "ok": False,
                    "message": message,
                    "target_name": target_name,
                    "skipped": True,
                    "duplicate": duplicate_type,
                }
                summary_items.append({"email": email or f"item-{index}", "source": source, "result": entry})
                continue

        try:
            cpa_request(
                "POST",
                base_url,
                api_key,
                "/v0/management/auth-files",
                params={"name": target_name},
                raw_body=bytes(raw_content),
                expect_json=True,
                log=log,
            )
            success += 1
            log(f"{index}/{len(items)} {email or '-'} 推送成功: {target_name}")
            entry = {"ok": True, "message": f"上传成功: {target_name}", "target_name": target_name}
            existing.append(
                {
                    "name": target_name,
                    "provider": str(payload.get("type", "")).strip().lower(),
                    "email": str(payload.get("email", "")).strip(),
                    "account_id": str(
                        payload.get("account_id") or payload.get("sub") or ""
                    ).strip(),
                }
            )
        except Exception as exc:
            failed += 1
            log(f"{index}/{len(items)} {email or '-'} 推送异常: {exc}")
            entry = {"ok": False, "message": str(exc), "target_name": target_name}

        summary_items.append({"email": email or f"item-{index}", "source": source, "result": entry})

    return {
        "ok": True,
        "has_errors": failed > 0,
        "target": "cpa",
        "total": len(items),
        "success": success,
        "failed": failed,
        "skipped": skipped,
        "items": summary_items,
        "message": f"推送完成：成功 {success} / 失败 {failed} / 共 {len(items)}",
    }


def push_local_credentials(
    *,
    base_url: str,
    api_key: str,
    output_dir: Path | str,
    use_local_name: bool = True,
    names: Optional[Iterable[str]] = None,
    skip_duplicates: bool = True,
    log: Optional[LogFn] = None,
) -> Dict[str, Any]:
    items = collect_local_cpa_items(
        output_dir,
        use_local_name=use_local_name,
        names=names,
    )
    return upload_cpa_items(
        base_url,
        api_key,
        items,
        log=log,
        skip_duplicates=skip_duplicates,
    )


def auto_push_credential_file(
    *,
    config: Dict[str, Any],
    credential_path: Path | str,
    log: Optional[LogFn] = None,
) -> Optional[Dict[str, Any]]:
    """Best-effort auto push after a local credential JSON is written."""
    log = log or _noop_log
    if not bool(config.get("cpa_auto_upload")):
        return None
    base_url = normalize_cpa_base_url(config.get("cpa_api_url", ""))
    api_key = str(config.get("cpa_api_key", "")).strip()
    if not base_url or not api_key:
        log("已开启 CPA 自动推送，但接口地址或管理密钥未配置，跳过")
        return None

    path = Path(credential_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log(f"CPA 自动推送读取失败: {path.name}: {exc}")
        return {"ok": False, "message": str(exc)}
    if not isinstance(payload, dict):
        return {"ok": False, "message": "凭证不是对象"}

    validate_error = validate_cpa_payload(payload)
    if validate_error:
        log(f"CPA 自动推送跳过 {path.name}: {validate_error}")
        return {"ok": False, "message": validate_error, "skipped": True}

    email = str(payload.get("email", "")).strip().lower()
    use_local_name = bool(config.get("cpa_use_local_name", True))
    item = {
        "email": email,
        "target_name": build_cpa_remote_name(
            email,
            use_local_name=use_local_name,
            source_path=str(path),
        ),
        "raw_content": serialize_cpa_payload(payload),
        "payload": payload,
        "source": str(path),
        "json_name": path.name,
    }
    try:
        return upload_cpa_items(base_url, api_key, [item], log=log, skip_duplicates=True)
    except Exception as exc:
        log(f"CPA 自动推送失败 {path.name}: {exc}")
        return {"ok": False, "message": str(exc)}

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reverse converter: export line(s) -> credential .json + .sso

Input line format (same as WebUI export):
  <json-full-text>____<sso-full-text>

Run interactive TUI:
  python3 reverse_export_to_credentials.py

CLI:
  python3 reverse_export_to_credentials.py --line '{...}____sso...'
  python3 reverse_export_to_credentials.py --file .local/exports/grok+20260712073603.txt
  python3 reverse_export_to_credentials.py --file .local/exports/xxx.txt --out-dir .local/credentials
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from local_paths import CREDENTIALS_DIR


SEP = "____"
DEFAULT_OUT_DIR = CREDENTIALS_DIR


def sanitize_file_segment(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = re.sub(r"[\\/:*?\"<>|\s]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("._")
    return text[:180]


def credential_file_name(email: str = "", subject: str = "") -> str:
    email = sanitize_file_segment(email)
    if email:
        return f"xai-{email}.json"
    subject = sanitize_file_segment(subject)
    if subject:
        return f"xai-{subject}.json"
    return f"xai-{int(time.time() * 1000)}.json"


def sso_file_name(json_name: str) -> str:
    name = str(json_name or "").strip()
    if name.endswith(".json"):
        return name[:-5] + ".sso"
    return name + ".sso"


def split_export_line(line: str) -> Tuple[str, str]:
    raw = str(line or "").strip()
    if not raw:
        raise ValueError("空行")
    if SEP not in raw:
        raise ValueError(f"缺少分隔符 {SEP!r}")
    left, right = raw.split(SEP, 1)
    left = left.strip()
    right = right.strip()
    if not left:
        raise ValueError("JSON 部分为空")
    return left, right


def parse_json_side(text: str) -> Dict[str, Any]:
    payload = str(text or "").strip()
    if not payload:
        raise ValueError("JSON 为空")
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON 无法解析: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("JSON 根节点必须是对象")
    return data


def pick_names(data: Dict[str, Any]) -> Tuple[str, str]:
    email = str(data.get("email") or data.get("user_email") or "").strip()
    subject = str(data.get("sub") or data.get("user_id") or data.get("principal_id") or "").strip()
    return email, subject


def write_pair(
    out_dir: Path,
    data: Dict[str, Any],
    sso: str,
    *,
    overwrite: bool = True,
) -> Tuple[Path, Optional[Path]]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    email, subject = pick_names(data)
    json_name = credential_file_name(email=email, subject=subject)
    json_path = out_dir / json_name
    sso_path = out_dir / sso_file_name(json_name)

    if not overwrite and json_path.exists():
        raise FileExistsError(f"已存在: {json_path.name}")

    json_text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    tmp_json = json_path.with_suffix(json_path.suffix + f".{os.getpid()}.tmp")
    tmp_json.write_text(json_text, encoding="utf-8")
    os.replace(tmp_json, json_path)
    try:
        if os.name != "nt":
            os.chmod(json_path, 0o600)
    except OSError:
        pass

    written_sso: Optional[Path] = None
    sso_text = str(sso or "").strip()
    if sso_text:
        if "\n" in sso_text or "\r" in sso_text:
            # export may keep SSO as single line already; strip internal newlines just in case
            sso_text = re.sub(r"[\r\n]+", "", sso_text).strip()
        tmp_sso = sso_path.with_suffix(sso_path.suffix + f".{os.getpid()}.tmp")
        tmp_sso.write_text(sso_text + "\n", encoding="utf-8")
        os.replace(tmp_sso, sso_path)
        try:
            if os.name != "nt":
                os.chmod(sso_path, 0o600)
        except OSError:
            pass
        written_sso = sso_path
    return json_path, written_sso


def convert_line(line: str, out_dir: Path, *, overwrite: bool = True) -> Dict[str, Any]:
    left, right = split_export_line(line)
    data = parse_json_side(left)
    json_path, sso_path = write_pair(out_dir, data, right, overwrite=overwrite)
    return {
        "ok": True,
        "json": str(json_path),
        "sso": str(sso_path) if sso_path else "",
        "email": str(data.get("email") or ""),
        "has_sso": bool(sso_path),
    }


def convert_lines(lines: Iterable[str], out_dir: Path, *, overwrite: bool = True) -> Dict[str, Any]:
    ok_items: List[Dict[str, Any]] = []
    errors: List[str] = []
    for idx, line in enumerate(lines, 1):
        text = str(line or "").strip()
        if not text or text.startswith("#"):
            continue
        try:
            item = convert_line(text, out_dir, overwrite=overwrite)
            item["index"] = idx
            ok_items.append(item)
        except Exception as exc:  # noqa: BLE001 - collect per-line errors for batch restore
            errors.append(f"第{idx}行: {exc}")
    return {
        "ok": not errors,
        "converted": len(ok_items),
        "failed": len(errors),
        "items": ok_items,
        "errors": errors,
        "out_dir": str(Path(out_dir).resolve()),
    }


def read_multiline(prompt: str) -> str:
    print(prompt)
    print("提示: 可粘贴一行或多行；单独输入空行结束；也可 Ctrl+D 结束。")
    chunks: List[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line == "":
            if chunks:
                break
            # first empty line keeps waiting? treat consecutive empty as end only after content
            continue
        chunks.append(line)
    return "\n".join(chunks).strip()


def print_banner(out_dir: Path) -> None:
    print("=" * 60)
    print("  逆转换 TUI  ·  export行 -> json + sso")
    print("=" * 60)
    print(f"输出目录: {out_dir}")
    print(f"分隔符  : {SEP}")
    print("输入格式: {json全文}____sso全文")
    print("-" * 60)


def tui_loop(out_dir: Path, *, overwrite: bool = True) -> int:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    while True:
        print_banner(out_dir)
        print("1) 粘贴单条/多条 export 行并转换")
        print("2) 从 txt 文件批量转换")
        print("3) 修改输出目录")
        print("4) 退出")
        choice = input("\n请选择 [1-4]: ").strip() or "1"

        if choice in {"4", "q", "Q", "exit"}:
            print("已退出")
            return 0

        if choice == "3":
            raw = input(f"新输出目录（当前 {out_dir}）: ").strip()
            if raw:
                out_dir = Path(raw).expanduser()
                out_dir.mkdir(parents=True, exist_ok=True)
                print(f"✅ 输出目录已改为: {out_dir.resolve()}")
            continue

        if choice == "2":
            path_raw = input("txt 文件路径: ").strip()
            if not path_raw:
                print("⚠️ 未输入路径")
                continue
            path = Path(path_raw).expanduser()
            if not path.is_file():
                print(f"❌ 文件不存在: {path}")
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                print(f"❌ 读取失败: {exc}")
                continue
            result = convert_lines(content.splitlines(), out_dir, overwrite=overwrite)
            _print_result(result)
            input("\n回车继续...")
            continue

        # default: paste mode
        text = read_multiline("\n请粘贴 export 行（可多行）:")
        if not text:
            print("⚠️ 没有输入内容")
            input("\n回车继续...")
            continue
        # If user pasted one long line broken by terminals, still ok as multiple lines;
        # each non-empty line is treated as one export record.
        result = convert_lines(text.splitlines(), out_dir, overwrite=overwrite)
        _print_result(result)
        input("\n回车继续...")


def _print_result(result: Dict[str, Any]) -> None:
    print("\n----- 转换结果 -----")
    print(f"输出目录: {result.get('out_dir')}")
    print(f"成功: {result.get('converted')}  失败: {result.get('failed')}")
    for item in result.get("items") or []:
        sso_name = Path(item.get("sso") or "").name if item.get("sso") else "(无sso)"
        print(f"  ✅ {Path(item.get('json') or '').name} + {sso_name}")
    for err in result.get("errors") or []:
        print(f"  ❌ {err}")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="把 export 行(json____sso) 逆转换成 xai-*.json 和 .sso"
    )
    ap.add_argument("--line", action="append", default=[], help="单条 export 行，可重复")
    ap.add_argument("--file", action="append", default=[], help="包含 export 行的 txt 文件，可重复")
    ap.add_argument(
        "--out-dir",
        default=str(DEFAULT_OUT_DIR),
        help=f"输出目录（默认 {DEFAULT_OUT_DIR})",
    )
    ap.add_argument(
        "--no-overwrite",
        action="store_true",
        help="目标文件已存在时跳过/报错，不覆盖",
    )
    ap.add_argument(
        "--tui",
        action="store_true",
        help="强制进入交互 TUI（默认无 CLI 参数时也会进 TUI）",
    )
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    out_dir = Path(str(args.out_dir or DEFAULT_OUT_DIR)).expanduser()
    overwrite = not bool(args.no_overwrite)

    lines: List[str] = []
    for line in args.line or []:
        lines.append(str(line))
    for file_path in args.file or []:
        path = Path(str(file_path)).expanduser()
        if not path.is_file():
            print(f"❌ 文件不存在: {path}", file=sys.stderr)
            return 2
        lines.extend(path.read_text(encoding="utf-8", errors="replace").splitlines())

    if args.tui or not lines:
        return tui_loop(out_dir, overwrite=overwrite)

    result = convert_lines(lines, out_dir, overwrite=overwrite)
    _print_result(result)
    return 0 if int(result.get("failed") or 0) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

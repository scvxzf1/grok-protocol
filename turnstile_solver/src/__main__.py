from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

from turnstile_broker import build_canonical_fingerprint_profile

from .browser_runtime import _read_browser_full_version
from .config import MAX_SUBMIT_WORKERS, SolverConfig, load_config
from .models import SolveRequest
from .service import SolverService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local Turnstile token factory")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Start HTTP API")
    serve.add_argument("--config", default="", help="Path to solver config JSON")
    serve.add_argument("--host", default="", help="Override bind host")
    serve.add_argument("--port", type=int, default=0, help="Override bind port")
    serve.add_argument("--max-concurrency", type=int, default=0)
    serve.add_argument("--external-provider-workers", type=int, default=0)
    serve.add_argument("--external-queue-limit", type=int, default=0)
    serve.add_argument("--submit-workers", type=int, default=0)

    solve = sub.add_parser("solve", help="Capture one Turnstile token via local Chrome")
    solve.add_argument("--config", default="", help="Path to solver config JSON")
    solve.add_argument("--proxy", default="", help="Proxy URL/string for this task")
    solve.add_argument("--page-url", default="", help="Signup page URL")
    solve.add_argument("--timeout-sec", type=int, default=0)
    solve.add_argument("--headless", action="store_true")
    solve.add_argument("--browser-path", default="", help="Chrome executable override")
    solve.add_argument("--user-agent", default="", help="Browser UA override")
    solve.add_argument("--accept-language", default="", help="Accept-Language override")
    solve.add_argument("--expected-platform", default="", help="navigator.platform override")
    solve.add_argument(
        "--expected-client-hint-platform",
        default="",
        help="navigator.userAgentData platform override",
    )
    solve.add_argument("--expected-browser-major", type=int, default=0)
    solve.add_argument(
        "--output",
        default="",
        help="Optional path to write token (utf-8). Also prints JSON to stdout.",
    )
    solve.add_argument(
        "--proxy-used-file",
        default="",
        help="Optional path to write the upstream proxy that should be reused for register",
    )
    solve.add_argument(
        "--no-diagnose",
        action="store_true",
        help="Disable page diagnostics (enabled by default)",
    )

    health = sub.add_parser("health", help="Print local service health JSON")
    health.add_argument("--config", default="", help="Path to solver config JSON")
    return parser


def _write_text(path: str, content: str) -> None:
    out = Path(path).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    try:
        if os.name != "nt":
            out.chmod(0o600)
    except OSError:
        pass


def _current_language() -> str:
    return build_canonical_fingerprint_profile().accept_language


def _current_os_fingerprint(browser_version: str) -> Dict[str, object]:
    canonical = build_canonical_fingerprint_profile()
    version = str(browser_version or "").strip()
    try:
        actual_major = int(version.split(".", 1)[0])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid browser version: {version!r}") from exc
    canonical_major = int(canonical.browser_major)
    if actual_major != canonical_major:
        raise ValueError(
            "strict browser major does not match canonical HTTP profile: "
            f"expected={canonical_major}, actual={actual_major}"
        )
    return {
        "user_agent": canonical.user_agent,
        "accept_language": canonical.accept_language,
        "expected_platform": canonical.navigator_platform,
        "expected_client_hint_platform": canonical.client_hint_platform,
        "expected_browser_major": canonical_major,
    }


def _strict_solve_fingerprint(args: argparse.Namespace, config: SolverConfig) -> Dict[str, object]:
    browser_path = config.resolved_browser_path()
    browser_version = _read_browser_full_version(browser_path)
    defaults = _current_os_fingerprint(browser_version)
    overrides = {
        "user_agent": str(args.user_agent or config.user_agent or "").strip(),
        "accept_language": str(
            args.accept_language or config.accept_language or ""
        ).strip(),
        "expected_platform": str(args.expected_platform or "").strip(),
        "expected_client_hint_platform": str(
            args.expected_client_hint_platform or ""
        ).strip(),
    }
    for name, value in overrides.items():
        expected = str(defaults[name])
        if value and value != expected:
            raise ValueError(
                f"strict {name} override does not match canonical HTTP profile: "
                f"expected={expected!r}, actual={value!r}"
            )
    expected_major = int(defaults["expected_browser_major"])
    if args.expected_browser_major and int(args.expected_browser_major) != expected_major:
        raise ValueError(
            "strict expected_browser_major override does not match canonical HTTP profile: "
            f"expected={expected_major}, actual={args.expected_browser_major}"
        )
    canonical_locale = str(defaults["accept_language"]).split(",", 1)[0]
    if config.locale and str(config.locale).strip() != canonical_locale:
        raise ValueError(
            "strict locale does not match canonical HTTP profile: "
            f"expected={canonical_locale!r}, actual={config.locale!r}"
        )
    return dict(defaults)


def _apply_serve_overrides(args: argparse.Namespace, config: SolverConfig) -> None:
    if args.host:
        config.host = args.host
    if args.port:
        config.port = int(args.port)
    for name in (
        "max_concurrency",
        "external_provider_workers",
        "external_queue_limit",
        "submit_workers",
    ):
        value = int(getattr(args, name, 0) or 0)
        if value > 0:
            if name == "submit_workers":
                value = min(MAX_SUBMIT_WORKERS, value)
            setattr(config, name, value)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    config = load_config(args.config or None)
    fingerprint: Dict[str, object] = {}

    if args.command == "serve":
        _apply_serve_overrides(args, config)
    elif args.command == "solve":
        if args.browser_path:
            config.browser_path = args.browser_path
        if config.strict_fingerprint:
            fingerprint = _strict_solve_fingerprint(args, config)
        else:
            fingerprint = {
                "user_agent": args.user_agent or config.user_agent,
                "accept_language": args.accept_language or config.accept_language,
                "expected_platform": args.expected_platform,
                "expected_client_hint_platform": args.expected_client_hint_platform,
                "expected_browser_major": max(0, int(args.expected_browser_major or 0)),
            }

    service = SolverService(config)

    if args.command == "health":
        try:
            print(json.dumps(service.health(), ensure_ascii=False, indent=2))
        finally:
            service.close()
        return 0

    if args.command == "solve":
        try:
            result = service.solve(
                SolveRequest(
                    proxy=args.proxy or config.proxy,
                    page_url=args.page_url,
                    timeout_sec=args.timeout_sec or config.browser_timeout_sec,
                    headless=bool(args.headless or config.headless),
                    user_agent=str(fingerprint["user_agent"]),
                    accept_language=str(fingerprint["accept_language"]),
                    expected_platform=str(fingerprint["expected_platform"]),
                    expected_client_hint_platform=str(
                        fingerprint["expected_client_hint_platform"]
                    ),
                    expected_browser_major=int(fingerprint["expected_browser_major"]),
                    metadata={
                        "diagnose": (not args.no_diagnose),
                    },
                )
            )
        finally:
            service.close()
        if result.ok and args.output:
            _write_text(args.output, result.token + "\n")
        if args.proxy_used_file:
            _write_text(args.proxy_used_file, (result.proxy or args.proxy or "") + "\n")
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        return 0 if result.ok else 2

    if args.command == "serve":
        try:
            import uvicorn
            from .api import create_app
        except Exception as exc:  # pragma: no cover
            service.close()
            print(
                f"serve dependencies missing: {exc}\n"
                "Install: pip install -r turnstile_solver/requirements.txt",
                file=sys.stderr,
            )
            return 1
        app = create_app(service)
        try:
            uvicorn.run(app, host=config.host, port=config.port, log_level="info", workers=1)
        finally:
            service.close()
        return 0

    service.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

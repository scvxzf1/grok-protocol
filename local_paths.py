"""Canonical locations for machine-local configuration, fixtures, and output."""

from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent


def _resolved_path(value: object, default: Path) -> Path:
    raw = str(value or "").strip()
    path = Path(raw).expanduser() if raw else Path(default)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


LOCAL_ROOT = _resolved_path(os.environ.get("XAI_LOCAL_DIR"), PROJECT_ROOT / ".local")
CONFIG_PATH = _resolved_path(os.environ.get("XAI_CONFIG_PATH"), LOCAL_ROOT / "config.json")
ACCOUNTS_DIR = LOCAL_ROOT / "accounts"
CREDENTIALS_DIR = LOCAL_ROOT / "credentials"
RUNS_DIR = LOCAL_ROOT / "runs"
EXPORTS_DIR = LOCAL_ROOT / "exports"
FIXTURES_DIR = LOCAL_ROOT / "fixtures"
STATE_DIR = LOCAL_ROOT / "state"


__all__ = [
    "PROJECT_ROOT",
    "LOCAL_ROOT",
    "CONFIG_PATH",
    "ACCOUNTS_DIR",
    "CREDENTIALS_DIR",
    "RUNS_DIR",
    "EXPORTS_DIR",
    "FIXTURES_DIR",
    "STATE_DIR",
]

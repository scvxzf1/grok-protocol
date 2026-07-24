from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import http_batch_service as batch
import local_paths
import proxy_pool
import webui_app
import xai_http_flow


ROOT = Path(__file__).resolve().parents[1]


def test_clean_environment_defaults_every_local_path_under_dot_local():
    script = """
import json
import local_paths as p
print(json.dumps({
    'root': str(p.PROJECT_ROOT),
    'local': str(p.LOCAL_ROOT),
    'config': str(p.CONFIG_PATH),
    'dirs': [str(p.ACCOUNTS_DIR), str(p.CREDENTIALS_DIR), str(p.REGISTRATION_INFO_DIR),
             str(p.RUNS_DIR), str(p.EXPORTS_DIR), str(p.FIXTURES_DIR), str(p.STATE_DIR)],
}))
"""
    env = dict(os.environ)
    env.pop("XAI_LOCAL_DIR", None)
    env.pop("XAI_CONFIG_PATH", None)
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    paths = json.loads(result.stdout)
    expected_local = (ROOT / ".local").resolve()
    assert Path(paths["root"]) == ROOT.resolve()
    assert Path(paths["local"]) == expected_local
    assert Path(paths["config"]) == expected_local / "config.json"
    assert {Path(value).parent for value in paths["dirs"]} == {expected_local}


def test_service_and_cli_defaults_use_canonical_local_layout():
    assert batch.DEFAULT_CONFIG_PATH == local_paths.CONFIG_PATH
    assert batch.DEFAULT_OUTPUT_DIR == local_paths.CREDENTIALS_DIR
    assert batch.RUNS_DIR == local_paths.RUNS_DIR
    assert Path(proxy_pool.default_stats_path()) == local_paths.STATE_DIR / "proxy_stats.log"

    register = xai_http_flow.build_parser().parse_args(["register"])
    credential = xai_http_flow.build_parser().parse_args(["credential"])
    capture = xai_http_flow.build_parser().parse_args(["turnstile-capture"])
    assert Path(register.output_dir) == local_paths.CREDENTIALS_DIR
    assert Path(credential.output_dir) == local_paths.CREDENTIALS_DIR
    assert Path(capture.output) == local_paths.STATE_DIR / "turnstile.txt"
    assert Path(capture.proxy_used_file) == local_paths.STATE_DIR / "turnstile.proxy.txt"


def test_batch_service_resolves_relative_output_next_to_config():
    with tempfile.TemporaryDirectory() as directory:
        local_root = Path(directory) / ".local"
        local_root.mkdir()
        config = local_root / "config.json"
        config.write_text(
            json.dumps({"xai_oauth_output_dir": "credentials"}),
            encoding="utf-8",
        )
        service = batch.BatchService(config_path=config, root_dir=ROOT)
        assert service.settings.output_dir == (local_root / "credentials").resolve()
        assert service.export_dir() == (local_root / "exports").resolve()


def test_webui_uses_default_when_config_environment_is_blank():
    with mock.patch.dict(os.environ, {"XAI_CONFIG_PATH": ""}):
        args = webui_app.build_parser().parse_args([])
    assert Path(args.config) == batch.DEFAULT_CONFIG_PATH


def test_removed_ui_settings_are_dropped_when_config_is_loaded():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "config.json"
        path.write_text(
            json.dumps(
                {
                    "proxy_parent": "legacy",
                    "grok2api_remote_base": "legacy",
                    "enable_nsfw": True,
                    "register_count": 2,
                }
            ),
            encoding="utf-8",
        )
        loaded = batch._read_config(path)
    assert loaded == {"register_count": 2}


def test_register_main_loads_custom_config_for_runtime_proxy_selection():
    with tempfile.TemporaryDirectory() as directory:
        config = Path(directory) / "config.json"
        config.write_text(
            json.dumps({"turnstile_proxy_enabled": True, "sentinel": "loaded"}),
            encoding="utf-8",
        )
        before = os.environ.get("XAI_CONFIG_PATH")
        with mock.patch.object(xai_http_flow, "BrowserlessXAIClient"), mock.patch(
            "http_batch_service.pick_turnstile_proxy", return_value=""
        ) as pick_proxy, mock.patch.object(
            xai_http_flow,
            "run_registration",
            return_value=SimpleNamespace(
                email="masked@invalid.test",
                credential_path="",
                account_path="",
            ),
        ):
            result = xai_http_flow.main(
                [
                    "register",
                    "--mail-config",
                    str(config),
                    "--email",
                    "masked@invalid.test",
                    "--email-code",
                    "123456",
                    "--turnstile-token",
                    "token",
                ]
            )
        assert result == 0
        assert pick_proxy.call_args.args[0]["sentinel"] == "loaded"
        assert os.environ.get("XAI_CONFIG_PATH") == before


def test_active_config_ui_has_no_removed_grok2api_controls_or_copy():
    overview = (ROOT / "webui" / "templates" / "config.html").read_text(encoding="utf-8")
    output = (ROOT / "webui" / "templates" / "config_output.html").read_text(encoding="utf-8")
    javascript = (ROOT / "webui" / "static" / "config.js").read_text(encoding="utf-8")
    assert "Grok2API" not in overview
    assert "grok2api" not in output.lower()
    assert "grok2api" not in javascript.lower()


class _GhostPath(type(Path())):
    """Path subclass that mimics NTFS ghost entries raising EINVAL on probe."""

    def is_file(self):  # type: ignore[override]
        raise OSError(22, "Invalid argument", str(self))

    def stat(self, *args, **kwargs):  # type: ignore[override]
        raise OSError(22, "Invalid argument", str(self))


def test_iter_readable_files_skips_oserror_ghost_entries():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        good = root / "xai-good@example.test.json"
        good.write_text(
            json.dumps(
                {
                    "type": "xai",
                    "email": "good@example.test",
                    "access_token": "a",
                    "refresh_token": "r",
                    "id_token": "i",
                    "expired": "2099-01-01T00:00:00Z",
                    "sub": "sub-1",
                }
            ),
            encoding="utf-8",
        )
        ghost = _GhostPath(root / "xai-ghost@example.test.json")

        with mock.patch.object(Path, "iterdir", return_value=iter([good, ghost])):
            files, skipped = local_paths.iter_readable_files(
                root,
                suffixes=(".json",),
                sort_by_mtime=True,
            )

        assert [path.name for path in files] == [good.name]
        assert skipped == [ghost.name]
        assert local_paths.path_is_file(good) is True
        assert local_paths.path_is_file(ghost) is False


def test_list_credential_pairs_skips_unreadable_json_and_reports_them():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        good = root / "xai-good@example.test.json"
        good.write_text(
            json.dumps(
                {
                    "email": "good@example.test",
                    "account_id": "acct-1234567890",
                    "access_token": "token-value",
                    "password": "secret",
                }
            ),
            encoding="utf-8",
        )
        (root / "xai-good@example.test.sso").write_text("sso-token\n", encoding="utf-8")
        ghost = _GhostPath(root / "xai-ghost@example.test.json")

        with mock.patch.object(Path, "iterdir", return_value=iter([good, ghost])):
            page = batch.list_credential_pairs(
                root,
                page=1,
                page_size=50,
                include_secrets=True,
            )

        assert page["total"] == 1
        assert page["skipped_unreadable_count"] == 1
        assert page["skipped_unreadable"] == [ghost.name]
        assert len(page["items"]) == 1
        assert page["items"][0]["json_name"] == good.name
        assert page["items"][0]["has_sso"] is True
        assert "token-value" in page["items"][0]["line"]


def test_collect_local_cpa_items_skips_unreadable_json():
    import cpa_push

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        good = root / "xai-good@example.test.json"
        good.write_text(
            json.dumps(
                {
                    "type": "xai",
                    "email": "good@example.test",
                    "access_token": "access-token-value",
                    "refresh_token": "refresh-token-value",
                    "id_token": "id-token-value",
                    "expired": "2099-01-01T00:00:00Z",
                    "sub": "sub-1",
                }
            ),
            encoding="utf-8",
        )
        ghost = _GhostPath(root / "xai-ghost@example.test.json")

        with mock.patch.object(Path, "iterdir", return_value=iter([good, ghost])):
            items = cpa_push.collect_local_cpa_items(root)

        assert len(items) == 1
        assert items[0]["email"] == "good@example.test"

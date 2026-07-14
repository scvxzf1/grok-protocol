import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import http_batch_service as batch_service
import http_tui as tui


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tui.sh"


@unittest.skipUnless(shutil.which("bash"), "bash is required for the HTTP TUI launcher")
class HttpTuiLauncherTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX launcher paths require a POSIX host")
    def test_dry_run_uses_requested_count_and_concurrency_without_exposing_key(self):
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            config_path = directory_path / "config.json"
            output_dir = directory_path / "credentials"
            config_path.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "turnstile_provider": "capsolver",
                        "turnstile_api_key": "test-secret-key",
                        "register_count": 1,
                        "concurrent_workers": 1,
                        "proxy": "",
                        "proxy_file": "",
                        "proxy_random": False,
                    }
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "bash",
                    str(SCRIPT),
                    "--config",
                    str(config_path),
                    "--count",
                    "3",
                    "--workers",
                    "2",
                    "--output-dir",
                    str(output_dir),
                    "--no-proxy",
                    "--dry-run",
                    "--yes",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("运行模式: 模式1:注册+otp", result.stdout)
        self.assertIn("注册数量: 3", result.stdout)
        self.assertIn("并发数: 2", result.stdout)
        self.assertIn("HTTP 协议", result.stdout)
        self.assertNotIn("test-secret-key", result.stdout)
        self.assertNotIn("test-secret-key", result.stderr)

    @unittest.skipIf(os.name == "nt", "POSIX launcher paths require a POSIX host")
    def test_mode2_dry_run_mentions_sso_converter(self):
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            config_path = directory_path / "config.json"
            output_dir = directory_path / "credentials"
            config_path.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "turnstile_provider": "capsolver",
                        "turnstile_api_key": "test-secret-key",
                        "register_count": 1,
                        "concurrent_workers": 1,
                        "proxy": "",
                        "proxy_file": "",
                        "proxy_random": False,
                    }
                ),
                encoding="utf-8",
            )
            dry_run = subprocess.run(
                [
                    "bash",
                    str(SCRIPT),
                    "--config",
                    str(config_path),
                    "--mode",
                    "register_sso",
                    "--output-dir",
                    str(output_dir),
                    "--no-proxy",
                    "--dry-run",
                    "--yes",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
        self.assertIn("运行模式: 模式2:注册+sso转换", dry_run.stdout)
        self.assertIn("sso_to_auth_json", dry_run.stdout)
        self.assertNotIn("仍是占位", dry_run.stdout)

    def test_batch_runner_streams_child_logs_and_merges_worker_accounts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_entry = root / "grok_register_ttk.py"
            fake_entry.write_text(
                """
import argparse
from pathlib import Path

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--accounts-output', required=True)
args, _ = parser.parse_known_args()
print('[HTTP] fake backend started', flush=True)
Path(args.accounts_output).write_text('demo@example.test----password----sso\\n', encoding='utf-8')
print('[HTTP] fake backend completed', flush=True)
""".strip(),
                encoding="utf-8",
            )
            config_path = root / "config.json"
            config_path.write_text("{}", encoding="utf-8")
            plan = tui.RunPlan(
                config_path=config_path,
                run_mode=tui.DEFAULT_RUN_MODE,
                count=2,
                workers=2,
                output_dir=root / "credentials",
                provider="capsolver",
                email_provider="yyds",
                proxy_mode="none",
                proxy_args=[],
            )
            with mock.patch.object(batch_service, "ROOT_DIR", root), mock.patch.object(batch_service, "RUNS_DIR", root / "runs"), mock.patch.object(tui, "ROOT_DIR", root), mock.patch.object(tui, "RUNS_DIR", root / "runs"):
                runner = tui.BatchRunner(plan)
                runner.start()
                deadline = time.monotonic() + 5
                while not runner.done and time.monotonic() < deadline:
                    runner.tick()
                    time.sleep(0.02)

            self.assertTrue(runner.done)
            self.assertEqual(runner.succeeded, 2)
            self.assertEqual(runner.failed, 0)
            self.assertEqual(runner.account_count, 2)
            self.assertIsNotNone(runner.summary_path)
            self.assertTrue(any("fake backend completed" in line for line in runner.logs))

    def test_mode2_runner_converts_sso_after_register(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_entry = root / "grok_register_ttk.py"
            fake_entry.write_text(
                "\n".join(
                    [
                        "import argparse",
                        "from pathlib import Path",
                        "",
                        "parser = argparse.ArgumentParser(add_help=False)",
                        "parser.add_argument('--accounts-output', required=True)",
                        "parser.add_argument('--output-dir')",
                        "args, _ = parser.parse_known_args()",
                        "print('[HTTP] fake backend started', flush=True)",
                        "Path(args.accounts_output).write_text('demo@example.test----password----sso-token\\n', encoding='utf-8')",
                        "print('[HTTP] fake backend completed', flush=True)",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            fake_converter = root / "sso_to_auth_json.py"
            fake_converter.write_text(
                "\n".join(
                    [
                        "import argparse",
                        "from pathlib import Path",
                        "",
                        "parser = argparse.ArgumentParser()",
                        "parser.add_argument('--mode', default='auth')",
                        "parser.add_argument('--sso-cookie', default='')",
                        "parser.add_argument('--out-dir', required=True)",
                        "parser.add_argument('--workers', type=int, default=1)",
                        "parser.add_argument('--email', default='')",
                        "args = parser.parse_args()",
                        "out = Path(args.out_dir)",
                        "out.mkdir(parents=True, exist_ok=True)",
                        "name = args.email or 'unknown'",
                        "path = out / f'xai-{name}.json'",
                        "path.write_text('{\"access_token\":\"tok\",\"email\":\"%s\",\"type\":\"xai\"}\\n' % name, encoding='utf-8')",
                        "print(f'converted {name} sso={args.sso_cookie}', flush=True)",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            config_path = root / "config.json"
            config_path.write_text("{}", encoding="utf-8")
            plan = tui.RunPlan(
                config_path=config_path,
                run_mode=tui.RUN_MODE_REGISTER_SSO,
                count=1,
                workers=1,
                output_dir=root / "credentials",
                provider="capsolver",
                email_provider="yyds",
                proxy_mode="none",
                proxy_args=[],
            )
            with mock.patch.object(batch_service, "ROOT_DIR", root), mock.patch.object(batch_service, "RUNS_DIR", root / "runs"), mock.patch.object(tui, "ROOT_DIR", root), mock.patch.object(tui, "RUNS_DIR", root / "runs"):
                runner = tui.BatchRunner(plan)
                runner.start()
                deadline = time.monotonic() + 5
                while not runner.done and time.monotonic() < deadline:
                    runner.tick()
                    time.sleep(0.02)

            self.assertTrue(runner.done)
            self.assertEqual(runner.succeeded, 1)
            self.assertEqual(runner.failed, 0)
            self.assertEqual(runner.account_count, 1)
            cred = root / "credentials" / "xai-demo@example.test.json"
            self.assertTrue(cred.is_file(), "mode2 should write credential json")
            self.assertTrue(any("SSO→凭证转换" in line or "converted" in line for line in runner.logs))

    def test_runtime_settings_persist_to_config(self):
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            config_path = directory_path / "config.json"
            output_dir = directory_path / "out_creds"
            config_path.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "turnstile_provider": "capsolver",
                        "turnstile_api_key": "test-secret-key",
                        "register_count": 1,
                        "concurrent_workers": 1,
                        "proxy": "",
                        "proxy_file": "",
                        "proxy_random": False,
                    }
                ),
                encoding="utf-8",
            )
            settings = tui.Settings(
                config_path=config_path,
                count=7,
                workers=3,
                output_dir=output_dir,
                run_mode=tui.RUN_MODE_REGISTER_SSO,
                proxy_mode="pool",
                no_proxy=False,
                config=tui._read_config(config_path),
            )
            tui.persist_settings(settings)
            saved = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["register_count"], 7)
            self.assertEqual(saved["concurrent_workers"], 3)
            self.assertEqual(saved["tui_run_mode"], "register_sso")
            self.assertEqual(saved["tui_proxy_mode"], "pool")
            self.assertTrue(str(saved["xai_oauth_output_dir"]).endswith("out_creds") or saved["xai_oauth_output_dir"] == "out_creds")

            # 再读回，确认 settings_from_args 会恢复
            args = tui.build_parser().parse_args(["--config", str(config_path), "--dry-run"])
            args._explicit_cli = set()
            restored = tui.settings_from_args(args)
            self.assertEqual(restored.count, 7)
            self.assertEqual(restored.workers, 3)
            self.assertEqual(restored.run_mode, tui.RUN_MODE_REGISTER_SSO)
            self.assertEqual(restored.proxy_mode, "pool")
            self.assertEqual(restored.output_dir, output_dir.resolve())


    def test_mode2_starts_convert_without_blocking_main_loop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "grok_register_ttk.py").write_text(
                "\n".join(
                    [
                        "import argparse",
                        "from pathlib import Path",
                        "parser = argparse.ArgumentParser(add_help=False)",
                        "parser.add_argument('--accounts-output', required=True)",
                        "parser.add_argument('--output-dir')",
                        "args, _ = parser.parse_known_args()",
                        "Path(args.accounts_output).write_text('demo@example.test----password----sso-token\\n', encoding='utf-8')",
                        "print('register done output_dir=' + repr(args.output_dir), flush=True)",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            (root / "sso_to_auth_json.py").write_text(
                "\n".join(
                    [
                        "import argparse, time",
                        "from pathlib import Path",
                        "parser = argparse.ArgumentParser()",
                        "parser.add_argument('--mode', default='auth')",
                        "parser.add_argument('--sso-cookie', default='')",
                        "parser.add_argument('--out-dir', required=True)",
                        "parser.add_argument('--workers', type=int, default=1)",
                        "parser.add_argument('--email', default='')",
                        "args = parser.parse_args()",
                        "time.sleep(0.2)",
                        "out = Path(args.out_dir)",
                        "out.mkdir(parents=True, exist_ok=True)",
                        "name = args.email or 'unknown'",
                        "(out / f'xai-{name}.json').write_text('{\"access_token\":\"tok\",\"email\":\"%s\"}\\n' % name, encoding='utf-8')",
                        "print('converted ' + name, flush=True)",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            config_path = root / "config.json"
            config_path.write_text("{}", encoding="utf-8")
            plan = tui.RunPlan(
                config_path=config_path,
                run_mode=tui.RUN_MODE_REGISTER_SSO,
                count=2,
                workers=2,
                output_dir=root / "credentials",
                provider="capsolver",
                email_provider="yyds",
                proxy_mode="none",
                proxy_args=[],
            )
            with mock.patch.object(batch_service, "ROOT_DIR", root), mock.patch.object(batch_service, "RUNS_DIR", root / "runs"), mock.patch.object(tui, "ROOT_DIR", root), mock.patch.object(tui, "RUNS_DIR", root / "runs"):
                runner = tui.BatchRunner(plan)
                runner.start()
                saw_parallel_convert = False
                deadline = time.monotonic() + 5
                while not runner.done and time.monotonic() < deadline:
                    runner.tick()
                    converting = [w for w in runner.workers if w.status == "converting"]
                    if len(converting) >= 2:
                        saw_parallel_convert = True
                    time.sleep(0.02)
            self.assertTrue(runner.done)
            self.assertEqual(runner.succeeded, 2)
            self.assertTrue(saw_parallel_convert, "two workers should convert in parallel")
            self.assertTrue(any("output_dir=''" in line or 'output_dir=""' in line for line in runner.logs))
            self.assertTrue((root / "credentials" / "xai-demo@example.test.json").is_file())



    def test_mode2_convert_retries_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            register_script = (
                "import argparse\n"
                "from pathlib import Path\n"
                "parser = argparse.ArgumentParser(add_help=False)\n"
                "parser.add_argument('--accounts-output', required=True)\n"
                "parser.add_argument('--output-dir')\n"
                "args, _ = parser.parse_known_args()\n"
                "Path(args.accounts_output).write_text("
                "'demo@example.test----password----sso-token\\n', encoding='utf-8')\n"
                "print('register done', flush=True)\n"
            )
            (root / "grok_register_ttk.py").write_text(register_script, encoding="utf-8")
            counter = root / "convert_count.txt"
            counter.write_text("0", encoding="utf-8")
            converter_script = (
                "from pathlib import Path\n"
                "import sys\n"
                "p = Path('convert_count.txt')\n"
                "n = int(p.read_text().strip() or '0') + 1\n"
                "p.write_text(str(n), encoding='utf-8')\n"
                "print('attempt', n, flush=True)\n"
                "if n < 3:\n"
                "    print('device/code HTTP 429 slow_down', flush=True)\n"
                "    raise SystemExit(1)\n"
                "out = Path(sys.argv[sys.argv.index('--out-dir') + 1])\n"
                "out.mkdir(parents=True, exist_ok=True)\n"
                "email = sys.argv[sys.argv.index('--email') + 1]\n"
                "path = out / ('xai-%s.json' % email)\n"
                "path.write_text('{\"ok\": true}\\n', encoding='utf-8')\n"
                "print('converted', email, flush=True)\n"
            )
            (root / "sso_to_auth_json.py").write_text(converter_script, encoding="utf-8")
            config_path = root / "config.json"
            config_path.write_text("{}", encoding="utf-8")
            plan = tui.RunPlan(
                config_path=config_path,
                run_mode=tui.RUN_MODE_REGISTER_SSO,
                count=1,
                workers=1,
                output_dir=root / "credentials",
                provider="capsolver",
                email_provider="yyds",
                proxy_mode="none",
                proxy_args=[],
                sso_convert_retries=5,
                sso_convert_cooldown=0,
            )
            with mock.patch.object(batch_service, "ROOT_DIR", root), mock.patch.object(batch_service, "RUNS_DIR", root / "runs"), mock.patch.object(tui, "ROOT_DIR", root), mock.patch.object(tui, "RUNS_DIR", root / "runs"):
                runner = tui.BatchRunner(plan)
                runner.start()
                deadline = time.monotonic() + 8
                while not runner.done and time.monotonic() < deadline:
                    runner.tick()
                    time.sleep(0.02)
            self.assertTrue(runner.done)
            self.assertEqual(runner.succeeded, 1)
            self.assertEqual(counter.read_text(encoding="utf-8").strip(), "3")
            self.assertTrue(any("尝试 3/5" in line for line in runner.logs))
            self.assertTrue((root / "credentials" / "xai-demo@example.test.json").is_file())


    def test_turnstile_provider_persist_and_command_headless(self):
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            config_path = directory_path / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "turnstile_provider": "capsolver",
                        "turnstile_api_key": "test-secret-key",
                        "turnstile_headless": False,
                        "register_count": 1,
                        "concurrent_workers": 1,
                    }
                ),
                encoding="utf-8",
            )
            settings = tui.Settings(
                config_path=config_path,
                count=1,
                workers=1,
                output_dir=directory_path / "creds",
                run_mode=tui.DEFAULT_RUN_MODE,
                turnstile_provider="local",
                turnstile_headless=True,
                config=tui._read_config(config_path),
            )
            tui.persist_settings(settings)
            saved = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["turnstile_provider"], "local")
            self.assertTrue(saved["turnstile_headless"])

            plan = tui.build_plan(settings)
            self.assertEqual(plan.provider, "local")
            self.assertTrue(plan.turnstile_headless)
            worker = tui.WorkerState(index=1)
            worker.accounts_path = directory_path / "accounts_001.txt"
            command = tui.BatchRunner(plan)._command_for(worker)
            self.assertIn("--turnstile-provider", command)
            self.assertIn("local", command)
            self.assertIn("--turnstile-headless", command)



    def test_browser_health_status_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # fake temp profiles
            (root / "xai-ts-chrome-aaa").mkdir()
            os.utime(root / "xai-ts-chrome-aaa", (1, 1))
            (root / "xai-ts-probe-bbb").mkdir()
            (root / "xai-chrome-raw-ccc").mkdir()
            (root / "playwright_chromiumdev_profile-ddd").mkdir()
            (root / "keep-me").mkdir()

            with mock.patch.object(
                batch_service,
                "_pgrep_count",
                side_effect=[12, 34, 2],
            ), mock.patch.object(batch_service, "_count_zombie_chrome", return_value=1):
                status = tui.browser_health_status()
            self.assertEqual(status["chrome_count"], 12)
            self.assertEqual(status["playwright_count"], 34)
            self.assertEqual(status["solver_count"], 2)
            self.assertEqual(status["zombie_chrome_count"], 1)
            self.assertIn("chrome=12", tui.format_browser_health(status))

            result = tui.cleanup_browser_residues(
                temp_root=root,
                kill_playwright=True,
                kill_all_chrome=False,
                pkill_fn=lambda pattern: 3 if "ms-playwright" in pattern else 0,
            )
            self.assertEqual(result["killed_playwright"], 0)
            self.assertEqual(result["removed_temp_dirs"], 1)
            self.assertFalse((root / "xai-ts-chrome-aaa").exists())
            self.assertTrue((root / "xai-ts-probe-bbb").exists())
            self.assertTrue((root / "xai-chrome-raw-ccc").exists())
            self.assertTrue((root / "playwright_chromiumdev_profile-ddd").exists())
            self.assertTrue((root / "keep-me").exists())
            summary = tui.format_cleanup_result(result)
            self.assertIn("Playwright", summary)
            self.assertIn("临时目录", summary)

    def test_local_turnstile_caps_workers(self):
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            config_path = directory_path / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "local",
                        "turnstile_headless": True,
                        "register_count": 50,
                        "concurrent_workers": 10,
                    }
                ),
                encoding="utf-8",
            )
            settings = tui.Settings(
                config_path=config_path,
                count=50,
                workers=10,
                output_dir=directory_path / "creds",
                run_mode=tui.DEFAULT_RUN_MODE,
                turnstile_provider="local",
                turnstile_headless=True,
                config=tui._read_config(config_path),
            )
            plan = tui.build_plan(settings)
            self.assertEqual(plan.workers, 10)
            self.assertLessEqual(plan.turnstile_workers, tui.MAX_LOCAL_TURNSTILE_WORKERS)
            self.assertTrue(any("本地浏览器" in w and "并发" in w for w in plan.warnings))


if __name__ == "__main__":
    unittest.main()

# -*- coding: utf-8 -*-
"""Transitional curses TUI for HTTP batch registration.

Core batch logic lives in http_batch_service; this module only draws the
terminal UI and re-exports service symbols for existing tests/imports.
"""

from __future__ import annotations

import argparse
import curses
import os
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

from http_batch_service import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_RUN_MODE,
    DEFAULT_SSO_CONVERT_COOLDOWN,
    DEFAULT_SSO_CONVERT_RETRIES,
    DEFAULT_SUBMIT_WORKERS,
    DEFAULT_TURNSTILE_QUEUE_SIZE,
    MAX_COUNT,
    MAX_LOCAL_TURNSTILE_WORKERS,
    MAX_SSO_CONVERT_COOLDOWN,
    MAX_SSO_CONVERT_RETRIES,
    MAX_WORKERS,
    PROXY_MODE_LABELS,
    ROOT_DIR,
    RUN_MODE_ALIASES,
    RUN_MODE_LABELS,
    RUN_MODE_ORDER,
    RUN_MODE_REGISTER_OTP,
    RUN_MODE_REGISTER_SSO,
    RUNS_DIR,
    STATUS_LABELS,
    TURNSTILE_PROVIDER_LABELS,
    TURNSTILE_PROVIDER_ORDER,
    BatchRunner,
    RunPlan,
    Settings,
    TuiConfigError,
    WorkerState,
    _as_bool,
    _bounded_int,
    _normalize_run_mode,
    _normalize_turnstile_provider,
    _pgrep_count,
    _positive_int,
    _proxy_mode_label,
    _read_config,
    _run_mode_label,
    _status_label,
    _turnstile_provider_label,
    browser_health_status,
    build_plan,
    cleanup_browser_residues,
    describe_plan,
    format_browser_health,
    format_cleanup_result,
    persist_settings,
    refresh_settings_config,
    settings_from_args,
)

# Keep module-level ROOT_DIR/RUNS_DIR names assignable for older tests that
# patch http_tui.ROOT_DIR; BatchRunner still resolves names from http_batch_service.
import http_batch_service as _batch_service

class ProtocolTui:
    """可编辑运行表单 + 实时批量仪表盘的 curses 界面。"""

    def __init__(self, screen: "curses._CursesWindow", settings: Settings, *, auto_start: bool = False):
        self.screen = screen
        self.settings = settings
        self.auto_start = auto_start
        self.selected = 0
        self.mode = "form"
        self.runner: Optional[BatchRunner] = None
        self.message = "方向键选择，回车确认。Turnstile=local 时会启动本机浏览器。"
        self.log_scroll = 0
        self._configure_screen()

    def _configure_screen(self) -> None:
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        self.screen.keypad(True)
        self.screen.timeout(100)
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)
            curses.init_pair(3, curses.COLOR_GREEN, -1)
            curses.init_pair(4, curses.COLOR_RED, -1)
            curses.init_pair(5, curses.COLOR_YELLOW, -1)
            curses.init_pair(6, curses.COLOR_MAGENTA, -1)

    @staticmethod
    def _clip(text: object, width: int) -> str:
        value = _safe_text(text, max(1, width * 2))
        return _clip_display(value, max(0, width))

    def _add(self, y: int, x: int, text: object, attr: int = 0, width: Optional[int] = None) -> None:
        height, screen_width = self.screen.getmaxyx()
        if y < 0 or y >= height or x < 0 or x >= screen_width:
            return
        available = screen_width - x if width is None else min(width, screen_width - x)
        if available <= 0:
            return
        try:
            self.screen.addnstr(y, x, self._clip(text, available), available, attr)
        except curses.error:
            pass

    def _box(self, y: int, x: int, height: int, width: int, title: str = "") -> None:
        if height < 3 or width < 4:
            return
        self._add(y, x, "+" + "-" * (width - 2) + "+")
        for line in range(y + 1, y + height - 1):
            self._add(line, x, "|")
            self._add(line, x + width - 1, "|")
        self._add(y + height - 1, x, "+" + "-" * (width - 2) + "+")
        if title:
            self._add(y, x + 2, f" {title} ", curses.color_pair(1) | curses.A_BOLD, width - 4)

    def _modal(self, title: str, prompt: str, value: str = "", *, secret: bool = False) -> Optional[str]:
        height, width = self.screen.getmaxyx()
        modal_width = min(max(54, _display_width(prompt) + 12), max(54, width - 8))
        modal_height = 7
        y = max(0, (height - modal_height) // 2)
        x = max(0, (width - modal_width) // 2)
        buffer = value
        curses.curs_set(1)
        self.screen.timeout(-1)
        while True:
            self.screen.erase()
            self._draw_frame("HTTP 协议 TUI")
            self._box(y, x, modal_height, modal_width, title)
            self._add(y + 2, x + 2, prompt, width=modal_width - 4)
            shown = "*" * len(buffer) if secret else buffer
            self._add(y + 4, x + 2, shown, curses.color_pair(2), modal_width - 4)
            self._add(y + 5, x + 2, "回车确认 | Esc 取消", curses.color_pair(5), modal_width - 4)
            self.screen.refresh()
            key = self.screen.get_wch()
            if key in ("\n", "\r", curses.KEY_ENTER):
                self.screen.timeout(100)
                curses.curs_set(0)
                return buffer
            if key == "\x1b":
                self.screen.timeout(100)
                curses.curs_set(0)
                return None
            if key in (curses.KEY_BACKSPACE, "\b", "\x7f"):
                buffer = buffer[:-1]
            elif isinstance(key, str) and key.isprintable():
                buffer += key

    def _confirm(self, question: str) -> bool:
        answer = self._modal("确认", f"{question} [y/N]", "")
        return bool(answer and answer.strip().lower() in {"y", "yes"})

    def _draw_frame(self, title: str) -> None:
        height, width = self.screen.getmaxyx()
        self.screen.erase()
        self._add(0, 0, "=" * max(1, width))
        text = f" {title} "
        left = max(0, (width - _display_width(text)) // 2)
        self._add(0, left, text, curses.color_pair(6) | curses.A_BOLD)
        self._add(height - 2, 0, "-" * max(1, width))

    def _draw_form(self) -> None:
        height, width = self.screen.getmaxyx()
        self._draw_frame("HTTP 协议 TUI - 协议批量启动器")
        self._add(2, 2, "主流程走 HTTP 协议。仅 Turnstile=本地浏览器时，会在求解阶段临时开 Chrome。", curses.color_pair(1))
        proxy_value = "none" if self.settings.no_proxy else self.settings.proxy_mode
        rows = [
            ("配置文件", str(self.settings.config_path)),
            ("运行模式", _run_mode_label(self.settings.run_mode)),
            ("Turnstile", _turnstile_provider_label(self.settings.turnstile_provider, headless=self.settings.turnstile_headless)),
            ("注册数量", str(self.settings.count)),
            ("并发数", str(self.settings.workers)),
            ("OAuth 输出", str(self.settings.output_dir)),
            ("代理", _proxy_mode_label(proxy_value)),
            ("SSO重试", f"{self.settings.sso_convert_retries} 次（仅 Device Flow）"),
            ("SSO冷却", f"{self.settings.sso_convert_cooldown} 秒（仅 Device Flow）"),
            ("浏览器状态", format_browser_health()),
            ("清理残留", "清 Playwright + /tmp 临时浏览器目录"),
            ("重载配置", "重新读取服务商、邮箱和默认值"),
            ("保存配置", "把上方运行设置写回配置文件"),
            ("开始", "启动当前模式任务"),
            ("退出", "不启动并离开"),
        ]
        panel_width = min(width - 8, 104)
        panel_x = max(2, (width - panel_width) // 2)
        panel_y = 4
        panel_height = min(height - 8, len(rows) + 4)
        self._box(panel_y, panel_x, panel_height, panel_width, "运行设置")
        for index, (label, value) in enumerate(rows):
            y = panel_y + 2 + index
            if y >= panel_y + panel_height - 1:
                break
            selected = index == self.selected
            attr = curses.color_pair(2) | curses.A_BOLD if selected else 0
            self._add(y, panel_x + 2, _pad_display(label, 12), attr, 14)
            self._add(y, panel_x + 17, value, attr, panel_width - 19)
        self._add(height - 1, 2, "上下键选择 | 回车编辑/执行 | q 退出", curses.color_pair(5))
        self._add(
            height - 3,
            2,
            self.message,
            curses.color_pair(4) if self.message.startswith("错误:") else 0,
            width - 4,
        )
        self.screen.refresh()

    def _status_attr(self, status: str) -> int:
        if status == "succeeded":
            return curses.color_pair(3) | curses.A_BOLD
        if status in {"failed", "stopped"}:
            return curses.color_pair(4) | curses.A_BOLD
        if status in {"running", "converting"}:
            return curses.color_pair(1) | curses.A_BOLD
        return curses.color_pair(5) if status == "queued" else 0

    def _draw_dashboard(self) -> None:
        assert self.runner is not None
        runner = self.runner
        height, width = self.screen.getmaxyx()
        self._draw_frame("HTTP 协议 TUI - 实时协议运行")
        if width < 80 or height < 20:
            self._add(2, 2, "终端太小。请调整到至少 80x20。", curses.color_pair(4) | curses.A_BOLD)
            self.screen.refresh()
            return

        left_width = max(32, min(width // 2, int(width * 0.37)))
        right_width = width - left_width - 3
        panel_top = 2
        panel_height = height - 5
        self._box(panel_top, 1, panel_height, left_width, "进度")
        self._box(panel_top, left_width + 2, panel_height, right_width, "后端日志")

        if runner.stopping and not runner.done:
            state = "停止中"
        elif runner.done:
            state = "已完成"
        else:
            state = "运行中"
        progress = runner.completed / max(1, runner.plan.count)
        bar_width = max(10, left_width - 6)
        filled = min(bar_width, int(progress * bar_width))
        bar = "[" + "#" * filled + "-" * (bar_width - filled) + "]"
        details = [
            f"状态: {state}",
            f"模式: {_run_mode_label(runner.plan.run_mode)}",
            f"邮箱: {runner.plan.email_provider}",
            f"Turnstile: {_turnstile_provider_label(runner.plan.provider, headless=runner.plan.turnstile_headless)}",
            f"代理: {_proxy_mode_label(runner.plan.proxy_mode)}",
            f"任务: {runner.completed}/{runner.plan.count}",
            f"活动: {len(runner.active)} / {runner.plan.workers}",
            f"成功: {runner.succeeded}",
            f"失败: {runner.failed}",
            bar,
        ]
        for index, line in enumerate(details):
            self._add(
                panel_top + 2 + index,
                3,
                line,
                self._status_attr("running") if index == 0 else 0,
                left_width - 4,
            )

        worker_top = panel_top + 14
        self._add(worker_top, 3, "工作线程", curses.color_pair(1) | curses.A_BOLD, left_width - 4)
        visible_workers = max(1, panel_height - (worker_top - panel_top) - 3)
        for offset, worker in enumerate(runner.workers[:visible_workers]):
            y = worker_top + 1 + offset
            status_text = _pad_display(_status_label(worker.status), 6)
            line = f"W{worker.index:02d} {status_text} {worker.last_log}"
            self._add(y, 3, line, self._status_attr(worker.status), left_width - 4)

        log_height = panel_height - 2
        log_width = right_width - 4
        logs = list(runner.logs)
        max_start = max(0, len(logs) - log_height)
        start = max(0, max_start - self.log_scroll)
        visible_logs = logs[start : start + log_height]
        for offset, log_line in enumerate(visible_logs):
            attr = curses.color_pair(4) if "[!]" in log_line or "失败" in log_line or "failed" in log_line.lower() else 0
            self._add(panel_top + 1 + offset, left_width + 4, log_line, attr, log_width)

        if runner.done:
            summary = str(runner.summary_path) if runner.summary_path else "没有成功的账号记录"
            footer = f"已完成。账号数={runner.account_count} | {summary} | q 退出"
        else:
            footer = "q 停止批次 | 上下键滚动日志 | l 跟随最新"
        self._add(height - 1, 2, footer, curses.color_pair(5), width - 4)
        self.screen.refresh()

    def _start_run(self) -> None:
        try:
            plan = build_plan(self.settings)
        except TuiConfigError as exc:
            self.message = f"错误: {exc}"
            return
        self.runner = BatchRunner(plan)
        self.runner.start()
        self.mode = "dashboard"
        self.log_scroll = 0
        self.message = ""

    def _persist_runtime_settings(self, note: str) -> None:
        persist_settings(self.settings)
        self.message = note

    def _edit_field(self, index: int) -> None:
        try:
            if index == 0:
                value = self._modal("配置路径", "路径", str(self.settings.config_path))
                if value:
                    self.settings.config_path = _absolute_path(value)
                    refresh_settings_config(self.settings)
                    self.message = "配置已重新加载。"
            elif index == 1:
                order = list(RUN_MODE_ORDER)
                current = self.settings.run_mode if self.settings.run_mode in order else DEFAULT_RUN_MODE
                next_mode = order[(order.index(current) + 1) % len(order)]
                self.settings.run_mode = next_mode
                self._persist_runtime_settings(f"运行模式已保存: {_run_mode_label(next_mode)}")
            elif index == 2:
                # 循环：capsolver -> 2captcha -> yescaptcha -> local有界面 -> local无头
                current = _normalize_turnstile_provider(self.settings.turnstile_provider)
                if current == "local" and not self.settings.turnstile_headless:
                    self.settings.turnstile_provider = "local"
                    self.settings.turnstile_headless = True
                elif current == "local" and self.settings.turnstile_headless:
                    self.settings.turnstile_provider = "capsolver"
                    self.settings.turnstile_headless = False
                else:
                    order = list(TURNSTILE_PROVIDER_ORDER)
                    idx = order.index(current) if current in order else 0
                    nxt = order[(idx + 1) % len(order)]
                    self.settings.turnstile_provider = nxt
                    self.settings.turnstile_headless = False
                self._persist_runtime_settings(
                    "Turnstile 已保存: "
                    + _turnstile_provider_label(
                        self.settings.turnstile_provider,
                        headless=self.settings.turnstile_headless,
                    )
                )
            elif index == 3:
                value = self._modal("注册数量", "数量", str(self.settings.count))
                if value is not None:
                    self.settings.count = _positive_int(value, "注册数量", MAX_COUNT)
                    self._persist_runtime_settings(f"注册数量已保存: {self.settings.count}")
            elif index == 4:
                value = self._modal("并发工作线程", "并发数", str(self.settings.workers))
                if value is not None:
                    self.settings.workers = _positive_int(value, "并发数", MAX_WORKERS)
                    self._persist_runtime_settings(f"并发数已保存: {self.settings.workers}")
            elif index == 5:
                value = self._modal("OAuth 输出", "目录", str(self.settings.output_dir))
                if value:
                    self.settings.output_dir = _absolute_path(value)
                    self._persist_runtime_settings(f"OAuth 输出已保存: {self.settings.output_dir}")
            elif index == 6:
                order = ["auto", "none", "direct", "pool"]
                current = "none" if self.settings.no_proxy else self.settings.proxy_mode
                next_mode = order[(order.index(current) + 1) % len(order)] if current in order else "auto"
                self.settings.no_proxy = next_mode == "none"
                self.settings.proxy_mode = next_mode
                self._persist_runtime_settings(f"代理模式已保存: {_proxy_mode_label(next_mode)}")
            elif index == 7:
                value = self._modal(
                    "SSO转换重试",
                    "次数(1-20)",
                    str(self.settings.sso_convert_retries),
                )
                if value is not None:
                    self.settings.sso_convert_retries = _bounded_int(
                        value,
                        "SSO转换重试次数",
                        minimum=1,
                        maximum=MAX_SSO_CONVERT_RETRIES,
                        default=DEFAULT_SSO_CONVERT_RETRIES,
                    )
                    self._persist_runtime_settings(
                        f"SSO转换重试已保存: {self.settings.sso_convert_retries} 次"
                    )
            elif index == 8:
                value = self._modal(
                    "SSO转换冷却",
                    "秒数(0-120)",
                    str(self.settings.sso_convert_cooldown),
                )
                if value is not None:
                    self.settings.sso_convert_cooldown = _bounded_int(
                        value,
                        "SSO转换冷却秒数",
                        minimum=0,
                        maximum=MAX_SSO_CONVERT_COOLDOWN,
                        default=DEFAULT_SSO_CONVERT_COOLDOWN,
                    )
                    self._persist_runtime_settings(
                        f"SSO转换冷却已保存: {self.settings.sso_convert_cooldown}s"
                    )
            elif index == 9:
                self.message = "浏览器状态: " + format_browser_health()
            elif index == 10:
                if self._confirm("清理 Playwright 残留和 /tmp 临时浏览器目录？"):
                    result = cleanup_browser_residues(kill_playwright=True, kill_all_chrome=False)
                    self.message = format_cleanup_result(result)
                else:
                    self.message = "已取消清理。"
            elif index == 11:
                refresh_settings_config(self.settings, reset_defaults=False)
                self.message = "配置已重新加载；当前运行设置保持不变。"
            elif index == 12:
                self._persist_runtime_settings(f"配置已写入: {self.settings.config_path}")
            elif index == 13:
                try:
                    persist_settings(self.settings)
                except TuiConfigError as exc:
                    self.message = f"错误: {exc}"
                    return
                # Soft preflight for local Turnstile.
                if _normalize_turnstile_provider(self.settings.turnstile_provider) == "local":
                    health = browser_health_status()
                    if int(health.get("chrome_count") or 0) >= 80 or int(health.get("playwright_count") or 0) >= 30:
                        self.message = (
                            "警告: 浏览器残留偏高（"
                            + format_browser_health(health)
                            + "）。建议先执行“清理残留”再开始。"
                        )
                self._start_run()
            elif index == 14:
                self.mode = "exit"
        except TuiConfigError as exc:
            self.message = f"错误: {exc}"


    def _handle_form_key(self, key: object) -> None:
        rows = 15
        if key in (curses.KEY_UP, "k"):
            self.selected = (self.selected - 1) % rows
        elif key in (curses.KEY_DOWN, "j", "\t"):
            self.selected = (self.selected + 1) % rows
        elif key in ("\n", "\r", curses.KEY_ENTER, " "):
            self._edit_field(self.selected)
        elif key in ("s", "S"):
            self._start_run()
        elif key in ("q", "Q", "\x1b"):
            self.mode = "exit"

    def _handle_dashboard_key(self, key: object) -> None:
        assert self.runner is not None
        if key in (curses.KEY_UP, "k"):
            self.log_scroll = min(self.log_scroll + 1, max(0, len(self.runner.logs) - 1))
        elif key in (curses.KEY_DOWN, "j"):
            self.log_scroll = max(0, self.log_scroll - 1)
        elif key in ("l", "L"):
            self.log_scroll = 0
        elif key in ("q", "Q", "\x1b"):
            if self.runner.done:
                self.mode = "exit"
            elif self._confirm("停止所有活动中的协议任务？"):
                self.runner.stop()

    def run(self) -> int:
        if self.auto_start:
            self._start_run()
        while self.mode != "exit":
            if self.mode == "dashboard":
                assert self.runner is not None
                self.runner.tick()
                self._draw_dashboard()
            else:
                self._draw_form()
            try:
                key = self.screen.get_wch()
            except curses.error:
                continue
            if self.mode == "dashboard":
                self._handle_dashboard_key(key)
            else:
                self._handle_form_key(key)
        if self.runner is not None and not self.runner.done:
            self.runner.stop()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not self.runner.done:
                self.runner.tick()
                time.sleep(0.05)
        return self.runner.exit_code() if self.runner else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="全屏 HTTP 协议注册 TUI（仅 local Turnstile 临时开浏览器）")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="邮箱和验证码 JSON 配置")
    parser.add_argument(
        "--mode",
        default=None,
        choices=list(RUN_MODE_ORDER),
        help="凭证方式：register_otp=同会话 PKCE；register_sso=SSO Device Flow；默认读配置",
    )
    parser.add_argument("--count", type=int, default=None, help="注册任务数量")
    parser.add_argument("--workers", "--concurrency", dest="workers", type=int, default=None, help="最大并发数")
    parser.add_argument("--output-dir", default=None, help="OAuth 凭证输出目录；默认读配置 xai_oauth_output_dir")
    parser.add_argument("--no-proxy", action="store_true", help="不使用已配置的代理设置")
    parser.add_argument("--dry-run", action="store_true", help="只打印计划，不发送请求")
    parser.add_argument("--yes", action="store_true", help="打开仪表盘并立即开始")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv_list = list(argv) if argv is not None else None
    parser = build_parser()
    args = parser.parse_args(argv_list)
    # 记录哪些 CLI 参数是显式传入的，避免覆盖配置文件默认值。
    explicit: set[str] = set()
    tokens = list(argv_list if argv_list is not None else sys.argv[1:])
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in {"--mode"}:
            explicit.add("mode")
        elif token in {"--output-dir"}:
            explicit.add("output_dir")
        elif token in {"--count"}:
            explicit.add("count")
        elif token in {"--workers", "--concurrency"}:
            explicit.add("workers")
        elif token in {"--no-proxy"}:
            explicit.add("no_proxy")
        i += 1
    args._explicit_cli = explicit  # type: ignore[attr-defined]
    if "mode" in explicit and args.mode is None:
        args.mode = DEFAULT_RUN_MODE
    try:
        settings = settings_from_args(args)
        plan = build_plan(settings)
    except TuiConfigError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        print(describe_plan(plan, dry_run=True))
        return 0
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print(
            "[!] HTTP TUI 需要交互式终端。非交互校验请使用 --dry-run。",
            file=sys.stderr,
        )
        return 2
    try:
        return int(curses.wrapper(lambda screen: ProtocolTui(screen, settings, auto_start=args.yes).run()))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

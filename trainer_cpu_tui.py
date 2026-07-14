# -*- coding: utf-8 -*-
"""应用 / 训练器 资源监控 TUI。

核心只回答：
1. 当前应用在系统里占了多少 CPU / 内存（主指标，绝对值优先）
2. 整机系统 CPU / 内存占了多少

用法:
  python trainer_cpu_tui.py
  python trainer_cpu_tui.py --interval 0.5
  python trainer_cpu_tui.py --once
  python trainer_cpu_tui.py --scope trainer
  python trainer_cpu_tui.py --scope app
"""

from __future__ import annotations

import argparse
import curses
import os
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, List, Optional, Sequence, Tuple

try:
    import psutil
except ImportError as exc:  # pragma: no cover - 运行时依赖提示
    raise SystemExit("缺少 psutil，请先: pip install psutil") from exc


ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_INTERVAL = 1.0
HISTORY_LEN = 72

# 分类：应用相关进程
CAT_TRAINER = "trainer"
CAT_WEBUI = "webui"
CAT_CHROME = "chrome"
CAT_MIHOMO = "mihomo"
CAT_OTHER = "other"

CAT_LABELS = {
    CAT_TRAINER: "训练器",
    CAT_WEBUI: "WebUI",
    CAT_CHROME: "Chrome",
    CAT_MIHOMO: "Mihomo",
    CAT_OTHER: "其它",
}

SCOPE_APP = "app"
SCOPE_TRAINER = "trainer"


@dataclass
class ProcSnap:
    pid: int
    cpu: float  # 单核口径 %，多核可合计 >100
    share: float  # 折合整机占比 % = cpu / cores
    mem_pct: float
    rss_bytes: int
    etime: str
    category: str
    cmdline: str

    @property
    def rss_mb(self) -> float:
        return self.rss_bytes / (1024 * 1024)


@dataclass
class Sample:
    ts: float
    system_cpu: float  # 整机占用 0~100
    app_cpu_raw: float  # 应用进程单核%合计
    app_share: float  # 应用折合整机占比 0~100
    app_count: int
    other_share: float  # 系统占用 - 应用占用（粗算，下限 0）
    load1: float
    load5: float
    load15: float
    # 内存：全部用字节绝对值
    mem_total: int
    mem_used: int
    mem_available: int
    mem_used_pct: float
    app_rss: int  # 应用 RSS 合计（字节）
    by_cat_raw: Dict[str, float] = field(default_factory=dict)
    by_cat_share: Dict[str, float] = field(default_factory=dict)
    by_cat_rss: Dict[str, int] = field(default_factory=dict)
    by_cat_count: Dict[str, int] = field(default_factory=dict)
    procs: List[ProcSnap] = field(default_factory=list)

    @property
    def app_mem_pct(self) -> float:
        if self.mem_total <= 0:
            return 0.0
        return self.app_rss * 100.0 / self.mem_total


def _safe_text(value: object, limit: int = 200) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\n", " ").replace("\r", " ")
    if len(text) > limit:
        return text[: max(0, limit - 3)] + "..."
    return text


def _display_width(text: str) -> int:
    return sum(2 if ord(ch) > 127 else 1 for ch in text)


def _clip_display(text: str, width: int) -> str:
    if width <= 0:
        return ""
    out: List[str] = []
    used = 0
    for ch in text:
        w = 2 if ord(ch) > 127 else 1
        if used + w > width:
            break
        out.append(ch)
        used += w
    result = "".join(out)
    if len(result) < len(text) and width >= 3:
        while result and _display_width(result) > width - 3:
            result = result[:-1]
        result = result + "..."
        while _display_width(result) > width and result:
            result = result[:-1]
    return result


def _fmt_bytes(num: float | int, *, precision: Optional[int] = None) -> str:
    """人类可读容量：优先显示准确值，如 1.00G / 256M / 12.3G。"""
    n = float(max(0, num))
    units = [
        (1024 ** 4, "T"),
        (1024 ** 3, "G"),
        (1024 ** 2, "M"),
        (1024, "K"),
    ]
    for base, suffix in units:
        if n >= base:
            val = n / base
            if precision is not None:
                return f"{val:.{precision}f}{suffix}"
            # 自动精度：大数少小数，小数多一点
            if val >= 100:
                return f"{val:.0f}{suffix}"
            if val >= 10:
                return f"{val:.1f}{suffix}"
            return f"{val:.2f}{suffix}"
    if precision is not None:
        return f"{n:.{precision}f}B"
    return f"{int(round(n))}B"


def _fmt_bytes_pair(used: int | float, total: int | float) -> str:
    return f"{_fmt_bytes(used)} / {_fmt_bytes(total)}"


def _bar(pct: float, width: int, fill: str = "█", empty: str = "░") -> str:
    if width <= 0:
        return ""
    pct = max(0.0, min(100.0, pct))
    filled = int(round(pct / 100.0 * width))
    filled = max(0, min(width, filled))
    return fill * filled + empty * (width - filled)


def _dual_bar(app_share: float, system_cpu: float, width: int) -> str:
    """一条进度条：应用占比用实心，系统其余占用用半实心。"""
    if width <= 0:
        return ""
    app = max(0.0, min(100.0, app_share))
    sys_total = max(0.0, min(100.0, system_cpu))
    app_vis = min(app, sys_total)
    rest = max(0.0, sys_total - app_vis)
    n_app = int(round(app_vis / 100.0 * width))
    n_rest = int(round(rest / 100.0 * width))
    if n_app + n_rest > width:
        n_rest = max(0, width - n_app)
    n_empty = max(0, width - n_app - n_rest)
    return "█" * n_app + "▒" * n_rest + "░" * n_empty


def _spark(values: Sequence[float], width: int, scale: Optional[float] = None) -> str:
    if width <= 0:
        return ""
    blocks = " ▁▂▃▄▅▆▇█"
    if not values:
        return " " * width
    data = list(values)[-width:]
    if len(data) < width:
        data = [0.0] * (width - len(data)) + data
    peak = scale if scale and scale > 0 else max(data) if max(data) > 0 else 1.0
    out = []
    for v in data:
        ratio = max(0.0, min(1.0, float(v) / peak))
        idx = int(round(ratio * (len(blocks) - 1)))
        out.append(blocks[idx])
    return "".join(out)


def _fmt_etime(seconds: float) -> str:
    sec = max(0, int(seconds))
    days, rem = divmod(sec, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    if days:
        return f"{days}d{hours:02d}:{mins:02d}:{secs:02d}"
    if hours:
        return f"{hours:02d}:{mins:02d}:{secs:02d}"
    return f"{mins:02d}:{secs:02d}"


def _argv_basename(part: str) -> str:
    return Path(part).name.lower()


def _classify_proc(parts: Sequence[str], name: str = "") -> Optional[str]:
    """返回应用分类；None 表示不属于本应用。"""
    if not parts:
        return None

    joined = " ".join(parts).lower()
    if "trainer_cpu_tui.py" in joined or "test_trainer_cpu_tui" in joined:
        return None
    bases = {_argv_basename(p) for p in parts}

    if "grok_register_ttk.py" in bases or "grok_register_ttk" in bases:
        return CAT_TRAINER
    if "webui_app.py" in bases or "cpa_main.py" in bases:
        return CAT_WEBUI
    if "http_batch_service.py" in bases or "http_tui.py" in bases:
        return CAT_WEBUI

    if "xai-ts-chrome" in joined or "/tmp/xai-ts-chrome" in joined:
        return CAT_CHROME
    low_name = (name or "").lower()
    if ("chrome" in low_name or "chromium" in low_name) and (
        "xai-ts" in joined or "turnstile" in joined or "grok" in joined
    ):
        return CAT_CHROME

    if ".embedded_mihomo" in joined or "verge-mihomo" in joined:
        if "grok" in joined or ".embedded_mihomo" in joined:
            return CAT_MIHOMO
    if "mihomo" in bases and ".embedded_mihomo" in joined:
        return CAT_MIHOMO

    return None


def _is_target_proc(parts: Sequence[str] | str, name: str = "", scope: str = SCOPE_APP) -> bool:
    if isinstance(parts, str):
        part_list = parts.split()
    else:
        part_list = list(parts)
    cat = _classify_proc(part_list, name)
    if cat is None:
        return False
    if scope == SCOPE_TRAINER:
        return cat == CAT_TRAINER
    return True


def _proc_cmdline_parts(proc: "psutil.Process") -> List[str]:
    try:
        parts = proc.cmdline()
        if parts:
            return list(parts)
    except (psutil.Error, OSError):
        pass
    try:
        pname = proc.name() or ""
        return [pname] if pname else []
    except (psutil.Error, OSError):
        return []


class CpuSampler:
    """采样系统与当前应用的 CPU / 内存。"""

    def __init__(self, scope: str = SCOPE_APP) -> None:
        self.scope = scope if scope in (SCOPE_APP, SCOPE_TRAINER) else SCOPE_APP
        self._cpu_count = psutil.cpu_count(logical=True) or 1
        psutil.cpu_percent(interval=None)
        self._known: Dict[int, "psutil.Process"] = {}

    @property
    def cpu_count(self) -> int:
        return self._cpu_count

    def sample(self) -> Sample:
        system_cpu = float(psutil.cpu_percent(interval=None))
        try:
            load1, load5, load15 = os.getloadavg()
        except (AttributeError, OSError):
            load1 = load5 = load15 = 0.0

        mem = psutil.virtual_memory()
        procs = self._collect()
        app_raw = sum(p.cpu for p in procs)
        app_share = app_raw / max(1, self._cpu_count)
        other_share = max(0.0, system_cpu - app_share)
        app_rss = sum(p.rss_bytes for p in procs)

        by_raw: Dict[str, float] = {}
        by_share: Dict[str, float] = {}
        by_rss: Dict[str, int] = {}
        by_count: Dict[str, int] = {}
        for p in procs:
            by_raw[p.category] = by_raw.get(p.category, 0.0) + p.cpu
            by_share[p.category] = by_share.get(p.category, 0.0) + p.share
            by_rss[p.category] = by_rss.get(p.category, 0) + p.rss_bytes
            by_count[p.category] = by_count.get(p.category, 0) + 1

        return Sample(
            ts=time.time(),
            system_cpu=system_cpu,
            app_cpu_raw=app_raw,
            app_share=app_share,
            app_count=len(procs),
            other_share=other_share,
            load1=float(load1),
            load5=float(load5),
            load15=float(load15),
            mem_total=int(mem.total),
            mem_used=int(mem.used),
            mem_available=int(mem.available),
            mem_used_pct=float(mem.percent),
            app_rss=int(app_rss),
            by_cat_raw=by_raw,
            by_cat_share=by_share,
            by_cat_rss=by_rss,
            by_cat_count=by_count,
            procs=procs,
        )

    def _collect(self) -> List[ProcSnap]:
        alive: Dict[int, "psutil.Process"] = {}
        snaps: List[ProcSnap] = []
        cores = max(1, self._cpu_count)

        for proc in psutil.process_iter(["pid", "name"]):
            pid = int(proc.info.get("pid") or 0)
            if pid <= 0:
                continue
            try:
                name = str(proc.info.get("name") or "")
                cached = self._known.get(pid)
                if cached is not None and cached.is_running():
                    target = cached
                    parts = _proc_cmdline_parts(target)
                    cat = _classify_proc(parts, name)
                    if cat is None:
                        continue
                    if self.scope == SCOPE_TRAINER and cat != CAT_TRAINER:
                        continue
                else:
                    parts = _proc_cmdline_parts(proc)
                    cat = _classify_proc(parts, name)
                    if cat is None:
                        continue
                    if self.scope == SCOPE_TRAINER and cat != CAT_TRAINER:
                        continue
                    target = psutil.Process(pid)
                    try:
                        target.cpu_percent(interval=None)
                    except (psutil.Error, OSError):
                        pass
                    alive[pid] = target
                    continue

                with target.oneshot():
                    cpu = float(target.cpu_percent(interval=None))
                    mem_pct = float(target.memory_percent())
                    rss = int(target.memory_info().rss)
                    create = float(target.create_time())
                snaps.append(
                    ProcSnap(
                        pid=pid,
                        cpu=cpu,
                        share=cpu / cores,
                        mem_pct=mem_pct,
                        rss_bytes=rss,
                        etime=_fmt_etime(time.time() - create),
                        category=cat,
                        cmdline=_safe_text(" ".join(parts), 180),
                    )
                )
                alive[pid] = target
            except (psutil.Error, OSError):
                continue

        self._known = alive
        # 默认按内存绝对值排序，CPU 高的也容易看见；最终展示时仍可按 CPU
        snaps.sort(key=lambda p: (p.share, p.rss_bytes), reverse=True)
        return snaps


class AppCpuTui:
    """全屏 curses：主指标 = 应用在系统中的 CPU/内存占用（绝对值优先）。"""

    def __init__(
        self,
        screen: "curses._CursesWindow",
        interval: float = DEFAULT_INTERVAL,
        scope: str = SCOPE_APP,
    ):
        self.screen = screen
        self.interval = max(0.2, float(interval))
        self.scope = scope if scope in (SCOPE_APP, SCOPE_TRAINER) else SCOPE_APP
        self.sampler = CpuSampler(scope=self.scope)
        self.history_system: Deque[float] = deque(maxlen=HISTORY_LEN)
        self.history_app: Deque[float] = deque(maxlen=HISTORY_LEN)
        self.history_app_mem: Deque[float] = deque(maxlen=HISTORY_LEN)
        self.last: Optional[Sample] = None
        self.sort_by = "cpu"  # cpu | mem
        self.message = "q退出 | +/-间隔 | r刷新 | s切换范围 | m按内存排序 | c按CPU排序"
        self._configure()

    def _configure(self) -> None:
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
            curses.init_pair(2, curses.COLOR_GREEN, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1)
            curses.init_pair(4, curses.COLOR_RED, -1)
            curses.init_pair(5, curses.COLOR_MAGENTA, -1)
            curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_CYAN)
            curses.init_pair(7, curses.COLOR_WHITE, -1)
            curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_GREEN)

    def _add(self, y: int, x: int, text: object, attr: int = 0, width: Optional[int] = None) -> None:
        height, screen_width = self.screen.getmaxyx()
        if y < 0 or y >= height or x < 0 or x >= screen_width:
            return
        available = screen_width - x if width is None else min(width, screen_width - x)
        if available <= 0:
            return
        try:
            shown = _clip_display(_safe_text(text, available * 2), available)
            self.screen.addnstr(y, x, shown, available, attr)
        except curses.error:
            pass

    def _color_for_pct(self, pct: float) -> int:
        if pct >= 90:
            return curses.color_pair(4) | curses.A_BOLD
        if pct >= 70:
            return curses.color_pair(3) | curses.A_BOLD
        if pct >= 40:
            return curses.color_pair(2)
        return curses.color_pair(1)

    def _scope_title(self) -> str:
        if self.scope == SCOPE_TRAINER:
            return "训练器在系统中的占用（CPU + 内存绝对值）"
        return "当前应用在系统中的占用（CPU + 内存绝对值）"

    def _draw_frame(self, title: str) -> Tuple[int, int]:
        height, width = self.screen.getmaxyx()
        self.screen.erase()
        try:
            self.screen.border()
        except curses.error:
            pass
        label = f" {title} "
        self._add(
            0,
            max(2, (width - _display_width(label)) // 2),
            label,
            curses.color_pair(6) | curses.A_BOLD,
        )
        return height, width

    def _refresh_sample(self) -> None:
        sample = self.sampler.sample()
        self.last = sample
        self.history_system.append(sample.system_cpu)
        self.history_app.append(sample.app_share)
        self.history_app_mem.append(sample.app_mem_pct)

    def _set_scope(self, scope: str) -> None:
        self.scope = scope if scope in (SCOPE_APP, SCOPE_TRAINER) else SCOPE_APP
        self.sampler = CpuSampler(scope=self.scope)
        self.history_app.clear()
        self.history_system.clear()
        self.history_app_mem.clear()
        self._refresh_sample()
        time.sleep(0.12)
        self._refresh_sample()
        self.message = f"范围 -> {self.scope}（app=整套应用 / trainer=仅训练器）"

    def _sorted_procs(self, sample: Sample) -> List[ProcSnap]:
        procs = list(sample.procs)
        if self.sort_by == "mem":
            procs.sort(key=lambda p: p.rss_bytes, reverse=True)
        else:
            procs.sort(key=lambda p: (p.share, p.rss_bytes), reverse=True)
        return procs

    def _draw(self) -> None:
        height, width = self._draw_frame(self._scope_title())
        sample = self.last
        if sample is None:
            self._add(2, 2, "采样中...", curses.color_pair(3))
            self.screen.refresh()
            return

        inner_w = max(10, width - 4)
        bar_w = max(12, min(40, inner_w - 34))
        cpu_n = self.sampler.cpu_count
        app_name = "训练器" if self.scope == SCOPE_TRAINER else "应用"

        y = 2
        self._add(
            y,
            2,
            (
                f"刷新 {self.interval:.1f}s | 逻辑核 {cpu_n} | scope={self.scope} | "
                f"排序={self.sort_by} | {time.strftime('%F %T', time.localtime(sample.ts))}"
            ),
            curses.color_pair(1),
            inner_w,
        )
        y += 2

        # ===== 主指标 1：应用内存绝对值 =====
        mem_attr = self._color_for_pct(sample.app_mem_pct) | curses.A_BOLD
        self._add(y, 2, f"{app_name}内存", curses.color_pair(8) | curses.A_BOLD, 10)
        self._add(y, 13, _bar(sample.app_mem_pct, bar_w), mem_attr)
        self._add(
            y,
            14 + bar_w,
            (
                f" {_fmt_bytes(sample.app_rss)} / {_fmt_bytes(sample.mem_total)}"
                f"  ({sample.app_mem_pct:4.1f}%)  n={sample.app_count}"
            ),
            mem_attr,
            max(0, width - 16 - bar_w),
        )
        y += 1

        # 系统内存绝对值
        sys_mem_attr = self._color_for_pct(sample.mem_used_pct)
        self._add(y, 2, "系统内存", curses.A_BOLD, 10)
        self._add(y, 13, _bar(sample.mem_used_pct, bar_w), sys_mem_attr)
        self._add(
            y,
            14 + bar_w,
            (
                f" {_fmt_bytes(sample.mem_used)} / {_fmt_bytes(sample.mem_total)}"
                f"  ({sample.mem_used_pct:4.1f}%)  可用 {_fmt_bytes(sample.mem_available)}"
            ),
            sys_mem_attr,
            max(0, width - 16 - bar_w),
        )
        y += 2

        # ===== 主指标 2：应用 CPU（系统内占比）=====
        app_attr = self._color_for_pct(sample.app_share) | curses.A_BOLD
        self._add(y, 2, f"{app_name}CPU ", curses.color_pair(8) | curses.A_BOLD, 10)
        self._add(y, 13, _bar(sample.app_share, bar_w), app_attr)
        self._add(
            y,
            14 + bar_w,
            f" {sample.app_share:5.1f}%  系统内占用   原始合计 {sample.app_cpu_raw:.1f}%",
            app_attr,
            max(0, width - 16 - bar_w),
        )
        y += 1

        sys_attr = self._color_for_pct(sample.system_cpu)
        self._add(y, 2, "系统CPU ", curses.A_BOLD, 10)
        self._add(y, 13, _bar(sample.system_cpu, bar_w), sys_attr)
        self._add(
            y,
            14 + bar_w,
            (
                f" {sample.system_cpu:5.1f}%  load "
                f"{sample.load1:.2f} {sample.load5:.2f} {sample.load15:.2f}"
            ),
            sys_attr,
            max(0, width - 16 - bar_w),
        )
        y += 1

        # 构成条
        self._add(y, 2, "CPU构成 ", curses.A_BOLD, 10)
        self._add(y, 13, _dual_bar(sample.app_share, sample.system_cpu, bar_w), curses.color_pair(5))
        self._add(
            y,
            14 + bar_w,
            (
                f" █{app_name}{sample.app_share:4.1f}%  "
                f"▒其它{sample.other_share:4.1f}%  "
                f"░空闲{max(0.0, 100.0 - sample.system_cpu):4.1f}%"
            ),
            curses.color_pair(7),
            max(0, width - 16 - bar_w),
        )
        y += 2

        # 分类拆解：内存绝对值 + CPU 系统占比
        if self.scope == SCOPE_APP:
            self._add(
                y,
                2,
                "应用拆解（内存=绝对值，CPU=系统内占比）",
                curses.color_pair(6) | curses.A_BOLD,
                inner_w,
            )
            y += 1
            order = [CAT_TRAINER, CAT_WEBUI, CAT_CHROME, CAT_MIHOMO, CAT_OTHER]
            for cat in order:
                share = sample.by_cat_share.get(cat, 0.0)
                rss = sample.by_cat_rss.get(cat, 0)
                cnt = sample.by_cat_count.get(cat, 0)
                if cnt <= 0 and share <= 0 and rss <= 0:
                    continue
                label = CAT_LABELS.get(cat, cat)
                mem_pct = (rss * 100.0 / sample.mem_total) if sample.mem_total else 0.0
                attr = self._color_for_pct(max(share, mem_pct))
                small = max(8, min(18, bar_w // 2))
                self._add(y, 2, f"{label:<6}", curses.A_BOLD, 8)
                self._add(y, 10, _bar(mem_pct, small), attr)
                self._add(
                    y,
                    11 + small,
                    (
                        f" 内存 {_fmt_bytes(rss):>7} ({mem_pct:4.1f}%)"
                        f"  CPU {share:5.1f}%  n={cnt}"
                    ),
                    attr,
                    max(0, width - 13 - small),
                )
                y += 1
            y += 1

        # 历史
        spark_w = max(10, min(HISTORY_LEN, inner_w - 14))
        self._add(y, 2, f"{app_name}CPU ", curses.color_pair(5))
        self._add(y, 12, _spark(self.history_app, spark_w, scale=100.0), curses.color_pair(5), spark_w)
        y += 1
        self._add(y, 2, f"{app_name}内存", curses.color_pair(2))
        self._add(
            y,
            12,
            _spark(self.history_app_mem, spark_w, scale=100.0),
            curses.color_pair(2),
            spark_w,
        )
        y += 1
        self._add(y, 2, "系统CPU ", curses.color_pair(1))
        self._add(
            y,
            12,
            _spark(self.history_system, spark_w, scale=100.0),
            curses.color_pair(1),
            spark_w,
        )
        y += 2

        sort_label = "内存绝对值" if self.sort_by == "mem" else "系统内CPU占比"
        self._add(
            y,
            2,
            f"{app_name}进程 Top（按{sort_label}）",
            curses.color_pair(6) | curses.A_BOLD,
            inner_w,
        )
        y += 1
        header = (
            f"{'PID':>8}  {'内存':>8}  {'内存%':>6}  {'系统CPU':>7}  "
            f"{'单核CPU':>7}  {'分类':<6}  {'ETIME':>10}  CMD"
        )
        self._add(y, 2, header, curses.A_BOLD, inner_w)
        y += 1

        max_rows = max(0, height - y - 2)
        procs = self._sorted_procs(sample)
        if not procs:
            self._add(y, 2, f"（当前没有{app_name}进程）", curses.color_pair(3), inner_w)
        else:
            for idx, proc in enumerate(procs[:max_rows]):
                # 着色：内存优先时看内存占比，否则看 CPU
                if self.sort_by == "mem":
                    score = proc.mem_pct
                else:
                    score = min(100.0, proc.share * 4)
                attr = self._color_for_pct(score)
                cat = CAT_LABELS.get(proc.category, proc.category)
                line = (
                    f"{proc.pid:>8}  {_fmt_bytes(proc.rss_bytes):>8}  {proc.mem_pct:5.1f}%  "
                    f"{proc.share:6.2f}%  {proc.cpu:6.1f}%  {cat:<6}  "
                    f"{proc.etime:>10}  {proc.cmdline}"
                )
                self._add(y + idx, 2, line, attr, inner_w)

        self._add(height - 1, 2, self.message, curses.color_pair(3), max(0, width - 4))
        self.screen.refresh()

    def run(self) -> int:
        self._refresh_sample()
        time.sleep(0.15)
        self._refresh_sample()
        next_tick = time.monotonic()

        while True:
            now = time.monotonic()
            if now >= next_tick:
                self._refresh_sample()
                next_tick = now + self.interval

            self._draw()
            try:
                key = self.screen.getch()
            except curses.error:
                key = -1

            if key in (ord("q"), ord("Q"), 27):
                return 0
            if key in (ord("+"), ord("=")):
                self.interval = min(10.0, round(self.interval + 0.5, 1))
                self.message = f"刷新间隔 -> {self.interval:.1f}s"
            elif key in (ord("-"), ord("_")):
                self.interval = max(0.2, round(self.interval - 0.5, 1))
                self.message = f"刷新间隔 -> {self.interval:.1f}s"
            elif key in (ord("r"), ord("R")):
                self._refresh_sample()
                next_tick = time.monotonic() + self.interval
                self.message = "已强制刷新"
            elif key in (ord("s"), ord("S")):
                self._set_scope(SCOPE_TRAINER if self.scope == SCOPE_APP else SCOPE_APP)
                next_tick = time.monotonic() + self.interval
            elif key in (ord("m"), ord("M")):
                self.sort_by = "mem"
                self.message = "进程列表按内存绝对值排序"
            elif key in (ord("c"), ord("C")):
                self.sort_by = "cpu"
                self.message = "进程列表按系统内CPU占比排序"
            elif key == curses.KEY_RESIZE:
                self.message = "窗口已调整"


def render_once(interval_hint: float = 0.3, scope: str = SCOPE_APP) -> str:
    sampler = CpuSampler(scope=scope)
    sampler.sample()
    time.sleep(max(0.1, interval_hint))
    s = sampler.sample()
    cpu_n = sampler.cpu_count
    app_name = "trainer" if scope == SCOPE_TRAINER else "app"
    lines = [
        f"time={time.strftime('%F %T', time.localtime(s.ts))}",
        f"scope={scope}  cores={cpu_n}",
        (
            f"{app_name}_mem={_fmt_bytes(s.app_rss)} / {_fmt_bytes(s.mem_total)} "
            f"({s.app_mem_pct:.2f}%)  n={s.app_count}   ← 应用内存（绝对值）"
        ),
        (
            f"system_mem={_fmt_bytes(s.mem_used)} / {_fmt_bytes(s.mem_total)} "
            f"({s.mem_used_pct:.1f}%)  available={_fmt_bytes(s.mem_available)}"
        ),
        (
            f"{app_name}_cpu={s.app_share:.2f}%  system_cpu={s.system_cpu:.1f}%  "
            f"other={s.other_share:.2f}%  idle={max(0.0, 100.0 - s.system_cpu):.1f}%"
        ),
        (
            f"raw_cpu_sum={s.app_cpu_raw:.1f}%  "
            f"load={s.load1:.2f}/{s.load5:.2f}/{s.load15:.2f}"
        ),
    ]
    if s.by_cat_rss or s.by_cat_share:
        parts = []
        for cat in (CAT_TRAINER, CAT_WEBUI, CAT_CHROME, CAT_MIHOMO, CAT_OTHER):
            if cat in s.by_cat_rss or cat in s.by_cat_share:
                rss = s.by_cat_rss.get(cat, 0)
                share = s.by_cat_share.get(cat, 0.0)
                cnt = s.by_cat_count.get(cat, 0)
                parts.append(
                    f"{CAT_LABELS[cat]}={_fmt_bytes(rss)}/{share:.2f}%cpu(n={cnt})"
                )
        if parts:
            lines.append("breakdown: " + "  ".join(parts))
    lines.extend(
        [
            "",
            (
                f"{'PID':>8}  {'内存':>8}  {'内存%':>6}  {'系统CPU':>7}  "
                f"{'单核CPU':>7}  {'分类':<6}  {'ETIME':>10}  CMD"
            ),
        ]
    )
    if not s.procs:
        lines.append("(no target processes)")
    else:
        # once 模式默认按内存绝对值排序，方便看“到底吃了多少G”
        procs = sorted(s.procs, key=lambda p: p.rss_bytes, reverse=True)
        for p in procs[:40]:
            cat = CAT_LABELS.get(p.category, p.category)
            lines.append(
                f"{p.pid:>8}  {_fmt_bytes(p.rss_bytes):>8}  {p.mem_pct:5.1f}%  "
                f"{p.share:6.2f}%  {p.cpu:6.1f}%  {cat:<6}  "
                f"{p.etime:>10}  {p.cmdline}"
            )
    return "\n".join(lines)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="当前应用 / 训练器 在系统中的 CPU+内存占用监控 TUI（内存显示绝对值）"
    )
    parser.add_argument(
        "--interval",
        "-i",
        type=float,
        default=DEFAULT_INTERVAL,
        help=f"刷新间隔秒，默认 {DEFAULT_INTERVAL}",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="只打印一次文本快照后退出（无需 TTY）",
    )
    parser.add_argument(
        "--scope",
        choices=(SCOPE_APP, SCOPE_TRAINER),
        default=SCOPE_APP,
        help="app=整套应用(默认) / trainer=仅训练器 worker",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.once or not sys.stdout.isatty():
        if not args.once and not sys.stdout.isatty():
            print("[!] 非交互终端，自动切换 --once 模式", file=sys.stderr)
        print(render_once(scope=args.scope))
        return 0

    interval = max(0.2, float(args.interval))
    return int(
        curses.wrapper(
            lambda screen: AppCpuTui(screen, interval=interval, scope=args.scope).run()
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())

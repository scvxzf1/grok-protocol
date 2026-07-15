# -*- coding: utf-8 -*-
from __future__ import annotations

import trainer_cpu_tui as m


def test_classify_and_scope():
    trainer = [
        "/home/scv/miniconda3/bin/python3",
        "/path/xai_http_flow.py",
        "register",
    ]
    webui = ["python3", "webui_app.py", "--port", "33844"]
    bash_echo = ["/bin/bash", "-c", "echo xai_http_flow.py"]
    self_mon = ["python3", "trainer_cpu_tui.py", "--once"]

    assert m._classify_proc(trainer) == m.CAT_TRAINER
    assert m._classify_proc(webui) == m.CAT_WEBUI
    assert m._classify_proc(bash_echo) is None
    assert m._classify_proc(self_mon) is None

    assert m._is_target_proc(trainer, scope=m.SCOPE_APP)
    assert m._is_target_proc(webui, scope=m.SCOPE_APP)
    assert m._is_target_proc(trainer, scope=m.SCOPE_TRAINER)
    assert not m._is_target_proc(webui, scope=m.SCOPE_TRAINER)
    assert not m._is_target_proc(bash_echo, scope=m.SCOPE_APP)


def test_fmt_bytes():
    assert m._fmt_bytes(0) == "0B"
    assert m._fmt_bytes(512) == "512B"
    assert m._fmt_bytes(1024) == "1.00K"
    assert m._fmt_bytes(1024 * 1024) == "1.00M"
    assert m._fmt_bytes(1024 * 1024 * 1024) == "1.00G"
    assert m._fmt_bytes(int(1.5 * 1024 * 1024 * 1024)) == "1.50G"
    assert m._fmt_bytes(12.34 * 1024 * 1024 * 1024).endswith("G")
    assert " / " in m._fmt_bytes_pair(1024**3, 64 * 1024**3)


def test_bars():
    assert len(m._bar(50, 10)) == 10
    assert m._bar(0, 5) == "░░░░░"
    assert m._bar(100, 5) == "█████"
    dual = m._dual_bar(30, 70, 10)
    assert len(dual) == 10
    spark = m._spark([0, 50, 100], 5, scale=100)
    assert len(spark) == 5


def test_fmt_etime():
    assert m._fmt_etime(65) == "01:05"
    assert m._fmt_etime(3661) == "01:01:01"


def test_render_once_runs():
    text = m.render_once(interval_hint=0.15, scope=m.SCOPE_APP)
    assert "system_mem=" in text
    assert "_mem=" in text
    assert "G" in text or "M" in text
    assert "PID" in text
    assert "内存" in text

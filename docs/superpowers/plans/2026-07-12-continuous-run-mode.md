# Continuous Run Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add continuous (watermark refill) batch mode so long runs no longer preallocate huge worker lists, with optional success target and manual stop.

**Architecture:** Unify fixed-count and continuous modes on on-demand spawn. Keep only active + recent worker window in memory; expose counters via snapshot/WebUI.

**Tech Stack:** Python BatchRunner (`http_batch_service.py`), FastAPI WebUI, vanilla JS run console.

## Global Constraints

- Default remains `run_target_mode=count` for backward compatibility
- `failed` never includes `stopped`
- Continuous mode must not preallocate `register_count` workers
- Mode2 success still requires SSO convert completion
- Keep concurrent cap at existing `MAX_WORKERS`

---

### Task 1: Plan fields + on-demand runner counters

**Files:**
- Modify: `http_batch_service.py`
- Test: `tests/test_http_batch_service.py`

- [ ] Add `run_target_mode`, `target_success`, `continuous_max_runtime_min` to settings/plan
- [ ] Change BatchRunner to spawn workers on demand for both modes
- [ ] Snapshot includes `target_mode/started/phase/target_success`
- [ ] Tests for continuous stop conditions and no giant prealloc

### Task 2: WebUI run console controls

**Files:**
- Modify: `webui/templates/index.html`, `webui/static/app.js`, `webui_app.py` (if needed)
- Test: `tests/test_webui_app.py`

- [ ] Add mode toggle + target_success inputs
- [ ] Progress text for continuous mode
- [ ] Persist via existing settings API

### Task 3: Verify + commit

- [ ] pytest targeted suites
- [ ] commit

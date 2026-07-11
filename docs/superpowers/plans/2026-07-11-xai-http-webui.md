# xAI HTTP WebUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用本机 FastAPI Web 控制台（默认 `127.0.0.1:33843`）替换 curses TUI 作为日常主入口，完整对齐批量配置/启停/日志，并增加失败汇总与历史运行浏览。

**Architecture:** 从 `http_tui.py` 抽出无 UI 的 `http_batch_service.py`（Settings/RunPlan/BatchRunner/浏览器工具/失败分类/历史索引）；`webui_app.py` 只做 HTTP/SSE/页面；进程内单例批次；业务注册仍走现有 worker 子进程与 `xai_http_flow.py`。

**Tech Stack:** Python 3、FastAPI、Uvicorn、SSE、Jinja2Templates + 原生 JS、现有 unittest、`http_runs/` 文件系统存储。

## Global Constraints

- 仅绑定 `127.0.0.1`；默认端口 `33843`
- 同时只允许 1 个批次；重复开始返回 HTTP 409
- 不重写 Turnstile/注册协议主链
- 默认清理不杀日常 Chrome（只清 Playwright + 项目临时目录）
- local Turnstile 并发 cap 与 YYDS 跨进程限流必须继续生效
- API 响应中密钥脱敏；文件读取禁止路径逃逸
- 测试命令优先：`python3 -m unittest ...`
- 提交信息用英文祈使句；文档/UI 文案用中文

---

## File Map

| 文件 | 职责 |
|---|---|
| `http_batch_service.py` | 配置、plan、BatchRunner、浏览器健康/清理、失败分类、run 历史索引、单例 BatchService |
| `http_tui.py` | 薄 curses UI，从 service import 核心逻辑（过渡期） |
| `webui_app.py` | FastAPI 路由、SSE、模板挂载、CLI 启动 |
| `webui.sh` | 一键启动 |
| `webui/templates/index.html` | 单页控制台 |
| `webui/static/app.css` | 样式 |
| `webui/static/app.js` | 配置表单、SSE、进度/日志/历史 |
| `tests/test_http_batch_service.py` | service 单测 |
| `tests/test_webui_app.py` | API/SSE/路径安全单测 |
| `tests/test_http_tui_launcher.py` | 更新 import 后仍通过 |
| `requirements.txt` | 增加 fastapi/uvicorn/jinja2/httpx（TestClient） |
| `README.md` / `USAGE.md` | 主入口改为 WebUI |

---

### Task 1: 抽出 `http_batch_service` 并让 TUI 复用

**Files:**
- Create: `http_batch_service.py`
- Modify: `http_tui.py`（改为 re-export / 调用 service）
- Test: `tests/test_http_tui_launcher.py`（应尽量零改或只改 import）
- Test: `tests/test_http_batch_service.py`（新建最小烟雾）

**Interfaces:**
- Produces:
  - `TuiConfigError`
  - `@dataclass Settings`, `RunPlan`, `WorkerState`
  - `build_plan(settings: Settings) -> RunPlan`
  - `persist_settings(settings: Settings) -> None`
  - `refresh_settings_config(settings: Settings, *, reset_defaults: bool = True) -> None`
  - `settings_from_args(args: argparse.Namespace) -> Settings`
  - `describe_plan(plan: RunPlan, *, dry_run: bool = False) -> str`
  - `browser_health_status() -> Dict[str, int]`
  - `cleanup_browser_residues(...) -> Dict[str, int]`
  - `format_browser_health(...)`, `format_cleanup_result(...)`
  - `class BatchRunner`（保留 `start/stop/poll` 与现有属性）
  - 常量：`ROOT_DIR`, `DEFAULT_CONFIG_PATH`, `RUNS_DIR`, `MAX_LOCAL_TURNSTILE_WORKERS`, run mode / provider 常量

- [ ] **Step 1: 写失败测试确认 service 模块契约**

在 `tests/test_http_batch_service.py`：

```python
import unittest
from pathlib import Path
import tempfile
import json

import http_batch_service as svc


class HttpBatchServiceSmokeTests(unittest.TestCase):
    def test_build_plan_local_caps_workers(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = root / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "email_provider": "yyds",
                        "yyds_api_key": "k",
                        "turnstile_provider": "local",
                        "turnstile_headless": True,
                        "register_count": 10,
                        "concurrent_workers": 10,
                    }
                ),
                encoding="utf-8",
            )
            settings = svc.Settings(
                config_path=cfg,
                count=10,
                workers=10,
                output_dir=root / "creds",
                run_mode=svc.RUN_MODE_REGISTER_SSO,
                turnstile_provider="local",
                turnstile_headless=True,
                config=svc._read_config(cfg),
            )
            plan = svc.build_plan(settings)
            self.assertLessEqual(plan.workers, svc.MAX_LOCAL_TURNSTILE_WORKERS)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行确认失败（模块不存在）**

Run: `python3 -m unittest tests.test_http_batch_service -v`  
Expected: `ModuleNotFoundError: http_batch_service` 或 import 失败

- [ ] **Step 3: 实现抽取**

1. 将 `http_tui.py` 中所有**非 curses** 逻辑复制/搬到 `http_batch_service.py`：
   - 文件头常量、browser helpers、Settings/RunPlan/WorkerState
   - config 读写、`build_plan`、`BatchRunner` 全文
   - **不要**搬 `ProtocolTui`、curses 绘制、`main` 的 curses.wrapper
2. `http_batch_service.py` 顶部 docstring 标明：无 UI 批量服务层，供 WebUI 与 TUI 共用。
3. 改 `http_tui.py`：

```python
from http_batch_service import (  # noqa: F401
    MAX_LOCAL_TURNSTILE_WORKERS,
    # ... 导出 TUI 仍需要的符号
    BatchRunner,
    Settings,
    build_plan,
    browser_health_status,
    cleanup_browser_residues,
    # ...
)
# ProtocolTui + main 留在本文件
```

原则：现有 `tests.test_http_tui_launcher` 继续 `import http_tui as tui` 能工作（可在 `http_tui` re-export）。

- [ ] **Step 4: 跑测试**

```bash
python3 -m unittest tests.test_http_batch_service tests.test_http_tui_launcher -v
```

Expected: OK

- [ ] **Step 5: Commit**

```bash
git add http_batch_service.py http_tui.py tests/test_http_batch_service.py
git commit -m "refactor: extract HTTP batch service from curses TUI"
```

---

### Task 2: 失败分类与当前批次快照

**Files:**
- Modify: `http_batch_service.py`
- Modify: `tests/test_http_batch_service.py`

**Interfaces:**
- Produces:
  - `FAILURE_CATEGORIES: Tuple[str, ...]`
  - `classify_failure_text(text: str) -> str`
  - `BatchRunner.failure_counts: Dict[str, int]`（或通过 `snapshot()` 暴露）
  - `BatchRunner.snapshot() -> Dict[str, Any]`
  - `BatchService` 单例封装（本 task 可先实现 classify + snapshot；单例可在 Task 3）

- [ ] **Step 1: 写分类单测**

```python
class FailureClassifyTests(unittest.TestCase):
    def test_classify_yyds_429(self):
        self.assertEqual(
            svc.classify_failure_text('YYDS create HTTP 429: Too many account creation requests'),
            "yyds_rate_limit",
        )

    def test_classify_hard_block(self):
        self.assertEqual(
            svc.classify_failure_text("检测到拦截 | kind=cloudflare_hard_block"),
            "turnstile_hard_block",
        )

    def test_classify_browser_launch(self):
        self.assertEqual(
            svc.classify_failure_text("无法启动浏览器: Maximum number of clients reached"),
            "browser_launch_failed",
        )
```

- [ ] **Step 2: 跑测确认失败**

Run: `python3 -m unittest tests.FAKESECRET_e1f2g3h4i5j6k7l8m9n0 -v`  
Expected: FAIL attribute missing

- [ ] **Step 3: 实现 `classify_failure_text` 与 snapshot**

```python
FAILURE_CATEGORIES = (
    "yyds_rate_limit",
    "turnstile_hard_block",
    "turnstile_timeout",
    "browser_launch_failed",
    "sso_convert_failed",
    "register_failed",
    "unknown",
)

def classify_failure_text(text: str) -> str:
    t = (text or "").lower()
    if "429" in t and ("yyds" in t or "too many account creation" in t):
        return "yyds_rate_limit"
    if "hard_block" in t or "硬拦截" in (text or "") or "cloudflare_hard_block" in t:
        return "turnstile_hard_block"
    if "turnstile" in t and ("timeout" in t or "超时" in (text or "")):
        return "turnstile_timeout"
    if "无法启动浏览器" in (text or "") or "browser" in t and "launch" in t:
        return "browser_launch_failed"
    if "maximum number of clients" in t or "x11" in t and "client" in t:
        return "browser_launch_failed"
    if "sso" in t and ("转换失败" in (text or "") or "convert" in t or "退出码" in (text or "")):
        return "sso_convert_failed"
    if "注册" in (text or "") and ("失败" in (text or "") or "error" in t):
        return "register_failed"
    return "unknown"
```

在 `BatchRunner`：

- 初始化 `self.failure_counts = {k: 0 for k in FAILURE_CATEGORIES}`
- worker 失败时：用该 worker 日志尾部 / `last_log` 调用 `classify_failure_text` 并 +1
- 新增：

```python
def snapshot(self) -> Dict[str, Any]:
    return {
        "run_id": self.run_id,
        "done": self.done,
        "stopping": self.stopping,
        "count": len(self.workers),
        "completed": self.completed,
        "succeeded": self.succeeded,
        "failed": self.failed,
        "active": len(self.active),
        "failure_counts": dict(self.failure_counts),
        "warnings": list(self.plan.warnings),
        "workers": [
            {
                "index": w.index,
                "status": w.status,
                "last_log": w.last_log,
                "return_code": w.return_code,
            }
            for w in self.workers
        ],
        "run_dir": str(self.run_dir),
    }
```

批次结束时写 `run_dir / "summary.json"`（含 snapshot 关键字段）。

- [ ] **Step 4: 跑测**

```bash
python3 -m unittest tests.test_http_batch_service tests.test_http_tui_launcher -v
```

Expected: OK

- [ ] **Step 5: Commit**

```bash
git add http_batch_service.py tests/test_http_batch_service.py
git commit -m "feat: add batch failure classification and runner snapshot"
```

---

### Task 3: `BatchService` 单例（start/stop/current）

**Files:**
- Modify: `http_batch_service.py`
- Modify: `tests/test_http_batch_service.py`

**Interfaces:**
- Produces:

```python
class BatchService:
    def __init__(self) -> None: ...
    def get_settings(self) -> Settings: ...
    def update_settings_from_mapping(self, data: Dict[str, Any], *, persist: bool) -> Settings: ...
    def reload_settings(self) -> Settings: ...
    def start_run(self, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]: ...
    def stop_run(self) -> Dict[str, Any]: ...
    def current_snapshot(self) -> Optional[Dict[str, Any]]: ...
    def poll(self) -> None: ...  # 驱动 BatchRunner 内部推进
    def attach_log_listener(self, callback: Callable[[str], None]) -> None: ...
```

- 忙时 `start_run` 抛 `TuiConfigError` 或专用 `BatchBusyError(TuiConfigError)`，消息：`当前已有批次在运行`

- [ ] **Step 1: 单测**

```python
class BatchServiceSingletonTests(unittest.TestCase):
    def test_reject_second_start(self):
        with tempfile.TemporaryDirectory() as d:
            # 构造可用 config + mock BatchRunner.start 避免真子进程
            ...
            service = svc.BatchService(config_path=cfg, root_dir=root)
            with mock.patch.object(svc.BatchRunner, "start", lambda self: None), \
                 mock.patch.object(svc.BatchRunner, "snapshot", lambda self: {"run_id": self.run_id, "done": False}):
                service.start_run({"count": 1, "workers": 1})
                with self.assertRaises(svc.TuiConfigError):
                    service.start_run({"count": 1, "workers": 1})
```

（实现时用真实 `Settings`/`build_plan`，但 patch runner 子进程启动。）

- [ ] **Step 2: 跑测确认失败**

Expected: `BatchService` missing

- [ ] **Step 3: 实现 `BatchService`**

要点：

- 持有 `self._runner: Optional[BatchRunner] = None`
- `start_run`：`if self._runner and not self._runner.done: raise ...`
- 用 overrides 更新内存 settings → `build_plan` → `BatchRunner(plan)` → `start()`
- `stop_run`：调用 `runner.stop()`
- `poll`：调用现有 runner 的 tick/poll 方法（若目前靠 TUI 循环调内部逻辑，则把 `ProtocolTui` 里推进 runner 的那段抽成 `BatchRunner.tick()` / `BatchService.poll()`）
- 日志：包装 runner 的 log 回调或轮询 `runner.logs`，供 SSE 使用

**重要：** 打开现有 `BatchRunner` 与 `ProtocolTui.run` 循环，确保 WebUI 后台线程能每 100–200ms `poll()` 一次推进 spawn/回收，行为与 TUI 一致。

- [ ] **Step 4: 跑测**

```bash
python3 -m unittest tests.test_http_batch_service -v
```

Expected: OK

- [ ] **Step 5: Commit**

```bash
git add http_batch_service.py tests/test_http_batch_service.py
git commit -m "feat: add singleton BatchService for single-run control"
```

---

### Task 4: 历史 run 索引与安全读文件

**Files:**
- Modify: `http_batch_service.py`
- Modify: `tests/test_http_batch_service.py`

**Interfaces:**
- Produces:

```python
def list_runs(runs_dir: Path = RUNS_DIR, *, limit: int = 50) -> List[Dict[str, Any]]: ...
def get_run_detail(run_id: str, runs_dir: Path = RUNS_DIR) -> Dict[str, Any]: ...
def resolve_run_file(run_id: str, rel_path: str, runs_dir: Path = RUNS_DIR) -> Path: ...
```

- `resolve_run_file` 必须：`resolve()` 后 `relative_to(run_dir)`，失败抛 `TuiConfigError` 或 `ValueError`

- [ ] **Step 1: 单测路径逃逸**

```python
def test_resolve_run_file_blocks_escape(self):
    with tempfile.TemporaryDirectory() as d:
        runs = Path(d) / "http_runs"
        rid = "20260711_demo"
        (runs / rid).mkdir(parents=True)
        (runs / rid / "worker_001.log").write_text("ok", encoding="utf-8")
        path = svc.resolve_run_file(rid, "worker_001.log", runs_dir=runs)
        self.assertTrue(path.is_file())
        with self.assertRaises(Exception):
            svc.resolve_run_file(rid, "../secret.txt", runs_dir=runs)
```

- [ ] **Step 2: 跑测失败 → 实现 list/detail/resolve**

`list_runs`：按目录 mtime 倒序；字段含 `run_id`、`succeeded/failed`（若有 summary.json 则读，否则扫 accounts_*/worker 粗算）。

- [ ] **Step 3: 跑测通过并 commit**

```bash
python3 -m unittest tests.test_http_batch_service -v
git add http_batch_service.py tests/test_http_batch_service.py
git commit -m "feat: add run history listing and safe file resolve"
```

---

### Task 5: FastAPI 应用骨架（health/settings/browser）

**Files:**
- Create: `webui_app.py`
- Create: `tests/test_webui_app.py`
- Modify: `requirements.txt`（`fastapi`、`uvicorn`、`jinja2`、`httpx`）

**Interfaces:**
- Produces: `create_app(service: Optional[BatchService] = None) -> FastAPI`
- 默认 host/port 常量：`DEFAULT_WEBUI_HOST = "127.0.0.1"`，`DEFAULT_WEBUI_PORT = 33843`

- [ ] **Step 1: 安装依赖（若环境缺）**

```bash
python3 -m pip install fastapi uvicorn jinja2 httpx
```

并把版本钉到 `requirements.txt`（以 pip show 为准或兼容范围）。

- [ ] **Step 2: API 单测（settings + browser）**

```python
from fastapi.testclient import TestClient
import webui_app

class WebUIAppTests(unittest.TestCase):
    def test_health_and_settings_get(self):
        app = webui_app.create_app(service=...)  # 指向临时 config 的 BatchService
        client = TestClient(app)
        r = client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["host"], "127.0.0.1")
        s = client.get("/api/settings")
        self.assertEqual(s.status_code, 200)
        body = s.json()
        self.assertIn("count", body)
        # 密钥应脱敏
        if "turnstile_api_key" in body:
            self.assertNotIn("CAP-", str(body.get("turnstile_api_key")))
```

- [ ] **Step 3: 实现路由**

`webui_app.py` 最小集：

- `GET /api/health`
- `GET/PUT /api/settings`
- `POST /api/settings/reload`
- `GET /api/browser/health`
- `POST /api/browser/cleanup`
- `GET /` 先返回简单 HTML `WebUI OK`（完整页面 Task 8）

settings PUT：写盘；响应脱敏。

- [ ] **Step 4: 跑测**

```bash
python3 -m unittest tests.test_webui_app -v
```

- [ ] **Step 5: Commit**

```bash
git add webui_app.py tests/test_webui_app.py requirements.txt
git commit -m "feat: add FastAPI webui skeleton for settings and browser tools"
```

---

### Task 6: Runs API + SSE

**Files:**
- Modify: `webui_app.py`
- Modify: `http_batch_service.py`（如需事件队列）
- Modify: `tests/test_webui_app.py`

**Interfaces:**
- `POST /api/runs` → 202 `{run_id,...}` 或 409
- `POST /api/runs/current/stop`
- `GET /api/runs/current`
- `GET /api/runs/current/events` text/event-stream
- `GET /api/runs`、`GET /api/runs/{run_id}`、logs/files

- [ ] **Step 1: 单测 409 与 current**

```python
def test_start_run_conflict(self):
    # mock service.start_run 第二次抛 TuiConfigError busy
    ...
    r1 = client.post("/api/runs", json={"count": 1, "workers": 1})
    self.assertIn(r1.status_code, {200, 202})
    r2 = client.post("/api/runs", json={"count": 1, "workers": 1})
    self.assertEqual(r2.status_code, 409)
```

- [ ] **Step 2: 实现 runs 路由**

后台：`threading.Thread` 循环 `service.poll()` 直到 `done`（daemon=True）。

SSE：

```python
async def event_stream():
    yield format_sse("snapshot", service.current_snapshot())
    # 然后读 service 事件队列，超时也发 ping/snapshot
```

事件格式：`event: snapshot\ndata: {...}\n\n`

- [ ] **Step 3: 历史 API 单测 + 实现**

`GET /api/runs` 返回 list；`GET /api/runs/{id}/files?path=worker_001.log` 受控读取。

- [ ] **Step 4: 跑测并 commit**

```bash
python3 -m unittest tests.test_webui_app tests.test_http_batch_service -v
git add webui_app.py http_batch_service.py tests/test_webui_app.py
git commit -m "feat: add run control APIs and SSE event stream"
```

---

### Task 7: Web 页面（完整对齐 TUI + 增强）

**Files:**
- Create: `webui/templates/index.html`
- Create: `webui/static/app.css`
- Create: `webui/static/app.js`
- Modify: `webui_app.py`（StaticFiles + Jinja2Templates）

**UI 要求（务实控制台，非营销页）：**

- 配置表单字段对齐 TUI：模式、邮箱展示、Turnstile provider/headless、数量、并发、代理模式、输出目录、SSO 重试/冷却
- 按钮：重载、保存、开始、停止、浏览器状态、清理残留
- 进度卡：成功/失败/活动 + worker 表
- 失败汇总卡：各类计数
- 日志窗：EventSource 订阅 `/api/runs/current/events`
- 历史侧栏/下区：拉 `/api/runs`，点击看详情

- [ ] **Step 1: 挂载静态资源并渲染模板**

```python
app.mount("/static", StaticFiles(directory=str(ROOT / "webui" / "static")), name="static")
templates = Jinja2Templates(directory=str(ROOT / "webui" / "templates"))

@app.get("/")
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "port": 33843})
```

- [ ] **Step 2: 实现 `app.js` 核心流**

```javascript
async function loadSettings() {
  const r = await fetch("/api/settings");
  const data = await r.json();
  // fill form
}

async function startRun() {
  const body = readForm();
  const r = await fetch("/api/runs", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
  if (r.status === 409) { alert("当前已有批次在运行"); return; }
  connectEvents();
}

function connectEvents() {
  const es = new EventSource("/api/runs/current/events");
  es.addEventListener("snapshot", (e) => renderSnapshot(JSON.parse(e.data)));
  es.addEventListener("log", (e) => appendLog(JSON.parse(e.data)));
  es.addEventListener("done", (e) => { renderSnapshot(JSON.parse(e.data)); es.close(); });
}
```

- [ ] **Step 3: 手工冒烟（实现者执行）**

```bash
python3 webui_app.py --host 127.0.0.1 --port 33843
curl -s http://127.0.0.1:33843/api/health
curl -s http://127.0.0.1:33843/ | head
```

Expected: health JSON；HTML 含配置/日志区域

- [ ] **Step 4: Commit**

```bash
git add webui webui_app.py
git commit -m "feat: add localhost web console UI for batch registration"
```

---

### Task 8: 启动脚本、文档主入口、回归

**Files:**
- Create: `webui.sh`
- Modify: `README.md`、`USAGE.md`（主推 WebUI；TUI 标为过渡）
- Modify: `http_tui.py` 帮助文案可提示 WebUI 地址（可选一行）

- [ ] **Step 1: `webui.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
HOST="${XAI_WEBUI_HOST:-127.0.0.1}"
PORT="${XAI_WEBUI_PORT:-33843}"
exec python3 webui_app.py --host "$HOST" --port "$PORT" "$@"
```

`chmod +x webui.sh`

- [ ] **Step 2: CLI**

`webui_app.py`：

```python
parser.add_argument("--host", default=os.environ.get("XAI_WEBUI_HOST", "127.0.0.1"))
parser.add_argument("--port", type=int, default=int(os.environ.get("XAI_WEBUI_PORT", "33843")))
# uvicorn.run(app, host=host, port=port, log_level="info")
```

拒绝把默认 host 做成 `0.0.0.0`。

- [ ] **Step 3: 全量相关测试**

```bash
python3 -m unittest tests.test_http_batch_service tests.test_webui_app tests.test_http_tui_launcher tests.test_xai_http_flow -v
```

Expected: OK

- [ ] **Step 4: 文档**

README/USAGE 增加：

- 启动：`./webui.sh` → `http://127.0.0.1:33843`
- 说明：仅本机、单批次、local 并发 cap、清理残留入口
- TUI：`./tui.sh` 过渡保留

- [ ] **Step 5: Commit**

```bash
git add webui.sh README.md USAGE.md webui_app.py
git commit -m "docs: make localhost WebUI the primary batch console entry"
```

---

## Spec Coverage Checklist

| 规格项 | Task |
|---|---|
| 127.0.0.1:33843 | 5, 8 |
| 对齐 TUI 配置/启停/日志 | 1, 3, 6, 7 |
| 失败汇总 | 2, 6, 7 |
| 历史 + 结果浏览 | 4, 6, 7 |
| 单批次 409 | 3, 6 |
| 浏览器状态/清理 | 1, 5, 7 |
| 复用 BatchRunner / 不重写协议 | 1, 全程 |
| 密钥脱敏 / 路径安全 | 4, 5, 6 |
| TUI 过渡、WebUI 主入口 | 1, 8 |
| 测试 | 每 task |

## Placeholder / Consistency Review

- 无 TBD；符号名统一 `BatchService` / `classify_failure_text` / `snapshot`
- `TuiConfigError` 名称保留以减少 TUI 测试震荡；Web 层映射 400/409
- 若 `BatchRunner` 当前缺少独立 `tick/poll`，在 Task 3 从 `ProtocolTui` 抽出，禁止 WebUI 复制一份调度循环逻辑

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-11-xai-http-webui.md`.

**Two execution options:**

1. **Subagent-Driven（推荐）** — 每任务新子代理，任务间审查，迭代快  
2. **Inline Execution** — 本会话按 `executing-plans` 连续执行并设检查点  

Which approach?

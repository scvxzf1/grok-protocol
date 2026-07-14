# WebUI Config Center Help Tips Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add short hover/tap help tips (`?`) beside every config-center field on `/config` without changing APIs or the run page.

**Architecture:** Hard-code tip text in `config.html` as `button.help-tip[data-tip]`. Style bubbles in `app.css` with `::after`. Add minimal mobile toggle logic in `config.js`. Leave save/reload logic untouched.

**Tech Stack:** Jinja HTML, plain CSS, plain JS, FastAPI static files.

**Spec:** `docs/superpowers/specs/2026-07-11-webui-config-help-tips-design.md`

## Global Constraints

- Only touch config-center frontend: `webui/templates/config.html`, `webui/static/app.css`, `webui/static/config.js`
- Do not change `webui_app.py`, run page, or config read/write APIs
- Tip copy is one short Chinese sentence (about 10-25 chars sense-length), matching design section 7
- `help-tip` must be `button type="button"`
- No tips on proxy-pool textarea section or top action buttons
- Keep existing workspace field `local_turnstile_max_workers` and give it a tip
- Do not revert unrelated uncommitted worktree changes

---

## File Map

| File | Responsibility |
|---|---|
| `webui/static/app.css` | `.field-title` / `.help-tip` bubble styles |
| `webui/templates/config.html` | Attach `?` + `data-tip` to every config field |
| `webui/static/config.js` | Mobile click toggle, outside click close, only one open |
| `tests/test_webui_app.py` | Assert `/config` HTML includes help-tip markup |

---

### Task 1: CSS hover bubble styles

**Files:**
- Modify: `webui/static/app.css`

**Interfaces:**
- Produces: `.field-title`, `.help-tip`, `.help-tip.is-open`; bubble text from `attr(data-tip)`

- [ ] **Step 1: Append/merge styles into `app.css`**

Append these rules. If `label.check` already exists, merge instead of duplicating:

```css
.field-title {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--muted);
}

.help-tip {
  position: relative;
  width: 16px;
  height: 16px;
  min-width: 16px;
  padding: 0;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: #121821;
  color: var(--muted);
  font-size: 11px;
  line-height: 1;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: help;
}

.help-tip::after {
  content: attr(data-tip);
  position: absolute;
  left: 50%;
  bottom: calc(100% + 8px);
  transform: translateX(-50%);
  width: max-content;
  max-width: 220px;
  padding: 6px 8px;
  border-radius: 6px;
  border: 1px solid var(--line);
  background: #0c1015;
  color: var(--text);
  font-size: 12px;
  line-height: 1.35;
  white-space: normal;
  text-align: left;
  box-shadow: 0 6px 18px rgba(0, 0, 0, 0.35);
  opacity: 0;
  pointer-events: none;
  visibility: hidden;
  transition: opacity 0.12s ease;
  z-index: 20;
}

.help-tip:hover::after,
.help-tip:focus-visible::after,
.help-tip.is-open::after {
  opacity: 1;
  visibility: visible;
}

label.check .field-title {
  margin: 0;
}
```

- [ ] **Step 2: Static check**

Run: `rg -n "help-tip|field-title" webui/static/app.css`

Expected: matches for `.help-tip`, `.field-title`, `attr(data-tip)`.

- [ ] **Step 3: Commit**

```bash
git add webui/static/app.css
git commit -m "style: add config help-tip bubble styles"
```

---

### Task 2: Attach tips to all config fields in HTML

**Files:**
- Modify: `webui/templates/config.html`

**Interfaces:**
- Consumes: Task 1 CSS classes
- Produces: exactly 19 `button.help-tip[data-tip]` nodes

- [ ] **Step 1: Rewrite each field label title**

Rules:
- Keep all `name` / `form` / `flag` / secret-row markup
- Keep `local_turnstile_max_workers`
- Remove the extra always-visible `p.muted` under local Turnstile max workers (tip replaces it)
- Do not add tips in proxy-pool textarea section

Required `data-tip` map:

| field | data-tip |
|---|---|
| email_provider | 选临时邮箱服务商，决定用哪套邮箱配置 |
| yyds_api_base | YYDS 接口地址，一般不用改默认值 |
| yyds_api_key | YYDS 密钥；空=未配置，清空保存=删除 |
| yyds_jwt | YYDS 登录令牌；可与 API Key 二选一 |
| turnstile_provider | 验证码求解方式：本地浏览器或第三方 |
| turnstile_api_key | 第三方求解服务的 Key；local 可留空 |
| turnstile_headless | 本地求解时尽量不弹窗（需 Xvfb 环境） |
| local_turnstile_max_workers | 仅 local 生效；总并发仍受运行台与 32 上限约束 |
| cloudflare_api_base | Cloudflare 临时邮箱 Worker 的 API 根地址 |
| cloudflare_api_key | 匿名模式留空；admin 模式填管理密码 |
| duckmail_api_key | DuckMail 服务密钥；选 duckmail 时必填 |
| ms_mail_file | Outlook 四段账号文件路径（msgraph 用） |
| proxy_mode | auto/直连/代理池/关闭，控制出口怎么走 |
| proxy | 单个代理地址，格式如 http://user:pass@host:port |
| proxy_file | 代理列表文件路径，默认 fixtures/proxies.txt |
| local_proxy_port | 本机无认证转发端口，浏览器流常用 |
| proxy_random | 从代理池随机挑，而不是固定顺序 |
| proxy_rotate_session | 尽量换会话出口，降低同 IP 连打风险 |
| xai_oauth_output_dir | SSO/凭证 JSON 写出目录 |

Normal field template:

```html
<label>
  <span class="field-title">
    邮箱源
    <button type="button" class="help-tip" aria-label="说明" data-tip="选临时邮箱服务商，决定用哪套邮箱配置">?</button>
  </span>
  <select name="email_provider">...</select>
</label>
```

Checkbox template:

```html
<label class="check">
  <input type="checkbox" name="turnstile_headless" />
  <span class="field-title">
    Turnstile 无头
    <button type="button" class="help-tip" aria-label="说明" data-tip="本地求解时尽量不弹窗（需 Xvfb 环境）">?</button>
  </span>
</label>
```

- [ ] **Step 2: Count tips**

Run:

```bash
python3 -c "from pathlib import Path; import re; html=Path(\"webui/templates/config.html\").read_text(encoding=\"utf-8\"); tips=re.findall(r\"class=\\\"help-tip\\\"[^>]*data-tip=\\\"([^\\\"]+)\\\"\", html); names=[n for n in re.findall(r\"name=\\\"([a-z0-9_]+)\\\"\", html) if n!=\"viewport\"]; expected={\"email_provider\",\"yyds_api_base\",\"yyds_api_key\",\"yyds_jwt\",\"turnstile_provider\",\"turnstile_api_key\",\"turnstile_headless\",\"local_turnstile_max_workers\",\"cloudflare_api_base\",\"cloudflare_api_key\",\"duckmail_api_key\",\"ms_mail_file\",\"proxy_mode\",\"proxy\",\"proxy_file\",\"local_proxy_port\",\"proxy_random\",\"proxy_rotate_session\",\"xai_oauth_output_dir\"}; print(len(tips), sorted(expected-set(names))); assert len(tips)==19 and not (expected-set(names)); print(\"OK\")"
```

Expected: `19 []` then `OK`

- [ ] **Step 3: Commit**

```bash
git add webui/templates/config.html
git commit -m "feat: add help-tip buttons to config center fields"
```

---

### Task 3: Mobile toggle + page assertion test

**Files:**
- Modify: `webui/static/config.js`
- Modify: `tests/test_webui_app.py`
- Test: `tests/test_webui_app.py`

**Interfaces:**
- Consumes: `.help-tip` and `.is-open` in DOM
- Produces: click toggle, outside click close, only one open bubble

- [ ] **Step 1: Append tip interaction at end of `config.js`**

Do not change `collectFields` or save handlers. Append:

```js
function setupHelpTips() {
  const tips = Array.from(document.querySelectorAll(".help-tip"));
  if (!tips.length) return;

  const closeAll = (except = null) => {
    tips.forEach((btn) => {
      if (btn !== except) btn.classList.remove("is-open");
    });
  };

  tips.forEach((btn) => {
    btn.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      const willOpen = !btn.classList.contains("is-open");
      closeAll();
      if (willOpen) btn.classList.add("is-open");
    });
  });

  document.addEventListener("click", () => closeAll());
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeAll();
  });
}

setupHelpTips();
```

- [ ] **Step 2: Add HTML assertion test**

Read `tests/test_webui_app.py` first and reuse its existing fake service / TestClient style. Add:

```python
def test_config_page_includes_help_tips():
    # reuse existing fake service construction from this file
    app = webui_app.create_app(service=service)
    client = TestClient(app)
    resp = client.get("/config")
    assert resp.status_code == 200
    html = resp.text
    assert "class=\"help-tip\"" in html
    assert "data-tip=\"选临时邮箱服务商，决定用哪套邮箱配置\"" in html
    assert "data-tip=\"仅 local 生效；总并发仍受运行台与 32 上限约束\"" in html
    assert html.count("class=\"help-tip\"") >= 19
```

Replace `service=` with the real construction used in that file.

- [ ] **Step 3: Run tests**

Run: `python -m pytest tests/test_webui_app.py -q --tb=short`

Fallback: `python -m unittest tests.test_webui_app -v`

Expected: PASS

- [ ] **Step 4: Optional manual smoke**

```bash
./webui.sh
# open /config: hover, tap, save/reload
```

- [ ] **Step 5: Commit**

```bash
git add webui/static/config.js tests/test_webui_app.py
git commit -m "feat: enable mobile toggle for config help tips"
```

---

## Self-Review

1. **Spec coverage**
   - Hover/focus bubble -> Task 1
   - Full field copy list -> Task 2
   - Mobile tap / outside close -> Task 3
   - No API/run-page changes -> Global Constraints
   - Verification -> tip count script + webui test

2. **Placeholder scan**
   - No TBD/TODO; selectors and copy are concrete

3. **Consistency**
   - Classes: `field-title` / `help-tip` / `is-open` / `data-tip`
   - Tip count target: 19
   - Keep `local_turnstile_max_workers`

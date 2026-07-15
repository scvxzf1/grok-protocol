# WebUI 配置中心字段 `?` 悬停说明 设计

日期：2026-07-11  
范围：仅配置中心 `/config` 前端展示  
状态：已确认

## 1. 背景与目标

一句话：配置中心字段只有标题，缺少“这是干什么 / 什么时候填”的即时说明。

当前 `/config` 表单字段多、密钥/代理/邮箱源混排，用户需要反复翻 `README.md` / `USAGE.md`。  
目标是在**每个配置项标题旁**增加 `?` 悬停（手机可点）提示，文案控制在超短一句。

## 2. 非目标

- 不改运行台 `/` 的运行参数说明
- 不改配置读写 API、`config.json` 结构、业务逻辑
- 不做后端 `field_help` 下发
- 不把说明做成字段下方常显长文案（用户已明确选悬停）
- 代理池大文本框上方已有段落说明，不再重复加 `?`

## 3. 已确认决策

| 项 | 决策 |
|---|---|
| 页面范围 | 只改配置中心 |
| 展示方式 | 标题旁 `?` 悬停提示 |
| 文案长度 | 超短一句（约 10–25 字） |
| 实现方案 | 纯 HTML 写死文案 + 轻量 CSS 气泡 + 可选轻量 JS（移动端点按） |

## 4. 方案选择

采用 **A. 纯 HTML + CSS 悬停气泡**。

| 方案 | 结论 |
|---|---|
| A. HTML 写死 + CSS | **采用**：改动最小、零 API、好维护 |
| B. `config.js` 字典映射 | 备选：字段集中管理，但多一层脚本 |
| C. 后端下发 help | 不采用：对本需求过重 |

## 5. 交互设计

### 5.1 桌面

- 鼠标悬停 `?` 显示气泡
- 键盘聚焦 `?` 时也显示（无障碍）

### 5.2 移动端

- 点 `?` 切换气泡开/关
- 点页面其他区域关闭当前气泡
- 同时最多显示一个气泡

### 5.3 视觉

- `?`：小号圆形按钮，灰色边框，不抢主按钮视觉
- 气泡：深色底、浅色字、最大宽度约 `220px`
- 优先显示在 `?` 上方；避免遮挡输入框主体

## 6. HTML 结构

```html
<label>
  <span class="field-title">
    邮箱源
    <button type="button" class="help-tip" aria-label="说明" data-tip="选临时邮箱服务商，决定用哪套邮箱配置">?</button>
  </span>
  <select name="email_provider">...</select>
</label>
```

checkbox 示例：

```html
<label class="check">
  <input type="checkbox" name="turnstile_headless" />
  <span class="field-title">
    Turnstile 无头
    <button type="button" class="help-tip" aria-label="说明" data-tip="本地求解时尽量不弹窗（需 Xvfb 环境）">?</button>
  </span>
</label>
```

约束：

- `help-tip` 必须是 `button type="button"`，避免误提交表单
- 文案放在 `data-tip`，CSS 用 `attr(data-tip)` 或 `::after` 展示
- 现有 `name` / 保存逻辑 / `flag` 状态文案保持不变

## 7. 字段与文案清单

覆盖配置中心当前全部可编辑配置项（含工作区已有的本地 Turnstile 并发上限字段）。

| 字段 | 悬停说明 |
|---|---|
| 邮箱源 | 选临时邮箱服务商，决定用哪套邮箱配置 |
| YYDS API Base | YYDS 接口地址，一般不用改默认值 |
| YYDS API Key | YYDS 密钥；空=未配置，清空保存=删除 |
| YYDS JWT | YYDS 登录令牌；可与 API Key 二选一 |
| Turnstile 提供商 | 验证码求解方式：本地浏览器或第三方 |
| Turnstile API Key | 第三方求解服务的 Key；local 可留空 |
| Turnstile 无头 | 本地求解时尽量不弹窗（需 Xvfb 环境） |
| 本地 Turnstile 并发上限 | 仅 local 生效；总并发仍受运行台与 32 上限约束 |
| Cloudflare API Base | Cloudflare 临时邮箱 Worker 的 API 根地址 |
| Cloudflare API Key | 匿名模式留空；admin 模式填管理密码 |
| DuckMail API Key | DuckMail 服务密钥；选 duckmail 时必填 |
| MS 邮箱文件 | Outlook 四段账号文件路径（msgraph 用） |
| 代理模式 | auto/直连/代理池/关闭，控制出口怎么走 |
| 直连代理 URL | 单个代理地址，格式如 http://user:pass@host:port |
| 代理池文件 | 代理列表文件路径，默认 fixtures/proxies.txt |
| 本地转发端口 | 本机无认证转发端口，浏览器流常用 |
| 代理池随机 | 从代理池随机挑，而不是固定顺序 |
| 轮换 session | 尽量换会话出口，降低同 IP 连打风险 |
| OAuth 输出目录 | SSO/凭证 JSON 写出目录 |

说明：

- 若实现时发现页面新增了配置字段，按同样规则补一条超短 tip
- 顶部操作按钮（重载/保存/测试）不加 tip
- 代理池内容 textarea 区沿用现有段落说明，不加 `?`

## 8. 文件改动

| 文件 | 改动 |
|---|---|
| `webui/templates/config.html` | 每个配置项标题改为 `field-title` + `help-tip` |
| `webui/static/app.css` | 增加 `field-title` / `help-tip` / 气泡样式；checkbox 行对齐微调 |
| `webui/static/config.js` | 可选轻量交互：点击切换、点外部关闭、同时只开一个 |

不改：

- `webui_app.py`
- `http_batch_service.py` 配置读写
- `webui/templates/index.html` / `app.js`

## 9. 验收标准

- [ ] 配置中心每个配置项标题旁都有 `?`
- [ ] 桌面悬停 / 键盘聚焦可看到对应超短说明
- [ ] 移动端点 `?` 可开关；点其他处关闭
- [ ] 文案与第 7 节清单一致（允许极小措辞润色，不改语义）
- [ ] 保存、重载、仅保存代理池、随机测试 5 条功能正常
- [ ] 两列表单布局不乱，气泡不长期挡住输入框

## 10. 风险与处理

| 风险 | 级别 | 处理 |
|---|---|---|
| 气泡遮挡输入 | Low | 限制宽度；优先显示在 `?` 上方 |
| checkbox 对齐偏移 | Low | `field-title` 与勾选框同行 flex |
| 纯 CSS 在部分移动浏览器不友好 | Low | 用极少量 JS 做 tap toggle |
| 与未提交的其它 config 改动叠加 | Medium | 实现时基于当前工作区字段合并，不回滚他人改动 |

## 11. 测试建议

- 手动打开 `/config`，逐字段悬停检查 tip 文案
- 窄屏/手机宽度下点按 `?` 开关
- 点「重载」「保存配置」确认表单读写不受 `button.help-tip` 影响
- 若有 WebUI 静态相关测试，保持通过；本需求以 UI 文案为主，可不强求单测覆盖 tip 文本

## 12. 实现顺序（设计层）

1. CSS：先落 `help-tip` 视觉
2. HTML：按字段清单挂 `data-tip`
3. JS：补移动端点按行为
4. 手动验收清单打勾

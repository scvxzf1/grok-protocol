# Grok Register — 使用指南（人类 / AI 共用）


## WebUI 主入口（推荐）

```bash
./webui.sh
# 浏览器打开 http://127.0.0.1:33843
```

- 仅本机绑定 `127.0.0.1`，默认端口 `33843`（可用 `XAI_WEBUI_PORT` 覆盖）
- 同时只跑 1 个批次；含失败汇总、历史 run、浏览器残留清理
- 旧 TUI（`./tui.sh`）仍保留作过渡

面向：**本地研究、联调、个人测试**。请遵守目标站 ToS 与当地法律。  
本文同时给人和 AI agent 用：先读「系统图」，再按「最短路径」执行，出错查「故障表」。

---

## 0. 一分钟系统图

```text
                    ┌─────────────────────┐
                    │  邮箱来源             │
                    │  YYDS / Cloudflare   │
                    │  / Outlook Graph     │
                    └──────────┬──────────┘
                               │ OTP
┌──────────────┐    ┌──────────▼──────────┐    ┌──────────────────┐
│ 出口代理      │───▶│  xAI 注册 / 登录      │───▶│ SSO cookie       │
│ (可选)        │    │  accounts.x.ai       │    │ email----pw----sso│
└──────────────┘    └──────────┬──────────┘    └────────┬─────────┘
        ▲                      │ turnstile               │
        │                      │                         ▼
┌───────┴────────┐             │               ┌──────────────────┐
│ Turnstile 来源  │◀────────────┘               │ OAuth credential │
│ captcha API 或  │                            │ xai-*.json       │
│ 浏览器 capture  │                            │ (CLIProxyAPI)    │
└────────────────┘                            └──────────────────┘
```

两条运行形态：

| 形态 | 入口 | 浏览器 | 用途 |
| --- | --- | --- | --- |
| **GUI / CLI 浏览器流** | `python grok_register_ttk.py` / `… cli` | 需要 Chrome | 传统页面自动化批量注册 |
| **HTTP 无浏览器流** | `python grok_register_ttk.py http …` | 默认不需要 | 协议级注册 + OAuth 凭证（推荐分享后主路径） |

---

## 1. 分享包里应有什么 / 不该有什么

### 可以分享

- 源码：`*.py`、`tests/`、`assets/`
- `config.example.json`、`requirements.txt`、`LICENSE`
- `README.md`、`USAGE.md`、脱敏协议说明
- `need/*.example.txt`、`need/README.md`

### 禁止分享（本机已清空或 gitignore）

| 类型 | 示例 |
| --- | --- |
| 密钥配置 | `config.json` 内 API key / 代理账密 |
| 账号产物 | `accounts_*.txt`、`xai_credentials/`、`mail_credentials.txt` |
| 代理池真值 | `proxies.txt`、真实 `need/*` 池文件 |
| 抓包 | `*.json` Recorder、含 cookie 的 HAR |
| 求解密钥 | YesCaptcha / CapSolver / 2Captcha API key |

**分享前自检：**

```bash
# 不应出现真实 key / 邮箱 refresh_token / sso JWT
rg -n "M\\.C|eyJ|AC-|yescaptcha|gate\\.|password|refresh_token" --glob '!USAGE.md' --glob '!README.md' .
```

---

## 2. 环境准备

### 依赖

- Python 3.9+
- 网络可访问 `accounts.x.ai` / `auth.x.ai`
- **浏览器流**另需 Chrome / Chromium + `DrissionPage`
- **HTTP 流**需要 `curl_cffi`（见 `requirements.txt`）

### 安装

```bash
git clone <your-fork-or-path>
cd grok-register
pip install -r requirements.txt
cp config.example.json config.json
```

编辑 `config.json`（**不要提交**）。

---

## 3. 配置项速查

文件：`config.json`（从 `config.example.json` 复制）

### 3.1 邮箱

| 字段 | 说明 |
| --- | --- |
| `email_provider` | `cloudflare` \| `yyds` \| `msgraph`（HTTP 注册也认这些） |
| `cloudflare_api_base` | 临时邮箱 Worker API 根 |
| `cloudflare_api_key` | 匿名模式留空；admin 模式填 `ADMIN_PASSWORD` |
| `cloudflare_auth_mode` | `none` / `x-admin-auth` / `bearer` / … |
| `defaultDomains` | CF 收信域名 |
| `yyds_api_key` 或 `yyds_jwt` | YYDS 临时邮箱 |
| `yyds_api_base` | 默认 `https://maliapi.215.im/v1` |
| `ms_mail_file` | Outlook 四段文件路径（可选） |

### 3.2 代理

| 字段 | 说明 |
| --- | --- |
| `proxy` | 单条代理；支持 `host:port:user:pass` |
| `proxy_file` | 代理池文件，默认 `proxies.txt` |
| `proxy_random` | 是否随机选代理 |
| `proxy_parent` | 父代理，如本地 Clash `http://127.0.0.1:7890`（先 CONNECT 再上认证代理） |
| `local_proxy_port` | 本机无认证转发端口（浏览器流常用） |

### 3.3 Turnstile（HTTP 流）

| 字段 / 环境变量 | 说明 |
| --- | --- |
| `turnstile_provider` | `yescaptcha` \| `capsolver` \| `2captcha` |
| `turnstile_api_key` | 求解服务 key |
| `local_turnstile_max_workers` | 本地浏览器 Turnstile 并发上限（默认 3，范围 1~6666；仅 `turnstile_provider=local` 生效） |
| `XAI_TURNSTILE_PROVIDER` | 环境变量覆盖 provider |
| `XAI_TURNSTILE_API_KEY` | 环境变量覆盖 key |
| `CAPSOLVER_API_KEY` | `turnstile_provider=capsolver` 时的专用 key |
| `TWOCAPTCHA_API_KEY` / `TWO_CAPTCHA_API_KEY` | `turnstile_provider=2captcha` 时的专用 key |
| `YESCAPTCHA_API_KEY` | `turnstile_provider=yescaptcha` 时的专用 key |

也可用 CLI：`--turnstile-provider` / `--turnstile-api-key` / `--turnstile-token-file`。

CapSolver 使用官方 `createTask` / `getTaskResult` 流程，Turnstile 任务固定为 `AntiTurnstileTaskProxyLess`。程序会在可用时转发页面的 `data-action`、`data-cdata`；根据 CapSolver 当前文档，传入的 HTTP 上游代理不会被加入 CapSolver 任务。

### 3.4 其它

| 字段 | 说明 |
| --- | --- |
| `register_count` | GUI/CLI 浏览器批量目标数 |
| `enable_nsfw` | 注册后尝试开 NSFW |
| `xai_oauth_auto` | 浏览器流是否自动跑 OAuth |
| `xai_oauth_output_dir` | OAuth JSON 输出目录 |
| `grok2api_*` | 可选写入 grok2api 本地/远端池 |

---

## 4. 最短路径（推荐：无浏览器 HTTP）

### 4.1 前置清单

1. 可用邮箱：`email_provider=yyds|cloudflare` **或** Outlook 四段文件  
2. Turnstile：captcha API key **或** 接受浏览器 `turnstile-capture`  
3. 代理：2Captcha / YesCaptcha 会尽量使用指定上游；CapSolver Turnstile 按官方任务类型固定为 **proxyless**，与注册 HTTP 流的出口可能不同

### 4.2 探测邮箱（不触达 xAI 注册）

```bash
python grok_register_ttk.py http mail-probe --mail-config config.json
# 或
python grok_register_ttk.py http mail-probe --mail-file need/my_outlook.txt
```

期望：`[+] mail-probe ok email=…`

### 4.3 一键注册 + OAuth 凭证

```bash
python grok_register_ttk.py http register \
  --proxy "http://127.0.0.1:7890" \
  --mail-config config.json \
  --turnstile-provider yescaptcha \
  --turnstile-api-key "$YESCAPTCHA_KEY" \
  --output-dir xai_credentials \
  --accounts-output accounts_http_out.txt
```

带认证住宅代理 + 父代理：

```bash
python grok_register_ttk.py http register \
  --proxy-file proxies.txt --proxy-random \
  --proxy-parent http://127.0.0.1:7890 \
  --mail-config config.json \
  --turnstile-provider capsolver \
  --turnstile-api-key "$CAPSOLVER_KEY" \
  --output-dir xai_credentials
```

### HTTP TUI 启动器

`http_tui.sh` 始终调用 `grok_register_ttk.py http register`，不会进入 GUI、`cli` 或 `turnstile-capture` 的 Chrome 路径。它使用标准库 `curses` 提供全屏配置页和运行页：左侧显示总体进度、成功/失败数和每个 worker 状态；右侧实时显示协议子进程的后端日志。它会读取 `register_count` 与 `concurrent_workers` 作为默认值，但数量和并发的 TUI 输入仅覆盖本次运行。

```bash
chmod +x http_tui.sh
./http_tui.sh
```

无交互预览示例：

```bash
./http_tui.sh --config config.json --count 3 --workers 2 --dry-run
```

每个任务都有独立的账号输出和日志，结束后会在项目根目录汇总成功账号到 `accounts_http_*.txt`；运行日志位于 `http_runs/`。运行中按 `q` 可停止任务，`↑` / `↓` 滚动右侧日志，`l` 回到日志末尾；建议终端至少为 80x20。

### 4.4 成功日志顺序（验收标准）

```text
[HTTP] 已就绪邮箱 …
[HTTP] 注册页已建立会话 | turnstileSitekey=yes …
[HTTP] 已请求 xAI 邮箱验证码 …
[HTTP] 已收到 xAI 邮箱验证码 … code=XXX***
[HTTP] 邮箱验证码已通过校验 …
[HTTP] 请求 Turnstile 求解 …   # 或使用 token 文件时跳过
[HTTP] Turnstile 求解完成 …
[HTTP] 跟随 cookie setter | host=auth.grokipedia.com …
[HTTP] 注册成功 …
[HTTP] OAuth 凭证已保存 …
[+] 注册与凭证获取完成: …
```

### 4.5 产物格式

**账号行** `accounts_*.txt`：

```text
email----password----sso
```

**OAuth JSON** `xai_credentials/xai-<email>.json`（CLIProxyAPI 兼容字段）：

- `type` / `email` / `access_token` / `refresh_token` / `id_token` / `expired` / …

两者均含敏感信息，仅本地保存。

### 4.6 仅已有 SSO → 凭证

```bash
# sso.txt 内一行 sso cookie 值
python grok_register_ttk.py http credential \
  --sso-file sso.txt \
  --output-dir xai_credentials
```

密码登录（需 Turnstile）：

```bash
python grok_register_ttk.py http credential \
  --email "user@example.com" \
  --password "$XAI_PASSWORD" \
  --turnstile-provider yescaptcha \
  --turnstile-api-key "$YESCAPTCHA_KEY" \
  --output-dir xai_credentials
```

### 4.7 浏览器只负责抓 Turnstile（可选）

```bash
python grok_register_ttk.py http turnstile-capture \
  --proxy-file proxies.txt --proxy-random \
  --proxy-parent http://127.0.0.1:7890 \
  --output turnstile.txt \
  --proxy-used-file turnstile.proxy.txt
```

立刻用**同一代理**注册（PowerShell）：

```powershell
$proxy = (Get-Content turnstile.proxy.txt -Raw).Trim()
python grok_register_ttk.py http register `
  --proxy $proxy `
  --proxy-parent http://127.0.0.1:7890 `
  --mail-config config.json `
  --turnstile-token-file turnstile.txt `
  --output-dir xai_credentials
```

---

## 5. 浏览器 GUI / CLI 流（遗留批量）

```bash
# GUI
python grok_register_ttk.py

# CLI（无 Tk，但仍开 Chrome）
python grok_register_ttk.py cli
# 提示后输入: start
# 停止: Ctrl+C
```

依赖：`config.json` 邮箱 + 代理 + 本机 Chrome。  
成功写入 `accounts_*.txt`；若开启 `xai_oauth_auto` 再写 OAuth 目录。

---

## 6. HTTP 子命令一览

```bash
python grok_register_ttk.py http --help
```

| 子命令 | 作用 |
| --- | --- |
| `register` | 注册 → SSO →（可选）OAuth JSON |
| `credential` | SSO 或账密 → OAuth JSON |
| `mail-probe` | 只测邮箱创建/读信 |
| `turnstile-capture` | 真浏览器捕获 Turnstile（会开 Chrome） |

公共代理参数：`--proxy` / `--proxy-file` / `--proxy-random` / `--proxy-index` / `--proxy-parent` / `--timeout`。

---

## 7. 数据格式

### 7.1 Outlook 四段（`--mail-file`）

```text
email----password----client_id----refresh_token
```

| 列 | 含义 |
| --- | --- |
| 1 | 注册用邮箱 |
| 2 | 邮箱密码（Graph 读信不用） |
| 3 | 签发 refresh 的 Azure 公共 `client_id` |
| 4 | MSA `refresh_token`（常以 `M.C` 开头） |

成功占用后行会移到同目录 `*.used`。  
无效 token 会跳过并尝试下一行。

### 7.2 代理行

```text
host:port:username:password
http://user:pass@host:port
```

---

## 8. HTTP 注册协议步骤（给 AI / 排障）

实现模块：`xai_http_flow.py`。

1. `GET https://accounts.x.ai/sign-up?redirect=grok-com` 建会话，解析 sitekey  
2. gRPC-Web `CreateEmailValidationCode`  
3. 邮箱轮询 OTP（格式多为 `ABC-DEF`；**不要**误用同箱 OpenAI 数字码）  
4. gRPC-Web `VerifyEmailValidationCode`（错误可能在 **HTTP 头** `grpc-status`，body 为空）  
5. Turnstile token（captcha 或文件）  
6. Next Server Action（`next-action` + `createUserAndSessionRequest`）  
7. 从 RSC 提取 `https://auth.grokipedia.com/set-cookie?q=<JWT>`  
   - Flight 形态：`18:T9d5,<url>`（按 hex 长度切片；host 为 `*.com` / `auth.x.ai`）  
8. 跟随 303 四跳拿 `sso`  
9. OAuth authorize → consent Server Action → token 交换 → 写 JSON  

Castle：`castleRequestToken` 可选；未提供会 warn 后继续，服务端若强制会返回明确错误。

---

## 9. 故障表

| 现象 | 可能原因 | 处理 |
| --- | --- | --- |
| `mail-probe` Graph `invalid_grant` | refresh_token 失效/scope 不对 | 换可用四段号；或改用 yyds/cf |
| `send-validation-code-rate-limited` | 同邮箱发码过频 | 换邮箱，等待冷却 |
| `Email validation code is invalid` | 用了旧信 / 非 xAI 码 | 已修：按收信时间 + xAI 特征过滤；更新代码 |
| Turnstile 求解失败 | key/余额/provider 错误 | 查余额；换 provider |
| 注册被拒 turnstile | token 与站点会话/出口不匹配 | 2Captcha / YesCaptcha 可尝试同一住宅代理；CapSolver 当前 Turnstile 任务固定 proxyless，检查页面 `action` / `cdata` 与任务日志 |
| cookie setter HTTP 400 | URL 截断（旧 bug） | 更新提取逻辑；勿手截 JWT |
| `parent proxy CONNECT … 407` | 上游代理账密错误或失效 | 换代理池 |
| 直连住宅超时，经 Clash 可用 | 出口需本地代理 | `--proxy-parent http://127.0.0.1:7890` |
| curl TLS error 35（间歇） | 本机/代理 TLS 毛刺 | 重试 |
| OAuth 未进 consent | SSO 无效/过期 | 重新注册或导入新 sso |
| 仅浏览器 CLI 仍开 Chrome | 设计如此 | 无浏览器请用 `http` 子命令 |

---

## 10. 给 AI Agent 的操作契约

```text
GOAL: produce accounts_*.txt line + optional xai_credentials JSON
MODE: prefer `python grok_register_ttk.py http register`
NEVER: commit config.json, proxies, mail pools, accounts, credentials, captures
NEVER: forge turnstile/castle; only captcha API or user-provided token
SECRETS: read from env or local untracked files only
VERIFY:
  1) mail-probe ok
  2) register log contains 注册成功 + OAuth 凭证已保存 (if --output-dir set)
  3) accounts file has 3 columns; JSON has access_token + refresh_token
ON FAILURE: report exact stderr line + which stage (mail|otp|turnstile|action|cookie|oauth)
PIVOT: if proxy 407 → try proxy_parent or fresh pool; if graph invalid_grant → yyds/cf
```

---

## 11. 测试

```bash
python -m unittest tests.test_xai_http_flow tests.test_local_proxy_forwarder -v
```

单元测试不触网、不消耗 captcha / 邮箱额度。

---

## 12. 模块地图

| 文件 | 职责 |
| --- | --- |
| `grok_register_ttk.py` | GUI / CLI 浏览器注册；`http` 入口转发 |
| `xai_http_flow.py` | 无浏览器注册、邮箱适配、Turnstile 求解、OAuth 凭证 CLI |
| `xai_oauth.py` | OAuth PKCE / token / 浏览器 OAuth 辅助 |
| `turnstile_flow.py` | 页面 Turnstile 状态机（浏览器流） |
| `local_proxy_forwarder.py` | 本机无认证 → 认证上游（可选 parent） |
| `cf_mail_debug.py` | Cloudflare 临时邮箱接口探测 |
| `config.example.json` | 配置模板 |

---

## 13. 合规与边界

- 不实现 Turnstile/Castle **伪造**；只转发合法求解结果。  
- 目标站协议可能变更；以 live 响应为准，失败时用故障表定位。  
- 分享仓库前再跑一遍第 1 节自检。

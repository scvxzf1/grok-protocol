# Grok Register — 使用指南（人类 / AI 共用）


## WebUI 主入口（推荐）

```bash
./webui.sh
# 浏览器打开 http://127.0.0.1:33844
```

- 仅本机绑定 `127.0.0.1`，默认端口 `33844`（可用 `XAI_WEBUI_PORT` 覆盖）
- 默认配置：`.local/config.json`；自定义路径可用 `python webui_app.py --config /path/to/config.json` 或 `XAI_CONFIG_PATH`
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
                    │  / Outlook OAuth     │
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

三种入口共用同一套 HTTP 批次服务：

| 形态 | 入口 | 浏览器 | 用途 |
| --- | --- | --- | --- |
| **WebUI** | `./webui.sh` | 仅 local Turnstile 需要 | 配置、运行、凭证与 CPA 巡检 |
| **HTTP TUI** | `./http_tui.sh` | 仅 local Turnstile 需要 | 终端批次运行与日志 |
| **直接 CLI** | `python xai_http_flow.py …` | 仅 local Turnstile 需要 | 单次探测、注册或凭证转换 |

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
| 机器本地目录 | `.local/`（配置、夹具、账号、凭证、运行、导出、状态） |
| 密钥配置 | `.local/config.json` 内 API key / 代理账密 |
| 账号产物 | `.local/accounts/`、`.local/credentials/` |
| 代理池真值 | `.local/fixtures/`、真实 `need/*` 池文件 |
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
mkdir -p .local
cp config.example.json .local/config.json
```

编辑 `.local/config.json`（**不要提交**）。

---

## 3. 配置项速查

文件：`.local/config.json`（从 `config.example.json` 复制）

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
| `proxy_file` | 代理池文件，默认 `fixtures/proxies.txt`（相对 `.local/config.json`） |
| `proxy_random` | 是否随机选代理 |
| `local_proxy_port` | 本机无认证转发端口（浏览器流常用） |

### 3.3 Turnstile（HTTP 流）

| 字段 / 环境变量 | 说明 |
| --- | --- |
| `turnstile_provider` | `local` \| `yescaptcha` \| `capsolver` \| `2captcha` |
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
| `register_count` | 批次目标数 |
| `xai_oauth_output_dir` | OAuth JSON 输出目录 |

---

## 4. 最短路径（推荐：HTTP）

### 4.1 前置清单

1. 可用邮箱：`email_provider=yyds|cloudflare` **或** Outlook 四段文件  
2. Turnstile：captcha API key **或** 接受浏览器 `turnstile-capture`  
3. 代理：2Captcha / YesCaptcha 会尽量使用指定上游；CapSolver Turnstile 按官方任务类型固定为 **proxyless**，与注册 HTTP 流的出口可能不同

### 4.2 探测邮箱（不触达 xAI 注册）

```bash
python xai_http_flow.py mail-probe --mail-config .local/config.json
# 或
python xai_http_flow.py mail-probe --mail-file .local/fixtures/my_outlook.txt
```

期望：`[+] mail-probe ok email=…`

### 4.3 一键注册 + OAuth 凭证

```bash
python xai_http_flow.py register \
  --proxy "http://127.0.0.1:7890" \
  --mail-config .local/config.json \
  --turnstile-provider yescaptcha \
  --turnstile-api-key "$YESCAPTCHA_KEY" \
  --output-dir .local/credentials \
  --accounts-output .local/accounts/accounts_http_out.txt
```

带认证住宅代理池：

```bash
python xai_http_flow.py register \
  --proxy-file .local/fixtures/proxies.txt --proxy-random \
  --mail-config .local/config.json \
  --turnstile-provider capsolver \
  --turnstile-api-key "$CAPSOLVER_KEY"
```

### HTTP TUI 启动器

`http_tui.sh` 调用 `xai_http_flow.py register`。它使用标准库 `curses` 提供全屏配置页和运行页：左侧显示总体进度、成功/失败数和每个 worker 状态，右侧实时显示协议子进程日志。

```bash
chmod +x http_tui.sh
./http_tui.sh
```

无交互预览示例：

```bash
./http_tui.sh --config .local/config.json --count 3 --workers 2 --dry-run
```

每个任务都有独立的账号输出和日志，汇总位于 `.local/accounts/`，运行日志位于 `.local/runs/`。运行中按 `q` 可停止任务，`↑` / `↓` 滚动右侧日志，`l` 回到日志末尾。

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

**OAuth JSON** `.local/credentials/xai-<email>.json`（CLIProxyAPI 兼容字段）：

- `type` / `email` / `access_token` / `refresh_token` / `id_token` / `expired` / …

两者均含敏感信息，仅本地保存。

### 4.6 仅已有 SSO → 凭证

```bash
# sso.txt 内一行 sso cookie 值
python xai_http_flow.py credential \
  --sso-file .local/fixtures/sso.txt
```

密码登录（需 Turnstile）：

```bash
python xai_http_flow.py credential \
  --email "user@example.com" \
  --password "$XAI_PASSWORD" \
  --turnstile-provider yescaptcha \
  --turnstile-api-key "$YESCAPTCHA_KEY"
```

### 4.7 浏览器只负责抓 Turnstile（可选）

```bash
python xai_http_flow.py turnstile-capture \
  --proxy-file .local/fixtures/proxies.txt --proxy-random
```

立刻用**同一代理**注册（PowerShell）：

```powershell
$proxy = (Get-Content .local/state/turnstile.proxy.txt -Raw).Trim()
python xai_http_flow.py register `
  --proxy $proxy `
  --mail-config .local/config.json `
  --turnstile-token-file .local/state/turnstile.txt
```

---

## 5. HTTP 子命令一览

```bash
python xai_http_flow.py --help
```

| 子命令 | 作用 |
| --- | --- |
| `register` | 注册 → SSO →（可选）OAuth JSON |
| `credential` | SSO 或账密 → OAuth JSON |
| `mail-probe` | 只测邮箱创建/读信 |
| `turnstile-capture` | 真浏览器捕获 Turnstile（会开 Chrome） |

公共代理参数：`--proxy` / `--proxy-file` / `--proxy-random` / `--proxy-index` / `--timeout`。

---

## 6. 数据格式

### 6.1 Outlook 四段（`--mail-file`）

```text
email----password----client_id----refresh_token
```

| 列 | 含义 |
| --- | --- |
| 1 | 注册用邮箱 |
| 2 | 邮箱密码（OAuth 读信不用） |
| 3 | 签发 refresh 的 Azure 公共 `client_id` |
| 4 | MSA `refresh_token`（常以 `M.C` 开头） |

程序按 `client_id` 自动选择 Graph 或 Thunderbird IMAP OAuth，四段格式保持一致。

成功占用后行会移到同目录 `*.used`。  
无效 token 会跳过并尝试下一行。

### 6.2 代理行

```text
host:port:username:password
http://user:pass@host:port
```

---

## 7. HTTP 注册协议步骤（给 AI / 排障）

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

## 8. 故障表

| 现象 | 可能原因 | 处理 |
| --- | --- | --- |
| `mail-probe` Microsoft OAuth `invalid_grant` | refresh_token 与 client/scope 不匹配 | 核对四段来源；或改用 yyds/cf |
| `send-validation-code-rate-limited` | 同邮箱发码过频 | 换邮箱，等待冷却 |
| `Email validation code is invalid` | 用了旧信 / 非 xAI 码 | 已修：按收信时间 + xAI 特征过滤；更新代码 |
| Turnstile 求解失败 | key/余额/provider 错误 | 查余额；换 provider |
| 注册被拒 turnstile | token 与站点会话/出口不匹配 | 2Captcha / YesCaptcha 可尝试同一住宅代理；CapSolver 当前 Turnstile 任务固定 proxyless，检查页面 `action` / `cdata` 与任务日志 |
| cookie setter HTTP 400 | URL 截断（旧 bug） | 更新提取逻辑；勿手截 JWT |
| curl TLS error 35（间歇） | 本机/代理 TLS 毛刺 | 重试 |
| OAuth 未进 consent | SSO 无效/过期 | 重新注册或导入新 sso |
| 运行时打开 Chrome | `turnstile_provider=local` | 使用第三方 provider，或保留本地求解并检查浏览器上限 |

---

## 9. 给 AI Agent 的操作契约

```text
GOAL: produce .local/accounts row + optional .local/credentials JSON
MODE: prefer `python xai_http_flow.py register`
NEVER: commit .local/, mail pools, accounts, credentials, captures
NEVER: forge turnstile/castle; only captcha API or user-provided token
SECRETS: read from env or local untracked files only
VERIFY:
  1) mail-probe ok
  2) register log contains 注册成功 + OAuth 凭证已保存 (if --output-dir set)
  3) accounts file has 3 columns; JSON has access_token + refresh_token
ON FAILURE: report exact stderr line + which stage (mail|otp|turnstile|action|cookie|oauth)
PIVOT: if proxy 407 → refresh proxy credentials or use a fresh pool; if Microsoft OAuth invalid_grant → check client/scope or use yyds/cf
```

---

## 10. 持续邮箱池监督器

外部 Outlook OAuth master 较大、需要固定小批次断点续跑时：

```bash
python server_mail_supervisor.py \
  --config .local/config.json \
  --master .local/fixtures/mail-master.txt \
  --work .local/state/mail-work.txt \
  --proxy .local/fixtures/proxies.txt \
  --output .local/credentials \
  --state .local/state/mail-supervisor.state.json
```

- master 行格式仍是 `email----password----client_id----refresh_token`；work 每轮原子重建，
  相邻的 `work.txt.used` 与 `work.txt.lock` 由 Microsoft OAuth worker 维护。
- 未传 `--state` 时使用 `MASTER.state.json`；同一 state set 只允许一个 supervisor。
- 默认 epoch / 注册 worker / Turnstile worker / submit worker 为 `20 / 4 / 2 / 2`。
- 每轮通过当前 `BatchService` 和静态代理独占租约运行；重启时按
  master → work → used 确定性合并，used 中轮换后的 refresh token 优先。
- state 只含聚合计数、状态与时间；邮箱、代理、token、凭证和本机路径不写入 state/日志。
- 退出码：`0` 全部完成，`2` 运行错误，`3` 单实例锁占用，`130` 收到停止请求。
- master/work/proxy/state/凭证目录统一放在受 `.gitignore` 保护的 `.local/`。

---

## 11. 测试

```bash
python -m unittest \
  tests.test_xai_http_flow \
  tests.test_local_proxy_forwarder \
  tests.test_server_mail_supervisor -v
```

单元测试不触网、不消耗 captcha / 邮箱额度。

---

## 12. 模块地图

| 文件 | 职责 |
| --- | --- |
| `xai_http_flow.py` | HTTP 注册、邮箱适配、Turnstile 求解、OAuth 凭证 CLI |
| `xai_oauth.py` | OAuth PKCE / token / 浏览器 OAuth 辅助 |
| `turnstile_flow.py` | 页面 Turnstile 状态机（浏览器流） |
| `local_proxy_forwarder.py` | 本机无认证 → 认证 HTTP 上游 |
| `http_batch_service.py` | WebUI/TUI 共用批次服务与静态代理租约编排 |
| `server_mail_supervisor.py` | Outlook OAuth master 的断点续跑与小批次监督 |
| `cross_process_lock.py` | 跨平台进程锁与私有原子文件写入 |
| `local_paths.py` | `.local/` 配置、夹具与运行产物路径约定 |
| `config.example.json` | 配置模板 |

---

## 13. 合规与边界

- 不实现 Turnstile/Castle **伪造**；只转发合法求解结果。  
- 目标站协议可能变更；以 live 响应为准，失败时用故障表定位。  
- 分享仓库前再跑一遍第 1 节自检。

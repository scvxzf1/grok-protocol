## WebUI 主入口（推荐）

```bash
./webui.sh
# 浏览器打开 http://127.0.0.1:33843
```

- 仅本机绑定 `127.0.0.1`，默认端口 `33843`（可用 `XAI_WEBUI_PORT` 覆盖）
- 同时只跑 1 个批次；含失败汇总、历史 run、浏览器残留清理
- 旧 TUI（`./tui.sh`）仍保留作过渡


<div align="center">

[![Grok Register — GUI and CLI registration automation toolkit](assets/banner.png)](https://github.com/AaronL725/grok-register)

Grok Register 是一个面向自动化流程研究、测试环境验证和个人学习的 Python 自动化注册工具 — 支持 GUI / CLI、临时邮箱、浏览器流程控制、账号输出和 grok2api token 池写入。

<p>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776AB.svg" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/Interface-GUI%20%2B%20CLI-success.svg" alt="GUI + CLI">
  <img src="https://img.shields.io/badge/Browser-Chromium%2FChrome-4285F4.svg" alt="Chromium/Chrome">
  <a href="http://makeapullrequest.com"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome"></a>
  <a href="https://linux.do"><img src="https://img.shields.io/badge/Join-linux.do-orange" alt="linux.do"></a>
</p>

<p align="center">
 <a href="https://www.star-history.com/aaronl725/grok-register">
  <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/badge?repo=AaronL725/grok-register&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/badge?repo=AaronL725/grok-register" />
   <img alt="Star History Rank" src="https://api.star-history.com/badge?repo=AaronL725/grok-register" />
  </picture>
 </a>
</p>

</div>

---

> 本项目仅用于自动化流程研究、测试环境验证和个人学习。请遵守目标网站服务条款、当地法律法规和第三方服务限制。

## Contents

- [功能](#功能)
- [环境要求](#环境要求)
- [安装](#安装)
- [配置](#配置)
- [运行](#运行)
- [无浏览器 HTTP 模式](#无浏览器-http-模式)
- [完整使用指南](#完整使用指南)
- [输出文件](#输出文件)
- [稳定性机制](#稳定性机制)
- [常见问题](#常见问题)
- [目录结构](#目录结构)
- [分享前注意](#分享前注意)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Star History](#star-history)

## 功能

- 支持 GUI 图形界面运行。
- 支持 CLI 终端运行，不启动 Tk GUI。
- 注册流程使用 Chromium/Chrome 浏览器页面完成。
- 支持独立的无浏览器 HTTP 注册、SSO 会话导入和 OAuth 凭证获取命令。
- 支持 DuckMail、YYDS、Cloudflare 临时邮箱接口。
- 支持验证码邮件轮询和解析。
- 支持成功账号实时写入 `accounts_*.txt`。
- 支持将 SSO token 写入 grok2api 本地或远端池。
- 支持注册后尝试开启 NSFW。
- 支持页面卡住检测、当前账号重试、浏览器重启和内存清理。

## 环境要求

- Python 3.9+
- Google Chrome 或 Chromium
- 可访问注册页面和临时邮箱 API 的网络环境

## 安装

下载项目到电脑：

```bash
git clone https://github.com/AaronL725/grok-register.git
cd grok-register
```

安装依赖：

```bash
pip install -r requirements.txt
```

复制配置文件：

```bash
cp config.example.json config.json
```

然后按需编辑 `config.json`。

## 配置

常用配置项：

| 配置项 | 说明 |
| --- | --- |
| `email_provider` | 邮箱服务商：`duckmail`、`yyds`、`cloudflare` |
| `register_count` | 本次目标注册数量 |
| `proxy_mode` | `auto`、`none`、`direct` 或 `pool` |
| `proxy` | `direct` 模式使用的单个代理 URL |
| `proxy_file` | `pool` 模式使用的代理列表文件 |
| `embedded_proxy_enabled` | 可选；由项目内置 mihomo 节点接管任务出口 |
| `enable_nsfw` | 注册后是否尝试开启 NSFW |
| `cloudflare_api_base` | Cloudflare 临时邮箱 API 地址 |
| `cloudflare_api_key` | Cloudflare 临时邮箱接口密钥；默认匿名模式留空，admin 模式填 `ADMIN_PASSWORD` |
| `cloudflare_auth_mode` | Cloudflare API 鉴权模式；默认 `none`，可选 `bearer`、`x-api-key`、`x-admin-auth`、`query-key` |
| `cloudflare_path_domains` | Cloudflare 域名列表路径；默认 `/api/domains` |
| `cloudflare_path_accounts` | Cloudflare 创建邮箱路径；默认匿名模式用 `/api/new_address`，admin 模式用 `/admin/new_address` |
| `cloudflare_path_token` | Cloudflare token 路径；默认 `/api/token` |
| `cloudflare_path_messages` | Cloudflare 收件列表路径；默认 `/api/mails` |
| `defaultDomains` | Cloudflare 临时邮箱默认域名 |
| `grok2api_auto_add_local` | 是否写入本地 grok2api token 池 |
| `grok2api_local_token_file` | 本地 grok2api token 文件路径 |
| `grok2api_auto_add_remote` | 是否写入远端 grok2api |
| `grok2api_remote_base` | 远端 grok2api 地址，可填站点根地址或 `/admin/api` 管理 API 地址 |
| `grok2api_remote_app_key` | 远端 grok2api app key |
| `turnstile_provider` | HTTP 流验证码服务：`capsolver`、`yescaptcha`、`2captcha` |
| `turnstile_api_key` | HTTP 流验证码服务 API key；也可优先通过环境变量传入 |

### Cloudflare 临时邮箱匿名模式（默认）

默认情况下，Cloudflare 邮箱使用 `dreamhunter2333/cloudflare_temp_email` 的匿名接口创建邮箱并读取邮件：

- 创建邮箱：`POST /api/new_address`
- 读取邮件：`GET /api/mails`
- 鉴权模式：`none`
- `cloudflare_api_key`：留空

这是项目的默认路线。没有特殊需求时，保持下面配置即可：

```json
{
  "email_provider": "cloudflare",
  "cloudflare_api_base": "https://你的-worker-api-域名",
  "cloudflare_api_key": "",
  "cloudflare_auth_mode": "none",
  "cloudflare_path_domains": "/api/domains",
  "cloudflare_path_accounts": "/api/new_address",
  "cloudflare_path_token": "/api/token",
  "cloudflare_path_messages": "/api/mails",
  "defaultDomains": "你的收信域名.com"
}
```

### Cloudflare 临时邮箱 admin 模式（可选）

如果使用 `dreamhunter2333/cloudflare_temp_email` 且匿名 `/api/new_address` 开启了 Turnstile，可以改用 admin 创建邮箱接口：

```json
{
  "email_provider": "cloudflare",
  "cloudflare_api_base": "https://你的-worker-api-域名",
  "cloudflare_api_key": "你的 ADMIN_PASSWORD",
  "cloudflare_auth_mode": "x-admin-auth",
  "cloudflare_path_accounts": "/admin/new_address",
  "cloudflare_path_messages": "/api/mails",
  "defaultDomains": "你的收信域名.com"
}
```

创建邮箱会使用 `x-admin-auth` 调用 `/admin/new_address`，后续收件仍使用接口返回的地址 JWT 调用 `/api/mails`。也就是说，admin 密码只用于创建邮箱，不用于读取邮箱邮件。

可先用调试脚本验证 admin 创建接口：

```bash
python cf_mail_debug.py --api-base "https://你的-worker-api-域名" --auth-mode x-admin-auth --api-key "你的 ADMIN_PASSWORD" --create-path /admin/new_address --domain "你的收信域名.com"
```

### grok2api 远端入池配置

如果开启 `grok2api_auto_add_remote`，`grok2api_remote_base` 可以填写站点根地址，也可以直接填写管理 API 地址：

```json
{
  "grok2api_auto_add_remote": true,
  "grok2api_remote_base": "https://你的-grok2api-域名",
  "grok2api_remote_app_key": "你的 app_key"
}
```

或：

```json
{
  "grok2api_auto_add_remote": true,
  "grok2api_remote_base": "https://你的-grok2api-域名/admin/api",
  "grok2api_remote_app_key": "你的 app_key"
}
```

程序会优先尝试 `/tokens/add`，并兼容 `/admin/api/tokens/add`；旧版全量保存接口也会兼容 `/tokens` 和 `/admin/api/tokens`。

`config.json` 包含个人配置和密钥，不要提交到 Git。

## 运行

### CLI 模式

CLI 模式不会启动 Tk GUI，但注册流程仍会打开 Chromium/Chrome 浏览器页面。

```bash
python grok_register_ttk.py cli
```

看到提示后输入：

```text
start
```

停止任务：

```text
Ctrl+C
```

CLI 模式适合长时间批量运行。程序每成功注册 5 个账号会关闭浏览器、清理运行时对象并重新启动浏览器，降低长任务内存占用。

### 无浏览器 HTTP 模式

`http` 子命令不会导入 Tk、DrissionPage 或启动 Chrome。它直接维护 xAI 的跨域 Cookie、调用注册/邮箱验证码/OAuth consent 接口，并将 OAuth 凭证写成 CLIProxyAPI 兼容的 JSON：

```bash
python grok_register_ttk.py http --help
```

已存在 SSO 会话时，只获取凭证：

```bash
python grok_register_ttk.py http credential --sso-file sso.txt --output-dir xai_credentials
```

完整注册可使用 `config.json` 邮箱服务商创建/轮询验证码（`yyds` / `cloudflare` / `msgraph`），或 Outlook 四段文件（格式见 `need/outlook_mail.example.txt`）：

```bash
# 探测邮箱（不注册）
python grok_register_ttk.py http mail-probe --mail-config config.json

# 代理池 + captcha 服务 + 邮箱配置
python grok_register_ttk.py http register \
  --proxy-file proxies.txt \
  --proxy-random \
  --mail-config config.json \
  --turnstile-provider yescaptcha \
  --turnstile-api-key "$YESCAPTCHA_KEY" \
  --output-dir xai_credentials
```

Turnstile 也可改用浏览器捕获（会开 Chrome），见 [USAGE.md](USAGE.md)。

支持的 captcha provider：`yescaptcha`、`capsolver`、`2captcha`（环境变量：`XAI_TURNSTILE_PROVIDER`、`XAI_TURNSTILE_API_KEY` 等）。

### HTTP TUI 启动器

`http_tui.sh` 是无浏览器 HTTP 模式的全屏终端启动器，使用 Python 标准库 `curses`，不需要新增依赖。启动页可编辑配置文件、注册数量、并发数、OAuth 输出目录和代理模式；开始后左侧固定渲染批次进度和 worker 状态，右侧实时滚动每个协议子进程的后端日志。每个并发任务独立运行协议注册，不会启动 Chrome。

```bash
chmod +x http_tui.sh
./http_tui.sh
```

可先检查运行计划，不发送任何请求：

```bash
./http_tui.sh --config config.json --count 3 --workers 2 --dry-run
```

TUI 的数量和并发只影响本次运行，不会改写 `config.json`。批次日志会写入已忽略的 `http_runs/`，成功账号汇总为 `accounts_http_*.txt`。

运行页快捷键：`q` 停止/退出，`↑` / `↓` 滚动右侧日志，`l` 回到最新日志。建议终端尺寸至少为 80x20。

### CapSolver Turnstile

CapSolver 接入使用其 `createTask` / `getTaskResult` API。优先通过环境变量提供密钥，避免把密钥写入 `config.json`：

```bash
export CAPSOLVER_API_KEY="你的 CapSolver API key"

python grok_register_ttk.py http register \
  --mail-config config.json \
  --turnstile-provider capsolver \
  --output-dir xai_credentials
```

实现遵循 CapSolver 当前 Turnstile 文档，提交 `AntiTurnstileTaskProxyLess`，并在页面声明时转发 `data-action` 与 `data-cdata`。该任务类型不接收自定义代理；即使注册 HTTP 流配置了 `--proxy`，CapSolver 求解任务仍会以 proxyless 方式创建，日志会明确提示这一点。

注册成功默认写 `accounts_http_*.txt`（`email----password----sso`）与 OAuth JSON；**均含敏感信息，勿提交**。

HTTP 模式不伪造 Turnstile/Castle：需 captcha 服务或 token 文件。Castle 按可选字段转发。注册会先 `VerifyEmailValidationCode` 再提交 Server Action。

已有 SSO 只取凭证：

```bash
python grok_register_ttk.py http credential --sso-file sso.txt --output-dir xai_credentials
```

## 完整使用指南

人读 / AI agent 共用的完整说明（系统图、配置表、验收日志、故障表、Agent 契约）：

**→ [USAGE.md](USAGE.md)**

### GUI 模式

```bash
python grok_register_ttk.py
```

GUI 模式会打开 Tkinter 窗口，适合手动调整配置和观察日志。

## 输出文件

运行过程中会生成：

- `accounts_*.txt`：成功账号、密码和 SSO token。
- `mail_credentials.txt`：临时邮箱凭证。
- `*.log`：可选日志文件。

这些文件包含敏感信息，已被 `.gitignore` 忽略。

## 稳定性机制

- 每个账号结束后重启浏览器。
- 每成功 5 个账号执行一次内存清理。
- CLI 模式支持 `Ctrl+C` 中断并清理浏览器。
- 最终页长时间无变化时自动重试当前账号。
- 验证码未收到时自动更换邮箱重试。

## 常见问题

### CLI 模式为什么还会打开浏览器？

CLI 模式只是不启动 Tk GUI。注册页、Turnstile、验证码提交和 SSO cookie 获取仍依赖真实浏览器环境。

### NSFW 开启失败怎么办？

如果日志显示 `Cloudflare 防护拦截，HTTP 403`，说明请求被目标站点防护拦截。程序会继续保存账号和写入 grok2api。

### GUI 显示的数量和配置不同？

GUI 数量控件可能有上限。CLI 模式直接读取 `config.json` 中的 `register_count`。

## 目录结构

```text
.
├── grok_register_ttk.py   # 主程序（GUI / CLI / http 入口）
├── xai_http_flow.py       # 无浏览器 HTTP 注册与 OAuth 凭证
├── xai_oauth.py           # OAuth PKCE / token
├── turnstile_flow.py      # 浏览器页 Turnstile 状态机
├── local_proxy_forwarder.py
├── cf_mail_debug.py
├── config.example.json
├── need/                  # 仅示例；真实池文件勿提交
├── tests/
├── USAGE.md               # 完整使用指南（人类 + AI）
├── requirements.txt
└── README.md
```

## 分享前注意

1. 只提交/打包源码与示例；**不要**带上 `config.json`、`proxies.txt`、`accounts_*`、`xai_credentials/`、真实 `need/*` 池、抓包 JSON。  
2. `config.json` 从 `config.example.json` 复制后本地填写。  
3. 分享前可用 `USAGE.md` 第 1 节自检命令扫一遍密钥残留。

## License

[MIT](LICENSE).

## Acknowledgments

Thanks to [linux.do](https://linux.do) — a vibrant tech community where this project is shared and discussed.

## Star History

<a href="https://www.star-history.com/?repos=AaronL725%2Fgrok-register&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=AaronL725/grok-register&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=AaronL725/grok-register&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=AaronL725/grok-register&type=date&legend=top-left" />
 </picture>
</a>

## WebUI 主入口（推荐）

统一入口（含 **CPA 巡检**）：

```bash
./webui.sh
# 浏览器打开 http://127.0.0.1:33844
# CPA 巡检：http://127.0.0.1:33844/cpa
```

- 仅本机绑定 `127.0.0.1`，默认端口 `33844`（可用 `XAI_WEBUI_PORT` 覆盖）
- 同时只跑 1 个批次；含失败汇总、历史 run、浏览器残留清理
- 导航：运行台 / 配置中心 / 凭证列表 / **CPA 巡检**
- 默认配置为 `.local/config.json`；隔离配置可用 `python webui_app.py --config /path/to/config.json`（或 `XAI_CONFIG_PATH`）
- 旧 TUI（`./tui.sh`）仍保留作过渡
- 也可单独启动 CPA：`python cpa_main.py`（默认 `127.0.0.1:8218`，自动跳到 `/cpa`）



<div align="center">

[![Grok Register — HTTP registration automation toolkit](assets/banner.png)](https://github.com/AaronL725/grok-register)

Grok Register 是一个 HTTP 优先的 Python 自动化流程工具，提供 WebUI / TUI / CLI、临时邮箱、内置 mihomo 出口、局部 Turnstile 浏览器求解和 OAuth 凭证管理。

<p>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776AB.svg" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/Interface-WebUI%20%2B%20CLI-success.svg" alt="WebUI + CLI">
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

- 支持 WebUI、TUI 与直接 CLI 运行。
- 注册主流程直接使用 HTTP；只有选择本地 Turnstile 时启动受控 Chrome。
- 支持 HTTP 注册、SSO 会话导入和 OAuth 凭证获取命令。
- 支持 DuckMail、YYDS、Cloudflare 临时邮箱接口。
- 支持验证码邮件轮询和解析。
- 支持账号、凭证、运行记录和导出统一写入 `.local/`。
- 支持静态 HTTP 代理池、订阅导入和内置 mihomo 多协议节点。
- 支持有界重试、代理租约、浏览器生命周期和残留清理。

## 环境要求

- Python 3.9+
- Google Chrome 或 Chromium（仅本地 Turnstile 求解需要）
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
mkdir -p .local
cp config.example.json .local/config.json
```

然后按需编辑 `.local/config.json`，或直接从 WebUI 保存配置。

## 配置

常用配置项：

| 配置项 | 说明 |
| --- | --- |
| `email_provider` | 邮箱服务商：`duckmail`、`yyds`、`cloudflare` |
| `register_count` | 本次目标注册数量 |
| `proxy` | 代理地址，可留空 |
| `cloudflare_api_base` | Cloudflare 临时邮箱 API 地址 |
| `cloudflare_api_key` | Cloudflare 临时邮箱接口密钥；默认匿名模式留空，admin 模式填 `ADMIN_PASSWORD` |
| `cloudflare_auth_mode` | Cloudflare API 鉴权模式；默认 `none`，可选 `bearer`、`x-api-key`、`x-admin-auth`、`query-key` |
| `cloudflare_path_accounts` | Cloudflare 创建邮箱路径；默认匿名模式用 `/api/new_address`，admin 模式用 `/admin/new_address` |
| `cloudflare_path_messages` | Cloudflare 收件列表路径；默认 `/api/mails` |
| `defaultDomains` | Cloudflare 临时邮箱默认域名 |
| `turnstile_provider` | Turnstile：`local`、`capsolver`、`yescaptcha`、`2captcha` |
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
  "cloudflare_path_accounts": "/api/new_address",
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

`.local/config.json` 包含个人配置和密钥，整个 `.local/` 均不提交到 Git。

## 运行

### HTTP CLI

CLI 直接维护跨域 Cookie，并调用注册、邮箱验证码和 OAuth consent 接口；选择第三方 Turnstile provider 时全程不启动浏览器：

```bash
python xai_http_flow.py --help
```

已存在 SSO 会话时，只获取凭证：

```bash
python xai_http_flow.py credential --sso-file .local/fixtures/sso.txt
```

完整注册可使用 `.local/config.json` 邮箱服务商创建/轮询验证码（`yyds` / `cloudflare` / `msgraph`），或 `.local/fixtures/` 下的 Outlook 四段文件：

```bash
# 探测邮箱（不注册）
python xai_http_flow.py mail-probe --mail-config .local/config.json

# 推荐：captcha 服务 + 邮箱配置，无浏览器
python xai_http_flow.py register \
  --proxy-file .local/fixtures/proxies.txt --proxy-random \
  --mail-config .local/config.json \
  --turnstile-provider yescaptcha \
  --turnstile-api-key "$YESCAPTCHA_KEY"
```

Turnstile 也可改用浏览器捕获（会开 Chrome），见 [USAGE.md](USAGE.md)。

支持的 captcha provider：`yescaptcha`、`capsolver`、`2captcha`（环境变量：`XAI_TURNSTILE_PROVIDER`、`XAI_TURNSTILE_API_KEY` 等）。

### HTTP TUI 启动器

`http_tui.sh` 是 HTTP 模式的全屏终端启动器。每个并发任务独立执行 `xai_http_flow.py register`；仅本地 Turnstile provider 会启动 Chrome。

```bash
chmod +x http_tui.sh
./http_tui.sh
```

可先检查运行计划，不发送任何请求：

```bash
./http_tui.sh --config .local/config.json --count 3 --workers 2 --dry-run
```

TUI 的数量和并发只影响本次运行。批次日志写入 `.local/runs/`，成功账号汇总到 `.local/accounts/`。

运行页快捷键：`q` 停止/退出，`↑` / `↓` 滚动右侧日志，`l` 回到最新日志。建议终端尺寸至少为 80x20。

### CapSolver Turnstile

CapSolver 接入使用其 `createTask` / `getTaskResult` API。优先通过环境变量提供密钥，避免把密钥写入 `.local/config.json`：

```bash
export CAPSOLVER_API_KEY="你的 CapSolver API key"

python xai_http_flow.py register \
  --mail-config .local/config.json \
  --turnstile-provider capsolver \
  --output-dir .local/credentials
```

实现遵循 CapSolver 当前 Turnstile 文档，提交 `AntiTurnstileTaskProxyLess`，并在页面声明时转发 `data-action` 与 `data-cdata`。该任务类型不接收自定义代理；即使注册 HTTP 流配置了 `--proxy`，CapSolver 求解任务仍会以 proxyless 方式创建，日志会明确提示这一点。

注册成功默认写 `.local/accounts/accounts_http_*.txt` 与 `.local/credentials/` 下的 OAuth JSON。

HTTP 模式不伪造 Turnstile/Castle：需 captcha 服务或 token 文件。Castle 按可选字段转发。注册会先 `VerifyEmailValidationCode` 再提交 Server Action。

已有 SSO 只取凭证：

```bash
python xai_http_flow.py credential --sso-file .local/fixtures/sso.txt
```

## 完整使用指南

人读 / AI agent 共用的完整说明（系统图、配置表、验收日志、故障表、Agent 契约）：

**→ [USAGE.md](USAGE.md)**

持续处理外部 Outlook/Graph 邮箱池时，可使用
`server_mail_supervisor.py` 的断点续跑批次模式；master/work/state、代理清单与凭证目录
都属于本机私有数据。完整命令、状态语义和退出码见 `USAGE.md`。

## 输出文件

运行过程中会生成：

- `.local/accounts/`：成功账号、密码和 SSO token。
- `.local/credentials/`：OAuth 凭证。
- `.local/runs/`、`.local/exports/`、`.local/state/`：运行日志、导出和状态。
- `.local/fixtures/`：机器本地代理、邮箱等私有测试输入。

这些文件包含敏感信息，已被 `.gitignore` 忽略。

## 稳定性机制

- 本地 Turnstile 浏览器有任务数、年龄、空闲、RSS 和重试上限。
- 停止批次时只清理本项目创建的浏览器与转发器。
- 静态 HTTP 代理按任务独占租约并在所有退出路径释放。
- 验证码未收到时自动更换邮箱重试。

## 常见问题

### 为什么会打开浏览器？

只有 `turnstile_provider=local` 会启动本地 Chrome；改用已配置的第三方 provider 后，注册主链保持 HTTP。

## 目录结构

```text
.
├── webui_app.py           # WebUI 入口
├── http_batch_service.py  # WebUI/TUI 批次服务
├── xai_http_flow.py       # HTTP 注册、邮箱与 OAuth 凭证 CLI
├── xai_oauth.py           # OAuth PKCE / token
├── turnstile_flow.py      # 浏览器页 Turnstile 状态机
├── local_proxy_forwarder.py
├── local_paths.py         # .local/ 机器本地路径约定
├── config.example.json
├── need/                  # 仅示例；真实池文件勿提交
├── tests/
├── USAGE.md               # 完整使用指南（人类 + AI）
├── requirements.txt
└── README.md
```

## 分享前注意

1. 只提交/打包源码与示例；**不要**带上 `.local/`、真实 `need/*` 池或抓包 JSON。
2. `.local/config.json` 从 `config.example.json` 复制后本地填写。
3. 分享前可用 `USAGE.md` 第 1 节自检命令扫一遍密钥残留。

## License

[MIT](LICENSE).

## Acknowledgments

Thanks to [linux.do](https://linux.do) — a vibrant tech community where this project is shared and discussed.

## Star History

<a href="https://www.star-history.com/?repos=AaronL725%2Fgrok-register&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=AaronL725/grok-register&type=date&theme=dark&legend=top-left&sealed_token=uCM--S2xEp0n8rFUZHUg6wUJOgYcfO4XEVCIF9UZAT04YjL9YsMEOVOGAOlQfqwsoS7cQef0Rwc1cYCY4lAmTuMmcg-hKzNnx1A7KNekuCXQotFd4YifLIkvJWOEy5vxiREJX80Mwxbr8F-3GfCv0utIsQz_iq19nS57svUqwv0mSosV8OTxqXTLjmsI" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=AaronL725/grok-register&type=date&legend=top-left&sealed_token=uCM--S2xEp0n8rFUZHUg6wUJOgYcfO4XEVCIF9UZAT04YjL9YsMEOVOGAOlQfqwsoS7cQef0Rwc1cYCY4lAmTuMmcg-hKzNnx1A7KNekuCXQotFd4YifLIkvJWOEy5vxiREJX80Mwxbr8F-3GfCv0utIsQz_iq19nS57svUqwv0mSosV8OTxqXTLjmsI" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=AaronL725/grok-register&type=date&legend=top-left&sealed_token=uCM--S2xEp0n8rFUZHUg6wUJOgYcfO4XEVCIF9UZAT04YjL9YsMEOVOGAOlQfqwsoS7cQef0Rwc1cYCY4lAmTuMmcg-hKzNnx1A7KNekuCXQotFd4YifLIkvJWOEy5vxiREJX80Mwxbr8F-3GfCv0utIsQz_iq19nS57svUqwv0mSosV8OTxqXTLjmsI" />
 </picture>
</a>

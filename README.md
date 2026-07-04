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

</div>

---

> 本项目仅用于自动化流程研究、测试环境验证和个人学习。请遵守目标网站服务条款、当地法律法规和第三方服务限制。

## Contents

- [功能](#功能)
- [环境要求](#环境要求)
- [安装](#安装)
- [配置](#配置)
- [运行](#运行)
- [输出文件](#输出文件)
- [稳定性机制](#稳定性机制)
- [常见问题](#常见问题)
- [目录结构](#目录结构)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Star History](#star-history)

## 功能

- 支持 GUI 图形界面运行。
- 支持 CLI 终端运行，不启动 Tk GUI。
- 注册流程使用 Chromium/Chrome 浏览器页面完成。
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
| `proxy` | 代理地址，可留空 |
| `enable_nsfw` | 注册后是否尝试开启 NSFW |
| `cloudflare_api_base` | Cloudflare 临时邮箱 API 地址 |
| `cloudflare_auth_mode` | Cloudflare API 鉴权模式：`none`、`bearer`、`x-api-key`、`query-key` |
| `defaultDomains` | Cloudflare 临时邮箱默认域名 |
| `grok2api_auto_add_local` | 是否写入本地 grok2api token 池 |
| `grok2api_local_token_file` | 本地 grok2api token 文件路径 |
| `grok2api_auto_add_remote` | 是否写入远端 grok2api |
| `grok2api_remote_base` | 远端 grok2api 管理 API 地址 |
| `grok2api_remote_app_key` | 远端 grok2api app key |

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
├── grok_register_ttk.py   # 主程序
├── cf_mail_debug.py       # Cloudflare 邮箱调试工具
├── config.example.json    # 配置示例
├── requirements.txt       # Python 依赖
└── README.md
```

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
# Turnstile Solver（本地浏览器 token 工厂）

一句话：这不是 Cloudflare 硬解码器，而是给 xAI HTTP 注册流提供**真实 Turnstile token** 的本地服务。

## 目标

- 专用场景：`accounts.x.ai` 注册页 Turnstile
- 设计原则：一任务一代理一浏览器，token 现产现用
- 并发目标：先 2，再 5，最后 10
- 对接方式：HTTP API / CLI，供 `xai_http_flow.py` 调用

## 当前阶段

Phase 1：已接入 DrissionPage 真实捕获逻辑。

`headless=true` 使用 Chrome 原生 `headless=new`，不经过 Xvfb，也不静默启动
可见窗口。浏览器槽默认在空闲 90 秒、进程树 RSS 超过 1024 MiB、运行 12
个任务或存活 15 分钟时回收，减少长时间运行的内存堆积。

直接读取项目主配置时，`max_concurrency` 未填写会沿用
`local_turnstile_max_workers`；当前五端口配置可因此直接建立 5 个求解槽。

## 快速开始

```bash
# 在仓库根目录
python3 -m turnstile_solver.src health

python3 -m turnstile_solver.src solve \
  --proxy "http://user:pass@host:port" \
  --output /tmp/turnstile.txt \
  --proxy-used-file /tmp/turnstile.proxy.txt
```

更完整说明见 `docs/PHASE1_USAGE.md`。

## 原则

1. 不伪造 Turnstile / Castle
2. solve 与 register 尽量同一出口代理
3. token 不入库囤积，只短时传递
4. 浏览器池有上限，失败可熔断重启

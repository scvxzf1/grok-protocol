# Phase 1 使用说明

## 单次捕获

```bash
cd /path/to/grok协议
python3 -m turnstile_solver.src solve \
  --proxy "http://user:pass@host:port" \
  --output /tmp/turnstile.txt \
  --proxy-used-file /tmp/turnstile.proxy.txt
```

成功时 stdout 为 JSON，`ok=true` 且带 `token`。

## 立刻同代理注册

```bash
python3 xai_http_flow.py register \
  --proxy "$(cat /tmp/turnstile.proxy.txt)" \
  --mail-config .local/config.json \
  --turnstile-token-file /tmp/turnstile.txt \
  --output-dir .local/credentials
```

## 说明

- 有账密代理时，solver 会自动起本机 forwarder 给 Chrome 用
- 返回的 `proxy` 字段是上游代理，供注册复用
- token 要马上用，不要囤

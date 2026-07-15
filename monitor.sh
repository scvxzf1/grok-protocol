#!/usr/bin/env bash
# 项目资源监控快捷方式
# 用法:
#   ./monitor.sh           # 每 2 秒刷新
#   ./monitor.sh 1         # 每 1 秒刷新
#   ./monitor.sh once      # 只打一次
set -euo pipefail
cd "$(dirname "$0")"

INTERVAL="${1:-2}"
ONCE=0
if [[ "${INTERVAL}" == "once" || "${INTERVAL}" == "-1" ]]; then
  ONCE=1
  INTERVAL=2
fi
if ! [[ "${INTERVAL}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "用法: $0 [秒|once]" >&2
  exit 1
fi

render() {
  local now load memline
  now="$(date '+%F %T')"
  load="$(cut -d ' ' -f1-3 /proc/loadavg)"
  memline="$(free -h | awk 'NR==2{printf "Mem total=%s used=%s free=%s avail=%s", $2,$3,$4,$7}')"

  echo "==== ${now} | load ${load} ===="
  echo "${memline}"
  echo

  echo "==== 项目进程汇总 ===="
  ps -eo pid,ppid,%cpu,%mem,rss,etime,cmd --no-headers \
  | awk '
    /webui_app\.py|xai_http_flow\.py|xai-ts-chrome|embedded_mihomo|\.local\/runs\// {
      n++; cpu+=$3; rss+=$5
      if ($0 ~ /webui_app\.py/) { w_n++; w_cpu+=$3; w_rss+=$5 }
      else if ($0 ~ /xai_http_flow\.py/) { r_n++; r_cpu+=$3; r_rss+=$5 }
      else if ($0 ~ /embedded_mihomo/) { m_n++; m_cpu+=$3; m_rss+=$5 }
      else if ($0 ~ /xai-ts-chrome/) { c_n++; c_cpu+=$3; c_rss+=$5 }
      else { o_n++; o_cpu+=$3; o_rss+=$5 }
    }
    END {
      printf "总计     n=%-4d cpu=%7.1f%%  mem=%6.2fG\n", n+0, cpu+0, rss/1024/1024
      printf "webui    n=%-4d cpu=%7.1f%%  mem=%6.2fG\n", w_n+0, w_cpu+0, w_rss/1024/1024
      printf "workers  n=%-4d cpu=%7.1f%%  mem=%6.2fG\n", r_n+0, r_cpu+0, r_rss/1024/1024
      printf "chrome   n=%-4d cpu=%7.1f%%  mem=%6.2fG\n", c_n+0, c_cpu+0, c_rss/1024/1024
      printf "mihomo   n=%-4d cpu=%7.1f%%  mem=%6.2fG\n", m_n+0, m_cpu+0, m_rss/1024/1024
      printf "other    n=%-4d cpu=%7.1f%%  mem=%6.2fG\n", o_n+0, o_cpu+0, o_rss/1024/1024
    }'

  local chrome_dirs port_webui port_proxy
  chrome_dirs="$(ls -d /tmp/xai-ts-chrome-* 2>/dev/null | wc -l | tr -d " ")"
  port_webui="$(ss -lntp 2>/dev/null | grep -c "127.0.0.1:33844" || true)"
  port_proxy="$(ss -lntp 2>/dev/null | grep -c "127.0.0.1:280" || true)"
  echo
  echo "tmp chrome dirs: ${chrome_dirs} | ports webui=${port_webui} proxy280xx=${port_proxy}"

  if command -v curl >/dev/null 2>&1; then
    curl -sS -m 1 "http://127.0.0.1:33844/api/health" 2>/dev/null \
    | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    print("webui: offline")
    raise SystemExit(0)
e = d.get("embedded_proxy") or {}
print(
    "webui: busy=%s run=%s emb=%s healthy=%s/%s leases=%s"
    % (
        d.get("busy"),
        d.get("run_id"),
        e.get("phase"),
        e.get("healthy"),
        e.get("total"),
        e.get("leases"),
    )
)
' 2>/dev/null || echo "webui: offline"
  fi

  echo
  echo "==== Top 10 CPU (项目相关) ===="
  ps -eo pid,%cpu,%mem,rss,etime,cmd --sort=-%cpu --no-headers \
  | awk '
    /webui_app\.py|xai_http_flow\.py|xai-ts-chrome|embedded_mihomo/ { print }
  ' \
  | head -10 \
  | awk '{
      rss=$4/1024
      cmd=substr($0, index($0,$6))
      if (length(cmd) > 90) cmd=substr(cmd,1,87) "..."
      printf "%-7s %6s%% %5s%% %7.0fMB %8s  %s\n", $1,$2,$3,rss,$5,cmd
    }'
}

if [[ "${ONCE}" -eq 1 ]]; then
  render
  exit 0
fi

if command -v watch >/dev/null 2>&1; then
  # 用 watch 清屏刷新；内部再调自己 once，避免转义地狱
  exec watch -n "${INTERVAL}" -c "$0 once"
fi

# 没有 watch 时退化为 while 循环
while true; do
  clear 2>/dev/null || true
  render
  sleep "${INTERVAL}"
done

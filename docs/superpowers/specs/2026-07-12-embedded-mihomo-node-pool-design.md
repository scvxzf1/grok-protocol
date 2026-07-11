# 内嵌 Mihomo 多节点轮换池设计

日期：2026-07-12  
状态：待用户审阅  
范围：为 xAI HTTP 注册机增加内嵌 mihomo 兼容层，把订阅中的 VLESS 节点转成可分配的本地 HTTP 出口，并按任务轮换/复用。

## 1. 背景与问题

当前注册主链路（`curl_cffi` / HTTP 协议）只直接支持 HTTP 代理（及有限 SOCKS），不能直接使用 `vless://` 订阅节点。

已有能力：

- `proxy_subscription.py`：可拉取并解析订阅（含 VLESS）
- `local_proxy_forwarder.py`：仅做 HTTP 代理转发/去鉴权，不理解 VLESS
- WebUI 配置中心：可管理普通代理池与订阅链接

缺口：

- VLESS 节点无法直接进入注册代理池
- 依赖用户手动开启外部 Clash/V2Ray
- 多任务并发时缺少“按任务分配节点 + 失败换节点 + 节点复用”的统一调度

## 2. 目标

### 2.1 必须达成

1. 项目可复用本机 `mihomo` / `verge-mihomo`，自动拉起 **单个** 内嵌内核进程。
2. 从订阅解析出的 VLESS 节点，映射为本地 HTTP 出口：`http://127.0.0.1:<port>`。
3. **按任务**分配节点：一个注册任务全程固定一个节点。
4. 节点不够时允许 **复用**（引用计数），优先空闲节点。
5. 任务失败可换节点重试，最多 **3** 个节点。
6. 选节点前做 **预检测**：经该节点访问 `accounts.x.ai:443` 成功才算 healthy。
7. WebUI 可启用/查看状态/触发预检与重载。

### 2.2 非目标（第一版不做）

- 不内嵌/双开 xray 引擎
- 不按请求级切换节点
- 不把 VLESS 协议直接塞进 `curl_cffi`
- 不把内核二进制打包进仓库
- 不做跨机器分布式节点调度

## 3. 方案选择

采用 **方案 A：单 mihomo + 多监听端口 + 任务级租约**。

```text
订阅 VLESS
  → 生成一份 mihomo 配置（每节点一个本地 HTTP 入站/或等价端口映射）
  → 启动 1 个 mihomo 进程
  → 预检 accounts.x.ai:443
  → 任务 acquire 节点（空闲优先，可复用）
  → 失败最多换 3 个节点
```

放弃：

- 每任务一个 mihomo 进程（太重）
- 单入口 API 动态切节点（并发会串出口）

## 4. 架构

### 4.1 组件

| 组件 | 职责 |
|---|---|
| `proxy_subscription.py` | 拉取/解析订阅，产出节点清单（已有） |
| `embedded_proxy_manager.py`（新） | 生成配置、启停 mihomo、端口映射、预检、租约、选节点 |
| `http_batch_service.py` | 配置读写、批次生命周期、任务拿/还节点 |
| `xai_http_flow.py` | 只消费 HTTP 代理 URL，不感知 VLESS |
| WebUI 配置中心 | 开关、路径、状态、预检/重载按钮 |

### 4.2 数据流

```text
enable embedded proxy + import subscription
  → parse VLESS nodes (cap by max_nodes)
  → write runtime config dir
  → start mihomo
  → parallel probe accounts.x.ai:443 via each local HTTP port
  → mark healthy/unhealthy

worker task:
  acquire_node()
    → only healthy
    → prefer ref_count == 0
    → else lowest ref_count
    → lease +1
  run registration with http://127.0.0.1:port
  on proxy-level failure and retries left:
    release(node, failed=True)
    acquire another node (max 3 total)
  finally:
    release(node)
```

### 4.3 节点模型（内存态）

```text
NodeSlot:
  id, name, server, port, protocol
  local_http: http://127.0.0.1:28xxx
  healthy: bool
  ref_count: int
  success_count / fail_count
  last_latency_ms
  cooldown_until
  last_error
```

## 5. 预检测规则

代理场景不依赖 ICMP ping，而做“经节点访问 xAI”探测：

- 默认目标：`accounts.x.ai:443`
- 超时默认：5s
- 成功：标记 `healthy`，记录耗时
- 失败：标记 `unhealthy`，记录错误，进入短冷却
- 启动后批量预检（限制并发）
- 任务只从 healthy 集合选择
- 若 healthy 为空：禁止分配，返回明确错误
- 节点任务失败后可立即复检一次（可选，第一版建议做）

## 6. 分配与复用规则

1. 过滤：`healthy == true` 且未在冷却期
2. 优先：`ref_count == 0`
3. 否则：`ref_count` 最小（节点不够时复用）
4. 同分时可按 `last_latency_ms` 升序
5. 同一任务粘滞该节点，不中途自动跳
6. 单任务最多尝试 3 个不同节点
7. 任务结束必须 release，防止泄漏

## 7. 配置项

| 字段 | 默认 | 说明 |
|---|---|---|
| `embedded_proxy_enabled` | `false` | 启用内嵌 mihomo 池 |
| `embedded_proxy_binary` | `""` | 空则自动探测 `mihomo`/`verge-mihomo` |
| `embedded_proxy_listen_host` | `127.0.0.1` | 仅本机 |
| `embedded_proxy_base_port` | `28000` | 本地 HTTP 起始端口 |
| `embedded_proxy_max_nodes` | `50` | 最多接入节点数 |
| `embedded_proxy_probe_host` | `accounts.x.ai` | 预检主机 |
| `embedded_proxy_probe_port` | `443` | 预检端口 |
| `embedded_proxy_probe_timeout_sec` | `5` | 预检超时 |
| `embedded_proxy_max_node_retries` | `3` | 单任务最多节点数 |

与现有代理模式关系：

- `embedded_proxy_enabled=false`：完全走现有 `none/direct/pool`
- `embedded_proxy_enabled=true`：注册任务改走内嵌节点分配；普通代理池不参与该批次出口选择

## 8. WebUI

配置中心新增“内嵌代理内核”区块：

- 启用开关
- 内核路径（可空）
- 预检目标展示/可配
- 按钮：启动或重载内核、预检全部节点、刷新状态
- 状态：运行中/已停止、healthy/total、当前租约数、最近错误

运行日志示例：

```text
[W03] [Proxy] 分配节点 #12 日本高速01 -> http://127.0.0.1:28012 (lease=1)
[W03] [Proxy] 节点失败，切换 #07 香港高速02 (2/3)
```

约束：

- 批次运行中禁止重载/停内核（第一版）
- 需先停批次再重载

## 9. 生命周期与失败处理

| 场景 | 行为 |
|---|---|
| 找不到内核二进制 | 启动失败并提示路径 |
| 订阅无 VLESS | 不启动池 |
| 预检全失败 | degraded，拒绝分配 |
| 代理连接失败 | 换节点，最多 3 |
| 节点连续失败 | unhealthy + 冷却 |
| 批次结束 | 释放全部租约；内核能保持常驻或随服务停 |
| 运行中请求重载 | 返回错误：请先停止批次 |

## 10. 实现边界

新增：

- `embedded_proxy_manager.py`
- 相关单测
- WebUI 字段/API/状态接口

修改：

- `http_batch_service.py`：配置中心字段、批次 ensure/acquire/release
- `webui_app.py` / `webui/templates/config.html` / `webui/static/config.js`
- `config.example.json`
- 必要时 `xai_http_flow.py` 仅接收已分配 HTTP 代理（不解析 VLESS）

不修改：

- 既有普通 HTTP 代理池语义（关闭内嵌时保持原样）

## 11. 测试计划

单元：

1. VLESS 节点 → mihomo 配置端口映射生成
2. acquire：空闲优先、不足复用最低 ref
3. release 引用计数正确
4. 失败换节点不超过 3，且避免无意义重复
5. unhealthy 节点不可被选中
6. 运行中重载被拒绝

集成（本机有 mihomo 时）：

1. 启动内核
2. 预检 `accounts.x.ai:443`
3. 经分配到的本地 HTTP 口完成探测
4. 两个并发任务在节点不足时能复用同一 healthy 节点

## 12. 风险与缓解

| 风险 | 缓解 |
|---|---|
| 端口占用冲突 | base_port 可配；启动前探测端口可用性 |
| 节点质量差 | 预检 + 失败降权/冷却 |
| 并发打爆上游 | 预检并发限制；任务级粘滞减少切换 |
| 内核配置兼容差异 | 先支持常见 VLESS TCP/TLS/Reality/WS；解析失败跳过并告警 |
| 用户误以为 VLESS 可直接入 proxies.txt | WebUI 文案明确“需内嵌内核/本地客户端” |

## 13. 验收标准

1. 仅填订阅并启用内嵌后，无需手开 Clash 也能为任务分配本地 HTTP 出口。
2. 预检未通过的节点不会被新任务选中。
3. 并发大于节点数时任务仍可启动（复用 healthy 节点）。
4. 单任务最多换 3 个节点；成功或耗尽后正确 release。
5. 关闭内嵌后，原代理模式行为不变。
6. WebUI 能看到内核状态与 healthy/total。

## 14. 后续可扩展（非本版）

- xray 后端可切换
- 节点分组/地区偏好
- 自动下载 mihomo 二进制
- 运行中安全热更新订阅
- 更细的成功率统计面板

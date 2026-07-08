# CaptCha API Reference

本文档面向自研 Gateway、服务网格适配器、内部平台控制面和后端服务接入。普通业务接入优先看 [Integration Guide](integration-guide.md) 和各语言中间件 README。

## 接口分层

| 层级 | 协议 | 用途 |
|---|---|---|
| Browser Runtime API | HTTP JSON | 浏览器创建、读取、刷新和提交 challenge。 |
| Data-plane API | HTTP JSON / gRPC | Gateway、中间件、后端服务做策略评估、ticket 校验、配置同步和事件上报。 |
| Admin API | HTTP JSON | 管理应用、策略、素材、审计、样本和模型版本。 |
| Metrics | HTTP text | Prometheus 指标抓取。 |

## 鉴权

| 调用方 | 鉴权方式 |
|---|---|
| 浏览器 Runtime | 不携带 `client_secret`。依赖 CORS、短 TTL、服务端答案、ticket 单次消费和部署边界。 |
| HTTP Data-plane API | 应用配置 secret 后，携带 `X-Captcha-Client-Secret: <secret>` 或 `Authorization: Bearer <secret>`。 |
| gRPC Data-plane API | 平台级 token 使用 metadata `x-captcha-grpc-token: <token>` 或 `authorization: Bearer <token>`。应用级 secret 使用 metadata `x-captcha-client-secret: <secret>`，也可用 bearer。 |
| Admin API | `X-Captcha-Admin-Token: <token>` 或 `Authorization: Bearer <token>`。 |
| Metrics | `X-Captcha-Metrics-Token: <token>` 或 `Authorization: Bearer <token>`。 |

不要把 `client_secret`、admin token、metrics token 或 gRPC token 放进浏览器代码。

## HTTP API

默认 HTTP 服务端口是 `:8080`。示例里的 `https://captcha.example.com` 替换为实际平台地址。

### 健康和指标

| Method | Path | 说明 |
|---|---|---|
| `GET` | `/healthz` | 进程健康检查。 |
| `GET` | `/metrics` | Prometheus 文本指标；生产环境可配置 metrics token。 |

### Browser Runtime API

这些接口由 Runtime 前端调用。响应不会暴露答案、目标点、容差、评分规则或阈值。

| Method | Path | 说明 |
|---|---|---|
| `POST` | `/api/v1/challenge/sessions` | 创建 challenge session。 |
| `GET` | `/api/v1/challenge/sessions/{session_id}` | 获取 challenge 展示数据。 |
| `POST` | `/api/v1/challenge/sessions/{session_id}/verify` | 提交答案和交互轨迹，成功后返回一次性 ticket。 |
| `POST` | `/api/v1/challenge/sessions/{session_id}/refresh` | 刷新 challenge。 |

创建 session 的常用字段：

| 字段 | 说明 |
|---|---|
| `client_id` | 应用标识。 |
| `scene` | 业务场景，如 `login`、`register`、`pay`。 |
| `captcha_type` | 验证码类型，或 `AUTO` / `RANDOM`。 |
| `route` | ticket 绑定的业务路由。 |
| `request_nonce` | ticket 绑定的一次性请求 nonce。 |
| `return_url` | redirect 模式返回地址，必须通过 allowlist。 |
| `resource_tag` | 素材选择标签。 |

示例：

```bash
curl -X POST https://captcha.example.com/api/v1/challenge/sessions \
  -H 'content-type: application/json' \
  -d '{
    "client_id": "your-client",
    "scene": "login",
    "captcha_type": "AUTO",
    "route": "/api/login",
    "request_nonce": "nonce-123"
  }'
```

### Data-plane HTTP API

这些接口由业务后端、Gateway 或中间件调用。应用配置 secret 后必须携带应用 secret。

#### Verify Ticket

```text
POST /api/v1/tickets/verify
```

用途：校验或消费 Runtime 返回的一次性 ticket。`consume=true` 时会消费 ticket，并在成功时返回 clearance。

请求字段：

| 字段 | 必填 | 说明 |
|---|---|---|
| `ticket` | 是 | Runtime 返回的一次性 ticket。 |
| `client_id` | 是 | 应用标识。 |
| `scene` | 是 | 业务场景。 |
| `route` | 否 | ticket 绑定过 route 时必须匹配。 |
| `request_nonce` | 否 | ticket 绑定过 nonce 时必须匹配。 |
| `ip_hash` | 否 | ticket 绑定过 IP hash 时必须匹配。 |
| `user_agent_hash` | 否 | ticket 绑定过 User-Agent hash 时必须匹配。 |
| `account_id_hash` | 否 | 外部账号标识哈希。 |
| `device_id_hash` | 否 | 外部设备或访客标识哈希。 |
| `consume` | 否 | 是否消费 ticket 并返回 clearance。 |

示例：

```bash
curl -X POST https://captcha.example.com/api/v1/tickets/verify \
  -H 'content-type: application/json' \
  -H 'X-Captcha-Client-Secret: cap_secret_xxx' \
  -d '{
    "client_id": "your-client",
    "scene": "login",
    "ticket": "ticket-from-runtime",
    "route": "/api/login",
    "request_nonce": "nonce-123",
    "consume": true
  }'
```

响应成功时 `valid=true`。失败时 HTTP 仍可能是 `200`，通过 `valid=false` 和 `reason` 判断，例如 `NOT_FOUND`、`EXPIRED`、`CONSUMED`。

#### Evaluate Policy

```text
POST /api/v1/policy/evaluate
```

用途：让平台根据 ticket、clearance、应用状态、IP 策略、路由策略、频控和风险上下文返回处置动作。

请求字段：

| 字段 | 说明 |
|---|---|
| `client_id` | 应用标识。 |
| `scene` | 业务场景。 |
| `path` | 业务请求路径。 |
| `method` | HTTP 方法。 |
| `ip` | 请求来源 IP，由服务端或可信代理解析后传入。 |
| `user_agent` | 浏览器 User-Agent。 |
| `account_id_hash` | 外部账号标识哈希。 |
| `device_id_hash` | 外部设备或访客标识哈希。 |
| `ticket` | 可选。存在时优先消费 ticket。 |
| `clearance` | 可选。已有通行态。 |
| `request_nonce` | 可选。高风险操作的一次性请求 nonce。 |
| `resource_tag` | 可选。素材选择标签。 |
| `risk_score` / `risk_level` | 可选。接入方风控信号。 |
| `model_score` / `model_mode` | 可选。模型风险信号。 |
| `headers` | 可选。仅传显式 allowlist 的低敏业务头。 |

示例：

```bash
curl -X POST https://captcha.example.com/api/v1/policy/evaluate \
  -H 'content-type: application/json' \
  -H 'X-Captcha-Client-Secret: cap_secret_xxx' \
  -d '{
    "client_id": "your-client",
    "scene": "login",
    "path": "/api/login",
    "method": "POST",
    "ip": "203.0.113.10",
    "user_agent": "browser user-agent",
    "request_nonce": "nonce-123"
  }'
```

常见响应字段：

| 字段 | 说明 |
|---|---|
| `action` | `allow`、`challenge`、`block`、`observe` 等决策。接入层遇到未知 action 应 fail closed。 |
| `reason` | 稳定原因码。 |
| `challenge_url` | `challenge` 时返回 Runtime 地址。 |
| `session_id` | challenge session ID。 |
| `scene` | 决策场景。 |
| `challenge_type` | 使用的验证码类型。 |
| `ttl_seconds` | challenge TTL。 |
| `clearance_token` | 放行动作可能返回的通行态。 |
| `clearance_ttl_seconds` | clearance TTL。 |

#### Report Events

```text
POST /api/v1/events/report
```

用途：Gateway 或中间件异步上报本地决策、ticket 消费结果、平台不可用降级结果。

```json
{
  "events": [
    {
      "client_id": "your-client",
      "scene": "login",
      "route": "/api/login",
      "action": "allow",
      "decision_reason": "TICKET_CONSUMED",
      "result": "allow",
      "account_id_hash": "acct_hash",
      "device_id_hash": "device_hash",
      "ip_hash": "sha256:..."
    }
  ]
}
```

服务端会覆盖外部传入的事件时间和事件 ID。

### Risk Collection API

| Method | Path | 说明 |
|---|---|---|
| `GET` | `/api/v1/risk/demo-collection-summary` | Demo 轨迹采集摘要。 |
| `POST` | `/api/v1/risk/track-samples` | 写入候选轨迹特征快照；默认不直接进入训练集。 |

### Admin API

Admin API 需要 admin token。它服务于管理台和内部运营工具，不应从普通业务浏览器直接调用。

| Method | Path | 说明 |
|---|---|---|
| `GET` | `/api/v1/admin/auth/check` | 检查管理 token。 |
| `GET` | `/api/v1/admin/metrics` | 管理台概览指标。 |
| `GET` / `POST` | `/api/v1/admin/applications` | 应用列表和保存。 |
| `POST` | `/api/v1/admin/applications/{client_id}/secret` | 轮换应用 secret。 |
| `GET` / `POST` | `/api/v1/admin/route-policies` | 路由策略列表和保存。 |
| `POST` | `/api/v1/admin/route-policies/delete` | 删除路由策略。 |
| `GET` / `POST` | `/api/v1/admin/policies` | 可配置策略规则列表和保存。 |
| `POST` | `/api/v1/admin/policies/delete` | 删除策略规则。 |
| `GET` / `POST` | `/api/v1/admin/ip-policies` | IP 策略列表和保存。 |
| `POST` | `/api/v1/admin/ip-policies/delete` | 删除 IP 策略。 |
| `POST` | `/api/v1/admin/policy/simulate` | 策略 dry-run；不消费 ticket、不创建 session、不写审计。 |
| `GET` / `POST` | `/api/v1/admin/resources` | 资源列表和保存。 |
| `POST` | `/api/v1/admin/resources/upload` | 上传素材。 |
| `POST` | `/api/v1/admin/resources/delete` | 删除素材。 |
| `GET` | `/api/v1/admin/audit-events` | 审计事件列表。 |
| `GET` | `/api/v1/admin/risk-feature-snapshots` | 风险样本列表。 |
| `GET` | `/api/v1/admin/risk-feature-snapshots/export` | 风险样本导出。 |
| `POST` | `/api/v1/admin/risk-feature-snapshots/{id}/label` | 标注风险样本。 |
| `GET` / `POST` | `/api/v1/admin/risk-model-versions` | 模型版本列表和保存。 |
| `POST` | `/api/v1/admin/risk-model-versions/{id}/activate` | 启用模型版本。 |
| `POST` | `/api/v1/admin/risk-model-versions/{id}/rollback` | 回滚模型版本。 |

## gRPC API

正式契约在 [proto/captcha/v1/captcha.proto](../proto/captcha/v1/captcha.proto)。默认 gRPC 服务端口是 `:9090`。

| Service | Method | 能力 |
|---|---|---|
| `PolicyService` | `Evaluate` | 策略评估，功能对应 HTTP `POST /api/v1/policy/evaluate`。 |
| `TicketService` | `VerifyTicket` | 校验 ticket，不消费。 |
| `TicketService` | `ConsumeTicket` | 消费 ticket，成功时返回 clearance。 |
| `ConfigService` | `GetConfig` | 获取应用配置快照，用于 Gateway 或自研接入层缓存策略。 |
| `ConfigService` | `WatchConfig` | 监听配置变化，stream 返回配置快照。 |
| `EventService` | `Report` | 上报审计事件。 |

推荐 metadata：

```text
x-captcha-grpc-token: <platform-token>
x-captcha-client-secret: <application-secret>
```

也支持 `authorization: Bearer <token>`。同时启用平台 token 和应用 secret 时，推荐分开放在 `x-captcha-grpc-token` 和 `x-captcha-client-secret`，避免一个 bearer token 承担两种语义。

## 接入安全建议

- 业务浏览器只调用 Runtime API，不持有任何 secret。
- Gateway / middleware 默认不要转发 `authorization`、`cookie` 等敏感头；只转发显式 allowlist 的低敏业务头。
- 高风险操作绑定 `route` 和 `request_nonce`。
- ticket 校验或消费失败按失败处理，不回退普通策略放行。
- `policy/evaluate` 或 gRPC `Evaluate` 返回未知 action 时，接入层应 fail closed。
- 公开采集流量只能进入候选样本，不能直接作为训练集。

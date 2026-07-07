# 策略引擎实现规格

本文档把“可配置风控策略平台”的产品口径落成工程规格。它是后续实现策略存储、API、后台、Gateway 下发和 dry-run 测试的依据。

## 1. 边界

CaptCha 是平台，不拥有接入方的业务用户体系。所有主体字段都是接入方传入的外部脱敏上下文：

- `account_id_hash`：外部账号标识哈希。
- `device_id_hash`：外部设备、匿名访客或终端标识哈希。
- `ip` / `ip_hash`：请求来源或服务端计算摘要。
- `user_agent` / `user_agent_hash`：浏览器标识或摘要。
- `headers`：接入方显式 allowlist 的低敏业务头。

策略引擎只消费这些上下文并输出决策，不保存明文业务用户，不建立平台用户表。

## 2. 目标

策略引擎必须支持模板化入口，但不能被模板锁死。

模板用于快速建策略：

- 固定验证。
- 访问过快。
- 风险较高。
- 可信外部主体低风险跳过验证。
- 登录防护、注册防护、短信防护、支付防护等业务模板。

底层模型必须是可配置规则：

```text
scope + conditions + aggregation + actions + governance
```

## 3. 数据模型

### 3.1 PolicyRule

```json
{
  "id": "rule_login_trusted_skip",
  "client_id": "app_xxx",
  "name": "可信主体低风险跳过登录验证",
  "description": "外部账号和设备都稳定时跳过验证码",
  "priority": 100,
  "enabled": true,
  "status": "draft|active|retired",
  "version": "2026-06-28.1",
  "scope": {},
  "conditions": {},
  "aggregation": {},
  "action": {},
  "rollout_percent": 100,
  "created_at": "...",
  "updated_at": "..."
}
```

### 3.2 Scope

`scope` 决定规则是否进入候选集。

字段：

- `client_id`
- `scenes`
- `path_patterns`
- `methods`
- `resource_tags`
- `active_from`
- `active_until`
- `rollout_percent`

路径匹配一期支持精确匹配、末尾 `*` 前缀匹配，以及空路径或 `*` 表示全部路径；方法为空表示全部 HTTP 方法。全站默认策略可用空路径和空方法表达，接口级覆盖策略通过更高优先级的具体路径表达；`force_challenge` 覆盖会在 clearance 校验前生效，适合永远验证的高风险接口。后续可扩展 glob 或正则，但正则必须有限制和测试，避免复杂表达式拖慢请求路径。

### 3.3 Conditions

条件树支持：

```json
{
  "all": [
    { "field": "account_id_hash", "op": "exists" },
    { "field": "device_id_hash", "op": "exists" },
    { "field": "risk_score", "op": "lte", "value": 30 }
  ]
}
```

组合：

- `all`
- `any`
- `not`

操作符：

- `exists`
- `not_exists`
- `eq`
- `ne`
- `in`
- `not_in`
- `gte`
- `gt`
- `lte`
- `lt`
- `prefix`
- `suffix`
- `contains`
- `path_match`
- `cidr_match`

一期字段白名单：

- `client_id`
- `scene`
- `path`
- `method`
- `ip`
- `user_agent`
- `account_id_hash`
- `device_id_hash`
- `request_nonce`
- `resource_tag`
- `risk_score`
- `risk_level`
- `model_score`
- `model_mode`
- `headers.<name>`

未知字段默认不匹配，并在 dry-run 的解释中标记。

### 3.4 Aggregation

`aggregation` 描述需要跨请求计数的规则，例如频控和冷却。

字段：

- `dimensions`：`ip`、`account_id_hash`、`device_id_hash`、`client_id`、`scene`、`path`。
- `window_seconds`
- `max_requests`
- `strategy`：`fixed_window`、`sliding_window`、`token_bucket`。
- `cooldown_seconds`

一期可以先复用现有 `RateStore.IncrementRate`，后续按规则 ID 生成稳定 key：

```text
policy:<client_id>:<rule_id>:<dimension>:<value>
```

### 3.5 Actions

动作枚举：

- `allow`
- `skip_challenge`
- `challenge`
- `step_up_challenge`
- `rate_limit`
- `cooldown`
- `block`
- `observe`
- `require_business_verify`

动作字段：

- `reason`
- `challenge_type`
- `challenge_escalation`
- `ttl_seconds`
- `cooldown_seconds`
- `business_verify_type`

`skip_challenge` 与 `allow` 都是不创建验证码 session 的放行类动作，但 `skip_challenge` 必须保留独立原因，便于审计说明“为什么低风险跳过验证码”。

`require_business_verify` 只告诉接入方需要业务侧二次校验，平台不实现短信、邮箱、支付密码或人工审核。

### 3.6 Governance

治理字段：

- `priority`
- `rollout_percent`
- `status`
- `version`
- `created_by`
- `published_by`
- `published_at`
- `retired_at`

规则发布需要支持：

- 草稿。
- 发布。
- 回滚。
- diff。
- dry-run。
- 审计。

## 4. 决策流程

推荐顺序：

```text
application status
  -> IP allowlist
  -> IP blocklist
  -> policy rules by priority
  -> legacy route policy compatibility
  -> default allow
```

规则内部：

```text
scope match
  -> rollout match
  -> conditions match
  -> aggregation check
  -> action
  -> explanation
```

IP 放行名单优先于 IP 拦截名单。普通规则中的 allow / skip_challenge 不应绕过应用禁用。

## 5. Dry-Run API

现有接口保留：

```text
POST /api/v1/admin/policy/simulate
```

目标响应结构应包含：

```json
{
  "dry_run": true,
  "request": {},
  "decision": {
    "action": "skip_challenge",
    "reason": "TRUSTED_SUBJECT_LOW_RISK"
  },
  "matched_rule": {
    "id": "rule_login_trusted_skip",
    "name": "可信主体低风险跳过登录验证",
    "priority": 100,
    "action": "skip_challenge",
    "reason": "TRUSTED_SUBJECT_LOW_RISK"
  },
  "explanation": [
    "scope matched",
    "condition account_id_hash exists",
    "condition risk_score <= 30",
    "action skip_challenge"
  ],
  "side_effects": [
    "no_challenge_session_created",
    "no_ticket_consumed",
    "no_rate_counter_incremented",
    "no_audit_event_written"
  ],
  "notes": []
}
```

Dry-run 不能创建 session、消费 ticket、递增限流计数或写审计事件。

## 6. 兼容迁移

现有 `RoutePolicy` 不立即删除。迁移路径：

1. 新增纯内存规则评估器，验证 `scope / conditions / action`。
2. 将 `RoutePolicy.mode` 视为模板兼容字段。
3. 后端支持把旧路由策略转换成等价 `PolicyRule`。
4. API 同时保留 `/route-policies` 和新增 `/policies`。
5. 后台逐步从“路由策略表单”过渡到“策略模板 + 高级规则”。
6. Gateway 配置快照增加 `policy_rules`，旧客户端继续读取 `routes`。

## 7. 测试矩阵

必须覆盖：

- 条件组合：`all / any / not`。
- 操作符：数值比较、集合、CIDR、路径、header。
- 外部主体：`account_id_hash`、`device_id_hash` 存在和缺失。
- 动作：`allow`、`skip_challenge`、`challenge`、`block`、`observe`。
- dry-run 无副作用。
- 旧 `RoutePolicy` 行为不变。
- 灰度稳定性。
- 未知字段和非法配置不会 panic。

第一阶段验收：

- 有 `PolicyRule` 类型。
- 有纯 Go 规则评估器。
- 有单测证明可信外部主体低风险可输出 `skip_challenge`。
- 有单测证明模板之外的组合条件可工作。
- 现有策略测试仍通过。

当前实现进度：

- 已新增 `types.PolicyRule`、`PolicyRuleScope`、`PolicyCondition`、`PolicyRuleAggregation` 和 `PolicyRuleAction`。
- 已新增 `policy.EvaluatePolicyRules` / `policy.EvaluatePolicyRule` 纯 Go 评估器。
- 已覆盖 scope、rollout、`all/any/not` 条件树、数值比较、CIDR、路径和 header 条件。
- 已新增 `policy_rules` PostgreSQL 迁移，内存 store 与 PostgreSQL control store 均支持 `ListPolicyRules`、`UpsertPolicyRule`、`DeletePolicyRules`。
- 已新增 Admin API：`GET /api/v1/admin/policies`、`POST /api/v1/admin/policies`、`POST /api/v1/admin/policies/delete`。
- `POST /api/v1/admin/policy/simulate` 已返回 `matched_rule` 与 `explanation`，并保持 dry-run 无 session、ticket、限流计数和审计副作用。
- HTTP/gRPC PolicyService 已在 IP 策略之后、旧 `RoutePolicy` 之前执行 `PolicyRule`；`skip_challenge` 不创建验证码 session，`challenge`、`step_up_challenge` 和 `rate_limit` 会创建验证码 session。
- `ConfigService.GetConfig/WatchConfig` 快照已下发 `policy_rules`；Gateway 本地缓存会执行无聚合、非挑战类的确定性规则动作，挑战类和聚合限流仍回平台端处理。
- gRPC proto 继续保持粗粒度决策枚举兼容：`skip_challenge` 映射为 `ALLOW`，`step_up_challenge` / `rate_limit` 映射为 `CHALLENGE`，`cooldown` / `require_business_verify` 映射为 `BLOCK`。

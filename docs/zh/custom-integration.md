# 自定义接入

语言：中文 | [English](../en/custom-integration.md)

适合自研 Gateway、服务网格、平台控制面或统一安全入口。你自己负责把业务请求上下文传给 CaptCha，并处理放行、挑战、阻断和 cookie 写入。

## 什么时候选

- 业务服务不想直接依赖 CaptCha 中间件。
- 已有 Gateway、服务网格或统一 API 入口。
- 想用自己的策略编排、日志、灰度和失败处理。
- 需要 HTTP / gRPC 作为内部数据面。

## 最小策略评估

```ts
const decision = await fetch("https://captcha.example.com/api/v1/policy/evaluate", {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "x-captcha-client-secret": process.env.CAPTCHA_CLIENT_SECRET || ""
  },
  body: JSON.stringify({
    client_id: "demo",
    scene: "login",
    path: req.path,
    method: req.method,
    ip: req.ip,
    user_agent: req.get("user-agent") || "",
    ticket: req.get("x-captcha-ticket") || "",
    clearance: req.cookies?.captcha_clearance || "",
    request_nonce: req.get("x-captcha-request-nonce") || "",
    account_id_hash: req.user?.captchaAccountHash || "",
    device_id_hash: req.get("x-captcha-device-id-hash") || ""
  })
}).then((response) => response.json());
```

## 处理返回动作

```ts
if (decision.clearance_token) {
  res.cookie("captcha_clearance", decision.clearance_token, {
    httpOnly: true,
    sameSite: "lax",
    secure: true,
    maxAge: (decision.clearance_ttl_seconds || 600) * 1000
  });
}

if (["allow", "observe", "pass"].includes(decision.action)) return next();

if (["challenge", "challenge_harder"].includes(decision.action)) {
  return res.status(403).json({
    action: decision.action,
    challenge_url: decision.challenge_url,
    session_id: decision.session_id,
    reason: decision.reason
  });
}

return res.status(403).json({ error: decision.reason || "CAPTCHA_BLOCKED" });
```

未知 action 建议 fail closed，不要默认放行。

## 字段约定

| 字段 | 说明 |
|---|---|
| `client_id` / `scene` | 应用和业务场景。 |
| `path` / `method` | 当前业务请求，用于匹配路由策略。 |
| `ip` / `user_agent` | 由后端或可信代理解析出的原始值，平台会自行计算 hash。 |
| `ticket` | Runtime 返回的一次性 ticket，有则优先消费。 |
| `clearance` | 已有通行态，通常来自 `captcha_clearance`。 |
| `request_nonce` | 高风险动作的一次性 nonce。 |
| `account_id_hash` / `device_id_hash` | 可选账号/设备维度，必须是业务后端生成的 hash。 |

## HTTP 和 gRPC

HTTP 适合早期联调和普通平台接入。gRPC 适合作为长期内部数据面，提供策略评估、ticket 消费、配置快照、配置监听和事件上报。

完整字段和鉴权见 [HTTP / gRPC API](api-reference.md)。

## 继续阅读

- [快速接入](quickstart.md)
- [后端 ticket 核销](backend-ticket-verification.md)
- [中间件接入](middleware-integration.md)

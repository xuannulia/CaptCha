# 自定义接入

语言：中文 | [English](../en/custom-integration.md)

适合自研 Gateway、服务网格、平台控制面或统一安全入口。你自己负责把业务请求上下文传给 CaptCha，并处理放行、挑战、阻断、clearance 写入和平台不可用时的失败策略。

## 什么时候选

- 业务服务不想直接依赖 CaptCha 中间件。
- 已有 Gateway、服务网格或统一 API 入口。
- 想用自己的策略编排、日志、灰度和失败处理。
- 需要 HTTP / gRPC 作为内部数据面。

## 推荐闭环

自定义接入最好按中间件同样的顺序实现：

1. 判断当前请求是否需要保护。
2. 如果有 `X-Captcha-Ticket`，先调用 `/api/v1/tickets/verify` 并 `consume=true`。
3. ticket 有效：写入短期 clearance，然后放行业务请求。
4. ticket 无效：直接返回 403，不要继续调用策略接口。
5. 没有 ticket：读取 `X-Captcha-Clearance` 或 `captcha_clearance`，调用 `/api/v1/policy/evaluate`。
6. 策略返回 allow/observe/pass：放行；返回 challenge/block：按返回值响应。
7. 平台超时、5xx、网络错误或熔断：执行你自己的 `fail_open` / `fail_close`。

## 失败策略模板

自定义接入没有内置中间件，所以失败策略必须由你自己的代码实现。推荐把它做成环境变量或路由级配置。

```ts
const CAPTCHA_FAIL_POLICY = process.env.CAPTCHA_FAIL_POLICY || "fail_open";

async function callCaptcha<T>(fn: (signal: AbortSignal) => Promise<T>): Promise<T | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1500);
  try {
    return await fn(controller.signal);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function handleCaptchaUnavailable(res, reason) {
  if (CAPTCHA_FAIL_POLICY === "fail_close") {
    return res.status(503).json({ action: "block", reason });
  }
  return null;
}
```

规则：

- 平台不可用、超时、熔断：可以按配置 fail-open 或 fail-close。
- ticket 无效、ticket 已消费、route/nonce/account/device 绑定不匹配：必须按验证失败处理，不要 fail-open。
- 未知 action：必须 fail closed。
- 事件上报失败不能阻断业务请求。

## 处理 ticket

```ts
async function consumeTicket(req, res, next) {
  const ticket = req.get("x-captcha-ticket") || "";
  if (!ticket) return null;

  const result = await callCaptcha((signal) =>
    fetch("https://captcha.example.com/api/v1/tickets/verify", {
      method: "POST",
      signal,
      headers: {
        "content-type": "application/json",
        "x-captcha-client-secret": process.env.CAPTCHA_CLIENT_SECRET || ""
      },
      body: JSON.stringify({
        client_id: "demo",
        scene: "login",
        ticket,
        route: req.path,
        request_nonce: req.get("x-captcha-request-nonce") || "",
        ip_hash: req.captchaIpHash,
        user_agent_hash: req.captchaUserAgentHash,
        account_id_hash: req.user?.captchaAccountHash || "",
        device_id_hash: req.get("x-captcha-device-id-hash") || "",
        consume: true
      })
    }).then((response) => {
      if (!response.ok) throw new Error("ticket service unavailable");
      return response.json();
    })
  );

  if (!result) return handleCaptchaUnavailable(res, "TICKET_SERVICE_UNAVAILABLE") || next();

  if (!result.valid) {
    return res.status(403).json({ action: "block", reason: result.reason || "TICKET_INVALID" });
  }

  writeClearance(res, result.clearance_token, result.clearance_ttl_seconds);
  return next();
}
```

`ip_hash` 和 `user_agent_hash` 要与创建 challenge 时绑定的上下文一致。中间件和 Gateway 内部使用 `sha256:<前 32 位 hex>` 的形式；自研接入也应保持同样格式。

## 策略评估

```ts
async function evaluatePolicy(req, res, next) {
  const decision = await callCaptcha((signal) =>
    fetch("https://captcha.example.com/api/v1/policy/evaluate", {
      method: "POST",
      signal,
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
        clearance: req.get("x-captcha-clearance") || req.cookies?.captcha_clearance || "",
        request_nonce: req.get("x-captcha-request-nonce") || "",
        account_id_hash: req.user?.captchaAccountHash || "",
        device_id_hash: req.get("x-captcha-device-id-hash") || "",
        headers: {
          "x-request-id": req.get("x-request-id") || ""
        }
      })
    }).then((response) => {
      if (!response.ok) throw new Error("policy service unavailable");
      return response.json();
    })
  );

  if (!decision) return handleCaptchaUnavailable(res, "POLICY_UNAVAILABLE") || next();

  if (decision.clearance_token) {
    writeClearance(res, decision.clearance_token, decision.clearance_ttl_seconds);
  }

  if (["allow", "observe", "pass", "skip_challenge"].includes(decision.action)) return next();

  if (["challenge", "challenge_harder", "step_up_challenge", "rate_limit"].includes(decision.action)) {
    return res.status(403).json({
      action: decision.action,
      challenge_url: decision.challenge_url,
      session_id: decision.session_id,
      scene: decision.scene,
      challenge_type: decision.challenge_type,
      reason: decision.reason
    });
  }

  if (["block", "cooldown", "require_business_verify"].includes(decision.action)) {
    return res.status(403).json({
      action: decision.action,
      reason: decision.reason,
      cooldown_seconds: decision.cooldown_seconds,
      business_verify_type: decision.business_verify_type
    });
  }

  return res.status(403).json({ action: "block", reason: "UNSUPPORTED_POLICY_DECISION" });
}
```

## 写入 clearance

```ts
function writeClearance(res, token, ttlSeconds = 600) {
  if (!token) return;

  res.setHeader("X-Captcha-Clearance", token);
  res.cookie("captcha_clearance", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: true,
    maxAge: ttlSeconds * 1000,
    path: "/"
  });
}
```

如果你的地区或业务对 cookie/terminal storage 有更严格要求，可以把 clearance 只放在服务端 session 或自有网关状态里，但接入成本会更高。

## 字段约定

| 字段 | 说明 |
|---|---|
| `client_id` / `scene` | 应用和业务场景。 |
| `path` / `method` | 当前业务请求，用于匹配路由策略。 |
| `ip` / `user_agent` | 由后端或可信代理解析出的原始值，策略接口会自行计算 hash。 |
| `ip_hash` / `user_agent_hash` | ticket 核销接口使用的绑定摘要。 |
| `ticket` | Runtime 返回的一次性 ticket，有则优先消费。 |
| `clearance` | 已有通行态，通常来自 `captcha_clearance`。 |
| `request_nonce` | 高风险动作的一次性 nonce。 |
| `account_id_hash` / `device_id_hash` | 可选账号/设备维度，必须是业务后端生成的 hash。 |
| `headers` | 只传低敏 allowlist header，例如 request id 或 traceparent。 |

## HTTP 和 gRPC

HTTP 适合早期联调和普通平台接入。gRPC 适合作为长期内部数据面，提供策略评估、ticket 消费、配置快照、配置监听和事件上报。

完整字段和鉴权见 [HTTP / gRPC API](api-reference.md)。

## 继续阅读

- [快速接入](quickstart.md)
- [后端 ticket 核销](backend-ticket-verification.md)
- [中间件接入](middleware-integration.md)

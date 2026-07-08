# Custom Integration

Language: [中文](../zh/custom-integration.md) | English

Use this path for a custom Gateway, service mesh, platform control plane, or centralized security entry. Your integration sends request context to CaptCha and owns allow, challenge, block, clearance writes, and platform-unavailable failure behavior.

## When To Choose It

- Business services should not depend directly on CaptCha middleware.
- You already have a Gateway, service mesh, or unified API entry.
- You want your own policy orchestration, logs, rollout, and failure handling.
- You need HTTP / gRPC as an internal data plane.

## Recommended Loop

Custom integrations should follow the same order as the middleware:

1. Decide whether the current request needs protection.
2. If `X-Captcha-Ticket` is present, call `/api/v1/tickets/verify` first with `consume=true`.
3. Valid ticket: write short-lived clearance and allow the business request.
4. Invalid ticket: return 403; do not continue to policy evaluation.
5. No ticket: read `X-Captcha-Clearance` or `captcha_clearance`, then call `/api/v1/policy/evaluate`.
6. Policy returns allow/observe/pass: allow; challenge/block: respond with the returned action.
7. Platform timeout, 5xx, network error, or circuit breaker open: apply your own `fail_open` / `fail_close`.

## Failure Policy Template

Custom integration has no built-in middleware, so you must implement the failure policy yourself. Prefer an environment variable or per-route configuration.

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

Rules:

- Platform unavailable, timeout, or circuit breaker open: may fail open or fail close by configuration.
- Invalid ticket, consumed ticket, route/nonce/account/device binding mismatch: treat as failed verification; do not fail open.
- Unknown action: fail closed.
- Event reporting failure must never block the business request.

## Consume Tickets

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

`ip_hash` and `user_agent_hash` must match the context bound when the challenge was created. Middleware and Gateway use `sha256:<first 32 hex chars>`; custom integrations should keep the same format.

## Evaluate Policy

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

## Write Clearance

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

If your region or business policy has stricter cookie/terminal-storage requirements, you can store clearance only in a server-side session or gateway state, but that increases integration cost.

## Field Contract

| Field | Purpose |
|---|---|
| `client_id` / `scene` | Application and business scene. |
| `path` / `method` | Current business request, used for route policy matching. |
| `ip` / `user_agent` | Raw values resolved by the backend or trusted proxy; policy evaluation hashes them internally. |
| `ip_hash` / `user_agent_hash` | Binding summaries used by ticket consumption. |
| `ticket` | One-time ticket returned by the Runtime; consume it first when present. |
| `clearance` | Existing pass state, usually from `captcha_clearance`. |
| `request_nonce` | One-time nonce for high-risk actions. |
| `account_id_hash` / `device_id_hash` | Optional account/device dimensions generated as hashes by the business backend. |
| `headers` | Only low-sensitive allowlisted headers, such as request id or traceparent. |

## HTTP And gRPC

HTTP is convenient for early integration and platform adapters. gRPC is better as a long-running internal data plane for policy evaluation, ticket consumption, config snapshots, config watching, and event reporting.

See [HTTP / gRPC API](api-reference.md) for the full field and authentication contract.

## Next

- [Quickstart](quickstart.md)
- [Backend Ticket Verification](backend-ticket-verification.md)
- [Middleware Integration](middleware-integration.md)

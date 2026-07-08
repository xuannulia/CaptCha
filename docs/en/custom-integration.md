# Custom Integration

Language: [中文](../zh/custom-integration.md) | English

Use this path for a custom Gateway, service mesh, platform control plane, or centralized security entry. Your integration sends request context to CaptCha and owns allow, challenge, block, and cookie handling.

## When To Choose It

- Business services should not depend directly on CaptCha middleware.
- You already have a Gateway, service mesh, or unified API entry.
- You want your own policy orchestration, logs, rollout, and failure handling.
- You need HTTP / gRPC as an internal data plane.

## Minimal Policy Evaluation

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

## Handle The Returned Action

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

Fail closed on unknown actions instead of passing the request through.

## Field Contract

| Field | Purpose |
|---|---|
| `client_id` / `scene` | Application and business scene. |
| `path` / `method` | Current business request, used for route policy matching. |
| `ip` / `user_agent` | Raw values resolved by the backend or trusted proxy; CaptCha hashes them internally. |
| `ticket` | One-time ticket returned by the Runtime; consumed first when present. |
| `clearance` | Existing pass state, usually from `captcha_clearance`. |
| `request_nonce` | One-time nonce for high-risk actions. |
| `account_id_hash` / `device_id_hash` | Optional account/device dimensions generated as hashes by the business backend. |

## HTTP And gRPC

HTTP is convenient for early integration and platform adapters. gRPC is better as a long-running internal data plane for policy evaluation, ticket consumption, config snapshots, config watching, and event reporting.

See [HTTP / gRPC API](api-reference.md) for the full field and authentication contract.

## Next

- [Quickstart](quickstart.md)
- [Backend Ticket Verification](backend-ticket-verification.md)
- [Middleware Integration](middleware-integration.md)

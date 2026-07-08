# Quickstart

Language: [中文](../zh/quickstart.md) | English

This page keeps only the shortest integration path. The examples use `https://captcha.example.com` as your public CaptCha Runtime/API origin; if Runtime and API use separate origins, use the Runtime origin for iframe and the API origin for backend consumption. Keep `client_secret` only in backend, middleware, or Gateway code.

## 1. Start With Docker

```bash
docker compose up --build
```

Configure real tokens, CORS origins, PostgreSQL, and Redis in your deployment platform for production; this quickstart does not expand those settings.

## 2. Minimal Iframe Integration

Open the Runtime before a protected action. The fixed `request_nonce` is only for illustration; in production, generate it on your backend for each protected action.

```html
<iframe
  src="https://captcha.example.com/?client_id=demo&scene=login&captcha_type=AUTO&route=/api/login&request_nonce=nonce-123"
  width="360"
  height="420"
  title="CaptCha"
></iframe>

<script>
  window.addEventListener("message", (event) => {
    if (event.origin !== "https://captcha.example.com") return;
    if (event.data?.type !== "CAPTCHA_SUCCESS") return;

    fetch("/api/login", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-captcha-ticket": event.data.ticket,
        "x-captcha-request-nonce": "nonce-123"
      },
      body: JSON.stringify({ username: "alice", password: "secret" })
    });
  });
</script>
```

## 3. Consume The Ticket On The Backend

Consume the ticket before your backend completes login, registration, payment, or another protected action. Treat failed consumption as failed verification.

```ts
app.post("/api/login", async (req, res) => {
  const result = await fetch("https://captcha.example.com/api/v1/tickets/verify", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-captcha-client-secret": process.env.CAPTCHA_CLIENT_SECRET || ""
    },
    body: JSON.stringify({
      client_id: "demo",
      scene: "login",
      ticket: req.get("x-captcha-ticket") || "",
      route: "/api/login",
      request_nonce: req.get("x-captcha-request-nonce") || "",
      consume: true
    })
  }).then((response) => response.json());

  if (!result.valid) {
    return res.status(403).json({ error: result.reason || "CAPTCHA_FAILED" });
  }

  return res.json({ ok: true });
});
```

## 4. Minimal Middleware Integration

If your service can add middleware, let it handle tickets, clearance, policy, and failure behavior.

```ts
import { createCaptchaMiddleware } from "@captcha/express-middleware";

app.use(createCaptchaMiddleware({
  platformURL: "https://captcha.example.com",
  clientID: "demo",
  clientSecret: process.env.CAPTCHA_CLIENT_SECRET,
  shouldProtect: (req) => req.path.startsWith("/api")
}));
```

The middleware reads `X-Captcha-Ticket`, `X-Captcha-Clearance`, and `captcha_clearance` by default. It sends request IP/User-Agent hashes plus optional account/device hashes to CaptCha, and writes short-lived clearance after a successful decision.

## 5. Custom Integration

Use the policy API when you are building a custom Gateway, service mesh adapter, or platform control plane. Your integration owns challenge, allow, block, and cookie handling.

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
  return res.status(403).json(decision);
}
return res.status(403).json({ error: decision.reason || "CAPTCHA_BLOCKED" });
```

Minimal rules:

- Iframe integration: get a ticket, then consume it on the backend.
- Middleware integration: let middleware handle ticket, clearance, IP/UA binding, policy, and reporting.
- Custom integration: pass ticket, clearance, route, nonce, IP/UA, account/device hashes, and fail closed on unknown actions.
- `captcha_clearance` is a short-lived security/functionality cookie; in the EU and similar ePrivacy contexts, document its purpose, TTL, and scope in your cookie policy.

Next:

- [Full Integration Guide](integration-guide.md)
- [HTTP / gRPC API](api-reference.md)
- [Express middleware](../../integrations/express-middleware/README.md)

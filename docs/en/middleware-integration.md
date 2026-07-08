# Middleware Integration

Language: [中文](../zh/middleware-integration.md) | English

Use middleware when your business service can modify its request chain. The middleware handles tickets, clearance, policy evaluation, and failure behavior before your business handler runs.

## When To Choose It

- Your service code can add middleware.
- You want one place to protect `/api`, login, registration, comment, payment, or similar routes.
- You want `captcha_clearance` handled automatically to reduce repeated challenges.
- You need IP/User-Agent plus optional account/device hashes bound to tickets and clearance.

## Runtime Entries

| Runtime | Package |
|---|---|
| Node/Express | [Express middleware](../../integrations/express-middleware/README.md) |
| Go `net/http` | [Go middleware](../../integrations/go-middleware/README.md) |
| Python ASGI | [Python middleware](../../integrations/python-middleware/README.md) |
| Java `HttpHandler` | [Java middleware](../../integrations/java-middleware/README.md) |
| ASP.NET Core | [ASP.NET Core middleware](../../integrations/dotnet-middleware/README.md) |

## Minimal Express Example

```ts
import { createCaptchaMiddleware } from "@captcha/express-middleware";

app.use(createCaptchaMiddleware({
  platformURL: "https://captcha.example.com",
  clientID: "demo",
  clientSecret: process.env.CAPTCHA_CLIENT_SECRET,
  shouldProtect: (req) => req.path.startsWith("/api")
}));
```

## Default Behavior

- Reads `X-Captcha-Ticket` first and consumes the ticket.
- Reads `X-Captcha-Clearance` or `captcha_clearance`.
- Calls `/api/v1/policy/evaluate` for policy decisions.
- Writes `X-Captcha-Clearance` and a short-lived HttpOnly cookie after success.
- Hashes request IP/User-Agent before using them as ticket context.
- Optionally reads `X-Captcha-Account-ID-Hash` and `X-Captcha-Device-ID-Hash`.
- Applies fail-open or fail-close behavior when the platform is unavailable.

## Account And Device Markers

`account_id_hash` and `device_id_hash` are optional. Lightweight integrations without a uid can rely on tickets, short-lived clearance, route, request nonce, IP hash, and User-Agent hash.

When an account or anonymous visitor identifier exists, hash it on the business backend first, preferably with HMAC:

```ts
app.use(createCaptchaMiddleware({
  platformURL: "https://captcha.example.com",
  clientID: "demo",
  clientSecret: process.env.CAPTCHA_CLIENT_SECRET,
  resolveAccountIDHash: (req) => req.user?.captchaAccountHash || "",
  resolveDeviceIDHash: (req) => req.cookies?.visitor_hash || "",
  shouldProtect: (req) => req.path.startsWith("/api")
}));
```

Do not expose raw user IDs, phone numbers, email addresses, or long-lived device IDs to the browser or to CaptCha.

## Cookie Note

Middleware writes a short-lived security/functionality cookie such as `captcha_clearance`. It marks that the current browser session has passed verification and is not intended for advertising, analytics, or cross-site tracking. In the EU and similar ePrivacy regimes, document its purpose, TTL, and scope in your cookie policy.

## Next

- [Quickstart](quickstart.md)
- [Backend Ticket Verification](backend-ticket-verification.md)
- [Custom Integration](custom-integration.md)

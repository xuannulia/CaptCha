# Middleware Integration

Language: [中文](../zh/middleware-integration.md) | English

Use middleware when your business service can modify its request chain. The middleware consumes tickets, reads and writes clearance, calls policy evaluation, and applies a configured behavior when the CaptCha platform is unavailable. Your business handler only sees requests that have been allowed.

## When To Choose It

- Your service code can add middleware.
- You want one place to protect `/api`, login, registration, comment, payment, or similar routes.
- You want `captcha_clearance` handled automatically to reduce repeated challenges.
- You need IP/User-Agent, route, request nonce, and optional account/device hashes bound to tickets and clearance.

## Runtime Entries

| Runtime | Package |
|---|---|
| Node/Express | [Express middleware](../../integrations/express-middleware/README.md) |
| Go `net/http` | [Go middleware](../../integrations/go-middleware/README.md) |
| Python ASGI | [Python middleware](../../integrations/python-middleware/README.md) |
| Java `HttpHandler` | [Java middleware](../../integrations/java-middleware/README.md) |
| ASP.NET Core | [ASP.NET Core middleware](../../integrations/dotnet-middleware/README.md) |

## Minimal Example

```ts
import { createCaptchaMiddleware } from "@captcha/express-middleware";

app.use(createCaptchaMiddleware({
  platformURL: "https://captcha.example.com",
  clientID: "demo",
  clientSecret: process.env.CAPTCHA_CLIENT_SECRET,
  shouldProtect: (req) => req.path.startsWith("/api")
}));
```

## Failure Policy

The default is `fail_open`: when the CaptCha platform times out, is unavailable, or is short-circuited by the circuit breaker, the request continues to the next business handler. This protects business availability, but risk control is temporarily degraded.

Use `fail_close` when platform unavailability must block the protected action. It returns HTTP 503 and does not call the business handler. This is better for payment, password changes, bulk export, admin actions, and other high-value flows.

```ts
app.use(createCaptchaMiddleware({
  platformURL: "https://captcha.example.com",
  clientID: "demo",
  clientSecret: process.env.CAPTCHA_CLIENT_SECRET,
  failPolicy: "fail_close",
  timeoutMs: 1500,
  circuitBreakerFailureThreshold: 3,
  circuitBreakerCooldownMs: 5000,
  shouldProtect: (req) => req.path.startsWith("/api/pay")
}));
```

| Case | Default result | Configurable |
|---|---|---|
| `/api/v1/policy/evaluate` timeout, 5xx, or network error | `fail_open` allows; `fail_close` returns 503 | Yes, with `failPolicy` |
| `/api/v1/tickets/verify` timeout, 5xx, or network error | `fail_open` allows; `fail_close` returns 503 | Yes, with `failPolicy` |
| Circuit breaker open after repeated failures | Skip platform calls and apply `failPolicy` during cooldown | Yes, with breaker settings |
| Ticket is present and platform returns `valid=false` | Return 403 | No. Invalid tickets must not fall back to allow |
| Platform returns an unknown action | Return 403 | No. Unknown actions fail closed |
| Policy returns `block` / `cooldown` / `require_business_verify` | Return 403 | Controlled by platform policy |
| Policy returns `challenge` / `challenge_harder` / `rate_limit` | Return 403 with challenge details | Controlled by platform policy |

Recommendations:

- Use `fail_open` with short timeout and circuit breaker for ordinary content APIs.
- Use `fail_close` for high-value writes, and prepare a clear 503 response in the business UX.
- Do not allow invalid tickets, nonce mismatches, or route mismatches. Those are verification failures, not platform outages.

## Request Flow

1. `shouldProtect` returns false: continue to the business handler.
2. Request has `X-Captcha-Ticket`: call `/api/v1/tickets/verify` with `consume=true`.
3. Ticket is valid: write `X-Captcha-Clearance` and `captcha_clearance`, then continue.
4. Ticket is invalid: return 403; do not call policy evaluation.
5. No ticket: read `X-Captcha-Clearance` or `captcha_clearance`, then call `/api/v1/policy/evaluate`.
6. Policy allows: continue; policy challenges or blocks: return 403.
7. Platform call fails: apply `failPolicy` and report the event asynchronously.

## Common Options

| Option | Default | Purpose |
|---|---|---|
| `platformURL` / `platform_url` / `PlatformURL` | Required | CaptCha API origin. |
| `clientID` | `demo` | Application identifier. |
| `clientSecret` | Empty | Server-side platform authentication. |
| `ticketHeader` | `X-Captcha-Ticket` | Header carrying Runtime tickets. |
| `clearanceHeader` | `X-Captcha-Clearance` | Clearance header. |
| `clearanceCookieName` | `captcha_clearance` | Short-lived HttpOnly cookie; set empty to disable cookie writes. |
| `clearanceCookieSecure` | `false` | Enable for HTTPS production deployments. |
| `requestNonceHeader` | `X-Captcha-Request-Nonce` | Nonce for high-risk actions. |
| `resourceTagHeader` | `X-Captcha-Resource-Tag` | Preferred material group or campaign tag. |
| `accountIDHashHeader` | `X-Captcha-Account-ID-Hash` | Optional account hash. |
| `deviceIDHashHeader` | `X-Captcha-Device-ID-Hash` | Optional device or anonymous visitor hash. |
| `riskScoreHeader` / `riskLevelHeader` | Matching `X-Captcha-*` | Business-side risk context. |
| `modelScoreHeader` / `modelModeHeader` | Matching `X-Captcha-*` | External model context. |
| `headerAllowlist` | Empty | Only explicitly allowlisted low-sensitive headers are sent to CaptCha. |
| `trustedProxyCIDRs` | Empty | Trust `X-Forwarded-For` only when the direct peer is in this list. |
| `timeoutMs` / `Timeout` | About 1500ms | Platform call timeout. |
| `failPolicy` | `fail_open` | Allow or return 503 when the platform is unavailable. |
| `circuitBreakerFailureThreshold` | `0` | Enable the circuit breaker when greater than 0. |
| `circuitBreakerCooldown*` | `0` | Circuit breaker cooldown. |

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

## Production Checklist

- Keep `clientSecret` only in backend environment variables.
- Choose `failPolicy` per route value; do not configure all routes as fail-close by habit.
- Keep timeout short so CaptCha cannot slow down your business service.
- Monitor or log `POLICY_UNAVAILABLE` and `TICKET_SERVICE_UNAVAILABLE`.
- Allowlist only low-sensitive headers; do not forward `authorization` or `cookie`.
- Configure `trustedProxyCIDRs` behind reverse proxies; otherwise do not trust `X-Forwarded-For`.

## Next

- [Quickstart](quickstart.md)
- [Backend Ticket Verification](backend-ticket-verification.md)
- [Custom Integration](custom-integration.md)

# CaptCha Express Middleware

Reference Express middleware for CaptCha platform integration.

It is intentionally thin: the platform owns policy, challenge generation, ticket state, short-lived clearance state, rate limits, and audit. The middleware extracts request context, consumes a ticket first when one is present, stores any returned clearance token, otherwise calls the platform policy API, reports ticket and fail-policy outcomes asynchronously, and decides whether to call `next()`.

```ts
import express from "express";
import { createCaptchaMiddleware } from "@captcha/express-middleware";

const app = express();

app.use(createCaptchaMiddleware({
  platformURL: "http://localhost:8080",
  clientID: "demo",
  clientSecret: "cap_secret_xxx",
  ticketHeader: "x-captcha-ticket",
  clearanceHeader: "x-captcha-clearance",
  clearanceCookieName: "captcha_clearance",
  requestNonceHeader: "x-captcha-request-nonce",
  resourceTagHeader: "x-captcha-resource-tag",
  accountIDHashHeader: "x-captcha-account-id-hash",
  deviceIDHashHeader: "x-captcha-device-id-hash",
  riskScoreHeader: "x-captcha-risk-score",
  riskLevelHeader: "x-captcha-risk-level",
  modelScoreHeader: "x-captcha-model-score",
  modelModeHeader: "x-captcha-model-mode",
  headerAllowlist: ["x-request-id", "traceparent"],
  trustedProxyCIDRs: ["10.0.0.0/8"],
  circuitBreakerFailureThreshold: 3,
  circuitBreakerCooldownMs: 5000,
  failPolicy: "fail_open",
  shouldProtect: (req) => req.path.startsWith("/api")
}));
```

Behavior:

- `clientSecret`: sent as `X-Captcha-Client-Secret` to policy, ticket, and event APIs when configured.
- `clearanceHeader` / `clearanceCookieName`: read existing clearance from the request and write newly minted clearance to the response after successful ticket consume or clearance refresh.
- `requestNonceHeader`: sent to ticket verification as `request_nonce` when a nonce-bound ticket is used.
- `resourceTagHeader`: sent to policy evaluation as `resource_tag` when a tagged challenge resource should be preferred.
- `accountIDHashHeader` / `deviceIDHashHeader`: sent to policy evaluation as `account_id_hash` and `device_id_hash`.
- `riskScoreHeader` / `riskLevelHeader`: sent to policy evaluation as server-side risk context for `risk_based` route thresholds.
- `modelScoreHeader` / `modelModeHeader`: optional model context. `shadow` mode does not affect decisions; `observe` and `enforce` modes can participate as risk-score inputs when route thresholds are configured.
- `headerAllowlist`: optional list of low-sensitive business headers to include in policy evaluation. It defaults to empty, so headers such as `authorization` and `cookie` are never forwarded unless explicitly allowlisted.
- `circuitBreakerFailureThreshold` / `circuitBreakerCooldownMs`: optional short circuit breaker for repeated policy/ticket API failures. When open, the middleware skips blocking platform calls and applies `failPolicy` during the cooldown window.
- ticket consumption also sends SHA-256 summaries of the request IP and User-Agent so platform-issued IP/UA-bound tickets can be consumed safely.
- request with ticket: call `/api/v1/tickets/verify` with `consume=true`; continue only when valid, then store the returned clearance token in the response header and an HttpOnly cookie when the response object supports it.
- request with clearance: send it to policy evaluation. The platform validates the server-side token against `client_id`, `scene`, IP hash, User-Agent hash, and any supplied account/device hash. Anonymous flows can rely on the clearance cookie and should also provide a device or anonymous visitor hash when available.
- ticket results and fail-open/fail-close outcomes: report asynchronously to `/api/v1/events/report`.
- `X-Forwarded-For`: ignored unless the direct peer IP is in `trustedProxyCIDRs`.
- `allow`, `observe`, `pass`: continue to the next handler.
- `challenge`, `challenge_harder`: return HTTP 403 with `challenge_url` and `session_id`.
- `block`: return HTTP 403.
- platform error: fail open by default, or fail close with HTTP 503.

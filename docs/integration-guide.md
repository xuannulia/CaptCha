# CaptCha Integration Guide

This guide is written in the order most teams actually adopt CaptCha: look at the demo, wire the smallest useful path, then move the policy work closer to the edge when the deployment needs it.

CaptCha should stay a server-owned verification platform. The browser runtime renders challenges and returns interaction facts; answers, scoring rules, tickets, clearance, rate limits, audit, and risk signals stay on the platform side.

![CaptCha demo page](assets/demo-page.png)

## Difficulty Ladder

| Level | Path | What You Touch |
|---|---|---|
| 0 | Demo page | Nothing in your app. You only run the platform and runtime locally. |
| 1 | Runtime iframe + backend ticket check | One iframe or redirect, plus one backend API call after success. |
| 2 | Express middleware | A normal Node/Express middleware layer. |
| 3 | Gateway reverse proxy | A proxy in front of an existing service. |
| 4 | Direct HTTP/gRPC integration | Your own gateway, service mesh, or platform control plane. |
| 5 | Production operations | Admin token, storage, Redis, resource materials, audit, model versions, and release checks. |

## Level 0: Try The Demo

Run the API server:

```bash
go run ./cmd/captcha-server
```

Run the runtime in another terminal:

```bash
npm run dev:runtime
```

Open:

```text
http://localhost:5173/demo
```

Use this page to check the feel of the challenge types and the packaged demo materials before you make integration choices. It is also a quick way to catch visual regressions after changing renderer or resource code.

## Level 1: Runtime Iframe And Ticket Check

This is the smallest production-shaped path. Your app opens the runtime when a user reaches a protected action. After the user passes, your backend verifies or consumes the returned ticket before it completes the action.

First create an application in the admin console. Keep the generated client secret on the backend only.

- `client_id` is public and may be sent to the iframe runtime.
- `client_secret` is private and belongs only in trusted backend, Gateway, or middleware code.
- Public challenge creation does not use the client secret.
- Policy, ticket, config, and event APIs require the client secret when the application has one.

Minimum iframe URL:

```text
https://captcha.example.com/?client_id=your-client&scene=login&captcha_type=AUTO
```

For real protected actions, bind the ticket to the route and a one-time request nonce:

```text
https://captcha.example.com/?client_id=your-client&scene=login&captcha_type=AUTO&route=/api/login&request_nonce=nonce-123
```

Useful runtime query parameters:

| Parameter | Purpose |
|---|---|
| `client_id` | Application identifier. |
| `scene` | Business scene, such as `login`, `register`, `verify`, or `pay`. |
| `captcha_type` | Concrete type, `AUTO`, or `RANDOM` for local demos. |
| `route` | Business route bound to the ticket. |
| `request_nonce` | One-time request nonce bound to the ticket. |
| `return_url` | Redirect-mode target; it must pass the platform allowlist. |
| `resource_tag` | Optional material tag for resource selection. |
| `input_device` | Optional collection hint: `mouse`, `trackpad`, or `touch`. |

The runtime posts `CAPTCHA_SUCCESS` to its parent with a one-time `ticket`. In redirect mode, it redirects to `return_url` with `captcha_ticket`, `captcha_session_id`, and the bound context.

Verify the ticket before completing the protected action:

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
    "ip": "203.0.113.10",
    "user_agent": "browser user-agent"
  }'
```

For follow-up requests, consume the ticket and mint clearance. Clearance is server-side state. It can be bound to `client_id`, `scene`, route, request nonce, IP hash, User-Agent hash, account hash, and device hash. Anonymous flows should prefer a clearance cookie plus a device or visitor hash when available. Do not treat IP as a broad allowlist.

## Level 2: Express Middleware

Use this path when the protected service is Node/Express and you want CaptCha to sit in the normal request chain.

```ts
import express from "express";
import { createCaptchaMiddleware } from "@captcha/express-middleware";

const app = express();

app.use(createCaptchaMiddleware({
  platformURL: "https://captcha.example.com",
  clientID: "your-client",
  clientSecret: process.env.CAPTCHA_CLIENT_SECRET,
  clearanceHeader: "x-captcha-clearance",
  clearanceCookieName: "captcha_clearance",
  requestNonceHeader: "x-captcha-request-nonce",
  accountIDHashHeader: "x-captcha-account-id-hash",
  deviceIDHashHeader: "x-captcha-device-id-hash",
  headerAllowlist: ["x-request-id", "traceparent"],
  shouldProtect: (req) => req.path.startsWith("/api")
}));
```

The middleware consumes tickets, stores clearance, calls policy evaluation, reports fail-open/fail-close outcomes asynchronously, and lets allowed requests continue to `next()`. It deliberately stays thin; CaptCha still owns policy, ticket state, clearance state, rate limits, audit, and risk scoring.

## Level 3: Gateway Reverse Proxy

Use the Gateway when you want to protect an existing HTTP service without touching every route.

```bash
CAPTCHA_UPSTREAM_URL=http://localhost:3000 \
CAPTCHA_PLATFORM_URL=http://localhost:8080 \
CAPTCHA_CLIENT_ID=your-client \
CAPTCHA_CLIENT_SECRET=cap_secret_xxx \
CAPTCHA_GATEWAY_HEADER_ALLOWLIST=x-request-id,traceparent \
  go run ./cmd/captcha-gateway
```

The Gateway:

- consumes `X-Captcha-Ticket` first when present;
- writes returned clearance to `X-Captcha-Clearance` and an HttpOnly cookie;
- forwards existing clearance to policy evaluation;
- asks CaptCha policy before proxying protected requests;
- returns challenge details when policy says `challenge`;
- blocks invalid or consumed tickets;
- forwards only explicitly allowlisted business headers.

Use gRPC for the Gateway policy path when the platform is close on the network:

```bash
CAPTCHA_GATEWAY_POLICY_TRANSPORT=grpc \
CAPTCHA_PLATFORM_GRPC_ADDR=captcha.example.com:9090 \
CAPTCHA_PLATFORM_GRPC_TOKEN=change-me-grpc \
  go run ./cmd/captcha-gateway
```

## Level 4: Direct HTTP Or gRPC APIs

Use this path when you are building a custom gateway, service mesh adapter, or internal platform integration.

HTTP is easiest to inspect during early integration:

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
    "user_agent": "browser user-agent"
  }'
```

gRPC is the better long-running data-plane path. It gives you typed contracts for policy evaluation, ticket consumption, config snapshots, config watching, and event reporting. Protect gRPC with `CAPTCHA_GRPC_TOKEN` or an equivalent deployment boundary, and keep application client secrets separate from the platform token.

## Level 5: Production Controls

Before deployment, configure:

- `CAPTCHA_ENV=production`
- `CAPTCHA_ADMIN_TOKEN`
- `CAPTCHA_GRPC_TOKEN`
- `CAPTCHA_METRICS_TOKEN`
- `CAPTCHA_ALLOWED_ORIGINS`
- `CAPTCHA_ALLOWED_RETURN_URL_ORIGINS`
- `CAPTCHA_POSTGRES_DSN`
- `CAPTCHA_REDIS_ADDR`
- `CAPTCHA_SEED_DEMO=false`

Production mode refuses to start when these controls are missing or unsafe.

## Rules Worth Keeping

- Do not put `client_secret`, admin token, metrics token, or gRPC token in browser code.
- Do not accept client-supplied `target`, `tolerance`, `answer_seed`, `verify_rule`, `score_rule`, or scoring thresholds.
- Bind tickets to route and nonce for high-risk actions.
- Treat ticket consumption failure as a protected-request failure.
- Forward business headers only by allowlist.
- Keep resource URLs, object storage URLs, and model artifacts private unless they are intended to be public.

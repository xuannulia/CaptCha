# CaptCha API Reference

This document is for custom gateways, service mesh adapters, internal platform control planes, and backend integrations. For ordinary application integration, start with the [Integration Guide](integration-guide.md) and the middleware README files.

## API Layers

| Layer | Protocol | Purpose |
|---|---|---|
| Browser Runtime API | HTTP JSON | Browser-side challenge creation, rendering, refresh, and verification submission. |
| Data-plane API | HTTP JSON / gRPC | Policy evaluation, ticket verification, config sync, and event reporting for Gateways, middleware, and backend services. |
| Admin API | HTTP JSON | Application, policy, resource, audit, sample, and model-version management. |
| Metrics | HTTP text | Prometheus metrics scraping. |

## Authentication

| Caller | Authentication |
|---|---|
| Browser Runtime | No `client_secret`. Protection relies on CORS, short TTL, server-side answers, one-time tickets, and deployment boundaries. |
| HTTP data-plane API | When an application has a secret, send `X-Captcha-Client-Secret: <secret>` or `Authorization: Bearer <secret>`. |
| gRPC data-plane API | Platform token: metadata `x-captcha-grpc-token: <token>` or `authorization: Bearer <token>`. Application secret: metadata `x-captcha-client-secret: <secret>`, or bearer. |
| Admin API | `X-Captcha-Admin-Token: <token>` or `Authorization: Bearer <token>`. |
| Metrics | `X-Captcha-Metrics-Token: <token>` or `Authorization: Bearer <token>`. |

Do not put `client_secret`, admin tokens, metrics tokens, or gRPC tokens in browser code.

## HTTP API

The default HTTP port is `:8080`. Replace `https://captcha.example.com` with your platform URL.

### Health And Metrics

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Process health check. |
| `GET` | `/metrics` | Prometheus text metrics; production deployments can protect it with a metrics token. |

### Browser Runtime API

These endpoints are called by the Runtime frontend. Responses do not expose answers, targets, tolerances, scoring rules, or thresholds.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/challenge/sessions` | Create a challenge session. |
| `GET` | `/api/v1/challenge/sessions/{session_id}` | Fetch challenge render data. |
| `POST` | `/api/v1/challenge/sessions/{session_id}/verify` | Submit answer and interaction trajectory; returns a one-time ticket on success. |
| `POST` | `/api/v1/challenge/sessions/{session_id}/refresh` | Refresh the challenge. |

Common session creation fields:

| Field | Purpose |
|---|---|
| `client_id` | Application identifier. |
| `scene` | Business scene, such as `login`, `register`, or `pay`. |
| `captcha_type` | Concrete captcha type, or `AUTO` / `RANDOM`. |
| `route` | Business route bound to the ticket. |
| `request_nonce` | One-time request nonce bound to the ticket. |
| `return_url` | Redirect-mode target; must pass the allowlist. |
| `resource_tag` | Optional material-selection tag. |

Example:

```bash
curl -X POST https://captcha.example.com/api/v1/challenge/sessions \
  -H 'content-type: application/json' \
  -d '{
    "client_id": "your-client",
    "scene": "login",
    "captcha_type": "AUTO",
    "route": "/api/login",
    "request_nonce": "nonce-123"
  }'
```

### Data-plane HTTP API

These endpoints are called by backend services, Gateways, or middleware. When the application has a secret, include it.

#### Verify Ticket

```text
POST /api/v1/tickets/verify
```

Verifies or consumes a one-time ticket returned by the Runtime. When `consume=true`, the ticket is consumed and a clearance can be returned.

Request fields:

| Field | Required | Purpose |
|---|---|---|
| `ticket` | Yes | One-time ticket returned by the Runtime. |
| `client_id` | Yes | Application identifier. |
| `scene` | Yes | Business scene. |
| `route` | No | Required when the ticket was bound to a route. |
| `request_nonce` | No | Required when the ticket was bound to a nonce. |
| `ip_hash` | No | Required when the ticket was bound to an IP hash. |
| `user_agent_hash` | No | Required when the ticket was bound to a User-Agent hash. |
| `account_id_hash` | No | External account identifier hash; required to match when the ticket is account-bound. |
| `device_id_hash` | No | External device or visitor identifier hash; required to match when the ticket is device-bound. |
| `consume` | No | Whether to consume the ticket and return clearance. |

Example:

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
    "consume": true
  }'
```

Successful verification returns `valid=true`. Failed verification may still return HTTP `200`; check `valid=false` and `reason`, such as `NOT_FOUND`, `EXPIRED`, or `CONSUMED`.

Custom integrations must keep field shape straight: `/api/v1/tickets/verify` accepts `ip_hash` / `user_agent_hash` because tickets store bound hashes; `/api/v1/policy/evaluate` accepts the server-resolved raw `ip` / `user_agent`, and the platform hashes them before ticket or clearance validation.

#### Evaluate Policy

```text
POST /api/v1/policy/evaluate
```

Returns an action based on ticket, clearance, application status, IP policy, route policy, rate limits, and risk context.

Request fields:

| Field | Purpose |
|---|---|
| `client_id` | Application identifier. |
| `scene` | Business scene. |
| `path` | Business request path. |
| `method` | HTTP method. |
| `ip` | Source IP parsed by the backend or trusted proxy. |
| `user_agent` | Browser User-Agent. |
| `account_id_hash` | External account identifier hash. |
| `device_id_hash` | External device or visitor identifier hash. |
| `ticket` | Optional. Consumed before normal policy evaluation. |
| `clearance` | Optional existing clearance. |
| `request_nonce` | Optional one-time request nonce. |
| `resource_tag` | Optional material-selection tag. |
| `risk_score` / `risk_level` | Optional risk signal from the integrating service. |
| `model_score` / `model_mode` | Optional model risk signal. |
| `headers` | Optional low-sensitive business headers from an explicit allowlist. |

Example:

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
    "user_agent": "browser user-agent",
    "request_nonce": "nonce-123"
  }'
```

Common response fields:

| Field | Purpose |
|---|---|
| `action` | `allow`, `challenge`, `block`, `observe`, and related decisions. Unknown actions should fail closed in the integration layer. |
| `reason` | Stable reason code. |
| `challenge_url` | Runtime URL returned for challenge decisions. |
| `session_id` | Challenge session ID. |
| `scene` | Decision scene. |
| `challenge_type` | Captcha type to render. |
| `ttl_seconds` | Challenge TTL. |
| `clearance_token` | Clearance returned by allow-like actions. |
| `clearance_ttl_seconds` | Clearance TTL. |

#### Report Events

```text
POST /api/v1/events/report
```

Reports local Gateway or middleware decisions, ticket-consumption results, and fail-open/fail-close outcomes asynchronously.

```json
{
  "events": [
    {
      "client_id": "your-client",
      "scene": "login",
      "route": "/api/login",
      "action": "allow",
      "decision_reason": "TICKET_CONSUMED",
      "result": "allow",
      "account_id_hash": "acct_hash",
      "device_id_hash": "device_hash",
      "ip_hash": "sha256:..."
    }
  ]
}
```

The server overwrites externally supplied event time and event ID.

### Risk Collection API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/risk/demo-collection-summary` | Demo trajectory collection summary. |
| `POST` | `/api/v1/risk/track-samples` | Writes candidate trajectory feature snapshots; samples do not directly enter the training set by default. |

### Admin API

Admin API requires an admin token. It is for the admin frontend and internal operation tools, not ordinary business browsers.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/admin/auth/check` | Check admin token. |
| `GET` | `/api/v1/admin/metrics` | Admin overview metrics. |
| `GET` / `POST` | `/api/v1/admin/applications` | List and save applications. |
| `POST` | `/api/v1/admin/applications/{client_id}/secret` | Rotate application secret. |
| `GET` / `POST` | `/api/v1/admin/route-policies` | List and save route policies. |
| `POST` | `/api/v1/admin/route-policies/delete` | Delete route policies. |
| `GET` / `POST` | `/api/v1/admin/policies` | List and save configurable policy rules. |
| `POST` | `/api/v1/admin/policies/delete` | Delete policy rules. |
| `GET` / `POST` | `/api/v1/admin/ip-policies` | List and save IP policies. |
| `POST` | `/api/v1/admin/ip-policies/delete` | Delete IP policies. |
| `POST` | `/api/v1/admin/policy/simulate` | Policy dry-run; does not consume tickets, create sessions, or write audit events. |
| `GET` / `POST` | `/api/v1/admin/resources` | List and save resources. |
| `POST` | `/api/v1/admin/resources/upload` | Upload materials. |
| `POST` | `/api/v1/admin/resources/delete` | Delete materials. |
| `GET` | `/api/v1/admin/audit-events` | List audit events. |
| `GET` | `/api/v1/admin/risk-feature-snapshots` | List risk samples. |
| `GET` | `/api/v1/admin/risk-feature-snapshots/export` | Export risk samples. |
| `POST` | `/api/v1/admin/risk-feature-snapshots/{id}/label` | Label a risk sample. |
| `GET` / `POST` | `/api/v1/admin/risk-model-versions` | List and save model versions. |
| `POST` | `/api/v1/admin/risk-model-versions/{id}/activate` | Activate a model version. |
| `POST` | `/api/v1/admin/risk-model-versions/{id}/rollback` | Roll back a model version. |

## gRPC API

The canonical contract is [proto/captcha/v1/captcha.proto](../../proto/captcha/v1/captcha.proto). The default gRPC port is `:9090`.

| Service | Method | Capability |
|---|---|---|
| `PolicyService` | `Evaluate` | Policy evaluation, equivalent to HTTP `POST /api/v1/policy/evaluate`. |
| `TicketService` | `VerifyTicket` | Verify ticket without consuming it. |
| `TicketService` | `ConsumeTicket` | Consume ticket and return clearance on success. |
| `ConfigService` | `GetConfig` | Fetch application config snapshot for Gateway or custom integration caching. |
| `ConfigService` | `WatchConfig` | Watch config changes through a stream of snapshots. |
| `EventService` | `Report` | Report audit events. |

Recommended metadata:

```text
x-captcha-grpc-token: <platform-token>
x-captcha-client-secret: <application-secret>
```

`authorization: Bearer <token>` is also supported. When both platform token and application secret are enabled, prefer separate `x-captcha-grpc-token` and `x-captcha-client-secret` metadata fields.

## Integration Safety

- Business browsers should only call Runtime API and must not hold secrets.
- Gateway / middleware should not forward `authorization`, `cookie`, or other sensitive headers by default; forward only explicitly allowlisted low-sensitive business headers.
- Bind high-risk operations to `route` and `request_nonce`.
- Treat ticket verification or consumption failure as failure; do not fall back to allow.
- If `policy/evaluate` or gRPC `Evaluate` returns an unknown action, fail closed.
- Public collection traffic should enter only candidate samples, not the training set directly.

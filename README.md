# CaptCha

CaptCha is an open-source human verification platform. It is designed as a hosted verification runtime plus policy, ticket, and gateway/middleware integration layer rather than as a traditional CAPTCHA SDK.

See [docs/architecture-design.md](docs/architecture-design.md) for the current design.

Project guides:

- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Release checklist](docs/release-checklist.md)
- [Implementation audit](docs/implementation-audit.md)

License: not selected yet. Choose and add a license before publishing the repository as open source.

## Development

Run the Go API server:

```bash
go run ./cmd/captcha-server
```

Default listeners:

```text
HTTP: :8080
gRPC: :9090
```

Set `CAPTCHA_RUNTIME_URL` when the iframe runtime is hosted on a different origin:

```bash
CAPTCHA_RUNTIME_URL=http://localhost:5173 go run ./cmd/captcha-server
```

Restrict browser origins in deployed environments:

```bash
CAPTCHA_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com \
  go run ./cmd/captcha-server
```

When unset, CORS defaults to `*` for local development.

Restrict redirect mode return targets:

```bash
CAPTCHA_ALLOWED_RETURN_URL_ORIGINS=https://app.example.com \
  go run ./cmd/captcha-server
```

When unset, return URL origins fall back to `CAPTCHA_ALLOWED_ORIGINS`; local development with no origin allowlist accepts any absolute `http` or `https` return URL. Unsafe schemes such as `javascript:` are always rejected.

Protect admin APIs in deployed environments:

```bash
CAPTCHA_ADMIN_TOKEN='change-me' go run ./cmd/captcha-server
```

When the admin token is enabled, the admin console should be built or started with `VITE_ADMIN_TOKEN` so requests include `Authorization: Bearer ...`.

Enable the production security gate before deploying:

```bash
CAPTCHA_ENV=production \
CAPTCHA_ADMIN_TOKEN='change-me-admin' \
CAPTCHA_GRPC_TOKEN='change-me-grpc' \
CAPTCHA_METRICS_TOKEN='change-me-metrics' \
CAPTCHA_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com \
CAPTCHA_ALLOWED_RETURN_URL_ORIGINS=https://app.example.com \
CAPTCHA_POSTGRES_DSN='postgres://captcha:captcha@localhost:5432/captcha?sslmode=disable' \
CAPTCHA_REDIS_ADDR=localhost:6379 \
CAPTCHA_SEED_DEMO=false \
  go run ./cmd/captcha-server
```

`CAPTCHA_ENV=production` or `CAPTCHA_PRODUCTION=true` makes startup fail when required production controls are missing: admin, gRPC and metrics tokens, explicit non-wildcard browser origins, persistent PostgreSQL and Redis storage, and disabled demo seeding.

Tune challenge generation and TTLs:

```bash
CAPTCHA_PREGENERATE_SIZE=8 \
CAPTCHA_CHALLENGE_ESCALATION_SEQUENCE=SLIDER,ROTATE,CONCAT,WORD_IMAGE_CLICK \
CAPTCHA_SESSION_TTL_SECONDS=120 \
CAPTCHA_TICKET_TTL_SECONDS=120 \
CAPTCHA_CLEARANCE_TTL_SECONDS=600 \
  go run ./cmd/captcha-server
```

Use Redis for short-lived sessions, tickets, and rate counters:

```bash
CAPTCHA_REDIS_ADDR=localhost:6379 go run ./cmd/captcha-server
```

Use PostgreSQL for applications, policies, resources, and audit events:

```bash
CAPTCHA_POSTGRES_DSN='postgres://captcha:captcha@localhost:5432/captcha?sslmode=disable' \
  go run ./cmd/captcha-server
```

Use the target local storage shape:

```bash
CAPTCHA_POSTGRES_DSN='postgres://captcha:captcha@localhost:5432/captcha?sslmode=disable' \
CAPTCHA_REDIS_ADDR=localhost:6379 \
  go run ./cmd/captcha-server
```

PostgreSQL migrations are applied from `./migrations/postgres` by default. Demo data is seeded by default; set `CAPTCHA_SEED_DEMO=false` to disable it.

When PostgreSQL is not configured, the memory control store persists captcha resource metadata to `./data/resource-state.json` by default. Override it with `CAPTCHA_MEMORY_RESOURCE_STATE_FILE` if local uploads should survive server restarts in another path.

Serve classpath captcha resources from packaged local directories:

```bash
CAPTCHA_RESOURCE_CLASSPATH_DIRS='./resources:./configs/resources' go run ./cmd/captcha-server
```

When unset, classpath lookup uses `./resources` and `./configs/resources`. A resource URI such as `classpath://backgrounds/login.png` resolves inside one of those roots and cannot escape with `..`.

Run the platform with PostgreSQL and Redis through Docker Compose:

```bash
docker compose up --build
```

This starts the platform HTTP API on `localhost:8080`, gRPC on `localhost:9090`, PostgreSQL on `localhost:5432`, and Redis on `localhost:6379`. The platform image includes `migrations` and `configs`, so PostgreSQL migrations still run from `./migrations/postgres` inside the container.

Start the optional reference gateway profile:

```bash
CAPTCHA_UPSTREAM_URL=http://host.docker.internal:3000 \
  docker compose --profile gateway up --build
```

The gateway listens on `localhost:8081` and talks to the platform over the compose network. For infrastructure only during local development, keep using `docker compose -f docker-compose.dev.yml up -d`.

Build backend images directly:

```bash
docker build -f deploy/docker/Dockerfile.server .
docker build -f deploy/docker/Dockerfile.gateway .
```

CI runs `make verify` and `make docker-build` through `.github/workflows/ci.yml`.

Health check:

```bash
curl http://localhost:8080/healthz
```

Scrape Prometheus-style metrics:

```bash
curl http://localhost:8080/metrics
```

Set `CAPTCHA_METRICS_TOKEN` to require `X-Captcha-Metrics-Token` or `Authorization: Bearer ...` for the metrics endpoint.

Protect gRPC data-plane APIs with a platform token:

```bash
CAPTCHA_GRPC_TOKEN='change-me-grpc' go run ./cmd/captcha-server
```

When enabled, gRPC callers must send `x-captcha-grpc-token` or `Authorization: Bearer ...`. Application client secrets are still checked separately for client-scoped Policy, Ticket, Config, and Event calls.

Evaluate a policy:

```bash
curl -X POST http://localhost:8080/api/v1/policy/evaluate \
  -H 'content-type: application/json' \
  -d '{"client_id":"demo","path":"/api/register","method":"POST","ip":"198.51.100.9"}'
```

Run the iframe runtime:

```bash
npm run dev:runtime
```

Open `http://localhost:5173/demo` for a local captcha demo with `RANDOM` plus `GESTURE`, `CURVE`, `CURVE_V2`, `CURVE_V3`, `SLIDER`, `SLIDER_V2`, `ROTATE`, `CONCAT`, `ROTATE_DEGREE`, `WORD_IMAGE_CLICK`, `IMAGE_CLICK`, `JIGSAW`, and `GRID_IMAGE_CLICK`.

The runtime accepts `session_id`, `client_id`, `scene`, `captcha_type`, `route`, `return_url`, `request_nonce`, and `resource_tag` query parameters. When `route`, `request_nonce`, IP hash, or user-agent hash is present on the server-side session, the issued ticket is bound to that context and the success `postMessage` includes the same route and nonce. A runtime opened with only `session_id` recovers route, nonce, resource tag, and return URL from the server-side session before verify. In top-level redirect mode, a successful verification redirects to an allowlisted absolute `http` or `https` `return_url` with `captcha_ticket`, `captcha_session_id`, and bound context query parameters. Ticket verification or consumption must pass the same bound context.

Tickets remain one-time credentials. A successful consume can mint a short-lived clearance token for normal follow-up requests in the same `client_id` and `scene`; integrations must send the request IP and User-Agent hashes during consume to receive clearance. Clearance is stored server-side and bound to IP hash, User-Agent hash, and any supplied `account_id_hash` or `device_id_hash`; anonymous flows should use the browser clearance cookie and, when available, a device or anonymous visitor hash instead of treating IP as a blanket allowlist.

Challenge sessions are single-use: a verified session cannot issue another ticket. A session is also closed after repeated verification failures. When the submitted answer is correct but the behavior track is clearly suspicious, the verify API returns `challenge_harder` with `can_refresh=true`; the runtime refreshes the same session into the next stronger captcha type. The default escalation sequence is `SLIDER,ROTATE,CONCAT,WORD_IMAGE_CLICK` and can be overridden with `CAPTCHA_CHALLENGE_ESCALATION_SEQUENCE`; route policies may also set `challenge_escalation` for route-specific escalation.

The verify API rejects client-supplied rule fields such as `tolerance`, `target`, `answer_seed`, `verify_rule`, and `score_rule`, including nested occurrences inside `answer` or metadata. Server-side answers, tolerances, and scoring rules are never accepted from the browser.

Run the admin console:

```bash
npm run dev:admin
```

The admin console can create applications, route policies, IP policies, captcha resources, risk model version records, and risk feature label feedback through the platform admin API. It also provides policy dry-run simulation for checking the matched route and decision without consuming tickets, creating challenge sessions, incrementing rate counters, or writing audit events. Route policies support `rollout_percent` for stable percentage rollout and `challenge_escalation` for route-specific upgraded challenges. The overview page uses `/api/v1/admin/metrics` to show operational totals, recent audit distribution, resource status, resource hit/failure analysis, trainable feature counts, and active model counts. Audit events and risk feature snapshots support server-side filters for operational review. Application client secrets are generated by the backend, returned once on rotation, stored only as hashes, and exposed to the admin console only as a `has_secret` status.

Successful admin configuration changes are written to audit events with `CONFIG_*` reasons and hashed admin IP context.

Active captcha resources are validated on upsert, including resource type, storage type, URI scheme, safe remote host checks, optional dimensions, MIME type, size, checksum, and metadata. They are selected when a challenge is created or refreshed and are returned as `challenge.parameters.resources` with runtime metadata sanitized to remove answer, target, tolerance, rule, secret, and token fields. Selection uses `client_id`, `scene`, `captcha_type`, and optional `resource_tag`; exact captcha-type and scene resources are preferred over fallback resources. When a route or iframe session asks for `AUTO`, the platform chooses a concrete captcha type from scene/risk preferences and resource availability. `classpath`, local `file`, remote `url`, `object_storage`, and `database` base64/data URL background resources can be server-composed into PNG challenge images with size, response MIME, decoded MIME, declared dimensions, checksum, unsafe-host, and classpath traversal checks, while the embedded PNG generator remains the fallback so server answers are not exposed as inspectable SVG attributes. Object storage resources can use metadata direct URLs such as `public_url` or `presigned_url`, or construct a fetch URL from `endpoint` / `base_url` plus an `s3`/`oss`/`cos`/`obs`/`minio` bucket/key URI. Server-side composition also consumes `slider_template` masks, `rotate_template` overlays, `concat_template` JSON/metadata moving/static split settings, and `font` metadata for word-click glyph scale, palette, and custom block glyphs. The resource model also accepts `background_library`, `concat_background_library`, `jigsaw_background_library`, `rotate_library`, `grid_category_library`, and `icon_library`: CONCAT and JIGSAW use their dedicated background galleries instead of generic backgrounds, because these challenge types need images chosen for alignment continuity, tile distinctiveness, and human pass difficulty rather than appearance alone. ROTATE uses the dedicated rotate library and server-crops a circular rotating image, image-grid challenges use category galleries, icon-click can use built-in/provided SVG icon libraries, and other visual captchas should draw from captcha-specific background libraries instead of a single fixed image. `CONCAT` uses a static lower half plus one transparent moving upper half; the background no longer exposes a target gap, answer-equivalent `initial_offset`, or legacy `split_x` fields. `CURVE` / `CURVE_V2` / `CURVE_V3` render target curves into server PNG images and do not expose target curve points in `curve_profile`.

Risk feature snapshots are collected asynchronously after verification. They include track statistics and a sanitized list of matched resource IDs/types for resource hit analysis, without resource URI, metadata, checksum, or answer data. Admin users can update snapshot labels from manual review or business feedback and only explicit human/bot labels can be marked trainable. Risk model versions can be registered, activated, and rolled back from the admin API/console with `shadow`, `observe`, or `enforce` mode metadata. When an active model version matches the feature version, the platform adds a server-side shadow score to the stored feature snapshot. Online training is not in the request path. For backend/Gateway integrations, `risk_based` route policies can optionally use server-side `risk_score`, `risk_level`, and `model_score` context with route thresholds; `shadow` model mode is ignored for decisions, while `observe` and `enforce` model modes participate only as risk-score inputs. The platform can also enrich policy evaluation from an optional external inference service before applying route thresholds; the call sends hashed IP/User-Agent context and active model metadata, and failures are logged then degraded to the existing request context.

```bash
CAPTCHA_RISK_INFERENCE_URL=http://localhost:9000/infer \
CAPTCHA_RISK_INFERENCE_TOKEN=change-me-risk \
CAPTCHA_RISK_INFERENCE_TIMEOUT=500ms \
  go run ./cmd/captcha-server
```

Applications must exist and be `active` before they can create or verify challenges. Disabled applications are rejected by runtime challenge APIs; policy evaluation returns a block decision, ticket verification returns `valid=false`, and event reporting is rejected.

When an application has a client secret, backend integration APIs require `X-Captcha-Client-Secret` or `Authorization: Bearer ...` for `/api/v1/policy/evaluate`, `/api/v1/tickets/verify`, and `/api/v1/events/report`. Public iframe challenge creation does not use the client secret.

Run the reference gateway reverse proxy:

```bash
CAPTCHA_UPSTREAM_URL=http://localhost:3000 \
CAPTCHA_PLATFORM_URL=http://localhost:8080 \
CAPTCHA_GATEWAY_HEADER_ALLOWLIST=x-request-id,traceparent \
CAPTCHA_CLIENT_SECRET=cap_secret_xxx \
  go run ./cmd/captcha-gateway
```

The gateway consumes `X-Captcha-Ticket` first when present. It sends the protected request IP and User-Agent hashes when consuming tickets, and if the ticket was nonce-bound, pass the nonce with `X-Captcha-Request-Nonce`. Successful ticket consumption returns `X-Captcha-Clearance` and an HttpOnly `captcha_clearance` cookie by default; later requests can present either value and the gateway forwards it to policy evaluation. `X-Captcha-Resource-Tag` can be used to request a resource tag for newly created challenges. `X-Captcha-Account-ID-Hash` and `X-Captcha-Device-ID-Hash` are forwarded to ticket consume and policy evaluation for clearance binding, rate-limit, and risk dimensions. Business headers are not forwarded by default; `CAPTCHA_GATEWAY_HEADER_ALLOWLIST` can forward low-sensitive headers such as request or trace IDs. Without a ticket or valid clearance, it asks the platform policy API before proxying. It forwards allowed requests, returns challenge details for challenged requests, and blocks invalid or consumed tickets.

For `risk_based` route thresholds, the gateway also forwards `X-Captcha-Risk-Score`, `X-Captcha-Risk-Level`, `X-Captcha-Model-Score`, and `X-Captcha-Model-Mode`. Override these names with `CAPTCHA_RISK_SCORE_HEADER`, `CAPTCHA_RISK_LEVEL_HEADER`, `CAPTCHA_MODEL_SCORE_HEADER`, and `CAPTCHA_MODEL_MODE_HEADER` when needed.

When a ticket is sent to the HTTP or gRPC policy evaluation API, the platform treats it as authoritative: valid tickets are consumed, allowed, and can return `clearance_token`; invalid, expired, consumed, or context-mismatched tickets return a block decision instead of falling back to normal no-ticket policy evaluation. When `clearance` is sent instead, the platform allows only if the server-side clearance token and its bound IP, User-Agent, account, and device context still match; otherwise it falls back to normal policy evaluation.

Use gRPC for the gateway policy path:

```bash
CAPTCHA_UPSTREAM_URL=http://localhost:3000 \
CAPTCHA_GATEWAY_POLICY_TRANSPORT=grpc \
CAPTCHA_PLATFORM_GRPC_ADDR=localhost:9090 \
CAPTCHA_PLATFORM_GRPC_TOKEN=change-me-grpc \
CAPTCHA_CLIENT_SECRET=cap_secret_xxx \
  go run ./cmd/captcha-gateway
```

When `CAPTCHA_GATEWAY_POLICY_TRANSPORT=grpc`, the gateway uses gRPC for `PolicyService.Evaluate`, `TicketService.ConsumeTicket`, `EventService.Report`, and optional config cache calls. `CAPTCHA_PLATFORM_GRPC_TOKEN` may also be supplied as `CAPTCHA_GRPC_TOKEN`.

Enable the optional gateway config cache:

```bash
CAPTCHA_UPSTREAM_URL=http://localhost:3000 \
CAPTCHA_PLATFORM_GRPC_ADDR=localhost:9090 \
CAPTCHA_GATEWAY_CONFIG_CACHE=true \
  go run ./cmd/captcha-gateway
```

The cache subscribes to `ConfigService.WatchConfig` and handles deterministic local decisions such as static IP allow/block, no matched route, `manual_bypass`, `silent`, and `observe`. Ticket consumption, challenge creation, rate limits, and risk decisions still go through the platform.

The gateway asynchronously reports local cache decisions, ticket consume results, and fail-open/fail-close outcomes through the platform event API. Remote policy decisions are already audited by the platform policy service. Set `CAPTCHA_GATEWAY_EVENT_BATCH_SIZE`, `CAPTCHA_GATEWAY_EVENT_FLUSH_INTERVAL`, and optionally `CAPTCHA_GATEWAY_EVENT_QUEUE_SIZE` to enable bounded queue batching for these gateway event reports.

Enable gateway event batching:

```bash
CAPTCHA_UPSTREAM_URL=http://localhost:3000 \
CAPTCHA_GATEWAY_EVENT_BATCH_SIZE=20 \
CAPTCHA_GATEWAY_EVENT_FLUSH_INTERVAL=1s \
CAPTCHA_GATEWAY_EVENT_QUEUE_SIZE=200 \
  go run ./cmd/captcha-gateway
```

Enable short circuit breaking for repeated platform policy/ticket failures:

```bash
CAPTCHA_UPSTREAM_URL=http://localhost:3000 \
CAPTCHA_GATEWAY_CIRCUIT_BREAKER_FAILURES=3 \
CAPTCHA_GATEWAY_CIRCUIT_BREAKER_COOLDOWN=5s \
  go run ./cmd/captcha-gateway
```

During the cooldown window the gateway skips policy/ticket calls and applies the configured `fail_open` or `fail_close` behavior while still attempting asynchronous event reports.

Configure trusted proxies before trusting `X-Forwarded-For`:

```bash
CAPTCHA_UPSTREAM_URL=http://localhost:3000 \
CAPTCHA_TRUSTED_PROXY_CIDRS=10.0.0.0/8,192.168.0.0/16 \
  go run ./cmd/captcha-gateway
```

IP policies accept CIDR ranges or a single IP address. The platform and gateway local cache apply IP policy precedence as allowlist, then blocklist, then other IP policies.

Route `rate_limit` policies count IP, `account_id_hash`, and `device_id_hash` dimensions independently. Any dimension crossing the route threshold triggers a challenge. Rate limits default to `fixed_window`; set `rate_limit.strategy` to `sliding_window` for rolling-window counting or `token_bucket` for burst-tolerant refill behavior in memory or Redis. `risk_based` policies can set `risk_observe_score`, `risk_challenge_score`, and `risk_block_score`; when a backend, Gateway, or middleware supplies `risk_score`, `risk_level`, or an `observe`/`enforce` `model_score`, the platform applies those thresholds. `risk_challenge_type` can upgrade the captcha type only for risk-score challenges, while `challenge_type` remains the default. `challenge_escalation` overrides the platform escalation sequence for sessions created by that route. `rollout_percent` uses stable hashing over account, device, IP, User-Agent, or path context, and rollout misses continue matching lower-priority policies.

Use the Express reference middleware:

```ts
import express from "express";
import { createCaptchaMiddleware } from "@captcha/express-middleware";

const app = express();

app.use(createCaptchaMiddleware({
  platformURL: "http://localhost:8080",
  clientID: "demo",
  clientSecret: "cap_secret_xxx",
  trustedProxyCIDRs: ["10.0.0.0/8"],
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
  shouldProtect: (req) => req.path.startsWith("/api")
}));
```

The middleware is intentionally thin. It consumes a ticket first when one is present, stores returned clearance in `x-captcha-clearance` plus an HttpOnly `captcha_clearance` cookie when possible, otherwise calls the platform policy API, passes allowed requests to `next()`, returns challenge details for challenged requests, and preserves platform ownership of policy, ticket state, clearance state, rate limits, risk thresholds, and audit. Business headers are not forwarded by default; use `headerAllowlist` for low-sensitive request or trace IDs. Ticket results and fail-open/fail-close outcomes are reported asynchronously to the platform event API with hashed account/device context when available.

The admin API also exposes risk feature snapshots at `/api/v1/admin/risk-feature-snapshots`. Audit events and risk feature snapshots support server-side filters plus `limit`/`offset` pagination. `/api/v1/admin/risk-feature-snapshots/export` returns JSONL for offline training and defaults to `model_trainable=true` samples. These snapshots are candidate training samples only; online model training is intentionally not part of the request path.

Build everything:

```bash
go test ./...
npm run build
```

Run the standard local verification suite:

```bash
make verify
```

This runs the Go/Docker/CI toolchain version check, frontend framework contract check, Docker delivery contract check, HTTP/gRPC API contract checks, captcha type, browser-smoke route coverage, documented command checks, Go tests, protobuf drift checks, production security gate smoke checks, HTTP/gRPC smoke tests, workspace tests, workspace builds, the runtime gzip budget check, and Docker Compose config validation, then removes generated build outputs and local browser smoke artifacts.

Run the local HTTP and gateway smoke test:

```bash
make smoke
```

The smoke test first verifies that production mode refuses to start without required controls. It then starts the platform server with the in-memory demo data, checks policy and challenge APIs, verifies that challenge payloads do not expose answer or rule fields, and exercises the reference gateway in both HTTP and gRPC policy modes.

Run the optional real-browser smoke test:

```bash
make browser-smoke
```

This starts the platform, runtime, and admin console on temporary local ports, then uses Playwright CLI to verify that the runtime renders all four captcha types, failed verification shows a retry state, and the admin console can load overview, application data, and every primary admin route.

Run the release audit before publishing:

```bash
make release-audit
```

This intentionally fails until release blockers such as the project license, private security reporting channel, and Docker image build environment are ready.

Remove generated build outputs and local browser artifacts after ad hoc build runs:

```bash
make clean
```

Start local storage dependencies:

```bash
docker compose -f docker-compose.dev.yml up -d
```

PostgreSQL schema lives in [migrations/postgres/001_init.sql](migrations/postgres/001_init.sql). Runtime configuration example lives in [configs/captcha.example.yaml](configs/captcha.example.yaml).

## Protocols

The gRPC contract is in [proto/captcha/v1/captcha.proto](proto/captcha/v1/captcha.proto). Generated Go protobuf code lives under `gen/captcha/v1`.

The current Go gRPC server exposes `PolicyService`, `TicketService`, `ConfigService`, and `EventService` through generated protobuf service code. `ConfigService` supports `GetConfig` and streaming `WatchConfig` updates when admin configuration changes in the running server, and snapshots include application status, route policies, IP policies, captcha resources, and config version.

Regenerate protobuf code after editing the contract:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
make proto
```

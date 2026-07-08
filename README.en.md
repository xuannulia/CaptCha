# CaptCha

Language: [中文](README.md) | English

[![CI](https://github.com/xuannulia/CaptCha/actions/workflows/ci.yml/badge.svg)](https://github.com/xuannulia/CaptCha/actions/workflows/ci.yml)
[![Pages](https://github.com/xuannulia/CaptCha/actions/workflows/pages.yml/badge.svg)](https://github.com/xuannulia/CaptCha/actions/workflows/pages.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](LICENSE)
![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-22-339933?logo=node.js&logoColor=white)
![Backend verification](https://img.shields.io/badge/Backend-Verification-2ea44f)
![Trajectory recognition](https://img.shields.io/badge/Trajectory-Recognition-6f42c1)
![Ticket clearance](https://img.shields.io/badge/Ticket-Clearance-0969da)
![Self hosted](https://img.shields.io/badge/Self--hosted-Captcha-555)

CaptCha is a backend-verified captcha platform with trajectory recognition, one-time tickets, clearance, and policy decisions. The browser renders challenges and reports interaction facts; answers, policy, rate limits, audit, and risk decisions stay on the server side.

![CaptCha demo page](docs/assets/demo-page.png)

- Demo: [https://xuannulia.github.io/CaptCha/](https://xuannulia.github.io/CaptCha/)
- License: [AGPL-3.0-only](LICENSE)

## Why Not A Third-Party Captcha Service

CaptCha fits deployments where you need to own the verification path:

- Policy, materials, answers, tickets, clearance, and audit data stay on your servers.
- User behavior trajectories do not need to be sent to an external captcha provider.
- The platform can be self-hosted when external captcha services are unavailable or undesirable.
- Captcha is one layer in a risk-control chain, not an external black box.

## What Is Included

- Go API server for challenges, tickets, policy, audit, resources, and admin APIs.
- Runtime frontend embedded by business pages.
- Admin frontend for applications, route policies, resources, audit, samples, and model versions.
- Gateway reverse proxy.
- Middleware for Express, Go `net/http`, Python ASGI, Java `HttpHandler`, and ASP.NET Core.
- HTTP / gRPC APIs for custom gateways, service meshes, or internal platform integrations.

## Status

Current status: early usable version.

Available:

- API server, Runtime frontend, and demo data.
- Gateway and multi-language middleware.
- PostgreSQL / Redis configuration.
- Basic audit, tickets, clearance, policy evaluation, and sample snapshots.

Still evolving:

- Admin UX and policy editor.
- More reusable captcha materials.
- Model training loop and performance reports.

## Architecture

```mermaid
flowchart LR
  Browser["Business browser"] --> Runtime["Runtime iframe / redirect"]
  Browser --> Entry["Middleware / Gateway"]
  Runtime --> API["CaptCha API Server"]
  Entry --> API
  Entry --> Upstream["Business service"]
  API --> Challenge["challenge / ticket / clearance"]
  API --> Policy["policy / rate limit / audit"]
  API --> Resource["resource manager"]
  API --> Sample["sample snapshots"]
  API --> Store[("PostgreSQL / Redis")]
```

## Local Start

The default local run uses in-memory storage and demo data.

```bash
go run ./cmd/captcha-server
```

In another terminal:

```bash
npm run dev:runtime
```

Open:

```text
http://localhost:5173/demo
```

## Business Traffic Integration

These options decide where business requests are intercepted.

| Option | When to use it | Entry |
|---|---|---|
| Runtime iframe + backend ticket check | You can change both the page and backend; smallest integration path. | [Integration Guide](docs/en/integration-guide.md) |
| Middleware | Your service can add middleware and handle tickets, clearance, and policy in the request chain. | [Middleware](#middleware) |
| Gateway | The business service is hard to change; intercept at the edge. | [Gateway](#gateway) |

## Custom Integration

HTTP / gRPC APIs are low-level interfaces, not another turnkey option beside middleware and Gateway. Use them when building your own gateway, service mesh adapter, or platform control plane.

- API Reference: [HTTP / gRPC API](docs/en/api-reference.md)

## Admin

Admin does not participate in business request handling. It manages applications, route policies, resources, audit, samples, and model versions.

```bash
npm run dev:admin
```

## Middleware

- [Express middleware](integrations/express-middleware/README.md)
- [Go `net/http` middleware](integrations/go-middleware/README.md)
- [Python ASGI middleware](integrations/python-middleware/README.md)
- [Java `HttpHandler` middleware](integrations/java-middleware/README.md)
- [ASP.NET Core middleware](integrations/dotnet-middleware/README.md)

Express example:

```ts
import express from "express";
import { createCaptchaMiddleware } from "@captcha/express-middleware";

const app = express();

app.use(createCaptchaMiddleware({
  platformURL: "http://localhost:8080",
  clientID: "demo",
  clientSecret: "cap_secret_xxx",
  shouldProtect: (req) => req.path.startsWith("/api")
}));
```

## Gateway

```bash
CAPTCHA_UPSTREAM_URL=http://localhost:3000 \
CAPTCHA_PLATFORM_URL=http://localhost:8080 \
CAPTCHA_CLIENT_SECRET=cap_secret_xxx \
  go run ./cmd/captcha-gateway
```

Docker Compose profile:

```bash
CAPTCHA_UPSTREAM_URL=http://host.docker.internal:3000 \
  docker compose --profile gateway up --build
```

## Production Configuration

Production deployments should configure at least:

- `CAPTCHA_ADMIN_TOKEN`
- `CAPTCHA_GRPC_TOKEN`
- `CAPTCHA_METRICS_TOKEN`
- `CAPTCHA_ALLOWED_ORIGINS`
- `CAPTCHA_ALLOWED_RETURN_URL_ORIGINS`
- `CAPTCHA_POSTGRES_DSN`
- `CAPTCHA_REDIS_ADDR`
- `CAPTCHA_SEED_DEMO=false`

Example:

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

## Security Boundaries

CaptCha is not a universal anti-bot system and should not be the only protection for high-value endpoints. Use it as a verification layer in a broader risk-control system.

Avoid:

- Relying only on captcha for high-value endpoints.
- Treating IP addresses as long-lived allowlists.
- Putting `client_secret`, admin tokens, or gRPC tokens in browser code.
- Accepting client-supplied answers, scoring thresholds, or verification rules.
- Sending public collection traffic directly into a training set.

Prefer:

- Binding high-risk operations to route and one-time nonce.
- Treating ticket consumption failure as failure.
- Combining captcha with rate limits, account reputation, device signals, IP risk, and business rules.

## Docker

Local dependencies:

```bash
docker compose -f docker-compose.dev.yml up -d
```

Full platform:

```bash
docker compose up --build
```

Build images:

```bash
make docker-build
```

## Verification

Day-to-day development:

```bash
go test ./...
npm run build
```

Before submitting:

```bash
make verify
```

Real-browser smoke:

```bash
make browser-smoke
```

Release audit:

```bash
make release-audit
```

Clean build outputs:

```bash
make clean
```

## Risk Samples

After verification, CaptCha stores behavior feature snapshots asynchronously. Samples do not include answers, material URIs, full metadata, or checksums. Only explicitly labeled human/bot samples can enter the training set.

Generate synthetic bot negatives locally:

```bash
make synthetic-bot-tracks
```

Output:

```text
output/synthetic-bot-tracks.jsonl
```

## Documentation

- [Integration Guide](docs/en/integration-guide.md)
- [HTTP / gRPC API](docs/en/api-reference.md)
- [Architecture Overview](docs/en/architecture-overview.md)
- [Security Policy](SECURITY.en.md)
- [Contributing](CONTRIBUTING.en.md)

## Protocol

gRPC contract: [proto/captcha/v1/captcha.proto](proto/captcha/v1/captcha.proto).

Regenerate protobuf code after changing the contract:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
make proto
```

AGPL reminder: if you provide a network service based on a modified version of this project, [AGPL-3.0-only](LICENSE) requires you to provide the corresponding source code to service users.

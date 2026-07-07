# Contributing

CaptCha is a human verification platform, not a browser-only CAPTCHA widget or a business SDK. Contributions should preserve that boundary: the platform owns challenge generation, answer verification, policy decisions, tickets, rate limits, risk signals, and audit.

## Development Setup

Run the platform locally:

```bash
go run ./cmd/captcha-server
```

Run the iframe runtime and admin console:

```bash
npm run dev:runtime
npm run dev:admin
```

Use PostgreSQL and Redis when changing storage behavior:

```bash
docker compose -f docker-compose.dev.yml up -d
```

## Validation

Run these before submitting changes:

```bash
make verify
```

When Docker is available, also run:

```bash
make docker-build
```

Before UI-facing changes, run:

```bash
make browser-smoke
```

Before publishing or cutting a release, run:

```bash
make release-audit
```

`make verify` removes generated frontend and middleware build outputs before it exits. Use `make clean` if you run individual build commands manually.

## Protobuf Contract

The gRPC contract lives in `proto/captcha/v1/captcha.proto`; generated Go code lives in `gen/captcha/v1`.

After editing the contract:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
make proto
make proto-check
```

Keep protobuf messages stable. Prefer additive fields over renaming or reusing field numbers.

## Security Invariants

Do not move these responsibilities to the browser:

- Server-side answer, tolerance, target point, scoring threshold, or verification rule.
- Ticket state or one-time consumption state.
- Production policy thresholds, IP lists, client secrets, or runtime counters.
- Trust decisions based only on frontend behavior.

Challenge payloads must not expose answer or rule fields. Verify requests must reject client-submitted `tolerance`, `target`, `answer_seed`, `verify_rule`, and `score_rule`, including nested fields.

Middleware and Gateway integrations must forward business headers only through explicit allowlists.

## License And Contributions

CaptCha is licensed as `AGPL-3.0-only`. Contributions to the public repository are accepted under the same license unless a separate written agreement says otherwise.

Do not submit code that cannot be redistributed under AGPL-3.0-only. If the project later accepts contributions for reuse in proprietary editions, that must be handled through a Contributor License Agreement or another explicit inbound licensing process.

## Frontend Guidelines

The runtime should stay small and focused on rendering challenges, collecting interaction facts, and returning tickets. The admin console should stay operational and dense: configuration, audit, metrics, resources, training features, and model versions.

Avoid landing pages, marketing copy, decorative dashboards, and in-app explanations of how the product works. The first screen should be useful.

## Pull Request Checklist

- The change matches the architecture in `docs/architecture-design.md`.
- Tests or smoke coverage match the risk of the change.
- Security-sensitive fields are not added to browser payloads.
- New remote calls have deadlines or request timeouts.
- Config changes are documented in `README.md` or `configs/captcha.example.yaml`.
- Generated protobuf code is updated when the `.proto` contract changes.

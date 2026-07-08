# Security Policy

CaptCha assumes the implementation is open source. Security must come from deployment secrets, server-side state, short-lived challenges, one-time tickets, rate limits, policy configuration, audit, and risk feedback, not from hidden frontend code.

## Supported Versions

The project is currently pre-release. Security fixes apply to the current main branch until versioned releases are introduced.

## Reporting a Vulnerability

Do not publish exploit details, bypass recipes, or working attack payloads in public issues.

Report vulnerabilities privately by email: loser@iloser.cn.

Use the public issue tracker only for non-sensitive bug reports and hardening discussions that do not include exploit details, bypass recipes, or working payloads.

Please include:

- Affected component: server, runtime, admin, Gateway, multi-language middleware, gRPC contract, storage, or deployment.
- Reproduction steps and impact.
- Whether the issue leaks answers, bypasses tickets, weakens client secret checks, bypasses rate limits, exposes sensitive headers, or allows unsafe resource fetching.
- Suggested fix, if available.

## Security Boundaries

Expected private state:

- Challenge answer, target, tolerance, scoring rules, and track thresholds.
- Ticket value, consumption state, TTL, route binding, nonce binding, IP hash, and User-Agent hash.
- Client secrets, admin token, metrics token, gRPC token, and TLS or mTLS keys.
- Production policy thresholds, IP lists, rollout state, rate counters, and model artifacts.

Expected public state:

- Frontend runtime code.
- Public challenge rendering data after answer and rule metadata are sanitized.
- Protobuf and HTTP contracts.
- Server algorithms and rule scoring logic.

## Deployment Requirements

Production deployments should enable the startup security gate:

```bash
CAPTCHA_ENV=production
```

or:

```bash
CAPTCHA_PRODUCTION=true
```

Production mode requires admin, gRPC, and metrics tokens, explicit non-wildcard browser origins, PostgreSQL, Redis, and disabled demo seeding.

## Disclosure

Security fixes should avoid publishing bypass mechanics in changelog text. Use concise impact language and document required upgrade or mitigation steps.

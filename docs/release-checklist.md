# Release Checklist

Use this checklist before publishing the project or cutting a release.

## Required Before Public Release

- Choose and add a project license file. Do not publish as open source without an explicit license.
- Configure a private security reporting channel and update `SECURITY.md`.
- Confirm `README.md`, `CONTRIBUTING.md`, and `docs/architecture-design.md` match the current behavior.
- Review `docs/implementation-audit.md` and update it when requirements or evidence change.
- Verify no production secrets, generated local credentials, or private endpoints are committed.
- Confirm Docker images build from a clean checkout.
- Confirm PostgreSQL migrations apply from an empty database.
- Confirm Redis-backed sessions, tickets, and rate limits work in the target deployment shape.

## Validation Commands

```bash
make verify
make docker-build
make release-audit
```

Clean build outputs and local browser smoke artifacts before committing if you ran individual build commands:

```bash
make clean
```

## Production Configuration Gate

Run a startup check with production mode enabled:

```bash
CAPTCHA_ENV=production \
CAPTCHA_ADMIN_TOKEN=change-me-admin \
CAPTCHA_GRPC_TOKEN=change-me-grpc \
CAPTCHA_METRICS_TOKEN=change-me-metrics \
CAPTCHA_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com \
CAPTCHA_ALLOWED_RETURN_URL_ORIGINS=https://app.example.com \
CAPTCHA_POSTGRES_DSN='postgres://captcha:captcha@localhost:5432/captcha?sslmode=disable' \
CAPTCHA_REDIS_ADDR=localhost:6379 \
CAPTCHA_SEED_DEMO=false \
  go run ./cmd/captcha-server
```

Use real deployment secrets and origins. The sample values above are placeholders for checking the expected environment shape.

## Browser Smoke

Before a UI-facing release, run a real browser check:

```bash
make browser-smoke
```

- Runtime loads with `client_id=demo`, creates `RANDOM` requests and `GESTURE`, `CURVE`, `CURVE_V2`, `CURVE_V3`, `SLIDER`, `SLIDER_V2`, `ROTATE`, `CONCAT`, `ROTATE_DEGREE`, `WORD_IMAGE_CLICK`, `IMAGE_CLICK`, `JIGSAW`, and `GRID_IMAGE_CLICK` concrete challenges, and renders the expected controls.
- Runtime verification failure for each captcha type shows a retry state without crashing; drag, path, point-click, and proof-of-work challenges keep manual verification disabled until a valid answer shape exists.
- Browser smoke includes successful iframe flows for representative drag, path, and click captchas, including `SLIDER` / `SLIDER_V2` gap alignment, `ROTATE` image rotation, `ROTATE_DEGREE` red-tick angle alignment, `CONCAT` piece alignment, `GESTURE` timed drawing and straight-line failure, `CURVE` / `CURVE_V2` / `CURVE_V3` canvas curve matching and wrong-offset failure, `WORD_IMAGE_CLICK` / `IMAGE_CLICK` ordered clicks, `JIGSAW` tile-layer drag swap, and `GRID_IMAGE_CLICK` grid selection plus wrong-selection failure, so the release check covers more than static rendering.
- Admin console loads metrics and shows applications, route policies, IP policies, resource gallery, audit, sample review, and model management.
- Browser console has no application errors.

## Security Review

- Challenge payloads do not expose answer, target, tolerance, verify rule, score rule, secret, or token fields.
- Verify API rejects client-supplied rule fields, including nested fields.
- Ticket consumption is one-time and bound to client, scene, route, nonce, IP hash, and User-Agent hash when present.
- Gateway and middleware default to not forwarding business headers.
- Trusted proxy behavior only uses forwarded IPs from configured CIDRs.
- Production mode rejects missing controls, wildcard origins, and demo seed.
- Remote calls have deadlines or request timeouts.

# Deployment Operations And Recovery

Language: [中文](../zh/deployment-operations.md) | English

This document records the production checks that matter: who supervises the service, whether it restarts after failure, whether health checks actually work, and whether business traffic is blocked when the CaptCha platform is unavailable.

## Current Hosted Demo

The public demo uses GitHub Pages for the Runtime, and `https://api.metool.tech/captcha` forwards to the CaptCha API Server.

The deployed CaptCha containers use Docker restart policy:

| Service | Recovery |
|---|---|
| `captcha-collector-api` | `restart=unless-stopped` |
| `captcha-collector-postgres` | `restart=unless-stopped` |
| `captcha-collector-redis` | `restart=unless-stopped` |

On the host, `docker.service` and `nginx.service` are supervised by systemd. The deployment is not running as loose foreground processes; containers are restored by Docker after process exit, Docker restart, or machine restart.

## Repository Defaults

`docker-compose.yml` configures production services with:

- `restart: unless-stopped`
- PostgreSQL / Redis health checks
- CaptCha API Server health check
- Gateway health check
- explicit Gateway failure-policy environment variables

The API Server and Gateway images are `scratch` images, so they do not include shell, curl, or wget. Health checks use the binaries themselves:

```text
captcha-server healthcheck http://127.0.0.1:8080/healthz
captcha-gateway healthcheck http://127.0.0.1:8081/healthz
```

This keeps health checks independent from tools that do not exist in the final image.

## Post-Deployment Checks

Confirm restart policy on the server:

```bash
docker inspect captcha-collector-api --format '{{.HostConfig.RestartPolicy.Name}}'
docker inspect captcha-collector-postgres --format '{{.HostConfig.RestartPolicy.Name}}'
docker inspect captcha-collector-redis --format '{{.HostConfig.RestartPolicy.Name}}'
systemctl is-active docker
systemctl is-active nginx
```

Confirm API health:

```bash
curl -fsS https://api.metool.tech/captcha/healthz
```

Confirm the GitHub Pages demo is reachable:

```bash
curl -fsS https://xuannulia.github.io/CaptCha/demo/
```

## Gateway Failure Policy

Gateway uses the same failure posture as middleware. The default is `fail_open`, so CaptCha platform incidents do not block business traffic. Configure it by route value and business risk:

```env
CAPTCHA_GATEWAY_FAIL_POLICY=fail_open
CAPTCHA_GATEWAY_TIMEOUT=1500ms
CAPTCHA_GATEWAY_CIRCUIT_BREAKER_FAILURES=3
CAPTCHA_GATEWAY_CIRCUIT_BREAKER_COOLDOWN=5s
```

For high-value actions, run a separate fail-close Gateway or configure middleware with `fail_close` on those routes.

## Failure Boundary

| Failure | Default result |
|---|---|
| API Server container exits | Docker restarts it. |
| PostgreSQL / Redis container exits | Docker restarts it. |
| nginx config changed | Run `nginx -t` before reload. |
| CaptCha platform is temporarily unavailable | Middleware / Gateway defaults to fail-open; business continues. |
| Ticket is invalid or already consumed | 403; no fail-open fallback. |
| Policy returns an unknown action | 403; fail closed. |

## Next

- [Middleware Integration](middleware-integration.md)
- [Custom Integration](custom-integration.md)
- [HTTP / gRPC API](api-reference.md)

# CaptCha Python Middleware

Reference ASGI middleware for CaptCha platform integration. It is dependency-free and can be used with ASGI stacks such as Starlette, FastAPI, Django ASGI, or any framework that accepts ASGI middleware.

CaptCha remains the owner of policy, challenge generation, ticket state, clearance state, rate limits, audit, and risk scoring. The middleware only extracts request context, consumes tickets, stores clearance, calls policy evaluation, and applies fail-open or fail-close behavior.

```python
from captcha_middleware import CaptchaASGIMiddleware, CaptchaOptions

app = CaptchaASGIMiddleware(
    app,
    CaptchaOptions(
        platform_url="https://captcha.example.com",
        client_id="your-client",
        client_secret=os.environ["CAPTCHA_CLIENT_SECRET"],
        clearance_header="x-captcha-clearance",
        clearance_cookie_name="captcha_clearance",
        request_nonce_header="x-captcha-request-nonce",
        account_id_hash_header="x-captcha-account-id-hash",
        device_id_hash_header="x-captcha-device-id-hash",
        header_allowlist=["x-request-id", "traceparent"],
        should_protect=lambda scope: scope.get("path", "").startswith("/api"),
    ),
)
```

## Behavior

- Consumes `x-captcha-ticket` before policy evaluation.
- Reads clearance from `x-captcha-clearance` first, then the `captcha_clearance` cookie.
- Sends route, nonce, IP hash, User-Agent hash, account hash, and device hash when consuming a ticket.
- Calls `/api/v1/policy/evaluate` when no ticket is present.
- Writes returned clearance to a response header and HttpOnly SameSite=Lax cookie.
- Reports ticket and fail-open/fail-close outcomes to `/api/v1/events/report`.
- Forwards business headers only through `header_allowlist`.
- Trusts `x-forwarded-for` only when `trusted_proxy_cidrs` includes the direct peer address.

## Test

```bash
cd integrations/python-middleware
PYTHONPATH=. python3 -m unittest discover -s tests
```

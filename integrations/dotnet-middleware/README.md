# CaptCha ASP.NET Core Middleware

Reference ASP.NET Core middleware for CaptCha platform integration.

CaptCha remains the owner of policy, challenge generation, ticket state, clearance state, rate limits, audit, and risk scoring. The middleware only extracts request context, consumes tickets, stores clearance, calls policy evaluation, and applies fail-open or fail-close behavior.

```csharp
using Captcha.AspNetCoreMiddleware;

app.UseCaptcha(options =>
{
    options.PlatformUrl = "https://captcha.example.com";
    options.ClientId = "your-client";
    options.ClientSecret = builder.Configuration["Captcha:ClientSecret"] ?? "";
    options.ClearanceHeader = "X-Captcha-Clearance";
    options.ClearanceCookieName = "captcha_clearance";
    options.RequestNonceHeader = "X-Captcha-Request-Nonce";
    options.AccountIdHashHeader = "X-Captcha-Account-ID-Hash";
    options.DeviceIdHashHeader = "X-Captcha-Device-ID-Hash";
    options.HeaderAllowlist = ["X-Request-ID", "Traceparent"];
    options.ShouldProtect = context => context.Request.Path.StartsWithSegments("/api");
});
```

## Behavior

- Consumes `X-Captcha-Ticket` before policy evaluation.
- Reads clearance from `X-Captcha-Clearance` first, then the `captcha_clearance` cookie.
- Sends route, nonce, IP hash, User-Agent hash, account hash, and device hash when consuming a ticket.
- Calls `/api/v1/policy/evaluate` when no ticket is present.
- Writes returned clearance to a response header and HttpOnly SameSite=Lax cookie.
- Reports ticket and fail-open/fail-close outcomes to `/api/v1/events/report`.
- Forwards business headers only through `HeaderAllowlist`.
- Trusts `X-Forwarded-For` only when `TrustedProxyCidrs` includes the direct peer address.

## Test

```bash
cd integrations/dotnet-middleware
dotnet run --project tests/Captcha.AspNetCoreMiddleware.Tests/Captcha.AspNetCoreMiddleware.Tests.csproj
```

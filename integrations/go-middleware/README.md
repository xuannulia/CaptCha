# CaptCha Go Middleware

Reference `net/http` middleware for CaptCha platform integration.

It stays intentionally thin: CaptCha owns policy, challenge generation, ticket state, clearance state, rate limits, audit, and risk scoring. The middleware extracts request context, consumes a ticket first when one is present, stores any returned clearance token, otherwise calls the platform policy API, reports ticket and fail-policy outcomes asynchronously, and decides whether to call the next handler.

```go
package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	captchamiddleware "captcha/integrations/go-middleware"
)

func main() {
	captcha, err := captchamiddleware.New(captchamiddleware.Options{
		PlatformURL:         "https://captcha.example.com",
		ClientID:            "your-client",
		ClientSecret:        os.Getenv("CAPTCHA_CLIENT_SECRET"),
		ClearanceHeader:     "X-Captcha-Clearance",
		ClearanceCookieName: "captcha_clearance",
		RequestNonceHeader:  "X-Captcha-Request-Nonce",
		AccountIDHashHeader: "X-Captcha-Account-ID-Hash",
		DeviceIDHashHeader:  "X-Captcha-Device-ID-Hash",
		HeaderAllowlist:    []string{"X-Request-ID", "Traceparent"},
		ShouldProtect: func(r *http.Request) bool {
			return strings.HasPrefix(r.URL.Path, "/api")
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	log.Fatal(http.ListenAndServe(":3000", captcha.Handler(mux)))
}
```

## Request Flow

- Skips protection when `ShouldProtect` returns false.
- Consumes `X-Captcha-Ticket` before policy evaluation.
- Sends route, nonce, IP hash, User-Agent hash, account hash, and device hash when consuming a ticket.
- Reads clearance from `X-Captcha-Clearance` first, then the `captcha_clearance` cookie.
- Calls `/api/v1/policy/evaluate` when no ticket is present.
- Writes successful clearance to a response header and HttpOnly SameSite=Lax cookie.
- Reports ticket and fail-open/fail-close outcomes to `/api/v1/events/report`.
- Forwards business headers only through `HeaderAllowlist`.
- Ignores `X-Forwarded-For` unless `TrustedProxyCIDRs` includes the direct peer address.

## Options

Important defaults:

| Option | Default |
|---|---|
| `ClientID` | `demo` |
| `TicketHeader` | `X-Captcha-Ticket` |
| `ClearanceHeader` | `X-Captcha-Clearance` |
| `ClearanceCookieName` | `captcha_clearance` |
| `RequestNonceHeader` | `X-Captcha-Request-Nonce` |
| `AccountIDHashHeader` | `X-Captcha-Account-ID-Hash` |
| `DeviceIDHashHeader` | `X-Captcha-Device-ID-Hash` |
| `FailPolicy` | `fail_open` |
| `Timeout` | `1500ms` |

Set `FailPolicy: "fail_close"` for routes where CaptCha platform unavailability must block protected actions. Set `CircuitBreakerFailureThreshold` and `CircuitBreakerCooldown` to avoid repeated blocking calls during platform incidents.

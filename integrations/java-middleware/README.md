# CaptCha Java Middleware

Reference Java middleware for CaptCha platform integration. This package uses only the JDK and wraps a `com.sun.net.httpserver.HttpHandler`, so it can be compiled and tested without Maven or servlet dependencies. Spring Boot, Spring MVC, and servlet filters can thinly adapt their request/response layer to the same policy and ticket flow.

CaptCha remains the owner of policy, challenge generation, ticket state, clearance state, rate limits, audit, and risk scoring. The middleware only extracts request context, consumes tickets, stores clearance, calls policy evaluation, and applies fail-open or fail-close behavior.

```java
import captcha.middleware.CaptchaMiddleware;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

CaptchaMiddleware.Options options = new CaptchaMiddleware.Options();
options.platformURL = "https://captcha.example.com";
options.clientID = "your-client";
options.clientSecret = System.getenv("CAPTCHA_CLIENT_SECRET");
options.headerAllowlist = List.of("X-Request-ID", "Traceparent");
options.shouldProtect = exchange -> exchange.getRequestURI().getPath().startsWith("/api");

HttpHandler protectedHandler = CaptchaMiddleware.wrap(appHandler, options);
server.createContext("/", protectedHandler);
```

## Behavior

- Consumes `X-Captcha-Ticket` before policy evaluation.
- Reads clearance from `X-Captcha-Clearance` first, then the `captcha_clearance` cookie.
- Sends route, nonce, IP hash, User-Agent hash, account hash, and device hash when consuming a ticket.
- Calls `/api/v1/policy/evaluate` when no ticket is present.
- Writes returned clearance to a response header and HttpOnly SameSite=Lax cookie.
- Reports ticket and fail-open/fail-close outcomes to `/api/v1/events/report`.
- Forwards business headers only through `headerAllowlist`.
- Trusts `X-Forwarded-For` only when `trustedProxyCIDRs` includes the direct peer address.

## Test

```bash
cd integrations/java-middleware
rm -rf build && mkdir -p build/classes
javac -d build/classes $(find src/main/java src/test/java -name '*.java')
java -cp build/classes captcha.middleware.CaptchaMiddlewareSmokeTest
rm -rf build
```

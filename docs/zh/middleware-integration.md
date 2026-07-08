# 中间件接入

语言：中文 | [English](../en/middleware-integration.md)

适合业务服务能加 middleware 的场景。中间件在请求链路里消费 ticket、读写 clearance、调用策略接口，并按配置处理 CaptCha 平台不可用的情况。业务 handler 只处理已经放行的请求。

## 什么时候选

- 业务服务可以改代码。
- 希望统一保护 `/api`、登录、注册、评论、支付等接口。
- 希望自动处理 `captcha_clearance`，减少重复验证。
- 需要把 IP/User-Agent、route、request nonce、可选账号/设备 hash 绑定到 ticket 和 clearance。

## 语言入口

| 运行时 | 包 |
|---|---|
| Node/Express | [Express middleware](../../integrations/express-middleware/README.md) |
| Go `net/http` | [Go middleware](../../integrations/go-middleware/README.md) |
| Python ASGI | [Python middleware](../../integrations/python-middleware/README.md) |
| Java `HttpHandler` | [Java middleware](../../integrations/java-middleware/README.md) |
| ASP.NET Core | [ASP.NET Core middleware](../../integrations/dotnet-middleware/README.md) |

## 最小示例

```ts
import { createCaptchaMiddleware } from "@captcha/express-middleware";

app.use(createCaptchaMiddleware({
  platformURL: "https://captcha.example.com",
  clientID: "demo",
  clientSecret: process.env.CAPTCHA_CLIENT_SECRET,
  shouldProtect: (req) => req.path.startsWith("/api")
}));
```

## 失败策略

中间件默认 `fail_open`：CaptCha 平台超时、不可用或熔断期间，业务请求继续进入后续 handler。这样不会因为验证码平台故障拖垮业务，但风险控制会短暂降级。

可以改成 `fail_close`：平台不可用时返回 `503`，不进入业务 handler。适合支付、改密、批量导出、管理后台等高价值动作。

```ts
app.use(createCaptchaMiddleware({
  platformURL: "https://captcha.example.com",
  clientID: "demo",
  clientSecret: process.env.CAPTCHA_CLIENT_SECRET,
  failPolicy: "fail_close",
  timeoutMs: 1500,
  circuitBreakerFailureThreshold: 3,
  circuitBreakerCooldownMs: 5000,
  shouldProtect: (req) => req.path.startsWith("/api/pay")
}));
```

| 场景 | 默认结果 | 可配置吗 |
|---|---|---|
| `/api/v1/policy/evaluate` 超时、5xx 或网络错误 | `fail_open` 时放行；`fail_close` 时返回 503 | 是，配置 `failPolicy` |
| `/api/v1/tickets/verify` 超时、5xx 或网络错误 | `fail_open` 时放行；`fail_close` 时返回 503 | 是，配置 `failPolicy` |
| 连续失败触发熔断 | 熔断窗口内跳过平台调用，直接执行 `failPolicy` | 是，配置熔断阈值和冷却时间 |
| ticket 存在但平台返回 `valid=false` | 返回 403 | 否。无效 ticket 不应降级放行 |
| 平台返回未知 action | 返回 403 | 否。未知策略动作按 fail closed 处理 |
| 策略返回 `block` / `cooldown` / `require_business_verify` | 返回 403 | 由平台策略决定 |
| 策略返回 `challenge` / `challenge_harder` / `rate_limit` | 返回 403 和 challenge 信息 | 由平台策略决定 |

建议：

- 普通内容接口用 `fail_open`，配短 timeout 和熔断。
- 高价值写操作用 `fail_close`，并在业务侧准备清晰的 503 提示。
- ticket 无效、nonce 不匹配、route 不匹配不要放行；这些不是平台故障，而是验证失败。

## 请求流

1. `shouldProtect` 返回 false：直接进入业务 handler。
2. 请求带 `X-Captcha-Ticket`：先调用 `/api/v1/tickets/verify` 并 `consume=true`。
3. ticket 有效：写回 `X-Captcha-Clearance` 和 `captcha_clearance`，再进入业务 handler。
4. ticket 无效：返回 403，不再调用策略接口。
5. 没有 ticket：读取 `X-Captcha-Clearance` 或 `captcha_clearance`，调用 `/api/v1/policy/evaluate`。
6. 策略允许：进入业务 handler；策略要求挑战或阻断：返回 403。
7. 平台调用异常：按 `failPolicy` 处理，并异步上报事件。

## 通用配置

| 配置 | 默认值 | 说明 |
|---|---|---|
| `platformURL` / `platform_url` / `PlatformURL` | 必填 | CaptCha API 地址。 |
| `clientID` | `demo` | 应用标识。 |
| `clientSecret` | 空 | 放在服务端，用于平台鉴权。 |
| `ticketHeader` | `X-Captcha-Ticket` | Runtime 返回 ticket 后，业务请求携带的 header。 |
| `clearanceHeader` | `X-Captcha-Clearance` | 通行态 header。 |
| `clearanceCookieName` | `captcha_clearance` | 短期 HttpOnly cookie；设为空可关闭 cookie 写入。 |
| `clearanceCookieSecure` | `false` | HTTPS 生产环境建议开启。 |
| `requestNonceHeader` | `X-Captcha-Request-Nonce` | 高风险动作 nonce。 |
| `resourceTagHeader` | `X-Captcha-Resource-Tag` | 指定素材分组或活动素材。 |
| `accountIDHashHeader` | `X-Captcha-Account-ID-Hash` | 可选账号 hash。 |
| `deviceIDHashHeader` | `X-Captcha-Device-ID-Hash` | 可选设备或匿名访客 hash。 |
| `riskScoreHeader` / `riskLevelHeader` | 对应 `X-Captcha-*` | 业务侧已有风险分时传入。 |
| `modelScoreHeader` / `modelModeHeader` | 对应 `X-Captcha-*` | 外部模型上下文。 |
| `headerAllowlist` | 空 | 只上传显式 allowlist 的低敏业务 header。 |
| `trustedProxyCIDRs` | 空 | 只有直连代理 IP 在列表内时才信任 `X-Forwarded-For`。 |
| `timeoutMs` / `Timeout` | 约 1500ms | 平台调用超时。 |
| `failPolicy` | `fail_open` | 平台不可用时放行或返回 503。 |
| `circuitBreakerFailureThreshold` | `0` | 大于 0 时启用熔断。 |
| `circuitBreakerCooldown*` | `0` | 熔断冷却时间。 |

## 账号和设备标识

`account_id_hash` 和 `device_id_hash` 都是可选项。没有 uid 的轻量接入可以只依赖 ticket、短期 clearance、route、request nonce、IP/User-Agent hash。

有账号或匿名访客标识时，建议在业务后端先 HMAC，再传给中间件：

```ts
app.use(createCaptchaMiddleware({
  platformURL: "https://captcha.example.com",
  clientID: "demo",
  clientSecret: process.env.CAPTCHA_CLIENT_SECRET,
  resolveAccountIDHash: (req) => req.user?.captchaAccountHash || "",
  resolveDeviceIDHash: (req) => req.cookies?.visitor_hash || "",
  shouldProtect: (req) => req.path.startsWith("/api")
}));
```

不要把原始 uid、手机号、邮箱或长期设备 ID 直接暴露给浏览器或 CaptCha。

## Cookie 提醒

中间件会写 `captcha_clearance` 这类短期安全/功能 cookie。它用于标记当前浏览器会话已经完成验证，不用于广告、分析或跨站追踪。欧盟和类似 ePrivacy 规则下，接入方应在自己的 cookie policy 中说明用途、TTL 和作用域。

## 上线检查

- `clientSecret` 只在服务端环境变量中配置。
- `failPolicy` 按接口价值分层，不要所有接口无脑 fail-close。
- timeout 保持短值，避免验证码平台拖慢业务。
- 熔断开启后要有监控或日志，能看到 `POLICY_UNAVAILABLE` / `TICKET_SERVICE_UNAVAILABLE`。
- 只 allowlist 低敏 header，不转发 `authorization`、`cookie`。
- 反向代理后面运行时，配置 `trustedProxyCIDRs`，否则不要信任 `X-Forwarded-For`。

## 继续阅读

- [快速接入](quickstart.md)
- [后端 ticket 核销](backend-ticket-verification.md)
- [自定义接入](custom-integration.md)

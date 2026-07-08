# 中间件接入

语言：中文 | [English](../en/middleware-integration.md)

适合业务服务能加 middleware 的场景。中间件在请求链路里处理 ticket、clearance、策略评估和失败策略，业务 handler 只处理已经放行的请求。

## 什么时候选

- 业务服务可以改代码。
- 希望在服务内统一保护 `/api`、登录、注册、评论、支付等接口。
- 希望自动处理 `captcha_clearance`，减少重复验证。
- 需要把 IP/User-Agent、可选账号/设备 hash 绑定到 ticket 和 clearance。

## 语言入口

| 运行时 | 包 |
|---|---|
| Node/Express | [Express middleware](../../integrations/express-middleware/README.md) |
| Go `net/http` | [Go middleware](../../integrations/go-middleware/README.md) |
| Python ASGI | [Python middleware](../../integrations/python-middleware/README.md) |
| Java `HttpHandler` | [Java middleware](../../integrations/java-middleware/README.md) |
| ASP.NET Core | [ASP.NET Core middleware](../../integrations/dotnet-middleware/README.md) |

## Express 最小示例

```ts
import { createCaptchaMiddleware } from "@captcha/express-middleware";

app.use(createCaptchaMiddleware({
  platformURL: "https://captcha.example.com",
  clientID: "demo",
  clientSecret: process.env.CAPTCHA_CLIENT_SECRET,
  shouldProtect: (req) => req.path.startsWith("/api")
}));
```

## 中间件默认做什么

- 优先读取 `X-Captcha-Ticket` 并消费 ticket。
- 读取 `X-Captcha-Clearance` 或 `captcha_clearance`。
- 调用 `/api/v1/policy/evaluate` 做策略评估。
- 成功后写回 `X-Captcha-Clearance` 和短期 HttpOnly cookie。
- 将请求 IP/User-Agent 计算成 hash，避免把原始上下文绑定进 ticket。
- 可选读取 `X-Captcha-Account-ID-Hash` 和 `X-Captcha-Device-ID-Hash`。
- 平台不可用时按配置执行 fail-open 或 fail-close。

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

## 继续阅读

- [快速接入](quickstart.md)
- [后端 ticket 核销](backend-ticket-verification.md)
- [自定义接入](custom-integration.md)

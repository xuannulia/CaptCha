# CaptCha 接入指南

本文按实际接入顺序组织：先跑 Demo，再接最小闭环，最后按部署需要把策略判断前移到中间件或 Gateway。

CaptCha 应保持为服务端掌握的人机验证平台。浏览器 Runtime 只负责展示 challenge 和回传交互事实；答案、评分规则、ticket、clearance、限流、审计和风险信号都留在平台侧。

![CaptCha demo page](../assets/demo-page.png)

在线 Demo：[https://xuannulia.github.io/CaptCha/demo](https://xuannulia.github.io/CaptCha/demo)

## 接入层级

| 层级 | 路径 | 需要改什么 |
|---|---|---|
| 0 | Demo 页面 | 不改业务应用，只跑平台和 Runtime。 |
| 1 | Runtime iframe + 后端 ticket 校验 | 页面加 iframe 或 redirect，后端成功后多一次 ticket 校验。 |
| 2 | 多语言中间件 | 在 Node/Express、Go `net/http`、Python ASGI、Java 或 ASP.NET Core 请求链路里加中间件。 |
| 3 | Gateway 反向代理 | 在已有 HTTP 服务前加代理。 |
| 4 | 直接 HTTP / gRPC API | 自研 Gateway、服务网格适配器或内部平台控制面。 |
| 5 | 生产治理 | 管理 token、存储、Redis、素材、审计、模型版本和发布检查。 |

## Level 0：运行 Demo

启动 API Server：

```bash
go run ./cmd/captcha-server
```

另开终端启动 Runtime：

```bash
npm run dev:runtime
```

访问：

```text
http://localhost:5173/demo
```

## Level 1：Runtime iframe + 后端 ticket 校验

这是最小生产形态。业务页面在需要保护的动作前打开 Runtime；用户通过验证后，业务后端在真正完成动作前校验或消费返回的 ticket。

先在管理台创建应用。生成的 `client_secret` 只放在后端、Gateway 或中间件里。

- `client_id` 是公开标识，可以传给 iframe Runtime。
- `client_secret` 是私密凭据，不能进入浏览器。
- 创建公开 challenge 不使用 client secret。
- Policy、Ticket、Config 和 Event API 在应用配置 secret 后会校验 secret。

最小 iframe URL：

```text
https://captcha.example.com/?client_id=your-client&scene=login&captcha_type=AUTO
```

真实高风险动作建议绑定 route 和一次性 nonce：

```text
https://captcha.example.com/?client_id=your-client&scene=login&captcha_type=AUTO&route=/api/login&request_nonce=nonce-123
```

常用 Runtime 参数：

| 参数 | 说明 |
|---|---|
| `client_id` | 应用标识。 |
| `scene` | 业务场景，如 `login`、`register`、`verify`、`pay`。 |
| `captcha_type` | 具体验证码类型，或 `AUTO` / `RANDOM`。 |
| `route` | ticket 绑定的业务路由。 |
| `request_nonce` | ticket 绑定的一次性请求 nonce。 |
| `return_url` | redirect 模式返回地址，必须通过 allowlist。 |
| `resource_tag` | 可选素材标签。 |
| `input_device` | 可选采集提示，如 `mouse`、`trackpad`、`touch`。 |

Runtime 通过 `postMessage` 返回 `CAPTCHA_SUCCESS` 和一次性 `ticket`。redirect 模式会在 `return_url` 后追加 `captcha_ticket`、`captcha_session_id` 和绑定上下文。

后端完成受保护动作前校验 ticket：

```bash
curl -X POST https://captcha.example.com/api/v1/tickets/verify \
  -H 'content-type: application/json' \
  -H 'X-Captcha-Client-Secret: cap_secret_xxx' \
  -d '{
    "client_id": "your-client",
    "scene": "login",
    "ticket": "ticket-from-runtime",
    "route": "/api/login",
    "request_nonce": "nonce-123",
    "consume": true
  }'
```

后续请求可以使用消费 ticket 后返回的 clearance。匿名场景优先使用 clearance cookie 加设备或访客标识，不要把 IP 当成长期白名单。

默认中间件和 Gateway 会把通行态写入 `captcha_clearance` 这类短期安全 cookie，用于减少重复验证并支撑策略判断。它不应用于广告、分析、跨站识别或长期画像。在欧盟和类似 ePrivacy 规则下，写入或读取 cookie、local storage、匿名访客 ID 等终端存储都可能触发 cookie / terminal storage 合规要求；接入方应在自己的 cookie policy 中说明用途、TTL 和作用域，并按地区判断是否需要同意或额外告知。

标记维度按接入深度增加。iframe 最小接入只要求后端消费 ticket；中间件、Gateway 和自研 API 应传入可信服务端解析出的 IP/User-Agent，可选传入 `account_id_hash` / `device_id_hash`。这些字段会绑定到策略创建的 session、验证成功后的 ticket 和后续 clearance，消费 ticket 或校验 clearance 时必须匹配。没有 uid 时不要伪造账号标识，使用短期 clearance、route、一次性 nonce、IP/User-Agent hash 和可选匿名设备 hash 即可。

## Level 2：多语言中间件

业务服务可以改请求链路时，优先使用中间件。

| 运行时 | 包 |
|---|---|
| Node/Express | `integrations/express-middleware` |
| Go `net/http` | `integrations/go-middleware` |
| Python ASGI | `integrations/python-middleware` |
| Java JDK `HttpHandler` | `integrations/java-middleware` |
| ASP.NET Core | `integrations/dotnet-middleware` |

Express 示例：

```ts
import express from "express";
import { createCaptchaMiddleware } from "@captcha/express-middleware";

const app = express();

app.use(createCaptchaMiddleware({
  platformURL: "https://captcha.example.com",
  clientID: "your-client",
  clientSecret: process.env.CAPTCHA_CLIENT_SECRET,
  clearanceHeader: "x-captcha-clearance",
  clearanceCookieName: "captcha_clearance",
  requestNonceHeader: "x-captcha-request-nonce",
  accountIDHashHeader: "x-captcha-account-id-hash",
  deviceIDHashHeader: "x-captcha-device-id-hash",
  headerAllowlist: ["x-request-id", "traceparent"],
  shouldProtect: (req) => req.path.startsWith("/api")
}));
```

Go 示例：

```go
captcha, err := captchamiddleware.New(captchamiddleware.Options{
  PlatformURL:         "https://captcha.example.com",
  ClientID:            "your-client",
  ClientSecret:        os.Getenv("CAPTCHA_CLIENT_SECRET"),
  ClearanceHeader:     "X-Captcha-Clearance",
  ClearanceCookieName: "captcha_clearance",
  RequestNonceHeader:  "X-Captcha-Request-Nonce",
  AccountIDHashHeader: "X-Captcha-Account-ID-Hash",
  DeviceIDHashHeader:  "X-Captcha-Device-ID-Hash",
  HeaderAllowlist:     []string{"X-Request-ID", "Traceparent"},
  ShouldProtect: func(r *http.Request) bool {
    return strings.HasPrefix(r.URL.Path, "/api")
  },
})
if err != nil {
  log.Fatal(err)
}

http.ListenAndServe(":3000", captcha.Handler(mux))
```

各中间件都会消费 ticket、写入 clearance、调用策略评估、异步上报 fail-open/fail-close 结果，并在允许时继续调用下一个 handler。策略、ticket 状态、clearance 状态、限流、审计和风险评分仍由 CaptCha 平台掌握。

## Level 3：Gateway 反向代理

已有服务不方便改代码时，把 Gateway 放在业务服务前面。

```bash
CAPTCHA_UPSTREAM_URL=http://localhost:3000 \
CAPTCHA_PLATFORM_URL=http://localhost:8080 \
CAPTCHA_CLIENT_ID=your-client \
CAPTCHA_CLIENT_SECRET=cap_secret_xxx \
CAPTCHA_GATEWAY_HEADER_ALLOWLIST=x-request-id,traceparent \
  go run ./cmd/captcha-gateway
```

Gateway 会：

- 优先消费 `X-Captcha-Ticket`。
- 把返回的 clearance 写入 `X-Captcha-Clearance` 和 HttpOnly cookie。
- 将已有 clearance 传给策略评估。
- 代理前向 CaptCha 策略接口询问放行、挑战或阻断。
- 策略返回 `challenge` 时返回 challenge 详情。
- 阻断无效或已消费 ticket。
- 只转发显式 allowlist 的低敏业务头。

平台和 Gateway 网络距离较近时，可以用 gRPC 作为策略路径：

```bash
CAPTCHA_GATEWAY_POLICY_TRANSPORT=grpc \
CAPTCHA_PLATFORM_GRPC_ADDR=captcha.example.com:9090 \
CAPTCHA_PLATFORM_GRPC_TOKEN=change-me-grpc \
  go run ./cmd/captcha-gateway
```

## Level 4：直接 HTTP / gRPC API

自研 Gateway、服务网格适配器或内部平台控制面时使用这一层。

HTTP 方便早期联调：

```bash
curl -X POST https://captcha.example.com/api/v1/policy/evaluate \
  -H 'content-type: application/json' \
  -H 'X-Captcha-Client-Secret: cap_secret_xxx' \
  -d '{
    "client_id": "your-client",
    "scene": "login",
    "path": "/api/login",
    "method": "POST",
    "ip": "203.0.113.10",
    "user_agent": "browser user-agent"
  }'
```

gRPC 更适合作为长期数据面。它提供策略评估、ticket 消费、配置快照、配置监听和事件上报的强类型契约。gRPC 应使用 `CAPTCHA_GRPC_TOKEN` 或等效部署边界保护，同时应用级 client secret 和平台 token 要分开处理。

完整接口见 [API 文档](api-reference.md)。

## Level 5：生产配置

生产环境至少配置：

- `CAPTCHA_ENV=production`
- `CAPTCHA_ADMIN_TOKEN`
- `CAPTCHA_GRPC_TOKEN`
- `CAPTCHA_METRICS_TOKEN`
- `CAPTCHA_ALLOWED_ORIGINS`
- `CAPTCHA_ALLOWED_RETURN_URL_ORIGINS`
- `CAPTCHA_POSTGRES_DSN`
- `CAPTCHA_REDIS_ADDR`
- `CAPTCHA_SEED_DEMO=false`

生产模式下这些配置缺失或不安全时，服务会拒绝启动。

## 安全边界

- 不要把 `client_secret`、admin token、metrics token 或 gRPC token 放进浏览器。
- 不接受浏览器提交的答案、目标点、容差、评分规则或评分阈值。
- ticket 校验或消费失败必须按失败处理。
- 高风险动作绑定 route 和一次性 nonce。
- Gateway 和中间件默认不要转发 `authorization`、`cookie` 等敏感头。
- 公开采集流量只进入候选样本，不能直接进入训练集。

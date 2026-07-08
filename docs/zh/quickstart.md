# 快速接入

语言：中文 | [English](../en/quickstart.md)

这页只保留最短闭环。下面用 `https://captcha.example.com` 表示你的 CaptCha Runtime/API 公开地址；如果 Runtime 和 API 分域，iframe 用 Runtime 域名，后端核销用 API 域名。`client_secret` 只放在后端、中间件或 Gateway。

## 1. Docker 启动平台

```bash
docker compose up --build
```

生产环境请在部署平台里配置真实 token、CORS origin、PostgreSQL 和 Redis；这里不展开。

## 2. Iframe 最小接入

业务页在受保护动作前打开 Runtime。`request_nonce` 示例写死是为了说明字段，生产中应由业务后端按动作生成。

```html
<iframe
  src="https://captcha.example.com/?client_id=demo&scene=login&captcha_type=AUTO&route=/api/login&request_nonce=nonce-123"
  width="360"
  height="420"
  title="CaptCha"
></iframe>

<script>
  window.addEventListener("message", (event) => {
    if (event.origin !== "https://captcha.example.com") return;
    if (event.data?.type !== "CAPTCHA_SUCCESS") return;

    fetch("/api/login", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-captcha-ticket": event.data.ticket,
        "x-captcha-request-nonce": "nonce-123"
      },
      body: JSON.stringify({ username: "alice", password: "secret" })
    });
  });
</script>
```

## 3. 后端核销 ticket

业务后端在真正执行登录、注册、支付等动作前消费 ticket。消费失败就按验证失败处理。

```ts
app.post("/api/login", async (req, res) => {
  const result = await fetch("https://captcha.example.com/api/v1/tickets/verify", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-captcha-client-secret": process.env.CAPTCHA_CLIENT_SECRET || ""
    },
    body: JSON.stringify({
      client_id: "demo",
      scene: "login",
      ticket: req.get("x-captcha-ticket") || "",
      route: "/api/login",
      request_nonce: req.get("x-captcha-request-nonce") || "",
      consume: true
    })
  }).then((response) => response.json());

  if (!result.valid) {
    return res.status(403).json({ error: result.reason || "CAPTCHA_FAILED" });
  }

  return res.json({ ok: true });
});
```

## 4. 中间件最小接入

服务能加 middleware 时，用中间件接管 ticket、clearance、策略和失败处理。

```ts
import { createCaptchaMiddleware } from "@captcha/express-middleware";

app.use(createCaptchaMiddleware({
  platformURL: "https://captcha.example.com",
  clientID: "demo",
  clientSecret: process.env.CAPTCHA_CLIENT_SECRET,
  shouldProtect: (req) => req.path.startsWith("/api")
}));
```

中间件默认读取 `X-Captcha-Ticket`、`X-Captcha-Clearance` 和 `captcha_clearance`，会把请求 IP/User-Agent hash、可选账号/设备 hash 送入平台，并在通过后写入短期 clearance。

## 5. 自定义接入

自研 Gateway、服务网格或平台控制面用策略接口。它适合你自己决定挑战、放行、阻断和 cookie 写入。

```ts
const decision = await fetch("https://captcha.example.com/api/v1/policy/evaluate", {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "x-captcha-client-secret": process.env.CAPTCHA_CLIENT_SECRET || ""
  },
  body: JSON.stringify({
    client_id: "demo",
    scene: "login",
    path: req.path,
    method: req.method,
    ip: req.ip,
    user_agent: req.get("user-agent") || "",
    ticket: req.get("x-captcha-ticket") || "",
    clearance: req.cookies?.captcha_clearance || "",
    request_nonce: req.get("x-captcha-request-nonce") || "",
    account_id_hash: req.user?.captchaAccountHash || "",
    device_id_hash: req.get("x-captcha-device-id-hash") || ""
  })
}).then((response) => response.json());

if (decision.clearance_token) {
  res.cookie("captcha_clearance", decision.clearance_token, {
    httpOnly: true,
    sameSite: "lax",
    secure: true,
    maxAge: (decision.clearance_ttl_seconds || 600) * 1000
  });
}

if (["allow", "observe", "pass"].includes(decision.action)) return next();
if (["challenge", "challenge_harder"].includes(decision.action)) {
  return res.status(403).json(decision);
}
return res.status(403).json({ error: decision.reason || "CAPTCHA_BLOCKED" });
```

最小原则：

- iframe 接入：拿 ticket，后端消费 ticket。
- 中间件接入：让中间件处理 ticket、clearance、IP/UA 绑定、策略和上报。
- 自定义接入：自己传入 ticket、clearance、route、nonce、IP/UA、账号/设备 hash，并对未知 action 默认拒绝。
- `captcha_clearance` 是短期安全/功能 cookie；在欧盟和类似 ePrivacy 语境下，接入方应在自己的 cookie policy 中说明用途、TTL 和作用域。

下一步：

- [完整接入指南](integration-guide.md)
- [HTTP / gRPC API](api-reference.md)
- [Express middleware](../../integrations/express-middleware/README.md)

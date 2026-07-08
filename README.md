# CaptCha

服务端验证码平台。浏览器只负责展示和上报交互轨迹；答案、策略、ticket、clearance、限流、审计和风控判断都在服务端。

![CaptCha demo page](docs/assets/demo-page.png)

- Demo: [https://xuannulia.github.io/CaptCha/](https://xuannulia.github.io/CaptCha/)
- License: [AGPL-3.0-only](LICENSE)

## 包含什么

- Go API server：验证码、ticket、策略、审计、资源和管理接口。
- Runtime 前端：业务页面嵌入的验证码界面。
- Admin 前端：应用、路由策略、素材、审计、样本和模型版本管理。
- Gateway：放在业务服务前的反向代理。
- 中间件：Express、Go `net/http`、Python ASGI、Java `HttpHandler`、ASP.NET Core。
- HTTP / gRPC API：接入自研网关、服务网格或平台控制面。

## 本地启动

默认使用内存存储和 demo 数据。

```bash
go run ./cmd/captcha-server
```

另开一个终端：

```bash
npm run dev:runtime
```

访问：

```text
http://localhost:5173/demo
```

## 接入方式

| 方式 | 什么时候选 | 入口 |
|---|---|---|
| Runtime iframe + 后端 ticket 校验 | 页面和后端都能改；改动最小 | [接入指南](docs/integration-guide.md) |
| 中间件 | 服务能加 middleware；在请求链路内处理 ticket、clearance 和策略 | [中间件](#中间件) |
| Gateway | 业务服务不便改；在入口统一拦截 | [Gateway](#gateway) |
| HTTP / gRPC API | 已有网关、服务网格或平台控制面 | [架构设计](docs/architecture-design.md) |

## 管理台

Admin 不参与业务请求接入。它用于管理应用、路由策略、素材、审计、样本和模型版本。

- 文档：[管理计划](docs/admin-management-plan.md)
- 本地启动：`npm run dev:admin`

## 中间件

- [Express middleware](integrations/express-middleware/README.md)
- [Go `net/http` middleware](integrations/go-middleware/README.md)
- [Python ASGI middleware](integrations/python-middleware/README.md)
- [Java `HttpHandler` middleware](integrations/java-middleware/README.md)
- [ASP.NET Core middleware](integrations/dotnet-middleware/README.md)

Express 示例：

```ts
import express from "express";
import { createCaptchaMiddleware } from "@captcha/express-middleware";

const app = express();

app.use(createCaptchaMiddleware({
  platformURL: "http://localhost:8080",
  clientID: "demo",
  clientSecret: "cap_secret_xxx",
  shouldProtect: (req) => req.path.startsWith("/api")
}));
```

## Gateway

```bash
CAPTCHA_UPSTREAM_URL=http://localhost:3000 \
CAPTCHA_PLATFORM_URL=http://localhost:8080 \
CAPTCHA_CLIENT_SECRET=cap_secret_xxx \
  go run ./cmd/captcha-gateway
```

Docker Compose profile：

```bash
CAPTCHA_UPSTREAM_URL=http://host.docker.internal:3000 \
  docker compose --profile gateway up --build
```

## 生产配置

生产环境至少配置这些项：

- `CAPTCHA_ADMIN_TOKEN`
- `CAPTCHA_GRPC_TOKEN`
- `CAPTCHA_METRICS_TOKEN`
- `CAPTCHA_ALLOWED_ORIGINS`
- `CAPTCHA_ALLOWED_RETURN_URL_ORIGINS`
- `CAPTCHA_POSTGRES_DSN`
- `CAPTCHA_REDIS_ADDR`
- `CAPTCHA_SEED_DEMO=false`

示例：

```bash
CAPTCHA_ENV=production \
CAPTCHA_ADMIN_TOKEN='change-me-admin' \
CAPTCHA_GRPC_TOKEN='change-me-grpc' \
CAPTCHA_METRICS_TOKEN='change-me-metrics' \
CAPTCHA_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com \
CAPTCHA_ALLOWED_RETURN_URL_ORIGINS=https://app.example.com \
CAPTCHA_POSTGRES_DSN='postgres://captcha:captcha@localhost:5432/captcha?sslmode=disable' \
CAPTCHA_REDIS_ADDR=localhost:6379 \
CAPTCHA_SEED_DEMO=false \
  go run ./cmd/captcha-server
```

## Docker

本地依赖：

```bash
docker compose -f docker-compose.dev.yml up -d
```

完整平台：

```bash
docker compose up --build
```

构建镜像：

```bash
make docker-build
```

## 验证

日常开发：

```bash
go test ./...
npm run build
```

提交前：

```bash
make verify
```

真实浏览器 smoke：

```bash
make browser-smoke
```

发布前：

```bash
make release-audit
```

清理构建产物：

```bash
make clean
```

## 风控样本

验证后会异步保存轨迹特征快照。样本不包含答案、素材 URI、完整 metadata 或 checksum。只有明确标注为人类/机器人的样本会进入训练集。

生成模拟机器人负样本：

```bash
make synthetic-bot-tracks
```

输出：

```text
output/synthetic-bot-tracks.jsonl
```

## 文档

- [接入指南](docs/integration-guide.md)
- [架构设计](docs/architecture-design.md)
- [实现审计](docs/implementation-audit.md)
- [发布检查](docs/release-checklist.md)
- [开源发布说明](docs/open-source-release.md)
- [安全策略](SECURITY.md)
- [贡献指南](CONTRIBUTING.md)

## 协议

gRPC 契约：[proto/captcha/v1/captcha.proto](proto/captcha/v1/captcha.proto)。

修改 proto 后重新生成：

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
make proto
```

AGPL 提醒：如果你通过网络提供基于本项目修改后的服务，需要按 [AGPL-3.0-only](LICENSE) 向服务使用者提供相应源码。

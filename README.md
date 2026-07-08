# CaptCha

CaptCha 是一个服务端掌握答案、策略和票据的人机验证平台。浏览器只负责展示验证码和回传交互事实；答案、评分规则、短期票据、通行态、限流、审计和风控决策都留在服务端。

CaptCha is a server-owned human verification platform. The browser renders challenges and sends interaction facts back; answers, scoring rules, short-lived tickets, clearance, rate limits, audit, and policy decisions stay on the server side.

![CaptCha demo page](docs/assets/demo-page.png)

许可证 / License: [AGPL-3.0-only](LICENSE)

## 在线演示 / Online Demo

先看演示，再决定要不要接入。演示站点使用 GitHub Pages 托管前端，后端部署在远端服务上。

Try the demo before wiring it into an application. The frontend is hosted on GitHub Pages and talks to a deployed backend.

- 演示页 / Demo: [https://xuannulia.github.io/CaptCha/](https://xuannulia.github.io/CaptCha/)

公开演示页主要用于查看验证码体验、素材质量和前后端闭环。

The public demo is mainly for checking challenge behavior, material quality, and the frontend-backend loop.

## 这个项目解决什么 / What It Solves

CaptCha 不是一个单纯的前端小组件。它更像一套可私有化的人机验证控制面：你可以管理应用、路由策略、验证码素材、一次性 ticket、通行态、审计事件、轨迹样本和模型版本。

CaptCha is not just a browser widget. It is a self-hostable verification control plane for applications, route policies, captcha materials, one-time tickets, clearance, audit events, behavior samples, and model versions.

适合这些场景：

Good fits:

- 你希望验证码答案和校验规则不暴露给浏览器。
- You do not want answers or verification rules exposed to the browser.
- 你希望按应用、接口、IP、风险分或业务场景调整验证策略。
- You want policies by application, route, IP, risk score, or business scene.
- 你需要 Gateway / 中间件 / HTTP / gRPC 多种接入方式。
- You need Gateway, middleware, HTTP, or gRPC integration paths.
- 你希望收集轨迹样本，但不让公开采集流量直接进入训练集。
- You want behavior sample collection without letting public traffic directly poison the training set.

## 本地快速启动 / Local Quick Start

第一步只需要跑 API 服务和 Runtime 前端。默认会使用内存存储和内置 demo 数据。

The first run only needs the API server and the Runtime frontend. By default it uses in-memory storage and seeded demo data.

```bash
go run ./cmd/captcha-server
```

另开一个终端：

In another terminal:

```bash
npm run dev:runtime
```

打开本地演示页：

Open the local demo:

```text
http://localhost:5173/demo
```

本地 demo 会使用 `demo` 应用和 `resources/captcha-demo` 下的素材，覆盖随机、手势、曲线、滑块、旋转、拼图、文字点选、图标点选和图片格子等验证码类型。

The local demo uses the seeded `demo` application and materials under `resources/captcha-demo`. It covers random, gesture, curve, slider, rotate, concat, word-click, icon-click, jigsaw, and image-grid challenges.

## 接入路径 / Integration Paths

按接入难度从低到高看这张表。第一次接入建议先走 Level 1，等验证闭环稳定后再考虑 Gateway 或更重的策略治理。

Read this from the smallest useful path to the heavier platform paths. For a first integration, Level 1 is usually the cleanest starting point.

| 等级 / Level | 路径 / Path | 适合场景 / When It Fits |
|---|---|---|
| 0 | 只看 Demo / Demo only | 先检查验证码体验和素材质量，不改业务代码。 / Inspect challenge behavior and material quality before touching your app. |
| 1 | Runtime iframe + 后端 ticket 校验 / Runtime iframe + backend ticket check | 页面加 iframe，后端多一次 ticket 校验；这是最小的生产形态。 / Add an iframe and one backend ticket check; this is the smallest production-shaped path. |
| 2 | Express 中间件 / Express middleware | Node/Express 服务希望在常规请求链路里接入。 / Your service is Node/Express and wants normal middleware protection. |
| 3 | Gateway 反向代理 / Gateway reverse proxy | 不想大改业务服务，希望在入口统一拦截。 / You want protection in front of an existing HTTP service. |
| 4 | HTTP / gRPC API 直连 / Direct HTTP or gRPC APIs | 自己有网关、服务网格或平台控制面。 / You are integrating with a gateway, service mesh, or custom platform layer. |
| 5 | 运营治理 / Operations | 开始维护策略、素材、审计、样本、模型版本和发布闸门。 / You are ready to operate policies, materials, audit, samples, model versions, and release gates. |

详细接入步骤在 [docs/integration-guide.md](docs/integration-guide.md)。系统边界、API、资源模型和安全设计在 [docs/architecture-design.md](docs/architecture-design.md)。

The walkthrough lives in [docs/integration-guide.md](docs/integration-guide.md). System boundaries, APIs, resource model, and security design live in [docs/architecture-design.md](docs/architecture-design.md).

## 常用部署配置 / Common Deployment Settings

如果 Runtime 和 API 不在同一个域名，设置 Runtime 地址：

Set the Runtime URL when the iframe runtime is hosted on another origin:

```bash
CAPTCHA_RUNTIME_URL=https://captcha.example.com go run ./cmd/captcha-server
```

生产环境要显式限制浏览器来源和 redirect 返回地址：

In production, restrict browser origins and redirect return targets explicitly:

```bash
CAPTCHA_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com \
CAPTCHA_ALLOWED_RETURN_URL_ORIGINS=https://app.example.com \
  go run ./cmd/captcha-server
```

保护管理 API：

Protect admin APIs:

```bash
CAPTCHA_ADMIN_TOKEN='change-me-admin' go run ./cmd/captcha-server
```

启用生产安全闸门后，缺少管理 token、gRPC token、metrics token、明确 CORS、PostgreSQL、Redis，或未关闭 demo seed，服务都会拒绝启动。

With the production gate enabled, startup fails if admin, gRPC, metrics tokens, explicit CORS, PostgreSQL, Redis, or disabled demo seeding are missing.

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

## 存储和容器 / Storage And Containers

只跑本地依赖：

Run local storage dependencies only:

```bash
docker compose -f docker-compose.dev.yml up -d
```

使用 PostgreSQL 和 Redis 启动完整平台：

Run the platform with PostgreSQL and Redis:

```bash
docker compose up --build
```

启动参考 Gateway：

Start the reference Gateway profile:

```bash
CAPTCHA_UPSTREAM_URL=http://host.docker.internal:3000 \
  docker compose --profile gateway up --build
```

直接构建 Docker 镜像：

Build Docker images directly:

```bash
docker build -f deploy/docker/Dockerfile.server .
docker build -f deploy/docker/Dockerfile.gateway .
```

## Gateway 和中间件 / Gateway And Middleware

参考 Gateway 可以放在业务服务前面，先消费 ticket 或 clearance，再按平台策略决定放行、挑战或拦截。

The reference Gateway sits in front of an upstream service. It consumes tickets or clearance first, then asks the platform policy API whether to allow, challenge, or block.

```bash
CAPTCHA_UPSTREAM_URL=http://localhost:3000 \
CAPTCHA_PLATFORM_URL=http://localhost:8080 \
CAPTCHA_CLIENT_SECRET=cap_secret_xxx \
  go run ./cmd/captcha-gateway
```

Express 中间件保持很薄：业务服务只接入中间件，策略、ticket、clearance、限流、风控阈值和审计仍由平台掌握。

The Express middleware stays intentionally thin. Your service adds middleware, while policy, ticket state, clearance, rate limits, risk thresholds, and audit remain owned by the platform.

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

## 风控样本 / Risk Samples

验证码验证后会异步写入轨迹特征快照。样本包含轨迹统计、粗粒度输入设备信息和脱敏资源摘要，不写入答案、素材 URI、完整 metadata 或 checksum。只有明确的人类/机器人标签才会进入可训练样本。

After verification, CaptCha asynchronously stores behavior feature snapshots. Samples contain track statistics, coarse input metadata, and sanitized resource summaries; they do not include answers, material URIs, full metadata, or checksums. Only explicit human/bot labels can become trainable.

生成本地模拟机器人负样本：

Generate local synthetic bot negative samples:

```bash
make synthetic-bot-tracks
# writes output/synthetic-bot-tracks.jsonl
```

## 验证和发布 / Verification And Release

日常开发先跑：

For day-to-day development:

```bash
go test ./...
npm run build
```

标准本地校验：

Standard local verification:

```bash
make verify
```

真实浏览器 smoke：

Real-browser smoke test:

```bash
make browser-smoke
```

发布前审计：

Release audit:

```bash
make release-audit
```

构建发布镜像：

Build release Docker images:

```bash
make docker-build
```

清理本地构建产物：

Clean local build outputs:

```bash
make clean
```

CI 会运行 `make verify` 和 `make docker-build`。公开发布前，`make release-audit` 应该报告 `0 failure(s), 0 warning(s)`。

CI runs `make verify` and `make docker-build`. Before a public release, `make release-audit` should report `0 failure(s), 0 warning(s)`.

## 文档地图 / Docs

- [接入指南 / Integration guide](docs/integration-guide.md)
- [架构设计 / Architecture design](docs/architecture-design.md)
- [发布检查 / Release checklist](docs/release-checklist.md)
- [开源发布说明 / Open-source release notes](docs/open-source-release.md)
- [实现审计 / Implementation audit](docs/implementation-audit.md)
- [安全策略 / Security policy](SECURITY.md)
- [贡献指南 / Contributing](CONTRIBUTING.md)

## 协议 / Protocols

gRPC 契约在 [proto/captcha/v1/captcha.proto](proto/captcha/v1/captcha.proto)。生成的 Go protobuf 代码在 `gen/captcha/v1`。

The gRPC contract is in [proto/captcha/v1/captcha.proto](proto/captcha/v1/captcha.proto). Generated Go protobuf code lives under `gen/captcha/v1`.

修改 proto 后重新生成：

Regenerate protobuf code after editing the contract:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
make proto
```

## 开源许可 / License

CaptCha 使用 [AGPL-3.0-only](LICENSE)。如果你通过网络提供基于本项目修改后的服务，也需要按 AGPL 的要求向服务使用者提供相应源码。

CaptCha is licensed under [AGPL-3.0-only](LICENSE). If you provide a network service based on a modified version of this project, AGPL requires you to provide the corresponding source code to service users.

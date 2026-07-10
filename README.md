# CaptCha

语言：中文 | [English](README.en.md)

[![CI](https://github.com/xuannulia/CaptCha/actions/workflows/ci.yml/badge.svg)](https://github.com/xuannulia/CaptCha/actions/workflows/ci.yml)
[![Pages](https://github.com/xuannulia/CaptCha/actions/workflows/pages.yml/badge.svg)](https://github.com/xuannulia/CaptCha/actions/workflows/pages.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](LICENSE)
![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-22-339933?logo=node.js&logoColor=white)
![Backend verification](https://img.shields.io/badge/Backend-Verification-2ea44f)
![Trajectory recognition](https://img.shields.io/badge/Trajectory-Recognition-6f42c1)
![Ticket clearance](https://img.shields.io/badge/Ticket-Clearance-0969da)
![Self hosted](https://img.shields.io/badge/Self--hosted-Captcha-555)

后端验证型验证码平台，带轨迹识别、ticket、clearance 和策略风控。浏览器只负责展示和上报交互轨迹；答案、策略、限流、审计和风控判断都在服务端。

![CaptCha 演示页面](docs/assets/demo-page.png)

- 快速接入：[5 分钟跑通接入](docs/zh/quickstart.md)
- 在线演示：[https://xuannulia.github.io/CaptCha/demo/](https://xuannulia.github.io/CaptCha/demo/)
- 许可证：[AGPL-3.0-only](LICENSE)

## 为什么不是第三方验证码服务

CaptCha 适合你需要自己掌握验证链路的场景：

- 策略、素材、答案、ticket、clearance 和审计数据留在自己的服务端。
- 不把用户行为轨迹交给第三方验证码平台。
- 私有化部署，或运行环境无法稳定访问外部验证码服务。
- 验证码只是风控链路的一层，需要和限流、账号信誉、IP 风险、设备信号、业务规则一起工作。

## 包含什么

- Go API server：验证码、ticket、策略、审计、资源和管理接口。
- Runtime 前端：业务页面嵌入的验证码界面。
- Admin 前端：应用、路由策略、素材、审计、样本和模型版本管理。
- Gateway：放在业务服务前的反向代理。
- 中间件：Express、Go `net/http`、Python ASGI、Java `HttpHandler`、ASP.NET Core。
- HTTP / gRPC API：接入自研网关、服务网格或平台控制面。

## 项目状态

当前是早期可运行版本。

已具备：

- API Server、Runtime 前端、Demo 数据。
- Gateway 和 Express / Go / Python / Java / ASP.NET Core 中间件。
- PostgreSQL / Redis 配置。
- 基础审计、ticket、clearance、策略评估和样本快照。

仍在完善：

- 管理台体验和策略编辑器。
- 更多可直接复用的验证码素材。
- 模型训练闭环和性能压测报告。

## 架构一览

```mermaid
flowchart LR
  Browser["业务浏览器"] --> Runtime["Runtime iframe / redirect"]
  Browser --> Entry["中间件 / Gateway"]
  Runtime --> API["CaptCha API Server"]
  Entry --> API
  Entry --> Upstream["业务服务"]
  API --> Challenge["challenge / ticket / clearance"]
  API --> Policy["policy / rate limit / audit"]
  API --> Resource["resource manager"]
  API --> Sample["sample snapshots"]
  API --> Store[("PostgreSQL / Redis")]
```

## 本地启动

想先看最短业务闭环，请直接看 [快速接入](docs/zh/quickstart.md)。

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

## 业务流量接入

这三种方式决定业务请求在哪里被拦截。

| 方式 | 什么时候选 | 入口 |
|---|---|---|
| Runtime iframe + 后端 ticket 校验 | 页面和后端都能改；改动最小 | [后端核销](docs/zh/backend-ticket-verification.md) |
| 中间件 | 服务能加 middleware；在请求链路内处理 ticket、clearance 和策略 | [中间件接入](docs/zh/middleware-integration.md) |
| Gateway | 业务服务不便改；在入口统一拦截 | [Gateway](#gateway) |

## 自研接入

HTTP / gRPC API 是底层接口，不是和中间件、Gateway 并列的开箱接入方式。已有网关、服务网格或平台控制面时，用它们自己封装接入层。

- 接入说明：[自定义接入](docs/zh/custom-integration.md)
- API 文档：[HTTP / gRPC API](docs/zh/api-reference.md)

## 标记和区分能力

CaptCha 按接入深度逐步增强标记能力：

| 接入层级 | 标记维度 | 说明 |
|---|---|---|
| Runtime iframe | `ticket`、可选 `route` / `request_nonce` | 最小接入。浏览器通过验证后拿到一次性 ticket，业务后端消费即可。 |
| 中间件 / Gateway | `ticket`、`clearance`、IP hash、User-Agent hash、可选 `account_id_hash` / `device_id_hash` | 推荐业务流量接入。ticket 消费前校验绑定上下文，成功后写短期通行态。 |
| HTTP / gRPC 自研接入 | 同中间件，由接入方显式传入 | 适合自研网关、服务网格或平台控制面，需要自己完成 ticket 消费、clearance 传递和失败处理。 |

`account_id_hash` 和 `device_id_hash` 都是可选项。没有 uid 的轻量接入可以只依赖 ticket、短期 clearance、route、request nonce、IP/User-Agent hash；有账号或匿名访客标识时，建议由业务后端 HMAC 后传入 hash，不要传原始 uid。中间件、Gateway 和自研 API 创建的 challenge 会把这些维度绑定进 session；验证成功签发的 ticket 会继续校验已绑定的账号/设备维度，消费成功后再签发绑定同一上下文的 clearance。

## 管理台

Admin 不参与业务请求接入。它用于管理应用、路由策略、素材、审计、样本和模型版本。

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
- `CAPTCHA_COLLECTOR_TOKEN`
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
CAPTCHA_COLLECTOR_TOKEN='change-me-collector' \
CAPTCHA_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com \
CAPTCHA_ALLOWED_RETURN_URL_ORIGINS=https://app.example.com \
CAPTCHA_POSTGRES_DSN='postgres://captcha:captcha@localhost:5432/captcha?sslmode=disable' \
CAPTCHA_REDIS_ADDR=localhost:6379 \
CAPTCHA_SEED_DEMO=false \
  go run ./cmd/captcha-server
```

管理台创建应用时会自动生成并仅展示一次 `client_secret`。生产模式会拒绝历史遗留的无密钥应用访问 Policy、Ticket、Config 和 Event 数据面；应先在管理台为这些应用生成密钥并同步到 Gateway 或服务端中间件。

Gateway 仅接受 `CAPTCHA_TRUSTED_PROXY_CIDRS` 内来源注入的账号、设备和风险/模型上下文头；不可信来源携带的这些头会在策略评估和上游转发前被删除。

## Cookie 和合规边界

CaptCha 为了减少重复验证、支撑通行态、限流和风险策略，会在中间件和 Gateway 路径中使用短期安全 cookie，例如 `captcha_clearance`。这个 cookie 用于标记当前浏览器会话已经完成验证，不用于广告、分析或跨站追踪；账号和设备维度请优先由业务后端提供 `account_id_hash` / `device_id_hash`，不要把原始 uid 暴露给浏览器或 CaptCha。

在欧盟和类似 ePrivacy 规则语境下，写入或读取 cookie、local storage、匿名访客 ID 等终端存储都可能落入 cookie / terminal storage 合规边界。验证码通行态更适合按“用户请求的受保护服务所需的安全措施”评估，而不是简单归类为“通信传输所必需”。接入方应结合自己的地区、业务场景和 cookie policy 判断是否需要同意、告知或额外配置。

建议：

- 将 `captcha_clearance` 作为安全/功能 cookie 说明用途、TTL 和作用域。
- 使用短 TTL、HttpOnly、SameSite、Secure，并限制 domain/path。
- 不把 CaptCha cookie 用于广告、分析、跨站识别或长期用户画像。
- 匿名访客 ID 如需持久化，应由接入方基于同意或明确的严格必要评估后启用。

## 安全边界

CaptCha 不是万能反爬系统，也不能单独阻止所有自动化攻击。它更适合作为风控链路中的验证层。

不建议：

- 单独依赖验证码保护高价值接口。
- 把 IP 当作长期白名单。
- 把 `client_secret`、管理 token 或 gRPC token 放到浏览器。
- 接受客户端提交答案、评分阈值或验证规则。
- 把公开采集流量直接作为训练数据。

建议：

- 高风险操作绑定 route 和一次性 nonce。
- ticket 消费失败按失败处理。
- 配合限流、账号信誉、设备信号、IP 风险和业务规则使用。

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

- [快速接入](docs/zh/quickstart.md)
- [接入指南](docs/zh/integration-guide.md)
- [后端 ticket 核销](docs/zh/backend-ticket-verification.md)
- [中间件接入](docs/zh/middleware-integration.md)
- [自定义接入](docs/zh/custom-integration.md)
- [部署运行与自恢复](docs/zh/deployment-operations.md)
- [HTTP / gRPC API](docs/zh/api-reference.md)
- [架构设计](docs/zh/architecture-design.md)
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

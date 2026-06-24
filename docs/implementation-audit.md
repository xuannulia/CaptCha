# 实现审计矩阵

本文档把 `docs/architecture-design.md` 中的一期范围和关键安全要求映射到当前实现与验证证据。它用于发布前复查，不替代自动化测试。

## 验证入口

| 命令 | 覆盖范围 |
|---|---|
| `make verify` | Go/Docker 工具链版本一致性检查、CI 工作流契约检查、前端框架契约检查、Docker 交付合约检查、HTTP/gRPC API 文档契约检查、验证码类型契约检查、Browser smoke 路由覆盖契约检查、文档命令契约检查、Go 全量测试、protobuf drift 检查、生产安全闸门 smoke、HTTP/gRPC 平台和 Gateway smoke、workspace 测试、workspace 构建、Runtime gzip 预算检查、Docker Compose 配置校验、构建产物和本地浏览器产物清理 |
| `make smoke` | 真实进程级平台 HTTP/gRPC、Gateway HTTP/gRPC、challenge payload 脱敏、非法 verify 字段拒绝、生产误配置启动失败 |
| `make browser-smoke` | 真实浏览器打开 Runtime 和 Admin，验证 `RANDOM` 请求入口以及 `GESTURE`/`CURVE`/`CURVE_V2`/`CURVE_V3`/`SLIDER`/`SLIDER_V2`/`ROTATE`/`CONCAT`/`ROTATE_DEGREE`/`WORD_IMAGE_CLICK`/`IMAGE_CLICK`/`JIGSAW`/`GRID_IMAGE_CLICK` Runtime 渲染和基础反馈、Admin React Router 深链、菜单导航、应用数据以及应用/路由策略/IP 策略/策略模拟/资源/审计/训练特征/模型版本主页面渲染 |
| `make docker-build` | 构建后端和 Gateway Docker 镜像，需要本机或 CI Docker daemon |
| `make release-audit` | 发布前检查许可证、安全报告渠道、CI 工作流契约、HTTP/gRPC API 文档契约、验证码类型契约、Browser smoke 路由覆盖契约、文档命令契约、构建产物、本地浏览器产物、git remote、Docker daemon 和常见密钥模式 |
| `make clean` | 清理前端、集成中间件、本地浏览器 smoke 和输出目录的生成产物 |

## MVP 范围

| 要求 | 当前证据 |
|---|---|
| 托管验证运行时、Iframe 模式 | `web/runtime`；`make browser-smoke` 验证 Runtime 可创建并渲染完整 Tianai 具体验证码矩阵，并覆盖基础反馈 |
| 后端 ticket 校验 API | `internal/api/server.go`；`internal/api/server_test.go`、`internal/store/ticket_test.go`、`make smoke` 覆盖 ticket 绑定和消费 |
| Tianai 具体验证码矩阵 | `internal/engine/engine.go`；`TestGenerateAndVerifyAllCaptchaTypes`、`web/runtime/src/main.tsx` 覆盖 `GESTURE`、`CURVE`、`CURVE_V2`、`CURVE_V3`、`SLIDER`、`SLIDER_V2`、`ROTATE`、`CONCAT`、`ROTATE_DEGREE`、`WORD_IMAGE_CLICK`、`IMAGE_CLICK`、`JIGSAW`、`GRID_IMAGE_CLICK` 展示和提交；`WORD_ORDER_IMAGE_CLICK` 作为兼容别名映射到文字点选，不再作为独立类型维护；`PROOF_OF_WORK` 已从验证码矩阵移除 |
| 验证码资源管理 | `internal/resource`、`internal/api/server.go`；资源 validator/selector/renderer 测试覆盖本地文件、URL、classpath、object storage、database base64、模板和字体 |
| 预生成和短 TTL 缓存 | `internal/engine`、`internal/token`；`TestPreGeneratedChallengePool` 和 session/ticket TTL 配置路径 |
| 应用和密钥管理 | `internal/api/server.go`、`internal/secret`；密钥轮换、hash、只返回一次和 client secret 鉴权测试 |
| 路由策略模型 | `internal/policy`、`internal/routepolicy`；策略、灰度、risk_based、rate_limit、dry-run 测试 |
| IP allowlist / blocklist | `internal/policy`、`internal/gateway`；IP 优先级、单 IP/CIDR、Gateway 本地缓存测试 |
| 基础 rate limit | `internal/store`、`internal/policy`；固定窗口、滑动窗口、令牌桶、IP/账号/设备维度测试 |
| gRPC Policy / Ticket / Config / Event | `proto/captcha/v1/captcha.proto`、`gen/captcha/v1`、`internal/grpcserver`、`internal/gateway/grpc_client.go`；gRPC server/client 测试和 `make smoke` 的 gRPC Gateway 路径 |
| Express 参考中间件 | `integrations/express-middleware`；workspace test 覆盖 allow/challenge/ticket/client secret/trusted proxy/circuit breaker/fail-open/fail-close |
| 参考 Gateway 反向代理 | `cmd/captcha-gateway`、`internal/gateway`；Gateway 单元测试和 `make smoke` 覆盖 HTTP/gRPC 策略路径、配置缓存、本地决策、事件批量上报和事件队列回压降级 |
| PostgreSQL 控制面存储 | `internal/store/postgres.go`、`migrations/postgres`；sqlmock 测试和 migration schema 测试；Docker/真实 PostgreSQL 需要 `make docker-build` 或部署环境验证 |
| Redis 临时态存储 | `internal/store/redis.go`；Redis transient store 测试覆盖 session、ticket、rate 计数 |
| 审计日志 | `internal/api/server.go`、`internal/gateway`；配置变更、策略事件、Gateway 事件、训练标签更新、缺失 `client_id` 事件整批拒绝且不部分写入、外部事件 ID/时间戳服务端生成测试 |
| 风控特征采集和 AI 模型元数据 | `internal/api/risk_model.go`、`internal/store/risk_feature.go`；轨迹特征入池、标签、导出、模型激活/回滚、shadow 评分、外部推理、推理失败降级和特征写入异常不阻塞验证测试 |
| 轻量管理台 | `web/admin` 使用 React Router、TanStack Query 和 Ant Design；前端契约检查限制 Admin 生产依赖停留在选定成熟栈、Runtime 生产依赖停留在 Preact 轻量栈，并拦截营销/教程式页面文案；Browser smoke 路由覆盖契约要求 Admin 主路由都进入真实浏览器 smoke；构建测试和 `make browser-smoke` 覆盖概览深链、菜单导航、应用页真实数据加载和所有主页面渲染 |

## 安全要求

| 要求 | 当前证据 |
|---|---|
| 答案、容差、评分规则不下发客户端 | `internal/resource/selector.go` 过滤 metadata；`make smoke` 检查 challenge payload 不包含 answer/target/tolerance/rule/secret/token |
| Verify API 拒绝客户端规则字段 | `readVerifySessionRequest`；`TestChallengeSessionSingleUseAndFailureLimit` 和 `make smoke` 覆盖顶层/嵌套禁用字段、评分阈值字段和客户端伪造评分字段 |
| ticket 不可伪造、一次性消费、绑定上下文 | token 使用随机值并由 store 管理；ticket store/API/gRPC/Gateway 测试覆盖 consumed、client、scene、route、nonce、IP hash、UA hash，Policy Evaluate 携带缺失 route/nonce/IP/UA 上下文的 bound ticket 会阻断且不回退普通策略 |
| clearance 短期通行态 | `internal/token`、`internal/store`、Policy/Ticket HTTP/gRPC、Gateway、Express middleware；测试覆盖 ticket 换 clearance、后续同 scene 放行、账号 hash 不匹配回退 challenge、匿名设备 hash 绑定、Gateway 写回 header/cookie 和 middleware 读取 cookie |
| challenge id 随机且短 TTL | `internal/store/id.go`、`internal/engine`；session 创建、TTL 配置和过期状态测试 |
| 应用 client secret 只返回一次并 hash 存储 | `internal/secret`、`handleRotateApplicationSecret`；API 和 store 测试确认不泄露 `secret_hash` |
| 管理 API 强鉴权 | `CAPTCHA_ADMIN_TOKEN`、`withAdminAuth`；`TestAdminTokenAuth` |
| gRPC 平台 token 和应用 secret 鉴权 | `internal/grpcserver` interceptors；`TestGRPCPlatformTokenAuth`、`TestGRPCClientSecretAuth` 覆盖 Policy、Ticket、Config 和 Event 服务，Event 同时拒绝缺失 `client_id` 的匿名写入 |
| 中间件/Gateway header allowlist | `collectAllowedHeaders`、Express middleware；Gateway 和 middleware 测试确认默认不信任/不转发敏感头 |
| 远程调用 deadline 与故障降级 | Gateway `context.WithTimeout`/HTTP client timeout、Express `AbortController` timeout、风险推理 HTTP/gRPC 入口降级、训练特征异步写入异常恢复、Gateway 事件队列回压降级；Gateway、middleware、策略评估和验证接口测试覆盖 fail-open/fail-close、熔断、超时、外部推理失败、特征采集失败和事件队列满不阻塞主链路 |
| CORS 和 return_url allowlist | `withCORS`、`normalizeReturnURL`；CORS 和 return URL 测试 |
| 生产误配置拒绝启动 | `productionSecurityErrors`；单元测试和 `make smoke` 真实进程级检查 |
| 应用状态治理 | `requireActiveApplication`、`applicationPolicyDecision`、`applicationTicketRejection`、Event client 校验；HTTP 和 gRPC 测试覆盖 disabled/unknown 应用在 Runtime、Policy、Ticket、Event、Config 路径上的行为 |
| Verify 响应不泄露评分细节 | `handleVerifySession`、`recordFailedVerification`；`TestVerifyResponsesDoNotExposeScoringDetails` 和 `make smoke` 确认响应不返回 track bucket、分数、阈值、容差或目标字段 |
| 验证失败次数限制 | session 状态机；`TestChallengeSessionSingleUseAndFailureLimit` |
| 训练样本脱敏 | `recordRiskFeatureSnapshot` 和 resource summary；风险特征与资源命中测试确认不写入 URI/metadata/checksum/答案数据 |

## 发布前仍需外部确认

| 项目 | 状态 |
|---|---|
| 许可证 | 需要项目所有者选择并添加 `LICENSE`。当前 README 和 release checklist 已阻止误认为可直接开源发布。 |
| 私有安全报告渠道 | 需要项目所有者配置邮箱、平台私有安全 advisory 或其他私有通道，并更新 `SECURITY.md`。 |
| Docker 镜像本机构建 | 当前本机 Docker daemon 未运行；CI 已接入 `make docker-build`，有 Docker 环境时可验证。 |
| 生产真实依赖联调 | PostgreSQL/Redis 真实部署、TLS/mTLS、真实域名 CORS、真实上游 Gateway 依赖部署环境。 |

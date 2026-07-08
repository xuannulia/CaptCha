# 贡献指南

语言：中文 | [English](CONTRIBUTING.en.md)

CaptCha 是人机验证平台，不是只跑在浏览器里的验证码小组件，也不是业务 SDK。贡献代码时请保持这个边界：challenge 生成、答案校验、策略决策、ticket、限流、风险信号和审计都属于平台侧。

## 开发环境

本地启动平台：

```bash
go run ./cmd/captcha-server
```

启动 iframe runtime 和管理台：

```bash
npm run dev:runtime
npm run dev:admin
```

修改存储行为时，请同时使用 PostgreSQL 和 Redis 验证：

```bash
docker compose -f docker-compose.dev.yml up -d
```

## 验证

提交前先运行：

```bash
make verify
```

Docker 可用时再运行：

```bash
make docker-build
```

涉及页面或交互改动时运行：

```bash
make browser-smoke
```

发布或打版本前运行：

```bash
make release-audit
```

`make verify` 结束前会清理前端和中间件构建产物。如果你手动运行过单项构建命令，可以用 `make clean` 清理。

## Protobuf 契约

gRPC 契约位于 `proto/captcha/v1/captcha.proto`，生成的 Go 代码位于 `gen/captcha/v1`。

修改契约后运行：

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
make proto
make proto-check
```

保持 protobuf message 稳定。优先新增字段，不要重命名字段或复用字段编号。

## 安全不变量

不要把这些职责移动到浏览器：

- 服务端答案、容差、目标点、评分阈值或验证规则。
- ticket 状态或一次性消费状态。
- 生产策略阈值、IP 列表、client secret 或 runtime 计数器。
- 只基于前端行为做出的信任决策。

challenge payload 不能暴露答案或规则字段。验证请求必须拒绝客户端提交的 `tolerance`、`target`、`answer_seed`、`verify_rule`、`score_rule`，包括嵌套字段。

中间件和 Gateway 接入只能通过显式 allowlist 转发业务 header。

## 协议和贡献

CaptCha 使用 `AGPL-3.0-only` 协议。除非有单独书面协议，提交到公开仓库的贡献默认按同一协议授权。

请不要提交无法按 AGPL-3.0-only 再分发的代码。如果项目未来需要接收可用于专有版本的贡献，必须通过 Contributor License Agreement 或其他明确的入站授权流程处理。

## 前端原则

runtime 应保持轻量，只负责展示 challenge、采集交互事实并返回 ticket。管理台应保持面向运维和风控工作的密度：配置、审计、指标、资源、训练功能和模型版本。

避免落地页、营销文案、装饰性 dashboard，以及在产品界面里解释产品如何工作。第一屏应该直接可用。

## PR 检查清单

- 改动符合 [架构设计](docs/zh/architecture-design.md)。
- 测试或 smoke 覆盖与风险匹配。
- 安全敏感字段没有进入浏览器 payload。
- 新增远程调用设置了 deadline 或请求超时。
- 配置变化已写入 `README.md` 或 `configs/captcha.example.yaml`。
- 修改 `.proto` 契约时，同步更新生成代码。

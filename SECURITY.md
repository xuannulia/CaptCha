# 安全策略

语言：中文 | [English](SECURITY.en.md)

CaptCha 默认实现是开源可见的。安全性来自部署密钥、服务端状态、短生命周期 challenge、一次性 ticket、限流、策略配置、审计和风险反馈，而不是隐藏前端代码。

## 支持版本

项目当前还没有正式版本号。引入版本化发布前，安全修复只面向当前 `main` 分支。

## 报告漏洞

请不要在公开 issue 中发布利用细节、绕过方法或可直接运行的攻击 payload。

安全问题请通过邮件私下报告：loser@iloser.cn。

公开 issue 只适合提交不包含利用细节的普通 bug、加固建议和安全边界讨论。

报告时请尽量包含：

- 受影响组件：server、runtime、admin、Gateway、多语言中间件、gRPC 契约、存储或部署配置。
- 复现步骤和影响范围。
- 是否会泄露答案、绕过 ticket、削弱 client secret 校验、绕过限流、暴露敏感 header，或允许不安全的资源抓取。
- 如有可行修复方案，也请一并说明。

## 安全边界

应该保持私有的状态：

- challenge 答案、目标点、容差、评分规则和轨迹阈值。
- ticket 值、消费状态、TTL、route 绑定、nonce 绑定、IP hash 和 User-Agent hash。
- client secret、admin token、metrics token、gRPC token、TLS 或 mTLS key。
- 生产策略阈值、IP 列表、灰度状态、限流计数器和模型产物。

可以公开的状态：

- 前端 runtime 代码。
- 清理掉答案和规则元数据后的公开 challenge 渲染数据。
- Protobuf 和 HTTP 契约。
- 服务端算法和规则评分逻辑。

## 部署要求

生产环境应开启启动安全门禁：

```bash
CAPTCHA_ENV=production
```

或：

```bash
CAPTCHA_PRODUCTION=true
```

生产模式要求配置 admin、gRPC、metrics token，显式配置非通配的浏览器来源，启用 PostgreSQL 和 Redis，并关闭 demo 数据写入。

## 披露原则

安全修复的 changelog 不应公开绕过细节。说明影响范围、升级要求和缓解步骤即可。

# USA Deployment Baseline

本文档记录 CaptCha 部署在美国区时的基础约束。这里的“USA 部署”指平台运行时、控制面数据、审计日志、风险样本、PostgreSQL、Redis、备份和运行日志默认都落在美国区域内。

## Region Boundary

推荐选择一个主美国区域作为单一区域部署边界，例如 US-East 或 US-West。平台服务、PostgreSQL、Redis、对象存储、日志、备份和密钥管理应保持在同一美国区域，避免策略评估路径跨区域访问。

如果业务服务也在美国，Gateway 应和业务 upstream 同区域或同 VPC 部署。若业务 upstream 不在美国，不建议为了“平台在美国”强行把 Gateway 放远；Gateway 是请求链路组件，应该贴近被保护业务，平台数据面再通过 gRPC/HTTP 访问美国区 CaptCha。

## Data Residency

持久数据默认不出美国区域：

- PostgreSQL：应用、策略规则、路由策略、IP 策略、资源元数据、审计事件、风险样本和模型版本。
- Redis：challenge session、ticket、clearance、限流计数和短期状态。
- 对象存储：上传的验证码素材、模型 artifact 和离线导出文件。
- 日志与指标：访问日志、错误日志、审计日志和 Prometheus/trace 后端。

业务用户仍然是接入方外部用户。平台只接收 `account_id_hash`、`device_id_hash`、IP 摘要、User-Agent 摘要和显式 allowlist 的低敏 header，不保存明文业务用户资料。

## Production Shape

最小生产形态：

```text
USA load balancer / ingress
  -> captcha-server HTTP :8080
  -> captcha-server gRPC :9090
  -> PostgreSQL in same USA region
  -> Redis in same USA region

optional:
  business ingress / gateway
    -> captcha-gateway
    -> protected upstream
```

`captcha-server` 必须启用生产安全闸门：

```bash
CAPTCHA_ENV=production
CAPTCHA_ADMIN_TOKEN=...
CAPTCHA_GRPC_TOKEN=...
CAPTCHA_METRICS_TOKEN=...
CAPTCHA_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
CAPTCHA_ALLOWED_RETURN_URL_ORIGINS=https://app.example.com
CAPTCHA_POSTGRES_DSN=postgres://...
CAPTCHA_REDIS_ADDR=...
CAPTCHA_SEED_DEMO=false
```

所有外部入口必须走 HTTPS。gRPC 可在内网使用 mTLS、私有网络或等价的服务网格保护；平台级 `CAPTCHA_GRPC_TOKEN` 和应用级 client secret 仍应保留。

## Gateway Placement

Gateway 有两种推荐放置方式：

- 业务服务也在美国：Gateway、业务 upstream 和 CaptCha 平台放在同一美国区域，延迟最低，配置快照可开启本地缓存。
- 业务服务不在美国：Gateway 靠近业务 upstream，CaptCha 平台在美国；Gateway 开启 gRPC、配置缓存、事件批量上报和熔断，减少跨区域同步调用次数。

Gateway 生产建议：

```bash
CAPTCHA_GATEWAY_POLICY_TRANSPORT=grpc
CAPTCHA_PLATFORM_GRPC_ADDR=<usa-captcha-grpc-endpoint>:9090
CAPTCHA_PLATFORM_GRPC_TOKEN=...
CAPTCHA_GATEWAY_CONFIG_CACHE=true
CAPTCHA_GATEWAY_EVENT_BATCH_SIZE=20
CAPTCHA_GATEWAY_EVENT_FLUSH_INTERVAL=1s
CAPTCHA_GATEWAY_EVENT_QUEUE_SIZE=200
CAPTCHA_GATEWAY_CIRCUIT_BREAKER_FAILURES=3
CAPTCHA_GATEWAY_CIRCUIT_BREAKER_COOLDOWN=5s
CAPTCHA_TRUSTED_PROXY_CIDRS=<ingress-or-lb-cidrs>
```

## CDN And Static Assets

Runtime 和管理台静态资源可以放在 CDN 后面。若部署要求严格的美国数据驻留，CDN 缓存、日志和 WAF 日志也应限制在美国区域；否则全局 CDN 可能把静态资源和访问日志扩散到美国以外的边缘节点。

策略评估、ticket、verify、事件上报、资源上传和管理 API 不应被 CDN 缓存。

## Release Checklist Additions

美国区上线前额外确认：

- PostgreSQL、Redis、对象存储、备份、日志和密钥均在美国区域。
- `CAPTCHA_SEED_DEMO=false`。
- `CAPTCHA_ALLOWED_ORIGINS` 和 `CAPTCHA_ALLOWED_RETURN_URL_ORIGINS` 只包含生产域名。
- Gateway 的 `CAPTCHA_TRUSTED_PROXY_CIDRS` 只包含美国区入口或负载均衡器 CIDR。
- 跨区域调用路径已压测，尤其是 `PolicyService.Evaluate`、`TicketService.ConsumeTicket` 和 verify。
- Prometheus、日志和审计保留策略符合美国区部署要求。

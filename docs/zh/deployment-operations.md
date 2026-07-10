# 部署运行与自恢复

语言：中文 | [English](../en/deployment-operations.md)

这份文档只记录生产运行需要确认的事项：服务由谁托管、挂掉后是否会拉起、健康检查是否有效、以及验证码平台异常时业务请求会不会被阻断。

## 当前线上状态

当前公开 Demo 使用 GitHub Pages 承载 Runtime，API 经由 `https://api.metool.tech/captcha` 转发到 CaptCha API Server。

服务器上 CaptCha 相关容器已配置 Docker restart policy：

| 服务 | 自恢复 |
|---|---|
| `captcha-collector-api` | `restart=unless-stopped` |
| `captcha-collector-postgres` | `restart=unless-stopped` |
| `captcha-collector-redis` | `restart=unless-stopped` |

宿主机上 `docker.service` 和 `nginx.service` 由 systemd 托管。也就是说，当前不是裸进程运行；容器退出、Docker 重启或机器重启后，服务会按 Docker 策略恢复。

## 仓库内置保障

`docker-compose.yml` 中生产服务都配置了：

- `restart: unless-stopped`
- PostgreSQL / Redis healthcheck
- CaptCha API Server healthcheck
- Gateway healthcheck
- Gateway 显式失败策略环境变量

API Server 和 Gateway 镜像都是 `scratch`，容器内没有 shell、curl 或 wget。健康检查使用二进制自身：

```text
captcha-server healthcheck http://127.0.0.1:8080/healthz
captcha-gateway healthcheck http://127.0.0.1:8081/healthz
```

这样健康检查不会依赖镜像里不存在的工具。

## 上线后检查

在服务器上确认自恢复策略：

```bash
docker inspect captcha-collector-api --format '{{.HostConfig.RestartPolicy.Name}}'
docker inspect captcha-collector-postgres --format '{{.HostConfig.RestartPolicy.Name}}'
docker inspect captcha-collector-redis --format '{{.HostConfig.RestartPolicy.Name}}'
systemctl is-active docker
systemctl is-active nginx
```

确认 API 健康：

```bash
curl -fsS https://api.metool.tech/captcha/healthz
```

确认 GitHub Pages Demo 使用的是公开 API：

```bash
curl -fsS https://xuannulia.github.io/CaptCha/demo/
```

## 管理台安全响应头

管理台不能只依赖 HTML `<meta>` 防点击劫持。生产静态站点必须由 Web Server 下发包含 `frame-ancestors 'none'` 的 CSP 响应头，并设置 `X-Frame-Options: DENY`。可复制 `deploy/nginx/captcha-admin.conf.example`，替换域名、静态目录和 API 地址后执行 `nginx -t`。

使用 Gateway 内部账号、设备或风险头时，认证代理必须覆盖这些头并注入共享令牌：

```nginx
proxy_set_header X-Captcha-Trusted-Context-Token "replace-with-random-secret";
proxy_set_header X-Captcha-Account-ID-Hash $authenticated_account_hash;
proxy_set_header X-Captcha-Device-ID-Hash $authenticated_device_hash;
```

Gateway 同时配置 `CAPTCHA_TRUSTED_PROXY_CIDRS` 和相同的 `CAPTCHA_TRUSTED_CONTEXT_TOKEN`。不要让普通公网请求直接携带共享令牌。

## Gateway 失败策略

Gateway 与中间件一样，平台不可用时默认 `fail_open`，不会因为 CaptCha 平台故障阻断业务。生产可按接口价值调整：

```env
CAPTCHA_GATEWAY_FAIL_POLICY=fail_open
CAPTCHA_GATEWAY_TIMEOUT=1500ms
CAPTCHA_GATEWAY_CIRCUIT_BREAKER_FAILURES=3
CAPTCHA_GATEWAY_CIRCUIT_BREAKER_COOLDOWN=5s
```

高价值动作可以单独部署 fail-close Gateway，或在业务服务中使用中间件并对对应路由配置 `fail_close`。

## 故障边界

| 故障 | 默认结果 |
|---|---|
| API Server 容器退出 | Docker 自动拉起。 |
| PostgreSQL / Redis 容器退出 | Docker 自动拉起。 |
| nginx reload 后配置错误 | `nginx -t` 应先通过再 reload。 |
| CaptCha 平台短暂不可用 | 中间件 / Gateway 默认 fail-open，业务继续。 |
| ticket 无效或已消费 | 403，不走 fail-open。 |
| 未知策略 action | 403，按 fail closed 处理。 |

## 继续阅读

- [中间件接入](middleware-integration.md)
- [自定义接入](custom-integration.md)
- [HTTP / gRPC API](api-reference.md)

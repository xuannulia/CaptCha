# CaptCha 人机验证平台设计文档

本文档记录当前最新设计决策。项目定位是开源的人机验证决策平台，而不是验证码 SDK。

## 1. 当前决策摘要

- 产品形态：人机验证平台 + 策略中心 + 可选 Gateway / 中间件接入。
- 核心价值：不是单个验证码多难破解，而是通过验证码、ticket、限流、策略、审计和网关联动提高自动化滥用成本。
- 开源模型：后端和算法可以开源；安全依赖运行时状态、部署密钥、一次性 ticket、短 TTL、限流计数和策略配置。
- 后端主语言：Go。
- Iframe Runtime：Preact + TypeScript + Vite，极轻量。
- 管理平台：React + TypeScript + Vite + Ant Design，成熟但轻量，不默认使用 Umi Max / Ant Design Pro。
- 中间件与 Gateway 协议：gRPC 优先，HTTP JSON 兜底。
- 浏览器 Runtime 协议：HTTPS + JSON。
- 存储：PostgreSQL + Redis。
- AI：可以做训练和可选在线推理，但不实时在线学习；每次滑动可进入训练数据池，模型必须离线训练、影子评估、灰度上线，在线推理只补充风险上下文。
- TAC 能力对齐：当前实现已覆盖 Tianai 在线体验站点暴露的完整具体验证码类型矩阵；`RANDOM` 作为 `AUTO`/随机选择模式处理。

### 1.1 当前实现状态

当前代码已经具备可运行的第一版平台闭环：

- Go 后端同时启动 HTTP JSON API 和 gRPC 服务。
- 默认使用内存存储，便于本地启动和演示。
- 设置 `CAPTCHA_POSTGRES_DSN` 后，PostgreSQL 承载应用、路由策略、IP 策略、验证码资源和审计事件。
- 设置 `CAPTCHA_REDIS_ADDR` 后，Redis 承载 challenge session、ticket 和频控计数。
- 同时设置 PostgreSQL 和 Redis 时，运行形态为 `PostgreSQL 控制面 + Redis 临时态`。
- 启动时可自动执行 `migrations/postgres` 下的 PostgreSQL schema。
- 启动时默认写入 demo 数据，可用 `CAPTCHA_SEED_DEMO=false` 关闭。
- 已补充后端和 Gateway 容器镜像、默认 `docker-compose.yml`、开发依赖 `docker-compose.dev.yml` 与 GitHub Actions CI；CI 通过 `make verify` 覆盖 Go/CI/Docker/前端契约检查、HTTP/gRPC API 文档契约检查、验证码类型契约检查、Browser smoke 路由覆盖契约检查、文档命令契约检查、Go 测试、protobuf drift 检查、生产安全闸门 smoke、HTTP/gRPC smoke、workspace 测试、前端/中间件构建、Runtime gzip 预算检查和 Docker Compose 配置校验，并通过 `make docker-build` 构建后端/Gateway Docker 镜像。仓库还提供可选的 `make browser-smoke`，用真实浏览器验证 Runtime 和管理台主页面渲染与交互。
- Runtime 已覆盖 `RANDOM` 请求入口，以及 `GESTURE`、`CURVE`、`CURVE_V2`、`CURVE_V3`、`SLIDER`、`SLIDER_V2`、`ROTATE`、`CONCAT`、`ROTATE_DEGREE`、`WORD_IMAGE_CLICK`、`IMAGE_CLICK`、`JIGSAW`、`GRID_IMAGE_CLICK` 的展示和提交；拖动和绘制类控件会采集真实 pointer 轨迹并在松手后自动提交验证，答案未形成前手动验证按钮保持禁用，避免空提交或误触直接失败；点选类验证码不在点击后自动验证，用户可再次点击已选点取消选择，再手动提交；`CURVE` 系列参考 Tianai 在线体验，使用后端 PNG 背景目标虚影叠加 canvas 曲线层，底部滑块推进移动曲线与目标曲线重合，不再复用 `GESTURE` 的自由描绘，也不使用竖向缺口片段或可移动图片 piece；`CONCAT` 使用静态下半片叠加单个透明移动上半片，背景不再挖出目标缺口或答案边界；点选类验证码独立校验点击坐标，避免滑动轨迹评分误伤。`WORD_ORDER_IMAGE_CLICK` 已降级为兼容别名，不再作为独立验证码类型维护；`PROOF_OF_WORK` 已移出验证码矩阵，不作为前台验证码类型提供。
- Demo 宿主页会区分请求类型和实际类型：`RANDOM` 请求由服务端随机落到具体验证码后，Runtime 通过 `CAPTCHA_READY` 消息回传实际 `captchaType`，宿主侧展示“请求/实际”，避免把随机选择器误认为一个独立验证码。
- 点选类验证码的默认生成器必须优先保证可读性和可点击性：目标采用稳定三列布局并保留安全间距，避免 Tianai 类体验中常见的字体堆叠、背景噪声压字、目标过近导致误点等问题；同时不能在目标背后绘制稳定圆形/靶心等可被脚本直接识别的泄露特征。
- `JIGSAW` 属于拼图片还原而非点击精确圆心：内置生成器将完整图片随机切成 2x2 或 3x3 瓦片并随机交换两块，不再绘制红框或答案高亮；Runtime 会以瓦片层展示乱序图片，支持拖动一块到另一块后松手自动验证，也支持点击两块完成可见交换后手动验证，服务端按目标瓦片区域判定命中。
- Runtime 支持 `session_id` 启动、按 `client_id/scene/captcha_type` 创建 session、真实刷新 challenge，并能从服务端 session 恢复 `route`、`request_nonce`、`resource_tag` 和 `return_url`。verify 时回传或使用 session 上下文，并在成功后通过 `postMessage` 返回 ticket、session、route、request nonce 和 return URL；失败时会清理本次交互轨迹/点击标记，拖动类控件会回到初始位置且验证按钮重新禁用，并通过 `postMessage` 同步失败状态，避免 Demo 或宿主页面仍显示“待验证”。当服务端返回 `challenge_harder` 且允许刷新时，Runtime 会刷新同一 session 并展示升级后的验证码，升级序列默认 `SLIDER -> ROTATE -> CONCAT -> WORD_IMAGE_CLICK`，也可由服务端配置覆盖。独立打开的 redirect 模式会在验证成功后跳转到通过 allowlist 校验的绝对 `http/https` `return_url`，并追加 ticket 与绑定上下文查询参数。由策略评估创建的 session 会保存 route、请求 IP/UA 摘要，并把它们绑定到签发 ticket。
- Challenge session 已按一次性状态机处理：成功验证后的 session 不能再次换票；同一 session 连续失败达到上限后会被置为不可继续刷新或验证。
- HTTP API 支持通过 `CAPTCHA_ALLOWED_ORIGINS` 配置浏览器 CORS 来源白名单；未配置时默认 `*` 便于本地开发。
- Engine 支持按验证码类型预生成 challenge，启动时通过 `CAPTCHA_PREGENERATE_SIZE` 控制每类预生成池大小。
- Challenge payload 会按 `client_id`、`scene`、`captcha_type` 和可选 `resource_tag` 选择 active 资源，并在 `parameters.resources` 下发资源引用；资源登记会校验类型、来源、URI、MIME、尺寸、大小和 checksum 声明。`classpath`、本地 `file`、远程 `url`、`object_storage` 和 `database` base64/data URL 背景图资源可进入服务端 PNG 合成，读取、下载、响应 MIME、实际解码 MIME、声明尺寸、大小或 checksum 校验失败时自动回退内置生成器；`background_library` 会在同一作用域保留多张候选背景并在服务端合成时抽样，避免长期固定单图；`concat_background_library` / `jigsaw_background_library` 分别是滑动还原和乱序拼图的独立背景图库，不复用通用背景，便于按图像连续性、切片可辨识度和通过难度筛选素材；`rotate_library` 是 ROTATE 独立图库，服务端会从图片中心裁切圆形旋转图后按随机初始角度生成 PNG；`grid_category_library` 用 metadata 的 `category`/`label` 建立图片格子分类图库，服务端按 session 答案格抽目标分类图片、非目标格抽干扰分类图片，目标格索引仍只保存在服务端。`classpath` 只允许从 `CAPTCHA_RESOURCE_CLASSPATH_DIRS` 指定目录或默认 `resources`、`configs/resources` 中读取，禁止绝对路径和 `..` 穿越，远程 URL 与对象存储 endpoint 会拒绝 localhost、私网和链路本地地址。`object_storage` 支持 metadata 直连 `public_url` / `signed_url` / `presigned_url` / `object_url`，也支持 `endpoint` / `base_url` + `bucket/key` 拼接，默认 path-style，可用 `addressing_style=virtual_hosted` 切换。`slider_template` 可作为滑块 mask，`rotate_template` 可作为旋转图覆盖层，`concat_template` 支持 JSON/metadata 配置移动上半片与静态下半片的分割线位置和边缘颜色；`font` 支持服务端文字渲染 metadata；`icon_library` 已开放登记，外部 SVG 图标库渲染链路后续补齐。
- 管理台已接入后端管理 API，覆盖应用、路由策略、IP 策略、策略模拟、资源、审计、指标、训练样本和模型管理；应用、路由策略、IP 策略、资源、模型登记和训练标签支持操作，策略模拟支持 dry-run 查看命中路由和决策。管理台顶部提供当前应用范围选择，概览、路由、IP 策略、资源、审计和训练样本会按所选应用过滤，新增策略和上传资源默认落到当前应用，避免多租户数据混杂。应用页以及路由、IP、审计、训练样本等跨页应用列均以应用名称作为主信息，应用标识只作为接入辅助信息展示，避免把 `Client ID` 或 `client_id` 当作后台主语言。路由策略编辑按业务触发条件只展示相关字段，默认只允许新增固定验证、访问过快、风险较高三类运营可理解策略；`risk_based` 额外展示风险阈值和风险验证码，`rate_limit` 额外展示限流窗口、请求上限和计数策略，`observe`、`silent` 和 `manual_bypass` 仅作为历史/内部模式兼容展示，不再作为常规新增选项；保存时清理不属于当前触发条件的旧配置。策略模拟主表单仅保留应用、方法、路径、场景和 IP，账号/设备/请求标识/资源标签/风险输入放入可展开上下文；策略模拟和审计筛选使用浏览器标识、请求标识、账号标识和设备标识等业务化文案，不把 UA、Nonce 或 hash 字段作为后台主语言；策略模拟、概览和审计列表会把策略原因、验证码校验原因、轨迹风险原因、dry-run side effects 与 notes 映射为中文运营原因；未收录原因显示为“其他原因”，原始码仅作为 hover 辅助。IP 策略编辑固定 `allowlist -> allow`、`blocklist -> block`，管理台以“放行名单/拦截名单”和“IP 范围”表达单 IP 或网段，不再重复展示底层动作列，避免类型、动作和底层 CIDR 字段互相干扰。资源图库主界面只保留文件式图库、下拉筛选、多选启停/删除和上传入口，不默认展示系统模板、底层 URI 或明细表。训练样本页使用业务化文案展示候选样本、入训样本和人工标签，不把 JSONL 或特征字段作为主要操作入口。模型管理页用“模型名称、模型版本、上线方式、样本版本、训练时间窗、模型文件、准确率、误伤率”表达模型登记和启停，登记时不预填 demo 模型名称或样本版本，列表直接展示模型质量指标，不把 shadow/observe/enforce、artifact URI 或 AUC 作为主要操作语言。审计页展示事件时间、路由、IP/账号/设备绑定主体和中文原因，并支持按中文原因下拉、动作、结果、场景和主体筛选；原因筛选提交给后端的仍是稳定 reason code。应用密钥轮换使用确认流程，明文密钥只在轮换成功后一次性展示并支持复制。路由策略、IP 策略和资源图库支持删除，删除操作必须能确定单一应用范围以保持审计归属清晰。`GET /api/v1/admin/metrics` 会聚合应用、策略、资源、资源命中/失败分析、近期审计事件、训练样本和模型版本，概览页直接使用该指标摘要；`GET /metrics` 输出 Prometheus 文本指标，可通过 `CAPTCHA_METRICS_TOKEN` 单独启用抓取鉴权。
- 路由策略列表的规则摘要必须面向运营人员展示：风险策略显示为“风险分 ≥X 观察/验证/拦截”，限流策略显示为“每 X 秒最多 Y 次”，不使用“观察/验证/拦截 0/0/0”这类压缩调试串。
- 资源图库卡片本身可点击或键盘选中，左上角复选框只作为辅助目标；多选启停/删除不能要求用户精确点击微小控件。
- 资源图库在管理端导航、页头和主体标题中都必须使用“资源图库”，避免退化成泛化的“资源”配置页。
- 资源上传表单对外使用“素材分组”表达底层 tag，并使用中文分类示例；不在管理台主操作里直接暴露 `default` 或英文分类样例。
- 概览页资源健康以验证码类型、素材类型和素材分组作为主标签，资源 ID 不能作为运营人员看到的首要信息。
- 管理端展示素材分组时必须把空分组和后端默认 `default` 映射为“通用”，避免把底层默认值当作运营语言。
- 资源上传弹窗不预填底层默认分组；用户留空时由提交逻辑写入后端默认分组。
- 策略模拟、审计和训练样本筛选不预填 `/api/login` 或 `login` 这类 demo 示例；需要用户按当前应用实际路径和场景输入。
- 策略模拟的可展开区域使用“识别信息”和“风险信号”表达，不把请求上下文、风险输入、模型上线等调试式字段名作为主界面文案。
- 管理 API 的应用、密钥轮换、路由策略、IP 策略、资源、模型版本和训练标签变更会写入审计事件，记录变更类型、目标上下文和脱敏后的管理端 IP。外部 Event 上报不能控制审计事件 ID 或创建时间，平台会在写入时生成服务端身份字段。
- 应用状态已进入主链路治理：不存在的应用不能创建 challenge；`disabled` 应用不能创建/获取/刷新/验证 challenge。HTTP/gRPC 策略评估会对 disabled/unknown 应用返回 `block` 决策，ticket 校验返回 `valid=false`，事件上报要求明确 `client_id` 并拒绝 disabled 应用写入。
- 应用密钥支持后端生成和轮换；明文 client secret 只在轮换响应中返回一次，服务端仅保存 PBKDF2-SHA256 hash。应用一旦配置 secret，HTTP 后端接入 API 和 gRPC Policy/Ticket/Config/Event 服务都会校验 `X-Captcha-Client-Secret` 或 Bearer token。
- 管理 API 支持开源版轻量 Bearer token 保护；设置 `CAPTCHA_ADMIN_TOKEN` 后，所有 `/api/v1/admin/*` 请求必须带管理 token。管理台启动时会先调用令牌检查接口，检查通过后才加载应用、策略、资源、审计和模型数据；令牌保存在当前浏览器并随 Admin API 请求发送，接口返回 401 时会要求重新输入管理令牌。
- Server 启动支持生产安全闸门：设置 `CAPTCHA_ENV=production` 或 `CAPTCHA_PRODUCTION=true` 后，缺少管理 token、gRPC token、metrics token、显式非通配 CORS/return_url allowlist、PostgreSQL、Redis，或未禁用 demo seed 时会启动失败。
- gRPC 当前服务已覆盖 Policy、Ticket、Config、Event，并支持平台级 `CAPTCHA_GRPC_TOKEN` 强鉴权和应用 client secret metadata 鉴权；Go 侧已由 `proto/captcha/v1/captcha.proto` 生成 `gen/captcha/v1` 客户端和服务端代码，业务内部类型通过转换层与 protobuf 契约隔离。
- ConfigService 支持 `GetConfig` 基础拉取和 `WatchConfig` 流式配置更新；配置快照包含 `application_status`、路由策略、IP 策略和验证码资源，管理 API 修改应用、路由策略、IP 策略或资源后会推送新版本配置快照。
- 已提供 `cmd/captcha-gateway` 参考反向代理入口，无 ticket 时通过平台策略 API 或 gRPC PolicyService 决定放行、返回 challenge 或阻断；有 ticket 时优先通过 HTTP ticket API 或 gRPC TicketService 消费一次性 ticket，并透传请求 IP/UA 摘要和 `X-Captcha-Request-Nonce` 参与上下文绑定校验。ticket 消费成功后平台会返回短期 clearance，Gateway 默认写入 `X-Captcha-Clearance` 和 HttpOnly `captcha_clearance` cookie，后续请求带 clearance 时由平台按 `client_id`、`scene`、IP/UA 摘要、账号 hash 和设备/匿名访客 hash 重新校验。Gateway 还支持从 `X-Captcha-Account-ID-Hash`、`X-Captcha-Device-ID-Hash`、`X-Captcha-Resource-Tag`、`X-Captcha-Risk-Score`、`X-Captcha-Risk-Level`、`X-Captcha-Model-Score` 和 `X-Captcha-Model-Mode` 提取策略上下文，通过 `CAPTCHA_GATEWAY_HEADER_ALLOWLIST` 只上传显式 allowlist 的低敏业务头，并可通过 `CAPTCHA_GATEWAY_CIRCUIT_BREAKER_FAILURES` / `CAPTCHA_GATEWAY_CIRCUIT_BREAKER_COOLDOWN` 对连续平台调用失败短期熔断降级。
- Gateway 支持可选本地配置缓存，通过 gRPC ConfigService 拉取配置并订阅 `WatchConfig` 更新；本地只处理应用禁用、静态 IP allow/block、未命中路由、`manual_bypass`、`silent` 和 `observe` 等确定性决策。
- Gateway 支持 `CAPTCHA_TRUSTED_PROXY_CIDRS` 配置可信代理，只有请求来自可信代理 CIDR 时才读取 `X-Forwarded-For`。
- IP 策略支持 CIDR 和单 IP 写法，并在平台策略和 Gateway 本地缓存中统一执行 `allowlist -> blocklist -> 其他 IP 策略` 的确定性优先级。
- 路由 `rate_limit` 策略已支持 IP、账号 hash 和设备 hash 三个维度计数；任一维度超过阈值都会触发 challenge；计数策略支持默认 `fixed_window`、滚动窗口 `sliding_window` 和令牌桶 `token_bucket`。
- 路由策略支持 `rollout_percent` 基础灰度发布，平台策略服务和 Gateway 本地缓存都会按账号 hash、设备 hash、IP、UA 或路径做稳定哈希抽样；未命中高优先级灰度策略时继续匹配低优先级路由。路由策略也支持 `challenge_escalation` 覆盖平台默认升级序列，使不同路由可以使用不同的 `challenge_harder` 多级挑战编排。
- Gateway 会异步上报本地缓存决策、ticket 消费结果和平台不可用降级结果；远程 PolicyService 决策由平台策略服务自身写入审计。Gateway 可通过 `CAPTCHA_GATEWAY_EVENT_BATCH_SIZE`、`CAPTCHA_GATEWAY_EVENT_FLUSH_INTERVAL` 和 `CAPTCHA_GATEWAY_EVENT_QUEUE_SIZE` 启用有界队列批量上报，达到批量大小或 flush 间隔后调用 EventService。
- 已提供 `@captcha/express-middleware` Node.js Express 参考中间件，有 ticket 时优先调用 HTTP ticket API 消费一次性 ticket 并写回短期 clearance，无 ticket 时读取 `x-captcha-clearance` 或 `captcha_clearance` cookie 并通过平台策略 API 决定放行、返回 challenge 或阻断；ticket 结果和降级结果会异步上报平台事件 API，并支持 `trustedProxyCIDRs` 控制是否信任 `X-Forwarded-For`，支持 `requestNonceHeader` 透传 nonce-bound ticket 上下文，支持账号/设备/匿名访客 hash、风险/模型上下文头，支持 `headerAllowlist` 只上传显式 allowlist 的低敏业务头，支持 `circuitBreakerFailureThreshold` / `circuitBreakerCooldownMs` 对连续 policy/ticket 调用失败短期熔断。
- 验证请求会异步写入 `RiskFeatureSnapshot` 候选样本，当前采集脱敏轨迹摘要特征，包括路径长度、速度方差、加速度方差、方向变化、停顿、异常标记和命中资源摘要；资源摘要只保留资源 ID、类型、验证码类型和 tag，不写入 URI、metadata、checksum 或答案数据，并用于管理指标和 Prometheus 的资源命中/失败率分析。管理面支持训练样本标签反馈、`RiskModelVersion` 登记、激活和回滚；active 模型可在异步入池阶段写入服务端影子评分；不在线训练。后端/Gateway/middleware 可向 PolicyService 提供脱敏 `risk_score`、`risk_level`、`model_score` 和 `model_mode`，平台服务也可通过 `CAPTCHA_RISK_INFERENCE_URL` 调用外部推理服务补充模型分；`risk_based` 路由在显式配置 `risk_observe_score`、`risk_challenge_score` 或 `risk_block_score` 后按阈值决策；`risk_challenge_type` 只在风险分触发 challenge 时覆盖默认验证码类型；`shadow` 模型模式不参与决策，`observe` / `enforce` 只作为 risk_score 输入。

## 2. 产品定位

本项目不是验证码 SDK，也不是只嵌入业务页面的一段前端组件。它应成为可独立部署、可运营、可配置策略的人机验证平台。

验证码挑战只是执行动作。平台真正的核心能力是：

- 判断一次请求是否需要人机验证。
- 决定使用什么验证类型和强度。
- 生成、校验和审计验证码挑战。
- 签发、校验、消费一次性 ticket。
- 通过 IP、路径、账号、设备、频率、失败次数等信号做策略决策。
- 支持 Iframe、Web 后端中间件、Gateway、反向代理等接入形态。

### 2.1 目标

- 提供托管验证运行时，支持 iframe、redirect、middleware、gateway 接入。
- 提供完整行为验证码能力，最终覆盖 Tianai 在线体验站点的验证码类型矩阵，而不是只覆盖开源默认四类。
- 提供统一策略中心，内置 IP 策略、路由策略、场景策略、频控策略和故障策略。
- 提供一次性 ticket，把“完成验证”转换成可被业务后端或网关消费的安全凭证。
- 提供轻量管理平台，管理应用、策略、资源、审计和指标。
- 提供 gRPC 数据面接口，支撑中间件、Gateway、反向代理和边缘节点。
- 支持私有化部署，核心链路低延迟、可观测、可降级。

### 2.2 非目标

- 不做以 npm、Maven、NuGet 等 SDK 为核心的产品形态。
- 不把验证码答案校验放到业务前端。
- 不承诺单个验证码挑战具备强防破解能力。
- 不设计“后端加偏移参数”作为防护手段。
- 不在一期做复杂设备指纹、机器学习实时决策、商业计费和插件市场。
- 不复刻 TAC 的 Java SDK 形态，而是吸收其验证码能力并平台化。

## 3. 安全定位

验证码不是防破解系统，而是提高自动化滥用成本的摩擦层。

单独的 iframe 验证可以挡住固定脚本、简单重放、直接刷接口和低成本批量请求，但挡不住真人打码、高级浏览器自动化、视觉识别、账号池/IP 池/设备池和针对源码的定制攻击。

平台安全应依赖组合防线：

```text
验证码挑战
  -> 服务端答案校验
  -> 行为轨迹评分
  -> 一次性 challenge session
  -> 一次性 ticket 消费
  -> IP / 账号 / 设备 / 路由策略
  -> 限流与失败次数
  -> Gateway / middleware 拦截
  -> 审计与风控反馈
```

### 3.1 开源安全模型

后端代码开源后，攻击者可以阅读实现、运行本地实例、理解算法和接口流程。因此平台不能依赖代码保密，而要遵循“算法公开，运行时秘密和状态不公开”的模型。

公开内容：

```text
source code
  challenge 生成逻辑
  图片处理逻辑
  轨迹分析逻辑
  ticket 协议流程
  中间件和 Gateway 协议

protocol
  HTTP API
  gRPC API
  protobuf schema
  错误码和基础状态机
```

不公开内容：

```text
deployment secrets
  ticket 签名密钥
  API client secret
  gRPC/mTLS 私钥
  管理后台密钥

runtime state
  challenge answer
  challenge session 状态
  ticket 消费状态
  失败次数
  限流计数
  风险计数

operator configuration
  生产环境策略阈值
  IP 黑白名单
  高风险路由
  租户密钥
  资源库内容
```

安全目标：

```text
不追求让破解不可能。
追求让自动化攻击无法离线伪造通过结果。
追求让攻击者必须参与真实 challenge 流程。
追求让高频攻击被限流、升级验证或阻断。
追求让 ticket 无法伪造、重放或跨场景复用。
滑动轨迹评分用于识别低成本脚本，不承诺抵御高级浏览器自动化。
```

### 3.2 服务端判定边界

算法可以开源，但当前 session 的答案、容差、评分参数、ticket 状态和限流计数不能下发到客户端。

核心原则：

- 客户端只提交用户行为事实，不提交校验规则。
- 服务端生成 challenge 时确定目标答案、容差、资源选择和校验参数。
- 服务端将校验上下文保存到 session 或服务端缓存中，客户端不能修改。
- 客户端不得通过 `tolerance`、`target`、`verify_rule`、`score_rule` 等字段影响校验逻辑。
- 前端 Runtime 可以开源，但只负责渲染 challenge、采集轨迹和提交事实，不负责决定是否通过。
- 内置 fallback 图像使用 PNG data URL，不把答案坐标、角度或偏移作为可解析 SVG 属性下发；标准答案只保存在服务端 session。对于 `CURVE` 这类可视匹配题，目标曲线只烘进服务端 PNG，前端 profile 不下发目标曲线点；开源前端仍不能把渲染算法保密当作防线，只能避免结构化答案字段，并叠加轨迹评分、一次性 session、频控和风险策略。
- 验证器只输出通过、失败、可刷新、升级挑战等粗粒度结果，不向客户端暴露具体阈值和失败维度。

### 3.3 不采用后端偏移防护

不设计额外的“后端偏移参数”作为防护手段。

`CONCAT` 中的“目标偏移量”是验证码本身答案的一部分，不是额外安全扰动层。开源前端不能把视觉算法当秘密；当前实现只避免把目标缺口、`initial_offset`、`split_x` 或 CSS 位置关系作为答案等价字段下发，用户通过移动上半片与静态下半片的图像连续性完成还原。真正防线应放在服务端判定、一次性 session、ticket 消费、限流、策略联动和审计反馈上。

## 4. TAC 能力对齐

截至 2026-06-22，Tianai 在线体验站点暴露的验证码类型包括：

| Tianai 类型 | 站点文案 | 平台目标类型 | 当前状态 | 说明 |
|---|---|---|---|---|
| `RANDOM` | 随机 | `AUTO` / `RANDOM` | 已实现 | `AUTO` 按策略选择类型；`RANDOM` 请求会随机选择一个具体验证码。 |
| `POW` | 工作量证明 | 不接入 | 已移除 | 不能证明真人，容易误导平台定位；不再作为验证码类型或资源能力提供。 |
| `GESTURE` | 曲线绘制 | `GESTURE` | 已实现 | 用户按指定曲线绘制，校验轨迹贴合度、方向和耗时。 |
| `CURVE3` | 滑动曲线 V3 | `CURVE_V3` | 已实现，待人工验收 | 已按 Tianai 观察基线重做为后端 PNG 目标虚影 + 双 canvas + 固定/隐藏端点 + slider 按钮和轨道 mask；滑块驱动曲线形变匹配，不做整条 `translateX`，也不使用图片 piece。 |
| `CURVE2` | 滑动曲线 V2 | `CURVE_V2` | 已实现，待人工验收 | 与 `CURVE_V3` 共享滑动曲线体验，端点策略和曲线复杂度不同；browser smoke 覆盖正确匹配通过和错误偏移失败。 |
| `CURVE` | 滑动曲线 | `CURVE` | 已实现，待人工验收 | 基础滑动曲线，端点初始可见且拖动中不随 slider 平移；仍需人工对照参考站点确认视觉和手感。 |
| `SLIDER2` | 滑块验证 V2 | `SLIDER_V2` | 已实现 | 滑块增强版，可复用滑块引擎但使用独立资源和评分策略。 |
| `SLIDER` | 滑块验证 | `SLIDER` | 已实现 | 已具备生成、展示、校验、ticket 闭环。 |
| `ROTATE` | 旋转验证 | `ROTATE` | 已实现 | 后端返回已按随机初始角度旋转后的圆形图片，前端只叠加用户旋转增量，不下发 answer-equivalent 初始角度。 |
| `CONCAT` | 滑动还原 | `CONCAT` | 已实现 | 已具备生成、展示、校验、ticket 闭环。 |
| `ROTATE_DEGREE` | 角度验证 | `ROTATE_DEGREE` | 已实现 | 与 `ROTATE` 不混同；按角度刻度或指针完成验证。 |
| `WORD_IMAGE_CLICK` | 文字点选 | `WORD_IMAGE_CLICK` | 已实现 | 已具备生成、展示、校验、ticket 闭环。 |
| `IMAGE_CLICK` | 图标点选 | `IMAGE_CLICK` | 已实现 | 用户按提示点击图标目标，校验顺序和坐标。 |
| `JIGSAW` | 乱序拼图 | `JIGSAW` | 已实现 | 2x2/3x3 随机乱序拼图；用户拖动交换错位碎片后松手自动验证，点击交换模式需要手动验证。 |
| Google-like grid | 图片格子点选 | `GRID_IMAGE_CLICK` | 已实现 | 类 reCAPTCHA 的 3x3 图片格子二次挑战，用户选择所有包含目标物的格子后手动验证。 |

`WORD_ORDER_IMAGE_CLICK` 曾作为独立类型存在，但与文字点选重复，已降级为兼容别名并映射到 `WORD_IMAGE_CLICK`；新接入不再使用该类型。

增强付费页还列出“滑动验证增强版、曲线验证增强版、点选类图片背景扭曲”等能力；这些不作为独立接入形态，而归入对应类型的资源模板、扰动参数和评分策略能力。

当前代码已接入的具体验证码类型包括；其中 `CURVE` / `CURVE_V2` / `CURVE_V3` 已按 Tianai 观察基线完成代码重做和浏览器烟测，仍待人工体验验收：

```text
GESTURE
  手势/曲线描绘验证码

CURVE
  滑动曲线验证码

CURVE_V2
  滑动曲线增强 V2

CURVE_V3
  滑动曲线增强 V3

SLIDER
  滑块验证码

SLIDER_V2
  滑块增强验证码

ROTATE
  旋转验证码

CONCAT
  滑动还原验证码

ROTATE_DEGREE
  角度刻度验证码

WORD_IMAGE_CLICK
  文字点选验证码

IMAGE_CLICK
  图标点选验证码

JIGSAW
  乱序拼图验证码

GRID_IMAGE_CLICK
  图片格子点选验证码
```

目标上，当前已进入完整类型闭环；后续重点转为素材资源、扰动模板、行为评分和移动端细节体验增强。

对齐原则：

- 所有目标验证码类型都要有可生成、可展示、可校验、可审计的完整闭环。
- Tianai `data-captcha-type` 命名作为外部兼容参考；平台内部可使用更清晰的类型名，但必须维护映射关系。
- 不以 Java SDK 或前端 SDK 为核心，而是以 Runtime + Engine + Policy + Ticket 为核心。
- 验证码类型只是挑战手段，平台还要提供策略、限流、ticket、审计和 Gateway 决策。
- 支持背景图、背景图库、图片格子分类图库、模板图、字体资源、图标资源、拼图资源、扰动模板、按类型配置资源和默认资源。
- 支持预生成、短 TTL、PostgreSQL 控制面存储、Redis 临时态存储和本地缓存策略。
- 平台 ticket 机制承担二次验证能力，并强化一次性消费和上下文绑定。

资料来源：

- https://github.com/dromara/tianai-captcha
- https://doc.captcha.tianai.cloud/
- https://captcha.tianai.cloud/
- https://captcha.tianai.cloud/pay.html

## 5. 技术选型

### 5.1 后端

平台核心后端使用 Go。

原因：

- 适合低延迟、高并发的数据面服务。
- gRPC 生态成熟，适合中间件和 Gateway 与平台通信。
- 标准库网络能力完整，已用于实现参考反向代理和轻量 Gateway。
- 静态二进制部署简单，适合容器化、私有化和边缘部署。
- 相比 JVM 系语言，资源占用和启动成本更适合策略评估、ticket 校验、限流等主链路组件。

推荐组合：

```text
Platform Backend
  Go

Internal RPC
  gRPC + Protocol Buffers

External API
  HTTP JSON

Storage
  PostgreSQL
  Redis

Risk Training
  Python offline training pipeline
  Go embedded inference or gRPC RiskModelService
```

语言边界：

```text
Go
  平台核心、策略服务、ticket 服务、限流、反向代理、Gateway 原型。

TypeScript
  托管验证运行时、Iframe 页面、管理后台。

Python
  后期 AI 离线训练、特征分析、模型评估。
  不作为平台在线主链路语言。

Java / Node.js / Python / .NET
  作为业务接入中间件生态，不承载平台核心逻辑。
```

### 5.2 前端

```text
Captcha Runtime
  Preact + TypeScript + Vite

Captcha Admin
  React + TypeScript + Vite + Ant Design
```

Runtime 原则：

- 极轻量，适合 iframe 首屏快速加载。
- 不引入 Ant Design、Element Plus、ECharts 等后台或图表库。
- JS gzip 目标约 30KB，CSS gzip 目标约 10KB，`make verify` 会通过 `scripts/check-runtime-budget.sh` 自动检查。
- 只负责验证页面、鼠标/触摸交互、postMessage、HTTP JSON 调用。

Admin 原则：

- 成熟组件，不从零实现表格、表单、分页、筛选、弹窗、菜单。
- 使用 Vite SPA，不默认使用 Next.js、Umi Max、Ant Design Pro。
- React Router + TanStack Query。
- 图表使用 ECharts 或 Ant Design Charts，并按路由懒加载。
- ProComponents 可作为复杂表格和高级表单的可选依赖，不作为一期默认依赖。

### 5.3 前端页面约束

后续使用 Codex 或其他生成工具实现页面时，必须避免啰嗦的信息展示页。平台页面应以操作、配置、验证和审计为中心。

通用约束：

- 默认不做营销式 landing page。
- 首屏必须是可操作界面，而不是产品介绍页。
- 不使用大段说明文、能力清单、价值主张、使用教程占据主界面。
- 不使用大 hero、宣传标语、装饰性卡片堆叠来包装后台功能。
- 不使用卡片套卡片的布局。
- 帮助信息优先放在 tooltip、文档链接或抽屉详情中。
- 表格、筛选、表单、策略编辑器承担主要信息表达。

Runtime 文案：

- Iframe 页面只展示完成验证所需的最少元素。
- 主要文案只包括验证标题、操作提示、加载状态、失败提示、刷新按钮。
- 拖动类验证码松手后自动验证；验证按钮仅作为键盘操作、重试或兜底入口。
- 不展示平台介绍、能力说明、安全科普、接入教程。
- 操作提示控制在一行内。
- 验证成功后尽快返回 ticket 或通知父页面。

Admin 文案：

- 首页优先展示应用概览、策略命中、验证通过率、异常请求。
- 应用、路由、IP 策略、ticket、审计日志页面优先使用表格、筛选和编辑表单。
- 不做“欢迎使用”“三步开始”“平台能力介绍”作为主页面核心。
- 空状态最多两行文案，并包含明确操作。

### 5.4 交付与部署约束

第一版交付形态以私有化部署和可审计构建为主：

- 后端平台和 Gateway 都提供独立 Dockerfile，默认构建静态 Go 二进制并使用轻量运行镜像。
- 平台容器必须包含 `migrations`，保证 `CAPTCHA_POSTGRES_MIGRATIONS=./migrations/postgres` 的默认行为在容器内可用。
- 默认 `docker-compose.yml` 启动 PostgreSQL、Redis 和平台服务；Gateway 作为 `gateway` profile 启动，避免没有业务 upstream 时阻塞平台本身。
- `docker-compose.dev.yml` 只保留开发依赖服务，用于本地直接 `go run` 和前端 Vite 开发。
- CI 至少覆盖 `make verify`、`make docker-build`、protobuf 工具安装、Node workspace 依赖安装、平台镜像构建和 Gateway 镜像构建；`make verify` 内部覆盖 Go 测试、workspace 测试、workspace 构建、protobuf drift、契约检查、smoke 和 Docker Compose 配置校验。
- 仓库不提供生产密钥；`CAPTCHA_ADMIN_TOKEN`、`CAPTCHA_METRICS_TOKEN`、`CAPTCHA_GRPC_TOKEN`、应用 client secret、TLS/mTLS 密钥和真实 CORS allowlist 必须由部署方配置。设置 `CAPTCHA_ENV=production` 或 `CAPTCHA_PRODUCTION=true` 会启用启动期安全校验，防止生产模式误用本地开发默认值。

## 6. 总体架构

```text
Client Browser
  |
  | iframe / redirect / challenge page
  v
Captcha Runtime
  |
  | HTTP JSON
  v
Captcha Platform
  |
  | gRPC / HTTP
  v
Business Middleware / Gateway
  |
  v
Business Service
```

平台模块：

```text
captcha-runtime
  托管验证页面
  Iframe 页面
  滑块、旋转、滑动还原、文字点选交互
  用户轨迹采集

captcha-engine
  challenge 生成
  图片处理
  答案保存
  行为轨迹校验
  规则风险评分
  SLIDER generator / verifier
  ROTATE generator / verifier
  CONCAT generator / verifier
  ROTATE_DEGREE generator / verifier
  WORD_IMAGE_CLICK generator / verifier
  IMAGE_CLICK generator / verifier

captcha-resource
  背景图管理
  模板图管理
  字体资源管理
  资源标签
  资源预处理
  资源选择策略

captcha-policy
  路由策略
  场景策略
  IP 策略
  频控策略
  fail policy

captcha-token
  ticket 签发
  ticket 校验
  ticket 一次性消费
  ticket 与请求上下文绑定

captcha-control-plane
  应用管理
  密钥管理
  路由配置
  策略配置
  资源管理

captcha-data-plane
  gRPC 策略评估
  gRPC ticket 校验
  配置下发
  事件上报

captcha-observability
  审计日志
  策略命中记录
  验证通过率
  失败率
  攻击来源统计

risk-training
  风控特征采集
  离线训练
  影子评分
  模型版本管理
```

## 7. 接入模式

### 7.1 Iframe 模式

业务页面嵌入平台托管验证页：

```html
<iframe src="https://captcha.example.com/challenge?client_id=app_xxx&scene=login"></iframe>
```

流程：

```text
业务页面加载 iframe
  -> 用户完成验证
  -> 平台签发 ticket
  -> iframe 使用 postMessage 通知父页面
  -> 业务前端提交 ticket
  -> 业务后端校验 ticket
```

适合登录、注册、找回密码、表单提交和低成本接入试用。

### 7.2 Web 后端中间件模式

中间件职责：

- 提取请求上下文。
- 本地匹配路径和基础策略。
- 调用平台评估是否需要验证。
- 校验或消费 ticket。
- 根据决策放行、挑战或阻断请求。

中间件不负责：

- 生成验证码图片。
- 实现验证码 UI。
- 保存标准答案。
- 实现核心风险算法。

可支持生态：

```text
Java
  Spring Boot Filter
  Spring MVC HandlerInterceptor
  Spring Cloud Gateway Filter

Node.js
  Express middleware
  Koa middleware
  Fastify plugin
  NestJS guard/interceptor

Go
  net/http middleware
  Gin middleware
  Echo middleware

Python
  ASGI middleware
  Django middleware
  Flask before_request

.NET
  ASP.NET Core Middleware
```

一期参考实现选择 Node.js Express。原因是 Express 生态覆盖广、接入形态轻，示例也容易被 Java、Go、Python、.NET 等生态复刻。该中间件不是平台 SDK，只是业务后端的薄接入层；平台仍负责策略、验证码、ticket、限流、审计和训练候选样本。

Express 参考中间件事件边界：

```text
异步上报：
  ticket 消费成功
  ticket 无效或已消费
  ticket 服务不可用时的 fail-open / fail-close
  Policy API 不可用时的 fail-open / fail-close

不重复上报：
  成功的 Policy API 决策由平台策略服务写入审计
```

### 7.3 Gateway 模式

Gateway 适合企业级多服务统一入口。

职责：

- 在业务服务之前统一拦截请求。
- 执行路径策略、IP 策略、频控策略。
- 将未验证用户引导到验证页面。
- 验证 ticket 后放行业务请求。
- 将事件上报到平台。

后续可支持 Kong、Apache APISIX、Envoy External Authorization、Nginx/OpenResty、Spring Cloud Gateway、Kubernetes Ingress。

当前一期已提供内置 Go 参考反向代理 Gateway 和 Node.js Express 参考中间件；其他 Gateway 生态保持薄适配器边界，按实际接入需求扩展。

### 7.4 反向代理模式

适合不想修改业务代码的系统。

```text
Client
  -> Captcha Reverse Proxy
  -> Business Service
```

代理根据策略直接转发、返回 challenge、校验 ticket 后转发或阻断请求。

## 8. 协议设计

### 8.1 协议选择

```text
浏览器 / iframe / 托管验证页  -> HTTPS + JSON
后端中间件 / Gateway         -> gRPC 优先
第三方轻量接入               -> HTTP API 兜底
管理后台                     -> HTTPS + JSON
```

gRPC 用于主链路数据面，因为它低延迟、强类型、支持多语言代码生成、HTTP/2 连接复用、deadline、mTLS 和 streaming 配置下发。

生产环境 gRPC 至少应启用平台级 token 或 mTLS：

```text
CAPTCHA_GRPC_TOKEN
  平台服务端 gRPC token。
  配置后所有 gRPC 方法都要求 metadata 携带 x-captcha-grpc-token 或 Authorization: Bearer <token>。

CAPTCHA_PLATFORM_GRPC_TOKEN
  Gateway 调用平台 gRPC 时携带的 token。
  未配置时可回退读取 CAPTCHA_GRPC_TOKEN。

x-captcha-client-secret
  应用级 client secret。
  当应用配置 secret 时，Policy / Ticket / Config / Event 仍会继续做 client 维度鉴权。
```

如果同时启用平台 token 和应用 client secret，推荐将平台 token 放在 `x-captcha-grpc-token`，将应用 secret 放在 `x-captcha-client-secret`，避免一个 `Authorization` 头承担两种语义。

### 8.2 gRPC 服务定义

```protobuf
service PolicyService {
  rpc Evaluate(EvaluateRequest) returns (EvaluateResponse);
}

service TicketService {
  rpc VerifyTicket(VerifyTicketRequest) returns (VerifyTicketResponse);
  rpc ConsumeTicket(VerifyTicketRequest) returns (VerifyTicketResponse);
}

service ConfigService {
  rpc GetConfig(ConfigRequest) returns (ConfigSnapshot);
  rpc WatchConfig(ConfigRequest) returns (stream ConfigSnapshot);
}

service EventService {
  rpc Report(EventBatch) returns (ReportResult);
}
```

核心对象：

```protobuf
message RequestContext {
  string client_id = 1;
  string scene = 2;
  string path = 3;
  string method = 4;
  string ip = 5;
  string user_agent = 6;
  string account_id_hash = 7;
  string device_id_hash = 8;
  string ticket = 9;
  string request_nonce = 10;
  string resource_tag = 11;
  map<string, string> headers = 12;
}

enum DecisionAction {
  DECISION_ACTION_UNSPECIFIED = 0;
  ALLOW = 1;
  CHALLENGE = 2;
  BLOCK = 3;
  OBSERVE = 4;
}

message EvaluateResponse {
  DecisionAction action = 1;
  string reason = 2;
  string challenge_url = 3;
  string session_id = 4;
  int32 ttl_seconds = 5;
}

message ConfigSnapshot {
  string client_id = 1;
  repeated RoutePolicy routes = 2;
  repeated IpPolicy ip_policies = 3;
  string application_status = 4;
  repeated CaptchaResource resources = 5;
}

message CaptchaResource {
  string id = 1;
  string client_id = 2;
  string scene = 3;
  string captcha_type = 4;
  string resource_type = 5;
  string storage_type = 6;
  string uri = 7;
  string tag = 8;
  string status = 9;
  string checksum = 10;
  map<string, string> metadata = 11;
}
```

### 8.3 Browser Runtime HTTP API

浏览器跨域访问：

```text
CAPTCHA_ALLOWED_ORIGINS
  逗号分隔的 Origin 白名单。
  未配置时默认允许 *，仅推荐本地开发使用。
  生产环境应配置为实际业务域名和管理后台域名。

CAPTCHA_ALLOWED_RETURN_URL_ORIGINS
  逗号分隔的 redirect return_url Origin 白名单。
  未配置时沿用 CAPTCHA_ALLOWED_ORIGINS。
  未配置任何 Origin 白名单的本地开发环境允许任意绝对 http/https return_url。
  javascript:、data:、相对路径、带 userinfo 的 URL 等不安全 return_url 始终拒绝。
```

运维端点：

```text
GET /healthz
  进程健康检查。

GET /metrics
  Prometheus 文本指标。生产环境可通过 CAPTCHA_METRICS_TOKEN 启用独立抓取鉴权。
```

```text
POST /api/v1/challenge/sessions
  创建验证会话。
  输入 client_id、scene、可选 captcha_type、route、return_url、request_nonce、resource_tag。
  输出 session_id、challenge_url、captcha_type、expire_in、route、request_nonce、resource_tag、return_url。
  challenge_url 会携带 session_id；如果输入 route、request_nonce、resource_tag 或 return_url，则同时携带这些上下文，供 Runtime 在 verify 时回传并绑定 ticket、维持资源选择上下文或完成 redirect 模式返回。
  return_url 必须是绝对 http/https URL，并匹配 CAPTCHA_ALLOWED_RETURN_URL_ORIGINS 或 CAPTCHA_ALLOWED_ORIGINS。

GET /api/v1/challenge/sessions/{session_id}
  获取当前 challenge 展示数据。
  输出验证码类型、资源数据、展示尺寸、渲染参数和 session 上下文 route、request_nonce、resource_tag、return_url。
  不输出标准答案。

POST /api/v1/challenge/sessions/{session_id}/verify
  校验用户答案和行为轨迹。
  输入 answer、track、viewport、route、runtime_meta。
  成功输出 ticket、route、request_nonce、resource_tag 和 return_url，失败输出可展示的短错误码和是否允许刷新。
  不接受 tolerance、target、answer_seed、verify_rule、score_rule、score_threshold、track_score 等会影响校验规则、评分阈值或服务端评分结果的客户端字段；当前实现会递归检查请求 JSON，字段出现在 answer 或 runtime_meta 等嵌套对象中也会被拒绝。

POST /api/v1/challenge/sessions/{session_id}/refresh
  刷新 challenge。
  失败次数、频率和过期时间由策略中心控制。

POST /api/v1/tickets/verify
  第三方 HTTP 兜底校验 ticket。
  如果 ticket 绑定了 request_nonce、ip_hash 或 user_agent_hash，校验或消费请求必须提供相同上下文。
  中间件和 Gateway 优先使用 gRPC TicketService。

POST /api/v1/policy/evaluate
  后端中间件或 Gateway 的策略评估入口。
  输入 client_id、scene、path、method、ip、user_agent、account_id_hash、device_id_hash、resource_tag、request_nonce、ticket 和风险上下文。
  有 ticket 时优先消费并校验 ticket；有效 ticket 返回 allow，无效、过期、已消费或上下文不匹配返回 block，不回退普通策略评估。
  无 ticket 时执行应用状态、IP 策略、路由策略、频控和风险上下文评估；challenge 决策会创建 challenge session 并返回 challenge_url。

POST /api/v1/events/report
  Gateway 和参考中间件异步上报本地决策、ticket 消费结果和平台不可用降级结果。
  要求明确 client_id；外部传入的 event id 和 created_at 会被服务端覆盖，避免伪造审计身份和时间。
```

管理 API：

```text
GET /api/v1/admin/metrics
  管理台概览指标，聚合应用、策略、资源、近期审计事件、训练样本、模型版本和资源命中/失败分析。

GET /api/v1/admin/auth/check
  管理台令牌检查。设置 CAPTCHA_ADMIN_TOKEN 时必须携带管理令牌，用于前端在加载后台数据前确认当前浏览器可访问管理 API。

GET /api/v1/admin/applications
POST /api/v1/admin/applications
POST /api/v1/admin/applications/{client_id}/secret

GET /api/v1/admin/route-policies
POST /api/v1/admin/route-policies
POST /api/v1/admin/route-policies/delete

GET /api/v1/admin/ip-policies
POST /api/v1/admin/ip-policies
POST /api/v1/admin/ip-policies/delete

POST /api/v1/admin/policy/simulate
  管理端策略 dry-run。
  输入 PolicyEvaluateRequest 形态的 client_id、path、method、ip、user_agent、scene、account_id_hash、device_id_hash、request_nonce、resource_tag、risk_score、risk_level、model_score、model_mode 等上下文。
  输出 dry_run、decision、命中的 route、rate_limit_evaluated、side_effects 和 notes。
  不消费 ticket，不创建 challenge session，不递增限流计数，不写审计事件。

GET /api/v1/admin/resources
POST /api/v1/admin/resources
POST /api/v1/admin/resources/upload
POST /api/v1/admin/resources/delete

GET /api/v1/admin/audit-events
GET /api/v1/admin/risk-feature-snapshots
GET /api/v1/admin/risk-feature-snapshots/export
POST /api/v1/admin/risk-feature-snapshots/{id}/label

GET /api/v1/admin/risk-model-versions
POST /api/v1/admin/risk-model-versions
POST /api/v1/admin/risk-model-versions/{id}/activate
POST /api/v1/admin/risk-model-versions/{id}/rollback
```

管理查询参数：

```text
audit-events
  client_id
  scene
  action
  result
  decision_reason
  account_id_hash
  device_id_hash
  limit
  offset

risk-feature-snapshots
  client_id
  scene
  challenge_type
  label
  model_trainable
  limit
  offset

risk-feature-snapshots/export
  client_id
  scene
  challenge_type
  label
  model_trainable
  trainable_only
  limit
  offset

risk-model-versions
  name
  limit
```

`captcha_type` 当前已接入支持值：

```text
GESTURE
CURVE
CURVE_V2
CURVE_V3
SLIDER
SLIDER_V2
ROTATE
CONCAT
ROTATE_DEGREE
WORD_IMAGE_CLICK
IMAGE_CLICK
JIGSAW
GRID_IMAGE_CLICK
AUTO
```

兼容输入值：

```text
RANDOM
CURVE2
CURVE3
SLIDER2
```

Tianai 站点兼容映射：

```text
RANDOM -> RANDOM / AUTO
GESTURE -> GESTURE
CURVE -> CURVE
CURVE2 -> CURVE_V2
CURVE3 -> CURVE_V3
SLIDER -> SLIDER
SLIDER2 -> SLIDER_V2
ROTATE -> ROTATE
ROTATE_DEGREE -> ROTATE_DEGREE
CONCAT -> CONCAT
WORD_IMAGE_CLICK -> WORD_IMAGE_CLICK
IMAGE_CLICK -> IMAGE_CLICK
WORD_ORDER_IMAGE_CLICK -> WORD_IMAGE_CLICK (deprecated alias)
JIGSAW -> JIGSAW
GRID_IMAGE_CLICK -> GRID_IMAGE_CLICK
```

`AUTO` 表示由策略中心根据 scene、风险和资源可用性选择验证码类型。直接 iframe 创建 session 时，如果传入 `AUTO` 或空类型，也会使用资源可用性做默认类型选择。

当前实现：

- 显式 `SLIDER` / `ROTATE` / `CONCAT` / `ROTATE_DEGREE` / `WORD_IMAGE_CLICK` / `IMAGE_CLICK` / `JIGSAW` / `GRID_IMAGE_CLICK` 会被保留，不被 AUTO 策略改写；`WORD_ORDER_IMAGE_CLICK` 会作为废弃别名映射到 `WORD_IMAGE_CLICK`。
- `AUTO` 会先按策略原因和场景生成偏好顺序，再结合当前应用 active 资源是否满足该类型的关键资源要求做选择。
- `RATE_LIMIT`、注册/短信/评论等场景优先尝试 `WORD_IMAGE_CLICK`；`risk_based` 和支付/提现类场景优先尝试 `ROTATE`；登录类场景默认优先 `SLIDER`。
- 如果资源不足以支持偏好里的前序类型，会选择下一个资源满足的类型；如果当前应用没有登记任何资源，则保留内置生成器兜底能力。

### 8.4 主链路性能

中间件和 Gateway 不应每个请求都远程问平台。

```text
本地完成：
  路径匹配
  方法匹配
  静态 IP 黑白名单
  本地配置缓存
  简单 header 检查

远程完成：
  ticket 消费
  分布式频控
  跨节点失败次数
  风险评分
  复杂策略决策

异步完成：
  访问事件上报
  验证结果上报
  风控特征汇总
```

当前 Gateway 本地配置缓存边界：

```text
本地可决策：
  静态 IP allowlist / blocklist
  未命中路由策略
  manual_bypass
  silent / observe

必须远程决策：
  ticket 校验或消费
  challenge 会话创建
  always
  rate_limit
  risk_based
  跨节点失败次数和分布式计数
```

本地缓存通过 `ConfigService.GetConfig` 获取初始快照，并通过 `ConfigService.WatchConfig` 接收管理端配置变更。缓存不可替代平台策略引擎；它只是减少确定性请求的远程调用。

Gateway 事件上报边界：

```text
异步上报：
  本地缓存 allow / block / observe 决策
  ticket 消费成功
  ticket 无效或已消费
  ticket 服务不可用时的 fail-open / fail-close
  PolicyService 不可用时的 fail-open / fail-close

不重复上报：
  远程 PolicyService.Evaluate 已经由平台策略服务写入审计
```

建议超时：

```text
Policy Evaluate: 30ms - 80ms
Ticket Verify:   50ms - 150ms
Event Report:    异步批量，不阻塞请求
Config Watch:    长连接 streaming
```

## 9. 策略模型

### 9.1 决策动作

```text
allow
  直接放行。

challenge
  要求人机验证。

block
  直接阻断。

observe
  只观察和记录，不影响请求。
```

### 9.2 策略模式

```text
always
  每次请求都要求验证。

risk_based
  风险达到阈值后要求验证。

rate_limit
  请求频率达到阈值后要求验证。

silent
  只采集信号，不打扰用户。

observe
  显式观察放行，并记录策略命中。

manual_bypass
  白名单或内部服务跳过验证。
```

### 9.3 示例配置

```yaml
applications:
  - clientId: app_xxx
    name: demo-app
    defaultFailPolicy: fail_open

routes:
  - name: login
    path: /api/login
    method: POST
    scene: login
    captcha:
      mode: risk_based
      challenge: SLIDER
      escalation:
        - SLIDER
        - ROTATE
        - WORD_IMAGE_CLICK
      failPolicy: fail_close
      rolloutPercent: 100
      tokenTtlSeconds: 120

  - name: register
    path: /api/register
    method: POST
    scene: register
    captcha:
      mode: always
      challenge: WORD_IMAGE_CLICK
      failPolicy: fail_close
      tokenTtlSeconds: 120

  - name: comment
    path: /api/comment
    method: POST
    scene: comment
    captcha:
      mode: rate_limit
      challenge: ROTATE
      failPolicy: fail_open
      rateLimit:
        windowSeconds: 60
        maxRequests: 5
```

## 10. IP 策略

IP 策略由策略中心统一配置，不散落在各个中间件中。

```yaml
ipPolicy:
  allowlist:
    - 10.0.0.0/8
    - 192.168.1.10

  blocklist:
    - 203.0.113.0/24

  rateLimit:
    windowSeconds: 60
    maxRequests: 20

  challengeThreshold:
    failedAttempts: 3
    requestsPerMinute: 10

  trustProxyHeaders:
    - X-Forwarded-For
    - X-Real-IP
    - CF-Connecting-IP
```

真实客户端 IP 不能无条件信任 header。

- 只有请求来自可信代理时，才读取 `X-Forwarded-For` 等代理头。
- 支持配置可信代理 CIDR。
- 从 `X-Forwarded-For` 中按可信链路解析真实客户端 IP。
- 默认使用 TCP peer IP。
- 对公网直接访问场景，不信任客户端自带的 IP header。

当前接入实现：

```text
Gateway
  CAPTCHA_TRUSTED_PROXY_CIDRS=10.0.0.0/8,192.168.0.0/16
  CAPTCHA_GATEWAY_HEADER_ALLOWLIST=x-request-id,traceparent

Express middleware
  trustedProxyCIDRs: ["10.0.0.0/8", "192.168.0.0/16"]
  headerAllowlist: ["x-request-id", "traceparent"]
```

默认优先级：

```text
explicit allowlist
  -> explicit blocklist
  -> other IP policies
  -> route policy
  -> rate limit
  -> risk score
  -> default action
```

当前实现中，平台策略服务和 Gateway 本地配置缓存都按上述优先级执行；`allowlist` 与 `blocklist` 重叠时优先放行。IP 条目可写 CIDR，也可写单个 IPv4/IPv6 地址。

当前路由 `rate_limit` 策略会按请求中的 IP、`account_id_hash` 和 `device_id_hash` 分别计数；任一维度超过路由阈值都会返回 `RATE_LIMIT` challenge。`rate_limit.strategy` 默认为 `fixed_window`，也可以配置为 `sliding_window` 或 `token_bucket`：滚动窗口会清理窗口外命中后计数，令牌桶以 `max_requests` 为容量，并在 `window_seconds` 内连续补满一桶，适合允许短时突发但限制长期速率。内存存储和 Redis 临时态都支持这些策略。Gateway 默认从 `X-Captcha-Account-ID-Hash` 和 `X-Captcha-Device-ID-Hash` 提取账号/设备维度，Express middleware 默认从 `x-captcha-account-id-hash` 和 `x-captcha-device-id-hash` 提取，也可通过 resolver 覆盖。Gateway 本地缓存不执行分布式限流，仍由平台策略服务或 Redis 计数承担。

路由策略支持基础灰度发布：`rollout_percent` 取 `1..100`，未设置或超出范围时按 `100` 处理。灰度命中使用稳定哈希，优先使用 `account_id_hash`，其次是 `device_id_hash`、IP、User-Agent 和路径。未命中当前路由灰度的请求会继续匹配下一条低优先级路由，因此可以用“高优先级小流量新策略 + 低优先级全量旧策略”完成平滑切换。Gateway 本地缓存使用同一套灰度逻辑；ticket 场景推断不使用灰度跳过，以避免已签发 ticket 在消费时因重新抽样产生场景错配。

路由策略可配置 `challenge_escalation`，用于覆盖平台级 `CAPTCHA_CHALLENGE_ESCALATION_SEQUENCE`。当该路由创建的 session 在验证阶段返回 `challenge_harder` 时，会优先使用 session 内冻结的路由升级序列；未配置时使用平台默认序列。

## 11. Ticket 设计

Ticket 是用户完成验证后的短期一次性凭证。

要求：

- 短 TTL。
- 不可伪造。
- 一次性消费。
- 消费动作原子化。
- 绑定应用。
- 绑定场景。
- 绑定路由或动作。
- 不允许跨 client、scene、route 复用。
- 可选绑定 request_nonce / IP / UA / 业务流水号。

初版推荐：

```text
opaque random token + Redis server state
```

原因是便于一次性消费、撤销、审计和原子化处理。后续可支持签名 token + 服务端消费状态作为优化。

Ticket 上下文：

```json
{
  "ticket": "cap_ticket_xxx",
  "clientId": "app_xxx",
  "scene": "login",
  "route": "/api/login",
  "issuedAt": 1710000000000,
  "expiresAt": 1710000120000,
  "bind": {
    "ipHash": "optional",
    "userAgentHash": "optional",
    "requestNonce": "optional"
  }
}
```

校验接口：

```text
VerifyTicket
  只校验 ticket 是否有效，不消费。

ConsumeTicket
  校验并消费 ticket，推荐用于业务关键动作。
```

当前实现支持 route、`request_nonce`、IP 摘要和 UA 摘要绑定：创建 session 或 Policy challenge 时传入 route/request_nonce 后，服务端会把它们保存到 session；Runtime 只带 `session_id` 启动时也会从服务端恢复上下文。verify 可以省略 route，此时使用 session route 签发 route-bound ticket；如果提交的 route 与 session route 不一致，则返回 `ROUTE_MISMATCH`。request_nonce 必须在 `runtime_meta.request_nonce` 中回传相同值；由 PolicyService/Policy API 创建的 challenge 会保存请求 IP 和 User-Agent 的 SHA-256 摘要，签发的 ticket 会绑定这些摘要。Gateway 使用 `X-Captcha-Request-Nonce` 并自动传入当前请求 IP/UA 摘要；Express middleware 默认使用 `x-captcha-request-nonce` 并自动传入当前请求 IP/UA 摘要；HTTP/gRPC ticket 校验请求使用 route、`request_nonce`、`ip_hash` 和 `user_agent_hash` 字段。

HTTP/gRPC Policy Evaluate 如果收到 `ticket`，必须先消费并校验 ticket；有效 ticket 直接返回 `TICKET_CONSUMED` allow，并可签发 `clearance_token`；无效、过期、已消费或上下文不匹配的 ticket 返回 block，不会退回普通无票策略评估。`/api/v1/tickets/verify` 使用 `consume=true` 时也会返回 clearance。

Clearance 是短期通行态，不是 IP 白名单。它由服务端随机生成并存入内存或 Redis，默认 TTL 由 `CAPTCHA_CLEARANCE_TTL_SECONDS` 控制；消费 ticket 时必须传入 IP 摘要和 UA 摘要才会签发 clearance。校验时必须匹配 `client_id`、`scene`、IP 摘要和 UA 摘要；如果签发时存在 `account_id_hash`，后续必须同账号 hash；如果存在 `device_id_hash`，后续必须同设备或匿名访客 hash。已登录用户应传账号 hash；匿名登录、注册或评论等场景应至少依赖 clearance cookie，并尽量提供设备/匿名访客 hash，避免把同出口 IP 的用户混为一类。

## 12. 验证码运行时

所有验证码类型都必须经过同一套生命周期：

```text
create session
  -> generate challenge
  -> save answer server-side
  -> render challenge
  -> collect behavior track
  -> verify answer and behavior
  -> issue ticket
  -> consume ticket
  -> write audit event
```

当前已实现能力矩阵：

| 类型 | 用户动作 | 服务端答案 | 关键资源 | 校验重点 |
|---|---|---|---|---|
| `SLIDER` | 拖动滑块到缺口 | 目标 x/y、容差 | 背景图、缺口模板、滑块图 | 终点、轨迹、耗时、容差 |
| `ROTATE` | 旋转图片到正确角度 | 目标角度、角度容差 | 背景图、旋转模板 | 角度、拖动/旋转轨迹、耗时 |
| `CONCAT` | 滑动还原错位图片 | 目标偏移量、方向、容差 | 背景图、移动上半片/静态下半片分割参数 | 偏移量、方向、轨迹 |
| `ROTATE_DEGREE` | 调整角度或指针 | 目标角度、容差 | 背景图、角度盘/指针模板 | 角度、拖动轨迹、耗时 |
| `WORD_IMAGE_CLICK` | 按顺序点击文字 | 文字序列、坐标、容差半径 | 背景图、字体、文字渲染参数 | 点击顺序、坐标、节奏 |
| `IMAGE_CLICK` | 按提示点击图标 | 图标序列、坐标、容差 | 背景图、图标库、扰动模板 | 点击顺序、坐标、误点 |

已接入扩展能力矩阵；其中曲线系列已按 Tianai 观察基线完成代码重做和浏览器烟测，但仍需人工体验验收：

| 类型 | 用户动作 | 服务端答案 | 关键资源 | 校验重点 |
|---|---|---|---|---|
| `GESTURE` | 按提示绘制曲线 | 曲线路径、方向、容差带 | 背景图、曲线模板 | 轨迹贴合度、方向、速度、断点 |
| `CURVE` | 滑动匹配曲线 | 目标 x、容差 | 后端 PNG 目标虚影、canvas 曲线 profile、drive 向量 | `single-rope` 基础单绳；固定端点、曲线形变匹配、错误偏移失败、轨迹末端一致 |
| `CURVE_V2` | 滑动匹配增强曲线 | 目标 x、容差 | 后端主题背景目标虚影、canvas 曲线 profile、drive 向量 | `dual-noise` 颗粒双轨；隐藏端点、曲线形变匹配、错误偏移失败、轨迹末端一致 |
| `CURVE_V3` | 滑动匹配圆环曲线 | 目标 x、容差 | 后端闭合圆环目标虚影、canvas 曲线 profile、周期 drive 向量 | `ring-deform` 圆环形变；隐藏端点、曲线形变匹配、错误偏移失败、轨迹末端一致 |

曲线 profile 的移动曲线使用浮点坐标，初始错位按像素级动态错位生成后再反推 drive，避免初始态过度重叠；服务端目标值必须与视觉最佳重合点一致，当前单元测试约束平均初始错位、最大错位、视觉目标反推一致性和三种曲线 `visual_style` 差异。当前 `CURVE_V2` 保留双轨噪声效果；Tianai V2 的“闭合圆环形变、无显式起点”效果迁入 `CURVE_V3`。
| `SLIDER_V2` | 拖动增强滑块 | 目标 x/y、容差 | 背景图、增强 mask、滑块图 | 终点、轨迹、素材扰动 |
| `JIGSAW` | 交换或拖拽拼图片 | 碎片排列、瓦片区域 | 专用背景图库、2x2/3x3 切片模板 | 排列正确性、瓦片区域命中、拖拽轨迹 |
| `GRID_IMAGE_CLICK` | 选择包含目标物的图片格 | 目标格子集合、瓦片区域 | 分类图片格图库、目标类别 | 多选集合、错选/漏选、点击节奏 |

资源要求：

```text
background image
  所有图片型类型都需要；单张图片只作为 fallback，不作为长期素材组织方式。

background library
  SLIDER / SLIDER_V2 / ROTATE_DEGREE / GESTURE / CURVE / CURVE_V2 / CURVE_V3 等通用图片型验证码按场景、难度、背景形态分组的图库。

concat background library
  CONCAT 使用。素材必须适合上下半片错位还原，优先选择横向连续纹理、边缘可衔接、不过度留白的图片，避免用户只能靠猜测通过。

jigsaw background library
  JIGSAW 使用。素材必须适合 2x2/3x3 切片复原，优先选择局部特征清晰、不同区域可区分、切片后仍可辨认的图片，避免低对比、纯色、重复纹理或主体全部集中在单一瓦片的图片。

cut / mask template
  SLIDER 使用。

rotate template
  ROTATE 使用。

concat moving/static split config
  CONCAT 使用。

font resource
  WORD_IMAGE_CLICK 使用。

icon resource
  IMAGE_CLICK 使用。

icon library
  IMAGE_CLICK 使用；项目会内置用户提供的 SVG 集，后续可按 tag/scene 扩展。

grid category library
  GRID_IMAGE_CLICK 使用；按 category 管理目标/非目标图片格素材。

degree template
  ROTATE_DEGREE 使用。

curve template
  GESTURE / CURVE / CURVE_V2 / CURVE_V3 使用。

jigsaw template
  JIGSAW 使用。
```

资源来源：

```text
classpath
file
url
object storage
database metadata
```

资源管理要求：

- 支持按 `client_id`、`scene`、`captcha_type` 和 `tag` 选择资源。
- 支持默认资源和租户自定义资源。
- 支持资源启用/禁用。
- 支持资源尺寸校验和预处理。
- 支持资源安全扫描和格式白名单。
- 后端只返回渲染所需素材，不返回标准答案。
- 图片格子必须使用分类图库：metadata 记录 `category`、`labels`、素材清单和目标/非目标标注，服务端抽样生成本次格子集合，只保存目标格集合在 session 内。
- 图标点选使用图标库：内置 SVG 由项目维护或用户提供，Runtime 只看到渲染后的题面与提示序列，不通过 DOM 暴露标准坐标。
- 其它图片型验证码按背景形态建立图库；通用视觉背景使用 `background_library`，滑动还原使用 `concat_background_library`，乱序拼图使用 `jigsaw_background_library`，两者不得从通用背景兜底，以免不适合切分/还原的图片影响用户通过体验。滑动还原素材要优先筛选横向连续纹理、上下分片后仍可自然对齐的图片；乱序拼图素材要优先筛选 2x2/3x3 切片后每块仍有局部识别特征的图片。图库可继续用 `difficulty`、`variant`、`scene` 和 `tag` 区分素材难度和场景。

当前实现：

- 管理 API 可新增和列出验证码资源；新增/更新时会规范化字段并校验 `captcha_type`、`resource_type`、`storage_type`、URI scheme、远程 URL 主机、可选尺寸、MIME、大小和 SHA-256 checksum 声明。
- `ConfigService.GetConfig/WatchConfig` 快照会下发资源列表。
- 创建或刷新 challenge 时会从 active 资源中选择与场景、验证码类型和可选 tag 匹配的资源；精确 `captcha_type` 优先于 `AUTO` 兜底，精确 `scene` 优先于全局资源，请求 tag 优先于 default/空 tag，同一 `resource_type` 只选择一个资源。
- `AUTO` 类型在生成 challenge 前会被解析为具体类型，资源选择阶段只处理已确定的具体验证码类型。
- 选中的资源以 `challenge.parameters.resources` 返回给 Runtime，字段包含 `id`、`scene`、`captcha_type`、`resource_type`、`storage_type`、`uri`、`tag`、`checksum`、脱敏后的 `metadata` 和 `status`；Runtime metadata 会递归过滤答案、目标点、容差、校验/评分规则、密钥和 token 类字段，控制面存储与配置快照仍保留原始 metadata 供管理使用。
- 当前使用内置 PNG 生成器作为默认兜底，避免 fallback 图像把精确答案作为可解析 SVG 属性暴露；`classpath`、本地 `file`、远程 `url`、`object_storage` 和 `database` base64/data URL 背景图已经可以由服务端合成为 `SLIDER`、`ROTATE`、`CONCAT` 和 `WORD_IMAGE_CLICK` 的 PNG challenge，完整类型矩阵均已支持资源登记、选择和内置 PNG 兜底生成，资源合成会继续细化。`CONCAT` 只读取 `concat_background_image` / `concat_background_library`，`JIGSAW` 只读取 `jigsaw_background_image` / `jigsaw_background_library`，不再复用 `background_image` / `background_library`。URL 与对象存储 endpoint 拉取会限制状态码、MIME、大小、checksum 和不安全主机，渲染前还会核对实际图片格式与 metadata 声明的 `mime_type`、`width`、`height`。对象存储支持 metadata 直连 `public_url` / `signed_url` / `presigned_url` / `object_url`，或通过 `endpoint` / `endpoint_url` / `base_url` / `public_endpoint` 拼接 `s3`、`oss`、`cos`、`obs`、`minio` URI，默认 path-style，`addressing_style=virtual_hosted` 时使用 bucket 子域名。模板和字体资源已进入服务端合成链路：`slider_template` 作为滑块 mask，`rotate_template` 作为覆盖层，`concat_template` 支持 JSON/metadata 配置 `split_y`、`split_ratio`、`gap_color` 和 `border_color`，并会输出透明下半区的移动上半片还原 piece；`font` 支持 `glyph_scale`、`palette` 和自定义点阵 `glyphs` metadata；`icon`、`background_library`、`concat_background_library`、`jigsaw_background_library`、`rotate_library`、`grid_category_library`、`icon_library`、`degree_template`、`curve_template`、`gesture_template`、`jigsaw_template` 已作为资源类型开放登记。

## 13. 滑动轨迹人机校验

滑动轨迹校验用于提高低成本自动化脚本的通过成本，不作为单独的强安全边界。它的输出是风险评分和失败原因分类，最终结果由答案校验、轨迹评分、失败次数、IP/账号策略和 ticket 机制共同决定。

### 13.1 轨迹采集

前端 Runtime 只采集行为事实，不判断是否通过。

轨迹点结构：

```json
{
  "x": 124,
  "y": 18,
  "t": 173,
  "type": "move"
}
```

字段：

```text
x / y
  相对验证控件的坐标。

t
  相对拖动开始的毫秒时间。

type
  start
  move
  end
```

可选运行时信息：

```text
pointer_type
  mouse
  touch
  pen

viewport
  控件尺寸和页面尺寸。

device_pixel_ratio
  用于服务端做坐标归一化。

runtime_version
  用于排查不同 Runtime 版本的行为差异。
```

采集约束：

- 轨迹点按时间递增。
- 服务端对点数设置上限，避免请求体过大。
- 服务端对坐标做归一化，不信任客户端预处理结果。
- 服务端接受低频采样和移动端触控差异，避免过度误伤。

### 13.2 特征提取

基础特征：

```text
duration_ms
point_count
distance_x / distance_y
path_length
straightness
overshoot_count
pause_count
```

速度和加速度特征：

```text
avg_velocity
max_velocity
velocity_variance
acceleration_variance
jerk_variance
```

形态特征：

```text
y_jitter
direction_changes
micro_corrections
start_delay
end_stability
```

异常特征：

```text
constant_velocity
perfect_line
too_fast
too_few_points
timestamp_anomaly
teleport
synthetic_curve
```

### 13.3 规则评分

一期使用规则评分，不引入机器学习实时决策。

评分输出：

```text
answer_score
  答案是否接近目标，例如位置、角度、点击点顺序。

track_score
  轨迹是否像正常人类操作。

risk_score
  结合 IP、账号、设备、失败次数、路由策略后的风险分。
  当前可由后端/Gateway/middleware 作为脱敏上下文传给 PolicyService，服务端按路由阈值执行 observe/challenge/block。

decision
  pass
  retry
  challenge_harder
  block
```

规则原则：

- 单个特征不应直接决定失败，除非明显异常。
- 多个弱异常累积后提高风险分。
- 移动端、触摸屏、低性能设备要有单独阈值。
- 低置信度情况优先返回重试或升级挑战，不直接阻断。
- 当前实现中，答案正确但轨迹明显异常会返回 `challenge_harder` 和 `can_refresh=true`，刷新后按服务端升级序列切换挑战类型；默认序列为 `SLIDER -> ROTATE -> CONCAT -> WORD_IMAGE_CLICK`，可通过 `CAPTCHA_CHALLENGE_ESCALATION_SEQUENCE` 覆盖，由路由策略创建的 session 可用 `challenge_escalation` 进一步覆盖。
- 轨迹评分参数只保存在服务端配置或 session 中，不由客户端提交。

反误伤原则：

- 不要求轨迹必须“很像人”，只拦明显脚本特征。
- 不以单一耗时阈值判断人机。
- 不强依赖 y 轴抖动，触控设备可能很平滑。
- 不强依赖点数，浏览器和设备采样率差异很大。
- 不把轨迹评分作为唯一通过条件。
- 对无障碍场景保留替代验证方式。

## 14. AI 训练与模型评分

可以加入 AI 训练，但它不替代规则评分和策略系统。AI 应定位为可插拔风险模型层，用于从历史验证、请求和业务反馈中学习异常模式。

### 14.1 数据入池与模型训练

每次滑动都可以成为训练候选样本，但不能直接实时更新线上模型。

推荐流程：

```text
user slide
  -> verify request
  -> feature extraction
  -> async event queue
  -> feature store
  -> delayed labeling
  -> offline training
  -> offline evaluation
  -> shadow scoring
  -> gray release
  -> enforce as risk_score input
```

允许：

- 每次滑动异步写入训练数据池。
- 对样本做脱敏、聚合、去重、采样。
- 等待业务反馈后补充标签。
- 定时批量训练新模型。
- 新模型先影子运行再灰度上线。

禁止：

- 每次滑动后立即更新线上模型。
- 未确认标签的数据直接作为正负样本。
- 用户可控数据不经过清洗直接进入训练集。
- 模型自动上线并直接阻断请求。

原因：

- 滑动当下通常没有可靠标签，只知道通过或失败，不等于人或机器。
- 攻击者可以制造大量样本进行数据投毒。
- 实时在线学习容易产生反馈回路，模型越拦越偏。
- 模型更新需要评估误伤率、漂移和回滚路径。

当前实现：

- 验证接口完成后异步写入 `RiskFeatureSnapshot`。
- 特征包含轨迹统计摘要、验证结果、验证码类型、场景和弱标签；轨迹摘要覆盖 `duration_ms`、`point_count`、`path_length`、`straightness`、速度/加速度/jerk 方差、`direction_changes`、`micro_corrections`、`pause_count`、`perfect_line`、`constant_velocity`、`synthetic_curve`、`teleport` 等字段。
- 不保存明文 IP、账号、cookie、完整 header 或业务 payload。
- 默认 `model_trainable=false`，表示候选样本需要离线清洗或业务反馈后才能进入训练集。
- 管理 API 和管理台提供训练样本列表，支持按场景、验证码类型、人工标签和可训练状态筛选，并支持人工审核或业务反馈后更新标签与 `model_trainable` 状态；管理台对进入训练集或撤销训练标注的操作使用确认流程，避免误点污染离线训练数据。
- `GET /api/v1/admin/risk-feature-snapshots/export` 支持按同样过滤条件导出离线训练样本文件，默认只导出 `model_trainable=true` 的明确标签样本；传入 `trainable_only=false` 可导出候选样本用于离线分析，但不代表可直接入训。
- `model_trainable=true` 只允许搭配 `likely_human`、`likely_bot`、`confirmed_human` 或 `confirmed_bot` 等明确标签；`captcha_pass` / `captcha_retry` 这类单次验证码结果只能作为弱标签候选，不能直接入训。
- 训练标签更新会写入审计事件，原因码为 `RISK_FEATURE_LABEL_UPDATE`。
- 管理 API 和管理台支持登记 `RiskModelVersion`，记录模型名称、版本、特征版本、训练窗口、artifact URI、评估指标和 `shadow/observe/enforce` 模式；管理台登记只创建候选版本，激活和回滚必须通过确认操作进入状态流转。
- 模型版本支持显式激活；同名模型激活新版本时，旧 active 版本会转为 `retired`。回滚接口会把当前 active 标记为 `rolled_back`，并恢复最近一个 retired 版本。
- 当 active 模型版本的 `feature_version` 与特征快照匹配时，异步入池任务会写入 `risk_model_shadow` 摘要，包括模型 id、名称、版本、模式、分数、分桶、原因和 `decision_effect=none`。
- 当前不实时训练，不自动上线，也不把模型分数返回给客户端。PolicyService 支持接收后端/Gateway/middleware 提供的 `model_score` 和 `model_mode`：`shadow` 不影响决策，`observe` / `enforce` 只作为 `risk_score` 输入，并且只有路由显式配置风险阈值时才生效；触发风险挑战时可用 `risk_challenge_type` 升级验证码类型。
- 如果配置 `CAPTCHA_RISK_INFERENCE_URL`，HTTP/gRPC PolicyService 会在正常策略评估前调用外部推理服务，使用当前 active `RiskModelVersion` 元数据、路由上下文、IP hash、User-Agent hash、账号 hash 和设备 hash 作为输入。返回的 `score` / `risk_score` 会写入 `model_score`，返回的 `mode` 缺省时使用 active 模型模式；调用失败只记录日志并降级为原请求上下文。已有 `model_score` 或 `model_mode` 的请求不会重复调用外部推理服务，避免覆盖 Gateway 或业务后端已提供的判断。

### 14.2 训练数据

数据来源：

```text
captcha attempts
  验证类型、答案结果、轨迹特征、失败原因、耗时、重试次数。

request context
  scene、route、method、IP hash、account hash、device hash、UA 摘要。

policy events
  命中的 IP 策略、频控策略、路由策略、fail policy。

business feedback
  登录失败、注册滥用、短信轰炸、评论垃圾、人工申诉结果。
```

标签来源：

```text
positive / likely human
  低风险来源，验证通过后业务行为正常。

negative / likely bot
  高频失败、黑名单命中、业务确认滥用、短时间批量行为。

unknown
  缺少业务反馈或置信度不足的数据。
```

模型输入只使用特征，不使用原始敏感信息。

允许特征：

```text
轨迹统计特征
验证结果特征
频率特征
IP/账号/设备 hash 后的聚合特征
路由和场景特征
```

禁止特征：

```text
明文 IP
明文账号
明文手机号、邮箱、身份证
原始 cookie
完整请求 header
未脱敏业务 payload
```

### 14.3 模型路线

```text
Phase 1
  规则评分。
  采集训练所需特征和标签。

Phase 2
  离线训练。
  模型仅离线评估，不进入请求链路。

Phase 3
  影子模式。
  验证后异步写入模型影子评分，但不影响决策。

Phase 4
  灰度决策。
  模型分数只作为 risk_score 的一个输入，不直接决定 block。
  当前已支持通过 PolicyService 请求上下文传入 observe/enforce 模型分数并由路由阈值灰度使用，也支持平台服务调用可选外部在线推理服务补充分数。
```

模型类型建议：

```text
baseline
  逻辑回归或简单规则校准，用于建立可解释基线。

tree model
  GBDT / XGBoost / LightGBM 一类特征模型，适合表格特征和轨迹统计特征。

anomaly detection
  Isolation Forest / One-Class 模型，用于发现未知脚本模式。

deep sequence model
  仅作为后续探索，用于原始轨迹序列。
  不作为一期或早期默认方案。
```

上线要求：

- 必须有模型版本号。
- 必须记录训练数据时间窗口。
- 必须记录特征版本。
- 必须支持一键回滚。
- 必须支持 shadow / observe / enforce 三种模式。
- 模型分数不能直接返回给客户端。
- 模型分数不能作为唯一阻断条件。
- 模型效果必须同时看拦截率和误伤率。
- 重要业务场景必须保留人工申诉或降级路径。

## 15. 验证流程

### 15.1 Iframe 流程

```text
业务页面
  -> 加载 iframe challenge_url
  -> 用户完成验证
  -> 平台签发 ticket
  -> iframe postMessage 给业务页面
  -> 业务页面提交表单时携带 ticket
  -> 业务后端校验 ticket
```

独立 redirect 模式：

```text
业务页面
  -> 跳转到 challenge_url?return_url=...
  -> 用户完成验证
  -> 平台签发 ticket
  -> Runtime 跳回 return_url 并追加 captcha_ticket / captcha_session_id / captcha_route / captcha_request_nonce
  -> 业务后端校验或消费 ticket
```

### 15.2 中间件流程

```text
用户请求业务接口
  -> middleware 提取上下文
  -> 本地匹配策略
  -> 如需要，调用 PolicyService.Evaluate
  -> allow: 放行
  -> block: 返回 403
  -> observe: 放行并上报
  -> challenge: 返回 challenge_url
  -> 用户完成验证拿到 ticket
  -> 再次请求携带 ticket
  -> middleware 调用 TicketService.ConsumeTicket
  -> 通过后放行业务请求
```

### 15.3 Gateway 流程

```text
用户请求
  -> Gateway
  -> 如携带 ticket，Gateway 优先消费 ticket
  -> ticket 有效: 转发业务服务
  -> ticket 无效或已消费: 阻断请求
  -> 未携带 ticket: Gateway 执行本地策略和远程决策
  -> 未命中验证: 转发业务服务
  -> 命中验证: 返回验证页面或 challenge_url
  -> 本地决策、ticket 结果和降级结果异步上报平台
  -> 用户完成验证
  -> Gateway 消费 ticket
  -> 转发业务服务
```

## 16. 故障策略

```yaml
failPolicy:
  login: fail_close
  register: fail_close
  reset_password: fail_close
  comment: fail_open
  search: fail_open
  browse: fail_open
```

```text
fail_open
  平台不可用时放行，避免影响普通业务可用性。

fail_close
  平台不可用时阻断，保护高风险业务。
```

要求：

- 所有远程调用必须设置 deadline。
- 平台异常必须打点。
- fail-open / fail-close 必须进入审计日志。
- Gateway 和 Express 参考中间件支持可选短期熔断；连续 policy/ticket 调用失败达到阈值后，在冷却窗口内跳过阻塞式平台调用并按 fail-open / fail-close 降级，同时继续尝试异步事件上报。
- AI 数据采集、事件队列或外部推理服务不可用时必须降级，不能阻塞验证接口。

## 17. 数据模型草案

### 17.1 Application

```text
id
client_id
name
secret_hash
has_secret
status
default_fail_policy
created_at
updated_at
```

`secret_hash` 不通过普通应用列表返回。管理 API 返回 `has_secret` 供后台展示应用是否已配置密钥；轮换密钥时，平台生成明文 `client_secret` 并只返回一次，随后只保存 hash。

`status=disabled` 会立即影响运行主链路：公开 challenge session 接口和 verify/refresh 接口会拒绝该应用；HTTP/gRPC Policy 返回 `APPLICATION_DISABLED` 阻断决策；Ticket 返回 `valid=false`；Event 要求事件具备明确 `client_id`，并拒绝 disabled 应用写入。ConfigService 仍可在鉴权后返回包含 `application_status=disabled` 的快照，供 Gateway 本地缓存停止放行。

### 17.2 RoutePolicy

```text
id
client_id
name
path_pattern
method
scene
mode
challenge_type
risk_challenge_type
challenge_escalation
fail_policy
priority
enabled
rollout_percent
token_ttl_seconds
risk_observe_score
risk_challenge_score
risk_block_score
rate_limit
  window_seconds
  max_requests
  strategy: fixed_window / sliding_window / token_bucket
created_at
updated_at
```

### 17.3 IpPolicy

```text
id
client_id
type
cidr
action
reason
enabled
created_at
updated_at
```

### 17.4 ChallengeSession

```text
id
client_id
scene
challenge_type
route
request_nonce
resource_tag
return_url
resource_ids
render_payload_ref
answer_ref
verify_context_ref
failure_count
status
expire_at
created_at
```

### 17.5 CaptchaResource

```text
id
client_id
scene
captcha_type
resource_type
storage_type
uri
tag
metadata
checksum
status
created_at
updated_at
```

`resource_type`:

```text
background_image
background_library
concat_background_image
concat_background_library
jigsaw_background_image
jigsaw_background_library
rotate_library
grid_category_library
slider_template
rotate_template
concat_template
font
icon
icon_library
degree_template
curve_template
gesture_template
jigsaw_template
```

`storage_type`:

```text
embedded
classpath
file
url
object_storage
database
```

当前 metadata 识别字段：

```text
width
height
mime_type
size_bytes
uri_scheme
resource_family
data_url / data_uri
base64 / data_base64 / content_base64
public_url / signed_url / presigned_url / object_url
endpoint / endpoint_url / base_url / public_endpoint
addressing_style
split_y / split_ratio / gap_color / border_color
glyph_scale / palette / glyphs
difficulty
usage_profile
suitability
```

`checksum` 使用 `sha256:<64 hex>` 规范格式；管理 API 可接收裸 64 位 sha256 hex 并自动补齐前缀。

### 17.6 CaptchaAttempt

```text
id
session_id
client_id
scene
challenge_type
ip_hash
account_id_hash
device_id_hash
answer_digest
track_digest
result
failure_reason
created_at
```

### 17.7 RiskFeatureSnapshot

```text
id
attempt_id
client_id
scene
challenge_type
feature_version
features_digest
features_ref
features
label
label_source
model_trainable
created_at
```

### 17.8 RiskModelVersion

```text
id
name
version
feature_version
training_window
artifact_uri
metrics
mode
status
created_at
activated_at
```

`mode`:

```text
shadow
observe
enforce
```

`status`:

```text
candidate
active
retired
rolled_back
```

### 17.9 CaptchaTicket

```text
id
ticket_hash
client_id
scene
route
status
bind_context
expire_at
consumed_at
created_at
```

### 17.10 AuditEvent

```text
id
client_id
scene
route
ip_hash
account_id_hash
device_id_hash
action
decision_reason
challenge_type
result
created_at
```

## 18. 安全要求

- 答案永不下发到客户端。
- 算法可以开源，但本次 challenge 的答案、容差、评分参数和 ticket 状态不下发到客户端。
- 生产环境密钥必须由部署方生成，仓库不得提供可直接用于生产的默认密钥。
- 应用 client secret 明文只能在生成或轮换时返回一次，普通管理列表和配置下发不得返回 secret hash。
- 业务后端、Gateway、middleware 调用策略评估、ticket 校验、事件上报和 gRPC 配置服务时，如果应用已配置 secret，必须携带 `X-Captcha-Client-Secret` 或 Bearer token。
- 浏览器 iframe Runtime 不持有 client secret；公开 challenge session 创建依赖短 TTL、服务端答案、ticket 一次性消费、策略限流和 CORS/部署边界共同防护。
- ticket 必须不可伪造，默认一次性消费，消费动作必须原子化。
- challenge id 必须随机且不可预测。
- challenge 必须短 TTL。
- ticket 必须绑定 client 和 scene。
- ticket 不允许跨 client、scene、route 复用；如果 ticket 签发时带有 route，校验或消费请求必须提供完全一致的 route，缺失 route 也应拒绝。
- 管理后台和 gRPC 通信应支持 mTLS 或强鉴权；当前 gRPC 已支持 `CAPTCHA_GRPC_TOKEN` 平台级 Bearer/header token，应用维度仍使用 client secret。
- 管理 API 在生产环境必须设置 `CAPTCHA_ADMIN_TOKEN` 或放在等价的受保护内网/网关之后；开源版不内置复杂角色权限体系。
- 中间件和 Gateway 上报 header 时必须使用 allowlist，避免泄露敏感信息；当前默认不上传业务 header，仅在 `headerAllowlist` 或 `CAPTCHA_GATEWAY_HEADER_ALLOWLIST` 显式配置时上传指定头。
- 资源接口应避免暴露原始答案信息。
- Verify API 不接受客户端提交的容差、服务端目标值、评分阈值、服务端评分结果或校验规则；当前实现会拒绝 `tolerance`、`target`、`answer_seed`、`verify_rule`、`score_rule`、`score_threshold` 和 `track_score` 等字段，包括嵌套字段。
- 验证失败只返回粗粒度错误码，不暴露具体失败维度和阈值。
- 验证失败次数应有限制；当前实现对单个 challenge session 设置失败上限，达到上限后返回 `TOO_MANY_FAILURES` 并停止复用该 session。
- 同一 IP、账号、设备维度都应支持限流。
- 生产策略阈值、IP 黑白名单、租户密钥和运行时计数不应暴露到前端。
- 配置变更必须有审计记录；当前实现对应用、应用密钥轮换、路由策略、IP 策略、验证码资源和模型版本的成功变更写入 `CONFIG_*` 审计事件，训练标签更新写入 `RISK_FEATURE_LABEL_UPDATE` 审计事件。
- 训练样本必须脱敏，AI 模型不能直接使用明文敏感信息。

## 19. MVP 范围

一期实现：

- 托管验证运行时。
- Iframe 模式。
- 后端 ticket 校验 API。
- `SLIDER` 滑块验证码。
- `ROTATE` 旋转验证码。
- `CONCAT` 滑动还原验证码。
- `ROTATE_DEGREE` 角度刻度验证码。
- `WORD_IMAGE_CLICK` 文字点选验证码。
- `IMAGE_CLICK` 图标点选验证码。
- 验证码资源管理：背景图、模板图、字体资源。
- 验证码预生成和短 TTL 缓存。
- 应用和密钥管理。
- 路由策略模型。
- IP allowlist / blocklist。
- 基础 rate limit。
- gRPC PolicyService。
- gRPC TicketService。
- gRPC ConfigService 基础配置拉取、同进程配置更新推送和 Gateway 本地配置缓存刷新。
- 一个 Node.js Express 参考中间件。
- 一个参考 Gateway 反向代理。
- PostgreSQL 存储应用、路由策略、IP 策略、验证码资源和审计事件。
- Redis 存储 challenge、ticket、限流计数。
- 审计日志。
- 风控特征采集：轨迹统计特征、策略命中、粗粒度结果标签。
- 轻量管理台基础页面：应用、路由策略、IP 策略、策略模拟、资源、审计、训练样本。

一期暂不做：

- 全量 Gateway 插件生态。
- 复杂设备指纹。
- 机器学习实时决策。
- 高级管理后台大屏。
- 多租户计费。
- 策略市场和插件市场。

## 20. 演进路线

### Phase 1: 验证平台闭环

- Runtime + Engine + Ticket。
- Iframe 接入。
- HTTP JSON API。
- `GESTURE` / `CURVE` / `CURVE_V2` / `CURVE_V3` / `SLIDER` / `SLIDER_V2` / `ROTATE` / `CONCAT` / `ROTATE_DEGREE` / `WORD_IMAGE_CLICK` / `IMAGE_CLICK` / `JIGSAW` / `GRID_IMAGE_CLICK` 具体验证码。
- 资源管理。
- 预生成缓存。
- PostgreSQL 控制面存储。
- Redis 临时态存储。
- 风控特征采集。
- 轻量管理台基础页面和核心配置新增表单。

### Phase 1.5: Tianai 在线体验类型对齐

- 已引入外部兼容类型映射：`RANDOM`、`GESTURE`、`CURVE`、`CURVE2`、`CURVE3`、`SLIDER2`、`JIGSAW`；`POW` / `PROOF_OF_WORK` 已移除，不再作为兼容输入。
- 已扩展 `CaptchaType` 枚举、管理台选择项、资源类型和 Browser smoke 覆盖。
- Runtime 已抽象统一交互事件：拖动、点选、绘制、刮擦和拼图交换。
- Engine 已增加每类验证码的服务端生成、答案保存、容差配置、校验和审计摘要。
- Demo 页面按 Tianai 在线体验站点排列验证码类型，未支持类型不能静默降级为已有类型。
- 下一步对增强版类型继续增加资源扰动、素材库和更细粒度行为评分。

### Phase 2: 策略和中间件

- PolicyService gRPC。
- TicketService gRPC。
- ConfigService 基础配置拉取和 WatchConfig 流式更新。
- IP 策略。
- 路由策略。
- fail-open / fail-close。
- 一个主流后端中间件：Node.js Express。
- 内置参考 Gateway 反向代理，支持 HTTP JSON 策略客户端、gRPC PolicyService 客户端和可选 ConfigService 本地配置缓存。

### Phase 3: Gateway 能力

- 反向代理模式。
- Gateway 插件原型。
- 配置热更新增强和多节点缓存一致性治理。
- Gateway 事件批量上报（当前已支持有界队列、批量大小和定时 flush）。
- 分布式频控；当前 Redis 临时态已支持固定窗口、滑动窗口和令牌桶计数。
- Gateway observe 模式和管理端策略 dry-run 模拟。

### Phase 4: 风控增强

- 行为轨迹评分增强。
- 账号维度风险。
- 设备维度风险。
- 基础路由策略灰度已支持；risk_based 路由已支持风险分阈值、风险挑战类型升级和 observe/enforce 模型分作为 risk_score 输入，后续增强更复杂的多维风险灰度。
- 异常资源命中分析；当前验证特征会记录脱敏资源摘要，管理指标和 Prometheus 已按资源维度输出近期命中、失败和失败率。
- AI 离线训练。
- AI 影子模式评分。
- AI 灰度参与 risk_score；当前已支持由后端/Gateway/middleware 提供模型分上下文，也支持平台调用可选外部推理服务补充分数，统一由路由阈值使用。
- 模型版本管理和回滚；当前已实现模型元数据登记、显式激活和回滚，内置模型仍只做异步 shadow 评分，在线推理采用可选外部服务边界。
- 更复杂的挑战编排；当前已支持 risk-score challenge 使用 `risk_challenge_type` 覆盖默认验证码类型，也支持验证阶段 `challenge_harder` 按平台配置序列升级下一题类型，并支持 route policy 级 `challenge_escalation` 覆盖。

## 21. 后续决策与扩展边界

- 其他 Gateway 生态适配按接入需求推进，继续保持薄中间件/薄插件边界。
- 频控已支持固定窗口、滑动窗口和令牌桶；是否增加更多策略需按误伤率和实现复杂度评估。
- AI 特征存储长期形态继续使用 PostgreSQL，还是扩展到对象存储、ClickHouse 或专用 feature store。

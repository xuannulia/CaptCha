#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

failures=0

fail() {
	echo "FAIL: $*" >&2
	failures=$((failures + 1))
}

pass() {
	echo "PASS: $*"
}

require_pattern() {
	local file=$1
	local pattern=$2
	local label=$3
	if rg -q "$pattern" "$file"; then
		pass "$label"
	else
		fail "$label"
	fi
}

reject_pattern() {
	local file=$1
	local pattern=$2
	local label=$3
	if rg -q "$pattern" "$file"; then
		fail "$label"
	else
		pass "$label"
	fi
}

require_dependency_allowlist() {
	local file=$1
	local label=$2
	shift 2
	if node - "$file" "$label" "$@" <<'NODE'
const fs = require("fs");
const [, , file, label, ...allowed] = process.argv;
const pkg = JSON.parse(fs.readFileSync(file, "utf8"));
const deps = Object.keys(pkg.dependencies || {});
const allowedSet = new Set(allowed);
const unexpected = deps.filter((dep) => !allowedSet.has(dep));
const missing = allowed.filter((dep) => !deps.includes(dep));
if (unexpected.length || missing.length) {
  if (unexpected.length) console.error(`FAIL: ${label}: unexpected production dependencies: ${unexpected.join(", ")}`);
  if (missing.length) console.error(`FAIL: ${label}: missing production dependencies: ${missing.join(", ")}`);
  process.exit(1);
}
console.log(`PASS: ${label}`);
NODE
	then
		return
	else
		fail "$label"
	fi
}

require_pattern web/runtime/package.json '"preact"' "runtime uses Preact"
require_pattern web/runtime/vite.config.ts '@preact/preset-vite' "runtime uses the Preact Vite preset"
reject_pattern web/runtime/package.json '"(antd|@ant-design/icons|@ant-design/charts|echarts|element-plus|react|react-dom|react-router-dom|@tanstack/react-query)"' "runtime package stays free of admin/heavy UI dependencies"
require_dependency_allowlist web/runtime/package.json "runtime production dependencies stay minimal" "@preact/signals" "preact"

require_pattern web/admin/package.json '"antd"' "admin uses Ant Design"
require_pattern web/admin/package.json '"react-router-dom"' "admin uses React Router"
require_pattern web/admin/package.json '"@tanstack/react-query"' "admin uses TanStack Query"
require_pattern web/admin/src/main.tsx 'react-router-dom' "admin code wires React Router"
require_pattern web/admin/src/main.tsx '@tanstack/react-query' "admin code wires TanStack Query"
require_pattern web/admin/src/main.tsx 'from "antd"' "admin code wires Ant Design"
require_pattern web/admin/src/main.tsx 'captcha-admin-token' "admin console supports runtime admin authorization"
require_pattern web/admin/src/main.tsx 'captcha-admin-unauthorized' "admin console reacts to backend authorization failures"
require_pattern web/admin/src/main.tsx '/api/v1/admin/auth/check' "admin console validates authorization before loading data"
require_pattern web/admin/src/main.tsx 'authState === "authorized"' "admin console gates management pages behind authorization state"
require_pattern web/admin/src/main.tsx '管理令牌' "admin console presents open-source management access as a simple token"
reject_pattern web/admin/src/main.tsx '令牌有效|管理控制台|header-subtitle' "admin header avoids redundant status and console copy"
require_pattern web/admin/src/main.tsx 'okText="保存令牌"' "admin token modal save action names its target"
require_pattern web/admin/src/main.tsx '>新增应用</Button>' "application page primary action names its target"
require_pattern web/admin/src/main.tsx '>新增策略</Button>' "route policy page primary action names its target"
require_pattern web/admin/src/main.tsx '>添加名单</Button>' "IP policy page primary action names its target"
require_pattern web/admin/src/main.tsx 'okText="保存应用"' "application modal save action names its target"
require_pattern web/admin/src/main.tsx 'okText="保存策略"' "route policy modal save action names its target"
require_pattern web/admin/src/main.tsx 'okText="保存名单"' "IP policy modal save action names its target"
require_pattern web/admin/src/main.tsx 'label="触发条件"' "route policy form uses business trigger wording"
require_pattern web/admin/src/main.tsx 'title: "验证方式"' "route policy list explains challenge type as a verification method"
require_pattern web/admin/src/main.tsx 'title: "失败后升级"' "route policy list explains escalation timing"
require_pattern web/admin/src/main.tsx 'title: "生效范围"' "route policy list uses activation range wording"
require_pattern web/admin/src/main.tsx 'title: "触发规则"' "route policy list uses trigger rule wording"
require_pattern web/admin/src/main.tsx 'label="异常处理"' "admin fail policy uses outage handling wording"
require_pattern web/admin/src/main.tsx 'fail_open: "异常时放行"' "fail-open copy is business readable"
require_pattern web/admin/src/main.tsx 'riskThresholdSummary' "route policy list summarizes risk thresholds with readable business copy"
require_pattern web/admin/src/main.tsx 'label="名单类型"' "IP policy form uses list wording instead of duplicate action wording"
require_pattern web/admin/src/main.tsx 'allowlist: "放行名单"' "IP allowlist is localized as an operational allow list"
require_pattern web/admin/src/main.tsx 'blocklist: "拦截名单"' "IP blocklist is localized as an operational block list"
require_pattern web/admin/src/main.tsx 'function ApplicationCell' "admin tables render application names before identifiers"
require_pattern web/admin/src/main.tsx 'className="application-option"' "admin application selectors render names before identifiers"
require_pattern web/admin/src/main.tsx 'optionFilterProp="searchText" options=\{appOptions\}' "admin application selectors search names and identifiers without making ids primary copy"
require_pattern web/admin/src/main.tsx 'label="上线方式"' "risk model admin uses release wording"
require_pattern web/admin/src/main.tsx 'title: "质量"' "risk model admin surfaces model quality metrics"
require_pattern web/admin/src/main.tsx 'label="模型名称"' "risk model registration uses explicit model naming"
require_pattern web/admin/src/main.tsx 'okText="保存模型"' "risk model registration save action names its target"
require_pattern web/admin/src/main.tsx 'label: "样本复核"' "risk sample review route uses operational wording"
require_pattern web/admin/src/main.tsx 'Card title="样本复核"' "risk sample review page title avoids training-console wording"
require_pattern web/admin/src/main.tsx '>导出入训样本</Button>' "risk sample review export names the dataset explicitly"
require_pattern web/admin/src/main.tsx '>启用</Button>' "risk model list uses enable wording"
require_pattern web/admin/src/main.tsx '>恢复</Button>' "risk model list uses restore wording"
require_pattern web/admin/src/main.tsx 'placeholder="输入样本批次"' "risk model registration avoids technical sample-version placeholders"
require_pattern web/admin/src/main.tsx 'placeholder="输入模型文件地址"' "risk model registration uses neutral model file placeholder"
require_pattern web/admin/src/main.tsx 'title: "训练时间窗"' "risk model admin explains training range as a time window"
require_pattern web/admin/src/main.tsx 'title: "样本版本"' "admin risk training uses sample version wording"
require_pattern web/admin/src/main.tsx 'label="人工标签"' "admin risk training uses human-review label wording"
require_pattern web/admin/src/main.tsx 'training_feedback: "样本反馈"' "admin audit uses sample-feedback wording"
require_pattern web/admin/src/main.tsx 'decisionReasonLabel' "admin maps backend decision reasons to business copy"
require_pattern web/admin/src/main.tsx 'decisionReasonOptions' "admin filters audit reasons with localized options"
require_pattern web/admin/src/main.tsx 'ANSWER_MISMATCH: "答案不匹配"' "admin localizes captcha answer failure reasons"
require_pattern web/admin/src/main.tsx 'TRACK_CHALLENGE_HARDER: "轨迹异常升级验证"' "admin localizes captcha track risk reasons"
require_pattern web/admin/src/main.tsx 'value \? "其他原因" : "-"' "admin avoids rendering unknown backend reason codes as primary copy"
require_pattern web/admin/src/main.tsx 'role="button"' "resource gallery cards can be selected without targeting a tiny checkbox"
require_pattern web/admin/src/style.css 'resource-file-item:focus-visible' "resource gallery cards expose keyboard focus"
require_pattern web/admin/src/main.tsx 'label: "资源图库"' "resource gallery navigation uses gallery wording"
require_pattern web/admin/src/main.tsx 'resources: "资源图库"' "resource gallery page title uses gallery wording"
require_pattern web/admin/src/main.tsx '>上传图片</Button>' "resource gallery primary action uses upload wording"
require_pattern web/admin/src/main.tsx 'title="上传图片素材"' "resource gallery modal uses image material wording"
require_pattern web/admin/src/main.tsx 'okText="保存图片"' "resource gallery save action avoids generic resource wording"
require_pattern web/admin/src/main.tsx 'formData\.set\("scene", ""\)' "resource upload keeps scene out of the default upload form"
require_pattern web/admin/src/main.tsx 'formData\.set\("tag", defaults\.tag\)' "resource upload keeps material grouping out of the default upload form"
require_pattern web/admin/src/main.tsx 'title="启用素材"' "overview metric uses material wording"
require_pattern web/admin/src/main.tsx 'Card title="素材健康"' "overview material health panel uses material wording"
require_pattern web/admin/src/main.tsx 'CONFIG_RESOURCE_UPSERT: "素材变更"' "audit config resource events use material wording"
require_pattern web/admin/src/main.tsx 'resourceHealthLabel' "overview resource health uses readable resource summaries"
require_pattern web/admin/src/main.tsx 'materialGroupLabel' "resource group labels map backend defaults to user-facing copy"
require_pattern web/admin/src/main.tsx 'placeholder="输入接口路径"' "policy simulator path field avoids demo defaults"
require_pattern web/admin/src/main.tsx 'label: "识别信息"' "policy simulator identifies request signals with operational wording"
require_pattern web/admin/src/main.tsx 'label: "风险信号"' "policy simulator groups risk inputs as business signals"
require_pattern web/admin/src/main.tsx 'label="模型状态"' "policy simulator uses model status wording"
require_pattern web/admin/src/main.tsx 'policy-simulator-options' "policy simulator keeps optional context out of the primary form"
require_dependency_allowlist web/admin/package.json "admin production dependencies stay on the chosen mature stack" "@ant-design/icons" "@tanstack/react-query" "antd" "react" "react-dom" "react-router-dom"
reject_pattern web/admin/package.json '"(@ant-design/pro-components|@ant-design/pro-layout|@umijs/|umi|next|nuxt|vue|element-plus|echarts|@ant-design/charts)"' "admin package avoids heavier alternate app frameworks and chart stacks"
reject_pattern web/admin/src/main.tsx '明细列表|系统资源|resource-uri|resource-table-wrap|system-resource-panel' "admin resource gallery avoids raw detail panels"
reject_pattern web/admin/src/style.css 'resource-uri|resource-table-wrap|system-resource-panel' "admin resource gallery styles avoid raw detail panels"
reject_pattern web/admin/src/main.tsx 'Card title="(应用|路由策略|IP 策略)" extra=\{<Button type="primary"[^>]*>新增</Button>\}' "primary configuration actions avoid generic add wording"
reject_pattern web/admin/src/main.tsx 'okText="保存"' "modal save actions name the object being saved"
reject_pattern web/admin/src/main.tsx 'label: "资源"|resources: "资源"' "resource gallery avoids generic resource wording in navigation and page title"
reject_pattern web/admin/src/main.tsx '还没有上传图库资源|title="新增图片"|okText="保存资源"|删除 \$\{selectedGalleryCount\} 个资源' "resource gallery avoids abstract resource CRUD wording"
reject_pattern web/admin/src/main.tsx '活跃资源|资源健康|暂无资源失败样本|暂无素材失败样本|CONFIG_RESOURCE_UPSERT: "资源变更"|CONFIG_RESOURCE_DELETE: "资源删除"' "overview and audit avoid backend resource wording"
reject_pattern web/admin/src/main.tsx 'SummaryRow label="配置变更"' "overview avoids raw config-change metric wording"
reject_pattern web/admin/src/main.tsx '失败策略|失败放行|失败拦截' "admin fail policy avoids raw failure wording"
reject_pattern web/admin/src/main.tsx '观察/验证/拦截' "route policy list avoids compact debug threshold summaries"
reject_pattern web/admin/src/main.tsx 'title: "升级"|title: "灰度"|title: "规则"|label="升级序列"|label="灰度比例"|label="默认验证码"|label="风险验证码"' "route policy avoids abbreviated rollout and escalation wording"
reject_pattern web/admin/src/main.tsx '训练特征|导出 JSONL|特征集|captcha-risk-features' "admin risk training copy avoids implementation wording"
reject_pattern web/admin/src/main.tsx '训练反馈' "admin audit avoids training-console result wording"
reject_pattern web/admin/src/main.tsx 'Client ID' "admin application copy avoids raw client-id wording"
reject_pattern web/admin/src/main.tsx 'Ticket TTL|Nonce|account hash|device hash|\bUA\b' "admin policy and audit copy avoids raw integration wording"
reject_pattern web/admin/src/main.tsx 'label: "请求上下文"|label: "风险输入"|label="模型评分"|label="模型上线"' "policy simulator avoids debugging-panel wording"
reject_pattern web/admin/src/main.tsx 'simulation\.side_effects|simulation\.notes|simulationMarkerLabel|no_ticket_consumed|no_challenge_session_created|no_rate_counter_incremented|no_audit_event_written' "policy simulator hides dry-run internals"
reject_pattern web/admin/src/main.tsx 'Select options=\{selectOptions\(\["always", "risk_based", "rate_limit", "observe", "silent", "manual_bypass"\]\)\}' "route policy form avoids exposing internal route modes as normal options"
reject_pattern web/admin/src/main.tsx 'title: "应用", dataIndex: "client_id"|label="CIDR"|title: "CIDR"' "admin tables avoid raw app and CIDR implementation fields"
reject_pattern web/admin/src/main.tsx 'label="AUC"|模型包地址|observe/enforce 模式|active 版本' "risk model admin avoids raw model implementation wording"
reject_pattern web/admin/src/main.tsx 'name: "track-baseline"|feature_version: "track-v1"|placeholder="track-v1"|placeholder="2026-06-v1"|placeholder="2026-06-01 至 2026-06-20"|placeholder="s3://models/track/2026-06-v1.json"' "risk model registration avoids demo defaults"
reject_pattern web/admin/src/main.tsx 'label="标签"|placeholder="default"|placeholder="car"' "resource upload avoids raw default tags and English category examples"
reject_pattern web/admin/src/main.tsx 'setFieldsValue\(\{[^}]*tag: "default"|initialValues=\{\{[^}]*tag: "default"' "resource upload avoids visible default material groups"
reject_pattern web/admin/src/main.tsx 'resourceDifficultyOptions|usesMaterialDifficulty|name="difficulty" label="素材难度"|formData\.set\("scene", values\.scene|formData\.set\("tag", values\.tag' "resource upload avoids advanced material fields in the primary flow"
reject_pattern web/admin/src/main.tsx 'path: "/api/login"|placeholder="login"' "admin forms avoid demo login placeholders"
reject_pattern web/admin/src/main.tsx 'label=\{compactText\(item.id, 28\)\}' "overview resource health avoids raw resource ids as primary labels"
reject_pattern web/admin/src/main.tsx 'item\.tag \? ` · \$\{item\.tag\}`' "overview resource health avoids raw backend resource groups"
reject_pattern web/admin/src/main.tsx '管理授权|访问令牌|已授权|未授权|重新授权' "admin token UI avoids complex authorization-system wording"
reject_pattern web/admin/src/main.tsx '<Tag key=\{item\}>\{item\}</Tag>|label=\{compactText\(item.name, 24\)\}|compactText\(row.decision_reason, 26\)' "admin avoids showing raw reason and dry-run markers"
reject_pattern web/admin/src/main.tsx 'placeholder="RISK_BASED"|name="decision_reason" label="原因"><Input' "audit reason filter avoids raw backend reason input"

if rg -n "欢迎使用|三步开始|平台能力介绍|hero|landing page|价值主张|能力清单|快速开始|接入教程|功能介绍|功能亮点|产品优势|为什么选择|使用说明|操作指南|快捷键|请先|你可以|强大|轻松|无需|开箱即用" web/admin/src web/runtime/src >/tmp/captcha-frontend-copy-check.txt; then
	cat /tmp/captcha-frontend-copy-check.txt >&2
	fail "frontend source contains marketing/onboarding copy forbidden by the page constraints"
else
	pass "frontend source avoids marketing/onboarding copy"
fi

exit "$failures"

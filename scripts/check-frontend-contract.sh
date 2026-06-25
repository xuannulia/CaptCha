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
require_dependency_allowlist web/admin/package.json "admin production dependencies stay on the chosen mature stack" "@ant-design/icons" "@tanstack/react-query" "antd" "react" "react-dom" "react-router-dom"
reject_pattern web/admin/package.json '"(@ant-design/pro-components|@ant-design/pro-layout|@umijs/|umi|next|nuxt|vue|element-plus|echarts|@ant-design/charts)"' "admin package avoids heavier alternate app frameworks and chart stacks"
reject_pattern web/admin/src/main.tsx '明细列表|系统资源|resource-uri|resource-table-wrap|system-resource-panel' "admin resource gallery avoids raw detail panels"
reject_pattern web/admin/src/style.css 'resource-uri|resource-table-wrap|system-resource-panel' "admin resource gallery styles avoid raw detail panels"
reject_pattern web/admin/src/main.tsx '训练特征|导出 JSONL' "admin risk training copy avoids implementation wording"
reject_pattern web/admin/src/main.tsx 'Client ID' "admin application copy avoids raw client-id wording"
reject_pattern web/admin/src/main.tsx 'Ticket TTL|Nonce|account hash|device hash|\bUA\b' "admin policy and audit copy avoids raw integration wording"

if rg -n "欢迎使用|三步开始|平台能力介绍|hero|landing page|价值主张|能力清单|快速开始|接入教程|功能介绍|功能亮点|产品优势|为什么选择|使用说明|操作指南|快捷键|请先|你可以|强大|轻松|无需|开箱即用" web/admin/src web/runtime/src >/tmp/captcha-frontend-copy-check.txt; then
	cat /tmp/captcha-frontend-copy-check.txt >&2
	fail "frontend source contains marketing/onboarding copy forbidden by the page constraints"
else
	pass "frontend source avoids marketing/onboarding copy"
fi

exit "$failures"

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

failures=0
warnings=0

fail() {
	echo "FAIL: $*" >&2
	failures=$((failures + 1))
}

warn() {
	echo "WARN: $*" >&2
	warnings=$((warnings + 1))
}

pass() {
	echo "PASS: $*"
}

if find . -maxdepth 1 -type f \( -iname 'LICENSE' -o -iname 'LICENSE.*' \) | grep -q .; then
	pass "project license file exists"
else
	fail "project license file is missing"
fi

if [[ -f SECURITY.md ]]; then
	pass "SECURITY.md exists"
	if grep -qi "Until a dedicated private reporting channel is configured" SECURITY.md; then
		fail "SECURITY.md still uses the placeholder private reporting channel"
	else
		pass "SECURITY.md has a non-placeholder reporting channel"
	fi
else
	fail "SECURITY.md is missing"
fi

for required in README.md CONTRIBUTING.md docs/release-checklist.md docs/implementation-audit.md Makefile scripts/verify.sh scripts/smoke.sh scripts/browser-smoke.sh scripts/clean.sh scripts/check-runtime-budget.sh scripts/check-go-version.sh scripts/check-ci-contract.sh scripts/check-frontend-contract.sh scripts/check-docker-contract.sh scripts/check-http-contract.sh scripts/check-grpc-contract.sh scripts/check-captcha-types-contract.sh scripts/check-browser-smoke-contract.sh scripts/check-doc-commands.sh; do
	if [[ -e "$required" ]]; then
		pass "$required exists"
	else
		fail "$required is missing"
	fi
done

if bash scripts/check-go-version.sh >/tmp/captcha-go-version-check.txt 2>&1; then
	cat /tmp/captcha-go-version-check.txt
	pass "Go toolchain versions are aligned"
else
	cat /tmp/captcha-go-version-check.txt >&2
	fail "Go toolchain versions are not aligned"
fi

if bash scripts/check-ci-contract.sh >/tmp/captcha-ci-contract-check.txt 2>&1; then
	cat /tmp/captcha-ci-contract-check.txt
	pass "CI contract is aligned"
else
	cat /tmp/captcha-ci-contract-check.txt >&2
	fail "CI contract is not aligned"
fi

if bash scripts/check-frontend-contract.sh >/tmp/captcha-frontend-contract-check.txt 2>&1; then
	cat /tmp/captcha-frontend-contract-check.txt
	pass "frontend framework contract is aligned"
else
	cat /tmp/captcha-frontend-contract-check.txt >&2
	fail "frontend framework contract is not aligned"
fi

if bash scripts/check-docker-contract.sh >/tmp/captcha-docker-contract-check.txt 2>&1; then
	cat /tmp/captcha-docker-contract-check.txt
	pass "Docker delivery contract is aligned"
else
	cat /tmp/captcha-docker-contract-check.txt >&2
	fail "Docker delivery contract is not aligned"
fi

if bash scripts/check-http-contract.sh >/tmp/captcha-http-contract-check.txt 2>&1; then
	cat /tmp/captcha-http-contract-check.txt
	pass "HTTP API contract is aligned"
else
	cat /tmp/captcha-http-contract-check.txt >&2
	fail "HTTP API contract is not aligned"
fi

if bash scripts/check-grpc-contract.sh >/tmp/captcha-grpc-contract-check.txt 2>&1; then
	cat /tmp/captcha-grpc-contract-check.txt
	pass "gRPC API contract is aligned"
else
	cat /tmp/captcha-grpc-contract-check.txt >&2
	fail "gRPC API contract is not aligned"
fi

if bash scripts/check-captcha-types-contract.sh >/tmp/captcha-types-contract-check.txt 2>&1; then
	cat /tmp/captcha-types-contract-check.txt
	pass "captcha type release contract is aligned"
else
	cat /tmp/captcha-types-contract-check.txt >&2
	fail "captcha type contract is not aligned"
fi

if bash scripts/check-browser-smoke-contract.sh >/tmp/captcha-browser-smoke-contract-check.txt 2>&1; then
	cat /tmp/captcha-browser-smoke-contract-check.txt
	pass "browser smoke route contract is aligned"
else
	cat /tmp/captcha-browser-smoke-contract-check.txt >&2
	fail "browser smoke route contract is not aligned"
fi

if bash scripts/check-doc-commands.sh >/tmp/captcha-doc-commands-contract-check.txt 2>&1; then
	cat /tmp/captcha-doc-commands-contract-check.txt
	pass "documentation command contract is aligned"
else
	cat /tmp/captcha-doc-commands-contract-check.txt >&2
	fail "documentation command contract is not aligned"
fi

if find web integrations \( -name '*.tsbuildinfo' -o -path '*/dist' \) -print | grep -q .; then
	fail "generated frontend or middleware build outputs are present; run make clean"
else
	pass "no generated frontend or middleware build outputs"
fi

if [[ -d .playwright-cli || -d output ]]; then
	fail "local Playwright/output artifacts are present; run make clean"
else
	pass "no local Playwright/output artifacts"
fi

if git remote get-url origin >/dev/null 2>&1; then
	pass "git origin remote is configured"
else
	warn "git origin remote is not configured"
fi

if docker info >/dev/null 2>&1; then
	pass "Docker daemon is reachable"
else
	fail "Docker daemon is not reachable; run make docker-build after Docker is available"
fi

if rg -n "BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE) KEY|AKIA[0-9A-Z]{16}|xox[baprs]-|ghp_[A-Za-z0-9_]{36,}|glpat-[A-Za-z0-9_-]{20,}" \
	--glob '!node_modules/**' \
	--glob '!package-lock.json' \
	. >/tmp/captcha-secret-scan.txt; then
	cat /tmp/captcha-secret-scan.txt >&2
	fail "potential secret material matched release audit patterns"
else
	pass "no obvious private keys or common access tokens matched"
fi

echo "release audit: $failures failure(s), $warnings warning(s)"
if [[ "$failures" -ne 0 ]]; then
	exit 1
fi

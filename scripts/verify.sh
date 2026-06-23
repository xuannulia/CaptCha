#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cleanup() {
	bash "$ROOT_DIR/scripts/clean.sh"
}

trap cleanup EXIT

cd "$ROOT_DIR"

bash -n scripts/verify.sh scripts/smoke.sh scripts/browser-smoke.sh scripts/clean.sh scripts/check-runtime-budget.sh scripts/check-go-version.sh scripts/check-ci-contract.sh scripts/check-frontend-contract.sh scripts/check-docker-contract.sh scripts/check-http-contract.sh scripts/check-grpc-contract.sh scripts/check-captcha-types-contract.sh scripts/check-browser-smoke-contract.sh scripts/check-doc-commands.sh
bash scripts/check-go-version.sh
bash scripts/check-ci-contract.sh
bash scripts/check-frontend-contract.sh
bash scripts/check-docker-contract.sh
bash scripts/check-http-contract.sh
bash scripts/check-grpc-contract.sh
bash scripts/check-captcha-types-contract.sh
bash scripts/check-browser-smoke-contract.sh
bash scripts/check-doc-commands.sh
go test ./...
make proto-check
make smoke
npm --workspaces --if-present run test
npm run build
bash scripts/check-runtime-budget.sh
docker compose config >/tmp/captcha-compose-config.txt
docker compose --profile gateway config >/tmp/captcha-compose-gateway-config.txt

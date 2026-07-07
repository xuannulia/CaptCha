#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

rm -rf \
	"$ROOT_DIR/web/runtime/dist" \
	"$ROOT_DIR/web/runtime/dist-captcha" \
	"$ROOT_DIR/web/runtime/dist-local-captcha" \
	"$ROOT_DIR/web/admin/dist" \
	"$ROOT_DIR/web/collector/dist" \
	"$ROOT_DIR/web/runtime/tsconfig.tsbuildinfo" \
	"$ROOT_DIR/web/admin/tsconfig.tsbuildinfo" \
	"$ROOT_DIR/web/collector/tsconfig.tsbuildinfo" \
	"$ROOT_DIR/integrations/express-middleware/dist" \
	"$ROOT_DIR/integrations/express-middleware/tsconfig.tsbuildinfo" \
	"$ROOT_DIR/scripts/__pycache__" \
	"$ROOT_DIR/.playwright-cli" \
	"$ROOT_DIR/output"

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

for dockerfile in deploy/docker/Dockerfile.server deploy/docker/Dockerfile.gateway; do
	require_pattern "$dockerfile" '^FROM golang:\$\{GO_VERSION\}-bookworm AS build$' "$dockerfile uses the pinned Go build stage"
	require_pattern "$dockerfile" '^FROM alpine:' "$dockerfile uses a lightweight runtime stage"
	require_pattern "$dockerfile" 'CGO_ENABLED=0' "$dockerfile builds a static Go binary"
	require_pattern "$dockerfile" 'go build -trimpath -ldflags="-s -w"' "$dockerfile strips build paths and symbols"
	require_pattern "$dockerfile" 'adduser -S -G captcha captcha' "$dockerfile creates a non-root captcha user"
	require_pattern "$dockerfile" '^USER captcha$' "$dockerfile runs as non-root"
	require_pattern "$dockerfile" 'apk add --no-cache ca-certificates' "$dockerfile includes CA certificates"
done

require_pattern deploy/docker/Dockerfile.server '^COPY migrations \./migrations$' "server image includes migrations"
require_pattern deploy/docker/Dockerfile.server '^COPY configs \./configs$' "server image includes configs"
require_pattern deploy/docker/Dockerfile.server '^EXPOSE 8080 9090$' "server image exposes HTTP and gRPC ports"
require_pattern deploy/docker/Dockerfile.server '^ENTRYPOINT \["captcha-server"\]$' "server image entrypoint is captcha-server"
require_pattern deploy/docker/Dockerfile.gateway '^EXPOSE 8081$' "gateway image exposes gateway port"
require_pattern deploy/docker/Dockerfile.gateway '^ENTRYPOINT \["captcha-gateway"\]$' "gateway image entrypoint is captcha-gateway"

require_pattern docker-compose.yml '^  postgres:$' "compose includes PostgreSQL"
require_pattern docker-compose.yml '^  redis:$' "compose includes Redis"
require_pattern docker-compose.yml '^  captcha-server:$' "compose includes platform server"
require_pattern docker-compose.yml '^  captcha-gateway:$' "compose includes optional gateway service"
require_pattern docker-compose.yml 'profiles:[[:space:]]*$' "compose defines service profiles"
require_pattern docker-compose.yml '^[[:space:]]+- gateway$' "gateway is guarded by the gateway profile"
require_pattern docker-compose.yml 'CAPTCHA_POSTGRES_DSN:' "compose wires PostgreSQL into the server"
require_pattern docker-compose.yml 'CAPTCHA_REDIS_ADDR:' "compose wires Redis into the server"
require_pattern docker-compose.yml 'CAPTCHA_PLATFORM_GRPC_ADDR:' "compose wires gateway to platform gRPC"
require_pattern docker-compose.yml 'condition: service_healthy' "compose waits for healthy dependencies"

require_pattern docker-compose.dev.yml '^  postgres:$' "dev compose includes PostgreSQL"
require_pattern docker-compose.dev.yml '^  redis:$' "dev compose includes Redis"
reject_pattern docker-compose.dev.yml '^  captcha-server:$|^  captcha-gateway:$' "dev compose stays infrastructure-only"

exit "$failures"

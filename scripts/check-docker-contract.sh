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
	require_pattern "$dockerfile" '^ARG GOPROXY=https://proxy.golang.org,direct$' "$dockerfile exposes a configurable Go module proxy"
	require_pattern "$dockerfile" '^ARG GOSUMDB=sum.golang.org$' "$dockerfile exposes a configurable Go checksum database"
	require_pattern "$dockerfile" '^FROM scratch$' "$dockerfile uses a minimal scratch runtime stage"
	require_pattern "$dockerfile" 'CGO_ENABLED=0' "$dockerfile builds a static Go binary"
	require_pattern "$dockerfile" 'go build -trimpath -ldflags="-s -w"' "$dockerfile strips build paths and symbols"
	require_pattern "$dockerfile" "captcha:x:10001:10001" "$dockerfile defines a non-root captcha user"
	require_pattern "$dockerfile" '^COPY --from=build /out/etc/passwd /etc/passwd$' "$dockerfile includes passwd data for the non-root user"
	require_pattern "$dockerfile" '^USER captcha$' "$dockerfile runs as non-root"
	require_pattern "$dockerfile" '^COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt$' "$dockerfile includes CA certificates"
done

require_pattern Makefile '^DOCKER_GOPROXY \?= https://goproxy.cn,direct$' "docker build target has a local-network friendly Go proxy default"
require_pattern Makefile '^DOCKER_GOSUMDB \?= sum.golang.google.cn$' "docker build target has a local-network friendly checksum database default"
require_pattern Makefile 'docker build --build-arg GOPROXY="\$\(DOCKER_GOPROXY\)" --build-arg GOSUMDB="\$\(DOCKER_GOSUMDB\)"' "docker build target passes Go module network settings"

require_pattern deploy/docker/Dockerfile.server '^COPY migrations \./migrations$' "server image includes migrations"
require_pattern deploy/docker/Dockerfile.server '^COPY configs \./configs$' "server image includes configs"
require_pattern deploy/docker/Dockerfile.server '^COPY resources \./resources$' "server image includes captcha resources"
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
require_pattern docker-compose.yml '\["CMD", "captcha-server", "healthcheck", "http://127\.0\.0\.1:8080/healthz"\]' "server healthcheck uses the scratch image binary"
require_pattern docker-compose.yml '\["CMD", "captcha-gateway", "healthcheck", "http://127\.0\.0\.1:8081/healthz"\]' "gateway healthcheck uses the scratch image binary"
reject_pattern docker-compose.yml 'wget|curl' "compose healthchecks do not depend on tools missing from scratch images"
require_pattern docker-compose.yml 'CAPTCHA_GATEWAY_FAIL_POLICY:' "compose exposes gateway fail policy"
require_pattern docker-compose.yml 'CAPTCHA_GATEWAY_TIMEOUT:' "compose exposes gateway timeout"
require_pattern docker-compose.yml 'CAPTCHA_GATEWAY_CIRCUIT_BREAKER_FAILURES:' "compose exposes gateway circuit breaker threshold"
require_pattern docker-compose.yml 'CAPTCHA_GATEWAY_CIRCUIT_BREAKER_COOLDOWN:' "compose exposes gateway circuit breaker cooldown"
require_pattern docker-compose.yml 'condition: service_healthy' "compose waits for healthy dependencies"

require_pattern docker-compose.dev.yml '^  postgres:$' "dev compose includes PostgreSQL"
require_pattern docker-compose.dev.yml '^  redis:$' "dev compose includes Redis"
reject_pattern docker-compose.dev.yml '^  captcha-server:$|^  captcha-gateway:$' "dev compose stays infrastructure-only"

exit "$failures"

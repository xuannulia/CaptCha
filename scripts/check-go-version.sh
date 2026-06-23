#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

go_version="$(awk '$1 == "go" { print $2; exit }' go.mod)"
if [[ -z "$go_version" ]]; then
	echo "go version check: go.mod does not declare a Go version" >&2
	exit 1
fi

failures=0
for dockerfile in deploy/docker/Dockerfile.server deploy/docker/Dockerfile.gateway; do
	docker_go_version="$(awk -F= '$1 == "ARG GO_VERSION" { print $2; exit }' "$dockerfile")"
	if [[ -z "$docker_go_version" ]]; then
		echo "FAIL: $dockerfile does not declare ARG GO_VERSION" >&2
		failures=$((failures + 1))
		continue
	fi
	if [[ "$docker_go_version" != "$go_version" ]]; then
		echo "FAIL: $dockerfile uses Go $docker_go_version, but go.mod declares Go $go_version" >&2
		failures=$((failures + 1))
	else
		echo "PASS: $dockerfile Go version matches go.mod ($go_version)"
	fi
done

exit "$failures"

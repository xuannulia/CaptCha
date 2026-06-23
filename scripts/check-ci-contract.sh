#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

workflow=".github/workflows/ci.yml"
failures=0

require_pattern() {
	local pattern=$1
	local label=$2
	if grep -Eq "$pattern" "$workflow"; then
		echo "PASS: $label"
	else
		echo "FAIL: $label" >&2
		failures=$((failures + 1))
	fi
}

if [[ ! -f "$workflow" ]]; then
	echo "FAIL: $workflow is missing" >&2
	exit 1
fi

require_pattern 'go-version-file:[[:space:]]*go\.mod' "CI reads Go version from go.mod"
require_pattern 'apt-get install -y protobuf-compiler' "CI installs protobuf compiler"
require_pattern 'protoc-gen-go@' "CI installs protoc-gen-go"
require_pattern 'protoc-gen-go-grpc@' "CI installs protoc-gen-go-grpc"
require_pattern 'node-version:[[:space:]]*22' "CI uses Node.js 22"
require_pattern 'run:[[:space:]]*npm ci' "CI installs workspace dependencies with npm ci"
require_pattern 'run:[[:space:]]*make verify' "CI runs make verify"
require_pattern 'needs:[[:space:]]*test' "Docker image job waits for test job"
require_pattern 'run:[[:space:]]*make docker-build' "CI runs make docker-build"

exit "$failures"

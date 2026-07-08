#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

docs_file="$(mktemp)"
proto_file="$(mktemp)"
trap 'rm -f "$docs_file" "$proto_file"' EXIT

extract_rpc_signatures() {
	awk '
		/^service [A-Za-z0-9_]+[[:space:]]*\{/ {
			service = $2
			gsub(/\{/, "", service)
		}
		/^[[:space:]]*rpc [A-Za-z0-9_]+/ && service != "" {
			line = $0
			gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
			gsub(/[[:space:]]+/, " ", line)
			print service " " line
		}
		/^\}/ && service != "" {
			service = ""
		}
	' "$1" | sort -u
}

extract_rpc_signatures docs/zh/architecture-design.md >"$docs_file"
extract_rpc_signatures proto/captcha/v1/captcha.proto >"$proto_file"

missing_proto="$(comm -23 "$docs_file" "$proto_file" || true)"
if [[ -n "$missing_proto" ]]; then
	echo "gRPC methods documented but not present in proto/captcha/v1/captcha.proto:" >&2
	echo "$missing_proto" >&2
	exit 1
fi

missing_docs="$(comm -13 "$docs_file" "$proto_file" || true)"
if [[ -n "$missing_docs" ]]; then
	echo "gRPC methods present in proto but not documented in docs/zh/architecture-design.md:" >&2
	echo "$missing_docs" >&2
	exit 1
fi

echo "PASS: documented gRPC methods match proto contract"

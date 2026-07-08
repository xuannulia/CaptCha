#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

docs_file="$(mktemp)"
server_file="$(mktemp)"
trap 'rm -f "$docs_file" "$server_file"' EXIT

normalize_path() {
	sed -E 's/\{[A-Za-z0-9_]+\}/\{\}/g'
}

awk '/^(GET|POST|PUT|PATCH|DELETE) \// { print $1 " " $2 }' docs/zh/architecture-design.md \
	| normalize_path \
	| sort -u >"$docs_file"

awk -F'"' '
	/mux\.HandleFunc\("/ {
		split($2, route, " ")
		if (route[1] ~ /^(GET|POST|PUT|PATCH|DELETE)$/) {
			print route[1] " " route[2]
		}
	}
' internal/api/server.go \
	| normalize_path \
	| sort -u >"$server_file"

missing_impl="$(comm -23 "$docs_file" "$server_file" || true)"
if [[ -n "$missing_impl" ]]; then
	echo "HTTP endpoints documented but not implemented:" >&2
	echo "$missing_impl" >&2
	exit 1
fi

missing_docs="$(comm -13 "$docs_file" "$server_file" || true)"
if [[ -n "$missing_docs" ]]; then
	echo "HTTP endpoints implemented but not documented in docs/zh/architecture-design.md:" >&2
	echo "$missing_docs" >&2
	exit 1
fi

echo "PASS: documented HTTP endpoints match server routes"

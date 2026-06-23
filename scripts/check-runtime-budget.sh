#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/web/runtime/dist/assets"
JS_BUDGET="${CAPTCHA_RUNTIME_JS_GZIP_BUDGET_BYTES:-30720}"
CSS_BUDGET="${CAPTCHA_RUNTIME_CSS_GZIP_BUDGET_BYTES:-10240}"

if [[ ! -d "$DIST_DIR" ]]; then
	echo "runtime budget check: missing $DIST_DIR; run npm run build first" >&2
	exit 1
fi

gzip_size() {
	gzip -c "$1" | wc -c | tr -d '[:space:]'
}

js_total=0
css_total=0
js_count=0

while IFS= read -r -d '' file; do
	size="$(gzip_size "$file")"
	js_total=$((js_total + size))
	js_count=$((js_count + 1))
done < <(find "$DIST_DIR" -type f -name '*.js' -print0)

while IFS= read -r -d '' file; do
	size="$(gzip_size "$file")"
	css_total=$((css_total + size))
done < <(find "$DIST_DIR" -type f -name '*.css' -print0)

if [[ "$js_count" -eq 0 ]]; then
	echo "runtime budget check: no JS assets found in $DIST_DIR" >&2
	exit 1
fi

echo "runtime budget: js gzip ${js_total}/${JS_BUDGET} bytes, css gzip ${css_total}/${CSS_BUDGET} bytes"

failures=0
if [[ "$js_total" -gt "$JS_BUDGET" ]]; then
	echo "FAIL: runtime JS gzip budget exceeded" >&2
	failures=$((failures + 1))
fi

if [[ "$css_total" -gt "$CSS_BUDGET" ]]; then
	echo "FAIL: runtime CSS gzip budget exceeded" >&2
	failures=$((failures + 1))
fi

exit "$failures"

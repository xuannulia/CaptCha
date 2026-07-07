#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
PIDS=()

SERVER_HTTP_ADDR="${CAPTCHA_SMOKE_SERVER_HTTP_ADDR:-127.0.0.1:18080}"
SERVER_GRPC_ADDR="${CAPTCHA_SMOKE_SERVER_GRPC_ADDR:-127.0.0.1:19090}"
UPSTREAM_HOST="${CAPTCHA_SMOKE_UPSTREAM_HOST:-127.0.0.1}"
UPSTREAM_PORT="${CAPTCHA_SMOKE_UPSTREAM_PORT:-13000}"
GATEWAY_HTTP_PORT="${CAPTCHA_SMOKE_GATEWAY_HTTP_PORT:-18081}"
GATEWAY_GRPC_PORT="${CAPTCHA_SMOKE_GATEWAY_GRPC_PORT:-18082}"

cleanup() {
	local status=$?
	for pid in "${PIDS[@]:-}"; do
		kill "$pid" 2>/dev/null || true
	done
	for pid in "${PIDS[@]:-}"; do
		wait "$pid" 2>/dev/null || true
	done
	if [[ "$status" -ne 0 ]]; then
		echo "smoke test failed; logs are in $TMP_DIR" >&2
		for log in "$TMP_DIR"/*.log; do
			[[ -e "$log" ]] || continue
			echo "--- $log ---" >&2
			tail -n 200 "$log" >&2 || true
		done
	else
		rm -rf "$TMP_DIR"
	fi
}
trap cleanup EXIT

cd "$ROOT_DIR"

if env CAPTCHA_ENV=production go run ./cmd/captcha-server >"$TMP_DIR/production-gate.log" 2>&1; then
	echo "expected production startup without required controls to fail" >&2
	exit 1
fi
if ! grep -q "production security check failed" "$TMP_DIR/production-gate.log"; then
	echo "expected production startup to fail at the security gate" >&2
	cat "$TMP_DIR/production-gate.log" >&2
	exit 1
fi
if ! grep -q "CAPTCHA_ADMIN_TOKEN must be set in production" "$TMP_DIR/production-gate.log"; then
	echo "expected production gate to report missing admin token" >&2
	cat "$TMP_DIR/production-gate.log" >&2
	exit 1
fi

wait_http() {
	local url=$1
	for _ in {1..120}; do
		if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.25
	done
	echo "timed out waiting for $url" >&2
	return 1
}

start_bg() {
	local name=$1
	shift
	"$@" >"$TMP_DIR/$name.log" 2>&1 &
	PIDS+=("$!")
}

start_bg captcha-server env \
	CAPTCHA_ENV=development \
	CAPTCHA_PRODUCTION=false \
	CAPTCHA_ADDR="$SERVER_HTTP_ADDR" \
	CAPTCHA_GRPC_ADDR="$SERVER_GRPC_ADDR" \
	CAPTCHA_RUNTIME_URL=http://localhost:5173 \
	go run ./cmd/captcha-server
wait_http "http://$SERVER_HTTP_ADDR/healthz"

python3 - "$SERVER_HTTP_ADDR" <<'PY'
import json
import sys
import urllib.error
import urllib.request

base = "http://" + sys.argv[1]

def request(method, path, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        base + path,
        data=data,
        method=method,
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode()
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        return exc.code, json.loads(body) if body else {}

status, apps = request("GET", "/api/v1/admin/applications")
assert status == 200, (status, apps)
assert any(app.get("client_id") == "demo" and app.get("status") == "active" for app in apps.get("items", [])), apps

status, decision = request("POST", "/api/v1/policy/evaluate", {
    "client_id": "demo",
    "path": "/api/register",
    "method": "POST",
    "ip": "198.51.100.9",
    "user_agent": "smoke-test",
    "request_nonce": "nonce-smoke",
})
assert status == 200, (status, decision)
assert decision.get("action") == "challenge", decision
assert decision.get("session_id"), decision

session_id = decision["session_id"]
status, session = request("GET", f"/api/v1/challenge/sessions/{session_id}")
assert status == 200, (status, session)
forbidden = ["answer", "target", "tolerance", "verify_rule", "score_rule", "score_threshold", "answer_seed", "initial_angle", "secret", "token"]

def leaked_key_paths(value, path="$"):
    leaks = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key).lower()
            child_path = f"{path}.{key}"
            if any(word in key_text for word in forbidden):
                leaks.append(child_path)
            leaks.extend(leaked_key_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            leaks.extend(leaked_key_paths(child, f"{path}[{index}]"))
    return leaks

leaks = leaked_key_paths(session)
assert not leaks, leaks

status, body = request("POST", f"/api/v1/challenge/sessions/{session_id}/verify", {
    "answer": {"target": 1},
    "runtime_meta": {"request_nonce": "nonce-smoke"},
    "route": "/api/register",
})
assert status == 400 and body.get("error") == "FORBIDDEN_VERIFY_FIELD", (status, body)

status, body = request("POST", f"/api/v1/challenge/sessions/{session_id}/verify", {
    "answer": {},
    "runtime_meta": {"request_nonce": "nonce-smoke", "track_score": 100},
    "route": "/api/register",
})
assert status == 400 and body.get("error") == "FORBIDDEN_VERIFY_FIELD", (status, body)

status, body = request("POST", f"/api/v1/challenge/sessions/{session_id}/verify", {
    "answer": {},
    "runtime_meta": {"request_nonce": "wrong"},
    "route": "/api/register",
})
assert status == 200 and body.get("reason_code") == "REQUEST_NONCE_MISMATCH", (status, body)
for leaked_key in ["track_bucket", "track_score", "answer_score", "risk_score", "score_threshold", "threshold", "tolerance", "target"]:
    assert leaked_key not in body, (leaked_key, body)

status, body = request("POST", "/api/v1/challenge/sessions", {
    "client_id": "missing",
    "scene": "login",
    "captcha_type": "SLIDER",
})
assert status == 404 and body.get("error") == "APPLICATION_NOT_FOUND", (status, body)
PY

python3 - "$UPSTREAM_HOST" "$UPSTREAM_PORT" >"$TMP_DIR/upstream.log" 2>&1 <<'PY' &
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"upstream-ok")

    def do_POST(self):
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"upstream-post-ok")

    def log_message(self, *args):
        pass

HTTPServer((sys.argv[1], int(sys.argv[2])), Handler).serve_forever()
PY
PIDS+=("$!")
wait_http "http://$UPSTREAM_HOST:$UPSTREAM_PORT/hello"

assert_gateway() {
	local name=$1
	local port=$2
	local transport=$3
	local config_cache=$4

	start_bg "$name" env \
		CAPTCHA_GATEWAY_ADDR="127.0.0.1:$port" \
		CAPTCHA_UPSTREAM_URL="http://$UPSTREAM_HOST:$UPSTREAM_PORT" \
		CAPTCHA_PLATFORM_URL="http://$SERVER_HTTP_ADDR" \
		CAPTCHA_PLATFORM_GRPC_ADDR="$SERVER_GRPC_ADDR" \
		CAPTCHA_GATEWAY_POLICY_TRANSPORT="$transport" \
		CAPTCHA_GATEWAY_CONFIG_CACHE="$config_cache" \
		go run ./cmd/captcha-gateway

	wait_http "http://127.0.0.1:$port/hello"
	local body
	body="$(curl -fsS "http://127.0.0.1:$port/hello")"
	[[ "$body" == "upstream-ok" ]] || {
		echo "unexpected gateway upstream body for $name: $body" >&2
		return 1
	}

	local response_file="$TMP_DIR/$name-register.json"
	local status
	status="$(curl -sS -o "$response_file" -w "%{http_code}" -X POST \
		-H "user-agent: $name-smoke" \
		"http://127.0.0.1:$port/api/register")"
	[[ "$status" == "403" ]] || {
		echo "unexpected gateway challenge status for $name: $status" >&2
		cat "$response_file" >&2
		return 1
	}
	python3 - "$response_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    body = json.load(fh)
assert body.get("action") == "challenge", body
assert body.get("session_id"), body
assert body.get("challenge_url"), body
PY
}

assert_gateway gateway-http "$GATEWAY_HTTP_PORT" http false
assert_gateway gateway-grpc "$GATEWAY_GRPC_PORT" grpc true

echo "smoke test passed"

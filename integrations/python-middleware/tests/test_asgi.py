import asyncio
import hashlib
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from captcha_middleware import CaptchaASGIMiddleware, CaptchaOptions


class CaptchaASGIMiddlewareTest(unittest.IsolatedAsyncioTestCase):
    async def test_allows_request_when_platform_allows(self):
        platform = FakePlatform()
        platform.policy_response = {
            "action": "allow",
            "reason": "CLEARANCE_VALID",
            "clearance_token": "clearance_py",
            "clearance_ttl_seconds": 600,
        }
        with platform.run() as url:
            app = CaptchaASGIMiddleware(
                ok_app(204),
                CaptchaOptions(
                    platform_url=url,
                    header_allowlist=["x-trace-id"],
                    clearance_cookie_secure=True,
                ),
            )
            messages = await call_asgi(
                app,
                "/api/login",
                {
                    "x-captcha-resource-tag": "campaign",
                    "x-captcha-account-id-hash": "acct_hash_py",
                    "x-captcha-device-id-hash": "device_hash_py",
                    "x-captcha-risk-score": "77",
                    "x-captcha-risk-level": "high",
                    "x-captcha-model-score": "88",
                    "x-captcha-model-mode": "observe",
                    "x-trace-id": "trace-py",
                    "authorization": "Bearer should-not-forward",
                },
            )

        self.assertEqual(messages[0]["status"], 204)
        response_headers = headers_from_messages(messages)
        self.assertEqual(response_headers["x-captcha-clearance"], "clearance_py")
        self.assertIn("captcha_clearance=clearance_py", response_headers["set-cookie"])
        self.assertIn("HttpOnly", response_headers["set-cookie"])
        self.assertIn("Secure", response_headers["set-cookie"])
        self.assertEqual(len(platform.policy_requests), 1)
        evaluated = platform.policy_requests[0]
        self.assertEqual(evaluated["scene"], "api")
        self.assertEqual(evaluated["resource_tag"], "campaign")
        self.assertEqual(evaluated["account_id_hash"], "acct_hash_py")
        self.assertEqual(evaluated["device_id_hash"], "device_hash_py")
        self.assertEqual(evaluated["risk_score"], 77)
        self.assertEqual(evaluated["risk_level"], "high")
        self.assertEqual(evaluated["model_score"], 88)
        self.assertEqual(evaluated["model_mode"], "observe")
        self.assertEqual(evaluated["headers"]["x-trace-id"], "trace-py")
        self.assertNotIn("authorization", evaluated.get("headers", {}))

    async def test_consumes_ticket_before_policy_evaluation(self):
        platform = FakePlatform()
        platform.ticket_response = {
            "valid": True,
            "client_id": "demo",
            "scene": "login",
            "route": "/login",
            "clearance_token": "clearance_ticket_py",
            "clearance_ttl_seconds": 300,
        }
        with platform.run() as url:
            app = CaptchaASGIMiddleware(
                ok_app(202),
                CaptchaOptions(platform_url=url, resolve_scene=lambda scope: "login"),
            )
            messages = await call_asgi(
                app,
                "/login",
                {
                    "x-captcha-ticket": "ticket_ok",
                    "x-captcha-request-nonce": "nonce-py",
                    "x-captcha-account-id-hash": "acct_ticket_py",
                    "x-captcha-device-id-hash": "device_ticket_py",
                },
            )
            await wait_for(lambda: len(platform.event_requests) == 1)

        self.assertEqual(messages[0]["status"], 202)
        response_headers = headers_from_messages(messages)
        self.assertEqual(response_headers["x-captcha-clearance"], "clearance_ticket_py")
        self.assertEqual(len(platform.ticket_requests), 1)
        consumed = platform.ticket_requests[0]
        self.assertTrue(consumed["consume"])
        self.assertEqual(consumed["ticket"], "ticket_ok")
        self.assertEqual(consumed["scene"], "login")
        self.assertEqual(consumed["route"], "/login")
        self.assertEqual(consumed["request_nonce"], "nonce-py")
        self.assertEqual(consumed["ip_hash"], bind_hash("198.51.100.9"))
        self.assertEqual(consumed["user_agent_hash"], bind_hash("python-test"))
        self.assertEqual(len(platform.policy_requests), 0)
        event = platform.event_requests[0]["events"][0]
        self.assertEqual(event["action"], "allow")
        self.assertEqual(event["decision_reason"], "TICKET_CONSUMED")
        self.assertEqual(event["scene"], "login")

    async def test_returns_challenge_details(self):
        platform = FakePlatform()
        platform.policy_response = {
            "action": "challenge",
            "reason": "ALWAYS",
            "challenge_url": "/challenge?session_id=cap_sess_test",
            "session_id": "cap_sess_test",
            "scene": "login",
            "challenge_type": "SLIDER",
            "ttl_seconds": 120,
        }
        with platform.run() as url:
            app = CaptchaASGIMiddleware(ok_app(204), CaptchaOptions(platform_url=url))
            messages = await call_asgi(app, "/login", {})

        self.assertEqual(messages[0]["status"], 403)
        body = json.loads(messages[1]["body"])
        self.assertEqual(body["challenge_url"], url + "/challenge?session_id=cap_sess_test")
        self.assertEqual(body["challenge_type"], "SLIDER")

    async def test_blocks_unsupported_policy_decision(self):
        platform = FakePlatform()
        platform.policy_response = {"action": "retry", "reason": "VERIFY_RETRY"}
        with platform.run() as url:
            app = CaptchaASGIMiddleware(ok_app(204), CaptchaOptions(platform_url=url))
            messages = await call_asgi(app, "/login", {})

        self.assertEqual(messages[0]["status"], 403)
        body = json.loads(messages[1]["body"])
        self.assertEqual(body["action"], "block")
        self.assertEqual(body["reason"], "UNSUPPORTED_POLICY_DECISION")

    async def test_blocks_invalid_ticket_without_policy_fallback(self):
        platform = FakePlatform()
        platform.ticket_response = {"valid": False, "reason": "CONSUMED"}
        with platform.run() as url:
            app = CaptchaASGIMiddleware(ok_app(204), CaptchaOptions(platform_url=url, resolve_scene=lambda scope: "login"))
            messages = await call_asgi(app, "/login", {"x-captcha-ticket": "ticket_consumed"})
            await wait_for(lambda: len(platform.event_requests) == 1)

        self.assertEqual(messages[0]["status"], 403)
        body = json.loads(messages[1]["body"])
        self.assertEqual(body["action"], "block")
        self.assertEqual(body["reason"], "CONSUMED")
        self.assertEqual(len(platform.policy_requests), 0)
        self.assertEqual(platform.event_requests[0]["events"][0]["decision_reason"], "CONSUMED")

    async def test_trusted_proxy_controls_forwarded_for(self):
        platform = FakePlatform()
        with platform.run() as url:
            app = CaptchaASGIMiddleware(
                ok_app(204),
                CaptchaOptions(platform_url=url, trusted_proxy_cidrs=["198.51.100.0/24"]),
            )
            await call_asgi(app, "/login", {"x-forwarded-for": "203.0.113.7, 198.51.100.9"})

        self.assertEqual(platform.policy_requests[0]["ip"], "203.0.113.7")

    async def test_ignores_forged_forwarded_for_from_untrusted_peer(self):
        platform = FakePlatform()
        with platform.run() as url:
            app = CaptchaASGIMiddleware(
                ok_app(204),
                CaptchaOptions(platform_url=url, trusted_proxy_cidrs=["203.0.113.0/24"]),
            )
            await call_asgi(app, "/login", {"x-forwarded-for": "10.0.0.1"})

        self.assertEqual(platform.policy_requests[0]["ip"], "198.51.100.9")

    async def test_fail_close_reports_policy_unavailable(self):
        platform = FakePlatform()
        platform.policy_status = 503
        with platform.run() as url:
            app = CaptchaASGIMiddleware(ok_app(204), CaptchaOptions(platform_url=url, fail_policy="fail_close"))
            messages = await call_asgi(app, "/login", {})
            await wait_for(lambda: len(platform.event_requests) == 1)

        self.assertEqual(messages[0]["status"], 503)
        body = json.loads(messages[1]["body"])
        self.assertEqual(body["reason"], "POLICY_UNAVAILABLE")
        event = platform.event_requests[0]["events"][0]
        self.assertEqual(event["action"], "block")
        self.assertEqual(event["decision_reason"], "POLICY_UNAVAILABLE")

    async def test_circuit_breaker_skips_platform_call_during_cooldown(self):
        platform = FakePlatform()
        platform.policy_status = 503
        with platform.run() as url:
            app = CaptchaASGIMiddleware(
                ok_app(204),
                CaptchaOptions(
                    platform_url=url,
                    circuit_breaker_failure_threshold=1,
                    circuit_breaker_cooldown_seconds=60,
                ),
            )
            for _ in range(2):
                messages = await call_asgi(app, "/login", {})
                self.assertEqual(messages[0]["status"], 204)
            await wait_for(lambda: len(platform.event_requests) == 2)

        self.assertEqual(len(platform.policy_requests), 1)
        self.assertEqual(platform.event_requests[0]["events"][0]["decision_reason"], "POLICY_UNAVAILABLE")
        self.assertEqual(platform.event_requests[1]["events"][0]["decision_reason"], "POLICY_UNAVAILABLE")


def ok_app(status):
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": status, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    return app


async def call_asgi(app, path, headers):
    messages = []
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "client": ("198.51.100.9", 12345),
        "headers": [(b"user-agent", b"python-test")]
        + [(key.lower().encode("latin-1"), value.encode("latin-1")) for key, value in headers.items()],
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await app(scope, receive, send)
    return messages


def headers_from_messages(messages):
    out = {}
    for name, value in messages[0].get("headers", []):
        out[name.decode("latin-1")] = value.decode("latin-1")
    return out


async def wait_for(predicate):
    for _ in range(200):
        if predicate():
            return
        await asyncio.sleep(0.005)
    raise AssertionError("timed out waiting for condition")


def bind_hash(value):
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:32]


class FakePlatform:
    def __init__(self):
        self.policy_response = {"action": "allow", "reason": "OK"}
        self.ticket_response = {"valid": True}
        self.policy_status = 200
        self.ticket_status = 200
        self.policy_requests = []
        self.ticket_requests = []
        self.event_requests = []

    def run(self):
        return RunningFakePlatform(self)


class RunningFakePlatform:
    def __init__(self, platform):
        self.platform = platform
        self.server = None
        self.thread = None

    def __enter__(self):
        platform = self.platform

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("content-length", "0"))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                if self.path == "/api/v1/policy/evaluate":
                    platform.policy_requests.append(body)
                    self.send_json(platform.policy_status, platform.policy_response)
                    return
                if self.path == "/api/v1/tickets/verify":
                    platform.ticket_requests.append(body)
                    self.send_json(platform.ticket_status, platform.ticket_response)
                    return
                if self.path == "/api/v1/events/report":
                    platform.event_requests.append(body)
                    self.send_json(200, {"accepted": len(body.get("events", []))})
                    return
                self.send_json(404, {"error": "not found"})

            def send_json(self, status, body):
                payload = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, _format, *_args):
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def __exit__(self, exc_type, exc, tb):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()


if __name__ == "__main__":
    unittest.main()

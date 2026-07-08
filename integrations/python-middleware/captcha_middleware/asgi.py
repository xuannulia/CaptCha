from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http import cookies
from typing import Any, Awaitable, Callable

ASGIApp = Callable[[dict[str, Any], Callable[[], Awaitable[dict[str, Any]]], Callable[[dict[str, Any]], Awaitable[None]]], Awaitable[None]]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


@dataclass
class CaptchaOptions:
    platform_url: str
    client_id: str = "demo"
    client_secret: str = ""
    ticket_header: str = "x-captcha-ticket"
    clearance_header: str = "x-captcha-clearance"
    clearance_cookie_name: str = "captcha_clearance"
    clearance_cookie_secure: bool = False
    request_nonce_header: str = "x-captcha-request-nonce"
    resource_tag_header: str = "x-captcha-resource-tag"
    account_id_hash_header: str = "x-captcha-account-id-hash"
    device_id_hash_header: str = "x-captcha-device-id-hash"
    risk_score_header: str = "x-captcha-risk-score"
    risk_level_header: str = "x-captcha-risk-level"
    model_score_header: str = "x-captcha-model-score"
    model_mode_header: str = "x-captcha-model-mode"
    scene_header: str = "x-captcha-scene"
    fail_policy: str = "fail_open"
    timeout_seconds: float = 1.5
    circuit_breaker_failure_threshold: int = 0
    circuit_breaker_cooldown_seconds: float = 0
    trusted_proxy_cidrs: list[str] = field(default_factory=list)
    header_allowlist: list[str] = field(default_factory=list)
    should_protect: Callable[[dict[str, Any]], bool] | None = None
    resolve_scene: Callable[[dict[str, Any]], str] | None = None
    resolve_account_id_hash: Callable[[dict[str, Any]], str] | None = None
    resolve_device_id_hash: Callable[[dict[str, Any]], str] | None = None


class CaptchaASGIMiddleware:
    def __init__(self, app: ASGIApp, options: CaptchaOptions):
        if not options.platform_url:
            raise ValueError("platform_url is required")
        self.app = app
        self.options = options
        self.platform_url = options.platform_url.rstrip("/")
        self.trusted_proxies = [ipaddress.ip_network(value, strict=False) for value in options.trusted_proxy_cidrs if value.strip()]
        self.policy_breaker = _CircuitBreaker(options.circuit_breaker_failure_threshold, options.circuit_breaker_cooldown_seconds)
        self.ticket_breaker = _CircuitBreaker(options.circuit_breaker_failure_threshold, options.circuit_breaker_cooldown_seconds)
        self.client = _HTTPPlatformClient(self.platform_url, options.client_secret, options.timeout_seconds)

    async def __call__(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        if self.options.should_protect and not self.options.should_protect(scope):
            await self.app(scope, receive, send)
            return

        evaluate_request = self._build_evaluate_request(scope)
        if evaluate_request.get("ticket"):
            await self._handle_ticket(scope, receive, send, evaluate_request)
            return
        await self._handle_policy(scope, receive, send, evaluate_request)

    async def _handle_ticket(self, scope: dict[str, Any], receive: Receive, send: Send, evaluate_request: dict[str, Any]) -> None:
        if not self.ticket_breaker.allow():
            await self._handle_unavailable(scope, receive, send, evaluate_request, "TICKET_SERVICE_UNAVAILABLE")
            return
        try:
            ticket = await self.client.consume(
                {
                    "ticket": evaluate_request["ticket"],
                    "client_id": evaluate_request["client_id"],
                    "scene": evaluate_request["scene"],
                    "route": evaluate_request["path"],
                    "request_nonce": evaluate_request.get("request_nonce", ""),
                    "ip_hash": _hash_value(evaluate_request.get("ip", "")),
                    "user_agent_hash": _hash_value(evaluate_request.get("user_agent", "")),
                    "account_id_hash": evaluate_request.get("account_id_hash", ""),
                    "device_id_hash": evaluate_request.get("device_id_hash", ""),
                    "consume": True,
                }
            )
            self.ticket_breaker.record_success()
        except Exception:
            self.ticket_breaker.record_failure()
            await self._handle_unavailable(scope, receive, send, evaluate_request, "TICKET_SERVICE_UNAVAILABLE")
            return

        if ticket.get("valid"):
            asyncio.create_task(
                self._report_decision(
                    evaluate_request,
                    {
                        "action": "allow",
                        "reason": "TICKET_CONSUMED",
                        "scene": ticket.get("scene") or evaluate_request["scene"],
                    },
                )
            )
            await self.app(
                scope,
                receive,
                _clearance_send(send, self.options, ticket.get("clearance_token", ""), int(ticket.get("clearance_ttl_seconds") or 0)),
            )
            return

        reason = ticket.get("reason") or "TICKET_INVALID"
        asyncio.create_task(
            self._report_decision(
                evaluate_request,
                {
                    "action": "block",
                    "reason": reason,
                    "scene": ticket.get("scene") or evaluate_request["scene"],
                },
            )
        )
        await _json_response(send, 403, {"action": "block", "reason": reason})

    async def _handle_policy(self, scope: dict[str, Any], receive: Receive, send: Send, evaluate_request: dict[str, Any]) -> None:
        if not self.policy_breaker.allow():
            await self._handle_unavailable(scope, receive, send, evaluate_request, "POLICY_UNAVAILABLE")
            return
        try:
            decision = await self.client.evaluate(evaluate_request)
            self.policy_breaker.record_success()
        except Exception:
            self.policy_breaker.record_failure()
            await self._handle_unavailable(scope, receive, send, evaluate_request, "POLICY_UNAVAILABLE")
            return

        action = decision.get("action")
        if action in {"allow", "observe", "pass", "skip_challenge"}:
            await self.app(
                scope,
                receive,
                _clearance_send(
                    send,
                    self.options,
                    decision.get("clearance_token", ""),
                    int(decision.get("clearance_ttl_seconds") or 0),
                ),
            )
            return
        if action in {"challenge", "challenge_harder", "step_up_challenge", "rate_limit"}:
            await _json_response(
                send,
                403,
                {
                    "action": action,
                    "reason": decision.get("reason", ""),
                    "challenge_url": self._absolute_challenge_url(decision.get("challenge_url", "")),
                    "session_id": decision.get("session_id", ""),
                    "scene": decision.get("scene", ""),
                    "challenge_type": decision.get("challenge_type", ""),
                    "ttl_seconds": int(decision.get("ttl_seconds") or 0),
                },
            )
            return
        if action in {"block", "cooldown", "require_business_verify"}:
            await _json_response(
                send,
                403,
                {
                    "action": action,
                    "reason": decision.get("reason", ""),
                    "cooldown_seconds": int(decision.get("cooldown_seconds") or 0),
                    "business_verify_type": decision.get("business_verify_type", ""),
                },
            )
            return
        await _json_response(send, 403, {"action": "block", "reason": "UNSUPPORTED_POLICY_DECISION"})

    async def _handle_unavailable(
        self,
        scope: dict[str, Any],
        receive: Receive,
        send: Send,
        evaluate_request: dict[str, Any],
        reason: str,
    ) -> None:
        action = "block" if self.options.fail_policy == "fail_close" else "allow"
        asyncio.create_task(self._report_decision(evaluate_request, {"action": action, "reason": reason}))
        if self.options.fail_policy == "fail_close":
            await _json_response(send, 503, {"action": "block", "reason": reason})
            return
        await self.app(scope, receive, send)

    def _build_evaluate_request(self, scope: dict[str, Any]) -> dict[str, Any]:
        headers = _headers(scope)
        path = scope.get("path") or "/"
        scene = ""
        if self.options.resolve_scene:
            scene = self.options.resolve_scene(scope).strip()
        scene = scene or headers.get(self.options.scene_header.lower(), "").strip() or _scene_from_path(path)

        account_id_hash = ""
        if self.options.resolve_account_id_hash:
            account_id_hash = self.options.resolve_account_id_hash(scope).strip()
        account_id_hash = account_id_hash or headers.get(self.options.account_id_hash_header.lower(), "").strip()

        device_id_hash = ""
        if self.options.resolve_device_id_hash:
            device_id_hash = self.options.resolve_device_id_hash(scope).strip()
        device_id_hash = device_id_hash or headers.get(self.options.device_id_hash_header.lower(), "").strip()

        request = {
            "client_id": self.options.client_id,
            "scene": scene,
            "path": path,
            "method": (scope.get("method") or "GET").upper(),
            "ip": self._remote_ip(scope, headers),
            "user_agent": headers.get("user-agent", ""),
            "account_id_hash": account_id_hash,
            "device_id_hash": device_id_hash,
            "ticket": headers.get(self.options.ticket_header.lower(), "").strip(),
            "clearance": headers.get(self.options.clearance_header.lower(), "").strip()
            or _cookie_value(headers.get("cookie", ""), self.options.clearance_cookie_name),
            "request_nonce": headers.get(self.options.request_nonce_header.lower(), "").strip(),
            "resource_tag": headers.get(self.options.resource_tag_header.lower(), "").strip(),
            "risk_score": _int_header(headers.get(self.options.risk_score_header.lower(), "")),
            "risk_level": headers.get(self.options.risk_level_header.lower(), "").strip(),
            "model_score": _int_header(headers.get(self.options.model_score_header.lower(), "")),
            "model_mode": headers.get(self.options.model_mode_header.lower(), "").strip(),
        }
        allowed = _collect_allowed_headers(headers, self.options.header_allowlist)
        if allowed:
            request["headers"] = allowed
        return {key: value for key, value in request.items() if value != "" and value != 0 and value is not None}

    def _remote_ip(self, scope: dict[str, Any], headers: dict[str, str]) -> str:
        client = scope.get("client") or ("", 0)
        direct = str(client[0] or "")
        if not direct or not self.trusted_proxies:
            return direct
        try:
            direct_ip = ipaddress.ip_address(direct)
        except ValueError:
            return direct
        if not any(direct_ip in network for network in self.trusted_proxies):
            return direct
        for part in headers.get("x-forwarded-for", "").split(","):
            candidate = part.strip()
            if not candidate:
                continue
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            return candidate
        return direct

    def _absolute_challenge_url(self, value: str) -> str:
        if not value:
            return ""
        lowered = value.lower()
        if lowered.startswith("http://") or lowered.startswith("https://"):
            return value
        if value.startswith("/"):
            return self.platform_url + value
        return self.platform_url + "/" + value

    async def _report_decision(self, request: dict[str, Any], decision: dict[str, Any]) -> None:
        event = {
            "client_id": request.get("client_id", ""),
            "scene": decision.get("scene") or request.get("scene", ""),
            "route": request.get("path", ""),
            "ip_hash": _hash_value(request.get("ip", "")),
            "account_id_hash": request.get("account_id_hash", ""),
            "device_id_hash": request.get("device_id_hash", ""),
            "action": decision.get("action", ""),
            "decision_reason": decision.get("reason", ""),
            "challenge_type": decision.get("challenge_type", ""),
            "result": decision.get("action", ""),
        }
        try:
            await self.client.report([event])
        except Exception:
            return


class _HTTPPlatformClient:
    def __init__(self, platform_url: str, client_secret: str, timeout_seconds: float):
        self.platform_url = platform_url
        self.client_secret = client_secret
        self.timeout_seconds = timeout_seconds

    async def evaluate(self, request: dict[str, Any]) -> dict[str, Any]:
        return await asyncio.to_thread(self._post_json, "/api/v1/policy/evaluate", request)

    async def consume(self, request: dict[str, Any]) -> dict[str, Any]:
        request = dict(request)
        request["consume"] = True
        return await asyncio.to_thread(self._post_json, "/api/v1/tickets/verify", request)

    async def report(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        return await asyncio.to_thread(self._post_json, "/api/v1/events/report", {"events": events})

    def _post_json(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.platform_url + path,
            data=data,
            method="POST",
            headers={"content-type": "application/json"},
        )
        if self.client_secret.strip():
            request.add_header("x-captcha-client-secret", self.client_secret.strip())
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            try:
                error.close()
            finally:
                raise RuntimeError(f"platform returned status {error.code}") from error


class _CircuitBreaker:
    def __init__(self, threshold: int, cooldown_seconds: float):
        self.threshold = threshold
        self.cooldown_seconds = cooldown_seconds
        self.failures = 0
        self.open_until = 0.0

    def allow(self) -> bool:
        if not self._enabled():
            return True
        return time.time() >= self.open_until

    def record_success(self) -> None:
        if not self._enabled():
            return
        self.failures = 0
        self.open_until = 0.0

    def record_failure(self) -> None:
        if not self._enabled():
            return
        self.failures += 1
        if self.failures >= self.threshold:
            self.failures = 0
            self.open_until = time.time() + self.cooldown_seconds

    def _enabled(self) -> bool:
        return self.threshold > 0 and self.cooldown_seconds > 0


def _clearance_send(send: Send, options: CaptchaOptions, token: str, ttl_seconds: int) -> Send:
    async def wrapped(message: dict[str, Any]) -> None:
        if message.get("type") == "http.response.start" and token:
            headers = list(message.get("headers", []))
            headers.append((options.clearance_header.lower().encode("latin-1"), token.encode("latin-1")))
            if options.clearance_cookie_name:
                parts = [
                    f"{options.clearance_cookie_name}={token}",
                    "Path=/",
                    "HttpOnly",
                    "SameSite=Lax",
                ]
                if options.clearance_cookie_secure:
                    parts.append("Secure")
                if ttl_seconds > 0:
                    parts.append(f"Max-Age={ttl_seconds}")
                headers.append((b"set-cookie", "; ".join(parts).encode("latin-1")))
            message = dict(message)
            message["headers"] = headers
        await send(message)

    return wrapped


async def _json_response(send: Send, status: int, body: dict[str, Any]) -> None:
    payload = json.dumps(body).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": payload})


def _headers(scope: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw_name, raw_value in scope.get("headers", []):
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        if name in out:
            out[name] += "," + value
        else:
            out[name] = value
    return out


def _cookie_value(header: str, name: str) -> str:
    if not header or not name:
        return ""
    jar = cookies.SimpleCookie()
    try:
        jar.load(header)
    except cookies.CookieError:
        return ""
    morsel = jar.get(name)
    return morsel.value if morsel else ""


def _collect_allowed_headers(headers: dict[str, str], allowlist: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in allowlist:
        normalized = name.strip().lower()
        value = headers.get(normalized, "").strip()
        if normalized and value:
            out[normalized] = value
    return out


def _int_header(value: str) -> int:
    try:
        parsed = int(value.strip())
    except (TypeError, ValueError):
        return 0
    return min(100, max(0, parsed))


def _scene_from_path(path: str) -> str:
    trimmed = path.strip("/")
    if not trimmed:
        return "default"
    return trimmed.split("/", 1)[0] or "default"


def _hash_value(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]

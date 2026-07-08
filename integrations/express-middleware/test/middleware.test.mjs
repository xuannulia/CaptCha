import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { createCaptchaMiddleware } from "../dist/index.js";

test("allows request when platform allows", async () => {
  let evaluated;
  const middleware = createCaptchaMiddleware({
    platformURL: "http://captcha.local",
    headerAllowlist: ["x-trace-id"],
    fetch: async (url, init) => {
      assert.equal(url, "http://captcha.local/api/v1/policy/evaluate");
      evaluated = JSON.parse(init.body);
      return jsonResponse({ action: "allow", reason: "TICKET_CONSUMED" });
    }
  });

  const response = fakeResponse();
  let nextCalled = false;
  await middleware(fakeRequest({
    path: "/api/login",
    headers: {
      "x-captcha-resource-tag": "campaign",
      "x-captcha-account-id-hash": "acct_hash_express",
      "x-captcha-device-id-hash": "device_hash_express",
      "x-captcha-risk-score": "77",
      "x-captcha-risk-level": "high",
      "x-captcha-model-score": "88",
      "x-captcha-model-mode": "observe",
      "x-trace-id": "trace-express",
      "authorization": "Bearer should-not-forward"
    }
  }), response, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.equal(response.statusCode, 200);
  assert.equal(evaluated.ticket, undefined);
  assert.equal(evaluated.scene, "api");
  assert.equal(evaluated.resource_tag, "campaign");
  assert.equal(evaluated.account_id_hash, "acct_hash_express");
  assert.equal(evaluated.device_id_hash, "device_hash_express");
  assert.equal(evaluated.risk_score, 77);
  assert.equal(evaluated.risk_level, "high");
  assert.equal(evaluated.model_score, 88);
  assert.equal(evaluated.model_mode, "observe");
  assert.equal(evaluated.headers["x-trace-id"], "trace-express");
  assert.equal(evaluated.headers.authorization, undefined);
});

test("consumes ticket before policy evaluation", async () => {
  const calls = [];
  const middleware = createCaptchaMiddleware({
    platformURL: "http://captcha.local",
    fetch: async (url, init) => {
      calls.push({ url, body: JSON.parse(init.body) });
      return jsonResponse({ valid: true, client_id: "demo", scene: "login", route: "/login", clearance_token: "clearance_express", clearance_ttl_seconds: 600 });
    },
    resolveScene: () => "login"
  });

  const response = fakeResponse();
  let nextCalled = false;
  await middleware(fakeRequest({
    path: "/login",
    ticket: "ticket_ok",
    headers: {
      "x-captcha-request-nonce": "nonce-express",
      "x-captcha-account-id-hash": "acct_ticket_express",
      "x-captcha-device-id-hash": "device_ticket_express"
    }
  }), response, () => {
    nextCalled = true;
  });
  await waitFor(() => calls.length === 2);

  assert.equal(nextCalled, true);
  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["x-captcha-clearance"], "clearance_express");
  assert.equal(response.cookies.captcha_clearance.value, "clearance_express");
  assert.equal(response.cookies.captcha_clearance.options.httpOnly, true);
  assert.equal(response.cookies.captcha_clearance.options.maxAge, 600_000);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, "http://captcha.local/api/v1/tickets/verify");
  assert.equal(calls[0].body.ticket, "ticket_ok");
  assert.equal(calls[0].body.client_id, "demo");
  assert.equal(calls[0].body.scene, "login");
  assert.equal(calls[0].body.route, "/login");
  assert.equal(calls[0].body.request_nonce, "nonce-express");
  assert.equal(calls[0].body.ip_hash, ticketBindHash("198.51.100.9"));
  assert.equal(calls[0].body.user_agent_hash, ticketBindHash("node-test"));
  assert.equal(calls[0].body.account_id_hash, "acct_ticket_express");
  assert.equal(calls[0].body.device_id_hash, "device_ticket_express");
  assert.equal(calls[0].body.consume, true);
  assert.equal(calls[1].url, "http://captcha.local/api/v1/events/report");
  assert.equal(calls[1].body.events[0].action, "allow");
  assert.equal(calls[1].body.events[0].decision_reason, "TICKET_CONSUMED");
  assert.equal(calls[1].body.events[0].scene, "login");
  assert.equal(calls[1].body.events[0].route, "/login");
  assert.equal(calls[1].body.events[0].account_id_hash, "acct_ticket_express");
  assert.equal(calls[1].body.events[0].device_id_hash, "device_ticket_express");
  assert.match(calls[1].body.events[0].ip_hash, /^fnv1a:/);
});

test("sends clearance cookie to policy evaluation", async () => {
  let evaluated;
  const middleware = createCaptchaMiddleware({
    platformURL: "http://captcha.local",
    fetch: async (_url, init) => {
      evaluated = JSON.parse(init.body);
      return jsonResponse({ action: "allow", reason: "CLEARANCE_VALID" });
    },
    resolveScene: () => "login"
  });

  const response = fakeResponse();
  let nextCalled = false;
  await middleware(fakeRequest({
    path: "/login",
    headers: { cookie: "captcha_clearance=clearance_cookie" }
  }), response, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.equal(evaluated.clearance, "clearance_cookie");
});

test("blocks invalid ticket before policy evaluation", async () => {
  const calls = [];
  const middleware = createCaptchaMiddleware({
    platformURL: "http://captcha.local",
    fetch: async (url, init) => {
      calls.push({ url, body: JSON.parse(init.body) });
      return jsonResponse({ valid: false, reason: "CONSUMED" });
    },
    resolveScene: () => "login"
  });

  const response = fakeResponse();
  let nextCalled = false;
  await middleware(fakeRequest({ path: "/login", ticket: "ticket_consumed" }), response, () => {
    nextCalled = true;
  });
  await waitFor(() => calls.length === 2);

  assert.equal(nextCalled, false);
  assert.equal(response.statusCode, 403);
  assert.equal(response.body.action, "block");
  assert.equal(response.body.reason, "CONSUMED");
  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, "http://captcha.local/api/v1/tickets/verify");
  assert.equal(calls[1].url, "http://captcha.local/api/v1/events/report");
  assert.equal(calls[1].body.events[0].action, "block");
  assert.equal(calls[1].body.events[0].decision_reason, "CONSUMED");
});

test("returns challenge details without calling next", async () => {
  const middleware = createCaptchaMiddleware({
    platformURL: "http://captcha.local",
    fetch: async () => jsonResponse({
      action: "challenge",
      reason: "ALWAYS",
      challenge_url: "/challenge?session_id=cap_sess_test",
      session_id: "cap_sess_test",
      scene: "login",
      challenge_type: "SLIDER",
      ttl_seconds: 120
    })
  });

  const response = fakeResponse();
  let nextCalled = false;
  await middleware(fakeRequest({ path: "/login" }), response, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, false);
  assert.equal(response.statusCode, 403);
  assert.equal(response.body.challenge_url, "http://captcha.local/challenge?session_id=cap_sess_test");
  assert.equal(response.body.challenge_type, "SLIDER");
});

test("blocks unsupported policy decisions instead of passing through", async () => {
  const middleware = createCaptchaMiddleware({
    platformURL: "http://captcha.local",
    fetch: async () => jsonResponse({ action: "retry", reason: "VERIFY_RETRY" })
  });

  const response = fakeResponse();
  let nextCalled = false;
  await middleware(fakeRequest({ path: "/login" }), response, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, false);
  assert.equal(response.statusCode, 403);
  assert.equal(response.body.action, "block");
  assert.equal(response.body.reason, "UNSUPPORTED_POLICY_DECISION");
});

test("sends client secret to platform requests", async () => {
  const middleware = createCaptchaMiddleware({
    platformURL: "http://captcha.local",
    clientSecret: "cap_secret_test",
    fetch: async (url, init) => {
      assert.equal(url, "http://captcha.local/api/v1/policy/evaluate");
      assert.equal(init.headers["x-captcha-client-secret"], "cap_secret_test");
      return jsonResponse({ action: "allow", reason: "OK" });
    }
  });

  const response = fakeResponse();
  let nextCalled = false;
  await middleware(fakeRequest({ path: "/login" }), response, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
});

test("ignores forwarded-for unless proxy is trusted", async () => {
  let evaluated;
  const middleware = createCaptchaMiddleware({
    platformURL: "http://captcha.local",
    fetch: async (_url, init) => {
      evaluated = JSON.parse(init.body);
      return jsonResponse({ action: "allow", reason: "OK" });
    }
  });

  const response = fakeResponse();
  await middleware(fakeRequest({
    path: "/login",
    headers: { "x-forwarded-for": "203.0.113.7" }
  }), response, () => undefined);

  assert.equal(evaluated.ip, "198.51.100.9");
});

test("uses forwarded-for from trusted proxy", async () => {
  let evaluated;
  const middleware = createCaptchaMiddleware({
    platformURL: "http://captcha.local",
    trustedProxyCIDRs: ["198.51.100.0/24"],
    fetch: async (_url, init) => {
      evaluated = JSON.parse(init.body);
      return jsonResponse({ action: "allow", reason: "OK" });
    }
  });

  const response = fakeResponse();
  await middleware(fakeRequest({
    path: "/login",
    headers: { "x-forwarded-for": "203.0.113.7, 198.51.100.9" }
  }), response, () => undefined);

  assert.equal(evaluated.ip, "203.0.113.7");
});

test("fails open by default when platform is unavailable", async () => {
  const middleware = createCaptchaMiddleware({
    platformURL: "http://captcha.local",
    fetch: async () => {
      throw new Error("offline");
    }
  });

  const response = fakeResponse();
  let nextCalled = false;
  await middleware(fakeRequest({ path: "/login" }), response, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.equal(response.statusCode, 200);
});

test("aborts policy calls after timeout and fails open", async () => {
  const calls = [];
  let aborted = false;
  const middleware = createCaptchaMiddleware({
    platformURL: "http://captcha.local",
    timeoutMs: 5,
    fetch: async (url, init) => {
      calls.push({ url, body: init?.body ? JSON.parse(init.body) : undefined });
      if (url === "http://captcha.local/api/v1/events/report") {
        return jsonResponse({ accepted: 1 });
      }
      return await new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => {
          aborted = true;
          reject(new Error("aborted"));
        }, { once: true });
      });
    }
  });

  const response = fakeResponse();
  let nextCalled = false;
  await middleware(fakeRequest({ path: "/login" }), response, () => {
    nextCalled = true;
  });
  await waitFor(() => calls.some((call) => call.url === "http://captcha.local/api/v1/events/report"));

  assert.equal(aborted, true);
  assert.equal(nextCalled, true);
  assert.equal(response.statusCode, 200);
  const eventCall = calls.find((call) => call.url === "http://captcha.local/api/v1/events/report");
  assert.equal(eventCall.body.events[0].decision_reason, "POLICY_UNAVAILABLE");
});

test("opens circuit breaker after platform failures", async () => {
  const calls = [];
  const middleware = createCaptchaMiddleware({
    platformURL: "http://captcha.local",
    circuitBreakerFailureThreshold: 1,
    circuitBreakerCooldownMs: 60_000,
    fetch: async (url, init) => {
      calls.push({ url, body: init?.body ? JSON.parse(init.body) : undefined });
      if (url === "http://captcha.local/api/v1/events/report") {
        return jsonResponse({ accepted: 1 });
      }
      throw new Error("offline");
    }
  });

  for (let i = 0; i < 2; i++) {
    const response = fakeResponse();
    let nextCalled = false;
    await middleware(fakeRequest({ path: "/login" }), response, () => {
      nextCalled = true;
    });
    assert.equal(nextCalled, true);
    assert.equal(response.statusCode, 200);
  }
  await waitFor(() => calls.filter((call) => call.url === "http://captcha.local/api/v1/events/report").length === 2);

  const policyCalls = calls.filter((call) => call.url === "http://captcha.local/api/v1/policy/evaluate");
  const eventCalls = calls.filter((call) => call.url === "http://captcha.local/api/v1/events/report");
  assert.equal(policyCalls.length, 1);
  assert.equal(eventCalls.length, 2);
  assert.equal(eventCalls[0].body.events[0].decision_reason, "POLICY_UNAVAILABLE");
  assert.equal(eventCalls[1].body.events[0].decision_reason, "POLICY_UNAVAILABLE");
});

test("supports fail close when configured", async () => {
  const calls = [];
  const middleware = createCaptchaMiddleware({
    platformURL: "http://captcha.local",
    failPolicy: "fail_close",
    fetch: async (url, init) => {
      if (url === "http://captcha.local/api/v1/events/report") {
        calls.push({ url, body: JSON.parse(init.body) });
        return jsonResponse({ accepted: 1 });
      }
      throw new Error("offline");
    }
  });

  const response = fakeResponse();
  let nextCalled = false;
  await middleware(fakeRequest({ path: "/login" }), response, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, false);
  assert.equal(response.statusCode, 503);
  assert.equal(response.body.reason, "POLICY_UNAVAILABLE");
  await waitFor(() => calls.length === 1);
  assert.equal(calls[0].body.events[0].action, "block");
  assert.equal(calls[0].body.events[0].decision_reason, "POLICY_UNAVAILABLE");
});

test("uses ticket unavailable reason when ticket consume fails closed", async () => {
  const calls = [];
  const middleware = createCaptchaMiddleware({
    platformURL: "http://captcha.local",
    failPolicy: "fail_close",
    fetch: async (url, init) => {
      if (url === "http://captcha.local/api/v1/events/report") {
        calls.push({ url, body: JSON.parse(init.body) });
        return jsonResponse({ accepted: 1 });
      }
      throw new Error("offline");
    },
    resolveScene: () => "login"
  });

  const response = fakeResponse();
  let nextCalled = false;
  await middleware(fakeRequest({ path: "/login", ticket: "ticket_ok" }), response, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, false);
  assert.equal(response.statusCode, 503);
  assert.equal(response.body.reason, "TICKET_SERVICE_UNAVAILABLE");
  await waitFor(() => calls.length === 1);
  assert.equal(calls[0].body.events[0].action, "block");
  assert.equal(calls[0].body.events[0].decision_reason, "TICKET_SERVICE_UNAVAILABLE");
  assert.equal(calls[0].body.events[0].scene, "login");
});

function fakeRequest({ path, ticket = "", headers = {} }) {
  return {
    method: "POST",
    path,
    ip: "198.51.100.9",
    headers: {
      "user-agent": "node-test",
      "x-captcha-ticket": ticket,
      ...headers
    },
    get(name) {
      return this.headers[name.toLowerCase()];
    }
  };
}

function fakeResponse() {
  return {
    statusCode: 200,
    body: undefined,
    headers: {},
    cookies: {},
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
      return this;
    },
    cookie(name, value, options) {
      this.cookies[name] = { value, options };
      return this;
    }
  };
}

function ticketBindHash(value) {
  return `sha256:${createHash("sha256").update(value.trim()).digest("hex").slice(0, 32)}`;
}

function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return body;
    }
  };
}

async function waitFor(predicate) {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started > 1000) {
      throw new Error("timed out waiting for condition");
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

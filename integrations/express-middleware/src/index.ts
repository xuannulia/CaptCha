export type DecisionAction = "allow" | "challenge" | "pass" | "retry" | "challenge_harder" | "block" | "observe";

export type PolicyDecision = {
  action: DecisionAction;
  reason: string;
  challenge_url?: string;
  session_id?: string;
  scene?: string;
  challenge_type?: string;
  ttl_seconds?: number;
  clearance_token?: string;
  clearance_ttl_seconds?: number;
};

export type PolicyEvaluateRequest = {
  client_id: string;
  scene: string;
  path: string;
  method: string;
  ip: string;
  user_agent: string;
  account_id_hash?: string;
  device_id_hash?: string;
  ticket?: string;
  clearance?: string;
  request_nonce?: string;
  resource_tag?: string;
  risk_score?: number;
  risk_level?: string;
  model_score?: number;
  model_mode?: string;
  headers?: Record<string, string>;
};

export type TicketConsumeRequest = {
  ticket: string;
  client_id: string;
  scene: string;
  route: string;
  request_nonce?: string;
  ip_hash?: string;
  user_agent_hash?: string;
  account_id_hash?: string;
  device_id_hash?: string;
};

export type TicketConsumeResponse = {
  valid: boolean;
  reason?: string;
  client_id?: string;
  scene?: string;
  route?: string;
  expire_at?: string;
  clearance_token?: string;
  clearance_ttl_seconds?: number;
};

export type AuditEvent = {
  client_id: string;
  scene: string;
  route: string;
  ip_hash?: string;
  account_id_hash?: string;
  device_id_hash?: string;
  action: DecisionAction;
  decision_reason: string;
  challenge_type?: string;
  result: string;
};

export type ReportResult = {
  accepted: number;
};

export type CaptchaMiddlewareOptions = {
  platformURL: string;
  clientID?: string;
  clientSecret?: string;
  ticketHeader?: string;
  clearanceHeader?: string;
  clearanceCookieName?: string;
  clearanceCookieSecure?: boolean;
  requestNonceHeader?: string;
  resourceTagHeader?: string;
  accountIDHashHeader?: string;
  deviceIDHashHeader?: string;
  riskScoreHeader?: string;
  riskLevelHeader?: string;
  modelScoreHeader?: string;
  modelModeHeader?: string;
  sceneHeader?: string;
  failPolicy?: "fail_open" | "fail_close";
  timeoutMs?: number;
  circuitBreakerFailureThreshold?: number;
  circuitBreakerCooldownMs?: number;
  trustedProxyCIDRs?: string[];
  headerAllowlist?: string[];
  resolveScene?: (request: RequestLike) => string;
  resolveAccountIDHash?: (request: RequestLike) => string | undefined;
  resolveDeviceIDHash?: (request: RequestLike) => string | undefined;
  shouldProtect?: (request: RequestLike) => boolean;
  fetch?: typeof globalThis.fetch;
};

export type RequestLike = {
  method?: string;
  path?: string;
  originalUrl?: string;
  url?: string;
  ip?: string;
  socket?: { remoteAddress?: string };
  headers: Record<string, string | string[] | undefined>;
  get?: (name: string) => string | undefined;
};

export type ResponseLike = {
  status: (code: number) => ResponseLike;
  json: (body: unknown) => unknown;
  setHeader?: (name: string, value: string | string[]) => unknown;
  cookie?: (name: string, value: string, options?: Record<string, unknown>) => unknown;
};

export type NextFunction = (error?: unknown) => void;

export type PolicyClient = {
  evaluate(request: PolicyEvaluateRequest): Promise<PolicyDecision>;
};

export type TicketClient = {
  consume(request: TicketConsumeRequest): Promise<TicketConsumeResponse>;
};

export type EventClient = {
  report(events: AuditEvent[]): Promise<ReportResult>;
};

export function createCaptchaMiddleware(options: CaptchaMiddlewareOptions) {
  const normalized = normalizeOptions(options);
  const client = new HTTPPlatformClient(normalized);
  const policyBreaker = new CircuitBreaker(normalized.circuitBreakerFailureThreshold, normalized.circuitBreakerCooldownMs);
  const ticketBreaker = new CircuitBreaker(normalized.circuitBreakerFailureThreshold, normalized.circuitBreakerCooldownMs);

  return async function captchaMiddleware(request: RequestLike, response: ResponseLike, next: NextFunction) {
    if (normalized.shouldProtect && !normalized.shouldProtect(request)) {
      next();
      return;
    }

    let unavailableReason = "POLICY_UNAVAILABLE";
    let currentRequest: PolicyEvaluateRequest | undefined;
    try {
      const evaluateRequest = buildEvaluateRequest(request, normalized);
      currentRequest = evaluateRequest;
      if (evaluateRequest.ticket) {
        unavailableReason = "TICKET_SERVICE_UNAVAILABLE";
        const ipHash = await ticketBindHashValue(evaluateRequest.ip);
        const userAgentHash = await ticketBindHashValue(evaluateRequest.user_agent);
        if (!ticketBreaker.allow()) {
          throw new Error("ticket service circuit breaker open");
        }
        let ticket: TicketConsumeResponse;
        try {
          ticket = await client.consume({
            ticket: evaluateRequest.ticket,
            client_id: evaluateRequest.client_id,
            scene: evaluateRequest.scene,
            route: evaluateRequest.path,
            request_nonce: evaluateRequest.request_nonce,
            ip_hash: ipHash,
            user_agent_hash: userAgentHash,
            account_id_hash: evaluateRequest.account_id_hash,
            device_id_hash: evaluateRequest.device_id_hash
          });
          ticketBreaker.recordSuccess();
        } catch (error) {
          ticketBreaker.recordFailure();
          throw error;
        }
        if (ticket.valid) {
          setClearance(response, normalized, ticket.clearance_token, ticket.clearance_ttl_seconds);
          reportDecision(client, evaluateRequest, {
            action: "allow",
            reason: "TICKET_CONSUMED",
            scene: ticket.scene || evaluateRequest.scene
          });
          next();
          return;
        }
        reportDecision(client, evaluateRequest, {
          action: "block",
          reason: ticket.reason || "TICKET_INVALID",
          scene: ticket.scene || evaluateRequest.scene
        });
        response.status(403).json({ action: "block", reason: ticket.reason || "TICKET_INVALID" });
        return;
      }

      unavailableReason = "POLICY_UNAVAILABLE";
      if (!policyBreaker.allow()) {
        throw new Error("policy service circuit breaker open");
      }
      let decision: PolicyDecision;
      try {
        decision = await client.evaluate(evaluateRequest);
        policyBreaker.recordSuccess();
      } catch (error) {
        policyBreaker.recordFailure();
        throw error;
      }
      if (decision.action === "allow" || decision.action === "observe" || decision.action === "pass") {
        setClearance(response, normalized, decision.clearance_token, decision.clearance_ttl_seconds);
        next();
        return;
      }
      if (decision.action === "challenge" || decision.action === "challenge_harder") {
        response.status(403).json({
          action: decision.action,
          reason: decision.reason,
          challenge_url: absoluteChallengeURL(normalized.platformURL, decision.challenge_url),
          session_id: decision.session_id,
          scene: decision.scene,
          challenge_type: decision.challenge_type,
          ttl_seconds: decision.ttl_seconds
        });
        return;
      }
      if (decision.action === "block") {
        response.status(403).json({ action: "block", reason: decision.reason });
        return;
      }
      next();
    } catch (error) {
      if (currentRequest) {
        reportDecision(client, currentRequest, {
          action: normalized.failPolicy === "fail_close" ? "block" : "allow",
          reason: unavailableReason
        });
      }
      if (normalized.failPolicy === "fail_close") {
        response.status(503).json({ action: "block", reason: unavailableReason });
        return;
      }
      next();
    }
  };
}

class HTTPPlatformClient implements PolicyClient, TicketClient, EventClient {
  constructor(private readonly options: NormalizedOptions) {}

  async evaluate(request: PolicyEvaluateRequest): Promise<PolicyDecision> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs);
    try {
      const response = await this.options.fetch(`${this.options.platformURL}/api/v1/policy/evaluate`, {
        method: "POST",
        headers: this.jsonHeaders(),
        body: JSON.stringify(request),
        signal: controller.signal
      });
      if (!response.ok) {
        throw new Error(`policy service returned ${response.status}`);
      }
      return await response.json() as PolicyDecision;
    } finally {
      clearTimeout(timeout);
    }
  }

  async consume(request: TicketConsumeRequest): Promise<TicketConsumeResponse> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs);
    try {
      const response = await this.options.fetch(`${this.options.platformURL}/api/v1/tickets/verify`, {
        method: "POST",
        headers: this.jsonHeaders(),
        body: JSON.stringify({ ...request, consume: true }),
        signal: controller.signal
      });
      if (!response.ok) {
        throw new Error(`ticket service returned ${response.status}`);
      }
      return await response.json() as TicketConsumeResponse;
    } finally {
      clearTimeout(timeout);
    }
  }

  async report(events: AuditEvent[]): Promise<ReportResult> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs);
    try {
      const response = await this.options.fetch(`${this.options.platformURL}/api/v1/events/report`, {
        method: "POST",
        headers: this.jsonHeaders(),
        body: JSON.stringify({ events }),
        signal: controller.signal
      });
      if (!response.ok) {
        throw new Error(`event service returned ${response.status}`);
      }
      return await response.json() as ReportResult;
    } finally {
      clearTimeout(timeout);
    }
  }

  private jsonHeaders(): Record<string, string> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.options.clientSecret) {
      headers["x-captcha-client-secret"] = this.options.clientSecret;
    }
    return headers;
  }
}

type NormalizedOptions = Required<Pick<
  CaptchaMiddlewareOptions,
  "platformURL" | "clientID" | "clientSecret" | "ticketHeader" | "requestNonceHeader" | "resourceTagHeader" | "accountIDHashHeader" | "deviceIDHashHeader" | "riskScoreHeader" | "riskLevelHeader" | "modelScoreHeader" | "modelModeHeader" | "sceneHeader" | "failPolicy" | "timeoutMs" | "circuitBreakerFailureThreshold" | "circuitBreakerCooldownMs" | "fetch"
  | "clearanceHeader" | "clearanceCookieName" | "clearanceCookieSecure"
>> & Pick<
  CaptchaMiddlewareOptions,
  "resolveScene" | "resolveAccountIDHash" | "resolveDeviceIDHash" | "shouldProtect" | "trustedProxyCIDRs" | "headerAllowlist"
>;

function normalizeOptions(options: CaptchaMiddlewareOptions): NormalizedOptions {
  if (!options.platformURL) {
    throw new Error("platformURL is required");
  }
  const fetchImpl = options.fetch || globalThis.fetch;
  if (!fetchImpl) {
    throw new Error("fetch is required; use Node.js 18+ or pass options.fetch");
  }
  return {
    platformURL: options.platformURL.replace(/\/+$/, ""),
    clientID: options.clientID || "demo",
    clientSecret: options.clientSecret || "",
    ticketHeader: options.ticketHeader || "x-captcha-ticket",
    clearanceHeader: options.clearanceHeader || "x-captcha-clearance",
    clearanceCookieName: options.clearanceCookieName || "captcha_clearance",
    clearanceCookieSecure: options.clearanceCookieSecure || false,
    requestNonceHeader: options.requestNonceHeader || "x-captcha-request-nonce",
    resourceTagHeader: options.resourceTagHeader || "x-captcha-resource-tag",
    accountIDHashHeader: options.accountIDHashHeader || "x-captcha-account-id-hash",
    deviceIDHashHeader: options.deviceIDHashHeader || "x-captcha-device-id-hash",
    riskScoreHeader: options.riskScoreHeader || "x-captcha-risk-score",
    riskLevelHeader: options.riskLevelHeader || "x-captcha-risk-level",
    modelScoreHeader: options.modelScoreHeader || "x-captcha-model-score",
    modelModeHeader: options.modelModeHeader || "x-captcha-model-mode",
    sceneHeader: options.sceneHeader || "x-captcha-scene",
    failPolicy: options.failPolicy || "fail_open",
    timeoutMs: options.timeoutMs || 1500,
    circuitBreakerFailureThreshold: options.circuitBreakerFailureThreshold || 0,
    circuitBreakerCooldownMs: options.circuitBreakerCooldownMs || 0,
    fetch: fetchImpl,
    trustedProxyCIDRs: options.trustedProxyCIDRs || [],
    headerAllowlist: options.headerAllowlist || [],
    resolveScene: options.resolveScene,
    resolveAccountIDHash: options.resolveAccountIDHash,
    resolveDeviceIDHash: options.resolveDeviceIDHash,
    shouldProtect: options.shouldProtect
  };
}

class CircuitBreaker {
  private failures = 0;
  private openUntil = 0;

  constructor(private readonly threshold: number, private readonly cooldownMs: number) {}

  allow() {
    if (!this.enabled()) return true;
    return Date.now() >= this.openUntil;
  }

  recordSuccess() {
    if (!this.enabled()) return;
    this.failures = 0;
    this.openUntil = 0;
  }

  recordFailure() {
    if (!this.enabled()) return;
    this.failures += 1;
    if (this.failures >= this.threshold) {
      this.failures = 0;
      this.openUntil = Date.now() + this.cooldownMs;
    }
  }

  private enabled() {
    return this.threshold > 0 && this.cooldownMs > 0;
  }
}

function buildEvaluateRequest(request: RequestLike, options: NormalizedOptions): PolicyEvaluateRequest {
  return {
    client_id: options.clientID,
    scene: options.resolveScene?.(request) || getHeader(request, options.sceneHeader) || sceneFromPath(request.path || request.url || "/"),
    path: request.path || stripQuery(request.originalUrl || request.url || "/"),
    method: (request.method || "GET").toUpperCase(),
    ip: remoteIP(request, options),
    user_agent: getHeader(request, "user-agent") || "",
    account_id_hash: options.resolveAccountIDHash?.(request) || getHeader(request, options.accountIDHashHeader) || undefined,
    device_id_hash: options.resolveDeviceIDHash?.(request) || getHeader(request, options.deviceIDHashHeader) || undefined,
    ticket: getHeader(request, options.ticketHeader) || undefined,
    clearance: getHeader(request, options.clearanceHeader) || getCookie(request, options.clearanceCookieName) || undefined,
    request_nonce: getHeader(request, options.requestNonceHeader) || undefined,
    resource_tag: getHeader(request, options.resourceTagHeader) || undefined,
    risk_score: intHeader(request, options.riskScoreHeader),
    risk_level: getHeader(request, options.riskLevelHeader) || undefined,
    model_score: intHeader(request, options.modelScoreHeader),
    model_mode: getHeader(request, options.modelModeHeader) || undefined,
    headers: collectAllowedHeaders(request, options.headerAllowlist || [])
  };
}

function absoluteChallengeURL(platformURL: string, challengeURL?: string) {
  if (!challengeURL) return "";
  if (/^https?:\/\//i.test(challengeURL)) return challengeURL;
  return `${platformURL}${challengeURL.startsWith("/") ? "" : "/"}${challengeURL}`;
}

function setClearance(response: ResponseLike, options: NormalizedOptions, token?: string, ttlSeconds?: number) {
  if (!token) return;
  response.setHeader?.(options.clearanceHeader, token);
  if (!options.clearanceCookieName) return;
  const maxAgeMs = ttlSeconds && ttlSeconds > 0 ? ttlSeconds * 1000 : undefined;
  if (response.cookie) {
    response.cookie(options.clearanceCookieName, token, {
      httpOnly: true,
      sameSite: "lax",
      secure: options.clearanceCookieSecure,
      path: "/",
      maxAge: maxAgeMs
    });
    return;
  }
  response.setHeader?.("Set-Cookie", serializeClearanceCookie(options, token, ttlSeconds));
}

function serializeClearanceCookie(options: NormalizedOptions, token: string, ttlSeconds?: number) {
  const parts = [
    `${options.clearanceCookieName}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax"
  ];
  if (options.clearanceCookieSecure) {
    parts.push("Secure");
  }
  if (ttlSeconds && ttlSeconds > 0) {
    parts.push(`Max-Age=${Math.floor(ttlSeconds)}`);
  }
  return parts.join("; ");
}

function reportDecision(
  client: EventClient,
  request: PolicyEvaluateRequest,
  decision: { action: DecisionAction; reason: string; scene?: string; challenge_type?: string }
) {
  const event: AuditEvent = {
    client_id: request.client_id,
    scene: decision.scene || request.scene,
    route: request.path,
    ip_hash: hashValue(request.ip),
    account_id_hash: request.account_id_hash,
    device_id_hash: request.device_id_hash,
    action: decision.action,
    decision_reason: decision.reason,
    challenge_type: decision.challenge_type,
    result: decision.action
  };
  void client.report([event]).catch(() => undefined);
}

function getHeader(request: RequestLike, name: string) {
  if (request.get) {
    const value = request.get(name);
    if (value) return value;
  }
  const lower = name.toLowerCase();
  const value = request.headers[lower] || request.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function getCookie(request: RequestLike, name: string) {
  if (!name) return "";
  const header = getHeader(request, "cookie");
  if (!header) return "";
  for (const part of header.split(";")) {
    const [rawName, ...rawValue] = part.trim().split("=");
    if (rawName === name) {
      try {
        return decodeURIComponent(rawValue.join("="));
      } catch {
        return rawValue.join("=");
      }
    }
  }
  return "";
}

function intHeader(request: RequestLike, name: string) {
  const value = getHeader(request, name);
  if (!value) return undefined;
  const parsed = Number.parseInt(value.trim(), 10);
  if (!Number.isFinite(parsed)) return undefined;
  if (parsed < 0) return 0;
  if (parsed > 100) return 100;
  return parsed;
}

function collectAllowedHeaders(request: RequestLike, allowlist: string[]) {
  const out: Record<string, string> = {};
  for (const name of allowlist) {
    const normalized = name.trim().toLowerCase();
    if (!normalized) continue;
    const value = getHeader(request, normalized);
    if (value && value.trim()) {
      out[normalized] = value.trim();
    }
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function remoteIP(request: RequestLike, options: NormalizedOptions) {
  const direct = directRemoteIP(request);
  const forwarded = getHeader(request, "x-forwarded-for");
  if (forwarded && isTrustedProxy(direct, options.trustedProxyCIDRs || [])) {
    return firstForwardedIP(forwarded) || direct;
  }
  return direct;
}

function directRemoteIP(request: RequestLike) {
  return request.socket?.remoteAddress || request.ip || "";
}

function firstForwardedIP(forwarded: string) {
  for (const part of forwarded.split(",")) {
    const candidate = part.trim();
    if (parseIPv4(candidate) !== undefined) return candidate;
  }
  return "";
}

function isTrustedProxy(ip: string, cidrs: string[]) {
  if (!ip || cidrs.length === 0) return false;
  return cidrs.some((cidr) => cidrContains(ip, cidr));
}

function cidrContains(ip: string, cidr: string) {
  const parsedIP = parseIPv4(ip);
  if (parsedIP === undefined) return false;
  const [range, prefixText = "32"] = cidr.split("/");
  const parsedRange = parseIPv4(range.trim());
  const prefix = Number(prefixText);
  if (parsedRange === undefined || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (parsedIP & mask) === (parsedRange & mask);
}

function parseIPv4(ip: string) {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return undefined;
  let value = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return undefined;
    const octet = Number(part);
    if (octet < 0 || octet > 255) return undefined;
    value = ((value << 8) | octet) >>> 0;
  }
  return value;
}

function sceneFromPath(path: string) {
  const trimmed = stripQuery(path).replace(/^\/+|\/+$/g, "");
  if (!trimmed) return "default";
  return trimmed.split("/")[0] || "default";
}

function stripQuery(path: string) {
  return path.split("?")[0] || "/";
}

function hashValue(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return "";
  let hash = 0x811c9dc5;
  for (let index = 0; index < trimmed.length; index++) {
    hash ^= trimmed.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return `fnv1a:${(hash >>> 0).toString(16).padStart(8, "0")}`;
}

async function ticketBindHashValue(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return "";
  const encoded = new TextEncoder().encode(trimmed);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", encoded);
  const hex = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `sha256:${hex.slice(0, 32)}`;
}

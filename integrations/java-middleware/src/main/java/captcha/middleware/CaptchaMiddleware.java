package captcha.middleware;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class CaptchaMiddleware implements HttpHandler {
    private final HttpHandler next;
    private final Options options;
    private final PlatformClient client;
    private final CircuitBreaker policyBreaker;
    private final CircuitBreaker ticketBreaker;
    private final List<CIDR> trustedProxies;

    public CaptchaMiddleware(HttpHandler next, Options options) {
        this.next = next == null ? exchange -> exchange.sendResponseHeaders(204, -1) : next;
        this.options = options == null ? new Options() : options.withDefaults();
        this.client = this.options.platformClient != null
                ? this.options.platformClient
                : new HTTPPlatformClient(this.options.platformURL, this.options.clientSecret, this.options.timeout);
        this.policyBreaker = new CircuitBreaker(this.options.circuitBreakerFailureThreshold, this.options.circuitBreakerCooldown);
        this.ticketBreaker = new CircuitBreaker(this.options.circuitBreakerFailureThreshold, this.options.circuitBreakerCooldown);
        this.trustedProxies = parseCIDRs(this.options.trustedProxyCIDRs);
    }

    public static CaptchaMiddleware wrap(HttpHandler next, Options options) {
        return new CaptchaMiddleware(next, options);
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if (options.shouldProtect != null && !options.shouldProtect.test(exchange)) {
            next.handle(exchange);
            return;
        }

        PolicyEvaluateRequest evaluateRequest = buildEvaluateRequest(exchange);
        if (!evaluateRequest.ticket.isBlank()) {
            handleTicket(exchange, evaluateRequest);
            return;
        }
        handlePolicy(exchange, evaluateRequest);
    }

    private void handleTicket(HttpExchange exchange, PolicyEvaluateRequest evaluateRequest) throws IOException {
        if (!ticketBreaker.allow()) {
            handleUnavailable(exchange, evaluateRequest, "TICKET_SERVICE_UNAVAILABLE");
            return;
        }
        TicketConsumeResponse ticket;
        try {
            ticket = client.consume(new TicketConsumeRequest(
                    evaluateRequest.ticket,
                    evaluateRequest.clientID,
                    evaluateRequest.scene,
                    evaluateRequest.path,
                    evaluateRequest.requestNonce,
                    hashValue(evaluateRequest.ip),
                    hashValue(evaluateRequest.userAgent),
                    evaluateRequest.accountIDHash,
                    evaluateRequest.deviceIDHash
            ));
            ticketBreaker.recordSuccess();
        } catch (Exception error) {
            ticketBreaker.recordFailure();
            handleUnavailable(exchange, evaluateRequest, "TICKET_SERVICE_UNAVAILABLE");
            return;
        }

        if (ticket.valid) {
            writeClearance(exchange, ticket.clearanceToken, ticket.clearanceTTLSeconds);
            reportDecision(evaluateRequest, new PolicyDecision("allow", "TICKET_CONSUMED", "", "", firstNonEmpty(ticket.scene, evaluateRequest.scene), "", 0, 0, "", "", 0));
            next.handle(exchange);
            return;
        }

        String reason = firstNonEmpty(ticket.reason, "TICKET_INVALID");
        reportDecision(evaluateRequest, new PolicyDecision("block", reason, "", "", firstNonEmpty(ticket.scene, evaluateRequest.scene), "", 0, 0, "", "", 0));
        writeJSON(exchange, 403, Map.of("action", "block", "reason", reason));
    }

    private void handlePolicy(HttpExchange exchange, PolicyEvaluateRequest evaluateRequest) throws IOException {
        if (!policyBreaker.allow()) {
            handleUnavailable(exchange, evaluateRequest, "POLICY_UNAVAILABLE");
            return;
        }

        PolicyDecision decision;
        try {
            decision = client.evaluate(evaluateRequest);
            policyBreaker.recordSuccess();
        } catch (Exception error) {
            policyBreaker.recordFailure();
            handleUnavailable(exchange, evaluateRequest, "POLICY_UNAVAILABLE");
            return;
        }

        switch (decision.action) {
            case "allow", "observe", "pass", "skip_challenge" -> {
                writeClearance(exchange, decision.clearanceToken, decision.clearanceTTLSeconds);
                next.handle(exchange);
            }
            case "challenge", "challenge_harder", "step_up_challenge", "rate_limit" -> writeJSON(exchange, 403, orderedMap(
                    "action", decision.action,
                    "reason", decision.reason,
                    "challenge_url", absoluteChallengeURL(decision.challengeURL),
                    "session_id", decision.sessionID,
                    "scene", decision.scene,
                    "challenge_type", decision.challengeType,
                    "ttl_seconds", decision.ttlSeconds
            ));
            case "block", "cooldown", "require_business_verify" -> writeJSON(exchange, 403, orderedMap(
                    "action", decision.action,
                    "reason", decision.reason,
                    "cooldown_seconds", decision.cooldownSeconds,
                    "business_verify_type", decision.businessVerifyType
            ));
            default -> writeJSON(exchange, 403, Map.of("action", "block", "reason", "UNSUPPORTED_POLICY_DECISION"));
        }
    }

    private void handleUnavailable(HttpExchange exchange, PolicyEvaluateRequest request, String reason) throws IOException {
        String action = "fail_close".equals(options.failPolicy) ? "block" : "allow";
        reportDecision(request, new PolicyDecision(action, reason, "", "", request.scene, "", 0, 0, "", "", 0));
        if ("fail_close".equals(options.failPolicy)) {
            writeJSON(exchange, 503, Map.of("action", "block", "reason", reason));
            return;
        }
        next.handle(exchange);
    }

    private PolicyEvaluateRequest buildEvaluateRequest(HttpExchange exchange) {
        Headers headers = exchange.getRequestHeaders();
        String path = exchange.getRequestURI().getPath();
        String scene = options.resolveScene != null ? trim(options.resolveScene.apply(exchange)) : "";
        if (scene.isBlank()) {
            scene = firstNonEmpty(header(headers, options.sceneHeader), sceneFromPath(path));
        }
        String accountIDHash = options.resolveAccountIDHash != null ? trim(options.resolveAccountIDHash.apply(exchange)) : "";
        if (accountIDHash.isBlank()) {
            accountIDHash = header(headers, options.accountIDHashHeader);
        }
        String deviceIDHash = options.resolveDeviceIDHash != null ? trim(options.resolveDeviceIDHash.apply(exchange)) : "";
        if (deviceIDHash.isBlank()) {
            deviceIDHash = header(headers, options.deviceIDHashHeader);
        }
        return new PolicyEvaluateRequest(
                options.clientID,
                scene,
                path,
                exchange.getRequestMethod().toUpperCase(Locale.ROOT),
                remoteIP(exchange),
                header(headers, "User-Agent"),
                accountIDHash,
                deviceIDHash,
                header(headers, options.ticketHeader),
                clearanceFromRequest(exchange),
                header(headers, options.requestNonceHeader),
                header(headers, options.resourceTagHeader),
                intHeader(headers, options.riskScoreHeader),
                header(headers, options.riskLevelHeader),
                intHeader(headers, options.modelScoreHeader),
                header(headers, options.modelModeHeader),
                collectAllowedHeaders(headers, options.headerAllowlist)
        );
    }

    private String clearanceFromRequest(HttpExchange exchange) {
        String headerValue = header(exchange.getRequestHeaders(), options.clearanceHeader);
        if (!headerValue.isBlank()) {
            return headerValue;
        }
        if (options.clearanceCookieName.isBlank()) {
            return "";
        }
        String cookie = header(exchange.getRequestHeaders(), "Cookie");
        for (String part : cookie.split(";")) {
            String[] pieces = part.trim().split("=", 2);
            if (pieces.length == 2 && pieces[0].equals(options.clearanceCookieName)) {
                return pieces[1];
            }
        }
        return "";
    }

    private void writeClearance(HttpExchange exchange, String token, int ttlSeconds) {
        token = trim(token);
        if (token.isBlank()) {
            return;
        }
        Headers headers = exchange.getResponseHeaders();
        headers.set(options.clearanceHeader, token);
        if (options.clearanceCookieName.isBlank()) {
            return;
        }
        List<String> parts = new ArrayList<>(List.of(
                options.clearanceCookieName + "=" + token,
                "Path=/",
                "HttpOnly",
                "SameSite=Lax"
        ));
        if (options.clearanceCookieSecure) {
            parts.add("Secure");
        }
        if (ttlSeconds > 0) {
            parts.add("Max-Age=" + ttlSeconds);
        }
        headers.add("Set-Cookie", String.join("; ", parts));
    }

    private void reportDecision(PolicyEvaluateRequest request, PolicyDecision decision) {
        AuditEvent event = new AuditEvent(
                request.clientID,
                firstNonEmpty(decision.scene, request.scene),
                request.path,
                hashValue(request.ip),
                request.accountIDHash,
                request.deviceIDHash,
                decision.action,
                decision.reason,
                decision.challengeType,
                decision.action
        );
        CompletableFuture.runAsync(() -> {
            try {
                client.report(List.of(event));
            } catch (Exception ignored) {
            }
        });
    }

    private String remoteIP(HttpExchange exchange) {
        InetSocketAddress address = exchange.getRemoteAddress();
        String direct = address == null || address.getAddress() == null ? "" : address.getAddress().getHostAddress();
        if (direct.isBlank() || trustedProxies.isEmpty()) {
            return direct;
        }
        if (!trustedProxies.stream().anyMatch(cidr -> cidr.contains(direct))) {
            return direct;
        }
        for (String part : header(exchange.getRequestHeaders(), "X-Forwarded-For").split(",")) {
            String candidate = part.trim();
            if (isIPv4(candidate)) {
                return candidate;
            }
        }
        return direct;
    }

    private String absoluteChallengeURL(String challengeURL) {
        challengeURL = trim(challengeURL);
        if (challengeURL.isBlank()) {
            return "";
        }
        String lowered = challengeURL.toLowerCase(Locale.ROOT);
        if (lowered.startsWith("http://") || lowered.startsWith("https://")) {
            return challengeURL;
        }
        if (challengeURL.startsWith("/")) {
            return options.platformURL.replaceAll("/+$", "") + challengeURL;
        }
        return options.platformURL.replaceAll("/+$", "") + "/" + challengeURL;
    }

    public static final class Options {
        public String platformURL;
        public String clientID = "demo";
        public String clientSecret = "";
        public String ticketHeader = "X-Captcha-Ticket";
        public String clearanceHeader = "X-Captcha-Clearance";
        public String clearanceCookieName = "captcha_clearance";
        public boolean clearanceCookieSecure = false;
        public String requestNonceHeader = "X-Captcha-Request-Nonce";
        public String resourceTagHeader = "X-Captcha-Resource-Tag";
        public String accountIDHashHeader = "X-Captcha-Account-ID-Hash";
        public String deviceIDHashHeader = "X-Captcha-Device-ID-Hash";
        public String riskScoreHeader = "X-Captcha-Risk-Score";
        public String riskLevelHeader = "X-Captcha-Risk-Level";
        public String modelScoreHeader = "X-Captcha-Model-Score";
        public String modelModeHeader = "X-Captcha-Model-Mode";
        public String sceneHeader = "X-Captcha-Scene";
        public String failPolicy = "fail_open";
        public Duration timeout = Duration.ofMillis(1500);
        public int circuitBreakerFailureThreshold = 0;
        public Duration circuitBreakerCooldown = Duration.ZERO;
        public List<String> trustedProxyCIDRs = List.of();
        public List<String> headerAllowlist = List.of();
        public Predicate<HttpExchange> shouldProtect;
        public Function<HttpExchange, String> resolveScene;
        public Function<HttpExchange, String> resolveAccountIDHash;
        public Function<HttpExchange, String> resolveDeviceIDHash;
        public PlatformClient platformClient;

        private Options withDefaults() {
            if (platformURL == null || platformURL.isBlank()) {
                throw new IllegalArgumentException("platformURL is required");
            }
            platformURL = platformURL.replaceAll("/+$", "");
            clientID = firstNonEmpty(clientID, "demo");
            clientSecret = firstNonEmpty(clientSecret, "");
            failPolicy = firstNonEmpty(failPolicy, "fail_open");
            timeout = timeout == null || timeout.isNegative() || timeout.isZero() ? Duration.ofMillis(1500) : timeout;
            circuitBreakerCooldown = circuitBreakerCooldown == null ? Duration.ZERO : circuitBreakerCooldown;
            trustedProxyCIDRs = trustedProxyCIDRs == null ? List.of() : trustedProxyCIDRs;
            headerAllowlist = headerAllowlist == null ? List.of() : headerAllowlist;
            return this;
        }
    }

    public interface PlatformClient {
        PolicyDecision evaluate(PolicyEvaluateRequest request) throws IOException, InterruptedException;
        TicketConsumeResponse consume(TicketConsumeRequest request) throws IOException, InterruptedException;
        ReportResult report(List<AuditEvent> events) throws IOException, InterruptedException;
    }

    public static final class HTTPPlatformClient implements PlatformClient {
        private final String platformURL;
        private final String clientSecret;
        private final Duration timeout;
        private final HttpClient client;

        public HTTPPlatformClient(String platformURL, String clientSecret, Duration timeout) {
            this.platformURL = Objects.requireNonNull(platformURL).replaceAll("/+$", "");
            this.clientSecret = firstNonEmpty(clientSecret, "");
            this.timeout = timeout == null ? Duration.ofMillis(1500) : timeout;
            this.client = HttpClient.newBuilder()
                    .connectTimeout(this.timeout)
                    .build();
        }

        @Override
        public PolicyDecision evaluate(PolicyEvaluateRequest request) throws IOException, InterruptedException {
            String body = postJSON("/api/v1/policy/evaluate", request.toJSON());
            return PolicyDecision.fromJSON(body);
        }

        @Override
        public TicketConsumeResponse consume(TicketConsumeRequest request) throws IOException, InterruptedException {
            String body = postJSON("/api/v1/tickets/verify", request.toJSON());
            return TicketConsumeResponse.fromJSON(body);
        }

        @Override
        public ReportResult report(List<AuditEvent> events) throws IOException, InterruptedException {
            StringJoiner joiner = new StringJoiner(",", "{\"events\":[", "]}");
            for (AuditEvent event : events) {
                joiner.add(event.toJSON());
            }
            String body = postJSON("/api/v1/events/report", joiner.toString());
            return new ReportResult(intField(body, "accepted"));
        }

        private String postJSON(String path, String body) throws IOException, InterruptedException {
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(platformURL + path))
                    .timeout(timeout)
                    .header("content-type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
            if (!clientSecret.isBlank()) {
                builder.header("x-captcha-client-secret", clientSecret);
            }
            HttpResponse<String> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IOException("platform returned status " + response.statusCode());
            }
            return response.body();
        }
    }

    public record PolicyEvaluateRequest(
            String clientID,
            String scene,
            String path,
            String method,
            String ip,
            String userAgent,
            String accountIDHash,
            String deviceIDHash,
            String ticket,
            String clearance,
            String requestNonce,
            String resourceTag,
            int riskScore,
            String riskLevel,
            int modelScore,
            String modelMode,
            Map<String, String> headers
    ) {
        String toJSON() {
            Map<String, Object> fields = orderedMap(
                    "client_id", clientID,
                    "scene", scene,
                    "path", path,
                    "method", method,
                    "ip", ip,
                    "user_agent", userAgent,
                    "account_id_hash", accountIDHash,
                    "device_id_hash", deviceIDHash,
                    "ticket", ticket,
                    "clearance", clearance,
                    "request_nonce", requestNonce,
                    "resource_tag", resourceTag,
                    "risk_score", riskScore,
                    "risk_level", riskLevel,
                    "model_score", modelScore,
                    "model_mode", modelMode,
                    "headers", headers
            );
            return jsonObject(fields);
        }
    }

    public record PolicyDecision(
            String action,
            String reason,
            String challengeURL,
            String sessionID,
            String scene,
            String challengeType,
            int ttlSeconds,
            int cooldownSeconds,
            String businessVerifyType,
            String clearanceToken,
            int clearanceTTLSeconds
    ) {
        static PolicyDecision fromJSON(String json) {
            return new PolicyDecision(
                    stringField(json, "action"),
                    stringField(json, "reason"),
                    stringField(json, "challenge_url"),
                    stringField(json, "session_id"),
                    stringField(json, "scene"),
                    stringField(json, "challenge_type"),
                    intField(json, "ttl_seconds"),
                    intField(json, "cooldown_seconds"),
                    stringField(json, "business_verify_type"),
                    stringField(json, "clearance_token"),
                    intField(json, "clearance_ttl_seconds")
            );
        }
    }

    public record TicketConsumeRequest(
            String ticket,
            String clientID,
            String scene,
            String route,
            String requestNonce,
            String ipHash,
            String userAgentHash,
            String accountIDHash,
            String deviceIDHash
    ) {
        String toJSON() {
            return jsonObject(orderedMap(
                    "ticket", ticket,
                    "client_id", clientID,
                    "scene", scene,
                    "route", route,
                    "request_nonce", requestNonce,
                    "ip_hash", ipHash,
                    "user_agent_hash", userAgentHash,
                    "account_id_hash", accountIDHash,
                    "device_id_hash", deviceIDHash,
                    "consume", true
            ));
        }
    }

    public record TicketConsumeResponse(
            boolean valid,
            String reason,
            String scene,
            String clearanceToken,
            int clearanceTTLSeconds
    ) {
        static TicketConsumeResponse fromJSON(String json) {
            return new TicketConsumeResponse(
                    boolField(json, "valid"),
                    stringField(json, "reason"),
                    stringField(json, "scene"),
                    stringField(json, "clearance_token"),
                    intField(json, "clearance_ttl_seconds")
            );
        }
    }

    public record AuditEvent(
            String clientID,
            String scene,
            String route,
            String ipHash,
            String accountIDHash,
            String deviceIDHash,
            String action,
            String decisionReason,
            String challengeType,
            String result
    ) {
        String toJSON() {
            return jsonObject(orderedMap(
                    "client_id", clientID,
                    "scene", scene,
                    "route", route,
                    "ip_hash", ipHash,
                    "account_id_hash", accountIDHash,
                    "device_id_hash", deviceIDHash,
                    "action", action,
                    "decision_reason", decisionReason,
                    "challenge_type", challengeType,
                    "result", result
            ));
        }
    }

    public record ReportResult(int accepted) {}

    private static final class CircuitBreaker {
        private final int threshold;
        private final Duration cooldown;
        private int failures;
        private Instant openUntil = Instant.EPOCH;

        CircuitBreaker(int threshold, Duration cooldown) {
            this.threshold = threshold;
            this.cooldown = cooldown == null ? Duration.ZERO : cooldown;
        }

        synchronized boolean allow() {
            if (!enabled()) {
                return true;
            }
            return Instant.now().isAfter(openUntil);
        }

        synchronized void recordSuccess() {
            if (!enabled()) {
                return;
            }
            failures = 0;
            openUntil = Instant.EPOCH;
        }

        synchronized void recordFailure() {
            if (!enabled()) {
                return;
            }
            failures++;
            if (failures >= threshold) {
                failures = 0;
                openUntil = Instant.now().plus(cooldown);
            }
        }

        private boolean enabled() {
            return threshold > 0 && !cooldown.isZero() && !cooldown.isNegative();
        }
    }

    private record CIDR(int address, int prefix) {
        boolean contains(String ip) {
            if (!isIPv4(ip)) {
                return false;
            }
            int value = ipv4ToInt(ip);
            int mask = prefix == 0 ? 0 : (int) (0xffffffffL << (32 - prefix));
            return (value & mask) == (address & mask);
        }
    }

    private static List<CIDR> parseCIDRs(List<String> values) {
        List<CIDR> out = new ArrayList<>();
        for (String value : values) {
            if (value == null || value.isBlank()) {
                continue;
            }
            String[] parts = value.trim().split("/", 2);
            if (!isIPv4(parts[0])) {
                continue;
            }
            int prefix = parts.length == 2 ? Integer.parseInt(parts[1]) : 32;
            out.add(new CIDR(ipv4ToInt(parts[0]), Math.max(0, Math.min(32, prefix))));
        }
        return out;
    }

    private static String header(Headers headers, String name) {
        if (name == null || name.isBlank()) {
            return "";
        }
        List<String> values = headers.get(name);
        if (values == null || values.isEmpty()) {
            return "";
        }
        return String.join(",", values).trim();
    }

    private static Map<String, String> collectAllowedHeaders(Headers headers, List<String> allowlist) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String name : allowlist) {
            String normalized = trim(name).toLowerCase(Locale.ROOT);
            if (normalized.isBlank()) {
                continue;
            }
            String value = header(headers, name);
            if (!value.isBlank()) {
                out.put(normalized, value);
            }
        }
        return out;
    }

    private static int intHeader(Headers headers, String name) {
        try {
            return Math.min(100, Math.max(0, Integer.parseInt(header(headers, name))));
        } catch (NumberFormatException error) {
            return 0;
        }
    }

    private static String sceneFromPath(String path) {
        String trimmed = trim(path).replaceAll("^/+|/+$", "");
        if (trimmed.isBlank()) {
            return "default";
        }
        int slash = trimmed.indexOf('/');
        return slash >= 0 ? trimmed.substring(0, slash) : trimmed;
    }

    private static void writeJSON(HttpExchange exchange, int status, Map<String, ?> body) throws IOException {
        byte[] payload = jsonObject(body).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("content-type", "application/json");
        exchange.sendResponseHeaders(status, payload.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(payload);
        }
    }

    private static Map<String, Object> orderedMap(Object... pairs) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int index = 0; index + 1 < pairs.length; index += 2) {
            out.put(String.valueOf(pairs[index]), pairs[index + 1]);
        }
        return out;
    }

    private static String jsonObject(Map<String, ?> fields) {
        StringJoiner joiner = new StringJoiner(",", "{", "}");
        for (Map.Entry<String, ?> entry : fields.entrySet()) {
            Object value = entry.getValue();
            if (value == null || value.equals("") || value.equals(0) || (value instanceof Map<?, ?> map && map.isEmpty())) {
                continue;
            }
            joiner.add(quote(entry.getKey()) + ":" + jsonValue(value));
        }
        return joiner.toString();
    }

    private static String jsonValue(Object value) {
        if (value instanceof Boolean || value instanceof Number) {
            return String.valueOf(value);
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> typed = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                typed.put(String.valueOf(entry.getKey()), entry.getValue());
            }
            return jsonObject(typed);
        }
        return quote(String.valueOf(value));
    }

    private static String quote(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (char ch : firstNonEmpty(value, "").toCharArray()) {
            switch (ch) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> out.append(ch);
            }
        }
        return out.append('"').toString();
    }

    private static String stringField(String json, String key) {
        Matcher matcher = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"").matcher(json);
        return matcher.find() ? unescape(matcher.group(1)) : "";
    }

    private static int intField(String json, String key) {
        Matcher matcher = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(-?\\d+)").matcher(json);
        if (!matcher.find()) {
            return 0;
        }
        return Integer.parseInt(matcher.group(1));
    }

    private static boolean boolField(String json, String key) {
        Matcher matcher = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(true|false)").matcher(json);
        return matcher.find() && Boolean.parseBoolean(matcher.group(1));
    }

    private static String unescape(String value) {
        return value.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t");
    }

    private static String hashValue(String value) {
        value = trim(value);
        if (value.isBlank()) {
            return "";
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder out = new StringBuilder("sha256:");
            for (int index = 0; index < 16; index++) {
                out.append(String.format("%02x", digest[index]));
            }
            return out.toString();
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException(error);
        }
    }

    private static boolean isIPv4(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        try {
            InetAddress address = InetAddress.getByName(value);
            return address.getHostAddress().equals(value) && value.split("\\.").length == 4;
        } catch (Exception error) {
            return false;
        }
    }

    private static int ipv4ToInt(String value) {
        String[] parts = value.split("\\.");
        int out = 0;
        for (String part : parts) {
            out = (out << 8) | Integer.parseInt(part);
        }
        return out;
    }

    private static String firstNonEmpty(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return "";
    }

    private static String trim(String value) {
        return value == null ? "" : value.trim();
    }
}

package captcha.middleware;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public final class CaptchaMiddlewareSmokeTest {
    public static void main(String[] args) throws Exception {
        testAllowsRequestWhenPlatformAllows();
        testConsumesTicketBeforePolicyEvaluation();
        testReturnsChallengeDetails();
        testBlocksUnsupportedPolicyDecision();
        testBlocksInvalidTicketWithoutPolicyFallback();
        testIgnoresForgedForwardedForFromUntrustedPeer();
        testFailCloseAndCircuitBreaker();
        System.out.println("PASS: CaptCha Java middleware smoke tests");
    }

    private static void testAllowsRequestWhenPlatformAllows() throws Exception {
        FakePlatform platform = new FakePlatform();
        platform.policyResponse = "{\"action\":\"allow\",\"reason\":\"CLEARANCE_VALID\",\"clearance_token\":\"clearance_java\",\"clearance_ttl_seconds\":600}";
        try (RunningServer server = platform.start()) {
            CaptchaMiddleware.Options options = new CaptchaMiddleware.Options();
            options.platformURL = server.url();
            options.headerAllowlist = List.of("X-Trace-ID");
            options.clearanceCookieSecure = true;
            CaptchaMiddleware middleware = new CaptchaMiddleware(statusHandler(204), options);

            Response response = request(middleware, "/api/login", List.of(
                    "X-Captcha-Resource-Tag: campaign",
                    "X-Captcha-Account-ID-Hash: acct_hash_java",
                    "X-Captcha-Device-ID-Hash: device_hash_java",
                    "X-Captcha-Risk-Score: 77",
                    "X-Captcha-Risk-Level: high",
                    "X-Captcha-Model-Score: 88",
                    "X-Captcha-Model-Mode: observe",
                    "X-Trace-ID: trace-java",
                    "Authorization: Bearer should-not-forward"
            ));

            assertEquals(204, response.status, "allow status");
            assertEquals("clearance_java", response.header("X-Captcha-Clearance"), "clearance header");
            assertContains(response.header("Set-Cookie"), "captcha_clearance=clearance_java", "clearance cookie");
            assertContains(response.header("Set-Cookie"), "Secure", "secure clearance cookie");
            assertEquals(1, platform.policyRequests.size(), "policy request count");
            String evaluated = platform.policyRequests.get(0);
            assertContains(evaluated, "\"scene\":\"api\"", "scene from path");
            assertContains(evaluated, "\"resource_tag\":\"campaign\"", "resource tag");
            assertContains(evaluated, "\"account_id_hash\":\"acct_hash_java\"", "account hash");
            assertContains(evaluated, "\"headers\":{\"x-trace-id\":\"trace-java\"}", "allowlisted header");
            assertNotContains(evaluated, "authorization", "authorization must not be forwarded");
        }
    }

    private static void testConsumesTicketBeforePolicyEvaluation() throws Exception {
        FakePlatform platform = new FakePlatform();
        platform.ticketResponse = "{\"valid\":true,\"scene\":\"login\",\"route\":\"/login\",\"clearance_token\":\"clearance_ticket_java\",\"clearance_ttl_seconds\":300}";
        try (RunningServer server = platform.start()) {
            CaptchaMiddleware.Options options = new CaptchaMiddleware.Options();
            options.platformURL = server.url();
            options.resolveScene = exchange -> "login";
            CaptchaMiddleware middleware = new CaptchaMiddleware(statusHandler(202), options);

            Response response = request(middleware, "/login", List.of(
                    "X-Captcha-Ticket: ticket_ok",
                    "X-Captcha-Request-Nonce: nonce-java",
                    "X-Captcha-Account-ID-Hash: acct_ticket_java",
                    "X-Captcha-Device-ID-Hash: device_ticket_java"
            ));
            waitFor(() -> platform.eventRequests.size() == 1);

            assertEquals(202, response.status, "ticket next status");
            assertEquals("clearance_ticket_java", response.header("X-Captcha-Clearance"), "ticket clearance header");
            assertEquals(1, platform.ticketRequests.size(), "ticket request count");
            assertEquals(0, platform.policyRequests.size(), "policy must not be called for ticket path");
            String consumed = platform.ticketRequests.get(0);
            assertContains(consumed, "\"ticket\":\"ticket_ok\"", "ticket body");
            assertContains(consumed, "\"scene\":\"login\"", "ticket scene");
            assertContains(consumed, "\"route\":\"/login\"", "ticket route");
            assertContains(consumed, "\"request_nonce\":\"nonce-java\"", "ticket nonce");
            String event = platform.eventRequests.get(0);
            assertContains(event, "\"action\":\"allow\"", "ticket event action");
            assertContains(event, "\"decision_reason\":\"TICKET_CONSUMED\"", "ticket event reason");
        }
    }

    private static void testReturnsChallengeDetails() throws Exception {
        FakePlatform platform = new FakePlatform();
        platform.policyResponse = "{\"action\":\"challenge\",\"reason\":\"ALWAYS\",\"challenge_url\":\"/challenge?session_id=cap_sess_test\",\"session_id\":\"cap_sess_test\",\"scene\":\"login\",\"challenge_type\":\"SLIDER\",\"ttl_seconds\":120}";
        try (RunningServer server = platform.start()) {
            CaptchaMiddleware.Options options = new CaptchaMiddleware.Options();
            options.platformURL = server.url();
            CaptchaMiddleware middleware = new CaptchaMiddleware(statusHandler(204), options);

            Response response = request(middleware, "/login", List.of());

            assertEquals(403, response.status, "challenge status");
            assertContains(response.body, "\"challenge_url\":\"" + server.url() + "/challenge?session_id=cap_sess_test\"", "absolute challenge url");
            assertContains(response.body, "\"challenge_type\":\"SLIDER\"", "challenge type");
        }
    }

    private static void testBlocksUnsupportedPolicyDecision() throws Exception {
        FakePlatform platform = new FakePlatform();
        platform.policyResponse = "{\"action\":\"retry\",\"reason\":\"VERIFY_RETRY\"}";
        try (RunningServer server = platform.start()) {
            CaptchaMiddleware.Options options = new CaptchaMiddleware.Options();
            options.platformURL = server.url();
            CaptchaMiddleware middleware = new CaptchaMiddleware(statusHandler(204), options);

            Response response = request(middleware, "/login", List.of());

            assertEquals(403, response.status, "unsupported decision status");
            assertContains(response.body, "\"action\":\"block\"", "unsupported decision action");
            assertContains(response.body, "\"reason\":\"UNSUPPORTED_POLICY_DECISION\"", "unsupported decision reason");
            assertEquals(1, platform.policyRequests.size(), "unsupported decision policy request count");
        }
    }

    private static void testBlocksInvalidTicketWithoutPolicyFallback() throws Exception {
        FakePlatform platform = new FakePlatform();
        platform.ticketResponse = "{\"valid\":false,\"reason\":\"CONSUMED\"}";
        try (RunningServer server = platform.start()) {
            CaptchaMiddleware.Options options = new CaptchaMiddleware.Options();
            options.platformURL = server.url();
            options.resolveScene = exchange -> "login";
            CaptchaMiddleware middleware = new CaptchaMiddleware(statusHandler(204), options);

            Response response = request(middleware, "/login", List.of(
                    "X-Captcha-Ticket: ticket_consumed"
            ));
            waitFor(() -> platform.eventRequests.size() == 1);

            assertEquals(403, response.status, "invalid ticket status");
            assertContains(response.body, "\"action\":\"block\"", "invalid ticket action");
            assertContains(response.body, "\"reason\":\"CONSUMED\"", "invalid ticket reason");
            assertEquals(0, platform.policyRequests.size(), "invalid ticket must not fall back to policy");
            assertContains(platform.eventRequests.get(0), "\"decision_reason\":\"CONSUMED\"", "invalid ticket event reason");
        }
    }

    private static void testIgnoresForgedForwardedForFromUntrustedPeer() throws Exception {
        FakePlatform platform = new FakePlatform();
        try (RunningServer server = platform.start()) {
            CaptchaMiddleware.Options options = new CaptchaMiddleware.Options();
            options.platformURL = server.url();
            options.trustedProxyCIDRs = List.of("203.0.113.0/24");
            CaptchaMiddleware middleware = new CaptchaMiddleware(statusHandler(204), options);

            Response response = request(middleware, "/login", List.of(
                    "X-Forwarded-For: 10.0.0.1"
            ));

            assertEquals(204, response.status, "untrusted forwarded-for status");
            assertContains(platform.policyRequests.get(0), "\"ip\":\"127.0.0.1\"", "direct peer ip");
            assertNotContains(platform.policyRequests.get(0), "\"ip\":\"10.0.0.1\"", "forged forwarded-for ip");
        }
    }

    private static void testFailCloseAndCircuitBreaker() throws Exception {
        FakePlatform platform = new FakePlatform();
        platform.policyStatus = 503;
        try (RunningServer server = platform.start()) {
            CaptchaMiddleware.Options options = new CaptchaMiddleware.Options();
            options.platformURL = server.url();
            options.failPolicy = "fail_close";
            options.circuitBreakerFailureThreshold = 1;
            options.circuitBreakerCooldown = Duration.ofSeconds(60);
            CaptchaMiddleware middleware = new CaptchaMiddleware(statusHandler(204), options);

            Response first = request(middleware, "/login", List.of());
            Response second = request(middleware, "/login", List.of());
            waitFor(() -> platform.eventRequests.size() == 2);

            assertEquals(503, first.status, "first fail-close status");
            assertEquals(503, second.status, "breaker fail-close status");
            assertEquals(1, platform.policyRequests.size(), "breaker skips second policy call");
            assertContains(platform.eventRequests.get(0), "\"decision_reason\":\"POLICY_UNAVAILABLE\"", "first unavailable event");
            assertContains(platform.eventRequests.get(1), "\"decision_reason\":\"POLICY_UNAVAILABLE\"", "second unavailable event");
        }
    }

    private static HttpHandler statusHandler(int status) {
        return exchange -> {
            exchange.sendResponseHeaders(status, -1);
            exchange.close();
        };
    }

    private static Response request(HttpHandler handler, String path, List<String> headers) throws Exception {
        HttpServer service = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        service.createContext("/", handler);
        service.start();
        try {
            URI uri = URI.create("http://127.0.0.1:" + service.getAddress().getPort() + path);
            HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("User-Agent", "java-test");
            for (String header : headers) {
                String[] pieces = header.split(": ", 2);
                connection.setRequestProperty(pieces[0], pieces[1]);
            }
            int status = connection.getResponseCode();
            InputStream stream = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
            String body = stream == null ? "" : new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            return new Response(status, connection.getHeaderField("X-Captcha-Clearance"), connection.getHeaderField("Set-Cookie"), body);
        } finally {
            service.stop(0);
        }
    }

    private record Response(int status, String clearance, String setCookie, String body) {
        String header(String name) {
            if ("X-Captcha-Clearance".equalsIgnoreCase(name)) {
                return clearance;
            }
            if ("Set-Cookie".equalsIgnoreCase(name)) {
                return setCookie;
            }
            return "";
        }
    }

    private static final class FakePlatform {
        volatile int policyStatus = 200;
        volatile int ticketStatus = 200;
        volatile String policyResponse = "{\"action\":\"allow\",\"reason\":\"OK\"}";
        volatile String ticketResponse = "{\"valid\":true}";
        final List<String> policyRequests = new CopyOnWriteArrayList<>();
        final List<String> ticketRequests = new CopyOnWriteArrayList<>();
        final List<String> eventRequests = new CopyOnWriteArrayList<>();

        RunningServer start() throws IOException {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                switch (exchange.getRequestURI().getPath()) {
                    case "/api/v1/policy/evaluate" -> {
                        policyRequests.add(body);
                        write(exchange, policyStatus, policyResponse);
                    }
                    case "/api/v1/tickets/verify" -> {
                        ticketRequests.add(body);
                        write(exchange, ticketStatus, ticketResponse);
                    }
                    case "/api/v1/events/report" -> {
                        eventRequests.add(body);
                        write(exchange, 200, "{\"accepted\":1}");
                    }
                    default -> write(exchange, 404, "{\"error\":\"not found\"}");
                }
            });
            server.start();
            return new RunningServer(server);
        }
    }

    private record RunningServer(HttpServer server) implements AutoCloseable {
        String url() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    private static void write(HttpExchange exchange, int status, String body) throws IOException {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("content-type", "application/json");
        exchange.sendResponseHeaders(status, payload.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(payload);
        }
    }

    private interface Condition {
        boolean ok();
    }

    private static void waitFor(Condition condition) throws InterruptedException {
        for (int i = 0; i < 200; i++) {
            if (condition.ok()) {
                return;
            }
            Thread.sleep(5);
        }
        throw new AssertionError("timed out waiting for condition");
    }

    private static void assertEquals(Object expected, Object actual, String label) {
        if (!expected.equals(actual)) {
            throw new AssertionError(label + ": expected " + expected + ", got " + actual);
        }
    }

    private static void assertContains(String value, String expected, String label) {
        if (value == null || !value.contains(expected)) {
            throw new AssertionError(label + ": expected " + expected + " in " + value);
        }
    }

    private static void assertNotContains(String value, String expected, String label) {
        if (value != null && value.contains(expected)) {
            throw new AssertionError(label + ": did not expect " + expected + " in " + value);
        }
    }
}

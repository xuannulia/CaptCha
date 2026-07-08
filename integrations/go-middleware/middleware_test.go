package captchamiddleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestAllowsRequestWhenPlatformAllows(t *testing.T) {
	recorder := newPlatformRecorder(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/policy/evaluate" {
			t.Fatalf("unexpected platform path %s", r.URL.Path)
		}
		recorder.recordPolicy(r)
		writeTestJSON(w, PolicyDecision{
			Action:              DecisionAllow,
			Reason:              "CLEARANCE_VALID",
			ClearanceToken:      "clearance_go",
			ClearanceTTLSeconds: 600,
		})
	}))
	defer server.Close()

	middleware, err := New(Options{
		PlatformURL:           server.URL,
		HeaderAllowlist:       []string{"x-trace-id"},
		ClearanceHeader:       "X-Captcha-Clearance",
		SceneHeader:           "X-Captcha-Scene",
		ResolveScene:          nil,
		ClearanceCookieSecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	middleware.Handler(statusHandler(http.StatusNoContent)).ServeHTTP(response, request("POST", "/api/login", map[string]string{
		"X-Captcha-Resource-Tag":    "campaign",
		"X-Captcha-Account-ID-Hash": "acct_hash_go",
		"X-Captcha-Device-ID-Hash":  "device_hash_go",
		"X-Captcha-Risk-Score":      "77",
		"X-Captcha-Risk-Level":      "high",
		"X-Captcha-Model-Score":     "88",
		"X-Captcha-Model-Mode":      "observe",
		"X-Trace-ID":                "trace-go",
		"Authorization":             "Bearer should-not-forward",
	}))

	if response.Code != http.StatusNoContent {
		t.Fatalf("expected next handler status 204, got %d", response.Code)
	}
	if response.Header().Get("X-Captcha-Clearance") != "clearance_go" {
		t.Fatalf("expected clearance header, got %q", response.Header().Get("X-Captcha-Clearance"))
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "captcha_clearance" || cookies[0].Value != "clearance_go" {
		t.Fatalf("expected clearance cookie, got %#v", cookies)
	}
	if !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].MaxAge != 600 {
		t.Fatalf("unexpected clearance cookie attributes: %#v", cookies[0])
	}

	policies := recorder.policies()
	if len(policies) != 1 {
		t.Fatalf("expected one policy request, got %d", len(policies))
	}
	evaluated := policies[0]
	if evaluated.Scene != "api" || evaluated.ResourceTag != "campaign" {
		t.Fatalf("unexpected scene/resource tag: %#v", evaluated)
	}
	if evaluated.AccountIDHash != "acct_hash_go" || evaluated.DeviceIDHash != "device_hash_go" {
		t.Fatalf("unexpected subject hashes: %#v", evaluated)
	}
	if evaluated.RiskScore != 77 || evaluated.RiskLevel != "high" || evaluated.ModelScore != 88 || evaluated.ModelMode != "observe" {
		t.Fatalf("unexpected risk/model context: %#v", evaluated)
	}
	if evaluated.Headers["x-trace-id"] != "trace-go" {
		t.Fatalf("expected allowlisted trace header, got %#v", evaluated.Headers)
	}
	if _, ok := evaluated.Headers["authorization"]; ok {
		t.Fatalf("authorization header must not be forwarded: %#v", evaluated.Headers)
	}
}

func TestConsumesTicketBeforePolicyEvaluation(t *testing.T) {
	recorder := newPlatformRecorder(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/tickets/verify":
			recorder.recordTicket(r)
			writeTestJSON(w, TicketConsumeResponse{
				Valid:               true,
				ClientID:            "demo",
				Scene:               "login",
				Route:               "/login",
				ClearanceToken:      "clearance_ticket_go",
				ClearanceTTLSeconds: 300,
			})
		case "/api/v1/events/report":
			recorder.recordEvents(r)
			writeTestJSON(w, ReportResult{Accepted: 1})
		default:
			t.Fatalf("unexpected platform path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	middleware, err := New(Options{
		PlatformURL:  server.URL,
		ResolveScene: func(*http.Request) string { return "login" },
	})
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	middleware.Handler(statusHandler(http.StatusAccepted)).ServeHTTP(response, request("POST", "/login", map[string]string{
		"X-Captcha-Ticket":          "ticket_ok",
		"X-Captcha-Request-Nonce":   "nonce-go",
		"X-Captcha-Account-ID-Hash": "acct_ticket_go",
		"X-Captcha-Device-ID-Hash":  "device_ticket_go",
	}))

	if response.Code != http.StatusAccepted {
		t.Fatalf("expected next handler status 202, got %d", response.Code)
	}
	if response.Header().Get("X-Captcha-Clearance") != "clearance_ticket_go" {
		t.Fatalf("expected clearance header, got %q", response.Header().Get("X-Captcha-Clearance"))
	}
	waitFor(t, func() bool { return len(recorder.events()) == 1 })

	tickets := recorder.tickets()
	if len(tickets) != 1 {
		t.Fatalf("expected one ticket consume request, got %d", len(tickets))
	}
	consumed := tickets[0]
	if !consumed.Consume || consumed.Ticket != "ticket_ok" || consumed.ClientID != "demo" || consumed.Scene != "login" || consumed.Route != "/login" {
		t.Fatalf("unexpected ticket request: %#v", consumed)
	}
	if consumed.RequestNonce != "nonce-go" {
		t.Fatalf("expected request nonce, got %q", consumed.RequestNonce)
	}
	if consumed.IPHash != hashValue("198.51.100.9") || consumed.UserAgentHash != hashValue("go-test") {
		t.Fatalf("unexpected bind hashes: %#v", consumed)
	}
	if len(recorder.policies()) != 0 {
		t.Fatalf("ticket path must not call policy evaluate")
	}
	events := recorder.events()
	if events[0].Action != DecisionAllow || events[0].DecisionReason != "TICKET_CONSUMED" || events[0].Scene != "login" {
		t.Fatalf("unexpected event: %#v", events[0])
	}
	if events[0].AccountIDHash != "acct_ticket_go" || events[0].DeviceIDHash != "device_ticket_go" {
		t.Fatalf("unexpected event subject hashes: %#v", events[0])
	}
}

func TestBlocksInvalidTicket(t *testing.T) {
	recorder := newPlatformRecorder(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/tickets/verify":
			recorder.recordTicket(r)
			writeTestJSON(w, TicketConsumeResponse{Valid: false, Reason: "CONSUMED"})
		case "/api/v1/events/report":
			recorder.recordEvents(r)
			writeTestJSON(w, ReportResult{Accepted: 1})
		default:
			t.Fatalf("unexpected platform path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	middleware, err := New(Options{
		PlatformURL:  server.URL,
		ResolveScene: func(*http.Request) string { return "login" },
	})
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	middleware.Handler(statusHandler(http.StatusNoContent)).ServeHTTP(response, request("POST", "/login", map[string]string{
		"X-Captcha-Ticket": "ticket_consumed",
	}))

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["action"] != string(DecisionBlock) || body["reason"] != "CONSUMED" {
		t.Fatalf("unexpected response body: %#v", body)
	}
	waitFor(t, func() bool { return len(recorder.events()) == 1 })
	if recorder.events()[0].DecisionReason != "CONSUMED" {
		t.Fatalf("unexpected event: %#v", recorder.events()[0])
	}
}

func TestReturnsChallengeDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, PolicyDecision{
			Action:        DecisionChallenge,
			Reason:        "ALWAYS",
			ChallengeURL:  "/challenge?session_id=cap_sess_test",
			SessionID:     "cap_sess_test",
			Scene:         "login",
			ChallengeType: "SLIDER",
			TTLSeconds:    120,
		})
	}))
	defer server.Close()

	middleware, err := New(Options{PlatformURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	middleware.Handler(statusHandler(http.StatusNoContent)).ServeHTTP(response, request("POST", "/login", nil))

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["challenge_url"] != server.URL+"/challenge?session_id=cap_sess_test" || body["challenge_type"] != "SLIDER" {
		t.Fatalf("unexpected challenge body: %#v", body)
	}
}

func TestBlocksUnsupportedPolicyDecision(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, PolicyDecision{Action: DecisionRetry, Reason: "VERIFY_RETRY"})
	}))
	defer server.Close()

	middleware, err := New(Options{PlatformURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	middleware.Handler(statusHandler(http.StatusNoContent)).ServeHTTP(response, request("POST", "/login", nil))

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected unsupported decision to block, got %d", response.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["action"] != string(DecisionBlock) || body["reason"] != "UNSUPPORTED_POLICY_DECISION" {
		t.Fatalf("unexpected unsupported decision body: %#v", body)
	}
}

func TestSendsClientSecretAndTrustsConfiguredProxy(t *testing.T) {
	recorder := newPlatformRecorder(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Captcha-Client-Secret") != "cap_secret_go" {
			t.Fatalf("expected client secret header, got %q", r.Header.Get("X-Captcha-Client-Secret"))
		}
		recorder.recordPolicy(r)
		writeTestJSON(w, PolicyDecision{Action: DecisionAllow, Reason: "OK"})
	}))
	defer server.Close()

	middleware, err := New(Options{
		PlatformURL:       server.URL,
		ClientSecret:      "cap_secret_go",
		TrustedProxyCIDRs: []string{"198.51.100.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	middleware.Handler(statusHandler(http.StatusNoContent)).ServeHTTP(response, request("POST", "/login", map[string]string{
		"X-Forwarded-For": "203.0.113.7, 198.51.100.9",
	}))

	policies := recorder.policies()
	if len(policies) != 1 {
		t.Fatalf("expected one policy request, got %d", len(policies))
	}
	if policies[0].IP != "203.0.113.7" {
		t.Fatalf("expected forwarded ip, got %q", policies[0].IP)
	}
}

func TestIgnoresForgedForwardedForFromUntrustedPeer(t *testing.T) {
	recorder := newPlatformRecorder(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.recordPolicy(r)
		writeTestJSON(w, PolicyDecision{Action: DecisionAllow, Reason: "OK"})
	}))
	defer server.Close()

	middleware, err := New(Options{
		PlatformURL:       server.URL,
		TrustedProxyCIDRs: []string{"203.0.113.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	middleware.Handler(statusHandler(http.StatusNoContent)).ServeHTTP(response, request("POST", "/login", map[string]string{
		"X-Forwarded-For": "10.0.0.1",
	}))

	policies := recorder.policies()
	if len(policies) != 1 {
		t.Fatalf("expected one policy request, got %d", len(policies))
	}
	if policies[0].IP != "198.51.100.9" {
		t.Fatalf("forged forwarded-for should be ignored, got %q", policies[0].IP)
	}
}

func TestFailsOpenByDefaultAndFailsClosedWhenConfigured(t *testing.T) {
	response := httptest.NewRecorder()
	openServer := failingPlatform(t, nil)
	defer openServer.Close()
	openMiddleware, err := New(Options{PlatformURL: openServer.URL})
	if err != nil {
		t.Fatal(err)
	}
	openMiddleware.Handler(statusHandler(http.StatusNoContent)).ServeHTTP(response, request("POST", "/login", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("expected fail-open next status 204, got %d", response.Code)
	}

	recorder := newPlatformRecorder(t)
	server := failingPlatform(t, recorder)
	defer server.Close()
	closeMiddleware, err := New(Options{
		PlatformURL: server.URL,
		FailPolicy:  "fail_close",
	})
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	closeMiddleware.Handler(statusHandler(http.StatusNoContent)).ServeHTTP(response, request("POST", "/login", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected fail-close 503, got %d", response.Code)
	}
	waitFor(t, func() bool { return len(recorder.events()) == 1 })
	if recorder.events()[0].Action != DecisionBlock || recorder.events()[0].DecisionReason != "POLICY_UNAVAILABLE" {
		t.Fatalf("unexpected fail-close event: %#v", recorder.events()[0])
	}
}

func TestCircuitBreakerSkipsPlatformCallDuringCooldown(t *testing.T) {
	recorder := newPlatformRecorder(t)
	server := failingPlatform(t, recorder)
	defer server.Close()

	middleware, err := New(Options{
		PlatformURL:                    server.URL,
		CircuitBreakerFailureThreshold: 1,
		CircuitBreakerCooldown:         time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		response := httptest.NewRecorder()
		middleware.Handler(statusHandler(http.StatusNoContent)).ServeHTTP(response, request("POST", "/login", nil))
		if response.Code != http.StatusNoContent {
			t.Fatalf("request %d expected fail-open status 204, got %d", i, response.Code)
		}
	}
	waitFor(t, func() bool { return len(recorder.events()) == 2 })
	if len(recorder.policies()) != 1 {
		t.Fatalf("expected one real policy call before breaker opened, got %d", len(recorder.policies()))
	}
}

func statusHandler(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	})
}

func request(method, path string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(method, "http://service.local"+path, nil)
	req.RemoteAddr = "198.51.100.9:12345"
	req.Header.Set("User-Agent", "go-test")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return req
}

func failingPlatform(t *testing.T, recorder *platformRecorder) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/policy/evaluate":
			if recorder != nil {
				recorder.recordPolicy(r)
			}
			http.Error(w, "offline", http.StatusServiceUnavailable)
		case "/api/v1/events/report":
			if recorder != nil {
				recorder.recordEvents(r)
			}
			writeTestJSON(w, ReportResult{Accepted: 1})
		default:
			t.Fatalf("unexpected platform path %s", r.URL.Path)
		}
	}))
}

type platformRecorder struct {
	t      *testing.T
	mu     sync.Mutex
	policy []PolicyEvaluateRequest
	ticket []TicketConsumeRequest
	event  []AuditEvent
}

func newPlatformRecorder(t *testing.T) *platformRecorder {
	return &platformRecorder{t: t}
}

func (r *platformRecorder) recordPolicy(request *http.Request) {
	r.t.Helper()
	var body PolicyEvaluateRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		r.t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policy = append(r.policy, body)
}

func (r *platformRecorder) recordTicket(request *http.Request) {
	r.t.Helper()
	var body TicketConsumeRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		r.t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ticket = append(r.ticket, body)
}

func (r *platformRecorder) recordEvents(request *http.Request) {
	r.t.Helper()
	var body struct {
		Events []AuditEvent `json:"events"`
	}
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		r.t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.event = append(r.event, body.Events...)
}

func (r *platformRecorder) policies() []PolicyEvaluateRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]PolicyEvaluateRequest(nil), r.policy...)
}

func (r *platformRecorder) tickets() []TicketConsumeRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]TicketConsumeRequest(nil), r.ticket...)
}

func (r *platformRecorder) events() []AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]AuditEvent(nil), r.event...)
}

func writeTestJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		panic(err)
	}
}

func waitFor(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for condition")
}

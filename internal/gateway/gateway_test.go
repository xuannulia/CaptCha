package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"captcha/internal/engine"
	"captcha/internal/grpcserver"
	"captcha/internal/policy"
	"captcha/internal/routepolicy"
	clientsecret "captcha/internal/secret"
	"captcha/internal/store"
	"captcha/internal/types"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type fakePolicyClient struct {
	decision types.PolicyDecision
	err      error
	request  types.PolicyEvaluateRequest
	calls    int
}

type fakeTicketClient struct {
	response types.TicketVerifyResponse
	err      error
	request  types.TicketVerifyRequest
	calls    int
}

type fakeEventClient struct {
	events chan []types.AuditEvent
}

type blockingEventClient struct {
	started chan struct{}
	release chan struct{}
}

func (c *fakePolicyClient) Evaluate(_ context.Context, req types.PolicyEvaluateRequest) (types.PolicyDecision, error) {
	c.calls++
	c.request = req
	return c.decision, c.err
}

func (c *fakeTicketClient) Consume(_ context.Context, req types.TicketVerifyRequest) (types.TicketVerifyResponse, error) {
	c.calls++
	c.request = req
	return c.response, c.err
}

func newFakeEventClient() *fakeEventClient {
	return &fakeEventClient{events: make(chan []types.AuditEvent, 4)}
}

func (c *fakeEventClient) Report(_ context.Context, events []types.AuditEvent) (types.ReportResult, error) {
	c.events <- events
	return types.ReportResult{Accepted: len(events)}, nil
}

func newBlockingEventClient() *blockingEventClient {
	return &blockingEventClient{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
}

func (c *blockingEventClient) Report(ctx context.Context, events []types.AuditEvent) (types.ReportResult, error) {
	select {
	case c.started <- struct{}{}:
	default:
	}
	select {
	case <-c.release:
		return types.ReportResult{Accepted: len(events)}, nil
	case <-ctx.Done():
		return types.ReportResult{}, ctx.Err()
	}
}

func TestGatewayChallengesBeforeProxy(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("upstream should not be reached when challenge is required")
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{
		Action:        types.DecisionChallenge,
		Reason:        "ALWAYS",
		ChallengeURL:  "/challenge/cap_sess_test",
		SessionID:     "cap_sess_test",
		Scene:         "login",
		ChallengeType: types.CaptchaSlider,
		TTLSeconds:    120,
	}}
	gateway, err := NewWithPolicyClient(Config{
		ClientID:        "demo",
		PlatformURL:     "http://platform.local",
		UpstreamURL:     upstream.URL,
		HeaderAllowlist: []string{"X-Trace-ID"},
		RequestTimeout:  time.Second,
	}, policy, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	req.RemoteAddr = "198.51.100.9:12345"
	req.Header.Set("X-Captcha-Resource-Tag", "campaign")
	req.Header.Set("X-Captcha-Account-ID-Hash", "acct_hash_gateway")
	req.Header.Set("X-Captcha-Device-ID-Hash", "device_hash_gateway")
	req.Header.Set("X-Captcha-Risk-Score", "77")
	req.Header.Set("X-Captcha-Risk-Level", "high")
	req.Header.Set("X-Captcha-Model-Score", "88")
	req.Header.Set("X-Captcha-Model-Mode", "observe")
	req.Header.Set("X-Trace-ID", "trace-gateway")
	req.Header.Set("Authorization", "Bearer should-not-forward")
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden challenge, got %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Action       types.Decision `json:"action"`
		ChallengeURL string         `json:"challenge_url"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Action != types.DecisionChallenge || body.ChallengeURL != "http://platform.local/challenge/cap_sess_test" {
		t.Fatalf("unexpected challenge body: %+v", body)
	}
	if policy.request.IP != "198.51.100.9" || policy.request.Path != "/api/login" || policy.request.ResourceTag != "campaign" || policy.request.AccountIDHash != "acct_hash_gateway" || policy.request.DeviceIDHash != "device_hash_gateway" {
		t.Fatalf("unexpected policy request: %+v", policy.request)
	}
	if policy.request.RiskScore != 77 || policy.request.RiskLevel != "high" || policy.request.ModelScore != 88 || policy.request.ModelMode != "observe" {
		t.Fatalf("unexpected policy risk context: %+v", policy.request)
	}
	if policy.request.Headers["x-trace-id"] != "trace-gateway" || policy.request.Headers["authorization"] != "" {
		t.Fatalf("unexpected allowlisted headers: %+v", policy.request.Headers)
	}
}

func TestGatewayAllowsProxyWhenPolicyAllows(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Captcha-Ticket") != "ticket_ok" {
			t.Fatalf("ticket header was not preserved")
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("proxied"))
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionAllow, Reason: "TICKET_CONSUMED"}}
	gateway, err := NewWithPolicyClient(Config{
		ClientID:       "demo",
		PlatformURL:    "http://platform.local",
		UpstreamURL:    upstream.URL,
		RequestTimeout: time.Second,
	}, policy, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	req.Header.Set("X-Captcha-Ticket", "ticket_ok")
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted || rec.Body.String() != "proxied" {
		t.Fatalf("expected proxied response, got %d %q", rec.Code, rec.Body.String())
	}
	if policy.request.Ticket != "ticket_ok" {
		t.Fatalf("expected policy request ticket, got %+v", policy.request)
	}
}

func TestGatewayForwardsClearanceToPolicy(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("clearance-proxied"))
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionAllow, Reason: "CLEARANCE_VALID", ClearanceToken: "clearance_refreshed", ClearanceTTLSeconds: 300}}
	gateway, err := NewWithPolicyClient(Config{
		ClientID:       "demo",
		PlatformURL:    "http://platform.local",
		UpstreamURL:    upstream.URL,
		RequestTimeout: time.Second,
	}, policy, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	req.AddCookie(&http.Cookie{Name: "captcha_clearance", Value: "clearance_cookie"})
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted || rec.Body.String() != "clearance-proxied" {
		t.Fatalf("expected proxied response, got %d %q", rec.Code, rec.Body.String())
	}
	if policy.request.Clearance != "clearance_cookie" {
		t.Fatalf("expected policy request clearance, got %+v", policy.request)
	}
	if rec.Header().Get("X-Captcha-Clearance") != "clearance_refreshed" {
		t.Fatalf("expected refreshed clearance header, got %q", rec.Header().Get("X-Captcha-Clearance"))
	}
}

func TestGatewayConsumesTicketBeforePolicy(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("ticket-proxied"))
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionBlock, Reason: "SHOULD_NOT_CALL"}}
	ticket := &fakeTicketClient{response: types.TicketVerifyResponse{Valid: true, ClientID: "demo", Scene: "login", Route: "/api/login", ClearanceToken: "clearance_gateway", ClearanceTTLSeconds: 600}}
	events := newFakeEventClient()
	gateway, err := NewWithClientsAndEvent(Config{
		ClientID:       "demo",
		PlatformURL:    "http://platform.local",
		UpstreamURL:    upstream.URL,
		RequestTimeout: time.Second,
	}, policy, ticket, events, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	gateway.cache = NewConfigCache("demo")
	gateway.cache.Update(types.ConfigSnapshot{
		ClientID: "demo",
		Version:  1,
		Routes: []types.RoutePolicy{
			{ClientID: "demo", PathPattern: "/api/login", Method: http.MethodPost, Scene: "login", Enabled: true},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	req.Header.Set("X-Captcha-Ticket", "ticket_ok")
	req.Header.Set("X-Captcha-Request-Nonce", "nonce-gateway")
	req.Header.Set("X-Captcha-Account-ID-Hash", "acct_gateway")
	req.Header.Set("X-Captcha-Device-ID-Hash", "device_gateway")
	req.Header.Set("User-Agent", "gateway-test")
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted || rec.Body.String() != "ticket-proxied" {
		t.Fatalf("expected ticket proxy response, got %d %q", rec.Code, rec.Body.String())
	}
	if ticket.calls != 1 {
		t.Fatalf("expected one ticket consume call, got %d", ticket.calls)
	}
	if ticket.request.Scene != "login" || ticket.request.Route != "/api/login" || ticket.request.Ticket != "ticket_ok" || ticket.request.RequestNonce != "nonce-gateway" || ticket.request.IPHash != hashValue("192.0.2.1") || ticket.request.UserAgentHash != hashValue("gateway-test") || ticket.request.AccountIDHash != "acct_gateway" || ticket.request.DeviceIDHash != "device_gateway" {
		t.Fatalf("unexpected ticket request: %+v", ticket.request)
	}
	if rec.Header().Get("X-Captcha-Clearance") != "clearance_gateway" {
		t.Fatalf("expected clearance response header, got %q", rec.Header().Get("X-Captcha-Clearance"))
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 1 || cookies[0].Name != "captcha_clearance" || cookies[0].Value != "clearance_gateway" || !cookies[0].HttpOnly || cookies[0].MaxAge != 600 {
		t.Fatalf("expected clearance cookie, got %+v", cookies)
	}
	if policy.calls != 0 {
		t.Fatalf("expected no policy calls after valid ticket, got %d", policy.calls)
	}
	reported := receiveEvent(t, events)
	if reported.Action != types.DecisionAllow || reported.DecisionReason != "TICKET_CONSUMED" || reported.Scene != "login" || reported.Route != "/api/login" {
		t.Fatalf("unexpected ticket audit event: %+v", reported)
	}
	if reported.IPHash == "" || reported.IPHash == "198.51.100.9" {
		t.Fatalf("expected hashed ip in event, got %q", reported.IPHash)
	}
}

func TestGatewayBlocksInvalidTicketBeforePolicy(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("upstream should not be reached when ticket is invalid")
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionAllow, Reason: "SHOULD_NOT_CALL"}}
	ticket := &fakeTicketClient{response: types.TicketVerifyResponse{Valid: false, Reason: "CONSUMED"}}
	gateway, err := NewWithClients(Config{
		ClientID:       "demo",
		PlatformURL:    "http://platform.local",
		UpstreamURL:    upstream.URL,
		RequestTimeout: time.Second,
	}, policy, ticket, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	req.Header.Set("X-Captcha-Scene", "login")
	req.Header.Set("X-Captcha-Ticket", "ticket_consumed")
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden response, got %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Action types.Decision `json:"action"`
		Reason string         `json:"reason"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Action != types.DecisionBlock || body.Reason != "CONSUMED" {
		t.Fatalf("unexpected invalid ticket body: %+v", body)
	}
	if policy.calls != 0 {
		t.Fatalf("expected no policy calls after invalid ticket, got %d", policy.calls)
	}
}

func TestGatewayLocalCacheAllowsNoRouteWithoutRemotePolicy(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("local-proxied"))
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionBlock, Reason: "SHOULD_NOT_CALL"}}
	gateway, err := NewWithPolicyClient(Config{
		ClientID:          "demo",
		PlatformURL:       "http://platform.local",
		UpstreamURL:       upstream.URL,
		RequestTimeout:    time.Second,
		EnableConfigCache: true,
	}, policy, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	gateway.cache.Update(types.ConfigSnapshot{ClientID: "demo", Version: 1})

	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted || rec.Body.String() != "local-proxied" {
		t.Fatalf("expected local proxy response, got %d %q", rec.Code, rec.Body.String())
	}
	if policy.calls != 0 {
		t.Fatalf("expected no remote policy calls, got %d", policy.calls)
	}
}

func TestGatewayLocalCacheBlocksIPWithoutRemotePolicy(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("upstream should not be reached when cached IP policy blocks")
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionAllow, Reason: "SHOULD_NOT_CALL"}}
	events := newFakeEventClient()
	gateway, err := NewWithClientsAndEvent(Config{
		ClientID:          "demo",
		PlatformURL:       "http://platform.local",
		UpstreamURL:       upstream.URL,
		RequestTimeout:    time.Second,
		EnableConfigCache: true,
		TrustedProxyCIDRs: []string{"192.0.2.0/24"},
	}, policy, nil, events, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	gateway.cache.Update(types.ConfigSnapshot{
		ClientID: "demo",
		Version:  1,
		IPPolicies: []types.IPPolicy{
			{ClientID: "demo", Type: "blocklist", CIDR: "198.51.100.0/24", Action: types.DecisionBlock, Enabled: true},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.22")
	req.Header.Set("X-Captcha-Account-ID-Hash", "acct_local_block")
	req.Header.Set("X-Captcha-Device-ID-Hash", "device_local_block")
	req.RemoteAddr = "192.0.2.10:12345"
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected local block response, got %d %s", rec.Code, rec.Body.String())
	}
	if policy.calls != 0 {
		t.Fatalf("expected no remote policy calls, got %d", policy.calls)
	}
	reported := receiveEvent(t, events)
	if reported.Action != types.DecisionBlock || reported.DecisionReason != "LOCAL_IP_BLOCKLIST" || reported.Route != "/api/login" {
		t.Fatalf("unexpected local block audit event: %+v", reported)
	}
	if reported.IPHash == "" || reported.IPHash == "198.51.100.22" {
		t.Fatalf("expected hashed ip in event, got %q", reported.IPHash)
	}
	if reported.AccountIDHash != "acct_local_block" || reported.DeviceIDHash != "device_local_block" {
		t.Fatalf("expected account/device hashes in event, got %+v", reported)
	}
}

func TestGatewayLocalCacheAllowlistPrecedesBlocklist(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("allowlisted"))
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionBlock, Reason: "SHOULD_NOT_CALL"}}
	gateway, err := NewWithClientsAndEvent(Config{
		ClientID:          "demo",
		PlatformURL:       "http://platform.local",
		UpstreamURL:       upstream.URL,
		RequestTimeout:    time.Second,
		EnableConfigCache: true,
		TrustedProxyCIDRs: []string{"192.0.2.0/24"},
	}, policy, nil, nil, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	gateway.cache.Update(types.ConfigSnapshot{
		ClientID: "demo",
		Version:  1,
		IPPolicies: []types.IPPolicy{
			{ClientID: "demo", Type: "blocklist", CIDR: "198.51.100.0/24", Action: types.DecisionBlock, Enabled: true},
			{ClientID: "demo", Type: "allowlist", CIDR: "198.51.100.22", Action: types.DecisionAllow, Enabled: true},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.22")
	req.RemoteAddr = "192.0.2.10:12345"
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted || rec.Body.String() != "allowlisted" {
		t.Fatalf("expected allowlisted proxy response, got %d %q", rec.Code, rec.Body.String())
	}
	if policy.calls != 0 {
		t.Fatalf("expected no remote policy calls, got %d", policy.calls)
	}
}

func TestGatewayLocalCacheBlocksDisabledApplication(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("upstream should not be reached when cached app status is disabled")
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionAllow, Reason: "SHOULD_NOT_CALL"}}
	events := newFakeEventClient()
	gateway, err := NewWithClientsAndEvent(Config{
		ClientID:          "demo",
		PlatformURL:       "http://platform.local",
		UpstreamURL:       upstream.URL,
		RequestTimeout:    time.Second,
		EnableConfigCache: true,
	}, policy, nil, events, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	gateway.cache.Update(types.ConfigSnapshot{
		ClientID:          "demo",
		ApplicationStatus: "disabled",
		Version:           2,
	})

	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected disabled app block response, got %d %s", rec.Code, rec.Body.String())
	}
	if policy.calls != 0 {
		t.Fatalf("expected no remote policy calls, got %d", policy.calls)
	}
	reported := receiveEvent(t, events)
	if reported.Action != types.DecisionBlock || reported.DecisionReason != "LOCAL_APPLICATION_DISABLED" || reported.Route != "/public" {
		t.Fatalf("unexpected disabled app audit event: %+v", reported)
	}
}

func TestGatewayLocalCacheObservesWithoutRemotePolicy(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("observed"))
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionBlock, Reason: "SHOULD_NOT_CALL"}}
	events := newFakeEventClient()
	gateway, err := NewWithClientsAndEvent(Config{
		ClientID:          "demo",
		PlatformURL:       "http://platform.local",
		UpstreamURL:       upstream.URL,
		RequestTimeout:    time.Second,
		EnableConfigCache: true,
	}, policy, nil, events, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	gateway.cache.Update(types.ConfigSnapshot{
		ClientID: "demo",
		Version:  3,
		Routes: []types.RoutePolicy{
			{ClientID: "demo", PathPattern: "/api/observe", Method: http.MethodPost, Scene: "login", Mode: " Observe ", Enabled: true},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/observe", nil)
	req.RemoteAddr = "198.51.100.9:12345"
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted || rec.Body.String() != "observed" {
		t.Fatalf("expected observed proxy response, got %d %q", rec.Code, rec.Body.String())
	}
	if policy.calls != 0 {
		t.Fatalf("expected no remote policy calls, got %d", policy.calls)
	}
	reported := receiveEvent(t, events)
	if reported.Action != types.DecisionObserve || reported.DecisionReason != "LOCAL_OBSERVE" || reported.Scene != "login" || reported.Route != "/api/observe" {
		t.Fatalf("unexpected observe audit event: %+v", reported)
	}
}

func TestGatewayLocalCacheAppWideManualBypass(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("app-wide"))
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionBlock, Reason: "SHOULD_NOT_CALL"}}
	events := newFakeEventClient()
	gateway, err := NewWithClientsAndEvent(Config{
		ClientID:          "demo",
		PlatformURL:       "http://platform.local",
		UpstreamURL:       upstream.URL,
		RequestTimeout:    time.Second,
		EnableConfigCache: true,
	}, policy, nil, events, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	gateway.cache.Update(types.ConfigSnapshot{
		ClientID: "demo",
		Version:  3,
		Routes: []types.RoutePolicy{
			{ID: "route_app_wide_gateway", ClientID: "demo", PathPattern: "", Method: "", Scene: "app", Mode: "manual_bypass", Priority: 100, Enabled: true, RolloutPercent: 100},
		},
	})

	req := httptest.NewRequest(http.MethodDelete, "/any/path", nil)
	req.RemoteAddr = "198.51.100.9:12345"
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted || rec.Body.String() != "app-wide" {
		t.Fatalf("expected app-wide proxy response, got %d %q", rec.Code, rec.Body.String())
	}
	if policy.calls != 0 {
		t.Fatalf("expected no remote policy calls, got %d", policy.calls)
	}
	reported := receiveEvent(t, events)
	if reported.Action != types.DecisionAllow || reported.DecisionReason != "LOCAL_MANUAL_BYPASS" || reported.Scene != "app" || reported.Route != "/any/path" {
		t.Fatalf("unexpected app-wide audit event: %+v", reported)
	}
}

func TestGatewayCachedPolicyRuleSkipChallenge(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("trusted"))
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionBlock, Reason: "SHOULD_NOT_CALL"}}
	events := newFakeEventClient()
	gateway, err := NewWithClientsAndEvent(Config{
		ClientID:          "demo",
		PlatformURL:       "http://platform.local",
		UpstreamURL:       upstream.URL,
		RequestTimeout:    time.Second,
		EnableConfigCache: true,
	}, policy, nil, events, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	gateway.cache.Update(types.ConfigSnapshot{
		ClientID: "demo",
		Version:  4,
		PolicyRules: []types.PolicyRule{{
			ID:       "rule_gateway_skip",
			ClientID: "demo",
			Name:     "gateway skip",
			Priority: 100,
			Enabled:  true,
			Scope: types.PolicyRuleScope{
				PathPatterns: []string{"/api/register"},
				Methods:      []string{http.MethodPost},
			},
			Conditions: types.PolicyCondition{All: []types.PolicyCondition{
				{Field: "account_id_hash", Op: "exists"},
				{Field: "device_id_hash", Op: "exists"},
			}},
			Action: types.PolicyRuleAction{Type: types.DecisionSkipChallenge, Reason: "TRUSTED_SUBJECT_LOW_RISK"},
		}},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/register", nil)
	req.Header.Set("X-Captcha-Account-ID-Hash", "acct_trusted")
	req.Header.Set("X-Captcha-Device-ID-Hash", "device_trusted")
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted || rec.Body.String() != "trusted" {
		t.Fatalf("expected trusted proxy response, got %d %q", rec.Code, rec.Body.String())
	}
	if policy.calls != 0 {
		t.Fatalf("cached skip policy should not call remote policy, got %d calls", policy.calls)
	}
	reported := receiveEvent(t, events)
	if reported.Action != types.DecisionSkipChallenge || reported.DecisionReason != "TRUSTED_SUBJECT_LOW_RISK" || reported.Route != "/api/register" {
		t.Fatalf("unexpected cached policy rule audit event: %+v", reported)
	}
}

func TestGatewayLocalCacheSkipsRouteOutsideRollout(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("fallback"))
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionBlock, Reason: "SHOULD_NOT_CALL"}}
	events := newFakeEventClient()
	gateway, err := NewWithClientsAndEvent(Config{
		ClientID:          "demo",
		PlatformURL:       "http://platform.local",
		UpstreamURL:       upstream.URL,
		RequestTimeout:    time.Second,
		EnableConfigCache: true,
	}, policy, nil, events, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	grayRoute := types.RoutePolicy{
		ID:             "route_gray_gateway",
		ClientID:       "demo",
		PathPattern:    "/api/pay",
		Method:         http.MethodPost,
		Scene:          "pay",
		Mode:           "always",
		ChallengeType:  types.CaptchaRotate,
		Priority:       100,
		Enabled:        true,
		RolloutPercent: 10,
	}
	gateway.cache.Update(types.ConfigSnapshot{
		ClientID: "demo",
		Version:  4,
		Routes: []types.RoutePolicy{
			grayRoute,
			{ID: "route_fallback_gateway", ClientID: "demo", PathPattern: "/api/pay", Method: http.MethodPost, Scene: "pay", Mode: "manual_bypass", Priority: 1, Enabled: true, RolloutPercent: 100},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/pay", nil)
	req.Header.Set("X-Captcha-Account-ID-Hash", gatewayRolloutMissAccount(t, grayRoute))
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted || rec.Body.String() != "fallback" {
		t.Fatalf("expected fallback proxy response, got %d %q", rec.Code, rec.Body.String())
	}
	if policy.calls != 0 {
		t.Fatalf("expected no remote policy calls, got %d", policy.calls)
	}
	reported := receiveEvent(t, events)
	if reported.DecisionReason != "LOCAL_MANUAL_BYPASS" || reported.Route != "/api/pay" {
		t.Fatalf("unexpected rollout fallback event: %+v", reported)
	}
}

func TestGatewayBatchesEventReportsBySize(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionBlock, Reason: "SHOULD_NOT_CALL"}}
	events := newFakeEventClient()
	gateway, err := NewWithClientsAndEvent(Config{
		ClientID:           "demo",
		PlatformURL:        "http://platform.local",
		UpstreamURL:        upstream.URL,
		RequestTimeout:     time.Second,
		EnableConfigCache:  true,
		EventBatchSize:     2,
		EventFlushInterval: time.Hour,
	}, policy, nil, events, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	defer gateway.Close()
	gateway.cache.Update(types.ConfigSnapshot{ClientID: "demo", Version: 1})

	for _, path := range []string{"/public/a", "/public/b"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		gateway.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("expected proxied response for %s, got %d", path, rec.Code)
		}
	}

	batch := receiveEventBatch(t, events, 2)
	routes := map[string]bool{}
	for _, event := range batch {
		routes[event.Route] = true
		if event.Action != types.DecisionAllow || event.DecisionReason != "LOCAL_NO_ROUTE_POLICY" {
			t.Fatalf("unexpected batched event: %+v", event)
		}
	}
	if !routes["/public/a"] || !routes["/public/b"] {
		t.Fatalf("unexpected batched routes: %+v", batch)
	}
}

func TestGatewayBatchesEventReportsByInterval(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionBlock, Reason: "SHOULD_NOT_CALL"}}
	events := newFakeEventClient()
	gateway, err := NewWithClientsAndEvent(Config{
		ClientID:           "demo",
		PlatformURL:        "http://platform.local",
		UpstreamURL:        upstream.URL,
		RequestTimeout:     time.Second,
		EnableConfigCache:  true,
		EventBatchSize:     10,
		EventFlushInterval: 10 * time.Millisecond,
	}, policy, nil, events, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	defer gateway.Close()
	gateway.cache.Update(types.ConfigSnapshot{ClientID: "demo", Version: 1})

	req := httptest.NewRequest(http.MethodGet, "/public/interval", nil)
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected proxied response, got %d", rec.Code)
	}

	batch := receiveEventBatch(t, events, 1)
	if batch[0].Route != "/public/interval" || batch[0].DecisionReason != "LOCAL_NO_ROUTE_POLICY" {
		t.Fatalf("unexpected interval batch: %+v", batch)
	}
}

func TestGatewayEventQueueBackpressureDoesNotBlockRequests(t *testing.T) {
	t.Parallel()

	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("proxied"))
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionBlock, Reason: "SHOULD_NOT_CALL"}}
	events := newBlockingEventClient()
	gateway, err := NewWithClientsAndEvent(Config{
		ClientID:           "demo",
		PlatformURL:        "http://platform.local",
		UpstreamURL:        upstream.URL,
		RequestTimeout:     time.Second,
		EnableConfigCache:  true,
		EventBatchSize:     2,
		EventFlushInterval: time.Hour,
		EventQueueSize:     2,
	}, policy, nil, events, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	defer gateway.Close()
	defer close(events.release)
	gateway.cache.Update(types.ConfigSnapshot{ClientID: "demo", Version: 1})

	req := httptest.NewRequest(http.MethodGet, "/public/first", nil)
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || rec.Body.String() != "proxied" {
		t.Fatalf("expected first request to proxy, got %d %q", rec.Code, rec.Body.String())
	}
	if _, err := gateway.events.Report(context.Background(), []types.AuditEvent{{ClientID: "demo", Route: "/flush-trigger"}}); err != nil {
		t.Fatalf("expected trigger event to flush first batch, got %v", err)
	}
	select {
	case <-events.started:
	case <-time.After(time.Second):
		t.Fatal("expected event reporter to block on first batch")
	}

	if _, err := gateway.events.Report(context.Background(), []types.AuditEvent{{ClientID: "demo", Route: "/queued-a"}}); err != nil {
		t.Fatalf("expected queue to accept first pending event, got %v", err)
	}
	if _, err := gateway.events.Report(context.Background(), []types.AuditEvent{{ClientID: "demo", Route: "/queued-b"}}); err != nil {
		t.Fatalf("expected queue to accept one pending event, got %v", err)
	}
	if _, err := gateway.events.Report(context.Background(), []types.AuditEvent{{ClientID: "demo", Route: "/overflow"}}); !errors.Is(err, errEventQueueFull) {
		t.Fatalf("expected full event queue error, got %v", err)
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/public/backpressure", nil)
		rec := httptest.NewRecorder()
		gateway.Handler().ServeHTTP(rec, req)
		done <- rec
	}()
	select {
	case rec := <-done:
		if rec.Code != http.StatusAccepted || rec.Body.String() != "proxied" {
			t.Fatalf("expected backpressured event queue request to proxy, got %d %q", rec.Code, rec.Body.String())
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("event queue backpressure blocked the gateway request path")
	}
	if upstreamCalls != 2 {
		t.Fatalf("expected both requests to reach upstream, got %d", upstreamCalls)
	}
}

func TestGatewayDoesNotTrustForwardedForByDefault(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("proxied"))
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionAllow, Reason: "REMOTE"}}
	gateway, err := NewWithPolicyClient(Config{
		ClientID:       "demo",
		PlatformURL:    "http://platform.local",
		UpstreamURL:    upstream.URL,
		RequestTimeout: time.Second,
	}, policy, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected proxied response, got %d %s", rec.Code, rec.Body.String())
	}
	if policy.request.IP != "192.0.2.10" {
		t.Fatalf("expected direct remote ip when proxy is not trusted, got %+v", policy.request)
	}
}

func TestGatewayUsesForwardedForFromTrustedProxy(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("proxied"))
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{decision: types.PolicyDecision{Action: types.DecisionAllow, Reason: "REMOTE"}}
	gateway, err := NewWithPolicyClient(Config{
		ClientID:          "demo",
		PlatformURL:       "http://platform.local",
		UpstreamURL:       upstream.URL,
		RequestTimeout:    time.Second,
		TrustedProxyCIDRs: []string{"192.0.2.0/24"},
	}, policy, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.99, 192.0.2.10")
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected proxied response, got %d %s", rec.Code, rec.Body.String())
	}
	if policy.request.IP != "203.0.113.99" {
		t.Fatalf("expected forwarded client ip from trusted proxy, got %+v", policy.request)
	}
}

func TestGatewayCircuitBreakerSkipsRemotePolicyDuringCooldown(t *testing.T) {
	t.Parallel()

	var upstreamCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("degraded"))
	}))
	defer upstream.Close()

	policy := &fakePolicyClient{err: errors.New("offline")}
	gateway, err := NewWithPolicyClient(Config{
		ClientID:               "demo",
		PlatformURL:            "http://platform.local",
		UpstreamURL:            upstream.URL,
		RequestTimeout:         time.Second,
		CircuitBreakerFailures: 1,
		CircuitBreakerCooldown: time.Minute,
	}, policy, nil)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
		rec := httptest.NewRecorder()
		gateway.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusAccepted || rec.Body.String() != "degraded" {
			t.Fatalf("expected fail-open degraded proxy response, got %d %q", rec.Code, rec.Body.String())
		}
	}
	if policy.calls != 1 {
		t.Fatalf("expected circuit breaker to skip second remote policy call, got %d calls", policy.calls)
	}
	if upstreamCalls != 2 {
		t.Fatalf("expected both requests to fail open to upstream, got %d calls", upstreamCalls)
	}
}

func TestHTTPPlatformClientsSendClientSecret(t *testing.T) {
	t.Parallel()

	const clientSecret = "cap_secret_gateway_test"
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Captcha-Client-Secret") != clientSecret {
			t.Fatalf("missing client secret header on %s", r.URL.Path)
		}
		switch r.URL.Path {
		case "/api/v1/policy/evaluate":
			writeJSON(w, http.StatusOK, types.PolicyDecision{Action: types.DecisionAllow, Reason: "OK"})
		case "/api/v1/tickets/verify":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode ticket body: %v", err)
			}
			if body["request_nonce"] != "nonce-http" || body["ip_hash"] != "sha256:ip" || body["user_agent_hash"] != "sha256:ua" {
				t.Fatalf("expected request nonce in ticket body, got %+v", body)
			}
			writeJSON(w, http.StatusOK, types.TicketVerifyResponse{Valid: true, ClientID: "demo", Scene: "login", Route: "/api/login"})
		case "/api/v1/events/report":
			writeJSON(w, http.StatusOK, types.ReportResult{Accepted: 1})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer platform.Close()

	baseURL, err := url.Parse(platform.URL)
	if err != nil {
		t.Fatalf("parse platform url: %v", err)
	}
	httpClient := platform.Client()
	policyClient := &HTTPPolicyClient{BaseURL: baseURL, Client: httpClient, ClientSecret: clientSecret}
	if _, err := policyClient.Evaluate(context.Background(), types.PolicyEvaluateRequest{ClientID: "demo"}); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	ticketClient := &HTTPTicketClient{BaseURL: baseURL, Client: httpClient, ClientSecret: clientSecret}
	if _, err := ticketClient.Consume(context.Background(), types.TicketVerifyRequest{Ticket: "ticket", ClientID: "demo", Scene: "login", Route: "/api/login", RequestNonce: "nonce-http", IPHash: "sha256:ip", UserAgentHash: "sha256:ua"}); err != nil {
		t.Fatalf("consume: %v", err)
	}
	eventClient := &HTTPEventClient{BaseURL: baseURL, Client: httpClient, ClientSecret: clientSecret}
	if _, err := eventClient.Report(context.Background(), []types.AuditEvent{{ClientID: "demo", Action: types.DecisionObserve}}); err != nil {
		t.Fatalf("report: %v", err)
	}
}

func TestGRPCPolicyClientEvaluate(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	captchaEngine := engine.New(2 * time.Minute)
	policyEvaluator := policy.NewEvaluator(memoryStore)
	grpcServer := grpcserver.New(grpcserver.Dependencies{
		Engine: captchaEngine,
		Policy: policyEvaluator,
		Store:  memoryStore,
		Logger: slog.Default(),
	})

	listener := bufconn.Listen(1024 * 1024)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("new grpc client: %v", err)
	}
	defer conn.Close()

	client := NewGRPCPolicyClientWithConn(conn)
	decision, err := client.Evaluate(context.Background(), types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/register",
		Method:   http.MethodPost,
		IP:       "198.51.100.9",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision.Action != types.DecisionChallenge || decision.SessionID == "" {
		t.Fatalf("expected challenge decision, got %+v", decision)
	}
}

func TestGRPCPolicyClientSendsPlatformTokenAndClientSecret(t *testing.T) {
	t.Parallel()

	appSecret := "cap_secret_gateway_grpc"
	secretHash, err := clientsecret.HashClientSecret(appSecret)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	memoryStore := store.NewMemoryStore()
	memoryStore.UpsertApplication(types.Application{
		ClientID:          "demo",
		Name:              "demo-app",
		Status:            "active",
		DefaultFailPolicy: "fail_open",
		SecretHash:        secretHash,
	})
	captchaEngine := engine.New(2 * time.Minute)
	policyEvaluator := policy.NewEvaluator(memoryStore)
	grpcServer := grpcserver.New(grpcserver.Dependencies{
		Engine:    captchaEngine,
		Policy:    policyEvaluator,
		Store:     memoryStore,
		Logger:    slog.Default(),
		GRPCToken: "gateway-grpc-token",
	})

	listener := bufconn.Listen(1024 * 1024)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("new grpc client: %v", err)
	}
	defer conn.Close()

	withoutPlatformToken := NewGRPCPolicyClientWithConnAndSecret(conn, appSecret)
	_, err = withoutPlatformToken.Evaluate(context.Background(), types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/register",
		Method:   http.MethodPost,
		IP:       "198.51.100.9",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected missing platform token to be unauthenticated, got %v", err)
	}

	client := NewGRPCPolicyClientWithConnAndAuth(conn, appSecret, "gateway-grpc-token")
	decision, err := client.Evaluate(context.Background(), types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/register",
		Method:   http.MethodPost,
		IP:       "198.51.100.9",
	})
	if err != nil {
		t.Fatalf("evaluate with platform token and client secret: %v", err)
	}
	if decision.Action != types.DecisionChallenge || decision.SessionID == "" {
		t.Fatalf("expected challenge decision, got %+v", decision)
	}
}

func TestGRPCTicketClientConsume(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	now := time.Now()
	memoryStore.PutTicket(types.Ticket{
		Value:     "ticket_ok",
		ClientID:  "demo",
		Scene:     "login",
		Route:     "/api/login",
		ExpiresAt: now.Add(time.Minute),
		CreatedAt: now,
	})
	captchaEngine := engine.New(2 * time.Minute)
	policyEvaluator := policy.NewEvaluator(memoryStore)
	grpcServer := grpcserver.New(grpcserver.Dependencies{
		Engine: captchaEngine,
		Policy: policyEvaluator,
		Store:  memoryStore,
		Logger: slog.Default(),
	})

	listener := bufconn.Listen(1024 * 1024)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("new grpc client: %v", err)
	}
	defer conn.Close()

	client := NewGRPCTicketClientWithConn(conn)
	response, err := client.Consume(context.Background(), types.TicketVerifyRequest{
		Ticket:   "ticket_ok",
		ClientID: "demo",
		Scene:    "login",
		Route:    "/api/login",
	})
	if err != nil {
		t.Fatalf("consume ticket: %v", err)
	}
	if !response.Valid || response.ClientID != "demo" || response.Scene != "login" {
		t.Fatalf("expected valid consumed ticket, got %+v", response)
	}

	response, err = client.Consume(context.Background(), types.TicketVerifyRequest{
		Ticket:   "ticket_ok",
		ClientID: "demo",
		Scene:    "login",
		Route:    "/api/login",
	})
	if err != nil {
		t.Fatalf("consume ticket again: %v", err)
	}
	if response.Valid || response.Reason != "CONSUMED" {
		t.Fatalf("expected consumed ticket rejection, got %+v", response)
	}
}

func TestGRPCEventClientReport(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	captchaEngine := engine.New(2 * time.Minute)
	policyEvaluator := policy.NewEvaluator(memoryStore)
	grpcServer := grpcserver.New(grpcserver.Dependencies{
		Engine: captchaEngine,
		Policy: policyEvaluator,
		Store:  memoryStore,
		Logger: slog.Default(),
	})

	listener := bufconn.Listen(1024 * 1024)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("new grpc client: %v", err)
	}
	defer conn.Close()

	client := NewGRPCEventClientWithConn(conn)
	result, err := client.Report(context.Background(), []types.AuditEvent{
		{ClientID: "demo", Scene: "login", Route: "/api/login", Action: types.DecisionObserve, DecisionReason: "GATEWAY_TEST", Result: "observe"},
	})
	if err != nil {
		t.Fatalf("report event: %v", err)
	}
	if result.Accepted != 1 {
		t.Fatalf("expected one accepted event, got %+v", result)
	}
	items := memoryStore.ListAuditEvents("demo", 1)
	if len(items) != 1 || items[0].DecisionReason != "GATEWAY_TEST" {
		t.Fatalf("expected reported event in store, got %+v", items)
	}
}

func receiveEvent(t *testing.T, client *fakeEventClient) types.AuditEvent {
	t.Helper()
	return receiveEventBatch(t, client, 1)[0]
}

func receiveEventBatch(t *testing.T, client *fakeEventClient, expected int) []types.AuditEvent {
	t.Helper()
	select {
	case batch := <-client.events:
		if len(batch) != expected {
			t.Fatalf("expected %d reported events, got %+v", expected, batch)
		}
		return batch
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reported event")
		return nil
	}
}

func gatewayRolloutMissAccount(t *testing.T, route types.RoutePolicy) string {
	t.Helper()
	for i := 0; i < 500; i++ {
		account := fmt.Sprintf("acct_gateway_rollout_miss_%d", i)
		if !routepolicy.MatchesRollout(route, routepolicy.RolloutContext{
			ClientID:      "demo",
			Path:          "/api/pay",
			Method:        http.MethodPost,
			AccountIDHash: account,
		}) {
			return account
		}
	}
	t.Fatal("could not find gateway rollout miss account")
	return ""
}

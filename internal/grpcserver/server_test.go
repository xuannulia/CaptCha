package grpcserver

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	captchav1 "captcha/gen/captcha/v1"
	"captcha/internal/configsync"
	"captcha/internal/engine"
	"captcha/internal/grpccontract"
	"captcha/internal/policy"
	riskpkg "captcha/internal/risk"
	clientsecret "captcha/internal/secret"
	"captcha/internal/store"
	"captcha/internal/token"
	"captcha/internal/types"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type fakeRiskInferencer struct {
	score int
	err   error
	calls atomic.Int32
}

func (f *fakeRiskInferencer) Infer(context.Context, types.PolicyEvaluateRequest, types.RiskModelVersion) (riskpkg.Inference, error) {
	f.calls.Add(1)
	if f.err != nil {
		return riskpkg.Inference{}, f.err
	}
	return riskpkg.Inference{Score: &f.score}, nil
}

func TestGRPCPolicyAndTicketServices(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	captchaEngine := engine.New(2 * time.Minute)
	policyEvaluator := policy.NewEvaluator(memoryStore)
	tokenService := token.NewService(memoryStore, 2*time.Minute)
	server := New(Dependencies{
		Engine: captchaEngine,
		Policy: policyEvaluator,
		Store:  memoryStore,
		Logger: slog.Default(),
		Tokens: tokenService,
	})

	listener := bufconn.Listen(1024 * 1024)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	ctx := context.Background()
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

	policyClient := captchav1.NewPolicyServiceClient(conn)
	ticketClient := captchav1.NewTicketServiceClient(conn)
	configClient := captchav1.NewConfigServiceClient(conn)
	eventClient := captchav1.NewEventServiceClient(conn)

	decision, err := grpcEvaluate(policyClient, ctx, types.PolicyEvaluateRequest{
		ClientID:     "demo",
		Path:         "/api/register",
		Method:       "POST",
		IP:           "198.51.100.44",
		RequestNonce: "nonce-grpc",
		ResourceTag:  "campaign",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision.Action != types.DecisionChallenge || decision.SessionID == "" {
		t.Fatalf("expected challenge decision, got %+v", decision)
	}
	challengeURL, err := url.Parse(decision.ChallengeURL)
	if err != nil {
		t.Fatalf("parse challenge url: %v", err)
	}
	if challengeURL.Query().Get("route") != "/api/register" {
		t.Fatalf("expected challenge route, got %q in %q", challengeURL.Query().Get("route"), decision.ChallengeURL)
	}
	if challengeURL.Query().Get("request_nonce") != "nonce-grpc" {
		t.Fatalf("expected challenge nonce, got %q in %q", challengeURL.Query().Get("request_nonce"), decision.ChallengeURL)
	}
	if challengeURL.Query().Get("resource_tag") != "campaign" {
		t.Fatalf("expected challenge resource tag, got %q in %q", challengeURL.Query().Get("resource_tag"), decision.ChallengeURL)
	}

	ticket, err := tokenService.Issue("demo", "login", "/api/login", "", "", "")
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}

	consumed, err := grpcConsumeTicket(ticketClient, ctx, types.TicketVerifyRequest{
		Ticket:        ticket.Value,
		ClientID:      "demo",
		Scene:         "login",
		Route:         "/api/login",
		IPHash:        hashValue("198.51.100.44"),
		UserAgentHash: hashValue("grpc-clearance"),
	})
	if err != nil {
		t.Fatalf("consume ticket: %v", err)
	}
	if !consumed.Valid {
		t.Fatalf("expected valid consume response, got %+v", consumed)
	}
	if consumed.ClearanceToken == "" || consumed.ClearanceTTLSeconds <= 0 {
		t.Fatalf("expected consumed ticket to mint clearance, got %+v", consumed)
	}
	consumedPolicy, err := grpcEvaluate(policyClient, ctx, types.PolicyEvaluateRequest{
		ClientID: "demo",
		Scene:    "login",
		Path:     "/api/login",
		Method:   "POST",
		Ticket:   ticket.Value,
	})
	if err != nil {
		t.Fatalf("evaluate consumed ticket policy: %v", err)
	}
	if consumedPolicy.Action != types.DecisionBlock || consumedPolicy.Reason != "CONSUMED" {
		t.Fatalf("expected consumed ticket to block policy evaluation, got %+v", consumedPolicy)
	}
	missingRoutePolicyTicket, err := tokenService.Issue("demo", "login", "/api/login", "", "", "")
	if err != nil {
		t.Fatalf("issue missing route policy ticket: %v", err)
	}
	missingRoutePolicy, err := grpcEvaluate(policyClient, ctx, types.PolicyEvaluateRequest{
		ClientID: "demo",
		Scene:    "login",
		Method:   "POST",
		Ticket:   missingRoutePolicyTicket.Value,
	})
	if err != nil {
		t.Fatalf("evaluate missing route ticket policy: %v", err)
	}
	if missingRoutePolicy.Action != types.DecisionBlock || missingRoutePolicy.Reason != "NOT_FOUND" || missingRoutePolicy.SessionID != "" {
		t.Fatalf("expected route-bound ticket without path to block grpc policy evaluation, got %+v", missingRoutePolicy)
	}
	missingNoncePolicyTicket, err := tokenService.Issue("demo", "login", "/api/login", "nonce-policy-ticket", "", "")
	if err != nil {
		t.Fatalf("issue missing nonce policy ticket: %v", err)
	}
	missingNoncePolicy, err := grpcEvaluate(policyClient, ctx, types.PolicyEvaluateRequest{
		ClientID: "demo",
		Scene:    "login",
		Path:     "/api/login",
		Method:   "POST",
		Ticket:   missingNoncePolicyTicket.Value,
	})
	if err != nil {
		t.Fatalf("evaluate missing nonce ticket policy: %v", err)
	}
	if missingNoncePolicy.Action != types.DecisionBlock || missingNoncePolicy.Reason != "NOT_FOUND" || missingNoncePolicy.SessionID != "" {
		t.Fatalf("expected nonce-bound ticket without request nonce to block grpc policy evaluation, got %+v", missingNoncePolicy)
	}
	missingContextPolicyTicket, err := tokenService.Issue("demo", "login", "/api/login", "", hashValue("198.51.100.44"), hashValue("grpc-policy-context"))
	if err != nil {
		t.Fatalf("issue missing context policy ticket: %v", err)
	}
	missingContextPolicy, err := grpcEvaluate(policyClient, ctx, types.PolicyEvaluateRequest{
		ClientID: "demo",
		Scene:    "login",
		Path:     "/api/login",
		Method:   "POST",
		Ticket:   missingContextPolicyTicket.Value,
	})
	if err != nil {
		t.Fatalf("evaluate missing context ticket policy: %v", err)
	}
	if missingContextPolicy.Action != types.DecisionBlock || missingContextPolicy.Reason != "NOT_FOUND" || missingContextPolicy.SessionID != "" {
		t.Fatalf("expected ip/ua-bound ticket without request context to block grpc policy evaluation, got %+v", missingContextPolicy)
	}

	nonceTicket, err := tokenService.Issue("demo", "login", "/api/login", "nonce-grpc-ticket", "", "")
	if err != nil {
		t.Fatalf("issue nonce ticket: %v", err)
	}
	missingNonce, err := grpcVerifyTicket(ticketClient, ctx, types.TicketVerifyRequest{
		Ticket:   nonceTicket.Value,
		ClientID: "demo",
		Scene:    "login",
		Route:    "/api/login",
	})
	if err != nil {
		t.Fatalf("verify missing nonce ticket: %v", err)
	}
	if missingNonce.Valid || missingNonce.Reason != "NOT_FOUND" {
		t.Fatalf("expected missing nonce rejection, got %+v", missingNonce)
	}
	nonceVerified, err := grpcVerifyTicket(ticketClient, ctx, types.TicketVerifyRequest{
		Ticket:       nonceTicket.Value,
		ClientID:     "demo",
		Scene:        "login",
		Route:        "/api/login",
		RequestNonce: "nonce-grpc-ticket",
	})
	if err != nil {
		t.Fatalf("verify nonce ticket: %v", err)
	}
	if !nonceVerified.Valid || nonceVerified.RequestNonce != "nonce-grpc-ticket" {
		t.Fatalf("expected nonce-bound ticket to verify, got %+v", nonceVerified)
	}

	missingRouteTicket, err := tokenService.Issue("demo", "login", "/api/login", "", "", "")
	if err != nil {
		t.Fatalf("issue missing route ticket: %v", err)
	}
	missingRoute, err := grpcVerifyTicket(ticketClient, ctx, types.TicketVerifyRequest{
		Ticket:   missingRouteTicket.Value,
		ClientID: "demo",
		Scene:    "login",
	})
	if err != nil {
		t.Fatalf("verify missing route ticket: %v", err)
	}
	if missingRoute.Valid || missingRoute.Reason != "NOT_FOUND" {
		t.Fatalf("expected missing route rejection, got %+v", missingRoute)
	}

	verified, err := grpcVerifyTicket(ticketClient, ctx, types.TicketVerifyRequest{
		Ticket:   ticket.Value,
		ClientID: "demo",
		Scene:    "login",
		Route:    "/api/login",
	})
	if err != nil {
		t.Fatalf("verify consumed ticket: %v", err)
	}
	if verified.Valid || verified.Reason != "CONSUMED" {
		t.Fatalf("expected consumed ticket rejection, got %+v", verified)
	}

	memoryStore.UpsertPolicyRule(types.PolicyRule{
		ID:       "rule_grpc_config",
		ClientID: "demo",
		Name:     "grpc config",
		Priority: 100,
		Enabled:  true,
		Scope: types.PolicyRuleScope{
			PathPatterns: []string{"/api/config-rule"},
			Methods:      []string{"POST"},
		},
		Action: types.PolicyRuleAction{Type: types.DecisionSkipChallenge, Reason: "GRPC_CONFIG_RULE"},
	})
	configPB, err := configClient.GetConfig(ctx, &captchav1.ConfigRequest{ClientId: "demo"})
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	config := grpccontract.ConfigSnapshotFromProto(configPB)
	if config.ClientID != "demo" || len(config.Routes) == 0 || len(config.IPPolicies) == 0 || len(config.Resources) == 0 {
		t.Fatalf("unexpected config snapshot: %+v", config)
	}
	if len(config.PolicyRules) != 1 || config.PolicyRules[0].ID != "rule_grpc_config" || config.PolicyRules[0].Action.Type != types.DecisionSkipChallenge {
		t.Fatalf("expected policy rules in config snapshot, got %+v", config.PolicyRules)
	}
	if config.ApplicationStatus != "active" {
		t.Fatalf("expected active app status in config snapshot, got %+v", config)
	}

	reportPB, err := eventClient.Report(ctx, grpccontract.EventBatchToProto(
		[]types.AuditEvent{
			{ClientID: "demo", Scene: "login", Route: "/api/login", Action: types.DecisionObserve, DecisionReason: "TEST_EVENT", Result: "observe"},
			{ClientID: "demo", Scene: "comment", Route: "/api/comment", Action: types.DecisionChallenge, DecisionReason: "TEST_EVENT", Result: "challenge"},
		},
	))
	if err != nil {
		t.Fatalf("report events: %v", err)
	}
	report := grpccontract.ReportResultFromProto(reportPB)
	if report.Accepted != 2 {
		t.Fatalf("expected 2 accepted events, got %+v", report)
	}
	beforeInvalidEvent := len(memoryStore.ListAuditEvents("", 20))
	_, err = eventClient.Report(ctx, grpccontract.EventBatchToProto(
		[]types.AuditEvent{
			{ClientID: "demo", Scene: "login", Route: "/api/login", Action: types.DecisionObserve, DecisionReason: "MIXED_BATCH_SHOULD_NOT_WRITE", Result: "observe"},
			{Scene: "login", Route: "/api/login", Action: types.DecisionObserve, DecisionReason: "MISSING_CLIENT", Result: "observe"},
		},
	))
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected missing client id event rejection, got %v", err)
	}
	if afterInvalidEvent := len(memoryStore.ListAuditEvents("", 20)); afterInvalidEvent != beforeInvalidEvent {
		t.Fatalf("missing client id event should not be recorded, before=%d after=%d", beforeInvalidEvent, afterInvalidEvent)
	}
	for _, event := range memoryStore.ListAuditEvents("demo", 20) {
		if event.DecisionReason == "MIXED_BATCH_SHOULD_NOT_WRITE" {
			t.Fatalf("valid event from rejected batch should not be partially recorded: %+v", event)
		}
	}
}

func TestGRPCWatchConfigPushesUpdates(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	notifier := configsync.NewNotifier()
	captchaEngine := engine.New(2 * time.Minute)
	policyEvaluator := policy.NewEvaluator(memoryStore)
	server := New(Dependencies{
		Engine:         captchaEngine,
		Policy:         policyEvaluator,
		Store:          memoryStore,
		Logger:         slog.Default(),
		ConfigNotifier: notifier,
	})

	listener := bufconn.Listen(1024 * 1024)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
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

	stream, err := captchav1.NewConfigServiceClient(conn).WatchConfig(ctx, &captchav1.ConfigRequest{ClientId: "demo"})
	if err != nil {
		t.Fatalf("new stream: %v", err)
	}

	initialPB, err := stream.Recv()
	if err != nil {
		t.Fatalf("receive initial snapshot: %v", err)
	}
	initial := grpccontract.ConfigSnapshotFromProto(initialPB)
	if initial.Version == 0 {
		t.Fatalf("expected initial version, got %+v", initial)
	}

	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ClientID:        "demo",
		Name:            "watch-route",
		PathPattern:     "/api/watch",
		Method:          "POST",
		Scene:           "watch",
		Mode:            "always",
		ChallengeType:   types.CaptchaSlider,
		FailPolicy:      "fail_close",
		Priority:        99,
		Enabled:         true,
		TokenTTLSeconds: 120,
	})
	notifier.Notify()

	updatedPB, err := stream.Recv()
	if err != nil {
		t.Fatalf("receive updated snapshot: %v", err)
	}
	updated := grpccontract.ConfigSnapshotFromProto(updatedPB)
	if updated.Version <= initial.Version {
		t.Fatalf("expected version increase, initial=%d updated=%d", initial.Version, updated.Version)
	}
	found := false
	for _, route := range updated.Routes {
		if route.Name == "watch-route" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("updated snapshot missing route: %+v", updated.Routes)
	}
}

func TestGRPCPolicyEvaluateUsesRiskInferencer(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	model := memoryStore.UpsertRiskModelVersion(types.RiskModelVersion{
		ID:             "model_grpc_observe",
		Name:           "grpc-online-baseline",
		Version:        "v1",
		FeatureVersion: "request-v1",
		TrainingWindow: "2026-01-01/2026-06-01",
		ArtifactURI:    "http://risk.local/model",
		Mode:           "observe",
	})
	if _, err := memoryStore.ActivateRiskModelVersion(model.ID); err != nil {
		t.Fatalf("activate model: %v", err)
	}
	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ID:                 "route_grpc_online_risk",
		ClientID:           "demo",
		Name:               "grpc online risk",
		PathPattern:        "/api/grpc-online-risk",
		Method:             "POST",
		Scene:              "pay",
		Mode:               "risk_based",
		ChallengeType:      types.CaptchaSlider,
		RiskChallengeType:  types.CaptchaRotate,
		FailPolicy:         "fail_close",
		Priority:           999,
		Enabled:            true,
		TokenTTLSeconds:    120,
		RiskChallengeScore: 70,
	})
	fakeInferencer := &fakeRiskInferencer{score: 82}
	captchaEngine := engine.New(2 * time.Minute)
	policyEvaluator := policy.NewEvaluator(memoryStore)
	server := New(Dependencies{
		Engine:         captchaEngine,
		Policy:         policyEvaluator,
		Store:          memoryStore,
		Logger:         slog.Default(),
		RiskInferencer: fakeInferencer,
	})

	listener := bufconn.Listen(1024 * 1024)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
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

	decision, err := grpcEvaluate(captchav1.NewPolicyServiceClient(conn), context.Background(), types.PolicyEvaluateRequest{
		ClientID:  "demo",
		Path:      "/api/grpc-online-risk",
		Method:    "POST",
		IP:        "198.51.100.82",
		UserAgent: "Mozilla/5.0 grpc-risk-inference-test",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision.Action != types.DecisionChallenge || decision.Reason != "RISK_SCORE" || decision.ChallengeType != types.CaptchaRotate || decision.SessionID == "" {
		t.Fatalf("expected external model score to trigger grpc risk challenge, got %+v", decision)
	}
	if fakeInferencer.calls.Load() != 1 {
		t.Fatalf("expected one risk inference call, got %d", fakeInferencer.calls.Load())
	}
}

func TestGRPCPolicyEvaluateDegradesWhenRiskInferencerFails(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	model := memoryStore.UpsertRiskModelVersion(types.RiskModelVersion{
		ID:             "model_grpc_degrade",
		Name:           "grpc-degrade-baseline",
		Version:        "v1",
		FeatureVersion: "request-v1",
		TrainingWindow: "2026-01-01/2026-06-01",
		ArtifactURI:    "http://risk.local/model",
		Mode:           "observe",
	})
	if _, err := memoryStore.ActivateRiskModelVersion(model.ID); err != nil {
		t.Fatalf("activate model: %v", err)
	}
	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ID:                 "route_grpc_risk_degrade",
		ClientID:           "demo",
		Name:               "grpc risk degrade",
		PathPattern:        "/api/grpc-risk-degrade",
		Method:             "POST",
		Scene:              "pay",
		Mode:               "risk_based",
		ChallengeType:      types.CaptchaSlider,
		RiskChallengeType:  types.CaptchaRotate,
		FailPolicy:         "fail_close",
		Priority:           999,
		Enabled:            true,
		TokenTTLSeconds:    120,
		RiskChallengeScore: 70,
	})
	fakeInferencer := &fakeRiskInferencer{err: errors.New("risk inference unavailable")}
	server := New(Dependencies{
		Engine:         engine.New(2 * time.Minute),
		Policy:         policy.NewEvaluator(memoryStore),
		Store:          memoryStore,
		Logger:         slog.Default(),
		RiskInferencer: fakeInferencer,
	})

	listener := bufconn.Listen(1024 * 1024)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
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

	decision, err := grpcEvaluate(captchav1.NewPolicyServiceClient(conn), context.Background(), types.PolicyEvaluateRequest{
		ClientID:      "demo",
		Path:          "/api/grpc-risk-degrade",
		Method:        "POST",
		IP:            "198.51.100.83",
		UserAgent:     "Mozilla/5.0 grpc-risk-inference-failure-test",
		AccountIDHash: "acct_grpc_risk_degrade",
	})
	if err != nil {
		t.Fatalf("evaluate should degrade instead of returning grpc error: %v", err)
	}
	if decision.Action != types.DecisionAllow || decision.Reason != "LOW_RISK_CONTEXT" || decision.SessionID != "" {
		t.Fatalf("expected grpc risk inference failure to fall back to local low-risk decision, got %+v", decision)
	}
	if fakeInferencer.calls.Load() != 1 {
		t.Fatalf("expected one risk inference call, got %d", fakeInferencer.calls.Load())
	}
}

func TestGRPCClientSecretAuth(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	secretValue := "cap_secret_grpc_test"
	secretHash, err := clientsecret.HashClientSecret(secretValue)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	memoryStore.UpsertApplication(types.Application{
		ClientID:          "demo",
		Name:              "demo-app",
		Status:            "active",
		DefaultFailPolicy: "fail_open",
		SecretHash:        secretHash,
	})
	captchaEngine := engine.New(2 * time.Minute)
	policyEvaluator := policy.NewEvaluator(memoryStore)
	server := New(Dependencies{
		Engine: captchaEngine,
		Policy: policyEvaluator,
		Store:  memoryStore,
		Logger: slog.Default(),
	})

	listener := bufconn.Listen(1024 * 1024)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
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

	policyClient := captchav1.NewPolicyServiceClient(conn)
	ticketClient := captchav1.NewTicketServiceClient(conn)
	configClient := captchav1.NewConfigServiceClient(conn)
	eventClient := captchav1.NewEventServiceClient(conn)
	_, err = grpcEvaluate(policyClient, context.Background(), types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/register",
		Method:   "POST",
		IP:       "198.51.100.44",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated error, got %v", err)
	}
	_, err = grpcVerifyTicket(ticketClient, context.Background(), types.TicketVerifyRequest{
		Ticket:   "cap_ticket_missing",
		ClientID: "demo",
		Scene:    "login",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated ticket error, got %v", err)
	}
	_, err = configClient.GetConfig(context.Background(), &captchav1.ConfigRequest{ClientId: "demo"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated config error, got %v", err)
	}
	_, err = eventClient.Report(context.Background(), grpccontract.EventBatchToProto([]types.AuditEvent{
		{ClientID: "demo", Scene: "login", Route: "/api/login", Action: types.DecisionObserve, DecisionReason: "GRPC_SECRET_EVENT", Result: "observe"},
	}))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated event error, got %v", err)
	}

	ctx := metadata.AppendToOutgoingContext(context.Background(), "x-captcha-client-secret", secretValue)
	decision, err := grpcEvaluate(policyClient, ctx, types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/register",
		Method:   "POST",
		IP:       "198.51.100.44",
	})
	if err != nil {
		t.Fatalf("authorized evaluate: %v", err)
	}
	if decision.Action != types.DecisionChallenge || decision.SessionID == "" {
		t.Fatalf("expected authorized challenge decision, got %+v", decision)
	}
	ticketService := token.NewService(memoryStore, 2*time.Minute)
	ticket, err := ticketService.Issue("demo", "login", "/api/login", "", "", "")
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	ticketResponse, err := grpcVerifyTicket(ticketClient, ctx, types.TicketVerifyRequest{
		Ticket:   ticket.Value,
		ClientID: "demo",
		Scene:    "login",
		Route:    "/api/login",
	})
	if err != nil {
		t.Fatalf("authorized ticket verify: %v", err)
	}
	if !ticketResponse.Valid {
		t.Fatalf("expected authorized ticket verification, got %+v", ticketResponse)
	}
	configPB, err := configClient.GetConfig(ctx, &captchav1.ConfigRequest{ClientId: "demo"})
	if err != nil {
		t.Fatalf("authorized config: %v", err)
	}
	config := grpccontract.ConfigSnapshotFromProto(configPB)
	if config.ClientID != "demo" || config.ApplicationStatus != "active" {
		t.Fatalf("expected authorized config snapshot, got %+v", config)
	}
	reportPB, err := eventClient.Report(ctx, grpccontract.EventBatchToProto([]types.AuditEvent{
		{ClientID: "demo", Scene: "login", Route: "/api/login", Action: types.DecisionObserve, DecisionReason: "GRPC_SECRET_EVENT", Result: "observe"},
	}))
	if err != nil {
		t.Fatalf("authorized event report: %v", err)
	}
	report := grpccontract.ReportResultFromProto(reportPB)
	if report.Accepted != 1 {
		t.Fatalf("expected authorized event report accepted, got %+v", report)
	}
}

func TestGRPCPlatformTokenAuth(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	captchaEngine := engine.New(2 * time.Minute)
	policyEvaluator := policy.NewEvaluator(memoryStore)
	server := New(Dependencies{
		Engine:    captchaEngine,
		Policy:    policyEvaluator,
		Store:     memoryStore,
		Logger:    slog.Default(),
		GRPCToken: "grpc-platform-token",
	})

	listener := bufconn.Listen(1024 * 1024)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
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

	policyClient := captchav1.NewPolicyServiceClient(conn)
	_, err = grpcEvaluate(policyClient, context.Background(), types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/register",
		Method:   "POST",
		IP:       "198.51.100.44",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected missing grpc token to be unauthenticated, got %v", err)
	}

	wrongCtx := metadata.AppendToOutgoingContext(context.Background(), "x-captcha-grpc-token", "wrong")
	_, err = grpcEvaluate(policyClient, wrongCtx, types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/register",
		Method:   "POST",
		IP:       "198.51.100.44",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected wrong grpc token to be unauthenticated, got %v", err)
	}

	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer grpc-platform-token")
	decision, err := grpcEvaluate(policyClient, ctx, types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/register",
		Method:   "POST",
		IP:       "198.51.100.44",
	})
	if err != nil {
		t.Fatalf("authorized evaluate: %v", err)
	}
	if decision.Action != types.DecisionChallenge || decision.SessionID == "" {
		t.Fatalf("expected platform-token challenge decision, got %+v", decision)
	}
}

func TestGRPCApplicationStatus(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	memoryStore.UpsertApplication(types.Application{
		ClientID:          "disabled-client",
		Name:              "disabled app",
		Status:            "disabled",
		DefaultFailPolicy: "fail_close",
	})
	captchaEngine := engine.New(2 * time.Minute)
	policyEvaluator := policy.NewEvaluator(memoryStore)
	server := New(Dependencies{
		Engine: captchaEngine,
		Policy: policyEvaluator,
		Store:  memoryStore,
		Logger: slog.Default(),
	})

	listener := bufconn.Listen(1024 * 1024)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
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

	policyClient := captchav1.NewPolicyServiceClient(conn)
	decision, err := grpcEvaluate(policyClient, context.Background(), types.PolicyEvaluateRequest{
		ClientID: "disabled-client",
		Path:     "/api/login",
		Method:   "POST",
		IP:       "198.51.100.44",
	})
	if err != nil {
		t.Fatalf("disabled app evaluate should return block decision, got %v", err)
	}
	if decision.Action != types.DecisionBlock || decision.Reason != "APPLICATION_DISABLED" {
		t.Fatalf("expected disabled app block decision, got %+v", decision)
	}

	ticketService := token.NewService(memoryStore, 2*time.Minute)
	ticket, err := ticketService.Issue("disabled-client", "login", "/api/login", "", "", "")
	if err != nil {
		t.Fatalf("issue disabled app ticket: %v", err)
	}
	ticketResponse, err := grpcVerifyTicket(captchav1.NewTicketServiceClient(conn), context.Background(), types.TicketVerifyRequest{
		Ticket:   ticket.Value,
		ClientID: "disabled-client",
		Scene:    "login",
		Route:    "/api/login",
	})
	if err != nil {
		t.Fatalf("disabled app ticket verify should return invalid response, got %v", err)
	}
	if ticketResponse.Valid || ticketResponse.Reason != "APPLICATION_DISABLED" {
		t.Fatalf("expected disabled app ticket rejection, got %+v", ticketResponse)
	}

	beforeEvent := len(memoryStore.ListAuditEvents("disabled-client", 20))
	_, err = captchav1.NewEventServiceClient(conn).Report(context.Background(), grpccontract.EventBatchToProto([]types.AuditEvent{
		{ClientID: "disabled-client", Scene: "login", Route: "/api/login", Action: types.DecisionObserve, DecisionReason: "DISABLED_EVENT", Result: "observe"},
	}))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected disabled app event report rejection, got %v", err)
	}
	if afterEvent := len(memoryStore.ListAuditEvents("disabled-client", 20)); afterEvent != beforeEvent {
		t.Fatalf("disabled app event should not be recorded, before=%d after=%d", beforeEvent, afterEvent)
	}

	configPB, err := captchav1.NewConfigServiceClient(conn).GetConfig(context.Background(), &captchav1.ConfigRequest{ClientId: "disabled-client"})
	if err != nil {
		t.Fatalf("get disabled app config: %v", err)
	}
	config := grpccontract.ConfigSnapshotFromProto(configPB)
	if config.ApplicationStatus != "disabled" {
		t.Fatalf("expected disabled status in config snapshot, got %+v", config)
	}
}

func grpcEvaluate(client captchav1.PolicyServiceClient, ctx context.Context, req types.PolicyEvaluateRequest) (types.PolicyDecision, error) {
	response, err := client.Evaluate(ctx, grpccontract.PolicyEvaluateRequestToProto(req))
	if err != nil {
		return types.PolicyDecision{}, err
	}
	return grpccontract.PolicyDecisionFromProto(response), nil
}

func grpcVerifyTicket(client captchav1.TicketServiceClient, ctx context.Context, req types.TicketVerifyRequest) (types.TicketVerifyResponse, error) {
	response, err := client.VerifyTicket(ctx, grpccontract.TicketVerifyRequestToProto(req))
	if err != nil {
		return types.TicketVerifyResponse{}, err
	}
	return grpccontract.TicketVerifyResponseFromProto(response), nil
}

func grpcConsumeTicket(client captchav1.TicketServiceClient, ctx context.Context, req types.TicketVerifyRequest) (types.TicketVerifyResponse, error) {
	response, err := client.ConsumeTicket(ctx, grpccontract.TicketVerifyRequestToProto(req))
	if err != nil {
		return types.TicketVerifyResponse{}, err
	}
	return grpccontract.TicketVerifyResponseFromProto(response), nil
}

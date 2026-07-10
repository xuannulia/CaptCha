package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"captcha/internal/policy"
	"captcha/internal/routepolicy"
	"captcha/internal/types"
)

type PolicyClient interface {
	Evaluate(context.Context, types.PolicyEvaluateRequest) (types.PolicyDecision, error)
}

type TicketClient interface {
	Consume(context.Context, types.TicketVerifyRequest) (types.TicketVerifyResponse, error)
}

type EventClient interface {
	Report(context.Context, []types.AuditEvent) (types.ReportResult, error)
}

type Config struct {
	ClientID               string
	ClientSecret           string
	PlatformURL            string
	PlatformGRPCAddr       string
	PlatformGRPCToken      string
	PolicyTransport        string
	EnableConfigCache      bool
	TrustedProxyCIDRs      []string
	UpstreamURL            string
	TicketHeader           string
	ClearanceHeader        string
	ClearanceCookieName    string
	RequestNonceHeader     string
	ResourceTagHeader      string
	AccountIDHeader        string
	DeviceIDHeader         string
	RiskScoreHeader        string
	RiskLevelHeader        string
	ModelScoreHeader       string
	ModelModeHeader        string
	HeaderAllowlist        []string
	FailPolicy             string
	RequestTimeout         time.Duration
	CircuitBreakerFailures int
	CircuitBreakerCooldown time.Duration
	EventBatchSize         int
	EventFlushInterval     time.Duration
	EventQueueSize         int
}

type Gateway struct {
	config        Config
	platform      *url.URL
	upstream      *url.URL
	policy        PolicyClient
	ticket        TicketClient
	events        EventClient
	cache         *ConfigCache
	proxy         *httputil.ReverseProxy
	httpClient    *http.Client
	logger        *slog.Logger
	proxies       []netip.Prefix
	policyBreaker *circuitBreaker
	ticketBreaker *circuitBreaker
	eventBatcher  *eventBatcher
}

var errCircuitBreakerOpen = errors.New("circuit breaker open")

func New(config Config, logger *slog.Logger) (*Gateway, error) {
	if config.ClientID == "" {
		config.ClientID = "demo"
	}
	if config.TicketHeader == "" {
		config.TicketHeader = "X-Captcha-Ticket"
	}
	if config.ClearanceHeader == "" {
		config.ClearanceHeader = "X-Captcha-Clearance"
	}
	if config.ClearanceCookieName == "" {
		config.ClearanceCookieName = "captcha_clearance"
	}
	if config.RequestNonceHeader == "" {
		config.RequestNonceHeader = "X-Captcha-Request-Nonce"
	}
	if config.ResourceTagHeader == "" {
		config.ResourceTagHeader = "X-Captcha-Resource-Tag"
	}
	if config.AccountIDHeader == "" {
		config.AccountIDHeader = "X-Captcha-Account-ID-Hash"
	}
	if config.DeviceIDHeader == "" {
		config.DeviceIDHeader = "X-Captcha-Device-ID-Hash"
	}
	if config.RiskScoreHeader == "" {
		config.RiskScoreHeader = "X-Captcha-Risk-Score"
	}
	if config.RiskLevelHeader == "" {
		config.RiskLevelHeader = "X-Captcha-Risk-Level"
	}
	if config.ModelScoreHeader == "" {
		config.ModelScoreHeader = "X-Captcha-Model-Score"
	}
	if config.ModelModeHeader == "" {
		config.ModelModeHeader = "X-Captcha-Model-Mode"
	}
	if config.FailPolicy == "" {
		config.FailPolicy = "fail_open"
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 1500 * time.Millisecond
	}
	if logger == nil {
		logger = slog.Default()
	}

	platformURL, err := url.Parse(strings.TrimRight(config.PlatformURL, "/"))
	if err != nil || platformURL.Scheme == "" || platformURL.Host == "" {
		return nil, fmt.Errorf("invalid platform url: %q", config.PlatformURL)
	}
	upstreamURL, err := url.Parse(config.UpstreamURL)
	if err != nil || upstreamURL.Scheme == "" || upstreamURL.Host == "" {
		return nil, fmt.Errorf("invalid upstream url: %q", config.UpstreamURL)
	}
	trustedProxies, err := parseTrustedProxyCIDRs(config.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{Timeout: config.RequestTimeout}
	policyTransport := strings.ToLower(strings.TrimSpace(config.PolicyTransport))
	if policyTransport == "" {
		policyTransport = "http"
	}
	grpcTarget := config.PlatformGRPCAddr
	if grpcTarget == "" && (policyTransport == "grpc" || config.EnableConfigCache) {
		grpcTarget = "localhost:9090"
	}
	gateway := &Gateway{
		config:        config,
		platform:      platformURL,
		upstream:      upstreamURL,
		httpClient:    httpClient,
		logger:        logger,
		proxies:       trustedProxies,
		policyBreaker: newCircuitBreaker(config.CircuitBreakerFailures, config.CircuitBreakerCooldown),
		ticketBreaker: newCircuitBreaker(config.CircuitBreakerFailures, config.CircuitBreakerCooldown),
	}
	if policyTransport == "grpc" {
		policyClient, err := NewGRPCPolicyClientWithAuth(grpcTarget, config.ClientSecret, config.PlatformGRPCToken)
		if err != nil {
			return nil, err
		}
		ticketClient, err := NewGRPCTicketClientWithAuth(grpcTarget, config.ClientSecret, config.PlatformGRPCToken)
		if err != nil {
			return nil, err
		}
		eventClient, err := NewGRPCEventClientWithAuth(grpcTarget, config.ClientSecret, config.PlatformGRPCToken)
		if err != nil {
			return nil, err
		}
		gateway.policy = policyClient
		gateway.ticket = ticketClient
		gateway.setEventClient(eventClient)
	} else {
		gateway.policy = &HTTPPolicyClient{BaseURL: platformURL, Client: httpClient, ClientSecret: config.ClientSecret}
		gateway.ticket = &HTTPTicketClient{BaseURL: platformURL, Client: httpClient, ClientSecret: config.ClientSecret}
		gateway.setEventClient(&HTTPEventClient{BaseURL: platformURL, Client: httpClient, ClientSecret: config.ClientSecret})
	}
	if config.EnableConfigCache {
		gateway.cache = NewConfigCache(config.ClientID)
		if grpcTarget != "" {
			configClient, err := NewGRPCConfigClientWithAuth(grpcTarget, config.ClientSecret, config.PlatformGRPCToken)
			if err != nil {
				return nil, err
			}
			gateway.startConfigCache(configClient)
		}
	}
	gateway.proxy = httputil.NewSingleHostReverseProxy(upstreamURL)
	return gateway, nil
}

func (g *Gateway) startConfigCache(client *GRPCConfigClient) {
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), g.config.RequestTimeout)
			snapshot, err := client.GetConfig(ctx, g.config.ClientID)
			cancel()
			if err == nil {
				g.cache.Update(snapshot)
			} else {
				g.logger.Warn("gateway config cache refresh failed", "error", err)
				time.Sleep(time.Second)
				continue
			}
			err = client.WatchConfig(context.Background(), g.config.ClientID, func(snapshot types.ConfigSnapshot) {
				g.cache.Update(snapshot)
			})
			if err != nil {
				g.logger.Warn("gateway config watch stopped", "error", err)
			}
			time.Sleep(time.Second)
		}
	}()
}

func NewWithPolicyClient(config Config, policy PolicyClient, logger *slog.Logger) (*Gateway, error) {
	gateway, err := New(config, logger)
	if err != nil {
		return nil, err
	}
	if policy != nil {
		gateway.policy = policy
		gateway.ticket = nil
		gateway.setEventClient(nil)
	}
	return gateway, nil
}

func NewWithClients(config Config, policy PolicyClient, ticket TicketClient, logger *slog.Logger) (*Gateway, error) {
	return NewWithClientsAndEvent(config, policy, ticket, nil, logger)
}

func NewWithClientsAndEvent(config Config, policy PolicyClient, ticket TicketClient, events EventClient, logger *slog.Logger) (*Gateway, error) {
	gateway, err := New(config, logger)
	if err != nil {
		return nil, err
	}
	if policy != nil {
		gateway.policy = policy
	}
	if ticket != nil {
		gateway.ticket = ticket
	}
	gateway.setEventClient(events)
	return gateway, nil
}

func (g *Gateway) Close() {
	if g == nil || g.eventBatcher == nil {
		return
	}
	g.eventBatcher.Close()
}

func (g *Gateway) setEventClient(events EventClient) {
	if g.eventBatcher != nil {
		g.eventBatcher.Close()
		g.eventBatcher = nil
	}
	if events == nil {
		g.events = nil
		return
	}
	if shouldBatchEvents(g.config) {
		batcher := newEventBatcher(events, eventBatcherOptions{
			MaxSize:       g.config.EventBatchSize,
			FlushInterval: g.config.EventFlushInterval,
			QueueSize:     g.config.EventQueueSize,
			ReportTimeout: g.config.RequestTimeout,
			Logger:        g.logger,
		})
		g.eventBatcher = batcher
		g.events = batcher
		return
	}
	g.events = events
}

func shouldBatchEvents(config Config) bool {
	return config.EventBatchSize > 1 || config.EventFlushInterval > 0 || config.EventQueueSize > 0
}

func (g *Gateway) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				_, _ = w.Write([]byte("ok\n"))
			}
			return
		}
		g.stripUntrustedContextHeaders(r)

		ctx, cancel := context.WithTimeout(r.Context(), g.config.RequestTimeout)
		defer cancel()

		evaluateRequest := types.PolicyEvaluateRequest{
			ClientID:      g.config.ClientID,
			Scene:         sceneFromRequest(r),
			Path:          r.URL.Path,
			Method:        r.Method,
			IP:            g.remoteIP(r),
			UserAgent:     r.UserAgent(),
			AccountIDHash: r.Header.Get(g.config.AccountIDHeader),
			DeviceIDHash:  r.Header.Get(g.config.DeviceIDHeader),
			Ticket:        r.Header.Get(g.config.TicketHeader),
			Clearance:     g.clearanceFromRequest(r),
			RequestNonce:  r.Header.Get(g.config.RequestNonceHeader),
			ResourceTag:   r.Header.Get(g.config.ResourceTagHeader),
			RiskScore:     intHeader(r.Header, g.config.RiskScoreHeader),
			RiskLevel:     r.Header.Get(g.config.RiskLevelHeader),
			ModelScore:    intHeader(r.Header, g.config.ModelScoreHeader),
			ModelMode:     r.Header.Get(g.config.ModelModeHeader),
			Headers:       collectAllowedHeaders(r.Header, g.config.HeaderAllowlist),
		}
		if decision, ok := g.localHardDecision(evaluateRequest); ok {
			g.reportDecision(evaluateRequest, decision)
			g.handleDecision(w, r, decision)
			return
		}
		if evaluateRequest.Ticket != "" && g.ticket != nil {
			ticketScene := g.ticketScene(evaluateRequest)
			ticketRequest := evaluateRequest
			ticketRequest.Scene = ticketScene
			if !g.ticketBreaker.Allow() {
				g.handleTicketError(w, r, ticketRequest, errCircuitBreakerOpen)
				return
			}
			response, err := g.ticket.Consume(ctx, types.TicketVerifyRequest{
				Ticket:        evaluateRequest.Ticket,
				ClientID:      evaluateRequest.ClientID,
				Scene:         ticketScene,
				Route:         evaluateRequest.Path,
				RequestNonce:  evaluateRequest.RequestNonce,
				IPHash:        hashValue(evaluateRequest.IP),
				UserAgentHash: hashValue(evaluateRequest.UserAgent),
				AccountIDHash: evaluateRequest.AccountIDHash,
				DeviceIDHash:  evaluateRequest.DeviceIDHash,
			})
			if err != nil {
				g.ticketBreaker.RecordFailure()
				g.handleTicketError(w, r, ticketRequest, err)
				return
			}
			g.ticketBreaker.RecordSuccess()
			if !response.Valid {
				reason := response.Reason
				if reason == "" {
					reason = "TICKET_INVALID"
				}
				writeJSON(w, http.StatusForbidden, map[string]any{
					"action": "block",
					"reason": reason,
				})
				g.reportDecision(ticketRequest, types.PolicyDecision{
					Action: types.DecisionBlock,
					Reason: reason,
					Scene:  firstNonEmpty(response.Scene, ticketScene),
				})
				return
			}
			g.reportDecision(ticketRequest, types.PolicyDecision{
				Action: types.DecisionAllow,
				Reason: "TICKET_CONSUMED",
				Scene:  firstNonEmpty(response.Scene, ticketScene),
			})
			g.writeClearance(w, r, response.ClearanceToken, response.ClearanceTTLSeconds)
			g.proxy.ServeHTTP(w, r)
			return
		}
		if decision, ok := g.localDecision(evaluateRequest); ok {
			g.reportDecision(evaluateRequest, decision)
			g.handleDecision(w, r, decision)
			return
		}

		if !g.policyBreaker.Allow() {
			g.handlePolicyError(w, r, errCircuitBreakerOpen)
			return
		}
		decision, err := g.policy.Evaluate(ctx, evaluateRequest)
		if err != nil {
			g.policyBreaker.RecordFailure()
			g.handlePolicyError(w, r, err)
			return
		}
		g.policyBreaker.RecordSuccess()
		g.handleDecision(w, r, decision)
	})
}

func (g *Gateway) ticketScene(req types.PolicyEvaluateRequest) string {
	if g.cache == nil {
		return req.Scene
	}
	snapshot, ok := g.cache.Snapshot()
	if !ok {
		return req.Scene
	}
	route := matchCachedRoute(snapshot.Routes, req, false)
	if route == nil || route.Scene == "" {
		return req.Scene
	}
	return route.Scene
}

func (g *Gateway) handleDecision(w http.ResponseWriter, r *http.Request, decision types.PolicyDecision) {
	switch decision.Action {
	case types.DecisionAllow, types.DecisionPass, types.DecisionObserve, types.DecisionSkipChallenge:
		g.writeClearance(w, r, decision.ClearanceToken, decision.ClearanceTTLSeconds)
		g.proxy.ServeHTTP(w, r)
	case types.DecisionChallenge, types.DecisionChallengeHarder, types.DecisionStepUpChallenge, types.DecisionRateLimit:
		g.writeChallenge(w, decision)
	case types.DecisionBlock, types.DecisionCooldown, types.DecisionBusinessVerify:
		writeJSON(w, http.StatusForbidden, map[string]any{
			"action":               decision.Action,
			"reason":               decision.Reason,
			"cooldown_seconds":     decision.CooldownSeconds,
			"business_verify_type": decision.BusinessVerifyType,
		})
	default:
		writeJSON(w, http.StatusForbidden, map[string]any{
			"action": types.DecisionBlock,
			"reason": "UNSUPPORTED_POLICY_DECISION",
		})
	}
}

func (g *Gateway) handleTicketError(w http.ResponseWriter, r *http.Request, req types.PolicyEvaluateRequest, err error) {
	g.logger.Error("gateway ticket consume failed", "error", err)
	if g.config.FailPolicy == "fail_close" {
		g.reportDecision(req, types.PolicyDecision{Action: types.DecisionBlock, Reason: "TICKET_SERVICE_UNAVAILABLE"})
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"action": "block",
			"reason": "TICKET_SERVICE_UNAVAILABLE",
		})
		return
	}
	g.reportDecision(req, types.PolicyDecision{Action: types.DecisionAllow, Reason: "TICKET_SERVICE_UNAVAILABLE"})
	g.proxy.ServeHTTP(w, r)
}

func (g *Gateway) handlePolicyError(w http.ResponseWriter, r *http.Request, err error) {
	g.logger.Error("gateway policy evaluate failed", "error", err)
	if g.config.FailPolicy == "fail_close" {
		g.reportDecision(types.PolicyEvaluateRequest{
			ClientID:      g.config.ClientID,
			Scene:         sceneFromRequest(r),
			Path:          r.URL.Path,
			Method:        r.Method,
			IP:            g.remoteIP(r),
			UserAgent:     r.UserAgent(),
			AccountIDHash: r.Header.Get(g.config.AccountIDHeader),
			DeviceIDHash:  r.Header.Get(g.config.DeviceIDHeader),
			ResourceTag:   r.Header.Get(g.config.ResourceTagHeader),
		}, types.PolicyDecision{Action: types.DecisionBlock, Reason: "POLICY_UNAVAILABLE"})
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"action": "block",
			"reason": "POLICY_UNAVAILABLE",
		})
		return
	}
	g.reportDecision(types.PolicyEvaluateRequest{
		ClientID:      g.config.ClientID,
		Scene:         sceneFromRequest(r),
		Path:          r.URL.Path,
		Method:        r.Method,
		IP:            g.remoteIP(r),
		UserAgent:     r.UserAgent(),
		AccountIDHash: r.Header.Get(g.config.AccountIDHeader),
		DeviceIDHash:  r.Header.Get(g.config.DeviceIDHeader),
		ResourceTag:   r.Header.Get(g.config.ResourceTagHeader),
	}, types.PolicyDecision{Action: types.DecisionAllow, Reason: "POLICY_UNAVAILABLE"})
	g.proxy.ServeHTTP(w, r)
}

func (g *Gateway) writeChallenge(w http.ResponseWriter, decision types.PolicyDecision) {
	challengeURL := decision.ChallengeURL
	if strings.HasPrefix(challengeURL, "/") {
		challengeURL = strings.TrimRight(g.platform.String(), "/") + challengeURL
	}
	writeJSON(w, http.StatusForbidden, map[string]any{
		"action":         decision.Action,
		"reason":         decision.Reason,
		"challenge_url":  challengeURL,
		"session_id":     decision.SessionID,
		"scene":          decision.Scene,
		"challenge_type": decision.ChallengeType,
		"ttl_seconds":    decision.TTLSeconds,
	})
}

func (g *Gateway) localDecision(req types.PolicyEvaluateRequest) (types.PolicyDecision, bool) {
	if req.Ticket != "" || g.cache == nil {
		return types.PolicyDecision{}, false
	}
	snapshot, ok := g.cache.Snapshot()
	if !ok {
		return types.PolicyDecision{}, false
	}
	if snapshot.ApplicationStatus != "" && !strings.EqualFold(snapshot.ApplicationStatus, "active") {
		return types.PolicyDecision{Action: types.DecisionBlock, Reason: "LOCAL_APPLICATION_DISABLED"}, true
	}
	if action, reason, ok := evaluateCachedIP(snapshot, req.IP); ok {
		switch action {
		case types.DecisionAllow, types.DecisionBlock:
			return types.PolicyDecision{Action: action, Reason: reason}, true
		default:
			return types.PolicyDecision{}, false
		}
	}
	if decision, ok := evaluateCachedPolicyRules(snapshot, req); ok {
		return decision, true
	}
	route := matchCachedRoute(snapshot.Routes, req, true)
	if route == nil {
		return types.PolicyDecision{Action: types.DecisionAllow, Reason: "LOCAL_NO_ROUTE_POLICY"}, true
	}
	mode := strings.ToLower(strings.TrimSpace(route.Mode))
	switch mode {
	case "manual_bypass":
		return types.PolicyDecision{Action: types.DecisionAllow, Reason: "LOCAL_MANUAL_BYPASS", Scene: route.Scene}, true
	case "silent":
		return types.PolicyDecision{Action: types.DecisionObserve, Reason: "LOCAL_SILENT", Scene: route.Scene}, true
	case "observe":
		return types.PolicyDecision{Action: types.DecisionObserve, Reason: "LOCAL_OBSERVE", Scene: route.Scene}, true
	default:
		return types.PolicyDecision{}, false
	}
}

func (g *Gateway) localHardDecision(req types.PolicyEvaluateRequest) (types.PolicyDecision, bool) {
	if g.cache == nil {
		return types.PolicyDecision{}, false
	}
	snapshot, ok := g.cache.Snapshot()
	if !ok {
		return types.PolicyDecision{}, false
	}
	if snapshot.ApplicationStatus != "" && !strings.EqualFold(snapshot.ApplicationStatus, "active") {
		return types.PolicyDecision{Action: types.DecisionBlock, Reason: "LOCAL_APPLICATION_DISABLED"}, true
	}
	if action, reason, ok := evaluateCachedIP(snapshot, req.IP); ok {
		switch action {
		case types.DecisionAllow, types.DecisionBlock:
			return types.PolicyDecision{Action: action, Reason: reason, Scene: req.Scene}, true
		default:
			return types.PolicyDecision{}, false
		}
	}
	return types.PolicyDecision{}, false
}

func (g *Gateway) clearanceFromRequest(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get(g.config.ClearanceHeader)); value != "" {
		return value
	}
	if g.config.ClearanceCookieName == "" {
		return ""
	}
	cookie, err := r.Cookie(g.config.ClearanceCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func (g *Gateway) writeClearance(w http.ResponseWriter, r *http.Request, token string, ttlSeconds int) {
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	w.Header().Set(g.config.ClearanceHeader, token)
	if g.config.ClearanceCookieName == "" {
		return
	}
	cookie := &http.Cookie{
		Name:     g.config.ClearanceCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
	}
	if ttlSeconds > 0 {
		cookie.MaxAge = ttlSeconds
	}
	http.SetCookie(w, cookie)
}

func (g *Gateway) reportDecision(req types.PolicyEvaluateRequest, decision types.PolicyDecision) {
	if g.events == nil {
		return
	}
	scene := decision.Scene
	if scene == "" {
		scene = req.Scene
	}
	event := types.AuditEvent{
		ClientID:       req.ClientID,
		Scene:          scene,
		Route:          req.Path,
		IPHash:         hashValue(req.IP),
		AccountIDHash:  req.AccountIDHash,
		DeviceIDHash:   req.DeviceIDHash,
		Action:         decision.Action,
		DecisionReason: decision.Reason,
		ChallengeType:  decision.ChallengeType,
		Result:         string(decision.Action),
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), g.config.RequestTimeout)
		defer cancel()
		if _, err := g.events.Report(ctx, []types.AuditEvent{event}); err != nil {
			g.logger.Warn("gateway event report failed", "error", err)
		}
	}()
}

func collectAllowedHeaders(headers http.Header, allowlist []string) map[string]string {
	if len(allowlist) == 0 {
		return nil
	}
	out := make(map[string]string)
	for _, name := range allowlist {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		values, ok := headerValues(headers, name)
		if !ok || len(values) == 0 {
			continue
		}
		value := strings.TrimSpace(strings.Join(values, ","))
		if value != "" {
			out[strings.ToLower(name)] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func headerValues(headers http.Header, name string) ([]string, bool) {
	for key, values := range headers {
		if strings.EqualFold(key, name) {
			return values, true
		}
	}
	return nil, false
}

type HTTPPolicyClient struct {
	BaseURL      *url.URL
	Client       *http.Client
	ClientSecret string
}

type HTTPTicketClient struct {
	BaseURL      *url.URL
	Client       *http.Client
	ClientSecret string
}

type HTTPEventClient struct {
	BaseURL      *url.URL
	Client       *http.Client
	ClientSecret string
}

type ConfigCache struct {
	mu       sync.RWMutex
	snapshot types.ConfigSnapshot
	ready    bool
}

func NewConfigCache(clientID string) *ConfigCache {
	return &ConfigCache{snapshot: types.ConfigSnapshot{ClientID: clientID}}
}

func (c *ConfigCache) Update(snapshot types.ConfigSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snapshot = snapshot
	c.ready = true
}

func (c *ConfigCache) Snapshot() (types.ConfigSnapshot, bool) {
	if c == nil {
		return types.ConfigSnapshot{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.ready {
		return types.ConfigSnapshot{}, false
	}
	return c.snapshot, true
}

func evaluateCachedPolicyRules(snapshot types.ConfigSnapshot, req types.PolicyEvaluateRequest) (types.PolicyDecision, bool) {
	evaluation := policy.EvaluatePolicyRules(snapshot.PolicyRules, req, time.Now().UTC())
	if !evaluation.Matched || evaluation.Rule == nil {
		return types.PolicyDecision{}, false
	}
	if cachedRuleAggregationConfigured(evaluation.Rule.Aggregation) || types.IsChallengeLikeDecision(evaluation.Action.Type) {
		return types.PolicyDecision{}, false
	}
	decision := types.PolicyDecision{
		Action:             evaluation.Action.Type,
		Reason:             evaluation.Reason,
		Scene:              req.Scene,
		CooldownSeconds:    evaluation.Action.CooldownSeconds,
		BusinessVerifyType: evaluation.Action.BusinessVerifyType,
	}
	if decision.Action == types.DecisionCooldown && decision.CooldownSeconds <= 0 {
		decision.CooldownSeconds = evaluation.Rule.Aggregation.CooldownSeconds
	}
	return decision, types.IsAllowLikeDecision(decision.Action) || types.IsBlockLikeDecision(decision.Action)
}

func cachedRuleAggregationConfigured(aggregation types.PolicyRuleAggregation) bool {
	return aggregation.WindowSeconds > 0 && aggregation.MaxRequests > 0 && len(aggregation.Dimensions) > 0
}

func evaluateCachedIP(snapshot types.ConfigSnapshot, ip string) (types.Decision, string, bool) {
	if ip == "" {
		return "", "", false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", "", false
	}
	for _, policyType := range []string{"allowlist", "blocklist"} {
		if action, reason, ok := firstMatchingCachedIPPolicy(addr, snapshot.IPPolicies, policyType); ok {
			return action, reason, true
		}
	}
	return firstMatchingCachedIPPolicy(addr, snapshot.IPPolicies, "")
}

func firstMatchingCachedIPPolicy(addr netip.Addr, policies []types.IPPolicy, policyType string) (types.Decision, string, bool) {
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		if policyType != "" && !strings.EqualFold(policy.Type, policyType) {
			continue
		}
		if policyType == "" && (strings.EqualFold(policy.Type, "allowlist") || strings.EqualFold(policy.Type, "blocklist")) {
			continue
		}
		prefix, err := parseIPPolicyPrefix(policy.CIDR)
		if err != nil || !prefix.Contains(addr) {
			continue
		}
		return policy.Action, "LOCAL_IP_" + strings.ToUpper(policy.Type), true
	}
	return "", "", false
}

func parseIPPolicyPrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	prefix, err := netip.ParsePrefix(value)
	if err == nil {
		return prefix.Masked(), nil
	}
	addr, addrErr := netip.ParseAddr(value)
	if addrErr != nil {
		return netip.Prefix{}, err
	}
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits), nil
}

func matchCachedRoute(routes []types.RoutePolicy, req types.PolicyEvaluateRequest, applyRollout bool) *types.RoutePolicy {
	candidates := append([]types.RoutePolicy(nil), routes...)
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].Priority > candidates[j].Priority
	})
	method := strings.ToUpper(req.Method)
	for i := range candidates {
		route := candidates[i]
		if !route.Enabled {
			continue
		}
		if route.Method != "" && strings.ToUpper(route.Method) != method {
			continue
		}
		if !matchCachedPath(route.PathPattern, req.Path) {
			continue
		}
		if applyRollout && !routepolicy.MatchesRollout(route, routepolicy.RolloutContext{
			ClientID:      req.ClientID,
			Path:          req.Path,
			Method:        req.Method,
			IP:            req.IP,
			UserAgent:     req.UserAgent,
			AccountIDHash: req.AccountIDHash,
			DeviceIDHash:  req.DeviceIDHash,
		}) {
			continue
		}
		return &route
	}
	return nil
}

func matchCachedPath(pattern, path string) bool {
	pattern = strings.TrimSpace(pattern)
	path = strings.TrimSpace(path)
	if pattern == "" || pattern == "*" {
		return true
	}
	if pattern == path {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "*"))
	}
	return false
}

func (c *HTTPPolicyClient) Evaluate(ctx context.Context, req types.PolicyEvaluateRequest) (types.PolicyDecision, error) {
	if c.BaseURL == nil {
		return types.PolicyDecision{}, errors.New("platform base url is nil")
	}
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}

	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(req); err != nil {
		return types.PolicyDecision{}, err
	}
	endpoint := c.BaseURL.ResolveReference(&url.URL{Path: "/api/v1/policy/evaluate"})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), &body)
	if err != nil {
		return types.PolicyDecision{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	setClientSecretHeader(httpReq.Header, c.ClientSecret)

	resp, err := client.Do(httpReq)
	if err != nil {
		return types.PolicyDecision{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return types.PolicyDecision{}, fmt.Errorf("platform returned status %d", resp.StatusCode)
	}

	var decision types.PolicyDecision
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return types.PolicyDecision{}, err
	}
	return decision, nil
}

func (c *HTTPTicketClient) Consume(ctx context.Context, req types.TicketVerifyRequest) (types.TicketVerifyResponse, error) {
	if c.BaseURL == nil {
		return types.TicketVerifyResponse{}, errors.New("platform base url is nil")
	}
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}

	body := map[string]any{
		"ticket":          req.Ticket,
		"client_id":       req.ClientID,
		"scene":           req.Scene,
		"route":           req.Route,
		"request_nonce":   req.RequestNonce,
		"ip_hash":         req.IPHash,
		"user_agent_hash": req.UserAgentHash,
		"account_id_hash": req.AccountIDHash,
		"device_id_hash":  req.DeviceIDHash,
		"consume":         true,
	}
	var encoded bytes.Buffer
	if err := json.NewEncoder(&encoded).Encode(body); err != nil {
		return types.TicketVerifyResponse{}, err
	}
	endpoint := c.BaseURL.ResolveReference(&url.URL{Path: "/api/v1/tickets/verify"})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), &encoded)
	if err != nil {
		return types.TicketVerifyResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	setClientSecretHeader(httpReq.Header, c.ClientSecret)

	resp, err := client.Do(httpReq)
	if err != nil {
		return types.TicketVerifyResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return types.TicketVerifyResponse{}, fmt.Errorf("platform returned status %d", resp.StatusCode)
	}

	var response types.TicketVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return types.TicketVerifyResponse{}, err
	}
	return response, nil
}

func (c *HTTPEventClient) Report(ctx context.Context, events []types.AuditEvent) (types.ReportResult, error) {
	if c.BaseURL == nil {
		return types.ReportResult{}, errors.New("platform base url is nil")
	}
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}

	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(types.EventBatch{Events: events}); err != nil {
		return types.ReportResult{}, err
	}
	endpoint := c.BaseURL.ResolveReference(&url.URL{Path: "/api/v1/events/report"})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), &body)
	if err != nil {
		return types.ReportResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	setClientSecretHeader(httpReq.Header, c.ClientSecret)

	resp, err := client.Do(httpReq)
	if err != nil {
		return types.ReportResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return types.ReportResult{}, fmt.Errorf("platform returned status %d", resp.StatusCode)
	}

	var result types.ReportResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return types.ReportResult{}, err
	}
	return result, nil
}

func sceneFromRequest(r *http.Request) string {
	if scene := r.Header.Get("X-Captcha-Scene"); scene != "" {
		return scene
	}
	trimmed := strings.Trim(r.URL.Path, "/")
	if trimmed == "" {
		return "default"
	}
	if idx := strings.Index(trimmed, "/"); idx >= 0 {
		return trimmed[:idx]
	}
	return trimmed
}

func (g *Gateway) remoteIP(r *http.Request) string {
	direct := directRemoteIP(r.RemoteAddr)
	if g.trustsProxy(direct) {
		if forwarded := firstForwardedIP(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			return forwarded
		}
	}
	return direct
}

func (g *Gateway) stripUntrustedContextHeaders(r *http.Request) {
	if g.trustsProxy(directRemoteIP(r.RemoteAddr)) {
		return
	}
	for _, header := range []string{
		g.config.AccountIDHeader,
		g.config.DeviceIDHeader,
		g.config.RiskScoreHeader,
		g.config.RiskLevelHeader,
		g.config.ModelScoreHeader,
		g.config.ModelModeHeader,
	} {
		if header != "" {
			r.Header.Del(header)
		}
	}
}

func (g *Gateway) trustsProxy(ip string) bool {
	if len(g.proxies) == 0 || ip == "" {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, prefix := range g.proxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func directRemoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func firstForwardedIP(forwarded string) string {
	for _, part := range strings.Split(forwarded, ",") {
		candidate := strings.TrimSpace(part)
		if candidate == "" {
			continue
		}
		if _, err := netip.ParseAddr(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

func parseTrustedProxyCIDRs(cidrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, addrErr := netip.ParseAddr(cidr)
		if addrErr != nil {
			return nil, fmt.Errorf("invalid trusted proxy cidr %q: %w", cidr, err)
		}
		bits := 128
		if addr.Is4() {
			bits = 32
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, bits))
	}
	return prefixes, nil
}

type circuitBreaker struct {
	mu        sync.Mutex
	threshold int
	cooldown  time.Duration
	failures  int
	openUntil time.Time
}

func newCircuitBreaker(threshold int, cooldown time.Duration) *circuitBreaker {
	return &circuitBreaker{threshold: threshold, cooldown: cooldown}
}

func (b *circuitBreaker) Allow() bool {
	if b == nil || b.threshold <= 0 || b.cooldown <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return time.Now().After(b.openUntil)
}

func (b *circuitBreaker) RecordSuccess() {
	if b == nil || b.threshold <= 0 || b.cooldown <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.openUntil = time.Time{}
}

func (b *circuitBreaker) RecordFailure() {
	if b == nil || b.threshold <= 0 || b.cooldown <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures++
	if b.failures >= b.threshold {
		b.failures = 0
		b.openUntil = time.Now().Add(b.cooldown)
	}
}

func hashValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	encoded := hex.EncodeToString(sum[:])
	return "sha256:" + encoded[:32]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func setClientSecretHeader(header http.Header, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		header.Set("X-Captcha-Client-Secret", value)
	}
}

func intHeader(header http.Header, name string) int {
	value := strings.TrimSpace(header.Get(name))
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	if parsed < 0 {
		return 0
	}
	if parsed > 100 {
		return 100
	}
	return parsed
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

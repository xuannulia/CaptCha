package captchamiddleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Decision string

const (
	DecisionAllow           Decision = "allow"
	DecisionChallenge       Decision = "challenge"
	DecisionPass            Decision = "pass"
	DecisionRetry           Decision = "retry"
	DecisionChallengeHarder Decision = "challenge_harder"
	DecisionBlock           Decision = "block"
	DecisionObserve         Decision = "observe"
	DecisionSkipChallenge   Decision = "skip_challenge"
	DecisionStepUpChallenge Decision = "step_up_challenge"
	DecisionRateLimit       Decision = "rate_limit"
	DecisionCooldown        Decision = "cooldown"
	DecisionBusinessVerify  Decision = "require_business_verify"
)

type PolicyEvaluateRequest struct {
	ClientID      string            `json:"client_id"`
	Scene         string            `json:"scene"`
	Path          string            `json:"path"`
	Method        string            `json:"method"`
	IP            string            `json:"ip"`
	UserAgent     string            `json:"user_agent"`
	AccountIDHash string            `json:"account_id_hash,omitempty"`
	DeviceIDHash  string            `json:"device_id_hash,omitempty"`
	Ticket        string            `json:"ticket,omitempty"`
	Clearance     string            `json:"clearance,omitempty"`
	RequestNonce  string            `json:"request_nonce,omitempty"`
	ResourceTag   string            `json:"resource_tag,omitempty"`
	RiskScore     int               `json:"risk_score,omitempty"`
	RiskLevel     string            `json:"risk_level,omitempty"`
	ModelScore    int               `json:"model_score,omitempty"`
	ModelMode     string            `json:"model_mode,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
}

type PolicyDecision struct {
	Action              Decision `json:"action"`
	Reason              string   `json:"reason"`
	ChallengeURL        string   `json:"challenge_url,omitempty"`
	SessionID           string   `json:"session_id,omitempty"`
	Scene               string   `json:"scene,omitempty"`
	ChallengeType       string   `json:"challenge_type,omitempty"`
	TTLSeconds          int      `json:"ttl_seconds,omitempty"`
	CooldownSeconds     int      `json:"cooldown_seconds,omitempty"`
	BusinessVerifyType  string   `json:"business_verify_type,omitempty"`
	ClearanceToken      string   `json:"clearance_token,omitempty"`
	ClearanceTTLSeconds int      `json:"clearance_ttl_seconds,omitempty"`
}

type TicketConsumeRequest struct {
	Ticket        string `json:"ticket"`
	ClientID      string `json:"client_id"`
	Scene         string `json:"scene"`
	Route         string `json:"route"`
	RequestNonce  string `json:"request_nonce,omitempty"`
	IPHash        string `json:"ip_hash,omitempty"`
	UserAgentHash string `json:"user_agent_hash,omitempty"`
	AccountIDHash string `json:"account_id_hash,omitempty"`
	DeviceIDHash  string `json:"device_id_hash,omitempty"`
	Consume       bool   `json:"consume"`
}

type TicketConsumeResponse struct {
	Valid               bool   `json:"valid"`
	Reason              string `json:"reason,omitempty"`
	ClientID            string `json:"client_id,omitempty"`
	Scene               string `json:"scene,omitempty"`
	Route               string `json:"route,omitempty"`
	RequestNonce        string `json:"request_nonce,omitempty"`
	IPHash              string `json:"ip_hash,omitempty"`
	UserAgentHash       string `json:"user_agent_hash,omitempty"`
	ClearanceToken      string `json:"clearance_token,omitempty"`
	ClearanceTTLSeconds int    `json:"clearance_ttl_seconds,omitempty"`
}

type AuditEvent struct {
	ClientID       string   `json:"client_id"`
	Scene          string   `json:"scene"`
	Route          string   `json:"route"`
	IPHash         string   `json:"ip_hash,omitempty"`
	AccountIDHash  string   `json:"account_id_hash,omitempty"`
	DeviceIDHash   string   `json:"device_id_hash,omitempty"`
	Action         Decision `json:"action"`
	DecisionReason string   `json:"decision_reason"`
	ChallengeType  string   `json:"challenge_type,omitempty"`
	Result         string   `json:"result"`
}

type ReportResult struct {
	Accepted int `json:"accepted"`
}

type PolicyClient interface {
	Evaluate(context.Context, PolicyEvaluateRequest) (PolicyDecision, error)
}

type TicketClient interface {
	Consume(context.Context, TicketConsumeRequest) (TicketConsumeResponse, error)
}

type EventClient interface {
	Report(context.Context, []AuditEvent) (ReportResult, error)
}

type Options struct {
	PlatformURL                    string
	ClientID                       string
	ClientSecret                   string
	TicketHeader                   string
	ClearanceHeader                string
	ClearanceCookieName            string
	ClearanceCookieSecure          bool
	RequestNonceHeader             string
	ResourceTagHeader              string
	AccountIDHashHeader            string
	DeviceIDHashHeader             string
	RiskScoreHeader                string
	RiskLevelHeader                string
	ModelScoreHeader               string
	ModelModeHeader                string
	SceneHeader                    string
	FailPolicy                     string
	Timeout                        time.Duration
	CircuitBreakerFailureThreshold int
	CircuitBreakerCooldown         time.Duration
	TrustedProxyCIDRs              []string
	HeaderAllowlist                []string
	ResolveScene                   func(*http.Request) string
	ResolveAccountIDHash           func(*http.Request) string
	ResolveDeviceIDHash            func(*http.Request) string
	ShouldProtect                  func(*http.Request) bool
	HTTPClient                     *http.Client
	PolicyClient                   PolicyClient
	TicketClient                   TicketClient
	EventClient                    EventClient
}

type Middleware struct {
	options     Options
	platform    *url.URL
	proxies     []netip.Prefix
	policy      PolicyClient
	ticket      TicketClient
	events      EventClient
	policyBreak *circuitBreaker
	ticketBreak *circuitBreaker
}

var errCircuitBreakerOpen = errors.New("circuit breaker open")

func New(options Options) (*Middleware, error) {
	if options.ClientID == "" {
		options.ClientID = "demo"
	}
	if options.TicketHeader == "" {
		options.TicketHeader = "X-Captcha-Ticket"
	}
	if options.ClearanceHeader == "" {
		options.ClearanceHeader = "X-Captcha-Clearance"
	}
	if options.ClearanceCookieName == "" {
		options.ClearanceCookieName = "captcha_clearance"
	}
	if options.RequestNonceHeader == "" {
		options.RequestNonceHeader = "X-Captcha-Request-Nonce"
	}
	if options.ResourceTagHeader == "" {
		options.ResourceTagHeader = "X-Captcha-Resource-Tag"
	}
	if options.AccountIDHashHeader == "" {
		options.AccountIDHashHeader = "X-Captcha-Account-ID-Hash"
	}
	if options.DeviceIDHashHeader == "" {
		options.DeviceIDHashHeader = "X-Captcha-Device-ID-Hash"
	}
	if options.RiskScoreHeader == "" {
		options.RiskScoreHeader = "X-Captcha-Risk-Score"
	}
	if options.RiskLevelHeader == "" {
		options.RiskLevelHeader = "X-Captcha-Risk-Level"
	}
	if options.ModelScoreHeader == "" {
		options.ModelScoreHeader = "X-Captcha-Model-Score"
	}
	if options.ModelModeHeader == "" {
		options.ModelModeHeader = "X-Captcha-Model-Mode"
	}
	if options.SceneHeader == "" {
		options.SceneHeader = "X-Captcha-Scene"
	}
	if options.FailPolicy == "" {
		options.FailPolicy = "fail_open"
	}
	if options.Timeout <= 0 {
		options.Timeout = 1500 * time.Millisecond
	}

	platformURL, err := url.Parse(strings.TrimRight(options.PlatformURL, "/"))
	if err != nil || platformURL.Scheme == "" || platformURL.Host == "" {
		return nil, fmt.Errorf("invalid platform url: %q", options.PlatformURL)
	}
	proxies, err := parseTrustedProxyCIDRs(options.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}

	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: options.Timeout}
	}
	httpPlatform := &HTTPPlatformClient{
		BaseURL:      platformURL,
		Client:       httpClient,
		ClientSecret: options.ClientSecret,
	}
	policy := options.PolicyClient
	if policy == nil {
		policy = httpPlatform
	}
	ticket := options.TicketClient
	if ticket == nil {
		ticket = httpPlatform
	}
	events := options.EventClient
	if events == nil {
		events = httpPlatform
	}

	return &Middleware{
		options:     options,
		platform:    platformURL,
		proxies:     proxies,
		policy:      policy,
		ticket:      ticket,
		events:      events,
		policyBreak: newCircuitBreaker(options.CircuitBreakerFailureThreshold, options.CircuitBreakerCooldown),
		ticketBreak: newCircuitBreaker(options.CircuitBreakerFailureThreshold, options.CircuitBreakerCooldown),
	}, nil
}

func (m *Middleware) Handler(next http.Handler) http.Handler {
	if next == nil {
		next = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.options.ShouldProtect != nil && !m.options.ShouldProtect(r) {
			next.ServeHTTP(w, r)
			return
		}

		evaluateRequest := m.buildEvaluateRequest(r)
		if evaluateRequest.Ticket != "" {
			if !m.ticketBreak.Allow() {
				m.handleUnavailable(w, r, next, evaluateRequest, "TICKET_SERVICE_UNAVAILABLE", errCircuitBreakerOpen)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), m.options.Timeout)
			response, err := m.ticket.Consume(ctx, TicketConsumeRequest{
				Ticket:        evaluateRequest.Ticket,
				ClientID:      evaluateRequest.ClientID,
				Scene:         evaluateRequest.Scene,
				Route:         evaluateRequest.Path,
				RequestNonce:  evaluateRequest.RequestNonce,
				IPHash:        hashValue(evaluateRequest.IP),
				UserAgentHash: hashValue(evaluateRequest.UserAgent),
				AccountIDHash: evaluateRequest.AccountIDHash,
				DeviceIDHash:  evaluateRequest.DeviceIDHash,
				Consume:       true,
			})
			cancel()
			if err != nil {
				m.ticketBreak.RecordFailure()
				m.handleUnavailable(w, r, next, evaluateRequest, "TICKET_SERVICE_UNAVAILABLE", err)
				return
			}
			m.ticketBreak.RecordSuccess()
			if !response.Valid {
				reason := firstNonEmpty(response.Reason, "TICKET_INVALID")
				m.reportDecision(evaluateRequest, PolicyDecision{
					Action: DecisionBlock,
					Reason: reason,
					Scene:  firstNonEmpty(response.Scene, evaluateRequest.Scene),
				})
				writeJSON(w, http.StatusForbidden, map[string]any{
					"action": DecisionBlock,
					"reason": reason,
				})
				return
			}
			m.writeClearance(w, r, response.ClearanceToken, response.ClearanceTTLSeconds)
			m.reportDecision(evaluateRequest, PolicyDecision{
				Action: DecisionAllow,
				Reason: "TICKET_CONSUMED",
				Scene:  firstNonEmpty(response.Scene, evaluateRequest.Scene),
			})
			next.ServeHTTP(w, r)
			return
		}

		if !m.policyBreak.Allow() {
			m.handleUnavailable(w, r, next, evaluateRequest, "POLICY_UNAVAILABLE", errCircuitBreakerOpen)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), m.options.Timeout)
		decision, err := m.policy.Evaluate(ctx, evaluateRequest)
		cancel()
		if err != nil {
			m.policyBreak.RecordFailure()
			m.handleUnavailable(w, r, next, evaluateRequest, "POLICY_UNAVAILABLE", err)
			return
		}
		m.policyBreak.RecordSuccess()
		m.handleDecision(w, r, next, decision)
	})
}

func (m *Middleware) buildEvaluateRequest(r *http.Request) PolicyEvaluateRequest {
	scene := ""
	if m.options.ResolveScene != nil {
		scene = strings.TrimSpace(m.options.ResolveScene(r))
	}
	if scene == "" {
		scene = strings.TrimSpace(r.Header.Get(m.options.SceneHeader))
	}
	if scene == "" {
		scene = sceneFromPath(r.URL.Path)
	}

	accountIDHash := ""
	if m.options.ResolveAccountIDHash != nil {
		accountIDHash = strings.TrimSpace(m.options.ResolveAccountIDHash(r))
	}
	if accountIDHash == "" {
		accountIDHash = strings.TrimSpace(r.Header.Get(m.options.AccountIDHashHeader))
	}
	deviceIDHash := ""
	if m.options.ResolveDeviceIDHash != nil {
		deviceIDHash = strings.TrimSpace(m.options.ResolveDeviceIDHash(r))
	}
	if deviceIDHash == "" {
		deviceIDHash = strings.TrimSpace(r.Header.Get(m.options.DeviceIDHashHeader))
	}

	return PolicyEvaluateRequest{
		ClientID:      m.options.ClientID,
		Scene:         scene,
		Path:          r.URL.Path,
		Method:        strings.ToUpper(firstNonEmpty(r.Method, http.MethodGet)),
		IP:            m.remoteIP(r),
		UserAgent:     r.UserAgent(),
		AccountIDHash: accountIDHash,
		DeviceIDHash:  deviceIDHash,
		Ticket:        strings.TrimSpace(r.Header.Get(m.options.TicketHeader)),
		Clearance:     m.clearanceFromRequest(r),
		RequestNonce:  strings.TrimSpace(r.Header.Get(m.options.RequestNonceHeader)),
		ResourceTag:   strings.TrimSpace(r.Header.Get(m.options.ResourceTagHeader)),
		RiskScore:     intHeader(r.Header, m.options.RiskScoreHeader),
		RiskLevel:     strings.TrimSpace(r.Header.Get(m.options.RiskLevelHeader)),
		ModelScore:    intHeader(r.Header, m.options.ModelScoreHeader),
		ModelMode:     strings.TrimSpace(r.Header.Get(m.options.ModelModeHeader)),
		Headers:       collectAllowedHeaders(r.Header, m.options.HeaderAllowlist),
	}
}

func (m *Middleware) handleDecision(w http.ResponseWriter, r *http.Request, next http.Handler, decision PolicyDecision) {
	switch decision.Action {
	case DecisionAllow, DecisionObserve, DecisionPass, DecisionSkipChallenge:
		m.writeClearance(w, r, decision.ClearanceToken, decision.ClearanceTTLSeconds)
		next.ServeHTTP(w, r)
	case DecisionChallenge, DecisionChallengeHarder, DecisionStepUpChallenge, DecisionRateLimit:
		writeJSON(w, http.StatusForbidden, map[string]any{
			"action":         decision.Action,
			"reason":         decision.Reason,
			"challenge_url":  m.absoluteChallengeURL(decision.ChallengeURL),
			"session_id":     decision.SessionID,
			"scene":          decision.Scene,
			"challenge_type": decision.ChallengeType,
			"ttl_seconds":    decision.TTLSeconds,
		})
	case DecisionBlock, DecisionCooldown, DecisionBusinessVerify:
		writeJSON(w, http.StatusForbidden, map[string]any{
			"action":               decision.Action,
			"reason":               decision.Reason,
			"cooldown_seconds":     decision.CooldownSeconds,
			"business_verify_type": decision.BusinessVerifyType,
		})
	default:
		writeJSON(w, http.StatusForbidden, map[string]any{
			"action": DecisionBlock,
			"reason": "UNSUPPORTED_POLICY_DECISION",
		})
	}
}

func (m *Middleware) handleUnavailable(w http.ResponseWriter, r *http.Request, next http.Handler, req PolicyEvaluateRequest, reason string, _ error) {
	action := DecisionAllow
	if m.options.FailPolicy == "fail_close" {
		action = DecisionBlock
	}
	m.reportDecision(req, PolicyDecision{Action: action, Reason: reason})
	if m.options.FailPolicy == "fail_close" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"action": DecisionBlock,
			"reason": reason,
		})
		return
	}
	next.ServeHTTP(w, r)
}

func (m *Middleware) clearanceFromRequest(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get(m.options.ClearanceHeader)); value != "" {
		return value
	}
	if m.options.ClearanceCookieName == "" {
		return ""
	}
	cookie, err := r.Cookie(m.options.ClearanceCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func (m *Middleware) writeClearance(w http.ResponseWriter, r *http.Request, token string, ttlSeconds int) {
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	w.Header().Set(m.options.ClearanceHeader, token)
	if m.options.ClearanceCookieName == "" {
		return
	}
	cookie := &http.Cookie{
		Name:     m.options.ClearanceCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   m.options.ClearanceCookieSecure,
	}
	if ttlSeconds > 0 {
		cookie.MaxAge = ttlSeconds
	}
	http.SetCookie(w, cookie)
}

func (m *Middleware) reportDecision(req PolicyEvaluateRequest, decision PolicyDecision) {
	if m.events == nil {
		return
	}
	event := AuditEvent{
		ClientID:       req.ClientID,
		Scene:          firstNonEmpty(decision.Scene, req.Scene),
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
		ctx, cancel := context.WithTimeout(context.Background(), m.options.Timeout)
		defer cancel()
		_, _ = m.events.Report(ctx, []AuditEvent{event})
	}()
}

func (m *Middleware) remoteIP(r *http.Request) string {
	direct := directRemoteIP(r.RemoteAddr)
	if len(m.proxies) == 0 || direct == "" {
		return direct
	}
	addr, err := netip.ParseAddr(direct)
	if err != nil {
		return direct
	}
	trusted := false
	for _, prefix := range m.proxies {
		if prefix.Contains(addr) {
			trusted = true
			break
		}
	}
	if !trusted {
		return direct
	}
	if forwarded := firstForwardedIP(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		return forwarded
	}
	return direct
}

func (m *Middleware) absoluteChallengeURL(challengeURL string) string {
	challengeURL = strings.TrimSpace(challengeURL)
	if challengeURL == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(challengeURL), "http://") || strings.HasPrefix(strings.ToLower(challengeURL), "https://") {
		return challengeURL
	}
	base := strings.TrimRight(m.platform.String(), "/")
	if strings.HasPrefix(challengeURL, "/") {
		return base + challengeURL
	}
	return base + "/" + challengeURL
}

type HTTPPlatformClient struct {
	BaseURL      *url.URL
	Client       *http.Client
	ClientSecret string
}

func (c *HTTPPlatformClient) Evaluate(ctx context.Context, req PolicyEvaluateRequest) (PolicyDecision, error) {
	var decision PolicyDecision
	if err := c.postJSON(ctx, "/api/v1/policy/evaluate", req, &decision); err != nil {
		return PolicyDecision{}, err
	}
	return decision, nil
}

func (c *HTTPPlatformClient) Consume(ctx context.Context, req TicketConsumeRequest) (TicketConsumeResponse, error) {
	req.Consume = true
	var response TicketConsumeResponse
	if err := c.postJSON(ctx, "/api/v1/tickets/verify", req, &response); err != nil {
		return TicketConsumeResponse{}, err
	}
	return response, nil
}

func (c *HTTPPlatformClient) Report(ctx context.Context, events []AuditEvent) (ReportResult, error) {
	var result ReportResult
	if err := c.postJSON(ctx, "/api/v1/events/report", map[string]any{"events": events}, &result); err != nil {
		return ReportResult{}, err
	}
	return result, nil
}

func (c *HTTPPlatformClient) postJSON(ctx context.Context, path string, requestBody any, responseBody any) error {
	if c.BaseURL == nil {
		return errors.New("platform base url is nil")
	}
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(requestBody); err != nil {
		return err
	}
	endpoint := c.BaseURL.ResolveReference(&url.URL{Path: path})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), &body)
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if secret := strings.TrimSpace(c.ClientSecret); secret != "" {
		httpReq.Header.Set("X-Captcha-Client-Secret", secret)
	}

	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("platform returned status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(responseBody)
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

func directRemoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return strings.TrimSpace(remoteAddr)
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

func sceneFromPath(path string) string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return "default"
	}
	if idx := strings.Index(trimmed, "/"); idx >= 0 {
		return trimmed[:idx]
	}
	return trimmed
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

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

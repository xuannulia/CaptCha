package policy

import (
	"net/netip"
	"sort"
	"strings"
	"time"

	"captcha/internal/resource"
	"captcha/internal/routepolicy"
	"captcha/internal/store"
	"captcha/internal/types"
)

type Evaluator struct {
	store store.Store
}

type Evaluation struct {
	Action              types.Decision
	Reason              string
	Route               *types.RoutePolicy
	ChallengeType       types.CaptchaType
	ChallengeEscalation []types.CaptchaType
	TTLSeconds          int
}

func NewEvaluator(store store.Store) *Evaluator {
	return &Evaluator{store: store}
}

func (e *Evaluator) Evaluate(req types.PolicyEvaluateRequest) Evaluation {
	return e.evaluate(req, false)
}

func (e *Evaluator) EvaluateDryRun(req types.PolicyEvaluateRequest) Evaluation {
	return e.evaluate(req, true)
}

func (e *Evaluator) EvaluateIP(req types.PolicyEvaluateRequest) (types.Decision, string, bool) {
	return e.evaluateIP(req)
}

func (e *Evaluator) evaluate(req types.PolicyEvaluateRequest, dryRun bool) Evaluation {
	if req.ClientID == "" {
		req.ClientID = "demo"
	}

	if action, reason, ok := e.evaluateIP(req); ok {
		return Evaluation{Action: action, Reason: reason}
	}

	route := e.matchRoute(req)
	if route == nil {
		return Evaluation{Action: types.DecisionAllow, Reason: "NO_ROUTE_POLICY"}
	}

	mode := strings.ToLower(strings.TrimSpace(route.Mode))
	switch mode {
	case "always":
		challengeType := e.chooseChallengeType(req, route, "ALWAYS")
		return Evaluation{
			Action:              types.DecisionChallenge,
			Reason:              "ALWAYS",
			Route:               route,
			ChallengeType:       challengeType,
			ChallengeEscalation: route.ChallengeEscalation,
			TTLSeconds:          ttl(route),
		}
	case "rate_limit":
		if dryRun {
			return e.evaluateRateLimitDryRun(req, route)
		}
		return e.evaluateRateLimit(req, route)
	case "risk_based":
		return e.evaluateRiskBased(req, route)
	case "silent":
		return Evaluation{Action: types.DecisionObserve, Reason: "SILENT", Route: route}
	case "observe":
		return Evaluation{Action: types.DecisionObserve, Reason: "OBSERVE", Route: route}
	case "manual_bypass":
		return Evaluation{Action: types.DecisionAllow, Reason: "MANUAL_BYPASS", Route: route}
	default:
		return Evaluation{Action: types.DecisionAllow, Reason: "UNKNOWN_MODE", Route: route}
	}
}

func (e *Evaluator) evaluateRiskBased(req types.PolicyEvaluateRequest, route *types.RoutePolicy) Evaluation {
	score, ok := effectiveRiskScore(req)
	if !ok || !riskThresholdConfigured(route) {
		if req.AccountIDHash != "" || req.DeviceIDHash != "" {
			return Evaluation{Action: types.DecisionAllow, Reason: "LOW_RISK_CONTEXT", Route: route}
		}
		challengeType := e.chooseChallengeType(req, route, "RISK_BASED")
		return Evaluation{
			Action:              types.DecisionChallenge,
			Reason:              "RISK_BASED",
			Route:               route,
			ChallengeType:       challengeType,
			ChallengeEscalation: route.ChallengeEscalation,
			TTLSeconds:          ttl(route),
		}
	}
	if route.RiskBlockScore > 0 && score >= route.RiskBlockScore {
		return Evaluation{Action: types.DecisionBlock, Reason: "RISK_SCORE_BLOCK", Route: route}
	}
	if route.RiskChallengeScore > 0 && score >= route.RiskChallengeScore {
		challengeType := e.chooseRiskChallengeType(req, route)
		return Evaluation{
			Action:              types.DecisionChallenge,
			Reason:              "RISK_SCORE",
			Route:               route,
			ChallengeType:       challengeType,
			ChallengeEscalation: route.ChallengeEscalation,
			TTLSeconds:          ttl(route),
		}
	}
	if route.RiskObserveScore > 0 && score >= route.RiskObserveScore {
		return Evaluation{Action: types.DecisionObserve, Reason: "RISK_SCORE_OBSERVE", Route: route}
	}
	return Evaluation{Action: types.DecisionAllow, Reason: "LOW_RISK_SCORE", Route: route}
}

func riskThresholdConfigured(route *types.RoutePolicy) bool {
	return route != nil && (route.RiskChallengeScore > 0 || route.RiskBlockScore > 0 || route.RiskObserveScore > 0)
}

func effectiveRiskScore(req types.PolicyEvaluateRequest) (int, bool) {
	score := -1
	if req.RiskScore > 0 {
		score = clampRiskScore(req.RiskScore)
	}
	if levelScore, ok := riskLevelScore(req.RiskLevel); ok && levelScore > score {
		score = levelScore
	}
	if modelDecisionMode(req.ModelMode) && req.ModelScore > score {
		score = clampRiskScore(req.ModelScore)
	}
	if score < 0 {
		return 0, false
	}
	return score, true
}

func riskLevelScore(level string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return 95, true
	case "high":
		return 80, true
	case "medium":
		return 55, true
	case "low":
		return 15, true
	default:
		return 0, false
	}
}

func modelDecisionMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "observe", "enforce":
		return true
	default:
		return false
	}
}

func clampRiskScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func (e *Evaluator) evaluateRateLimitDryRun(req types.PolicyEvaluateRequest, route *types.RoutePolicy) Evaluation {
	if route.RateLimit == nil || route.RateLimit.WindowSeconds <= 0 || route.RateLimit.MaxRequests <= 0 {
		return Evaluation{Action: types.DecisionAllow, Reason: "RATE_LIMIT_NOT_CONFIGURED", Route: route}
	}
	if len(rateLimitKeys(req, route)) == 0 {
		return Evaluation{Action: types.DecisionAllow, Reason: "UNDER_RATE_LIMIT", Route: route}
	}
	challengeType := e.chooseChallengeType(req, route, "RATE_LIMIT")
	return Evaluation{
		Action:              types.DecisionObserve,
		Reason:              "RATE_LIMIT_DRY_RUN",
		Route:               route,
		ChallengeType:       challengeType,
		ChallengeEscalation: route.ChallengeEscalation,
		TTLSeconds:          ttl(route),
	}
}

func (e *Evaluator) evaluateRateLimit(req types.PolicyEvaluateRequest, route *types.RoutePolicy) Evaluation {
	if route.RateLimit == nil || route.RateLimit.WindowSeconds <= 0 || route.RateLimit.MaxRequests <= 0 {
		return Evaluation{Action: types.DecisionAllow, Reason: "RATE_LIMIT_NOT_CONFIGURED", Route: route}
	}
	window := time.Duration(route.RateLimit.WindowSeconds) * time.Second
	for _, key := range rateLimitKeys(req, route) {
		if e.store.IncrementRate(key, window, route.RateLimit.MaxRequests, route.RateLimit.Strategy) > route.RateLimit.MaxRequests {
			challengeType := e.chooseChallengeType(req, route, "RATE_LIMIT")
			return Evaluation{
				Action:              types.DecisionChallenge,
				Reason:              "RATE_LIMIT",
				Route:               route,
				ChallengeType:       challengeType,
				ChallengeEscalation: route.ChallengeEscalation,
				TTLSeconds:          ttl(route),
			}
		}
	}
	return Evaluation{Action: types.DecisionAllow, Reason: "UNDER_RATE_LIMIT", Route: route}
}

func rateLimitKeys(req types.PolicyEvaluateRequest, route *types.RoutePolicy) []string {
	dimensions := []struct {
		name  string
		value string
	}{
		{name: "ip", value: req.IP},
		{name: "account", value: req.AccountIDHash},
		{name: "device", value: req.DeviceIDHash},
	}
	keys := make([]string, 0, len(dimensions))
	for _, dimension := range dimensions {
		value := strings.TrimSpace(dimension.value)
		if value == "" {
			continue
		}
		keys = append(keys, strings.Join([]string{"rate", req.ClientID, route.ID, dimension.name, value}, ":"))
	}
	return keys
}

func (e *Evaluator) chooseChallengeType(req types.PolicyEvaluateRequest, route *types.RoutePolicy, reason string) types.CaptchaType {
	if route == nil {
		return types.CaptchaSlider
	}
	scene := route.Scene
	if scene == "" {
		scene = req.Scene
	}
	return resource.ChooseCaptchaType(
		e.store.ListResources(req.ClientID),
		route.ChallengeType,
		scene,
		req.ResourceTag,
		autoChallengePreferences(scene, route.Mode, reason),
	)
}

func (e *Evaluator) chooseRiskChallengeType(req types.PolicyEvaluateRequest, route *types.RoutePolicy) types.CaptchaType {
	if route == nil || route.RiskChallengeType == "" {
		return e.chooseChallengeType(req, route, "RISK_SCORE")
	}
	copy := *route
	copy.ChallengeType = route.RiskChallengeType
	return e.chooseChallengeType(req, &copy, "RISK_SCORE")
}

func autoChallengePreferences(scene, mode, reason string) []types.CaptchaType {
	scene = strings.ToLower(strings.TrimSpace(scene))
	mode = strings.ToLower(strings.TrimSpace(mode))
	reason = strings.ToUpper(strings.TrimSpace(reason))
	if reason == "RATE_LIMIT" || strings.Contains(scene, "register") || strings.Contains(scene, "signup") || strings.Contains(scene, "sms") || strings.Contains(scene, "comment") {
		return []types.CaptchaType{types.CaptchaWordImageClick, types.CaptchaSlider, types.CaptchaRotate, types.CaptchaConcat}
	}
	if mode == "risk_based" || strings.Contains(scene, "pay") || strings.Contains(scene, "withdraw") {
		return []types.CaptchaType{types.CaptchaRotate, types.CaptchaSlider, types.CaptchaWordImageClick, types.CaptchaConcat}
	}
	if strings.Contains(scene, "login") {
		return []types.CaptchaType{types.CaptchaSlider, types.CaptchaRotate, types.CaptchaWordImageClick, types.CaptchaConcat}
	}
	return nil
}

func (e *Evaluator) evaluateIP(req types.PolicyEvaluateRequest) (types.Decision, string, bool) {
	if req.IP == "" {
		return "", "", false
	}
	addr, err := netip.ParseAddr(req.IP)
	if err != nil {
		return "", "", false
	}
	policies := e.store.ListIPPolicies(req.ClientID)
	for _, policyType := range []string{"allowlist", "blocklist"} {
		if action, reason, ok := firstMatchingIPPolicy(addr, policies, policyType); ok {
			return action, reason, true
		}
	}
	return firstMatchingIPPolicy(addr, policies, "")
}

func firstMatchingIPPolicy(addr netip.Addr, policies []types.IPPolicy, policyType string) (types.Decision, string, bool) {
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
		return policy.Action, "IP_" + strings.ToUpper(policy.Type), true
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

func (e *Evaluator) matchRoute(req types.PolicyEvaluateRequest) *types.RoutePolicy {
	routes := e.store.ListRoutePolicies(req.ClientID)
	sort.SliceStable(routes, func(i, j int) bool {
		return routes[i].Priority > routes[j].Priority
	})
	method := strings.ToUpper(req.Method)
	for i := range routes {
		route := routes[i]
		if !route.Enabled {
			continue
		}
		if route.Method != "" && strings.ToUpper(route.Method) != method {
			continue
		}
		if matchPath(route.PathPattern, req.Path) && routepolicy.MatchesRollout(route, rolloutContext(req)) {
			return &route
		}
	}
	return nil
}

func rolloutContext(req types.PolicyEvaluateRequest) routepolicy.RolloutContext {
	return routepolicy.RolloutContext{
		ClientID:      req.ClientID,
		Path:          req.Path,
		Method:        req.Method,
		IP:            req.IP,
		UserAgent:     req.UserAgent,
		AccountIDHash: req.AccountIDHash,
		DeviceIDHash:  req.DeviceIDHash,
	}
}

func matchPath(pattern, path string) bool {
	if pattern == path {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "*"))
	}
	return false
}

func ttl(route *types.RoutePolicy) int {
	if route.TokenTTLSeconds > 0 {
		return route.TokenTTLSeconds
	}
	return 120
}

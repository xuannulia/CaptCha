package grpccontract

import (
	"encoding/json"
	"fmt"
	"time"

	captchav1 "captcha/gen/captcha/v1"
	"captcha/internal/types"
)

func PolicyEvaluateRequestFromProto(req *captchav1.EvaluateRequest) types.PolicyEvaluateRequest {
	if req == nil {
		return types.PolicyEvaluateRequest{}
	}
	return types.PolicyEvaluateRequest{
		ClientID:      req.GetClientId(),
		Scene:         req.GetScene(),
		Path:          req.GetPath(),
		Method:        req.GetMethod(),
		IP:            req.GetIp(),
		UserAgent:     req.GetUserAgent(),
		AccountIDHash: req.GetAccountIdHash(),
		DeviceIDHash:  req.GetDeviceIdHash(),
		Ticket:        req.GetTicket(),
		RequestNonce:  req.GetRequestNonce(),
		ResourceTag:   req.GetResourceTag(),
		RiskScore:     int(req.GetRiskScore()),
		RiskLevel:     req.GetRiskLevel(),
		ModelScore:    int(req.GetModelScore()),
		ModelMode:     req.GetModelMode(),
		Clearance:     req.GetClearance(),
		Headers:       cloneStringMap(req.GetHeaders()),
	}
}

func PolicyEvaluateRequestToProto(req types.PolicyEvaluateRequest) *captchav1.EvaluateRequest {
	return &captchav1.EvaluateRequest{
		ClientId:      req.ClientID,
		Scene:         req.Scene,
		Path:          req.Path,
		Method:        req.Method,
		Ip:            req.IP,
		UserAgent:     req.UserAgent,
		AccountIdHash: req.AccountIDHash,
		DeviceIdHash:  req.DeviceIDHash,
		Ticket:        req.Ticket,
		RequestNonce:  req.RequestNonce,
		ResourceTag:   req.ResourceTag,
		RiskScore:     int32(req.RiskScore),
		RiskLevel:     req.RiskLevel,
		ModelScore:    int32(req.ModelScore),
		ModelMode:     req.ModelMode,
		Clearance:     req.Clearance,
		Headers:       cloneStringMap(req.Headers),
	}
}

func PolicyDecisionFromProto(decision *captchav1.EvaluateResponse) types.PolicyDecision {
	if decision == nil {
		return types.PolicyDecision{}
	}
	return types.PolicyDecision{
		Action:              decisionFromProto(decision.GetAction()),
		Reason:              decision.GetReason(),
		ChallengeURL:        decision.GetChallengeUrl(),
		SessionID:           decision.GetSessionId(),
		Scene:               decision.GetScene(),
		ChallengeType:       types.CaptchaType(decision.GetChallengeType()),
		TTLSeconds:          int(decision.GetTtlSeconds()),
		ClearanceToken:      decision.GetClearanceToken(),
		ClearanceTTLSeconds: int(decision.GetClearanceTtlSeconds()),
	}
}

func PolicyDecisionToProto(decision types.PolicyDecision) *captchav1.EvaluateResponse {
	return &captchav1.EvaluateResponse{
		Action:              decisionToProto(decision.Action),
		Reason:              decision.Reason,
		ChallengeUrl:        decision.ChallengeURL,
		SessionId:           decision.SessionID,
		Scene:               decision.Scene,
		ChallengeType:       string(decision.ChallengeType),
		TtlSeconds:          int32(decision.TTLSeconds),
		ClearanceToken:      decision.ClearanceToken,
		ClearanceTtlSeconds: int32(decision.ClearanceTTLSeconds),
	}
}

func TicketVerifyRequestFromProto(req *captchav1.VerifyTicketRequest) types.TicketVerifyRequest {
	if req == nil {
		return types.TicketVerifyRequest{}
	}
	return types.TicketVerifyRequest{
		Ticket:        req.GetTicket(),
		ClientID:      req.GetClientId(),
		Scene:         req.GetScene(),
		Route:         req.GetRoute(),
		RequestNonce:  req.GetRequestNonce(),
		IPHash:        req.GetIpHash(),
		UserAgentHash: req.GetUserAgentHash(),
		AccountIDHash: req.GetAccountIdHash(),
		DeviceIDHash:  req.GetDeviceIdHash(),
	}
}

func TicketVerifyRequestToProto(req types.TicketVerifyRequest) *captchav1.VerifyTicketRequest {
	return &captchav1.VerifyTicketRequest{
		Ticket:        req.Ticket,
		ClientId:      req.ClientID,
		Scene:         req.Scene,
		Route:         req.Route,
		RequestNonce:  req.RequestNonce,
		IpHash:        req.IPHash,
		UserAgentHash: req.UserAgentHash,
		AccountIdHash: req.AccountIDHash,
		DeviceIdHash:  req.DeviceIDHash,
	}
}

func TicketVerifyResponseFromProto(response *captchav1.VerifyTicketResponse) types.TicketVerifyResponse {
	if response == nil {
		return types.TicketVerifyResponse{}
	}
	var expireAt time.Time
	if response.GetExpireUnix() > 0 {
		expireAt = time.Unix(response.GetExpireUnix(), 0).UTC()
	}
	var clearanceExpireAt time.Time
	if response.GetClearanceExpireUnix() > 0 {
		clearanceExpireAt = time.Unix(response.GetClearanceExpireUnix(), 0).UTC()
	}
	return types.TicketVerifyResponse{
		Valid:               response.GetValid(),
		Reason:              response.GetReason(),
		ClientID:            response.GetClientId(),
		Scene:               response.GetScene(),
		Route:               response.GetRoute(),
		RequestNonce:        response.GetRequestNonce(),
		IPHash:              response.GetIpHash(),
		UserAgentHash:       response.GetUserAgentHash(),
		ExpireAt:            expireAt,
		ClearanceToken:      response.GetClearanceToken(),
		ClearanceExpireAt:   clearanceExpireAt,
		ClearanceTTLSeconds: int(response.GetClearanceTtlSeconds()),
	}
}

func TicketVerifyResponseToProto(response types.TicketVerifyResponse) *captchav1.VerifyTicketResponse {
	var expireUnix int64
	if !response.ExpireAt.IsZero() {
		expireUnix = response.ExpireAt.Unix()
	}
	var clearanceExpireUnix int64
	if !response.ClearanceExpireAt.IsZero() {
		clearanceExpireUnix = response.ClearanceExpireAt.Unix()
	}
	return &captchav1.VerifyTicketResponse{
		Valid:               response.Valid,
		Reason:              response.Reason,
		ClientId:            response.ClientID,
		Scene:               response.Scene,
		Route:               response.Route,
		RequestNonce:        response.RequestNonce,
		IpHash:              response.IPHash,
		UserAgentHash:       response.UserAgentHash,
		ExpireUnix:          expireUnix,
		ClearanceToken:      response.ClearanceToken,
		ClearanceExpireUnix: clearanceExpireUnix,
		ClearanceTtlSeconds: int32(response.ClearanceTTLSeconds),
	}
}

func ConfigSnapshotFromProto(snapshot *captchav1.ConfigSnapshot) types.ConfigSnapshot {
	if snapshot == nil {
		return types.ConfigSnapshot{}
	}
	routes := make([]types.RoutePolicy, 0, len(snapshot.GetRoutes()))
	for _, route := range snapshot.GetRoutes() {
		routes = append(routes, routePolicyFromProto(route))
	}
	ipPolicies := make([]types.IPPolicy, 0, len(snapshot.GetIpPolicies()))
	for _, policy := range snapshot.GetIpPolicies() {
		ipPolicies = append(ipPolicies, ipPolicyFromProto(policy))
	}
	policyRules := make([]types.PolicyRule, 0, len(snapshot.GetPolicyRules()))
	for _, rule := range snapshot.GetPolicyRules() {
		policyRules = append(policyRules, policyRuleFromProto(rule))
	}
	resources := make([]types.CaptchaResource, 0, len(snapshot.GetResources()))
	for _, resource := range snapshot.GetResources() {
		resources = append(resources, captchaResourceFromProto(resource))
	}
	return types.ConfigSnapshot{
		ClientID:          snapshot.GetClientId(),
		ApplicationStatus: snapshot.GetApplicationStatus(),
		Routes:            routes,
		PolicyRules:       policyRules,
		IPPolicies:        ipPolicies,
		Resources:         resources,
		Version:           snapshot.GetVersion(),
	}
}

func ConfigSnapshotToProto(snapshot types.ConfigSnapshot) *captchav1.ConfigSnapshot {
	routes := make([]*captchav1.RoutePolicy, 0, len(snapshot.Routes))
	for _, route := range snapshot.Routes {
		routes = append(routes, routePolicyToProto(route))
	}
	ipPolicies := make([]*captchav1.IpPolicy, 0, len(snapshot.IPPolicies))
	for _, policy := range snapshot.IPPolicies {
		ipPolicies = append(ipPolicies, ipPolicyToProto(policy))
	}
	policyRules := make([]*captchav1.PolicyRule, 0, len(snapshot.PolicyRules))
	for _, rule := range snapshot.PolicyRules {
		policyRules = append(policyRules, policyRuleToProto(rule))
	}
	resources := make([]*captchav1.CaptchaResource, 0, len(snapshot.Resources))
	for _, resource := range snapshot.Resources {
		resources = append(resources, captchaResourceToProto(resource))
	}
	return &captchav1.ConfigSnapshot{
		ClientId:          snapshot.ClientID,
		ApplicationStatus: snapshot.ApplicationStatus,
		Routes:            routes,
		IpPolicies:        ipPolicies,
		PolicyRules:       policyRules,
		Resources:         resources,
		Version:           snapshot.Version,
	}
}

func EventBatchFromProto(batch *captchav1.EventBatch) types.EventBatch {
	if batch == nil {
		return types.EventBatch{}
	}
	events := make([]types.AuditEvent, 0, len(batch.GetEvents()))
	for _, event := range batch.GetEvents() {
		events = append(events, auditEventFromProto(event))
	}
	return types.EventBatch{Events: events}
}

func EventBatchToProto(events []types.AuditEvent) *captchav1.EventBatch {
	out := make([]*captchav1.AuditEvent, 0, len(events))
	for _, event := range events {
		out = append(out, auditEventToProto(event))
	}
	return &captchav1.EventBatch{Events: out}
}

func ReportResultFromProto(result *captchav1.ReportResult) types.ReportResult {
	if result == nil {
		return types.ReportResult{}
	}
	return types.ReportResult{Accepted: int(result.GetAccepted())}
}

func ReportResultToProto(result types.ReportResult) *captchav1.ReportResult {
	return &captchav1.ReportResult{Accepted: int32(result.Accepted)}
}

func routePolicyFromProto(route *captchav1.RoutePolicy) types.RoutePolicy {
	if route == nil {
		return types.RoutePolicy{}
	}
	var rateLimit *types.RateLimit
	if route.GetRateLimit() != nil {
		rateLimit = &types.RateLimit{
			WindowSeconds: int(route.GetRateLimit().GetWindowSeconds()),
			MaxRequests:   int(route.GetRateLimit().GetMaxRequests()),
			Strategy:      route.GetRateLimit().GetStrategy(),
		}
	}
	escalation := make([]types.CaptchaType, 0, len(route.GetChallengeEscalation()))
	for _, captchaType := range route.GetChallengeEscalation() {
		escalation = append(escalation, types.CaptchaType(captchaType))
	}
	return types.RoutePolicy{
		ID:                  route.GetId(),
		ClientID:            route.GetClientId(),
		Name:                route.GetName(),
		PathPattern:         route.GetPathPattern(),
		Method:              route.GetMethod(),
		Scene:               route.GetScene(),
		Mode:                route.GetMode(),
		ChallengeType:       types.CaptchaType(route.GetChallengeType()),
		RiskChallengeType:   types.CaptchaType(route.GetRiskChallengeType()),
		ChallengeEscalation: escalation,
		FailPolicy:          route.GetFailPolicy(),
		Priority:            int(route.GetPriority()),
		Enabled:             route.GetEnabled(),
		RolloutPercent:      int(route.GetRolloutPercent()),
		TokenTTLSeconds:     int(route.GetTokenTtlSeconds()),
		RiskChallengeScore:  int(route.GetRiskChallengeScore()),
		RiskBlockScore:      int(route.GetRiskBlockScore()),
		RiskObserveScore:    int(route.GetRiskObserveScore()),
		RateLimit:           rateLimit,
	}
}

func routePolicyToProto(route types.RoutePolicy) *captchav1.RoutePolicy {
	var rateLimit *captchav1.RateLimit
	if route.RateLimit != nil {
		rateLimit = &captchav1.RateLimit{
			WindowSeconds: int32(route.RateLimit.WindowSeconds),
			MaxRequests:   int32(route.RateLimit.MaxRequests),
			Strategy:      route.RateLimit.Strategy,
		}
	}
	escalation := make([]string, 0, len(route.ChallengeEscalation))
	for _, captchaType := range route.ChallengeEscalation {
		escalation = append(escalation, string(captchaType))
	}
	return &captchav1.RoutePolicy{
		Id:                  route.ID,
		ClientId:            route.ClientID,
		Name:                route.Name,
		PathPattern:         route.PathPattern,
		Method:              route.Method,
		Scene:               route.Scene,
		Mode:                route.Mode,
		ChallengeType:       string(route.ChallengeType),
		RiskChallengeType:   string(route.RiskChallengeType),
		ChallengeEscalation: escalation,
		FailPolicy:          route.FailPolicy,
		Priority:            int32(route.Priority),
		Enabled:             route.Enabled,
		RolloutPercent:      int32(route.RolloutPercent),
		TokenTtlSeconds:     int32(route.TokenTTLSeconds),
		RiskChallengeScore:  int32(route.RiskChallengeScore),
		RiskBlockScore:      int32(route.RiskBlockScore),
		RiskObserveScore:    int32(route.RiskObserveScore),
		RateLimit:           rateLimit,
	}
}

func policyRuleFromProto(rule *captchav1.PolicyRule) types.PolicyRule {
	if rule == nil {
		return types.PolicyRule{}
	}
	out := types.PolicyRule{
		ID:             rule.GetId(),
		ClientID:       rule.GetClientId(),
		Name:           rule.GetName(),
		Description:    rule.GetDescription(),
		Priority:       int(rule.GetPriority()),
		Enabled:        rule.GetEnabled(),
		Status:         rule.GetStatus(),
		Version:        rule.GetVersion(),
		RolloutPercent: int(rule.GetRolloutPercent()),
	}
	_ = json.Unmarshal([]byte(rule.GetScopeJson()), &out.Scope)
	_ = json.Unmarshal([]byte(rule.GetConditionsJson()), &out.Conditions)
	_ = json.Unmarshal([]byte(rule.GetAggregationJson()), &out.Aggregation)
	_ = json.Unmarshal([]byte(rule.GetActionJson()), &out.Action)
	return out
}

func policyRuleToProto(rule types.PolicyRule) *captchav1.PolicyRule {
	return &captchav1.PolicyRule{
		Id:              rule.ID,
		ClientId:        rule.ClientID,
		Name:            rule.Name,
		Description:     rule.Description,
		Priority:        int32(rule.Priority),
		Enabled:         rule.Enabled,
		Status:          rule.Status,
		Version:         rule.Version,
		ScopeJson:       jsonString(rule.Scope),
		ConditionsJson:  jsonString(rule.Conditions),
		AggregationJson: jsonString(rule.Aggregation),
		ActionJson:      jsonString(rule.Action),
		RolloutPercent:  int32(rule.RolloutPercent),
	}
}

func jsonString(value any) string {
	data, err := json.Marshal(value)
	if err != nil || string(data) == "null" {
		return "{}"
	}
	return string(data)
}

func ipPolicyFromProto(policy *captchav1.IpPolicy) types.IPPolicy {
	if policy == nil {
		return types.IPPolicy{}
	}
	return types.IPPolicy{
		ID:       policy.GetId(),
		ClientID: policy.GetClientId(),
		Type:     policy.GetType(),
		CIDR:     policy.GetCidr(),
		Action:   types.Decision(policy.GetAction()),
		Reason:   policy.GetReason(),
		Enabled:  policy.GetEnabled(),
	}
}

func ipPolicyToProto(policy types.IPPolicy) *captchav1.IpPolicy {
	return &captchav1.IpPolicy{
		Id:       policy.ID,
		ClientId: policy.ClientID,
		Type:     policy.Type,
		Cidr:     policy.CIDR,
		Action:   string(policy.Action),
		Reason:   policy.Reason,
		Enabled:  policy.Enabled,
	}
}

func captchaResourceFromProto(resource *captchav1.CaptchaResource) types.CaptchaResource {
	if resource == nil {
		return types.CaptchaResource{}
	}
	return types.CaptchaResource{
		ID:           resource.GetId(),
		ClientID:     resource.GetClientId(),
		Scene:        resource.GetScene(),
		CaptchaType:  types.CaptchaType(resource.GetCaptchaType()),
		ResourceType: resource.GetResourceType(),
		StorageType:  resource.GetStorageType(),
		URI:          resource.GetUri(),
		Tag:          resource.GetTag(),
		Status:       resource.GetStatus(),
		Checksum:     resource.GetChecksum(),
		Metadata:     stringMapToAnyMap(resource.GetMetadata()),
	}
}

func captchaResourceToProto(resource types.CaptchaResource) *captchav1.CaptchaResource {
	return &captchav1.CaptchaResource{
		Id:           resource.ID,
		ClientId:     resource.ClientID,
		Scene:        resource.Scene,
		CaptchaType:  string(resource.CaptchaType),
		ResourceType: resource.ResourceType,
		StorageType:  resource.StorageType,
		Uri:          resource.URI,
		Tag:          resource.Tag,
		Status:       resource.Status,
		Checksum:     resource.Checksum,
		Metadata:     anyMapToStringMap(resource.Metadata),
	}
}

func auditEventFromProto(event *captchav1.AuditEvent) types.AuditEvent {
	if event == nil {
		return types.AuditEvent{}
	}
	return types.AuditEvent{
		ClientID:       event.GetClientId(),
		Scene:          event.GetScene(),
		Route:          event.GetRoute(),
		IPHash:         event.GetIpHash(),
		AccountIDHash:  event.GetAccountIdHash(),
		DeviceIDHash:   event.GetDeviceIdHash(),
		Action:         types.Decision(event.GetAction()),
		DecisionReason: event.GetDecisionReason(),
		ChallengeType:  types.CaptchaType(event.GetChallengeType()),
		Result:         event.GetResult(),
	}
}

func auditEventToProto(event types.AuditEvent) *captchav1.AuditEvent {
	return &captchav1.AuditEvent{
		ClientId:       event.ClientID,
		Scene:          event.Scene,
		Route:          event.Route,
		IpHash:         event.IPHash,
		AccountIdHash:  event.AccountIDHash,
		DeviceIdHash:   event.DeviceIDHash,
		Action:         string(event.Action),
		DecisionReason: event.DecisionReason,
		ChallengeType:  string(event.ChallengeType),
		Result:         event.Result,
	}
}

func decisionToProto(decision types.Decision) captchav1.DecisionAction {
	switch decision {
	case types.DecisionAllow, types.DecisionPass, types.DecisionSkipChallenge:
		return captchav1.DecisionAction_ALLOW
	case types.DecisionChallenge, types.DecisionChallengeHarder, types.DecisionStepUpChallenge, types.DecisionRateLimit:
		return captchav1.DecisionAction_CHALLENGE
	case types.DecisionBlock, types.DecisionCooldown, types.DecisionBusinessVerify:
		return captchav1.DecisionAction_BLOCK
	case types.DecisionObserve:
		return captchav1.DecisionAction_OBSERVE
	default:
		return captchav1.DecisionAction_DECISION_ACTION_UNSPECIFIED
	}
}

func decisionFromProto(decision captchav1.DecisionAction) types.Decision {
	switch decision {
	case captchav1.DecisionAction_ALLOW:
		return types.DecisionAllow
	case captchav1.DecisionAction_CHALLENGE:
		return types.DecisionChallenge
	case captchav1.DecisionAction_BLOCK:
		return types.DecisionBlock
	case captchav1.DecisionAction_OBSERVE:
		return types.DecisionObserve
	default:
		return ""
	}
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func anyMapToStringMap(input map[string]any) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		switch typed := value.(type) {
		case string:
			out[key] = typed
		case nil:
			out[key] = ""
		default:
			data, err := json.Marshal(typed)
			if err == nil {
				out[key] = string(data)
			} else {
				out[key] = fmt.Sprint(typed)
			}
		}
	}
	return out
}

func stringMapToAnyMap(input map[string]string) map[string]any {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		var decoded any
		if err := json.Unmarshal([]byte(value), &decoded); err == nil {
			out[key] = decoded
		} else {
			out[key] = value
		}
	}
	return out
}

package policy

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"captcha/internal/routepolicy"
	"captcha/internal/types"
)

type RuleEvaluation struct {
	Matched     bool
	Rule        *types.PolicyRule
	Action      types.PolicyRuleAction
	Reason      string
	Explanation []string
}

func EvaluatePolicyRules(rules []types.PolicyRule, req types.PolicyEvaluateRequest, now time.Time) RuleEvaluation {
	candidates := append([]types.PolicyRule(nil), rules...)
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].Priority > candidates[j].Priority
	})
	for i := range candidates {
		evaluation := EvaluatePolicyRule(candidates[i], req, now)
		if evaluation.Matched {
			return evaluation
		}
	}
	return RuleEvaluation{Explanation: []string{"no policy rule matched"}}
}

func EvaluatePolicyRule(rule types.PolicyRule, req types.PolicyEvaluateRequest, now time.Time) RuleEvaluation {
	explanation := make([]string, 0, 8)
	if !rule.Enabled {
		return RuleEvaluation{Explanation: []string{"rule disabled"}}
	}
	if strings.EqualFold(strings.TrimSpace(rule.Status), "retired") {
		return RuleEvaluation{Explanation: []string{"rule retired"}}
	}
	if !policyRuleScopeMatches(rule, req, now, &explanation) {
		return RuleEvaluation{Explanation: explanation}
	}
	if !policyRuleRolloutMatches(rule, req) {
		return RuleEvaluation{Explanation: append(explanation, "rollout skipped")}
	}
	matched, conditionExplanation := policyConditionMatches(rule.Conditions, req)
	explanation = append(explanation, conditionExplanation...)
	if !matched {
		return RuleEvaluation{Explanation: explanation}
	}
	action := rule.Action
	reason := strings.TrimSpace(action.Reason)
	if reason == "" {
		reason = "POLICY_RULE_MATCH"
	}
	explanation = append(explanation, "action "+string(action.Type))
	return RuleEvaluation{
		Matched:     true,
		Rule:        &rule,
		Action:      action,
		Reason:      reason,
		Explanation: explanation,
	}
}

func policyRuleScopeMatches(rule types.PolicyRule, req types.PolicyEvaluateRequest, now time.Time, explanation *[]string) bool {
	scope := rule.Scope
	clientID := firstNonEmpty(scope.ClientID, rule.ClientID)
	if clientID != "" && clientID != req.ClientID {
		*explanation = append(*explanation, "client_id did not match")
		return false
	}
	if len(scope.Scenes) > 0 && !stringIn(req.Scene, scope.Scenes, true) {
		*explanation = append(*explanation, "scene did not match")
		return false
	}
	if len(scope.Methods) > 0 && !stringIn(strings.ToUpper(req.Method), upperStrings(scope.Methods), false) {
		*explanation = append(*explanation, "method did not match")
		return false
	}
	if len(scope.PathPatterns) > 0 && !anyPathMatches(scope.PathPatterns, req.Path) {
		*explanation = append(*explanation, "path did not match")
		return false
	}
	if len(scope.ResourceTags) > 0 && !stringIn(req.ResourceTag, scope.ResourceTags, true) {
		*explanation = append(*explanation, "resource_tag did not match")
		return false
	}
	if scope.ActiveFrom != nil && now.Before(*scope.ActiveFrom) {
		*explanation = append(*explanation, "rule not active yet")
		return false
	}
	if scope.ActiveUntil != nil && !now.Before(*scope.ActiveUntil) {
		*explanation = append(*explanation, "rule expired")
		return false
	}
	*explanation = append(*explanation, "scope matched")
	return true
}

func policyRuleRolloutMatches(rule types.PolicyRule, req types.PolicyEvaluateRequest) bool {
	percent := rule.RolloutPercent
	if percent <= 0 {
		percent = rule.Scope.RolloutPercent
	}
	percent = routepolicy.NormalizeRolloutPercent(percent)
	if percent >= 100 {
		return true
	}
	key := rolloutContext(req)
	rolloutKey := firstNonEmpty(key.AccountIDHash, key.DeviceIDHash, key.IP, key.UserAgent, key.Path, key.ClientID)
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(strings.Join([]string{
		rule.ID,
		rule.Name,
		firstNonEmpty(firstPathPattern(rule.Scope.PathPatterns), req.Path),
		rolloutKey,
	}, "|")))
	return int(hash.Sum32()%100) < percent
}

func policyConditionMatches(condition types.PolicyCondition, req types.PolicyEvaluateRequest) (bool, []string) {
	explanation := make([]string, 0, 4)
	if len(condition.All) == 0 && len(condition.Any) == 0 && condition.Not == nil && strings.TrimSpace(condition.Field) == "" {
		return true, []string{"conditions empty"}
	}
	matched := true
	if len(condition.All) > 0 {
		for _, child := range condition.All {
			childMatched, childExplanation := policyConditionMatches(child, req)
			explanation = append(explanation, childExplanation...)
			if !childMatched {
				matched = false
			}
		}
	}
	if len(condition.Any) > 0 {
		anyMatched := false
		for _, child := range condition.Any {
			childMatched, childExplanation := policyConditionMatches(child, req)
			explanation = append(explanation, childExplanation...)
			if childMatched {
				anyMatched = true
			}
		}
		if !anyMatched {
			matched = false
		}
	}
	if condition.Not != nil {
		notMatched, childExplanation := policyConditionMatches(*condition.Not, req)
		explanation = append(explanation, childExplanation...)
		if notMatched {
			matched = false
		}
	}
	if strings.TrimSpace(condition.Field) != "" {
		leafMatched, leafExplanation := policyLeafConditionMatches(condition, req)
		explanation = append(explanation, leafExplanation)
		if !leafMatched {
			matched = false
		}
	}
	return matched, explanation
}

func policyLeafConditionMatches(condition types.PolicyCondition, req types.PolicyEvaluateRequest) (bool, string) {
	value, present := policyFieldValue(condition.Field, req)
	op := strings.ToLower(strings.TrimSpace(condition.Op))
	if op == "" {
		op = "eq"
	}
	var matched bool
	switch op {
	case "exists":
		matched = present
	case "not_exists":
		matched = !present
	case "eq":
		matched = present && valueString(value) == valueString(condition.Value)
	case "ne":
		matched = !present || valueString(value) != valueString(condition.Value)
	case "in":
		matched = present && valueIn(value, conditionValues(condition))
	case "not_in":
		matched = !present || !valueIn(value, conditionValues(condition))
	case "gte", "gt", "lte", "lt":
		matched = present && compareNumeric(value, condition.Value, op)
	case "prefix":
		matched = present && strings.HasPrefix(valueString(value), valueString(condition.Value))
	case "suffix":
		matched = present && strings.HasSuffix(valueString(value), valueString(condition.Value))
	case "contains":
		matched = present && strings.Contains(valueString(value), valueString(condition.Value))
	case "path_match":
		matched = present && anyPathMatches(valueStrings(conditionValues(condition)), valueString(value))
	case "cidr_match":
		matched = present && ipMatchesCIDRs(valueString(value), valueStrings(conditionValues(condition)))
	default:
		matched = false
	}
	return matched, fmt.Sprintf("condition %s %s matched=%t", strings.TrimSpace(condition.Field), op, matched)
}

func policyFieldValue(field string, req types.PolicyEvaluateRequest) (any, bool) {
	field = strings.ToLower(strings.TrimSpace(field))
	switch field {
	case "client_id":
		return nonEmpty(req.ClientID)
	case "scene":
		return nonEmpty(req.Scene)
	case "path":
		return nonEmpty(req.Path)
	case "method":
		return nonEmpty(strings.ToUpper(req.Method))
	case "ip":
		return nonEmpty(req.IP)
	case "user_agent":
		return nonEmpty(req.UserAgent)
	case "account_id_hash":
		return nonEmpty(req.AccountIDHash)
	case "device_id_hash":
		return nonEmpty(req.DeviceIDHash)
	case "ticket":
		return nonEmpty(req.Ticket)
	case "clearance":
		return nonEmpty(req.Clearance)
	case "request_nonce":
		return nonEmpty(req.RequestNonce)
	case "resource_tag":
		return nonEmpty(req.ResourceTag)
	case "risk_score":
		return req.RiskScore, req.RiskScore > 0
	case "risk_level":
		return nonEmpty(req.RiskLevel)
	case "model_score":
		return req.ModelScore, req.ModelScore > 0
	case "model_mode":
		return nonEmpty(req.ModelMode)
	default:
		if strings.HasPrefix(field, "headers.") {
			return headerValue(req.Headers, strings.TrimPrefix(field, "headers."))
		}
		return nil, false
	}
}

func nonEmpty(value string) (any, bool) {
	value = strings.TrimSpace(value)
	return value, value != ""
}

func headerValue(headers map[string]string, name string) (any, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for key, value := range headers {
		if strings.ToLower(strings.TrimSpace(key)) == name {
			return nonEmpty(value)
		}
	}
	return nil, false
}

func conditionValues(condition types.PolicyCondition) []any {
	if len(condition.Values) > 0 {
		return condition.Values
	}
	if condition.Value != nil {
		return []any{condition.Value}
	}
	return nil
}

func valueIn(value any, values []any) bool {
	value = valueString(value)
	for _, candidate := range values {
		if value == valueString(candidate) {
			return true
		}
	}
	return false
}

func compareNumeric(left, right any, op string) bool {
	leftNumber, leftOK := numericValue(left)
	rightNumber, rightOK := numericValue(right)
	if !leftOK || !rightOK {
		return false
	}
	switch op {
	case "gte":
		return leftNumber >= rightNumber
	case "gt":
		return leftNumber > rightNumber
	case "lte":
		return leftNumber <= rightNumber
	case "lt":
		return leftNumber < rightNumber
	default:
		return false
	}
}

func numericValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func valueString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func valueStrings(values []any) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if text := valueString(value); text != "" {
			out = append(out, text)
		}
	}
	return out
}

func ipMatchesCIDRs(ip string, cidrs []string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	for _, cidr := range cidrs {
		prefix, err := parseIPPolicyPrefix(cidr)
		if err == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func anyPathMatches(patterns []string, path string) bool {
	for _, pattern := range patterns {
		if matchPath(strings.TrimSpace(pattern), path) {
			return true
		}
	}
	return false
}

func stringIn(value string, candidates []string, caseInsensitive bool) bool {
	value = strings.TrimSpace(value)
	if caseInsensitive {
		value = strings.ToLower(value)
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if caseInsensitive {
			candidate = strings.ToLower(candidate)
		}
		if value == candidate {
			return true
		}
	}
	return false
}

func upperStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strings.ToUpper(strings.TrimSpace(value)))
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func firstPathPattern(patterns []string) string {
	if len(patterns) == 0 {
		return ""
	}
	return strings.TrimSpace(patterns[0])
}

package policy

import (
	"testing"
	"time"

	"captcha/internal/types"
)

func TestPolicyRuleTrustedExternalSubjectCanSkipChallenge(t *testing.T) {
	t.Parallel()

	rule := types.PolicyRule{
		ID:       "rule_trusted_skip",
		ClientID: "demo",
		Name:     "trusted external subject skip",
		Priority: 100,
		Enabled:  true,
		Scope: types.PolicyRuleScope{
			Scenes:       []string{"login"},
			PathPatterns: []string{"/api/login"},
			Methods:      []string{"POST"},
		},
		Conditions: types.PolicyCondition{
			All: []types.PolicyCondition{
				{Field: "account_id_hash", Op: "exists"},
				{Field: "device_id_hash", Op: "exists"},
				{Field: "risk_score", Op: "lte", Value: 30},
				{Field: "ip", Op: "cidr_match", Value: "198.51.100.0/24"},
				{Field: "headers.x-trust-tier", Op: "eq", Value: "trusted"},
			},
		},
		Action: types.PolicyRuleAction{
			Type:   types.DecisionSkipChallenge,
			Reason: "TRUSTED_SUBJECT_LOW_RISK",
		},
	}

	evaluation := EvaluatePolicyRules([]types.PolicyRule{rule}, types.PolicyEvaluateRequest{
		ClientID:      "demo",
		Scene:         "login",
		Path:          "/api/login",
		Method:        "post",
		IP:            "198.51.100.44",
		AccountIDHash: "acct_external_hash",
		DeviceIDHash:  "device_external_hash",
		RiskScore:     20,
		Headers:       map[string]string{"X-Trust-Tier": "trusted"},
	}, time.Now())

	if !evaluation.Matched || evaluation.Action.Type != types.DecisionSkipChallenge || evaluation.Reason != "TRUSTED_SUBJECT_LOW_RISK" {
		t.Fatalf("expected trusted subject skip_challenge, got %+v", evaluation)
	}
	if evaluation.Rule == nil || evaluation.Rule.ID != "rule_trusted_skip" {
		t.Fatalf("expected matched rule identity, got %+v", evaluation.Rule)
	}
}

func TestPolicyRuleSupportsAnyAndNotConditions(t *testing.T) {
	t.Parallel()

	rule := types.PolicyRule{
		ID:       "rule_high_risk_without_device",
		ClientID: "demo",
		Priority: 50,
		Enabled:  true,
		Scope: types.PolicyRuleScope{
			PathPatterns: []string{"/api/pay*"},
			Methods:      []string{"POST"},
		},
		Conditions: types.PolicyCondition{
			All: []types.PolicyCondition{
				{
					Any: []types.PolicyCondition{
						{Field: "risk_level", Op: "eq", Value: "high"},
						{Field: "model_score", Op: "gte", Value: 80},
					},
				},
				{Not: &types.PolicyCondition{Field: "device_id_hash", Op: "exists"}},
			},
		},
		Action: types.PolicyRuleAction{
			Type:   types.DecisionBlock,
			Reason: "HIGH_RISK_MISSING_DEVICE",
		},
	}

	matched := EvaluatePolicyRule(rule, types.PolicyEvaluateRequest{
		ClientID:  "demo",
		Path:      "/api/pay/submit",
		Method:    "POST",
		RiskLevel: "high",
	}, time.Now())
	if !matched.Matched || matched.Action.Type != types.DecisionBlock {
		t.Fatalf("expected high risk request without device to match, got %+v", matched)
	}

	withDevice := EvaluatePolicyRule(rule, types.PolicyEvaluateRequest{
		ClientID:     "demo",
		Path:         "/api/pay/submit",
		Method:       "POST",
		RiskLevel:    "high",
		DeviceIDHash: "device_external_hash",
	}, time.Now())
	if withDevice.Matched {
		t.Fatalf("expected not condition to reject request with device, got %+v", withDevice)
	}
}

func TestPolicyRuleUnknownFieldDoesNotMatchOrPanic(t *testing.T) {
	t.Parallel()

	rule := types.PolicyRule{
		ID:       "rule_unknown_field",
		ClientID: "demo",
		Priority: 10,
		Enabled:  true,
		Conditions: types.PolicyCondition{
			Field: "business_context.unsupported",
			Op:    "exists",
		},
		Action: types.PolicyRuleAction{Type: types.DecisionObserve},
	}

	evaluation := EvaluatePolicyRule(rule, types.PolicyEvaluateRequest{ClientID: "demo"}, time.Now())
	if evaluation.Matched {
		t.Fatalf("expected unsupported field not to match, got %+v", evaluation)
	}
}

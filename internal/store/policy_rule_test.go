package store

import (
	"testing"

	"captcha/internal/types"
)

func TestMemoryStorePolicyRuleCRUD(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	low := store.UpsertPolicyRule(types.PolicyRule{
		ID:       "rule_low",
		ClientID: "demo",
		Name:     "low priority",
		Priority: 10,
		Enabled:  true,
		Action:   types.PolicyRuleAction{Type: types.DecisionObserve},
	})
	high := store.UpsertPolicyRule(types.PolicyRule{
		ID:       "rule_high",
		ClientID: "demo",
		Name:     "high priority",
		Priority: 50,
		Enabled:  true,
		Action:   types.PolicyRuleAction{Type: types.DecisionSkipChallenge},
	})

	rules := store.ListPolicyRules("demo")
	if len(rules) < 2 || rules[0].ID != high.ID || rules[1].ID != low.ID {
		t.Fatalf("expected rules sorted by priority, got %+v", rules)
	}
	if high.Status != "active" || high.Scope.ClientID != "demo" || high.RolloutPercent != 100 {
		t.Fatalf("expected normalized policy rule, got %+v", high)
	}
	if deleted := store.DeletePolicyRules("demo", []string{high.ID}); deleted != 1 {
		t.Fatalf("expected one deleted rule, got %d", deleted)
	}
	for _, rule := range store.ListPolicyRules("demo") {
		if rule.ID == high.ID {
			t.Fatalf("deleted rule still listed: %+v", store.ListPolicyRules("demo"))
		}
	}
}

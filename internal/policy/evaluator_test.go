package policy

import (
	"fmt"
	"testing"
	"time"

	"captcha/internal/routepolicy"
	"captcha/internal/store"
	"captcha/internal/types"
)

func TestIPPolicyAllowlistPrecedesBlocklist(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	memoryStore.UpsertIPPolicy(types.IPPolicy{
		ID:        "ip_block_wide",
		ClientID:  "demo",
		Type:      "blocklist",
		CIDR:      "198.51.100.0/24",
		Action:    types.DecisionBlock,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	memoryStore.UpsertIPPolicy(types.IPPolicy{
		ID:        "ip_allow_single",
		ClientID:  "demo",
		Type:      "allowlist",
		CIDR:      "198.51.100.8",
		Action:    types.DecisionAllow,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	evaluation := NewEvaluator(memoryStore).Evaluate(types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/register",
		Method:   "POST",
		IP:       "198.51.100.8",
	})
	if evaluation.Action != types.DecisionAllow || evaluation.Reason != "IP_ALLOWLIST" {
		t.Fatalf("expected allowlist to win over wider blocklist, got %+v", evaluation)
	}
}

func TestIPPolicySingleAddressBlocklist(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	memoryStore.UpsertIPPolicy(types.IPPolicy{
		ID:        "ip_block_single",
		ClientID:  "demo",
		Type:      "blocklist",
		CIDR:      "198.51.100.44",
		Action:    types.DecisionBlock,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	evaluation := NewEvaluator(memoryStore).Evaluate(types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/register",
		Method:   "POST",
		IP:       "198.51.100.44",
	})
	if evaluation.Action != types.DecisionBlock || evaluation.Reason != "IP_BLOCKLIST" {
		t.Fatalf("expected single-address blocklist to match, got %+v", evaluation)
	}
}

func TestPolicyRuleSkipChallengePrecedesRoutePolicy(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ID:              "route_rule_precedence",
		ClientID:        "demo",
		Name:            "register fallback",
		PathPattern:     "/api/register",
		Method:          "POST",
		Scene:           "register",
		Mode:            "always",
		ChallengeType:   types.CaptchaSlider,
		Priority:        100,
		Enabled:         true,
		TokenTTLSeconds: 120,
	})
	memoryStore.UpsertPolicyRule(types.PolicyRule{
		ID:       "rule_trusted_subject_low_risk",
		ClientID: "demo",
		Name:     "trusted subject low risk",
		Priority: 200,
		Enabled:  true,
		Scope: types.PolicyRuleScope{
			PathPatterns: []string{"/api/register"},
			Methods:      []string{"POST"},
		},
		Conditions: types.PolicyCondition{All: []types.PolicyCondition{
			{Field: "account_id_hash", Op: "exists"},
			{Field: "device_id_hash", Op: "exists"},
			{Field: "risk_score", Op: "lt", Value: 30},
		}},
		Action: types.PolicyRuleAction{
			Type:   types.DecisionSkipChallenge,
			Reason: "TRUSTED_SUBJECT_LOW_RISK",
		},
	})

	evaluation := NewEvaluator(memoryStore).Evaluate(types.PolicyEvaluateRequest{
		ClientID:      "demo",
		Path:          "/api/register",
		Method:        "POST",
		AccountIDHash: "acct_trusted",
		DeviceIDHash:  "device_trusted",
		RiskScore:     12,
	})
	if evaluation.Action != types.DecisionSkipChallenge || evaluation.Reason != "TRUSTED_SUBJECT_LOW_RISK" || evaluation.PolicyRule == nil {
		t.Fatalf("expected policy rule skip challenge, got %+v", evaluation)
	}
}

func TestPolicyRuleAggregationChallengesAfterLimit(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	memoryStore.UpsertPolicyRule(types.PolicyRule{
		ID:       "rule_account_rate",
		ClientID: "demo",
		Name:     "account rate",
		Priority: 100,
		Enabled:  true,
		Scope: types.PolicyRuleScope{
			PathPatterns: []string{"/api/comment"},
			Methods:      []string{"POST"},
		},
		Conditions:  types.PolicyCondition{Field: "account_id_hash", Op: "exists"},
		Aggregation: types.PolicyRuleAggregation{Dimensions: []string{"account_id_hash"}, WindowSeconds: 60, MaxRequests: 1},
		Action: types.PolicyRuleAction{
			Type:          types.DecisionRateLimit,
			Reason:        "ACCOUNT_RATE_LIMIT",
			ChallengeType: types.CaptchaRotate,
		},
	})
	evaluator := NewEvaluator(memoryStore)
	req := types.PolicyEvaluateRequest{
		ClientID:      "demo",
		Path:          "/api/comment",
		Method:        "POST",
		Scene:         "comment",
		AccountIDHash: "acct_rate",
	}

	first := evaluator.Evaluate(req)
	if first.Action != types.DecisionAllow || first.Reason != "POLICY_RULE_AGGREGATION_UNDER_LIMIT" {
		t.Fatalf("expected first request under policy rule aggregation, got %+v", first)
	}
	second := evaluator.Evaluate(req)
	if second.Action != types.DecisionRateLimit || second.Reason != "ACCOUNT_RATE_LIMIT" || second.ChallengeType != types.CaptchaRotate {
		t.Fatalf("expected second request to trigger policy rule rate limit, got %+v", second)
	}
}

func TestRateLimitUsesAccountAndDeviceDimensions(t *testing.T) {
	t.Parallel()

	t.Run("account hash", func(t *testing.T) {
		t.Parallel()

		memoryStore := store.NewMemoryStore()
		evaluator := NewEvaluator(memoryStore)
		var evaluation Evaluation
		for i := 0; i < 6; i++ {
			evaluation = evaluator.Evaluate(types.PolicyEvaluateRequest{
				ClientID:      "demo",
				Path:          "/api/comment",
				Method:        "POST",
				IP:            fmt.Sprintf("198.51.100.%d", i+1),
				AccountIDHash: "acct_hash_same",
			})
		}
		if evaluation.Action != types.DecisionChallenge || evaluation.Reason != "RATE_LIMIT" {
			t.Fatalf("expected account dimension to trigger rate limit, got %+v", evaluation)
		}
	})

	t.Run("device hash", func(t *testing.T) {
		t.Parallel()

		memoryStore := store.NewMemoryStore()
		evaluator := NewEvaluator(memoryStore)
		var evaluation Evaluation
		for i := 0; i < 6; i++ {
			evaluation = evaluator.Evaluate(types.PolicyEvaluateRequest{
				ClientID:     "demo",
				Path:         "/api/comment",
				Method:       "POST",
				IP:           fmt.Sprintf("198.51.101.%d", i+1),
				DeviceIDHash: "device_hash_same",
			})
		}
		if evaluation.Action != types.DecisionChallenge || evaluation.Reason != "RATE_LIMIT" {
			t.Fatalf("expected device dimension to trigger rate limit, got %+v", evaluation)
		}
	})
}

func TestObserveRouteModeReturnsObserve(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ID:              "route_observe",
		ClientID:        "demo",
		Name:            "observe",
		PathPattern:     "/api/observe",
		Method:          "POST",
		Scene:           "login",
		Mode:            " Observe ",
		ChallengeType:   types.CaptchaSlider,
		Priority:        999,
		Enabled:         true,
		TokenTTLSeconds: 120,
	})

	evaluation := NewEvaluator(memoryStore).Evaluate(types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/observe",
		Method:   "POST",
		IP:       "198.51.100.8",
	})
	if evaluation.Action != types.DecisionObserve || evaluation.Reason != "OBSERVE" {
		t.Fatalf("expected observe decision, got %+v", evaluation)
	}
	if evaluation.Route == nil || evaluation.Route.ID != "route_observe" {
		t.Fatalf("expected observe route to match, got %+v", evaluation.Route)
	}
}

func TestRoutePolicyRolloutSkipsToLowerPriorityRoute(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	grayRoute := types.RoutePolicy{
		ID:              "route_gray",
		ClientID:        "demo",
		Name:            "gray",
		PathPattern:     "/api/pay",
		Method:          "POST",
		Scene:           "pay",
		Mode:            "always",
		ChallengeType:   types.CaptchaRotate,
		Priority:        100,
		Enabled:         true,
		RolloutPercent:  10,
		TokenTTLSeconds: 120,
	}
	fallbackRoute := types.RoutePolicy{
		ID:              "route_fallback",
		ClientID:        "demo",
		Name:            "fallback",
		PathPattern:     "/api/pay",
		Method:          "POST",
		Scene:           "pay",
		Mode:            "manual_bypass",
		ChallengeType:   types.CaptchaSlider,
		Priority:        1,
		Enabled:         true,
		RolloutPercent:  100,
		TokenTTLSeconds: 120,
	}
	memoryStore.UpsertRoutePolicy(grayRoute)
	memoryStore.UpsertRoutePolicy(fallbackRoute)

	account := rolloutMissAccount(t, grayRoute)
	evaluation := NewEvaluator(memoryStore).Evaluate(types.PolicyEvaluateRequest{
		ClientID:      "demo",
		Path:          "/api/pay",
		Method:        "POST",
		AccountIDHash: account,
		IP:            "198.51.100.8",
	})
	if evaluation.Route == nil || evaluation.Route.ID != "route_fallback" {
		t.Fatalf("expected rollout miss to use fallback route, got %+v", evaluation.Route)
	}
	if evaluation.Action != types.DecisionAllow || evaluation.Reason != "MANUAL_BYPASS" {
		t.Fatalf("expected fallback manual bypass, got %+v", evaluation)
	}
}

func TestAppWideRoutePolicyMatchesAnyPathAndMethod(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ID:              "route_app_wide",
		ClientID:        "demo",
		Name:            "app wide",
		PathPattern:     "",
		Method:          "",
		Scene:           "app",
		Mode:            "manual_bypass",
		Priority:        100,
		Enabled:         true,
		RolloutPercent:  100,
		TokenTTLSeconds: 120,
	})

	evaluation := NewEvaluator(memoryStore).Evaluate(types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/any/path",
		Method:   "PATCH",
		IP:       "198.51.100.8",
	})
	if evaluation.Route == nil || evaluation.Route.ID != "route_app_wide" {
		t.Fatalf("expected app-wide route to match, got %+v", evaluation.Route)
	}
	if evaluation.Action != types.DecisionAllow || evaluation.Reason != "MANUAL_BYPASS" {
		t.Fatalf("expected app-wide manual bypass, got %+v", evaluation)
	}
}

func TestForceChallengeRouteOverridesClearance(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ID:              "route_sms_force",
		ClientID:        "demo",
		Name:            "sms force",
		PathPattern:     "/api/sms/send",
		Method:          "POST",
		Scene:           "sms",
		Mode:            "force_challenge",
		ChallengeType:   types.CaptchaSlider,
		Priority:        100,
		Enabled:         true,
		RolloutPercent:  100,
		TokenTTLSeconds: 120,
	})
	evaluator := NewEvaluator(memoryStore)
	req := types.PolicyEvaluateRequest{
		ClientID:  "demo",
		Path:      "/api/sms/send",
		Method:    "POST",
		Clearance: "cap_clearance_existing",
	}

	evaluation, ok := evaluator.EvaluateClearanceOverride(req)
	if !ok {
		t.Fatal("expected force challenge route to override clearance")
	}
	if evaluation.Action != types.DecisionChallenge || evaluation.Reason != "FORCE_CHALLENGE" || evaluation.Route == nil || evaluation.Route.ID != "route_sms_force" {
		t.Fatalf("expected force challenge evaluation, got %+v", evaluation)
	}
}

func TestRiskBasedRouteUsesRiskScoreThresholds(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ID:                 "route_risk_score",
		ClientID:           "demo",
		Name:               "risk score",
		PathPattern:        "/api/pay",
		Method:             "POST",
		Scene:              "pay",
		Mode:               "risk_based",
		ChallengeType:      types.CaptchaSlider,
		RiskChallengeType:  types.CaptchaRotate,
		Priority:           100,
		Enabled:            true,
		TokenTTLSeconds:    120,
		RiskObserveScore:   40,
		RiskChallengeScore: 70,
		RiskBlockScore:     95,
	})
	evaluator := NewEvaluator(memoryStore)

	low := evaluator.Evaluate(types.PolicyEvaluateRequest{
		ClientID:  "demo",
		Path:      "/api/pay",
		Method:    "POST",
		RiskScore: 25,
	})
	if low.Action != types.DecisionAllow || low.Reason != "LOW_RISK_SCORE" {
		t.Fatalf("expected low risk allow, got %+v", low)
	}

	observed := evaluator.Evaluate(types.PolicyEvaluateRequest{
		ClientID:  "demo",
		Path:      "/api/pay",
		Method:    "POST",
		RiskScore: 45,
	})
	if observed.Action != types.DecisionObserve || observed.Reason != "RISK_SCORE_OBSERVE" {
		t.Fatalf("expected risk score observe, got %+v", observed)
	}

	challenged := evaluator.Evaluate(types.PolicyEvaluateRequest{
		ClientID:  "demo",
		Path:      "/api/pay",
		Method:    "POST",
		RiskScore: 75,
	})
	if challenged.Action != types.DecisionChallenge || challenged.Reason != "RISK_SCORE" || challenged.ChallengeType != types.CaptchaRotate {
		t.Fatalf("expected risk score challenge to use risk challenge type, got %+v", challenged)
	}

	blocked := evaluator.Evaluate(types.PolicyEvaluateRequest{
		ClientID:  "demo",
		Path:      "/api/pay",
		Method:    "POST",
		RiskScore: 98,
	})
	if blocked.Action != types.DecisionBlock || blocked.Reason != "RISK_SCORE_BLOCK" {
		t.Fatalf("expected risk score block, got %+v", blocked)
	}
}

func TestRiskBasedRouteUsesModelScoreOnlyInDecisionModes(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ID:                 "route_model_score",
		ClientID:           "demo",
		Name:               "model score",
		PathPattern:        "/api/login",
		Method:             "POST",
		Scene:              "login",
		Mode:               "risk_based",
		ChallengeType:      types.CaptchaSlider,
		RiskChallengeType:  types.CaptchaWordImageClick,
		Priority:           100,
		Enabled:            true,
		TokenTTLSeconds:    120,
		RiskChallengeScore: 70,
	})
	evaluator := NewEvaluator(memoryStore)

	shadow := evaluator.Evaluate(types.PolicyEvaluateRequest{
		ClientID:   "demo",
		Path:       "/api/login",
		Method:     "POST",
		ModelScore: 95,
		ModelMode:  "shadow",
	})
	if shadow.Action != types.DecisionChallenge || shadow.Reason != "RISK_BASED" {
		t.Fatalf("expected shadow model score to preserve legacy risk behavior, got %+v", shadow)
	}

	observe := evaluator.Evaluate(types.PolicyEvaluateRequest{
		ClientID:   "demo",
		Path:       "/api/login",
		Method:     "POST",
		ModelScore: 95,
		ModelMode:  "observe",
	})
	if observe.Action != types.DecisionChallenge || observe.Reason != "RISK_SCORE" || observe.ChallengeType != types.CaptchaWordImageClick {
		t.Fatalf("expected observe model score to participate in risk score, got %+v", observe)
	}
}

func TestDryRunRateLimitDoesNotIncrementCounters(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	evaluator := NewEvaluator(memoryStore)
	req := types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/comment",
		Method:   "POST",
		IP:       "198.51.100.200",
	}

	dryRun := evaluator.EvaluateDryRun(req)
	if dryRun.Action != types.DecisionObserve || dryRun.Reason != "RATE_LIMIT_DRY_RUN" || dryRun.ChallengeType != types.CaptchaRotate {
		t.Fatalf("expected dry-run rate limit observe with selected challenge type, got %+v", dryRun)
	}

	for i := 0; i < 5; i++ {
		evaluation := evaluator.Evaluate(req)
		if evaluation.Action != types.DecisionAllow || evaluation.Reason != "UNDER_RATE_LIMIT" {
			t.Fatalf("dry-run should not consume rate quota; request %d got %+v", i+1, evaluation)
		}
	}
	evaluation := evaluator.Evaluate(req)
	if evaluation.Action != types.DecisionChallenge || evaluation.Reason != "RATE_LIMIT" {
		t.Fatalf("expected sixth real request to trigger rate limit, got %+v", evaluation)
	}
}

func TestRateLimitUsesConfiguredStrategy(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ID:              "route_sliding_rate",
		ClientID:        "demo",
		Name:            "sliding rate",
		PathPattern:     "/api/sliding",
		Method:          "POST",
		Scene:           "comment",
		Mode:            "rate_limit",
		ChallengeType:   types.CaptchaRotate,
		Priority:        999,
		Enabled:         true,
		TokenTTLSeconds: 120,
		RateLimit:       &types.RateLimit{WindowSeconds: 60, MaxRequests: 1, Strategy: "sliding_window"},
	})
	evaluator := NewEvaluator(memoryStore)
	req := types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/sliding",
		Method:   "POST",
		IP:       "198.51.100.203",
	}

	first := evaluator.Evaluate(req)
	if first.Action != types.DecisionAllow || first.Reason != "UNDER_RATE_LIMIT" {
		t.Fatalf("expected first sliding-window request to pass, got %+v", first)
	}
	second := evaluator.Evaluate(req)
	if second.Action != types.DecisionChallenge || second.Reason != "RATE_LIMIT" {
		t.Fatalf("expected second sliding-window request to challenge, got %+v", second)
	}
}

func TestRateLimitUsesTokenBucketStrategy(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ID:              "route_token_bucket_rate",
		ClientID:        "demo",
		Name:            "token bucket rate",
		PathPattern:     "/api/token-bucket",
		Method:          "POST",
		Scene:           "comment",
		Mode:            "rate_limit",
		ChallengeType:   types.CaptchaRotate,
		Priority:        999,
		Enabled:         true,
		TokenTTLSeconds: 120,
		RateLimit:       &types.RateLimit{WindowSeconds: 60, MaxRequests: 2, Strategy: "token_bucket"},
	})
	evaluator := NewEvaluator(memoryStore)
	req := types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/token-bucket",
		Method:   "POST",
		IP:       "198.51.100.204",
	}

	for i := 0; i < 2; i++ {
		evaluation := evaluator.Evaluate(req)
		if evaluation.Action != types.DecisionAllow || evaluation.Reason != "UNDER_RATE_LIMIT" {
			t.Fatalf("expected token-bucket request %d to pass, got %+v", i+1, evaluation)
		}
	}
	evaluation := evaluator.Evaluate(req)
	if evaluation.Action != types.DecisionChallenge || evaluation.Reason != "RATE_LIMIT" {
		t.Fatalf("expected third token-bucket request to challenge, got %+v", evaluation)
	}
}

func rolloutMissAccount(t *testing.T, route types.RoutePolicy) string {
	t.Helper()
	for i := 0; i < 500; i++ {
		account := fmt.Sprintf("acct_rollout_miss_%d", i)
		if !routepolicy.MatchesRollout(route, routepolicy.RolloutContext{
			ClientID:      "demo",
			Path:          "/api/pay",
			Method:        "POST",
			AccountIDHash: account,
		}) {
			return account
		}
	}
	t.Fatal("could not find rollout miss account")
	return ""
}

func TestAutoChallengeTypeUsesResourceAvailability(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	memoryStore.UpsertApplication(types.Application{
		ID:                "app_auto",
		ClientID:          "auto-client",
		Name:              "auto",
		Status:            "active",
		DefaultFailPolicy: "fail_open",
	})
	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ID:              "route_auto",
		ClientID:        "auto-client",
		Name:            "auto",
		PathPattern:     "/api/auto",
		Method:          "POST",
		Scene:           "login",
		Mode:            "always",
		ChallengeType:   types.CaptchaAuto,
		Enabled:         true,
		TokenTTLSeconds: 120,
	})
	memoryStore.UpsertResource(types.CaptchaResource{
		ID:           "res_auto_background",
		ClientID:     "auto-client",
		CaptchaType:  types.CaptchaAuto,
		ResourceType: "background_image",
		StorageType:  "url",
		URI:          "https://cdn.example.test/background.png",
		Status:       "active",
	})
	memoryStore.UpsertResource(types.CaptchaResource{
		ID:           "res_auto_rotate",
		ClientID:     "auto-client",
		CaptchaType:  types.CaptchaRotate,
		ResourceType: "rotate_library",
		StorageType:  "url",
		URI:          "https://cdn.example.test/rotate.png",
		Status:       "active",
	})

	evaluation := NewEvaluator(memoryStore).Evaluate(types.PolicyEvaluateRequest{
		ClientID: "auto-client",
		Path:     "/api/auto",
		Method:   "POST",
	})
	if evaluation.Action != types.DecisionChallenge || evaluation.ChallengeType != types.CaptchaRotate {
		t.Fatalf("expected AUTO to choose resource-supported rotate, got %+v", evaluation)
	}
}

func TestAutoChallengeTypeUsesRiskAndScenePreference(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ID:              "route_auto_register",
		ClientID:        "demo",
		Name:            "auto register",
		PathPattern:     "/api/auto-register",
		Method:          "POST",
		Scene:           "register",
		Mode:            "always",
		ChallengeType:   types.CaptchaAuto,
		Priority:        100,
		Enabled:         true,
		TokenTTLSeconds: 120,
	})

	evaluation := NewEvaluator(memoryStore).Evaluate(types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/auto-register",
		Method:   "POST",
	})
	if evaluation.Action != types.DecisionChallenge || evaluation.ChallengeType != types.CaptchaWordImageClick {
		t.Fatalf("expected register AUTO to prefer word image click when resources are available, got %+v", evaluation)
	}
}

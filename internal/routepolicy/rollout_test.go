package routepolicy

import (
	"testing"

	"captcha/internal/types"
)

func TestMatchesRolloutIsStable(t *testing.T) {
	t.Parallel()

	route := types.RoutePolicy{ID: "route_rollout", PathPattern: "/api/*", RolloutPercent: 25}
	ctx := RolloutContext{
		ClientID:      "demo",
		Path:          "/api/login",
		Method:        "POST",
		AccountIDHash: "acct_same",
	}
	first := MatchesRollout(route, ctx)
	for i := 0; i < 20; i++ {
		if MatchesRollout(route, ctx) != first {
			t.Fatalf("expected rollout match to be stable")
		}
	}
}

func TestNormalizeRolloutPercentDefaultsToFullTraffic(t *testing.T) {
	t.Parallel()

	for _, value := range []int{-10, 0, 101} {
		if got := NormalizeRolloutPercent(value); got != 100 {
			t.Fatalf("expected %d to normalize to 100, got %d", value, got)
		}
	}
	if got := NormalizeRolloutPercent(25); got != 25 {
		t.Fatalf("expected 25 to remain 25, got %d", got)
	}
}

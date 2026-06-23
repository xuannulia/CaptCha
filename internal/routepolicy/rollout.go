package routepolicy

import (
	"fmt"
	"hash/fnv"
	"strings"

	"captcha/internal/types"
)

type RolloutContext struct {
	ClientID      string
	Path          string
	Method        string
	IP            string
	UserAgent     string
	AccountIDHash string
	DeviceIDHash  string
}

func NormalizeRolloutPercent(percent int) int {
	if percent <= 0 || percent > 100 {
		return 100
	}
	return percent
}

func MatchesRollout(route types.RoutePolicy, ctx RolloutContext) bool {
	percent := NormalizeRolloutPercent(route.RolloutPercent)
	if percent >= 100 {
		return true
	}
	key := rolloutKey(ctx)
	if key == "" {
		key = strings.Join([]string{ctx.Method, ctx.Path}, "|")
	}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(fmt.Sprintf("%s|%s|%s", route.ID, route.PathPattern, key)))
	return int(hash.Sum32()%100) < percent
}

func rolloutKey(ctx RolloutContext) string {
	for _, value := range []string{
		ctx.AccountIDHash,
		ctx.DeviceIDHash,
		ctx.IP,
		ctx.UserAgent,
		ctx.Path,
	} {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return strings.TrimSpace(ctx.ClientID)
}

package api

import (
	"strings"
	"time"

	"captcha/internal/types"
)

func (s *Server) attachRiskModelShadowScore(snapshot *types.RiskFeatureSnapshot) {
	model, ok := s.activeRiskModelVersion(snapshot.FeatureVersion)
	if !ok {
		return
	}
	features := cloneFeatureMap(snapshot.Features)
	score, bucket, reasons := shadowRiskScore(features)
	features["risk_model_shadow"] = map[string]any{
		"bucket":          bucket,
		"decision_effect": "none",
		"feature_version": model.FeatureVersion,
		"mode":            model.Mode,
		"model_id":        model.ID,
		"model_name":      model.Name,
		"model_version":   model.Version,
		"reasons":         reasons,
		"score":           score,
	}
	snapshot.Features = features
}

func (s *Server) activeRiskModelVersion(featureVersion string) (types.RiskModelVersion, bool) {
	versions := s.store.ListRiskModelVersions("", 100)
	var selected types.RiskModelVersion
	for _, version := range versions {
		if version.Status != "active" || version.FeatureVersion != featureVersion || !shadowScoringMode(version.Mode) {
			continue
		}
		if selected.ID == "" || activatedAfter(version, selected) {
			selected = version
		}
	}
	return selected, selected.ID != ""
}

func shadowScoringMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "shadow", "observe", "enforce":
		return true
	default:
		return false
	}
}

func activatedAfter(left, right types.RiskModelVersion) bool {
	leftAt := time.Time{}
	if left.ActivatedAt != nil {
		leftAt = *left.ActivatedAt
	}
	rightAt := time.Time{}
	if right.ActivatedAt != nil {
		rightAt = *right.ActivatedAt
	}
	if !leftAt.Equal(rightAt) {
		return leftAt.After(rightAt)
	}
	return left.CreatedAt.After(right.CreatedAt)
}

func shadowRiskScore(features map[string]any) (int, string, []string) {
	trackScore := intFeature(features, "track_score")
	score := 100 - trackScore
	reasons := make([]string, 0, 6)
	if boolFeature(features, "too_fast") {
		score += 10
		reasons = append(reasons, "too_fast")
	}
	if boolFeature(features, "too_few_points") {
		score += 8
		reasons = append(reasons, "too_few_points")
	}
	if boolFeature(features, "perfect_line") {
		score += 8
		reasons = append(reasons, "perfect_line")
	}
	if boolFeature(features, "constant_velocity") {
		score += 8
		reasons = append(reasons, "constant_velocity")
	}
	if boolFeature(features, "synthetic_curve") {
		score += 12
		reasons = append(reasons, "synthetic_curve")
	}
	if boolFeature(features, "teleport") {
		score += 12
		reasons = append(reasons, "teleport")
	}
	if !boolFeature(features, "result_ok") {
		score += 10
		reasons = append(reasons, "captcha_not_passed")
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	bucket := "low"
	if score >= 75 {
		bucket = "high"
	} else if score >= 45 {
		bucket = "medium"
	}
	return score, bucket, reasons
}

func cloneFeatureMap(features map[string]any) map[string]any {
	cloned := make(map[string]any, len(features)+1)
	for key, value := range features {
		cloned[key] = value
	}
	return cloned
}

func intFeature(features map[string]any, key string) int {
	switch value := features[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case float32:
		return int(value)
	default:
		return 0
	}
}

func boolFeature(features map[string]any, key string) bool {
	value, _ := features[key].(bool)
	return value
}

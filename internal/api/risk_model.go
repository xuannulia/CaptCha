package api

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
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
	if artifactScore, artifactBucket, artifactReasons, ok := scoreRiskModelArtifact(model, features); ok {
		score = artifactScore
		bucket = artifactBucket
		reasons = artifactReasons
	}
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

type trackRiskModelArtifact struct {
	SchemaVersion string                 `json:"schema_version"`
	ModelType     string                 `json:"model_type"`
	Features      []trackRiskFeatureSpec `json:"features"`
	Standardizer  trackRiskStandardizer  `json:"standardizer"`
	Weights       []float64              `json:"weights"`
	Bias          float64                `json:"bias"`
	Score         struct {
		Threshold float64 `json:"threshold"`
	} `json:"score"`
}

type trackRiskFeatureSpec struct {
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

type trackRiskStandardizer struct {
	Mean  []float64 `json:"mean"`
	Scale []float64 `json:"scale"`
}

func scoreRiskModelArtifact(model types.RiskModelVersion, features map[string]any) (int, string, []string, bool) {
	artifact, ok := readTrackRiskModelArtifact(model.ArtifactURI)
	if !ok {
		return 0, "", nil, false
	}
	if artifact.SchemaVersion != "track-risk-model-v1" || artifact.ModelType != "logistic_regression" {
		return 0, "", nil, false
	}
	if len(artifact.Features) == 0 || len(artifact.Features) != len(artifact.Weights) || len(artifact.Features) != len(artifact.Standardizer.Mean) || len(artifact.Features) != len(artifact.Standardizer.Scale) {
		return 0, "", nil, false
	}
	value := artifact.Bias
	for i, feature := range artifact.Features {
		scale := artifact.Standardizer.Scale[i]
		if scale == 0 {
			scale = 1
		}
		raw := riskArtifactFeatureValue(features, feature)
		value += artifact.Weights[i] * ((raw - artifact.Standardizer.Mean[i]) / scale)
	}
	probability := logistic(value)
	score := int(math.Round(probability * 100))
	threshold := artifact.Score.Threshold
	if threshold <= 0 || threshold >= 1 {
		threshold = 0.5
	}
	bucket := "low"
	if probability >= threshold {
		bucket = "high"
	} else if probability >= threshold*0.65 {
		bucket = "medium"
	}
	reasons := []string{"model_artifact"}
	if bucket == "high" {
		reasons = append(reasons, "model_threshold")
	}
	return score, bucket, reasons, true
}

func readTrackRiskModelArtifact(uri string) (trackRiskModelArtifact, bool) {
	path, ok := riskModelArtifactPath(uri)
	if !ok {
		return trackRiskModelArtifact{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return trackRiskModelArtifact{}, false
	}
	var artifact trackRiskModelArtifact
	if err := json.Unmarshal(data, &artifact); err != nil {
		return trackRiskModelArtifact{}, false
	}
	return artifact, true
}

func riskModelArtifactPath(uri string) (string, bool) {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return "", false
	}
	if strings.HasPrefix(uri, "file://") {
		path := strings.TrimPrefix(uri, "file://")
		if path == "" {
			return "", false
		}
		return filepath.Clean(path), true
	}
	if strings.HasPrefix(uri, "/") {
		return filepath.Clean(uri), true
	}
	return "", false
}

func riskArtifactFeatureValue(features map[string]any, spec trackRiskFeatureSpec) float64 {
	switch spec.Kind {
	case "numeric":
		return floatFeature(features, spec.Name)
	case "boolean":
		if boolFeature(features, spec.Name) {
			return 1
		}
		return 0
	case "categorical":
		if strings.TrimSpace(stringFeature(features, spec.Name)) == spec.Value {
			return 1
		}
		return 0
	default:
		return 0
	}
}

func floatFeature(features map[string]any, key string) float64 {
	switch value := features[key].(type) {
	case int:
		return float64(value)
	case int64:
		return float64(value)
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return 0
		}
		return value
	case float32:
		out := float64(value)
		if math.IsNaN(out) || math.IsInf(out, 0) {
			return 0
		}
		return out
	default:
		return 0
	}
}

func stringFeature(features map[string]any, key string) string {
	value, _ := features[key].(string)
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func logistic(value float64) float64 {
	if value >= 0 {
		z := math.Exp(-value)
		return 1 / (1 + z)
	}
	z := math.Exp(value)
	return z / (1 + z)
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

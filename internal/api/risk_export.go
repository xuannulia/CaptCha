package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"captcha/internal/types"
)

const riskFeatureExportSchemaVersion = "risk-feature-export-v1"

type riskFeatureExportRecord struct {
	SchemaVersion  string            `json:"schema_version"`
	ID             string            `json:"id"`
	AttemptID      string            `json:"attempt_id"`
	ClientID       string            `json:"client_id"`
	Scene          string            `json:"scene"`
	ChallengeType  types.CaptchaType `json:"challenge_type"`
	FeatureVersion string            `json:"feature_version"`
	FeaturesDigest string            `json:"features_digest"`
	FeaturesRef    string            `json:"features_ref,omitempty"`
	Features       map[string]any    `json:"features"`
	Label          string            `json:"label"`
	LabelSource    string            `json:"label_source"`
	ModelTrainable bool              `json:"model_trainable"`
	CreatedAt      time.Time         `json:"created_at"`
}

func (s *Server) handleExportRiskFeatureSnapshots(w http.ResponseWriter, r *http.Request) {
	filter := riskFeatureSnapshotFilterFromQuery(r)
	filter.Limit = normalizedExportLimit(filter.Limit)
	if strings.TrimSpace(r.URL.Query().Get("model_trainable")) == "" && trainableOnlyExport(r) {
		trainable := true
		filter.ModelTrainable = &trainable
	}
	items := s.store.ListRiskFeatureSnapshotsFiltered(filter)

	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="captcha-risk-features.jsonl"`)
	w.Header().Set("X-Captcha-Export-Count", strconv.Itoa(len(items)))
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	for _, item := range items {
		_ = encoder.Encode(riskFeatureExportRecord{
			SchemaVersion:  riskFeatureExportSchemaVersion,
			ID:             item.ID,
			AttemptID:      item.AttemptID,
			ClientID:       item.ClientID,
			Scene:          item.Scene,
			ChallengeType:  item.ChallengeType,
			FeatureVersion: item.FeatureVersion,
			FeaturesDigest: item.FeaturesDigest,
			FeaturesRef:    item.FeaturesRef,
			Features:       item.Features,
			Label:          item.Label,
			LabelSource:    item.LabelSource,
			ModelTrainable: item.ModelTrainable,
			CreatedAt:      item.CreatedAt,
		})
	}
}

func trainableOnlyExport(r *http.Request) bool {
	value := strings.TrimSpace(r.URL.Query().Get("trainable_only"))
	if value == "" {
		return true
	}
	parsed, err := strconv.ParseBool(value)
	return err != nil || parsed
}

func normalizedExportLimit(limit int) int {
	if limit <= 0 {
		return 1000
	}
	if limit > 5000 {
		return 5000
	}
	return limit
}

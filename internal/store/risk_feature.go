package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"captcha/internal/types"
)

func prepareRiskFeatureSnapshot(snapshot types.RiskFeatureSnapshot) types.RiskFeatureSnapshot {
	if snapshot.ID == "" {
		snapshot.ID = newID("feat")
	}
	if snapshot.FeatureVersion == "" {
		snapshot.FeatureVersion = "track-v1"
	}
	if snapshot.Features == nil {
		snapshot.Features = map[string]any{}
	}
	if snapshot.FeaturesDigest == "" {
		snapshot.FeaturesDigest = digestFeatures(snapshot.Features)
	}
	if snapshot.FeaturesRef == "" {
		snapshot.FeaturesRef = "inline"
	}
	if snapshot.Label == "" {
		snapshot.Label = "unknown"
	}
	if snapshot.CreatedAt.IsZero() {
		snapshot.CreatedAt = time.Now().UTC()
	}
	return snapshot
}

func digestFeatures(features map[string]any) string {
	data, err := json.Marshal(features)
	if err != nil {
		data = []byte("{}")
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

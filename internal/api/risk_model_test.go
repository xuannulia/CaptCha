package api

import (
	"os"
	"path/filepath"
	"testing"

	"captcha/internal/types"
)

func TestScoreRiskModelArtifact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "track-risk.json")
	artifact := `{
		"schema_version": "track-risk-model-v1",
		"model_type": "logistic_regression",
		"features": [
			{"kind": "numeric", "name": "track_score"},
			{"kind": "boolean", "name": "teleport"},
			{"kind": "categorical", "name": "input_device_hint", "value": "mouse"}
		],
		"standardizer": {
			"mean": [50, 0, 0],
			"scale": [10, 1, 1]
		},
		"weights": [-1, 4, 0.5],
		"bias": 0,
		"score": {"threshold": 0.5}
	}`
	if err := os.WriteFile(path, []byte(artifact), 0o600); err != nil {
		t.Fatal(err)
	}
	score, bucket, reasons, ok := scoreRiskModelArtifact(types.RiskModelVersion{ArtifactURI: "file://" + path}, map[string]any{
		"track_score":       20,
		"teleport":          true,
		"input_device_hint": "mouse",
	})
	if !ok {
		t.Fatal("expected artifact scorer to run")
	}
	if score < 95 || bucket != "high" {
		t.Fatalf("expected high model score, got score=%d bucket=%s reasons=%v", score, bucket, reasons)
	}
	if len(reasons) == 0 || reasons[0] != "model_artifact" {
		t.Fatalf("expected artifact reason, got %v", reasons)
	}
}

func TestScoreRiskModelArtifactRejectsUnsupportedURI(t *testing.T) {
	_, _, _, ok := scoreRiskModelArtifact(types.RiskModelVersion{ArtifactURI: "s3://models/track.json"}, map[string]any{})
	if ok {
		t.Fatal("s3 artifacts should be handled by external inference, not local file scorer")
	}
}

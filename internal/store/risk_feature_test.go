package store

import (
	"testing"

	"captcha/internal/types"
)

func TestMemoryStoreRiskFeatureSnapshots(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	snapshot := store.AddRiskFeatureSnapshot(types.RiskFeatureSnapshot{
		AttemptID:     "cap_sess_test",
		ClientID:      "demo",
		Scene:         "login",
		ChallengeType: types.CaptchaSlider,
		Features: map[string]any{
			"track_score": 80,
		},
		Label:       "captcha_pass",
		LabelSource: "captcha_result",
	})

	if snapshot.ID == "" || snapshot.FeaturesDigest == "" || snapshot.FeaturesRef != "inline" {
		t.Fatalf("snapshot was not prepared: %+v", snapshot)
	}
	items := store.ListRiskFeatureSnapshots("demo", 10)
	if len(items) != 1 || items[0].AttemptID != "cap_sess_test" {
		t.Fatalf("unexpected snapshots: %+v", items)
	}

	updated, err := store.UpdateRiskFeatureSnapshotLabel(snapshot.ID, "confirmed_human", "manual_review", true)
	if err != nil {
		t.Fatalf("update snapshot label: %v", err)
	}
	if updated.Label != "confirmed_human" || updated.LabelSource != "manual_review" || !updated.ModelTrainable {
		t.Fatalf("unexpected updated snapshot: %+v", updated)
	}

	items = store.ListRiskFeatureSnapshots("demo", 10)
	if len(items) != 1 || items[0].Label != "confirmed_human" || !items[0].ModelTrainable {
		t.Fatalf("expected list to reflect updated label, got %+v", items)
	}
}

func TestMemoryStoreRiskModelVersionActivationAndRollback(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	v1 := store.UpsertRiskModelVersion(types.RiskModelVersion{
		ID:             "model_track_v1",
		Name:           "track-baseline",
		Version:        "v1",
		FeatureVersion: "track-v1",
		TrainingWindow: "2026-06-01/2026-06-10",
		ArtifactURI:    "s3://models/track/v1.json",
		Mode:           "shadow",
	})
	v2 := store.UpsertRiskModelVersion(types.RiskModelVersion{
		ID:             "model_track_v2",
		Name:           "track-baseline",
		Version:        "v2",
		FeatureVersion: "track-v1",
		TrainingWindow: "2026-06-11/2026-06-20",
		ArtifactURI:    "s3://models/track/v2.json",
		Mode:           "observe",
	})

	active, err := store.ActivateRiskModelVersion(v1.ID)
	if err != nil {
		t.Fatalf("activate v1: %v", err)
	}
	if active.Status != "active" || active.ActivatedAt == nil {
		t.Fatalf("expected active v1, got %+v", active)
	}
	active, err = store.ActivateRiskModelVersion(v2.ID)
	if err != nil {
		t.Fatalf("activate v2: %v", err)
	}
	if active.ID != v2.ID || active.Status != "active" {
		t.Fatalf("expected active v2, got %+v", active)
	}
	rolledBack, err := store.RollbackRiskModelVersion(v2.ID)
	if err != nil {
		t.Fatalf("rollback v2: %v", err)
	}
	if rolledBack.ID != v1.ID || rolledBack.Status != "active" {
		t.Fatalf("expected rollback to v1, got %+v", rolledBack)
	}

	versions := store.ListRiskModelVersions("track-baseline", 10)
	statuses := map[string]string{}
	for _, version := range versions {
		statuses[version.ID] = version.Status
	}
	if statuses[v1.ID] != "active" || statuses[v2.ID] != "rolled_back" {
		t.Fatalf("unexpected statuses after rollback: %+v", statuses)
	}
}

package store

import (
	"database/sql"
	"log/slog"
	"testing"
	"time"

	challengepkg "captcha/internal/challenge"
	"captcha/internal/types"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPostgresControlStoreUpsertApplication(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"id",
		"client_id",
		"name",
		"secret_hash",
		"status",
		"default_fail_policy",
		"created_at",
		"updated_at",
	}).AddRow("app_new", "new-client", "new app", "hash", "active", "fail_open", now, now)

	mock.ExpectQuery("INSERT INTO applications").
		WithArgs(
			"app_new",
			"new-client",
			"new app",
			sql.NullString{String: "hash", Valid: true},
			"active",
			"fail_open",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnRows(rows)

	store := NewPostgresControlStore(db, slog.Default())
	application := store.UpsertApplication(types.Application{
		ID:                "app_new",
		ClientID:          "new-client",
		Name:              "new app",
		SecretHash:        "hash",
		Status:            "active",
		DefaultFailPolicy: "fail_open",
	})
	if application.SecretHash != "hash" || application.ClientID != "new-client" || !application.HasSecret {
		t.Fatalf("unexpected application: %+v", application)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestPostgresControlStoreRotateApplicationSecret(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"id",
		"client_id",
		"name",
		"secret_hash",
		"status",
		"default_fail_policy",
		"created_at",
		"updated_at",
	}).AddRow("app_demo", "demo", "demo-app", "hash", "active", "fail_open", now, now)

	mock.ExpectQuery("UPDATE applications").
		WithArgs("demo", "hash", sqlmock.AnyArg()).
		WillReturnRows(rows)

	store := NewPostgresControlStore(db, slog.Default())
	application, err := store.RotateApplicationSecret("demo", "hash")
	if err != nil {
		t.Fatalf("rotate secret: %v", err)
	}
	if application.SecretHash != "hash" || application.ClientID != "demo" || !application.HasSecret {
		t.Fatalf("unexpected application: %+v", application)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestPostgresControlStoreListRoutePolicies(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"id",
		"client_id",
		"name",
		"path_pattern",
		"method",
		"scene",
		"mode",
		"challenge_type",
		"risk_challenge_type",
		"challenge_escalation",
		"fail_policy",
		"priority",
		"enabled",
		"rollout_percent",
		"token_ttl_seconds",
		"risk_challenge_score",
		"risk_block_score",
		"risk_observe_score",
		"rate_window_seconds",
		"rate_max_requests",
		"rate_strategy",
		"created_at",
		"updated_at",
	}).AddRow(
		"route_comment",
		"demo",
		"comment",
		"/api/comment",
		"POST",
		"comment",
		"rate_limit",
		string(types.CaptchaRotate),
		string(types.CaptchaWordImageClick),
		"SLIDER,WORD_IMAGE_CLICK",
		"fail_open",
		30,
		true,
		75,
		120,
		70,
		95,
		40,
		60,
		5,
		"sliding_window",
		now,
		now,
	)
	mock.ExpectQuery("SELECT id, client_id, name, path_pattern, method, scene, mode, challenge_type, risk_challenge_type, challenge_escalation, fail_policy,\\s+priority, enabled, rollout_percent, token_ttl_seconds, risk_challenge_score, risk_block_score,\\s+risk_observe_score, rate_window_seconds, rate_max_requests, rate_strategy, created_at, updated_at\\s+FROM route_policies\\s+WHERE client_id = \\$1\\s+ORDER BY priority DESC, created_at ASC").
		WithArgs("demo").
		WillReturnRows(rows)

	store := NewPostgresControlStore(db, slog.Default())
	routes := store.ListRoutePolicies("demo")
	if len(routes) != 1 {
		t.Fatalf("expected one route, got %+v", routes)
	}
	if routes[0].ChallengeType != types.CaptchaRotate {
		t.Fatalf("expected rotate challenge, got %+v", routes[0])
	}
	if routes[0].RiskChallengeType != types.CaptchaWordImageClick {
		t.Fatalf("expected risk challenge type mapping, got %+v", routes[0])
	}
	if got := challengepkg.FormatEscalationCSV(routes[0].ChallengeEscalation); got != "SLIDER,WORD_IMAGE_CLICK" {
		t.Fatalf("expected challenge escalation mapping, got %q", got)
	}
	if routes[0].RateLimit == nil || routes[0].RateLimit.WindowSeconds != 60 || routes[0].RateLimit.MaxRequests != 5 {
		t.Fatalf("expected rate limit mapping, got %+v", routes[0].RateLimit)
	}
	if routes[0].RateLimit.Strategy != "sliding_window" {
		t.Fatalf("expected sliding window strategy mapping, got %+v", routes[0].RateLimit)
	}
	if routes[0].RolloutPercent != 75 {
		t.Fatalf("expected rollout percent mapping, got %+v", routes[0])
	}
	if routes[0].RiskChallengeScore != 70 || routes[0].RiskBlockScore != 95 || routes[0].RiskObserveScore != 40 {
		t.Fatalf("expected risk thresholds mapping, got %+v", routes[0])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestPostgresControlStoreDeleteRoutePolicies(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("DELETE FROM route_policies WHERE id IN \\(\\$1\\) AND client_id = \\$2").
		WithArgs("route_stale", "demo").
		WillReturnResult(sqlmock.NewResult(0, 1))

	store := NewPostgresControlStore(db, slog.Default())
	if deleted := store.DeleteRoutePolicies("demo", []string{"route_stale"}); deleted != 1 {
		t.Fatalf("expected one deleted route policy, got %d", deleted)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestNormalizeRateStrategy(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"":                 "fixed_window",
		"fixed_window":     "fixed_window",
		"sliding_window":   "sliding_window",
		"token_bucket":     "token_bucket",
		" TOKEN_BUCKET ":   "token_bucket",
		"unknown_strategy": "fixed_window",
	}
	for input, expected := range cases {
		if got := normalizeRateStrategy(input); got != expected {
			t.Fatalf("normalizeRateStrategy(%q)=%q, want %q", input, got, expected)
		}
	}
}

func TestPostgresControlStoreUpsertIPPolicy(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"id",
		"client_id",
		"type",
		"cidr",
		"action",
		"reason",
		"enabled",
		"created_at",
		"updated_at",
	}).AddRow("ip_abuse", "demo", "blocklist", "203.0.113.0/24", string(types.DecisionBlock), "abuse", true, now, now)

	mock.ExpectQuery("INSERT INTO ip_policies").
		WithArgs(
			"ip_abuse",
			"demo",
			"blocklist",
			"203.0.113.0/24",
			string(types.DecisionBlock),
			"abuse",
			true,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnRows(rows)

	store := NewPostgresControlStore(db, slog.Default())
	policy := store.UpsertIPPolicy(types.IPPolicy{
		ID:       "ip_abuse",
		ClientID: "demo",
		Type:     "blocklist",
		CIDR:     "203.0.113.0/24",
		Action:   types.DecisionBlock,
		Reason:   "abuse",
		Enabled:  true,
	})
	if policy.Action != types.DecisionBlock || policy.ID != "ip_abuse" {
		t.Fatalf("unexpected policy: %+v", policy)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestPostgresControlStoreDeleteIPPolicies(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("DELETE FROM ip_policies WHERE id IN \\(\\$1\\) AND client_id = \\$2").
		WithArgs("ip_stale", "demo").
		WillReturnResult(sqlmock.NewResult(0, 1))

	store := NewPostgresControlStore(db, slog.Default())
	if deleted := store.DeleteIPPolicies("demo", []string{"ip_stale"}); deleted != 1 {
		t.Fatalf("expected one deleted ip policy, got %d", deleted)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestPostgresControlStoreUpsertResourceWithScene(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"id",
		"client_id",
		"scene",
		"captcha_type",
		"resource_type",
		"storage_type",
		"uri",
		"tag",
		"status",
		"checksum",
		"metadata",
		"created_at",
		"updated_at",
	}).AddRow(
		"res_login_background",
		"demo",
		"login",
		string(types.CaptchaSlider),
		"background_image",
		"url",
		"https://cdn.example.test/login.png",
		"campaign",
		"active",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		[]byte(`{"height":160,"mime_type":"image/png","width":320}`),
		now,
		now,
	)

	mock.ExpectQuery("INSERT INTO captcha_resources").
		WithArgs(
			"res_login_background",
			"demo",
			"login",
			string(types.CaptchaSlider),
			"background_image",
			"url",
			"https://cdn.example.test/login.png",
			"campaign",
			"active",
			sql.NullString{String: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Valid: true},
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnRows(rows)

	store := NewPostgresControlStore(db, slog.Default())
	resource := store.UpsertResource(types.CaptchaResource{
		ID:           "res_login_background",
		ClientID:     "demo",
		Scene:        "login",
		CaptchaType:  types.CaptchaSlider,
		ResourceType: "background_image",
		StorageType:  "url",
		URI:          "https://cdn.example.test/login.png",
		Tag:          "campaign",
		Checksum:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Metadata: map[string]any{
			"width":     320,
			"height":    160,
			"mime_type": "image/png",
		},
		Status: "active",
	})
	if resource.Scene != "login" || resource.Tag != "campaign" || resource.CaptchaType != types.CaptchaSlider {
		t.Fatalf("unexpected resource: %+v", resource)
	}
	if resource.Checksum == "" || resource.Metadata["mime_type"] != "image/png" {
		t.Fatalf("expected persisted resource metadata, got %+v", resource)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestPostgresControlStoreAddAuditEvent(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("INSERT INTO audit_events").
		WithArgs(
			sqlmock.AnyArg(),
			"demo",
			"login",
			"/api/login",
			"",
			"",
			"",
			string(types.DecisionObserve),
			"HTTP_EVENT",
			"",
			"observe",
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	store := NewPostgresControlStore(db, slog.Default())
	event := store.AddAuditEvent(types.AuditEvent{
		ClientID:       "demo",
		Scene:          "login",
		Route:          "/api/login",
		Action:         types.DecisionObserve,
		DecisionReason: "HTTP_EVENT",
		Result:         "observe",
	})
	if event.ID == "" || event.CreatedAt.IsZero() {
		t.Fatalf("expected generated audit identity, got %+v", event)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestPostgresControlStoreAddRiskFeatureSnapshot(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("INSERT INTO risk_feature_snapshots").
		WithArgs(
			sqlmock.AnyArg(),
			"cap_sess_test",
			"demo",
			"login",
			string(types.CaptchaSlider),
			"track-v1",
			sqlmock.AnyArg(),
			"inline",
			sqlmock.AnyArg(),
			"captcha_retry",
			"captcha_result",
			false,
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	store := NewPostgresControlStore(db, slog.Default())
	snapshot := store.AddRiskFeatureSnapshot(types.RiskFeatureSnapshot{
		AttemptID:      "cap_sess_test",
		ClientID:       "demo",
		Scene:          "login",
		ChallengeType:  types.CaptchaSlider,
		FeatureVersion: "track-v1",
		Features: map[string]any{
			"track_score": 32,
		},
		Label:          "captcha_retry",
		LabelSource:    "captcha_result",
		ModelTrainable: false,
	})
	if snapshot.ID == "" || snapshot.FeaturesDigest == "" {
		t.Fatalf("snapshot was not prepared: %+v", snapshot)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestPostgresControlStoreUpdateRiskFeatureSnapshotLabel(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"id",
		"attempt_id",
		"client_id",
		"scene",
		"challenge_type",
		"feature_version",
		"features_digest",
		"features_ref",
		"features",
		"label",
		"label_source",
		"model_trainable",
		"created_at",
	}).AddRow(
		"feat_review",
		"cap_sess_test",
		"demo",
		"login",
		string(types.CaptchaSlider),
		"track-v1",
		"digest",
		"inline",
		[]byte(`{"track_score":82}`),
		"confirmed_bot",
		"manual_review",
		true,
		now,
	)

	mock.ExpectQuery("UPDATE risk_feature_snapshots").
		WithArgs(
			"feat_review",
			"confirmed_bot",
			sql.NullString{String: "manual_review", Valid: true},
			true,
		).
		WillReturnRows(rows)

	store := NewPostgresControlStore(db, slog.Default())
	snapshot, err := store.UpdateRiskFeatureSnapshotLabel("feat_review", "confirmed_bot", "manual_review", true)
	if err != nil {
		t.Fatalf("update label: %v", err)
	}
	if snapshot.Label != "confirmed_bot" || snapshot.LabelSource != "manual_review" || !snapshot.ModelTrainable {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestPostgresControlStoreUpsertRiskModelVersion(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"id",
		"name",
		"version",
		"feature_version",
		"training_window",
		"artifact_uri",
		"metrics",
		"mode",
		"status",
		"created_at",
		"activated_at",
	}).AddRow(
		"model_track_v1",
		"track-baseline",
		"v1",
		"track-v1",
		"2026-06-01/2026-06-10",
		"s3://models/track/v1.json",
		[]byte(`{"auc":0.91}`),
		"shadow",
		"candidate",
		now,
		sql.NullTime{},
	)

	mock.ExpectQuery("INSERT INTO risk_model_versions").
		WithArgs(
			"model_track_v1",
			"track-baseline",
			"v1",
			"track-v1",
			"2026-06-01/2026-06-10",
			"s3://models/track/v1.json",
			sqlmock.AnyArg(),
			"shadow",
			"candidate",
			sqlmock.AnyArg(),
			sql.NullTime{},
		).
		WillReturnRows(rows)

	store := NewPostgresControlStore(db, slog.Default())
	version := store.UpsertRiskModelVersion(types.RiskModelVersion{
		ID:             "model_track_v1",
		Name:           "track-baseline",
		Version:        "v1",
		FeatureVersion: "track-v1",
		TrainingWindow: "2026-06-01/2026-06-10",
		ArtifactURI:    "s3://models/track/v1.json",
		Mode:           "shadow",
		Metrics: map[string]any{
			"auc": 0.91,
		},
	})
	if version.ID != "model_track_v1" || version.Status != "candidate" || version.Metrics["auc"] == nil {
		t.Fatalf("unexpected model version: %+v", version)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

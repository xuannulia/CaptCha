package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	challengepkg "captcha/internal/challenge"
	"captcha/internal/routepolicy"
	"captcha/internal/types"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const postgresTimeout = 3 * time.Second

type PostgresControlStore struct {
	db     *sql.DB
	logger *slog.Logger
}

func NewPostgresControlStore(db *sql.DB, logger *slog.Logger) *PostgresControlStore {
	if logger == nil {
		logger = slog.Default()
	}
	return &PostgresControlStore{db: db, logger: logger}
}

func ApplyPostgresMigrations(ctx context.Context, db *sql.DB, dir string) error {
	entries, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		return err
	}
	sort.Strings(entries)
	if len(entries) == 0 {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	for _, entry := range entries {
		data, err := os.ReadFile(entry)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(data)) == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, string(data)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresControlStore) ListApplications() []types.Application {
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
SELECT id, client_id, name, secret_hash, status, default_fail_policy, created_at, updated_at
FROM applications
ORDER BY created_at DESC`)
	if err != nil {
		s.logError("list applications", err)
		return nil
	}
	defer rows.Close()

	applications := make([]types.Application, 0)
	for rows.Next() {
		application, err := scanApplication(rows)
		if err != nil {
			s.logError("scan application", err)
			continue
		}
		applications = append(applications, application)
	}
	if err := rows.Err(); err != nil {
		s.logError("iterate applications", err)
	}
	return applications
}

func (s *PostgresControlStore) UpsertApplication(application types.Application) types.Application {
	now := time.Now().UTC()
	if application.ID == "" {
		application.ID = newID("app")
	}
	if application.ClientID == "" {
		application.ClientID = application.ID
	}
	if application.Name == "" {
		application.Name = application.ClientID
	}
	if application.Status == "" {
		application.Status = "active"
	}
	if application.DefaultFailPolicy == "" {
		application.DefaultFailPolicy = "fail_open"
	}
	if application.CreatedAt.IsZero() {
		application.CreatedAt = now
	}
	application.UpdatedAt = now

	var secretHash sql.NullString
	if application.SecretHash != "" {
		secretHash = sql.NullString{String: application.SecretHash, Valid: true}
	}

	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	row := s.db.QueryRowContext(ctx, `
INSERT INTO applications (
  id, client_id, name, secret_hash, status, default_fail_policy, created_at, updated_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8
)
ON CONFLICT (client_id) DO UPDATE SET
  name = EXCLUDED.name,
  secret_hash = COALESCE(EXCLUDED.secret_hash, applications.secret_hash),
  status = EXCLUDED.status,
  default_fail_policy = EXCLUDED.default_fail_policy,
  updated_at = EXCLUDED.updated_at
RETURNING id, client_id, name, secret_hash, status, default_fail_policy, created_at, updated_at`,
		application.ID,
		application.ClientID,
		application.Name,
		secretHash,
		application.Status,
		application.DefaultFailPolicy,
		application.CreatedAt,
		application.UpdatedAt,
	)
	saved, err := scanApplication(row)
	if err != nil {
		s.logError("upsert application", err)
		return application
	}
	return saved
}

func (s *PostgresControlStore) RotateApplicationSecret(clientID, secretHash string) (types.Application, error) {
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	row := s.db.QueryRowContext(ctx, `
UPDATE applications
SET secret_hash = $2, updated_at = $3
WHERE client_id = $1
RETURNING id, client_id, name, secret_hash, status, default_fail_policy, created_at, updated_at`,
		clientID,
		secretHash,
		time.Now().UTC(),
	)
	application, err := scanApplication(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return types.Application{}, ErrNotFound
		}
		s.logError("rotate application secret", err)
		return types.Application{}, err
	}
	return application, nil
}

func (s *PostgresControlStore) ListRoutePolicies(clientID string) []types.RoutePolicy {
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	query := selectRoutePoliciesSQL + `
ORDER BY client_id ASC, priority DESC, created_at ASC`
	args := []any(nil)
	if clientID != "" {
		query = selectRoutePoliciesSQL + `
WHERE client_id = $1
ORDER BY priority DESC, created_at ASC`
		args = append(args, clientID)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		s.logError("list route policies", err)
		return nil
	}
	defer rows.Close()

	routes := make([]types.RoutePolicy, 0)
	for rows.Next() {
		route, err := scanRoutePolicy(rows)
		if err != nil {
			s.logError("scan route policy", err)
			continue
		}
		routes = append(routes, route)
	}
	if err := rows.Err(); err != nil {
		s.logError("iterate route policies", err)
	}
	return routes
}

func (s *PostgresControlStore) UpsertRoutePolicy(route types.RoutePolicy) types.RoutePolicy {
	now := time.Now().UTC()
	if route.ID == "" {
		route.ID = newID("route")
	}
	if route.ClientID == "" {
		route.ClientID = "demo"
	}
	if route.Mode == "" {
		route.Mode = "always"
	}
	if route.ChallengeType == "" || route.ChallengeType == types.CaptchaAuto {
		route.ChallengeType = types.CaptchaSlider
	}
	if route.FailPolicy == "" {
		route.FailPolicy = "fail_open"
	}
	if route.TokenTTLSeconds <= 0 {
		route.TokenTTLSeconds = 120
	}
	route.RolloutPercent = routepolicy.NormalizeRolloutPercent(route.RolloutPercent)
	route.ChallengeEscalation = challengepkg.NormalizeConfiguredEscalation(route.ChallengeEscalation)
	if route.CreatedAt.IsZero() {
		route.CreatedAt = now
	}
	route.UpdatedAt = now

	var rateWindow sql.NullInt64
	var rateMax sql.NullInt64
	rateStrategy := "fixed_window"
	if route.RateLimit != nil {
		rateWindow = sql.NullInt64{Int64: int64(route.RateLimit.WindowSeconds), Valid: true}
		rateMax = sql.NullInt64{Int64: int64(route.RateLimit.MaxRequests), Valid: true}
		rateStrategy = normalizeRateStrategy(route.RateLimit.Strategy)
	}

	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	row := s.db.QueryRowContext(ctx, `
INSERT INTO route_policies (
  id, client_id, name, path_pattern, method, scene, mode, challenge_type, risk_challenge_type, challenge_escalation, fail_policy,
  priority, enabled, rollout_percent, token_ttl_seconds, risk_challenge_score, risk_block_score,
  risk_observe_score, rate_window_seconds, rate_max_requests, rate_strategy, created_at, updated_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
)
ON CONFLICT (id) DO UPDATE SET
  client_id = EXCLUDED.client_id,
  name = EXCLUDED.name,
  path_pattern = EXCLUDED.path_pattern,
  method = EXCLUDED.method,
  scene = EXCLUDED.scene,
  mode = EXCLUDED.mode,
  challenge_type = EXCLUDED.challenge_type,
  risk_challenge_type = EXCLUDED.risk_challenge_type,
  challenge_escalation = EXCLUDED.challenge_escalation,
  fail_policy = EXCLUDED.fail_policy,
  priority = EXCLUDED.priority,
  enabled = EXCLUDED.enabled,
  rollout_percent = EXCLUDED.rollout_percent,
  token_ttl_seconds = EXCLUDED.token_ttl_seconds,
  risk_challenge_score = EXCLUDED.risk_challenge_score,
  risk_block_score = EXCLUDED.risk_block_score,
  risk_observe_score = EXCLUDED.risk_observe_score,
  rate_window_seconds = EXCLUDED.rate_window_seconds,
  rate_max_requests = EXCLUDED.rate_max_requests,
  rate_strategy = EXCLUDED.rate_strategy,
  updated_at = EXCLUDED.updated_at
RETURNING id, client_id, name, path_pattern, method, scene, mode, challenge_type, risk_challenge_type, challenge_escalation, fail_policy,
  priority, enabled, rollout_percent, token_ttl_seconds, risk_challenge_score, risk_block_score,
  risk_observe_score, rate_window_seconds, rate_max_requests, rate_strategy, created_at, updated_at`,
		route.ID,
		route.ClientID,
		route.Name,
		route.PathPattern,
		route.Method,
		route.Scene,
		route.Mode,
		string(route.ChallengeType),
		string(route.RiskChallengeType),
		challengepkg.FormatEscalationCSV(route.ChallengeEscalation),
		route.FailPolicy,
		route.Priority,
		route.Enabled,
		route.RolloutPercent,
		route.TokenTTLSeconds,
		route.RiskChallengeScore,
		route.RiskBlockScore,
		route.RiskObserveScore,
		rateWindow,
		rateMax,
		rateStrategy,
		route.CreatedAt,
		route.UpdatedAt,
	)
	saved, err := scanRoutePolicy(row)
	if err != nil {
		s.logError("upsert route policy", err)
		return route
	}
	return saved
}

func (s *PostgresControlStore) DeleteRoutePolicies(clientID string, ids []string) int {
	return s.deleteRowsByIDs("route_policies", clientID, ids)
}

func (s *PostgresControlStore) ListIPPolicies(clientID string) []types.IPPolicy {
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	query := selectIPPoliciesSQL + `
ORDER BY client_id ASC, created_at ASC`
	args := []any(nil)
	if clientID != "" {
		query = selectIPPoliciesSQL + `
WHERE client_id = $1
ORDER BY created_at ASC`
		args = append(args, clientID)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		s.logError("list ip policies", err)
		return nil
	}
	defer rows.Close()

	policies := make([]types.IPPolicy, 0)
	for rows.Next() {
		policy, err := scanIPPolicy(rows)
		if err != nil {
			s.logError("scan ip policy", err)
			continue
		}
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		s.logError("iterate ip policies", err)
	}
	return policies
}

func (s *PostgresControlStore) UpsertIPPolicy(policy types.IPPolicy) types.IPPolicy {
	now := time.Now().UTC()
	if policy.ID == "" {
		policy.ID = newID("ip")
	}
	if policy.ClientID == "" {
		policy.ClientID = "demo"
	}
	if policy.Action == "" {
		switch policy.Type {
		case "allowlist":
			policy.Action = types.DecisionAllow
		case "blocklist":
			policy.Action = types.DecisionBlock
		default:
			policy.Action = types.DecisionChallenge
		}
	}
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now

	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	row := s.db.QueryRowContext(ctx, `
INSERT INTO ip_policies (
  id, client_id, type, cidr, action, reason, enabled, created_at, updated_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8, $9
)
ON CONFLICT (id) DO UPDATE SET
  client_id = EXCLUDED.client_id,
  type = EXCLUDED.type,
  cidr = EXCLUDED.cidr,
  action = EXCLUDED.action,
  reason = EXCLUDED.reason,
  enabled = EXCLUDED.enabled,
  updated_at = EXCLUDED.updated_at
RETURNING id, client_id, type, cidr, action, reason, enabled, created_at, updated_at`,
		policy.ID,
		policy.ClientID,
		policy.Type,
		policy.CIDR,
		string(policy.Action),
		policy.Reason,
		policy.Enabled,
		policy.CreatedAt,
		policy.UpdatedAt,
	)
	saved, err := scanIPPolicy(row)
	if err != nil {
		s.logError("upsert ip policy", err)
		return policy
	}
	return saved
}

func (s *PostgresControlStore) DeleteIPPolicies(clientID string, ids []string) int {
	return s.deleteRowsByIDs("ip_policies", clientID, ids)
}

func (s *PostgresControlStore) ListResources(clientID string) []types.CaptchaResource {
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	query := selectResourcesSQL + `
ORDER BY client_id ASC, captcha_type ASC, resource_type ASC, created_at ASC`
	args := []any(nil)
	if clientID != "" {
		query = selectResourcesSQL + `
WHERE client_id = $1
ORDER BY captcha_type ASC, resource_type ASC, created_at ASC`
		args = append(args, clientID)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		s.logError("list resources", err)
		return nil
	}
	defer rows.Close()

	resources := make([]types.CaptchaResource, 0)
	for rows.Next() {
		resource, err := scanResource(rows)
		if err != nil {
			s.logError("scan resource", err)
			continue
		}
		resources = append(resources, resource)
	}
	if err := rows.Err(); err != nil {
		s.logError("iterate resources", err)
	}
	return resources
}

func (s *PostgresControlStore) UpsertResource(resource types.CaptchaResource) types.CaptchaResource {
	now := time.Now().UTC()
	if resource.ID == "" {
		resource.ID = newID("res")
	}
	if resource.ClientID == "" {
		resource.ClientID = "demo"
	}
	if resource.CaptchaType == "" {
		resource.CaptchaType = types.CaptchaAuto
	}
	if resource.StorageType == "" {
		resource.StorageType = "embedded"
	}
	if resource.Status == "" {
		resource.Status = "active"
	}
	if resource.CreatedAt.IsZero() {
		resource.CreatedAt = now
	}
	resource.UpdatedAt = now

	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	row := s.db.QueryRowContext(ctx, `
INSERT INTO captcha_resources (
  id, client_id, scene, captcha_type, resource_type, storage_type, uri, tag, status, checksum, metadata, created_at, updated_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
)
ON CONFLICT (id) DO UPDATE SET
  client_id = EXCLUDED.client_id,
  scene = EXCLUDED.scene,
  captcha_type = EXCLUDED.captcha_type,
  resource_type = EXCLUDED.resource_type,
  storage_type = EXCLUDED.storage_type,
  uri = EXCLUDED.uri,
  tag = EXCLUDED.tag,
  status = EXCLUDED.status,
  checksum = EXCLUDED.checksum,
  metadata = EXCLUDED.metadata,
  updated_at = EXCLUDED.updated_at
RETURNING id, client_id, scene, captcha_type, resource_type, storage_type, uri, tag, status, checksum, metadata, created_at, updated_at`,
		resource.ID,
		resource.ClientID,
		resource.Scene,
		string(resource.CaptchaType),
		resource.ResourceType,
		resource.StorageType,
		resource.URI,
		resource.Tag,
		resource.Status,
		nullString(resource.Checksum),
		resourceMetadataJSON(resource.Metadata),
		resource.CreatedAt,
		resource.UpdatedAt,
	)
	saved, err := scanResource(row)
	if err != nil {
		s.logError("upsert resource", err)
		return resource
	}
	return saved
}

func (s *PostgresControlStore) DeleteResources(clientID string, ids []string) int {
	return s.deleteRowsByIDs("captcha_resources", clientID, ids)
}

func (s *PostgresControlStore) deleteRowsByIDs(table, clientID string, ids []string) int {
	if len(ids) == 0 {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	placeholders := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids)+1)
	for _, id := range ids {
		args = append(args, id)
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
	}
	query := `DELETE FROM ` + table + ` WHERE id IN (` + strings.Join(placeholders, ", ") + `)`
	if clientID != "" {
		args = append(args, clientID)
		query += fmt.Sprintf(` AND client_id = $%d`, len(args))
	}
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		s.logError("delete "+table, err)
		return 0
	}
	count, err := result.RowsAffected()
	if err != nil {
		s.logError("delete "+table+" rows affected", err)
		return 0
	}
	return int(count)
}

func (s *PostgresControlStore) AddAuditEvent(event types.AuditEvent) types.AuditEvent {
	now := time.Now().UTC()
	if event.ID == "" {
		event.ID = newID("audit")
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = now
	}

	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_events (
  id, client_id, scene, route, ip_hash, account_id_hash, device_id_hash, action, decision_reason,
  challenge_type, result, created_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
)`,
		event.ID,
		event.ClientID,
		event.Scene,
		event.Route,
		event.IPHash,
		event.AccountIDHash,
		event.DeviceIDHash,
		string(event.Action),
		event.DecisionReason,
		string(event.ChallengeType),
		event.Result,
		event.CreatedAt,
	)
	if err != nil {
		s.logError("add audit event", err)
	}
	return event
}

func (s *PostgresControlStore) ListAuditEvents(clientID string, limit int) []types.AuditEvent {
	return s.ListAuditEventsFiltered(types.AuditEventFilter{ClientID: clientID, Limit: limit})
}

func (s *PostgresControlStore) ListAuditEventsFiltered(filter types.AuditEventFilter) []types.AuditEvent {
	limit := normalizedListFetchLimit(filter.Limit)
	offset := normalizedOffset(filter.Offset)

	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	conditions := make([]string, 0, 5)
	args := make([]any, 0, 6)
	addCondition := func(column string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	if filter.ClientID != "" {
		addCondition("client_id", filter.ClientID)
	}
	if filter.Scene != "" {
		addCondition("scene", filter.Scene)
	}
	if filter.Action != "" {
		addCondition("action", string(filter.Action))
	}
	if filter.Result != "" {
		addCondition("result", filter.Result)
	}
	if filter.DecisionReason != "" {
		addCondition("decision_reason", filter.DecisionReason)
	}
	if filter.AccountIDHash != "" {
		addCondition("account_id_hash", filter.AccountIDHash)
	}
	if filter.DeviceIDHash != "" {
		addCondition("device_id_hash", filter.DeviceIDHash)
	}
	query := selectAuditEventsSQL
	if len(conditions) > 0 {
		query += `
WHERE ` + strings.Join(conditions, " AND ")
	}
	args = append(args, limit)
	query += fmt.Sprintf(`
ORDER BY created_at DESC
LIMIT $%d`, len(args))
	args = append(args, offset)
	query += fmt.Sprintf(`
OFFSET $%d`, len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		s.logError("list audit events", err)
		return nil
	}
	defer rows.Close()

	events := make([]types.AuditEvent, 0)
	for rows.Next() {
		event, err := scanAuditEvent(rows)
		if err != nil {
			s.logError("scan audit event", err)
			continue
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		s.logError("iterate audit events", err)
	}
	return events
}

func (s *PostgresControlStore) AddRiskFeatureSnapshot(snapshot types.RiskFeatureSnapshot) types.RiskFeatureSnapshot {
	snapshot = prepareRiskFeatureSnapshot(snapshot)
	features, err := json.Marshal(snapshot.Features)
	if err != nil {
		features = []byte("{}")
	}

	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	_, err = s.db.ExecContext(ctx, `
INSERT INTO risk_feature_snapshots (
  id, attempt_id, client_id, scene, challenge_type, feature_version, features_digest,
  features_ref, features, label, label_source, model_trainable, created_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13
)`,
		snapshot.ID,
		snapshot.AttemptID,
		snapshot.ClientID,
		snapshot.Scene,
		string(snapshot.ChallengeType),
		snapshot.FeatureVersion,
		snapshot.FeaturesDigest,
		snapshot.FeaturesRef,
		string(features),
		snapshot.Label,
		snapshot.LabelSource,
		snapshot.ModelTrainable,
		snapshot.CreatedAt,
	)
	if err != nil {
		s.logError("add risk feature snapshot", err)
	}
	return snapshot
}

func (s *PostgresControlStore) ListRiskFeatureSnapshots(clientID string, limit int) []types.RiskFeatureSnapshot {
	return s.ListRiskFeatureSnapshotsFiltered(types.RiskFeatureSnapshotFilter{ClientID: clientID, Limit: limit})
}

func (s *PostgresControlStore) ListRiskFeatureSnapshotsFiltered(filter types.RiskFeatureSnapshotFilter) []types.RiskFeatureSnapshot {
	limit := normalizedListFetchLimit(filter.Limit)
	offset := normalizedOffset(filter.Offset)

	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	conditions := make([]string, 0, 5)
	args := make([]any, 0, 6)
	addCondition := func(column string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	if filter.ClientID != "" {
		addCondition("client_id", filter.ClientID)
	}
	if filter.Scene != "" {
		addCondition("scene", filter.Scene)
	}
	if filter.ChallengeType != "" {
		addCondition("challenge_type", string(filter.ChallengeType))
	}
	if filter.Label != "" {
		addCondition("label", filter.Label)
	}
	if filter.ModelTrainable != nil {
		addCondition("model_trainable", *filter.ModelTrainable)
	}
	query := selectRiskFeatureSnapshotsSQL
	if len(conditions) > 0 {
		query += `
WHERE ` + strings.Join(conditions, " AND ")
	}
	args = append(args, limit)
	query += fmt.Sprintf(`
ORDER BY created_at DESC
LIMIT $%d`, len(args))
	args = append(args, offset)
	query += fmt.Sprintf(`
OFFSET $%d`, len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		s.logError("list risk feature snapshots", err)
		return nil
	}
	defer rows.Close()

	snapshots := make([]types.RiskFeatureSnapshot, 0)
	for rows.Next() {
		snapshot, err := scanRiskFeatureSnapshot(rows)
		if err != nil {
			s.logError("scan risk feature snapshot", err)
			continue
		}
		snapshots = append(snapshots, snapshot)
	}
	if err := rows.Err(); err != nil {
		s.logError("iterate risk feature snapshots", err)
	}
	return snapshots
}

func (s *PostgresControlStore) UpdateRiskFeatureSnapshotLabel(id, label, labelSource string, modelTrainable bool) (types.RiskFeatureSnapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	row := s.db.QueryRowContext(ctx, `
UPDATE risk_feature_snapshots
SET label = $2, label_source = $3, model_trainable = $4
WHERE id = $1
RETURNING id, attempt_id, client_id, scene, challenge_type, feature_version, features_digest,
  features_ref, features, label, label_source, model_trainable, created_at`,
		id,
		label,
		nullString(labelSource),
		modelTrainable,
	)
	snapshot, err := scanRiskFeatureSnapshot(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return types.RiskFeatureSnapshot{}, ErrNotFound
		}
		s.logError("update risk feature snapshot label", err)
		return types.RiskFeatureSnapshot{}, err
	}
	return snapshot, nil
}

func (s *PostgresControlStore) ListRiskModelVersions(name string, limit int) []types.RiskModelVersion {
	if limit <= 0 || limit > 200 {
		limit = 100
	}

	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	query := selectRiskModelVersionsSQL + `
ORDER BY created_at DESC
LIMIT $1`
	args := []any{limit}
	if name != "" {
		query = selectRiskModelVersionsSQL + `
WHERE name = $1
ORDER BY created_at DESC
LIMIT $2`
		args = []any{name, limit}
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		s.logError("list risk model versions", err)
		return nil
	}
	defer rows.Close()

	versions := make([]types.RiskModelVersion, 0)
	for rows.Next() {
		version, err := scanRiskModelVersion(rows)
		if err != nil {
			s.logError("scan risk model version", err)
			continue
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		s.logError("iterate risk model versions", err)
	}
	return versions
}

func (s *PostgresControlStore) UpsertRiskModelVersion(version types.RiskModelVersion) types.RiskModelVersion {
	version = prepareRiskModelVersion(version)
	metrics, err := json.Marshal(version.Metrics)
	if err != nil {
		metrics = []byte("{}")
	}

	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	row := s.db.QueryRowContext(ctx, `
INSERT INTO risk_model_versions (
  id, name, version, feature_version, training_window, artifact_uri, metrics, mode, status, created_at, activated_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11
)
ON CONFLICT (name, version) DO UPDATE SET
  feature_version = EXCLUDED.feature_version,
  training_window = EXCLUDED.training_window,
  artifact_uri = EXCLUDED.artifact_uri,
  metrics = EXCLUDED.metrics,
  mode = EXCLUDED.mode,
  status = CASE WHEN risk_model_versions.status = 'active' THEN risk_model_versions.status ELSE EXCLUDED.status END
RETURNING id, name, version, feature_version, training_window, artifact_uri, metrics, mode, status, created_at, activated_at`,
		version.ID,
		version.Name,
		version.Version,
		version.FeatureVersion,
		version.TrainingWindow,
		version.ArtifactURI,
		string(metrics),
		version.Mode,
		version.Status,
		version.CreatedAt,
		nullTime(version.ActivatedAt),
	)
	saved, err := scanRiskModelVersion(row)
	if err != nil {
		s.logError("upsert risk model version", err)
		return version
	}
	return saved
}

func (s *PostgresControlStore) ActivateRiskModelVersion(id string) (types.RiskModelVersion, error) {
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return types.RiskModelVersion{}, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var name string
	if err := tx.QueryRowContext(ctx, `SELECT name FROM risk_model_versions WHERE id = $1`, id).Scan(&name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return types.RiskModelVersion{}, ErrNotFound
		}
		return types.RiskModelVersion{}, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE risk_model_versions
SET status = 'retired'
WHERE name = $1 AND id <> $2 AND status = 'active'`, name, id); err != nil {
		return types.RiskModelVersion{}, err
	}
	row := tx.QueryRowContext(ctx, `
UPDATE risk_model_versions
SET status = 'active', activated_at = $2
WHERE id = $1
RETURNING id, name, version, feature_version, training_window, artifact_uri, metrics, mode, status, created_at, activated_at`,
		id,
		time.Now().UTC(),
	)
	version, err := scanRiskModelVersion(row)
	if err != nil {
		return types.RiskModelVersion{}, err
	}
	if err := tx.Commit(); err != nil {
		return types.RiskModelVersion{}, err
	}
	return version, nil
}

func (s *PostgresControlStore) RollbackRiskModelVersion(id string) (types.RiskModelVersion, error) {
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return types.RiskModelVersion{}, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var name string
	if err := tx.QueryRowContext(ctx, `SELECT name FROM risk_model_versions WHERE id = $1`, id).Scan(&name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return types.RiskModelVersion{}, ErrNotFound
		}
		return types.RiskModelVersion{}, err
	}
	var candidateID string
	if err := tx.QueryRowContext(ctx, `
SELECT id
FROM risk_model_versions
WHERE name = $1 AND id <> $2 AND status = 'retired'
ORDER BY activated_at DESC NULLS LAST, created_at DESC
LIMIT 1`, name, id).Scan(&candidateID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return types.RiskModelVersion{}, ErrNotFound
		}
		return types.RiskModelVersion{}, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE risk_model_versions
SET status = 'rolled_back'
WHERE name = $1 AND status = 'active'`, name); err != nil {
		return types.RiskModelVersion{}, err
	}
	row := tx.QueryRowContext(ctx, `
UPDATE risk_model_versions
SET status = 'active', activated_at = $2
WHERE id = $1
RETURNING id, name, version, feature_version, training_window, artifact_uri, metrics, mode, status, created_at, activated_at`,
		candidateID,
		time.Now().UTC(),
	)
	version, err := scanRiskModelVersion(row)
	if err != nil {
		return types.RiskModelVersion{}, err
	}
	if err := tx.Commit(); err != nil {
		return types.RiskModelVersion{}, err
	}
	return version, nil
}

func (s *PostgresControlStore) SeedDemoData(ctx context.Context) error {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM applications`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, `
INSERT INTO applications (id, client_id, name, status, default_fail_policy, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (id) DO NOTHING`,
		"app_demo", "demo", "demo-app", "active", "fail_open", now, now,
	); err != nil {
		return err
	}

	routeRows := []types.RoutePolicy{
		{ID: "route_login", ClientID: "demo", Name: "login", PathPattern: "/api/login", Method: "POST", Scene: "login", Mode: "risk_based", ChallengeType: types.CaptchaSlider, FailPolicy: "fail_close", Priority: 10, Enabled: true, TokenTTLSeconds: 120, CreatedAt: now, UpdatedAt: now},
		{ID: "route_register", ClientID: "demo", Name: "register", PathPattern: "/api/register", Method: "POST", Scene: "register", Mode: "always", ChallengeType: types.CaptchaWordImageClick, FailPolicy: "fail_close", Priority: 20, Enabled: true, TokenTTLSeconds: 120, CreatedAt: now, UpdatedAt: now},
		{ID: "route_comment", ClientID: "demo", Name: "comment", PathPattern: "/api/comment", Method: "POST", Scene: "comment", Mode: "rate_limit", ChallengeType: types.CaptchaRotate, FailPolicy: "fail_open", Priority: 30, Enabled: true, TokenTTLSeconds: 120, RateLimit: &types.RateLimit{WindowSeconds: 60, MaxRequests: 5}, CreatedAt: now, UpdatedAt: now},
	}
	for _, route := range routeRows {
		route.RolloutPercent = routepolicy.NormalizeRolloutPercent(route.RolloutPercent)
		route.ChallengeEscalation = challengepkg.NormalizeConfiguredEscalation(route.ChallengeEscalation)
		var rateWindow sql.NullInt64
		var rateMax sql.NullInt64
		rateStrategy := "fixed_window"
		if route.RateLimit != nil {
			rateWindow = sql.NullInt64{Int64: int64(route.RateLimit.WindowSeconds), Valid: true}
			rateMax = sql.NullInt64{Int64: int64(route.RateLimit.MaxRequests), Valid: true}
			rateStrategy = normalizeRateStrategy(route.RateLimit.Strategy)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO route_policies (
  id, client_id, name, path_pattern, method, scene, mode, challenge_type, risk_challenge_type, challenge_escalation, fail_policy,
  priority, enabled, rollout_percent, token_ttl_seconds, risk_challenge_score, risk_block_score,
  risk_observe_score, rate_window_seconds, rate_max_requests, rate_strategy, created_at, updated_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
)
ON CONFLICT (id) DO NOTHING`,
			route.ID, route.ClientID, route.Name, route.PathPattern, route.Method, route.Scene,
			route.Mode, string(route.ChallengeType), string(route.RiskChallengeType), challengepkg.FormatEscalationCSV(route.ChallengeEscalation), route.FailPolicy, route.Priority, route.Enabled,
			route.RolloutPercent, route.TokenTTLSeconds, route.RiskChallengeScore, route.RiskBlockScore,
			route.RiskObserveScore, rateWindow, rateMax, rateStrategy, route.CreatedAt, route.UpdatedAt,
		); err != nil {
			return err
		}
	}

	ipRows := []types.IPPolicy{
		{ID: "ip_internal", ClientID: "demo", Type: "allowlist", CIDR: "10.0.0.0/8", Action: types.DecisionAllow, Reason: "internal", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "ip_abuse", ClientID: "demo", Type: "blocklist", CIDR: "203.0.113.0/24", Action: types.DecisionBlock, Reason: "abuse", Enabled: true, CreatedAt: now, UpdatedAt: now},
	}
	for _, policy := range ipRows {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO ip_policies (id, client_id, type, cidr, action, reason, enabled, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (id) DO NOTHING`,
			policy.ID, policy.ClientID, policy.Type, policy.CIDR, string(policy.Action), policy.Reason,
			policy.Enabled, policy.CreatedAt, policy.UpdatedAt,
		); err != nil {
			return err
		}
	}

	resources := []types.CaptchaResource{
		{ID: "res_background", ClientID: "demo", CaptchaType: types.CaptchaAuto, ResourceType: "background_image", StorageType: "embedded", URI: "embedded://default-backgrounds", Tag: "default", Status: "active", CreatedAt: now, UpdatedAt: now},
		{ID: "res_slider", ClientID: "demo", CaptchaType: types.CaptchaSlider, ResourceType: "slider_template", StorageType: "embedded", URI: "embedded://slider-template", Tag: "default", Status: "active", CreatedAt: now, UpdatedAt: now},
		{ID: "res_font", ClientID: "demo", CaptchaType: types.CaptchaWordImageClick, ResourceType: "font", StorageType: "embedded", URI: "embedded://default-font", Tag: "word", Status: "active", CreatedAt: now, UpdatedAt: now},
	}
	for _, resource := range resources {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO captcha_resources (
  id, client_id, scene, captcha_type, resource_type, storage_type, uri, tag, status, metadata, created_at, updated_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8, $9, '{}'::jsonb, $10, $11
)
ON CONFLICT (id) DO NOTHING`,
			resource.ID, resource.ClientID, resource.Scene, string(resource.CaptchaType), resource.ResourceType,
			resource.StorageType, resource.URI, resource.Tag, resource.Status, resource.CreatedAt,
			resource.UpdatedAt,
		); err != nil {
			return err
		}
	}

	auditRows := []types.AuditEvent{
		{ID: "audit_seed_1", ClientID: "demo", Scene: "login", Route: "/api/login", Action: types.DecisionChallenge, DecisionReason: "RISK_BASED", ChallengeType: types.CaptchaSlider, Result: "pass", CreatedAt: now},
		{ID: "audit_seed_2", ClientID: "demo", Scene: "comment", Route: "/api/comment", Action: types.DecisionChallenge, DecisionReason: "RATE_LIMIT", ChallengeType: types.CaptchaRotate, Result: "retry", CreatedAt: now},
	}
	for _, event := range auditRows {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_events (
  id, client_id, scene, route, ip_hash, account_id_hash, device_id_hash, action, decision_reason,
  challenge_type, result, created_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
)
ON CONFLICT (id) DO NOTHING`,
			event.ID, event.ClientID, event.Scene, event.Route, event.IPHash, event.AccountIDHash, event.DeviceIDHash,
			string(event.Action), event.DecisionReason, string(event.ChallengeType), event.Result, event.CreatedAt,
		); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *PostgresControlStore) logError(message string, err error) {
	if err != nil && s.logger != nil {
		s.logger.Error(message, "error", err)
	}
}

func nullString(value string) sql.NullString {
	value = strings.TrimSpace(value)
	if value == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}

func nullTime(value *time.Time) sql.NullTime {
	if value == nil || value.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *value, Valid: true}
}

func resourceMetadataJSON(metadata map[string]any) []byte {
	if len(metadata) == 0 {
		return []byte("{}")
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return []byte("{}")
	}
	return data
}

const selectRoutePoliciesSQL = `
SELECT id, client_id, name, path_pattern, method, scene, mode, challenge_type, risk_challenge_type, challenge_escalation, fail_policy,
  priority, enabled, rollout_percent, token_ttl_seconds, risk_challenge_score, risk_block_score,
  risk_observe_score, rate_window_seconds, rate_max_requests, rate_strategy, created_at, updated_at
FROM route_policies
`

const selectIPPoliciesSQL = `
SELECT id, client_id, type, cidr, action, reason, enabled, created_at, updated_at
FROM ip_policies
`

const selectResourcesSQL = `
SELECT id, client_id, scene, captcha_type, resource_type, storage_type, uri, tag, status, checksum, metadata, created_at, updated_at
FROM captcha_resources
`

const selectAuditEventsSQL = `
SELECT id, client_id, scene, route, ip_hash, account_id_hash, device_id_hash, action, decision_reason, challenge_type, result, created_at
FROM audit_events
`

const selectRiskFeatureSnapshotsSQL = `
SELECT id, attempt_id, client_id, scene, challenge_type, feature_version, features_digest,
  features_ref, features, label, label_source, model_trainable, created_at
FROM risk_feature_snapshots
`

const selectRiskModelVersionsSQL = `
SELECT id, name, version, feature_version, training_window, artifact_uri, metrics, mode, status, created_at, activated_at
FROM risk_model_versions
`

type scanner interface {
	Scan(dest ...any) error
}

func scanApplication(row scanner) (types.Application, error) {
	var application types.Application
	var secretHash sql.NullString
	err := row.Scan(
		&application.ID,
		&application.ClientID,
		&application.Name,
		&secretHash,
		&application.Status,
		&application.DefaultFailPolicy,
		&application.CreatedAt,
		&application.UpdatedAt,
	)
	if err != nil {
		return types.Application{}, err
	}
	application.SecretHash = secretHash.String
	application.HasSecret = secretHash.Valid && secretHash.String != ""
	return application, nil
}

func scanRoutePolicy(row scanner) (types.RoutePolicy, error) {
	var route types.RoutePolicy
	var captchaType string
	var riskCaptchaType string
	var challengeEscalation string
	var rateWindow sql.NullInt64
	var rateMax sql.NullInt64
	var rateStrategy string
	err := row.Scan(
		&route.ID,
		&route.ClientID,
		&route.Name,
		&route.PathPattern,
		&route.Method,
		&route.Scene,
		&route.Mode,
		&captchaType,
		&riskCaptchaType,
		&challengeEscalation,
		&route.FailPolicy,
		&route.Priority,
		&route.Enabled,
		&route.RolloutPercent,
		&route.TokenTTLSeconds,
		&route.RiskChallengeScore,
		&route.RiskBlockScore,
		&route.RiskObserveScore,
		&rateWindow,
		&rateMax,
		&rateStrategy,
		&route.CreatedAt,
		&route.UpdatedAt,
	)
	if err != nil {
		return types.RoutePolicy{}, err
	}
	route.ChallengeType = types.CaptchaType(captchaType)
	route.RiskChallengeType = types.CaptchaType(riskCaptchaType)
	route.ChallengeEscalation = challengepkg.ParseEscalationCSV(challengeEscalation)
	route.RolloutPercent = routepolicy.NormalizeRolloutPercent(route.RolloutPercent)
	if rateWindow.Valid && rateMax.Valid {
		route.RateLimit = &types.RateLimit{WindowSeconds: int(rateWindow.Int64), MaxRequests: int(rateMax.Int64), Strategy: normalizeRateStrategy(rateStrategy)}
	}
	return route, nil
}

func normalizeRateStrategy(strategy string) string {
	switch strings.ToLower(strings.TrimSpace(strategy)) {
	case "sliding_window":
		return "sliding_window"
	case "token_bucket":
		return "token_bucket"
	default:
		return "fixed_window"
	}
}

func scanIPPolicy(row scanner) (types.IPPolicy, error) {
	var policy types.IPPolicy
	var action string
	err := row.Scan(
		&policy.ID,
		&policy.ClientID,
		&policy.Type,
		&policy.CIDR,
		&action,
		&policy.Reason,
		&policy.Enabled,
		&policy.CreatedAt,
		&policy.UpdatedAt,
	)
	if err != nil {
		return types.IPPolicy{}, err
	}
	policy.Action = types.Decision(action)
	return policy, nil
}

func scanResource(row scanner) (types.CaptchaResource, error) {
	var resource types.CaptchaResource
	var captchaType string
	var checksum sql.NullString
	var metadata []byte
	err := row.Scan(
		&resource.ID,
		&resource.ClientID,
		&resource.Scene,
		&captchaType,
		&resource.ResourceType,
		&resource.StorageType,
		&resource.URI,
		&resource.Tag,
		&resource.Status,
		&checksum,
		&metadata,
		&resource.CreatedAt,
		&resource.UpdatedAt,
	)
	if err != nil {
		return types.CaptchaResource{}, err
	}
	resource.CaptchaType = types.CaptchaType(captchaType)
	if checksum.Valid {
		resource.Checksum = checksum.String
	}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &resource.Metadata); err != nil {
			return types.CaptchaResource{}, err
		}
	}
	return resource, nil
}

func scanAuditEvent(row scanner) (types.AuditEvent, error) {
	var event types.AuditEvent
	var action string
	var scene sql.NullString
	var route sql.NullString
	var ipHash sql.NullString
	var accountIDHash sql.NullString
	var deviceIDHash sql.NullString
	var captchaType sql.NullString
	err := row.Scan(
		&event.ID,
		&event.ClientID,
		&scene,
		&route,
		&ipHash,
		&accountIDHash,
		&deviceIDHash,
		&action,
		&event.DecisionReason,
		&captchaType,
		&event.Result,
		&event.CreatedAt,
	)
	if err != nil {
		return types.AuditEvent{}, err
	}
	event.Scene = scene.String
	event.Route = route.String
	event.IPHash = ipHash.String
	event.AccountIDHash = accountIDHash.String
	event.DeviceIDHash = deviceIDHash.String
	event.Action = types.Decision(action)
	event.ChallengeType = types.CaptchaType(captchaType.String)
	return event, nil
}

func scanRiskFeatureSnapshot(row scanner) (types.RiskFeatureSnapshot, error) {
	var snapshot types.RiskFeatureSnapshot
	var attemptID sql.NullString
	var scene sql.NullString
	var challengeType sql.NullString
	var labelSource sql.NullString
	var features []byte
	err := row.Scan(
		&snapshot.ID,
		&attemptID,
		&snapshot.ClientID,
		&scene,
		&challengeType,
		&snapshot.FeatureVersion,
		&snapshot.FeaturesDigest,
		&snapshot.FeaturesRef,
		&features,
		&snapshot.Label,
		&labelSource,
		&snapshot.ModelTrainable,
		&snapshot.CreatedAt,
	)
	if err != nil {
		return types.RiskFeatureSnapshot{}, err
	}
	snapshot.AttemptID = attemptID.String
	snapshot.Scene = scene.String
	snapshot.ChallengeType = types.CaptchaType(challengeType.String)
	snapshot.LabelSource = labelSource.String
	if len(features) > 0 {
		_ = json.Unmarshal(features, &snapshot.Features)
	}
	if snapshot.Features == nil {
		snapshot.Features = map[string]any{}
	}
	return snapshot, nil
}

func scanRiskModelVersion(row scanner) (types.RiskModelVersion, error) {
	var version types.RiskModelVersion
	var metrics []byte
	var activatedAt sql.NullTime
	err := row.Scan(
		&version.ID,
		&version.Name,
		&version.Version,
		&version.FeatureVersion,
		&version.TrainingWindow,
		&version.ArtifactURI,
		&metrics,
		&version.Mode,
		&version.Status,
		&version.CreatedAt,
		&activatedAt,
	)
	if err != nil {
		return types.RiskModelVersion{}, err
	}
	if len(metrics) > 0 {
		if err := json.Unmarshal(metrics, &version.Metrics); err != nil {
			return types.RiskModelVersion{}, err
		}
	}
	if version.Metrics == nil {
		version.Metrics = map[string]any{}
	}
	if activatedAt.Valid {
		version.ActivatedAt = &activatedAt.Time
	}
	return version, nil
}

var _ ControlStore = (*PostgresControlStore)(nil)
var _ AuditStore = (*PostgresControlStore)(nil)
var _ FeatureStore = (*PostgresControlStore)(nil)

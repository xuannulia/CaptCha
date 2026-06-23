CREATE TABLE IF NOT EXISTS applications (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  secret_hash TEXT,
  status TEXT NOT NULL,
  default_fail_policy TEXT NOT NULL DEFAULT 'fail_open',
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS route_policies (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES applications(client_id),
  name TEXT NOT NULL,
  path_pattern TEXT NOT NULL,
  method TEXT NOT NULL,
  scene TEXT NOT NULL,
  mode TEXT NOT NULL,
  challenge_type TEXT NOT NULL,
  risk_challenge_type TEXT NOT NULL DEFAULT '',
  challenge_escalation TEXT NOT NULL DEFAULT '',
  fail_policy TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  rollout_percent INTEGER NOT NULL DEFAULT 100,
  token_ttl_seconds INTEGER NOT NULL DEFAULT 120,
  risk_challenge_score INTEGER NOT NULL DEFAULT 0,
  risk_block_score INTEGER NOT NULL DEFAULT 0,
  risk_observe_score INTEGER NOT NULL DEFAULT 0,
  rate_window_seconds INTEGER,
  rate_max_requests INTEGER,
  rate_strategy TEXT NOT NULL DEFAULT 'fixed_window',
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_route_policies_client_priority
  ON route_policies (client_id, enabled, priority DESC);

CREATE TABLE IF NOT EXISTS ip_policies (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES applications(client_id),
  type TEXT NOT NULL,
  cidr TEXT NOT NULL,
  action TEXT NOT NULL,
  reason TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ip_policies_client_enabled
  ON ip_policies (client_id, enabled);

CREATE TABLE IF NOT EXISTS captcha_resources (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES applications(client_id),
  scene TEXT NOT NULL DEFAULT '',
  captcha_type TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  storage_type TEXT NOT NULL,
  uri TEXT NOT NULL,
  tag TEXT NOT NULL,
  status TEXT NOT NULL,
  checksum TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_captcha_resources_lookup
  ON captcha_resources (client_id, scene, captcha_type, resource_type, status);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  scene TEXT,
  route TEXT,
  ip_hash TEXT,
  account_id_hash TEXT,
  device_id_hash TEXT,
  action TEXT NOT NULL,
  decision_reason TEXT NOT NULL,
  challenge_type TEXT,
  result TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_client_created
  ON audit_events (client_id, created_at DESC);

CREATE TABLE IF NOT EXISTS risk_feature_snapshots (
  id TEXT PRIMARY KEY,
  attempt_id TEXT,
  client_id TEXT NOT NULL,
  scene TEXT,
  challenge_type TEXT,
  feature_version TEXT NOT NULL,
  features_digest TEXT NOT NULL,
  features_ref TEXT NOT NULL,
  features JSONB NOT NULL DEFAULT '{}'::jsonb,
  label TEXT NOT NULL DEFAULT 'unknown',
  label_source TEXT,
  model_trainable BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_risk_feature_snapshots_trainable
  ON risk_feature_snapshots (client_id, model_trainable, created_at DESC);

CREATE TABLE IF NOT EXISTS risk_model_versions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  feature_version TEXT NOT NULL,
  training_window TEXT NOT NULL,
  artifact_uri TEXT NOT NULL,
  metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
  mode TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  activated_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_risk_model_versions_name_version
  ON risk_model_versions (name, version);

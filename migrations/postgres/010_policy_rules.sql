CREATE TABLE IF NOT EXISTS policy_rules (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES applications(client_id),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  priority INTEGER NOT NULL DEFAULT 0,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  status TEXT NOT NULL DEFAULT 'active',
  version TEXT NOT NULL DEFAULT '',
  scope JSONB NOT NULL DEFAULT '{}'::jsonb,
  conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
  aggregation JSONB NOT NULL DEFAULT '{}'::jsonb,
  action JSONB NOT NULL DEFAULT '{}'::jsonb,
  rollout_percent INTEGER NOT NULL DEFAULT 100,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_policy_rules_client_priority
  ON policy_rules (client_id, enabled, priority DESC);

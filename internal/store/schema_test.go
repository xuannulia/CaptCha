package store

import (
	"os"
	"strings"
	"testing"
)

func TestPostgresMigrationContainsCoreTables(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../migrations/postgres/001_init.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := string(data)
	required := []string{
		"CREATE TABLE IF NOT EXISTS applications",
		"CREATE TABLE IF NOT EXISTS route_policies",
		"challenge_escalation TEXT NOT NULL DEFAULT ''",
		"CREATE TABLE IF NOT EXISTS ip_policies",
		"CREATE TABLE IF NOT EXISTS captcha_resources",
		"CREATE TABLE IF NOT EXISTS audit_events",
		"CREATE TABLE IF NOT EXISTS risk_feature_snapshots",
		"features JSONB NOT NULL DEFAULT '{}'::jsonb",
		"CREATE TABLE IF NOT EXISTS risk_model_versions",
	}
	for _, fragment := range required {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("migration missing %q", fragment)
		}
	}
}

func TestPostgresPolicyRuleMigrationContainsRuleTable(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../migrations/postgres/010_policy_rules.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := string(data)
	required := []string{
		"CREATE TABLE IF NOT EXISTS policy_rules",
		"scope JSONB NOT NULL DEFAULT '{}'::jsonb",
		"conditions JSONB NOT NULL DEFAULT '{}'::jsonb",
		"aggregation JSONB NOT NULL DEFAULT '{}'::jsonb",
		"action JSONB NOT NULL DEFAULT '{}'::jsonb",
		"idx_policy_rules_client_priority",
	}
	for _, fragment := range required {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("policy rule migration missing %q", fragment)
		}
	}
}

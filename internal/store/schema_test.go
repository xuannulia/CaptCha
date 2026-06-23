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

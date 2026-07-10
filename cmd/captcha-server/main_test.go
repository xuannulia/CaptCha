package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestProductionSecurityErrorsSkippedOutsideProduction(t *testing.T) {
	errors := productionSecurityErrors(mapGetenv(map[string]string{}))
	if len(errors) != 0 {
		t.Fatalf("expected no errors outside production, got %v", errors)
	}
}

func TestProductionSecurityErrorsRequireHardenedSettings(t *testing.T) {
	errors := productionSecurityErrors(mapGetenv(map[string]string{
		"CAPTCHA_ENV": "production",
	}))
	joined := strings.Join(errors, "\n")
	for _, expected := range []string{
		"CAPTCHA_ADMIN_TOKEN",
		"CAPTCHA_GRPC_TOKEN",
		"CAPTCHA_METRICS_TOKEN",
		"CAPTCHA_COLLECTOR_TOKEN",
		"CAPTCHA_POSTGRES_DSN",
		"CAPTCHA_REDIS_ADDR",
		"CAPTCHA_ALLOWED_ORIGINS",
		"CAPTCHA_SEED_DEMO",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected production error for %s, got %v", expected, errors)
		}
	}
}

func TestProductionSecurityErrorsRejectWildcardOriginsAndDemoSeed(t *testing.T) {
	errors := productionSecurityErrors(mapGetenv(map[string]string{
		"CAPTCHA_PRODUCTION":                 "true",
		"CAPTCHA_ADMIN_TOKEN":                "admin-token",
		"CAPTCHA_GRPC_TOKEN":                 "grpc-token",
		"CAPTCHA_METRICS_TOKEN":              "metrics-token",
		"CAPTCHA_COLLECTOR_TOKEN":            "collector-token",
		"CAPTCHA_POSTGRES_DSN":               "postgres://captcha:captcha@postgres:5432/captcha?sslmode=disable",
		"CAPTCHA_REDIS_ADDR":                 "redis:6379",
		"CAPTCHA_ALLOWED_ORIGINS":            "*",
		"CAPTCHA_ALLOWED_RETURN_URL_ORIGINS": "*",
		"CAPTCHA_SEED_DEMO":                  "true",
	}))
	joined := strings.Join(errors, "\n")
	for _, expected := range []string{
		"CAPTCHA_ALLOWED_ORIGINS",
		"CAPTCHA_ALLOWED_RETURN_URL_ORIGINS",
		"CAPTCHA_SEED_DEMO",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected production error for %s, got %v", expected, errors)
		}
	}
}

func TestProductionSecurityErrorsAcceptHardenedSettings(t *testing.T) {
	errors := productionSecurityErrors(mapGetenv(map[string]string{
		"CAPTCHA_ENV":                        "production",
		"CAPTCHA_ADMIN_TOKEN":                "admin-token",
		"CAPTCHA_GRPC_TOKEN":                 "grpc-token",
		"CAPTCHA_METRICS_TOKEN":              "metrics-token",
		"CAPTCHA_COLLECTOR_TOKEN":            "collector-token",
		"CAPTCHA_POSTGRES_DSN":               "postgres://captcha:captcha@postgres:5432/captcha?sslmode=disable",
		"CAPTCHA_REDIS_ADDR":                 "redis:6379",
		"CAPTCHA_ALLOWED_ORIGINS":            "https://app.example.com,https://admin.example.com",
		"CAPTCHA_ALLOWED_RETURN_URL_ORIGINS": "https://app.example.com",
		"CAPTCHA_SEED_DEMO":                  "false",
	}))
	if len(errors) != 0 {
		t.Fatalf("expected hardened production config to pass, got %v", errors)
	}
}

func TestRunHealthcheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"captcha-server", "healthcheck", server.URL}

	if code := runHealthcheck("http://127.0.0.1:8080/healthz"); code != 0 {
		t.Fatalf("expected successful healthcheck, got exit code %d", code)
	}
}

func TestRunHealthcheckFailsOnNonTwoHundred(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"captcha-server", "healthcheck", server.URL}

	if code := runHealthcheck("http://127.0.0.1:8080/healthz"); code == 0 {
		t.Fatal("expected failing healthcheck")
	}
}

func mapGetenv(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

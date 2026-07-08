package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestRunHealthcheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"captcha-gateway", "healthcheck", server.URL}

	if code := runHealthcheck("http://127.0.0.1:8081/healthz"); code != 0 {
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
	os.Args = []string{"captcha-gateway", "healthcheck", server.URL}

	if code := runHealthcheck("http://127.0.0.1:8081/healthz"); code == 0 {
		t.Fatal("expected failing healthcheck")
	}
}

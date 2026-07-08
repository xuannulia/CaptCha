package main

import (
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"captcha/internal/gateway"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck("http://127.0.0.1:8081/healthz"))
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	upstreamURL := os.Getenv("CAPTCHA_UPSTREAM_URL")
	if upstreamURL == "" {
		logger.Error("CAPTCHA_UPSTREAM_URL is required")
		os.Exit(1)
	}

	gatewayServer, err := gateway.New(gateway.Config{
		ClientID:               env("CAPTCHA_CLIENT_ID", "demo"),
		ClientSecret:           os.Getenv("CAPTCHA_CLIENT_SECRET"),
		PlatformURL:            env("CAPTCHA_PLATFORM_URL", "http://localhost:8080"),
		PlatformGRPCAddr:       os.Getenv("CAPTCHA_PLATFORM_GRPC_ADDR"),
		PlatformGRPCToken:      firstEnv("CAPTCHA_PLATFORM_GRPC_TOKEN", "CAPTCHA_GRPC_TOKEN"),
		PolicyTransport:        env("CAPTCHA_GATEWAY_POLICY_TRANSPORT", "http"),
		EnableConfigCache:      boolEnv("CAPTCHA_GATEWAY_CONFIG_CACHE", false),
		TrustedProxyCIDRs:      csvEnv("CAPTCHA_TRUSTED_PROXY_CIDRS"),
		UpstreamURL:            upstreamURL,
		TicketHeader:           env("CAPTCHA_TICKET_HEADER", "X-Captcha-Ticket"),
		ClearanceHeader:        env("CAPTCHA_CLEARANCE_HEADER", "X-Captcha-Clearance"),
		ClearanceCookieName:    env("CAPTCHA_CLEARANCE_COOKIE_NAME", "captcha_clearance"),
		RequestNonceHeader:     env("CAPTCHA_REQUEST_NONCE_HEADER", "X-Captcha-Request-Nonce"),
		ResourceTagHeader:      env("CAPTCHA_RESOURCE_TAG_HEADER", "X-Captcha-Resource-Tag"),
		AccountIDHeader:        env("CAPTCHA_ACCOUNT_ID_HASH_HEADER", "X-Captcha-Account-ID-Hash"),
		DeviceIDHeader:         env("CAPTCHA_DEVICE_ID_HASH_HEADER", "X-Captcha-Device-ID-Hash"),
		RiskScoreHeader:        env("CAPTCHA_RISK_SCORE_HEADER", "X-Captcha-Risk-Score"),
		RiskLevelHeader:        env("CAPTCHA_RISK_LEVEL_HEADER", "X-Captcha-Risk-Level"),
		ModelScoreHeader:       env("CAPTCHA_MODEL_SCORE_HEADER", "X-Captcha-Model-Score"),
		ModelModeHeader:        env("CAPTCHA_MODEL_MODE_HEADER", "X-Captcha-Model-Mode"),
		HeaderAllowlist:        csvEnv("CAPTCHA_GATEWAY_HEADER_ALLOWLIST"),
		FailPolicy:             env("CAPTCHA_GATEWAY_FAIL_POLICY", "fail_open"),
		RequestTimeout:         durationEnv("CAPTCHA_GATEWAY_TIMEOUT", 1500*time.Millisecond),
		CircuitBreakerFailures: intEnv("CAPTCHA_GATEWAY_CIRCUIT_BREAKER_FAILURES", 0),
		CircuitBreakerCooldown: durationEnv("CAPTCHA_GATEWAY_CIRCUIT_BREAKER_COOLDOWN", 0),
		EventBatchSize:         intEnv("CAPTCHA_GATEWAY_EVENT_BATCH_SIZE", 0),
		EventFlushInterval:     durationEnv("CAPTCHA_GATEWAY_EVENT_FLUSH_INTERVAL", 0),
		EventQueueSize:         intEnv("CAPTCHA_GATEWAY_EVENT_QUEUE_SIZE", 0),
	}, logger)
	if err != nil {
		logger.Error("gateway config failed", "error", err)
		os.Exit(1)
	}

	addr := env("CAPTCHA_GATEWAY_ADDR", ":8081")
	logger.Info("starting captcha gateway", "addr", addr, "upstream", upstreamURL)
	if err := http.ListenAndServe(addr, gatewayServer.Handler()); err != nil {
		logger.Error("gateway stopped", "error", err)
		os.Exit(1)
	}
}

func runHealthcheck(defaultURL string) int {
	endpoint := defaultURL
	if len(os.Args) > 2 && strings.TrimSpace(os.Args[2]) != "" {
		endpoint = strings.TrimSpace(os.Args[2])
	}
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get(endpoint)
	if err != nil {
		return 1
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return 1
	}
	return 0
}

func env(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return duration
}

func boolEnv(key string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return fallback
	}
}

func intEnv(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func csvEnv(key string) []string {
	value := os.Getenv(key)
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

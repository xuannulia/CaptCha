package main

import (
	"context"
	"database/sql"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"captcha/internal/api"
	"captcha/internal/configsync"
	"captcha/internal/engine"
	"captcha/internal/grpcserver"
	"captcha/internal/policy"
	"captcha/internal/risk"
	"captcha/internal/store"
	"captcha/internal/token"
	"captcha/internal/types"

	"github.com/redis/go-redis/v9"
)

type controlStore interface {
	store.ControlStore
	store.AuditStore
	store.FeatureStore
}

type transientStore interface {
	store.SessionStore
	store.TicketStore
	store.ClearanceStore
	store.RateStore
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if errors := productionSecurityErrors(os.Getenv); len(errors) > 0 {
		for _, message := range errors {
			logger.Error("production security check failed", "reason", message)
		}
		os.Exit(1)
	}
	appStore := buildStore(logger)
	configNotifier := configsync.NewNotifier()
	sessionTTL := durationSecondsEnv("CAPTCHA_SESSION_TTL_SECONDS", 120*time.Second)
	ticketTTL := durationSecondsEnv("CAPTCHA_TICKET_TTL_SECONDS", 120*time.Second)
	clearanceTTL := durationSecondsEnv("CAPTCHA_CLEARANCE_TTL_SECONDS", 10*time.Minute)
	preGenerateSize := intEnv("CAPTCHA_PREGENERATE_SIZE", 8)
	captchaEngine := engine.NewWithOptions(sessionTTL, engine.Options{PreGenerateSize: preGenerateSize})
	captchaEngine.StartPreGeneration(context.Background())
	policyEvaluator := policy.NewEvaluator(appStore)
	tokenService := token.NewService(appStore, ticketTTL)
	tokenService.SetClearanceTTL(clearanceTTL)
	riskInferencer := risk.NewHTTPInferencer(
		os.Getenv("CAPTCHA_RISK_INFERENCE_URL"),
		os.Getenv("CAPTCHA_RISK_INFERENCE_TOKEN"),
		durationEnv("CAPTCHA_RISK_INFERENCE_TIMEOUT", 500*time.Millisecond),
	)
	server := api.NewServerWithOptions(captchaEngine, policyEvaluator, appStore, tokenService, logger, api.Options{
		RuntimeBaseURL:          os.Getenv("CAPTCHA_RUNTIME_URL"),
		AdminToken:              os.Getenv("CAPTCHA_ADMIN_TOKEN"),
		MetricsToken:            os.Getenv("CAPTCHA_METRICS_TOKEN"),
		AllowedOrigins:          csvEnv("CAPTCHA_ALLOWED_ORIGINS"),
		AllowedReturnURLOrigins: csvEnv("CAPTCHA_ALLOWED_RETURN_URL_ORIGINS"),
		ChallengeEscalation:     captchaTypeCSVEnv("CAPTCHA_CHALLENGE_ESCALATION_SEQUENCE"),
		ConfigNotifier:          configNotifier,
		RiskInferencer:          riskInferencer,
	})
	grpcServer := grpcserver.New(grpcserver.Dependencies{
		Engine:         captchaEngine,
		Policy:         policyEvaluator,
		Store:          appStore,
		Logger:         logger,
		RuntimeBaseURL: os.Getenv("CAPTCHA_RUNTIME_URL"),
		GRPCToken:      os.Getenv("CAPTCHA_GRPC_TOKEN"),
		Tokens:         tokenService,
		RiskInferencer: riskInferencer,
		ConfigNotifier: configNotifier,
	})

	addr := env("CAPTCHA_ADDR", ":8080")
	grpcAddr := env("CAPTCHA_GRPC_ADDR", ":9090")

	listener, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		logger.Error("grpc listen failed", "addr", grpcAddr, "error", err)
		os.Exit(1)
	}
	go func() {
		logger.Info("starting captcha grpc server", "addr", grpcAddr)
		if err := grpcServer.Serve(listener); err != nil {
			logger.Error("grpc server stopped", "error", err)
		}
	}()

	logger.Info("starting captcha server", "addr", addr)
	if err := http.ListenAndServe(addr, server.Handler()); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func env(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func intEnv(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func durationSecondsEnv(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return time.Duration(parsed) * time.Second
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return fallback
	}
	return duration
}

func csvEnv(key string) []string {
	value := os.Getenv(key)
	if value == "" {
		return nil
	}
	return splitCSV(value)
}

func splitCSV(value string) []string {
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

func productionSecurityErrors(getenv func(string) string) []string {
	if !productionMode(getenv) {
		return nil
	}

	checks := []struct {
		key     string
		message string
	}{
		{"CAPTCHA_ADMIN_TOKEN", "CAPTCHA_ADMIN_TOKEN must be set in production"},
		{"CAPTCHA_GRPC_TOKEN", "CAPTCHA_GRPC_TOKEN must be set in production"},
		{"CAPTCHA_METRICS_TOKEN", "CAPTCHA_METRICS_TOKEN must be set in production"},
		{"CAPTCHA_POSTGRES_DSN", "CAPTCHA_POSTGRES_DSN must be set in production"},
		{"CAPTCHA_REDIS_ADDR", "CAPTCHA_REDIS_ADDR must be set in production"},
	}
	errors := make([]string, 0, len(checks)+3)
	for _, check := range checks {
		if strings.TrimSpace(getenv(check.key)) == "" {
			errors = append(errors, check.message)
		}
	}

	origins := splitCSV(getenv("CAPTCHA_ALLOWED_ORIGINS"))
	if len(origins) == 0 {
		errors = append(errors, "CAPTCHA_ALLOWED_ORIGINS must be set in production")
	} else if containsWildcardOrigin(origins) {
		errors = append(errors, "CAPTCHA_ALLOWED_ORIGINS must not contain wildcard origins in production")
	}

	returnOrigins := splitCSV(getenv("CAPTCHA_ALLOWED_RETURN_URL_ORIGINS"))
	if len(returnOrigins) == 0 {
		returnOrigins = origins
	}
	if len(returnOrigins) == 0 {
		errors = append(errors, "CAPTCHA_ALLOWED_RETURN_URL_ORIGINS or CAPTCHA_ALLOWED_ORIGINS must be set in production")
	} else if containsWildcardOrigin(returnOrigins) {
		errors = append(errors, "CAPTCHA_ALLOWED_RETURN_URL_ORIGINS must not contain wildcard origins in production")
	}

	if !isDisabled(envFrom(getenv, "CAPTCHA_SEED_DEMO", "true")) {
		errors = append(errors, "CAPTCHA_SEED_DEMO must be disabled in production")
	}
	return errors
}

func productionMode(getenv func(string) string) bool {
	if isTruthy(getenv("CAPTCHA_PRODUCTION")) {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(getenv("CAPTCHA_ENV")), "production")
}

func isTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func containsWildcardOrigin(origins []string) bool {
	for _, origin := range origins {
		origin = strings.TrimSpace(origin)
		if origin == "*" {
			return true
		}
	}
	return false
}

func envFrom(getenv func(string) string, key, fallback string) string {
	value := getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func captchaTypeCSVEnv(key string) []types.CaptchaType {
	values := csvEnv(key)
	if len(values) == 0 {
		return nil
	}
	out := make([]types.CaptchaType, 0, len(values))
	for _, value := range values {
		out = append(out, types.CaptchaType(value))
	}
	return out
}

func buildStore(logger *slog.Logger) store.Store {
	control := buildControlStore(logger)
	transient := buildTransientStore(logger)
	if transient == nil {
		if fullStore, ok := control.(store.Store); ok {
			return fullStore
		}
		logger.Info("using memory transient store")
		transient = store.NewMemoryStore()
	}
	return store.NewHybridStore(transient, control)
}

func buildControlStore(logger *slog.Logger) controlStore {
	postgresDSN := os.Getenv("CAPTCHA_POSTGRES_DSN")
	if postgresDSN == "" {
		logger.Info("using memory control store")
		return store.NewMemoryStore()
	}

	db, err := sql.Open("pgx", postgresDSN)
	if err != nil {
		logger.Error("postgres open failed", "error", err)
		os.Exit(1)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		logger.Error("postgres ping failed", "error", err)
		os.Exit(1)
	}

	migrationDir := env("CAPTCHA_POSTGRES_MIGRATIONS", "./migrations/postgres")
	if !isDisabled(migrationDir) {
		if err := store.ApplyPostgresMigrations(ctx, db, migrationDir); err != nil {
			logger.Error("postgres migrations failed", "dir", migrationDir, "error", err)
			os.Exit(1)
		}
	}

	postgresStore := store.NewPostgresControlStore(db, logger)
	if !isDisabled(env("CAPTCHA_SEED_DEMO", "true")) {
		if err := postgresStore.SeedDemoData(ctx); err != nil {
			logger.Error("postgres seed failed", "error", err)
			os.Exit(1)
		}
	}

	logger.Info("using postgres control store")
	return postgresStore
}

func buildTransientStore(logger *slog.Logger) transientStore {
	redisAddr := os.Getenv("CAPTCHA_REDIS_ADDR")
	if redisAddr == "" {
		return nil
	}

	client := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: os.Getenv("CAPTCHA_REDIS_PASSWORD"),
		DB:       0,
	})
	if err := client.Ping(context.Background()).Err(); err != nil {
		logger.Error("redis ping failed", "addr", redisAddr, "error", err)
		os.Exit(1)
	}

	prefix := env("CAPTCHA_REDIS_PREFIX", "captcha:")
	logger.Info("using redis transient store", "addr", redisAddr, "prefix", prefix)
	return store.NewRedisTransientStore(client, prefix)
}

func isDisabled(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "0", "false", "off", "no", "none", "skip", "disabled":
		return true
	default:
		return false
	}
}

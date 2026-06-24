package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	challengepkg "captcha/internal/challenge"
	"captcha/internal/engine"
	"captcha/internal/policy"
	riskpkg "captcha/internal/risk"
	clientsecret "captcha/internal/secret"
	"captcha/internal/store"
	"captcha/internal/token"
	"captcha/internal/types"
)

func TestAdminListsAndPolicyEvaluate(t *testing.T) {
	t.Parallel()

	server, memoryStore, tokens := testServer()
	demoSecret := ""
	integrationHeaders := func() map[string]string {
		if demoSecret == "" {
			return nil
		}
		return map[string]string{"X-Captcha-Client-Secret": demoSecret}
	}

	t.Run("admin lists route policies", func(t *testing.T) {
		response := request(t, server, http.MethodGet, "/api/v1/admin/route-policies", nil)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		var body struct {
			Items []types.RoutePolicy `json:"items"`
		}
		decode(t, response, &body)
		if len(body.Items) == 0 {
			t.Fatal("expected seeded route policies")
		}
	})

	t.Run("admin upserts application", func(t *testing.T) {
		response := request(t, server, http.MethodPost, "/api/v1/admin/applications", types.Application{
			ClientID:          "new-client",
			Name:              "new app",
			Status:            "active",
			DefaultFailPolicy: "fail_open",
		})
		var application types.Application
		decode(t, response, &application)
		if application.ID == "" || application.ClientID != "new-client" || application.Name != "new app" {
			t.Fatalf("unexpected application: %+v", application)
		}
		if application.HasSecret {
			t.Fatalf("new application should report no secret, got %+v", application)
		}

		response = request(t, server, http.MethodGet, "/api/v1/admin/applications", nil)
		var body struct {
			Items []types.Application `json:"items"`
		}
		decode(t, response, &body)
		found := false
		for _, item := range body.Items {
			if item.ClientID == "new-client" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("new application not listed: %+v", body.Items)
		}
	})

	t.Run("admin rotates application secret once", func(t *testing.T) {
		response := request(t, server, http.MethodPost, "/api/v1/admin/applications/demo/secret", nil)
		var body struct {
			ClientSecret string            `json:"client_secret"`
			Application  types.Application `json:"application"`
		}
		decode(t, response, &body)
		if body.ClientSecret == "" || body.Application.ClientID != "demo" {
			t.Fatalf("unexpected secret rotation response: %+v", body)
		}
		if !body.Application.HasSecret {
			t.Fatalf("rotated application should report has_secret, got %+v", body.Application)
		}
		demoSecret = body.ClientSecret
		if strings.Contains(response.Body.String(), "secret_hash") {
			t.Fatalf("secret hash leaked in response: %s", response.Body.String())
		}
		found := false
		for _, application := range memoryStore.ListApplications() {
			if application.ClientID != "demo" {
				continue
			}
			found = true
			if application.SecretHash == "" {
				t.Fatal("expected stored secret hash")
			}
		}
		if !found {
			t.Fatal("demo application not found")
		}

		response = request(t, server, http.MethodGet, "/api/v1/admin/applications", nil)
		var listBody struct {
			Items []types.Application `json:"items"`
		}
		decode(t, response, &listBody)
		found = false
		for _, application := range listBody.Items {
			if application.ClientID != "demo" {
				continue
			}
			found = true
			if !application.HasSecret {
				t.Fatalf("listed application should expose has_secret only, got %+v", application)
			}
		}
		if !found {
			t.Fatal("demo application not listed")
		}
	})

	t.Run("blocklisted ip is blocked", func(t *testing.T) {
		response := requestWithHeaders(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
			ClientID: "demo",
			Path:     "/api/login",
			Method:   "POST",
			IP:       "203.0.113.9",
		}, integrationHeaders())
		var decision types.PolicyDecision
		decode(t, response, &decision)
		if decision.Action != types.DecisionBlock {
			t.Fatalf("expected block, got %+v", decision)
		}
	})

	t.Run("always route creates challenge", func(t *testing.T) {
		response := requestWithHeaders(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
			ClientID: "demo",
			Path:     "/api/register",
			Method:   "POST",
			IP:       "198.51.100.10",
		}, integrationHeaders())
		var decision types.PolicyDecision
		decode(t, response, &decision)
		if decision.Action != types.DecisionChallenge {
			t.Fatalf("expected challenge, got %+v", decision)
		}
		if decision.SessionID == "" || decision.ChallengeType != types.CaptchaWordImageClick {
			t.Fatalf("unexpected challenge decision: %+v", decision)
		}
		challengeURL, err := url.Parse(decision.ChallengeURL)
		if err != nil {
			t.Fatalf("parse challenge url: %v", err)
		}
		if challengeURL.Query().Get("route") != "/api/register" {
			t.Fatalf("expected challenge route, got %q in %q", challengeURL.Query().Get("route"), decision.ChallengeURL)
		}
	})

	t.Run("policy challenge binds ticket to ip and user agent", func(t *testing.T) {
		response := requestWithHeaders(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
			ClientID:  "demo",
			Path:      "/api/register",
			Method:    "POST",
			IP:        "198.51.100.77",
			UserAgent: "Mozilla/5.0 policy-test",
		}, integrationHeaders())
		var decision types.PolicyDecision
		decode(t, response, &decision)
		if decision.Action != types.DecisionChallenge || decision.SessionID == "" {
			t.Fatalf("expected challenge, got %+v", decision)
		}
		session, err := memoryStore.GetSession(decision.SessionID)
		if err != nil {
			t.Fatalf("get policy session: %v", err)
		}
		if session.IPHash != hashValue("198.51.100.77") || session.UserAgentHash != hashValue("Mozilla/5.0 policy-test") {
			t.Fatalf("expected session to bind ip and ua hashes, got %+v", session)
		}

		response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+decision.SessionID+"/verify", map[string]any{
			"answer": answerForSession(session),
			"track":  trackForX(180),
			"route":  "/api/register",
		})
		var verified struct {
			OK     bool   `json:"ok"`
			Ticket string `json:"ticket"`
		}
		decode(t, response, &verified)
		if !verified.OK || verified.Ticket == "" {
			t.Fatalf("expected policy session verification to pass, got %+v", verified)
		}

		response = requestWithHeaders(t, server, http.MethodPost, "/api/v1/tickets/verify", map[string]any{
			"ticket":    verified.Ticket,
			"client_id": "demo",
			"scene":     "register",
			"route":     "/api/register",
		}, integrationHeaders())
		var missingContext struct {
			Valid  bool   `json:"valid"`
			Reason string `json:"reason"`
		}
		decode(t, response, &missingContext)
		if missingContext.Valid || missingContext.Reason != "NOT_FOUND" {
			t.Fatalf("expected missing ip/ua context to reject ticket, got %+v", missingContext)
		}

		response = requestWithHeaders(t, server, http.MethodPost, "/api/v1/tickets/verify", map[string]any{
			"ticket":          verified.Ticket,
			"client_id":       "demo",
			"scene":           "register",
			"route":           "/api/register",
			"ip_hash":         hashValue("198.51.100.77"),
			"user_agent_hash": hashValue("Mozilla/5.0 policy-test"),
		}, integrationHeaders())
		var ticketCheck struct {
			Valid         bool   `json:"valid"`
			IPHash        string `json:"ip_hash"`
			UserAgentHash string `json:"user_agent_hash"`
		}
		decode(t, response, &ticketCheck)
		if !ticketCheck.Valid || ticketCheck.IPHash != hashValue("198.51.100.77") || ticketCheck.UserAgentHash != hashValue("Mozilla/5.0 policy-test") {
			t.Fatalf("expected context-bound ticket to verify, got %+v", ticketCheck)
		}
	})

	t.Run("created session carries route into ticket", func(t *testing.T) {
		response := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
			"client_id":    "demo",
			"scene":        "login",
			"captcha_type": "SLIDER",
			"route":        "/api/login",
			"return_url":   "https://app.example.test/login/complete",
		})
		var created struct {
			SessionID    string `json:"session_id"`
			ChallengeURL string `json:"challenge_url"`
			Route        string `json:"route"`
			ReturnURL    string `json:"return_url"`
		}
		decode(t, response, &created)
		challengeURL, err := url.Parse(created.ChallengeURL)
		if err != nil {
			t.Fatalf("parse created challenge url: %v", err)
		}
		if challengeURL.Query().Get("route") != "/api/login" {
			t.Fatalf("expected created challenge route, got %q in %q", challengeURL.Query().Get("route"), created.ChallengeURL)
		}
		if created.Route != "/api/login" {
			t.Fatalf("expected created route, got %+v", created)
		}
		if challengeURL.Query().Get("return_url") != "https://app.example.test/login/complete" || created.ReturnURL != "https://app.example.test/login/complete" {
			t.Fatalf("expected created challenge return_url, got response=%q url=%q", created.ReturnURL, created.ChallengeURL)
		}

		session, err := memoryStore.GetSession(created.SessionID)
		if err != nil {
			t.Fatalf("get session: %v", err)
		}
		if session.ReturnURL != "https://app.example.test/login/complete" {
			t.Fatalf("expected stored return_url, got %+v", session)
		}
		if session.Route != "/api/login" {
			t.Fatalf("expected stored route, got %+v", session)
		}
		response = request(t, server, http.MethodGet, "/api/v1/challenge/sessions/"+created.SessionID, nil)
		var loaded struct {
			Route     string `json:"route"`
			ReturnURL string `json:"return_url"`
		}
		decode(t, response, &loaded)
		if loaded.Route != "/api/login" || loaded.ReturnURL != "https://app.example.test/login/complete" {
			t.Fatalf("expected loaded return_url, got %+v", loaded)
		}

		response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/refresh", nil)
		var refreshed struct {
			Route     string `json:"route"`
			ReturnURL string `json:"return_url"`
		}
		decode(t, response, &refreshed)
		if refreshed.Route != "/api/login" || refreshed.ReturnURL != "https://app.example.test/login/complete" {
			t.Fatalf("expected refreshed return_url, got %+v", refreshed)
		}
		session, err = memoryStore.GetSession(created.SessionID)
		if err != nil {
			t.Fatalf("get refreshed session: %v", err)
		}
		response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
			"answer": answerForSession(session),
			"track": []types.TrackPoint{
				{X: 0, Y: 20, T: 0, Type: "start"},
				{X: float64(session.Answer.X / 3), Y: 24, T: 160, Type: "move"},
				{X: float64(session.Answer.X * 2 / 3), Y: 21, T: 310, Type: "move"},
				{X: float64(session.Answer.X), Y: 23, T: 480, Type: "end"},
			},
		})
		var verified struct {
			OK        bool   `json:"ok"`
			Ticket    string `json:"ticket"`
			Route     string `json:"route"`
			ReturnURL string `json:"return_url"`
		}
		decode(t, response, &verified)
		if !verified.OK || verified.Ticket == "" || verified.Route != "/api/login" || verified.ReturnURL != "https://app.example.test/login/complete" {
			t.Fatalf("expected verified session with ticket, got %+v", verified)
		}

		response = requestWithHeaders(t, server, http.MethodPost, "/api/v1/tickets/verify", map[string]any{
			"ticket":    verified.Ticket,
			"client_id": "demo",
			"scene":     "login",
			"route":     "/api/login",
		}, integrationHeaders())
		var ticketCheck struct {
			Valid bool `json:"valid"`
		}
		decode(t, response, &ticketCheck)
		if !ticketCheck.Valid {
			t.Fatalf("expected ticket to be valid for original route, got %+v", ticketCheck)
		}

		response = requestWithHeaders(t, server, http.MethodPost, "/api/v1/tickets/verify", map[string]any{
			"ticket":    verified.Ticket,
			"client_id": "demo",
			"scene":     "login",
		}, integrationHeaders())
		var missingRoute struct {
			Valid  bool   `json:"valid"`
			Reason string `json:"reason"`
		}
		decode(t, response, &missingRoute)
		if missingRoute.Valid || missingRoute.Reason != "NOT_FOUND" {
			t.Fatalf("expected missing route to reject route-bound ticket, got %+v", missingRoute)
		}

		response = requestWithHeaders(t, server, http.MethodPost, "/api/v1/tickets/verify", map[string]any{
			"ticket":    verified.Ticket,
			"client_id": "demo",
			"scene":     "login",
			"route":     "/api/other",
		}, integrationHeaders())
		var mismatch struct {
			Valid  bool   `json:"valid"`
			Reason string `json:"reason"`
		}
		decode(t, response, &mismatch)
		if mismatch.Valid || mismatch.Reason != "NOT_FOUND" {
			t.Fatalf("expected route-bound ticket mismatch, got %+v", mismatch)
		}

		response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
			"client_id":    "demo",
			"scene":        "login",
			"captcha_type": "SLIDER",
			"route":        "/api/login",
		})
		var mismatchCreated struct {
			SessionID string `json:"session_id"`
		}
		decode(t, response, &mismatchCreated)
		mismatchSession, err := memoryStore.GetSession(mismatchCreated.SessionID)
		if err != nil {
			t.Fatalf("get mismatch session: %v", err)
		}
		response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+mismatchCreated.SessionID+"/verify", map[string]any{
			"answer": answerForSession(mismatchSession),
			"track":  trackForX(mismatchSession.Answer.X),
			"route":  "/api/other",
		})
		var routeMismatch struct {
			OK         bool   `json:"ok"`
			ReasonCode string `json:"reason_code"`
		}
		decode(t, response, &routeMismatch)
		if routeMismatch.OK || routeMismatch.ReasonCode != "ROUTE_MISMATCH" {
			t.Fatalf("expected route mismatch verification rejection, got %+v", routeMismatch)
		}
	})

	t.Run("challenge payload includes selected active resources", func(t *testing.T) {
		memoryStore.UpsertResource(types.CaptchaResource{
			ID:           "res_test_slider_background",
			ClientID:     "demo",
			Scene:        "login",
			CaptchaType:  types.CaptchaSlider,
			ResourceType: "background_image",
			StorageType:  "url",
			URI:          "https://cdn.example.test/slider-background.png",
			Tag:          "campaign",
			Status:       "active",
		})
		memoryStore.UpsertResource(types.CaptchaResource{
			ID:           "res_test_disabled_background",
			ClientID:     "demo",
			Scene:        "login",
			CaptchaType:  types.CaptchaSlider,
			ResourceType: "background_image",
			StorageType:  "url",
			URI:          "https://cdn.example.test/disabled.png",
			Tag:          "campaign",
			Status:       "disabled",
		})
		memoryStore.UpsertResource(types.CaptchaResource{
			ID:           "res_test_other_scene_background",
			ClientID:     "demo",
			Scene:        "register",
			CaptchaType:  types.CaptchaSlider,
			ResourceType: "background_image",
			StorageType:  "url",
			URI:          "https://cdn.example.test/register-background.png",
			Tag:          "campaign",
			Status:       "active",
		})
		response := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
			"client_id":     "demo",
			"scene":         "login",
			"captcha_type":  "SLIDER",
			"resource_tag":  "campaign",
			"request_nonce": "resource-nonce",
		})
		var created struct {
			SessionID    string `json:"session_id"`
			ChallengeURL string `json:"challenge_url"`
		}
		decode(t, response, &created)
		challengeURL, err := url.Parse(created.ChallengeURL)
		if err != nil {
			t.Fatalf("parse challenge url: %v", err)
		}
		if challengeURL.Query().Get("resource_tag") != "campaign" {
			t.Fatalf("expected challenge resource tag, got %q in %q", challengeURL.Query().Get("resource_tag"), created.ChallengeURL)
		}

		response = request(t, server, http.MethodGet, "/api/v1/challenge/sessions/"+created.SessionID, nil)
		var loaded struct {
			Challenge types.RenderPayload `json:"challenge"`
		}
		decode(t, response, &loaded)
		resources, ok := loaded.Challenge.Parameters["resources"].([]any)
		if !ok || len(resources) == 0 {
			t.Fatalf("expected selected resources in challenge parameters, got %+v", loaded.Challenge.Parameters)
		}
		if !hasRenderResource(resources, "background_image", "res_test_slider_background") {
			t.Fatalf("expected active exact background resource, got %+v", resources)
		}
		if hasRenderResource(resources, "background_image", "res_test_disabled_background") {
			t.Fatalf("disabled resource should not be selected: %+v", resources)
		}
		if hasRenderResource(resources, "background_image", "res_test_other_scene_background") {
			t.Fatalf("other scene resource should not be selected: %+v", resources)
		}
		if !hasRenderResource(resources, "slider_template", "res_slider") {
			t.Fatalf("expected seeded slider template resource, got %+v", resources)
		}
	})

	t.Run("local file background is composed into challenge image", func(t *testing.T) {
		background := color.RGBA{R: 15, G: 170, B: 92, A: 255}
		backgroundPath := writeAPITestPNG(t, background)
		memoryStore.UpsertResource(types.CaptchaResource{
			ID:           "res_test_file_background",
			ClientID:     "demo",
			Scene:        "login",
			CaptchaType:  types.CaptchaSlider,
			ResourceType: "background_image",
			StorageType:  "file",
			URI:          backgroundPath,
			Tag:          "local-file",
			Status:       "active",
		})
		response := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
			"client_id":    "demo",
			"scene":        "login",
			"captcha_type": "SLIDER",
			"resource_tag": "local-file",
		})
		var created struct {
			SessionID string `json:"session_id"`
		}
		decode(t, response, &created)

		response = request(t, server, http.MethodGet, "/api/v1/challenge/sessions/"+created.SessionID, nil)
		var loaded struct {
			Challenge types.RenderPayload `json:"challenge"`
		}
		decode(t, response, &loaded)
		img := decodeAPITestPNGDataURL(t, loaded.Challenge.Image)
		assertAPITestPixel(t, img, 5, 5, background)
	})

	t.Run("admin validates resource metadata and rejects unsafe uri", func(t *testing.T) {
		response := request(t, server, http.MethodPost, "/api/v1/admin/resources", types.CaptchaResource{
			ClientID:     "demo",
			Scene:        "login",
			CaptchaType:  types.CaptchaSlider,
			ResourceType: "background_image",
			StorageType:  "url",
			URI:          "https://cdn.example.test/login-safe.png",
			Tag:          "campaign",
			Checksum:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Metadata: map[string]any{
				"width":     320,
				"height":    160,
				"mime_type": "image/png",
			},
			Status: "active",
		})
		var saved types.CaptchaResource
		decode(t, response, &saved)
		if saved.Checksum != "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
			t.Fatalf("expected normalized checksum, got %+v", saved)
		}
		if saved.Metadata["uri_scheme"] != "https" || saved.Metadata["resource_family"] != "image" {
			t.Fatalf("expected normalized metadata, got %+v", saved.Metadata)
		}

		rejected := request(t, server, http.MethodPost, "/api/v1/admin/resources", types.CaptchaResource{
			ClientID:     "demo",
			CaptchaType:  types.CaptchaSlider,
			ResourceType: "background_image",
			StorageType:  "url",
			URI:          "http://127.0.0.1/private.png",
			Status:       "active",
		})
		if rejected.Code != http.StatusBadRequest {
			t.Fatalf("expected unsafe resource uri rejection, got %d %s", rejected.Code, rejected.Body.String())
		}
	})

	t.Run("direct auto session uses resource-aware captcha type", func(t *testing.T) {
		memoryStore.UpsertApplication(types.Application{
			ID:                "app_direct_auto",
			ClientID:          "direct-auto",
			Name:              "direct auto",
			Status:            "active",
			DefaultFailPolicy: "fail_open",
		})
		memoryStore.UpsertResource(types.CaptchaResource{
			ID:           "res_direct_auto_background",
			ClientID:     "direct-auto",
			CaptchaType:  types.CaptchaAuto,
			ResourceType: "background_image",
			StorageType:  "url",
			URI:          "https://cdn.example.test/direct-background.png",
			Status:       "active",
		})
		memoryStore.UpsertResource(types.CaptchaResource{
			ID:           "res_direct_auto_rotate",
			ClientID:     "direct-auto",
			CaptchaType:  types.CaptchaRotate,
			ResourceType: "rotate_library",
			StorageType:  "url",
			URI:          "https://cdn.example.test/direct-rotate.png",
			Status:       "active",
		})

		response := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
			"client_id":     "direct-auto",
			"scene":         "login",
			"captcha_type":  "AUTO",
			"resource_tag":  "default",
			"request_nonce": "direct-auto-nonce",
		})
		var created struct {
			SessionID   string            `json:"session_id"`
			CaptchaType types.CaptchaType `json:"captcha_type"`
		}
		decode(t, response, &created)
		if created.CaptchaType != types.CaptchaRotate {
			t.Fatalf("expected AUTO direct session to choose rotate, got %+v", created)
		}
		session, err := memoryStore.GetSession(created.SessionID)
		if err != nil {
			t.Fatalf("get direct auto session: %v", err)
		}
		if session.Type != types.CaptchaRotate {
			t.Fatalf("expected stored session type rotate, got %+v", session)
		}
	})

	t.Run("admin manages risk model versions with activation and rollback", func(t *testing.T) {
		response := request(t, server, http.MethodPost, "/api/v1/admin/risk-model-versions", types.RiskModelVersion{
			ID:             "model_api_v1",
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
		var v1 types.RiskModelVersion
		decode(t, response, &v1)
		if v1.Status != "candidate" || v1.Metrics["auc"] == nil {
			t.Fatalf("unexpected model v1: %+v", v1)
		}

		rejected := request(t, server, http.MethodPost, "/api/v1/admin/risk-model-versions", types.RiskModelVersion{
			Name:           "track-baseline",
			Version:        "bad-active",
			FeatureVersion: "track-v1",
			TrainingWindow: "2026-06-01/2026-06-10",
			ArtifactURI:    "s3://models/track/bad.json",
			Status:         "active",
		})
		if rejected.Code != http.StatusBadRequest {
			t.Fatalf("expected direct active model rejection, got %d %s", rejected.Code, rejected.Body.String())
		}

		response = request(t, server, http.MethodPost, "/api/v1/admin/risk-model-versions/"+v1.ID+"/activate", nil)
		var active types.RiskModelVersion
		decode(t, response, &active)
		if active.ID != v1.ID || active.Status != "active" || active.ActivatedAt == nil {
			t.Fatalf("expected active v1, got %+v", active)
		}

		response = request(t, server, http.MethodPost, "/api/v1/admin/risk-model-versions", types.RiskModelVersion{
			ID:             "model_api_v2",
			Name:           "track-baseline",
			Version:        "v2",
			FeatureVersion: "track-v1",
			TrainingWindow: "2026-06-11/2026-06-20",
			ArtifactURI:    "s3://models/track/v2.json",
			Mode:           "observe",
		})
		var v2 types.RiskModelVersion
		decode(t, response, &v2)
		response = request(t, server, http.MethodPost, "/api/v1/admin/risk-model-versions/"+v2.ID+"/activate", nil)
		decode(t, response, &active)
		if active.ID != v2.ID || active.Status != "active" {
			t.Fatalf("expected active v2, got %+v", active)
		}

		response = request(t, server, http.MethodPost, "/api/v1/admin/risk-model-versions/"+v2.ID+"/rollback", nil)
		var rolledBack types.RiskModelVersion
		decode(t, response, &rolledBack)
		if rolledBack.ID != v1.ID || rolledBack.Status != "active" {
			t.Fatalf("expected rollback to v1, got %+v", rolledBack)
		}

		response = request(t, server, http.MethodGet, "/api/v1/admin/risk-model-versions?name=track-baseline", nil)
		var body struct {
			Items []types.RiskModelVersion `json:"items"`
		}
		decode(t, response, &body)
		if len(body.Items) != 2 {
			t.Fatalf("expected two model versions, got %+v", body.Items)
		}
	})

	t.Run("admin updates risk feature label for training feedback", func(t *testing.T) {
		snapshot := memoryStore.AddRiskFeatureSnapshot(types.RiskFeatureSnapshot{
			ID:             "feat_admin_review",
			AttemptID:      "cap_sess_review",
			ClientID:       "demo",
			Scene:          "login",
			ChallengeType:  types.CaptchaSlider,
			FeatureVersion: "track-v1",
			Features: map[string]any{
				"track_score": 82,
			},
			Label:          "unknown",
			LabelSource:    "",
			ModelTrainable: false,
		})

		rejected := request(t, server, http.MethodPost, "/api/v1/admin/risk-feature-snapshots/"+snapshot.ID+"/label", map[string]any{
			"label":           "captcha_pass",
			"label_source":    "captcha_result",
			"model_trainable": true,
		})
		if rejected.Code != http.StatusBadRequest {
			t.Fatalf("expected weak label training rejection, got %d %s", rejected.Code, rejected.Body.String())
		}

		response := request(t, server, http.MethodPost, "/api/v1/admin/risk-feature-snapshots/"+snapshot.ID+"/label", map[string]any{
			"label":           "confirmed_bot",
			"label_source":    "manual_review",
			"model_trainable": true,
		})
		var updated types.RiskFeatureSnapshot
		decode(t, response, &updated)
		if updated.Label != "confirmed_bot" || updated.LabelSource != "manual_review" || !updated.ModelTrainable {
			t.Fatalf("unexpected updated feature snapshot: %+v", updated)
		}

		events := memoryStore.ListAuditEvents("demo", 20)
		found := false
		for _, event := range events {
			if event.DecisionReason == "RISK_FEATURE_LABEL_UPDATE" && event.Result == "training_feedback" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected training feedback audit event, got %+v", events)
		}

		memoryStore.AddRiskFeatureSnapshot(types.RiskFeatureSnapshot{
			ID:             "feat_admin_candidate",
			AttemptID:      "cap_sess_candidate",
			ClientID:       "demo",
			Scene:          "register",
			ChallengeType:  types.CaptchaRotate,
			FeatureVersion: "track-v1",
			Features: map[string]any{
				"track_score": 35,
			},
			Label:          "unknown",
			ModelTrainable: false,
		})
		memoryStore.AddRiskFeatureSnapshot(types.RiskFeatureSnapshot{
			ID:             "feat_admin_candidate_next",
			AttemptID:      "cap_sess_candidate_next",
			ClientID:       "demo",
			Scene:          "register",
			ChallengeType:  types.CaptchaRotate,
			FeatureVersion: "track-v1",
			Features: map[string]any{
				"track_score": 38,
			},
			Label:          "unknown",
			ModelTrainable: false,
		})
		response = request(t, server, http.MethodGet, "/api/v1/admin/risk-feature-snapshots?client_id=demo&scene=login&challenge_type=SLIDER&label=confirmed_bot&model_trainable=true&limit=20", nil)
		var list struct {
			Items []types.RiskFeatureSnapshot `json:"items"`
		}
		decode(t, response, &list)
		if len(list.Items) != 1 || list.Items[0].ID != snapshot.ID {
			t.Fatalf("expected filtered trainable feature snapshot, got %+v", list.Items)
		}
		response = request(t, server, http.MethodGet, "/api/v1/admin/risk-feature-snapshots?client_id=demo&label=confirmed_bot&model_trainable=false&limit=20", nil)
		decode(t, response, &list)
		if len(list.Items) != 0 {
			t.Fatalf("expected empty feature filter result, got %+v", list.Items)
		}

		response = request(t, server, http.MethodGet, "/api/v1/admin/risk-feature-snapshots?client_id=demo&scene=register&challenge_type=ROTATE&label=unknown&model_trainable=false&limit=1&offset=0", nil)
		var paged struct {
			Items   []types.RiskFeatureSnapshot `json:"items"`
			Limit   int                         `json:"limit"`
			Offset  int                         `json:"offset"`
			HasMore bool                        `json:"has_more"`
		}
		decode(t, response, &paged)
		if len(paged.Items) != 1 || paged.Limit != 1 || paged.Offset != 0 || !paged.HasMore {
			t.Fatalf("expected first paged feature result with next page, got %+v", paged)
		}
		firstFeatureID := paged.Items[0].ID

		response = request(t, server, http.MethodGet, "/api/v1/admin/risk-feature-snapshots?client_id=demo&scene=register&challenge_type=ROTATE&label=unknown&model_trainable=false&limit=1&offset=1", nil)
		decode(t, response, &paged)
		if len(paged.Items) != 1 || paged.Offset != 1 || paged.Items[0].ID == firstFeatureID {
			t.Fatalf("expected second paged feature result, got %+v first=%s", paged, firstFeatureID)
		}
	})

	t.Run("created session binds request nonce into ticket", func(t *testing.T) {
		response := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
			"client_id":     "demo",
			"scene":         "login",
			"captcha_type":  "SLIDER",
			"route":         "/api/login",
			"request_nonce": "nonce-1",
		})
		var created struct {
			SessionID    string `json:"session_id"`
			ChallengeURL string `json:"challenge_url"`
		}
		decode(t, response, &created)
		challengeURL, err := url.Parse(created.ChallengeURL)
		if err != nil {
			t.Fatalf("parse challenge url: %v", err)
		}
		if challengeURL.Query().Get("request_nonce") != "nonce-1" {
			t.Fatalf("expected challenge nonce, got %q in %q", challengeURL.Query().Get("request_nonce"), created.ChallengeURL)
		}

		session, err := memoryStore.GetSession(created.SessionID)
		if err != nil {
			t.Fatalf("get session: %v", err)
		}
		response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
			"answer": answerForSession(session),
			"track": []types.TrackPoint{
				{X: 0, Y: 20, T: 0, Type: "start"},
				{X: float64(session.Answer.X / 2), Y: 22, T: 220, Type: "move"},
				{X: float64(session.Answer.X), Y: 23, T: 520, Type: "end"},
			},
			"route": "/api/login",
			"runtime_meta": map[string]any{
				"request_nonce": "bad-nonce",
			},
		})
		var rejected struct {
			OK         bool   `json:"ok"`
			ReasonCode string `json:"reason_code"`
		}
		decode(t, response, &rejected)
		if rejected.OK || rejected.ReasonCode != "REQUEST_NONCE_MISMATCH" {
			t.Fatalf("expected nonce mismatch rejection, got %+v", rejected)
		}

		session, err = memoryStore.GetSession(created.SessionID)
		if err != nil {
			t.Fatalf("get refreshed nonce session: %v", err)
		}
		response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
			"answer": answerForSession(session),
			"track": []types.TrackPoint{
				{X: 0, Y: 20, T: 0, Type: "start"},
				{X: float64(session.Answer.X / 2), Y: 22, T: 220, Type: "move"},
				{X: float64(session.Answer.X), Y: 23, T: 520, Type: "end"},
			},
			"route": "/api/login",
			"runtime_meta": map[string]any{
				"request_nonce": "nonce-1",
			},
		})
		var verified struct {
			OK     bool   `json:"ok"`
			Ticket string `json:"ticket"`
		}
		decode(t, response, &verified)
		if !verified.OK || verified.Ticket == "" {
			t.Fatalf("expected nonce-bound verification to pass, got %+v", verified)
		}

		response = requestWithHeaders(t, server, http.MethodPost, "/api/v1/tickets/verify", map[string]any{
			"ticket":    verified.Ticket,
			"client_id": "demo",
			"scene":     "login",
			"route":     "/api/login",
		}, integrationHeaders())
		var missingNonce struct {
			Valid  bool   `json:"valid"`
			Reason string `json:"reason"`
		}
		decode(t, response, &missingNonce)
		if missingNonce.Valid || missingNonce.Reason != "NOT_FOUND" {
			t.Fatalf("expected missing nonce rejection, got %+v", missingNonce)
		}

		response = requestWithHeaders(t, server, http.MethodPost, "/api/v1/tickets/verify", map[string]any{
			"ticket":        verified.Ticket,
			"client_id":     "demo",
			"scene":         "login",
			"route":         "/api/login",
			"request_nonce": "nonce-1",
		}, integrationHeaders())
		var ticketCheck struct {
			Valid        bool   `json:"valid"`
			RequestNonce string `json:"request_nonce"`
		}
		decode(t, response, &ticketCheck)
		if !ticketCheck.Valid || ticketCheck.RequestNonce != "nonce-1" {
			t.Fatalf("expected nonce-bound ticket to verify, got %+v", ticketCheck)
		}
	})

	t.Run("rate limit creates challenge after threshold", func(t *testing.T) {
		var decision types.PolicyDecision
		for i := 0; i < 6; i++ {
			response := requestWithHeaders(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
				ClientID: "demo",
				Path:     "/api/comment",
				Method:   "POST",
				IP:       "198.51.100.20",
			}, integrationHeaders())
			decode(t, response, &decision)
		}
		if decision.Action != types.DecisionChallenge || decision.Reason != "RATE_LIMIT" {
			t.Fatalf("expected rate limit challenge, got %+v", decision)
		}
	})

	t.Run("ticket allows and is consumed", func(t *testing.T) {
		ticket, err := tokens.Issue("demo", "login", "/api/login", "", "", "")
		if err != nil {
			t.Fatalf("issue ticket: %v", err)
		}
		response := requestWithHeaders(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
			ClientID: "demo",
			Scene:    "login",
			Path:     "/api/login",
			Method:   "POST",
			IP:       "198.51.100.30",
			Ticket:   ticket.Value,
		}, integrationHeaders())
		var decision types.PolicyDecision
		decode(t, response, &decision)
		if decision.Action != types.DecisionAllow || decision.Reason != "TICKET_CONSUMED" {
			t.Fatalf("expected consumed ticket allow, got %+v", decision)
		}
		response = requestWithHeaders(t, server, http.MethodPost, "/api/v1/tickets/verify", map[string]any{
			"ticket":    ticket.Value,
			"client_id": "demo",
			"scene":     "login",
			"route":     "/api/login",
		}, integrationHeaders())
		var verify struct {
			Valid  bool   `json:"valid"`
			Reason string `json:"reason"`
		}
		decode(t, response, &verify)
		if verify.Valid || verify.Reason != "CONSUMED" {
			t.Fatalf("expected consumed ticket, got %+v", verify)
		}

		response = requestWithHeaders(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
			ClientID: "demo",
			Scene:    "login",
			Path:     "/api/login",
			Method:   "POST",
			IP:       "198.51.100.30",
			Ticket:   ticket.Value,
		}, integrationHeaders())
		decode(t, response, &decision)
		if decision.Action != types.DecisionBlock || decision.Reason != "CONSUMED" {
			t.Fatalf("expected consumed ticket to block policy evaluation, got %+v", decision)
		}

		missingRouteTicket, err := tokens.Issue("demo", "login", "/api/login", "", "", "")
		if err != nil {
			t.Fatalf("issue missing route policy ticket: %v", err)
		}
		response = requestWithHeaders(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
			ClientID: "demo",
			Scene:    "login",
			Method:   "POST",
			IP:       "198.51.100.30",
			Ticket:   missingRouteTicket.Value,
		}, integrationHeaders())
		decode(t, response, &decision)
		if decision.Action != types.DecisionBlock || decision.Reason != "NOT_FOUND" || decision.SessionID != "" {
			t.Fatalf("expected route-bound ticket without path to block policy evaluation, got %+v", decision)
		}

		missingNonceTicket, err := tokens.Issue("demo", "login", "/api/login", "nonce-policy-ticket", "", "")
		if err != nil {
			t.Fatalf("issue missing nonce policy ticket: %v", err)
		}
		response = requestWithHeaders(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
			ClientID: "demo",
			Scene:    "login",
			Path:     "/api/login",
			Method:   "POST",
			IP:       "198.51.100.30",
			Ticket:   missingNonceTicket.Value,
		}, integrationHeaders())
		decode(t, response, &decision)
		if decision.Action != types.DecisionBlock || decision.Reason != "NOT_FOUND" || decision.SessionID != "" {
			t.Fatalf("expected nonce-bound ticket without request nonce to block policy evaluation, got %+v", decision)
		}

		missingContextTicket, err := tokens.Issue("demo", "login", "/api/login", "", hashValue("198.51.100.30"), hashValue("Mozilla/5.0 policy-context"))
		if err != nil {
			t.Fatalf("issue missing context policy ticket: %v", err)
		}
		response = requestWithHeaders(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
			ClientID: "demo",
			Scene:    "login",
			Path:     "/api/login",
			Method:   "POST",
			Ticket:   missingContextTicket.Value,
		}, integrationHeaders())
		decode(t, response, &decision)
		if decision.Action != types.DecisionBlock || decision.Reason != "NOT_FOUND" || decision.SessionID != "" {
			t.Fatalf("expected ip/ua-bound ticket without request context to block policy evaluation, got %+v", decision)
		}
	})

	t.Run("ticket mints clearance for uid and anonymous device contexts", func(t *testing.T) {
		const (
			ip        = "198.51.100.64"
			userAgent = "Mozilla/5.0 clearance-test"
			account   = "acct_clearance_hash"
		)
		ticket, err := tokens.Issue("demo", "register", "/api/register", "", hashValue(ip), hashValue(userAgent))
		if err != nil {
			t.Fatalf("issue clearance ticket: %v", err)
		}
		response := requestWithHeaders(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
			ClientID:      "demo",
			Scene:         "register",
			Path:          "/api/register",
			Method:        "POST",
			IP:            ip,
			UserAgent:     userAgent,
			AccountIDHash: account,
			Ticket:        ticket.Value,
		}, integrationHeaders())
		var decision types.PolicyDecision
		decode(t, response, &decision)
		if decision.Action != types.DecisionAllow || decision.Reason != "TICKET_CONSUMED" || decision.ClearanceToken == "" || decision.ClearanceTTLSeconds <= 0 {
			t.Fatalf("expected consumed ticket to mint clearance, got %+v", decision)
		}

		response = requestWithHeaders(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
			ClientID:      "demo",
			Scene:         "register",
			Path:          "/api/register",
			Method:        "POST",
			IP:            ip,
			UserAgent:     userAgent,
			AccountIDHash: account,
			Clearance:     decision.ClearanceToken,
		}, integrationHeaders())
		var allowed types.PolicyDecision
		decode(t, response, &allowed)
		if allowed.Action != types.DecisionAllow || allowed.Reason != "CLEARANCE_VALID" {
			t.Fatalf("expected clearance to allow follow-up request, got %+v", allowed)
		}

		response = requestWithHeaders(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
			ClientID:      "demo",
			Scene:         "register",
			Path:          "/api/register",
			Method:        "POST",
			IP:            ip,
			UserAgent:     userAgent,
			AccountIDHash: "acct_other",
			Clearance:     decision.ClearanceToken,
		}, integrationHeaders())
		var mismatch types.PolicyDecision
		decode(t, response, &mismatch)
		if mismatch.Action != types.DecisionChallenge || mismatch.Reason != "ALWAYS" {
			t.Fatalf("expected mismatched uid to fall back to challenge, got %+v", mismatch)
		}

		anonTicket, err := tokens.Issue("demo", "register", "/api/register", "", hashValue(ip), hashValue(userAgent))
		if err != nil {
			t.Fatalf("issue anonymous clearance ticket: %v", err)
		}
		response = requestWithHeaders(t, server, http.MethodPost, "/api/v1/tickets/verify", map[string]any{
			"ticket":          anonTicket.Value,
			"client_id":       "demo",
			"scene":           "register",
			"route":           "/api/register",
			"ip_hash":         hashValue(ip),
			"user_agent_hash": hashValue(userAgent),
			"device_id_hash":  "anon_device_hash",
			"consume":         true,
		}, integrationHeaders())
		var consumed struct {
			Valid               bool   `json:"valid"`
			ClearanceToken      string `json:"clearance_token"`
			ClearanceTTLSeconds int    `json:"clearance_ttl_seconds"`
		}
		decode(t, response, &consumed)
		if !consumed.Valid || consumed.ClearanceToken == "" || consumed.ClearanceTTLSeconds <= 0 {
			t.Fatalf("expected anonymous ticket consume to mint clearance, got %+v", consumed)
		}

		response = requestWithHeaders(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
			ClientID:     "demo",
			Scene:        "register",
			Path:         "/api/register",
			Method:       "POST",
			IP:           ip,
			UserAgent:    userAgent,
			DeviceIDHash: "anon_device_hash",
			Clearance:    consumed.ClearanceToken,
		}, integrationHeaders())
		decode(t, response, &allowed)
		if allowed.Action != types.DecisionAllow || allowed.Reason != "CLEARANCE_VALID" {
			t.Fatalf("expected anonymous device clearance to allow follow-up request, got %+v", allowed)
		}
	})

	t.Run("event report appends audit events", func(t *testing.T) {
		forgedCreatedAt := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
		response := requestWithHeaders(t, server, http.MethodPost, "/api/v1/events/report", types.EventBatch{
			Events: []types.AuditEvent{
				{ID: "audit_forged_http_event", ClientID: "demo", Scene: "login", Route: "/api/login", AccountIDHash: "acct_http_event", DeviceIDHash: "device_http_event", Action: types.DecisionObserve, DecisionReason: "HTTP_EVENT", Result: "observe", CreatedAt: forgedCreatedAt},
			},
		}, integrationHeaders())
		var report types.ReportResult
		decode(t, response, &report)
		if report.Accepted != 1 {
			t.Fatalf("expected accepted event, got %+v", report)
		}

		response = request(t, server, http.MethodGet, "/api/v1/admin/audit-events?client_id=demo&limit=1", nil)
		var body struct {
			Items []types.AuditEvent `json:"items"`
		}
		decode(t, response, &body)
		if len(body.Items) != 1 || body.Items[0].DecisionReason != "HTTP_EVENT" || body.Items[0].AccountIDHash != "acct_http_event" || body.Items[0].DeviceIDHash != "device_http_event" {
			t.Fatalf("expected reported event at head, got %+v", body.Items)
		}
		if body.Items[0].ID == "audit_forged_http_event" || body.Items[0].CreatedAt.Equal(forgedCreatedAt) || body.Items[0].CreatedAt.IsZero() {
			t.Fatalf("reported event should use server-generated identity, got %+v", body.Items[0])
		}

		memoryStore.AddAuditEvent(types.AuditEvent{
			ID:             "audit_filter_block",
			ClientID:       "demo",
			Scene:          "checkout",
			Route:          "/api/pay",
			AccountIDHash:  "acct_filter",
			DeviceIDHash:   "device_filter",
			Action:         types.DecisionBlock,
			DecisionReason: "FILTER_BLOCK",
			ChallengeType:  types.CaptchaRotate,
			Result:         "block",
		})
		memoryStore.AddAuditEvent(types.AuditEvent{
			ID:             "audit_filter_block_next",
			ClientID:       "demo",
			Scene:          "checkout",
			Route:          "/api/pay",
			AccountIDHash:  "acct_other",
			DeviceIDHash:   "device_other",
			Action:         types.DecisionBlock,
			DecisionReason: "FILTER_BLOCK_NEXT",
			ChallengeType:  types.CaptchaRotate,
			Result:         "block",
		})
		response = request(t, server, http.MethodGet, "/api/v1/admin/audit-events?client_id=demo&scene=checkout&action=block&result=block&decision_reason=FILTER_BLOCK&limit=10", nil)
		decode(t, response, &body)
		if len(body.Items) != 1 || body.Items[0].DecisionReason != "FILTER_BLOCK" {
			t.Fatalf("expected filtered audit event, got %+v", body.Items)
		}
		response = request(t, server, http.MethodGet, "/api/v1/admin/audit-events?client_id=demo&scene=checkout&account_id_hash=acct_filter&device_id_hash=device_filter&limit=10", nil)
		decode(t, response, &body)
		if len(body.Items) != 1 || body.Items[0].ID != "audit_filter_block" {
			t.Fatalf("expected account/device filtered audit event, got %+v", body.Items)
		}
		response = request(t, server, http.MethodGet, "/api/v1/admin/audit-events?client_id=demo&scene=checkout&result=pass&limit=10", nil)
		decode(t, response, &body)
		if len(body.Items) != 0 {
			t.Fatalf("expected empty filtered audit result, got %+v", body.Items)
		}

		response = request(t, server, http.MethodGet, "/api/v1/admin/audit-events?client_id=demo&scene=checkout&action=block&result=block&limit=1&offset=0", nil)
		var paged struct {
			Items   []types.AuditEvent `json:"items"`
			Limit   int                `json:"limit"`
			Offset  int                `json:"offset"`
			HasMore bool               `json:"has_more"`
		}
		decode(t, response, &paged)
		if len(paged.Items) != 1 || paged.Limit != 1 || paged.Offset != 0 || !paged.HasMore {
			t.Fatalf("expected first paged audit result with next page, got %+v", paged)
		}
		firstAuditID := paged.Items[0].ID

		response = request(t, server, http.MethodGet, "/api/v1/admin/audit-events?client_id=demo&scene=checkout&action=block&result=block&limit=1&offset=1", nil)
		decode(t, response, &paged)
		if len(paged.Items) != 1 || paged.Offset != 1 || paged.Items[0].ID == firstAuditID {
			t.Fatalf("expected second paged audit result, got %+v first=%s", paged, firstAuditID)
		}
	})
}

func TestPolicyEvaluateUsesRiskScoreThresholds(t *testing.T) {
	t.Parallel()

	server, memoryStore, _ := testServer()
	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ID:                 "route_api_risk_score",
		ClientID:           "demo",
		Name:               "api risk score",
		PathPattern:        "/api/risk-score",
		Method:             "POST",
		Scene:              "pay",
		Mode:               "risk_based",
		ChallengeType:      types.CaptchaSlider,
		RiskChallengeType:  types.CaptchaRotate,
		FailPolicy:         "fail_close",
		Priority:           999,
		Enabled:            true,
		TokenTTLSeconds:    120,
		RiskChallengeScore: 70,
		RiskBlockScore:     95,
	})

	response := request(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
		ClientID:      "demo",
		Path:          "/api/risk-score",
		Method:        "POST",
		IP:            "198.51.100.88",
		AccountIDHash: "acct_policy_risk",
		DeviceIDHash:  "device_policy_risk",
		RiskScore:     72,
	})
	var challenge types.PolicyDecision
	decode(t, response, &challenge)
	if challenge.Action != types.DecisionChallenge || challenge.Reason != "RISK_SCORE" || challenge.ChallengeType != types.CaptchaRotate || challenge.SessionID == "" {
		t.Fatalf("expected risk score challenge to use risk challenge type, got %+v", challenge)
	}
	audits := memoryStore.ListAuditEvents("demo", 1)
	if len(audits) != 1 || audits[0].AccountIDHash != "acct_policy_risk" || audits[0].DeviceIDHash != "device_policy_risk" {
		t.Fatalf("expected policy audit to carry account/device hashes, got %+v", audits)
	}

	response = request(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
		ClientID:  "demo",
		Path:      "/api/risk-score",
		Method:    "POST",
		IP:        "198.51.100.88",
		RiskScore: 98,
	})
	var block types.PolicyDecision
	decode(t, response, &block)
	if block.Action != types.DecisionBlock || block.Reason != "RISK_SCORE_BLOCK" {
		t.Fatalf("expected risk score block, got %+v", block)
	}
}

func TestPolicyEvaluateUsesExternalRiskInference(t *testing.T) {
	riskCalls := 0
	riskServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		riskCalls++
		if got := r.Header.Get("Authorization"); got != "Bearer infer-token" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, ok := payload["ip"]; ok {
			http.Error(w, "raw ip leaked", http.StatusBadRequest)
			return
		}
		if _, ok := payload["user_agent"]; ok {
			http.Error(w, "raw user agent leaked", http.StatusBadRequest)
			return
		}
		if ipHash, _ := payload["ip_hash"].(string); !strings.HasPrefix(ipHash, "sha256:") {
			http.Error(w, "missing ip hash", http.StatusBadRequest)
			return
		}
		if userAgentHash, _ := payload["user_agent_hash"].(string); !strings.HasPrefix(userAgentHash, "sha256:") {
			http.Error(w, "missing user agent hash", http.StatusBadRequest)
			return
		}
		model, ok := payload["model"].(map[string]any)
		if !ok || model["mode"] != "observe" {
			http.Error(w, "missing active model metadata", http.StatusBadRequest)
			return
		}
		score := 82
		_ = json.NewEncoder(w).Encode(riskpkg.Inference{Score: &score, RiskLevel: "high"})
	}))
	t.Cleanup(riskServer.Close)

	memoryStore := store.NewMemoryStore()
	model := memoryStore.UpsertRiskModelVersion(types.RiskModelVersion{
		ID:             "model_online_observe",
		Name:           "online-baseline",
		Version:        "v1",
		FeatureVersion: "request-v1",
		TrainingWindow: "2026-01-01/2026-06-01",
		ArtifactURI:    "http://risk.local/model",
		Mode:           "observe",
	})
	if _, err := memoryStore.ActivateRiskModelVersion(model.ID); err != nil {
		t.Fatalf("activate model: %v", err)
	}
	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ID:                 "route_online_risk",
		ClientID:           "demo",
		Name:               "online risk",
		PathPattern:        "/api/online-risk",
		Method:             "POST",
		Scene:              "pay",
		Mode:               "risk_based",
		ChallengeType:      types.CaptchaSlider,
		RiskChallengeType:  types.CaptchaRotate,
		FailPolicy:         "fail_close",
		Priority:           999,
		Enabled:            true,
		TokenTTLSeconds:    120,
		RiskChallengeScore: 70,
	})
	captchaEngine := engine.New(2 * time.Minute)
	policyEvaluator := policy.NewEvaluator(memoryStore)
	tokenService := token.NewService(memoryStore, 2*time.Minute)
	server := NewServerWithOptions(captchaEngine, policyEvaluator, memoryStore, tokenService, slog.Default(), Options{
		RiskInferencer: riskpkg.NewHTTPInferencer(riskServer.URL, "infer-token", time.Second),
	}).Handler()

	response := request(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
		ClientID:  "demo",
		Path:      "/api/online-risk",
		Method:    "POST",
		IP:        "198.51.100.81",
		UserAgent: "Mozilla/5.0 risk-inference-test",
	})
	var decision types.PolicyDecision
	decode(t, response, &decision)
	if decision.Action != types.DecisionChallenge || decision.Reason != "RISK_SCORE" || decision.ChallengeType != types.CaptchaRotate || decision.SessionID == "" {
		t.Fatalf("expected external model score to trigger risk challenge, got %+v", decision)
	}
	if riskCalls != 1 {
		t.Fatalf("expected one risk inference call, got %d", riskCalls)
	}
}

func TestPolicyEvaluateDegradesWhenRiskInferenceFails(t *testing.T) {
	riskCalls := 0
	riskServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		riskCalls++
		http.Error(w, "risk inference unavailable", http.StatusInternalServerError)
	}))
	t.Cleanup(riskServer.Close)

	memoryStore := store.NewMemoryStore()
	model := memoryStore.UpsertRiskModelVersion(types.RiskModelVersion{
		ID:             "model_online_degrade",
		Name:           "online-degrade-baseline",
		Version:        "v1",
		FeatureVersion: "request-v1",
		TrainingWindow: "2026-01-01/2026-06-01",
		ArtifactURI:    "http://risk.local/model",
		Mode:           "observe",
	})
	if _, err := memoryStore.ActivateRiskModelVersion(model.ID); err != nil {
		t.Fatalf("activate model: %v", err)
	}
	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ID:                 "route_online_risk_degrade",
		ClientID:           "demo",
		Name:               "online risk degrade",
		PathPattern:        "/api/online-risk-degrade",
		Method:             "POST",
		Scene:              "pay",
		Mode:               "risk_based",
		ChallengeType:      types.CaptchaSlider,
		RiskChallengeType:  types.CaptchaRotate,
		FailPolicy:         "fail_close",
		Priority:           999,
		Enabled:            true,
		TokenTTLSeconds:    120,
		RiskChallengeScore: 70,
	})
	server := NewServerWithOptions(
		engine.New(2*time.Minute),
		policy.NewEvaluator(memoryStore),
		memoryStore,
		token.NewService(memoryStore, 2*time.Minute),
		slog.Default(),
		Options{RiskInferencer: riskpkg.NewHTTPInferencer(riskServer.URL, "infer-token", time.Second)},
	).Handler()

	response := request(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
		ClientID:      "demo",
		Path:          "/api/online-risk-degrade",
		Method:        "POST",
		IP:            "198.51.100.84",
		UserAgent:     "Mozilla/5.0 risk-inference-failure-test",
		AccountIDHash: "acct_api_risk_degrade",
	})
	var decision types.PolicyDecision
	decode(t, response, &decision)
	if decision.Action != types.DecisionAllow || decision.Reason != "LOW_RISK_CONTEXT" || decision.SessionID != "" {
		t.Fatalf("expected risk inference failure to fall back to local low-risk decision, got %+v", decision)
	}
	if riskCalls != 1 {
		t.Fatalf("expected one risk inference call, got %d", riskCalls)
	}
}

func TestAdminTokenAuth(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	captchaEngine := engine.New(2 * time.Minute)
	policyEvaluator := policy.NewEvaluator(memoryStore)
	tokenService := token.NewService(memoryStore, 2*time.Minute)
	server := NewServerWithOptions(captchaEngine, policyEvaluator, memoryStore, tokenService, slog.Default(), Options{AdminToken: "admin-secret"}).Handler()

	health := request(t, server, http.MethodGet, "/healthz", nil)
	if health.Code != http.StatusOK {
		t.Fatalf("health should not require admin token, got %d", health.Code)
	}

	unauthorized := request(t, server, http.MethodGet, "/api/v1/admin/applications", nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized admin request, got %d %s", unauthorized.Code, unauthorized.Body.String())
	}

	authorized := requestWithHeaders(t, server, http.MethodGet, "/api/v1/admin/applications", nil, map[string]string{
		"Authorization": "Bearer admin-secret",
	})
	if authorized.Code != http.StatusOK {
		t.Fatalf("expected authorized admin request, got %d %s", authorized.Code, authorized.Body.String())
	}
}

func TestAdminConfigChangesAreAudited(t *testing.T) {
	server, _, _ := testServer()

	request(t, server, http.MethodPost, "/api/v1/admin/applications", types.Application{
		ClientID:          "audit-client",
		Name:              "audit app",
		Status:            "active",
		DefaultFailPolicy: "fail_open",
	})
	request(t, server, http.MethodPost, "/api/v1/admin/applications/demo/secret", nil)
	request(t, server, http.MethodPost, "/api/v1/admin/route-policies", types.RoutePolicy{
		ClientID:        "demo",
		Name:            "audit route",
		PathPattern:     "/api/audit",
		Method:          "POST",
		Scene:           "audit",
		Mode:            "always",
		ChallengeType:   types.CaptchaSlider,
		FailPolicy:      "fail_close",
		Enabled:         true,
		TokenTTLSeconds: 120,
	})
	request(t, server, http.MethodPost, "/api/v1/admin/ip-policies", types.IPPolicy{
		ClientID: "demo",
		Type:     "blocklist",
		CIDR:     "198.51.100.200",
		Action:   types.DecisionBlock,
		Reason:   "audit test",
		Enabled:  true,
	})
	request(t, server, http.MethodPost, "/api/v1/admin/resources", types.CaptchaResource{
		ClientID:     "demo",
		Scene:        "audit",
		CaptchaType:  types.CaptchaSlider,
		ResourceType: "background_image",
		StorageType:  "url",
		URI:          "https://cdn.example.test/audit.png",
		Tag:          "audit",
		Status:       "active",
	})

	response := request(t, server, http.MethodGet, "/api/v1/admin/audit-events?limit=20", nil)
	var body struct {
		Items []types.AuditEvent `json:"items"`
	}
	decode(t, response, &body)
	reasons := make(map[string]types.AuditEvent)
	for _, event := range body.Items {
		reasons[event.DecisionReason] = event
	}
	for _, reason := range []string{
		"CONFIG_APPLICATION_UPSERT",
		"CONFIG_APPLICATION_SECRET_ROTATE",
		"CONFIG_ROUTE_POLICY_UPSERT",
		"CONFIG_IP_POLICY_UPSERT",
		"CONFIG_RESOURCE_UPSERT",
	} {
		event, ok := reasons[reason]
		if !ok {
			t.Fatalf("expected audit reason %s in %+v", reason, body.Items)
		}
		if event.Action != types.DecisionObserve || event.Result != "config_changed" {
			t.Fatalf("unexpected config audit event for %s: %+v", reason, event)
		}
		if event.IPHash == "" || strings.Contains(event.IPHash, "192.0.2.1") {
			t.Fatalf("expected hashed admin ip for %s, got %+v", reason, event)
		}
	}
	if reasons["CONFIG_ROUTE_POLICY_UPSERT"].Route != "/api/audit" || reasons["CONFIG_ROUTE_POLICY_UPSERT"].Scene != "audit" {
		t.Fatalf("expected route policy audit context, got %+v", reasons["CONFIG_ROUTE_POLICY_UPSERT"])
	}
	if reasons["CONFIG_RESOURCE_UPSERT"].Scene != "audit" || reasons["CONFIG_RESOURCE_UPSERT"].ChallengeType != types.CaptchaSlider {
		t.Fatalf("expected resource audit context, got %+v", reasons["CONFIG_RESOURCE_UPSERT"])
	}
}

func TestAdminUploadsResourceImages(t *testing.T) {
	t.Parallel()

	handler, _, _ := testServerWithOptions(Options{ResourceUploadDir: t.TempDir()})
	var pngBody bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 24, 18))
	for y := 0; y < img.Bounds().Dy(); y++ {
		for x := 0; x < img.Bounds().Dx(); x++ {
			img.Set(x, y, color.RGBA{R: 30, G: 120, B: 200, A: 255})
		}
	}
	if err := png.Encode(&pngBody, img); err != nil {
		t.Fatalf("encode upload png: %v", err)
	}

	response := multipartResourceUpload(t, handler, map[string]string{
		"client_id":     "demo",
		"captcha_type":  string(types.CaptchaGridImageClick),
		"resource_type": "grid_category_library",
		"tag":           "traffic",
		"category":      "car",
		"label":         "汽车",
	}, "car.png", pngBody.Bytes())

	var body struct {
		Items []types.CaptchaResource `json:"items"`
	}
	decode(t, response, &body)
	if len(body.Items) != 1 {
		t.Fatalf("expected one uploaded resource, got %+v", body.Items)
	}
	uploaded := body.Items[0]
	if uploaded.StorageType != "file" || uploaded.ResourceType != "grid_category_library" || uploaded.CaptchaType != types.CaptchaGridImageClick {
		t.Fatalf("unexpected uploaded resource: %+v", uploaded)
	}
	if uploaded.Metadata["category"] != "car" || uploaded.Metadata["label"] != "汽车" || uploaded.Metadata["thumbnail_data_url"] == "" {
		t.Fatalf("expected category metadata and thumbnail, got %+v", uploaded.Metadata)
	}
	parsed, err := url.Parse(uploaded.URI)
	if err != nil || parsed.Scheme != "file" {
		t.Fatalf("expected file uri, got %q err=%v", uploaded.URI, err)
	}
	if _, err := os.Stat(parsed.Path); err != nil {
		t.Fatalf("expected uploaded file to exist: %v", err)
	}

	response = multipartResourceUpload(t, handler, map[string]string{
		"client_id":     "demo",
		"captcha_type":  string(types.CaptchaConcat),
		"resource_type": "concat_background_library",
		"tag":           "default",
		"difficulty":    "hard",
	}, "concat.png", pngBody.Bytes())
	decode(t, response, &body)
	if len(body.Items) != 1 {
		t.Fatalf("expected one dedicated background resource, got %+v", body.Items)
	}
	uploaded = body.Items[0]
	if uploaded.ResourceType != "concat_background_library" || uploaded.CaptchaType != types.CaptchaConcat {
		t.Fatalf("unexpected dedicated upload: %+v", uploaded)
	}
	if uploaded.Metadata["usage_profile"] != "concat_restore" ||
		uploaded.Metadata["suitability"] != "horizontal_continuity" ||
		uploaded.Metadata["difficulty"] != "hard" {
		t.Fatalf("expected concat material metadata, got %+v", uploaded.Metadata)
	}
}

func TestCORSAllowedOrigins(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	captchaEngine := engine.New(2 * time.Minute)
	policyEvaluator := policy.NewEvaluator(memoryStore)
	tokenService := token.NewService(memoryStore, 2*time.Minute)
	defaultServer := NewServer(captchaEngine, policyEvaluator, memoryStore, tokenService, slog.Default()).Handler()

	defaultResponse := requestWithHeaders(t, defaultServer, http.MethodGet, "/healthz", nil, map[string]string{
		"Origin": "https://any.example",
	})
	if defaultResponse.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("expected wildcard CORS by default, got %q", defaultResponse.Header().Get("Access-Control-Allow-Origin"))
	}

	restrictedServer := NewServerWithOptions(captchaEngine, policyEvaluator, memoryStore, tokenService, slog.Default(), Options{
		AllowedOrigins: []string{"https://app.example.com"},
	}).Handler()
	allowed := requestWithHeaders(t, restrictedServer, http.MethodOptions, "/api/v1/challenge/sessions", nil, map[string]string{
		"Origin":                         "https://app.example.com",
		"Access-Control-Request-Method":  "POST",
		"Access-Control-Request-Headers": "X-Captcha-Ticket",
	})
	if allowed.Code != http.StatusNoContent {
		t.Fatalf("expected preflight no content, got %d", allowed.Code)
	}
	if allowed.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Fatalf("expected allowed origin echo, got %q", allowed.Header().Get("Access-Control-Allow-Origin"))
	}
	if !strings.Contains(allowed.Header().Get("Access-Control-Allow-Headers"), "X-Captcha-Ticket") {
		t.Fatalf("expected captcha ticket header to be allowed, got %q", allowed.Header().Get("Access-Control-Allow-Headers"))
	}
	if !strings.Contains(allowed.Header().Get("Access-Control-Allow-Headers"), "X-Captcha-Clearance") {
		t.Fatalf("expected captcha clearance header to be allowed, got %q", allowed.Header().Get("Access-Control-Allow-Headers"))
	}

	denied := requestWithHeaders(t, restrictedServer, http.MethodGet, "/healthz", nil, map[string]string{
		"Origin": "https://evil.example",
	})
	if denied.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("expected denied origin to have no CORS allow header, got %q", denied.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestReturnURLValidation(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	captchaEngine := engine.New(2 * time.Minute)
	policyEvaluator := policy.NewEvaluator(memoryStore)
	tokenService := token.NewService(memoryStore, 2*time.Minute)
	server := NewServerWithOptions(captchaEngine, policyEvaluator, memoryStore, tokenService, slog.Default(), Options{
		AllowedOrigins:          []string{"https://api-client.example"},
		AllowedReturnURLOrigins: []string{"https://app.example.com"},
	}).Handler()

	allowed := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
		"client_id":    "demo",
		"scene":        "login",
		"captcha_type": "SLIDER",
		"return_url":   "https://app.example.com/login/complete?source=captcha",
	})
	var created struct {
		ReturnURL string `json:"return_url"`
	}
	decode(t, allowed, &created)
	if created.ReturnURL != "https://app.example.com/login/complete?source=captcha" {
		t.Fatalf("expected allowed return url to be preserved, got %+v", created)
	}

	rejected := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
		"client_id":    "demo",
		"scene":        "login",
		"captcha_type": "SLIDER",
		"return_url":   "https://evil.example/login/complete",
	})
	var errorBody struct {
		Error string `json:"error"`
	}
	decodeAny(t, rejected, &errorBody)
	if rejected.Code != http.StatusBadRequest || errorBody.Error != "INVALID_RETURN_URL" {
		t.Fatalf("expected return url origin rejection, got status=%d body=%+v", rejected.Code, errorBody)
	}

	defaultServer := NewServer(captchaEngine, policyEvaluator, memoryStore, tokenService, slog.Default()).Handler()
	rejected = request(t, defaultServer, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
		"client_id":    "demo",
		"scene":        "login",
		"captcha_type": "SLIDER",
		"return_url":   "javascript:alert(1)",
	})
	decodeAny(t, rejected, &errorBody)
	if rejected.Code != http.StatusBadRequest || errorBody.Error != "INVALID_RETURN_URL" {
		t.Fatalf("expected unsafe return url scheme rejection, got status=%d body=%+v", rejected.Code, errorBody)
	}
}

func TestClientSecretAuthForIntegrationAPIs(t *testing.T) {
	server, memoryStore, tokens := testServer()
	secretValue := "cap_secret_test"
	secretHash, err := clientsecret.HashClientSecret(secretValue)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	memoryStore.UpsertApplication(types.Application{
		ClientID:          "demo",
		Name:              "demo-app",
		Status:            "active",
		DefaultFailPolicy: "fail_open",
		SecretHash:        secretHash,
	})

	unauthorized := request(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/register",
		Method:   "POST",
		IP:       "198.51.100.9",
	})
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("expected policy evaluate to require client secret, got %d %s", unauthorized.Code, unauthorized.Body.String())
	}

	wrong := requestWithHeaders(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/register",
		Method:   "POST",
		IP:       "198.51.100.9",
	}, map[string]string{"X-Captcha-Client-Secret": "bad-secret"})
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("expected wrong client secret to be rejected, got %d %s", wrong.Code, wrong.Body.String())
	}

	authorized := requestWithHeaders(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/register",
		Method:   "POST",
		IP:       "198.51.100.9",
	}, map[string]string{"X-Captcha-Client-Secret": secretValue})
	var decision types.PolicyDecision
	decode(t, authorized, &decision)
	if decision.Action != types.DecisionChallenge {
		t.Fatalf("expected authorized policy evaluation, got %+v", decision)
	}

	ticket, err := tokens.Issue("demo", "login", "/api/login", "", "", "")
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	ticketResponse := requestWithHeaders(t, server, http.MethodPost, "/api/v1/tickets/verify", map[string]any{
		"ticket":    ticket.Value,
		"client_id": "demo",
		"scene":     "login",
		"route":     "/api/login",
	}, map[string]string{"Authorization": "Bearer " + secretValue})
	var ticketBody struct {
		Valid bool `json:"valid"`
	}
	decode(t, ticketResponse, &ticketBody)
	if !ticketBody.Valid {
		t.Fatalf("expected authorized ticket verification, got %+v", ticketBody)
	}

	reportResponse := requestWithHeaders(t, server, http.MethodPost, "/api/v1/events/report", types.EventBatch{
		Events: []types.AuditEvent{
			{ClientID: "demo", Scene: "login", Route: "/api/login", Action: types.DecisionObserve, DecisionReason: "CLIENT_SECRET_EVENT", Result: "observe"},
		},
	}, map[string]string{"X-Captcha-Client-Secret": secretValue})
	var report types.ReportResult
	decode(t, reportResponse, &report)
	if report.Accepted != 1 {
		t.Fatalf("expected event report accepted, got %+v", report)
	}
}

func TestEventReportRejectsEventsWithoutClientID(t *testing.T) {
	server, memoryStore, _ := testServer()
	before := len(memoryStore.ListAuditEvents("", 100))
	response := request(t, server, http.MethodPost, "/api/v1/events/report", types.EventBatch{
		Events: []types.AuditEvent{
			{ClientID: "demo", Scene: "login", Route: "/api/login", Action: types.DecisionObserve, DecisionReason: "MIXED_BATCH_SHOULD_NOT_WRITE", Result: "observe"},
			{Scene: "login", Route: "/api/login", Action: types.DecisionObserve, DecisionReason: "MISSING_CLIENT", Result: "observe"},
		},
	})
	var body struct {
		Error string `json:"error"`
	}
	decodeAny(t, response, &body)
	if response.Code != http.StatusBadRequest || body.Error != "EVENT_CLIENT_ID_REQUIRED" {
		t.Fatalf("expected missing client id rejection, got status=%d body=%+v", response.Code, body)
	}
	if after := len(memoryStore.ListAuditEvents("", 100)); after != before {
		t.Fatalf("missing client id event should not be recorded, before=%d after=%d", before, after)
	}
	for _, event := range memoryStore.ListAuditEvents("demo", 100) {
		if event.DecisionReason == "MIXED_BATCH_SHOULD_NOT_WRITE" {
			t.Fatalf("valid event from rejected batch should not be partially recorded: %+v", event)
		}
	}
}

func TestApplicationStatusGuardsRuntimeAndIntegrationAPIs(t *testing.T) {
	server, memoryStore, tokens := testServer()
	memoryStore.UpsertApplication(types.Application{
		ClientID:          "disabled-client",
		Name:              "disabled app",
		Status:            "disabled",
		DefaultFailPolicy: "fail_close",
	})

	unknownCreate := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
		"client_id":    "missing-client",
		"scene":        "login",
		"captcha_type": "SLIDER",
	})
	if unknownCreate.Code != http.StatusNotFound {
		t.Fatalf("expected unknown app rejection, got %d %s", unknownCreate.Code, unknownCreate.Body.String())
	}

	disabledCreate := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
		"client_id":    "disabled-client",
		"scene":        "login",
		"captcha_type": "SLIDER",
	})
	if disabledCreate.Code != http.StatusForbidden {
		t.Fatalf("expected disabled app create rejection, got %d %s", disabledCreate.Code, disabledCreate.Body.String())
	}

	disabledPolicy := request(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
		ClientID: "disabled-client",
		Path:     "/api/login",
		Method:   "POST",
		IP:       "198.51.100.10",
	})
	var disabledDecision types.PolicyDecision
	decode(t, disabledPolicy, &disabledDecision)
	if disabledDecision.Action != types.DecisionBlock || disabledDecision.Reason != "APPLICATION_DISABLED" {
		t.Fatalf("expected disabled app policy block, got %+v", disabledDecision)
	}

	ticket, err := tokens.Issue("disabled-client", "login", "/api/login", "", "", "")
	if err != nil {
		t.Fatalf("issue disabled app ticket: %v", err)
	}
	disabledTicket := request(t, server, http.MethodPost, "/api/v1/tickets/verify", map[string]any{
		"ticket":    ticket.Value,
		"client_id": "disabled-client",
		"scene":     "login",
		"route":     "/api/login",
	})
	var disabledTicketBody struct {
		Valid  bool   `json:"valid"`
		Reason string `json:"reason"`
	}
	decode(t, disabledTicket, &disabledTicketBody)
	if disabledTicketBody.Valid || disabledTicketBody.Reason != "APPLICATION_DISABLED" {
		t.Fatalf("expected disabled app ticket invalid response, got %+v", disabledTicketBody)
	}

	disabledEvent := request(t, server, http.MethodPost, "/api/v1/events/report", types.EventBatch{
		Events: []types.AuditEvent{
			{ClientID: "disabled-client", Scene: "login", Route: "/api/login", Action: types.DecisionObserve, DecisionReason: "DISABLED_TEST", Result: "observe"},
		},
	})
	if disabledEvent.Code != http.StatusForbidden {
		t.Fatalf("expected disabled app event rejection, got %d %s", disabledEvent.Code, disabledEvent.Body.String())
	}

	memoryStore.UpsertApplication(types.Application{
		ClientID:          "toggle-client",
		Name:              "toggle app",
		Status:            "active",
		DefaultFailPolicy: "fail_open",
	})
	createdResponse := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
		"client_id":    "toggle-client",
		"scene":        "login",
		"captcha_type": "SLIDER",
	})
	var created struct {
		SessionID string `json:"session_id"`
	}
	decode(t, createdResponse, &created)
	session, err := memoryStore.GetSession(created.SessionID)
	if err != nil {
		t.Fatalf("get toggle session: %v", err)
	}
	memoryStore.UpsertApplication(types.Application{
		ClientID:          "toggle-client",
		Name:              "toggle app",
		Status:            "disabled",
		DefaultFailPolicy: "fail_open",
	})
	disabledVerify := request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
		"answer": answerForSession(session),
		"track": []types.TrackPoint{
			{X: 0, Y: 20, T: 0, Type: "start"},
			{X: float64(session.Answer.X / 2), Y: 22, T: 240, Type: "move"},
			{X: float64(session.Answer.X), Y: 21, T: 520, Type: "end"},
		},
	})
	if disabledVerify.Code != http.StatusForbidden {
		t.Fatalf("expected disabled app verify rejection, got %d %s", disabledVerify.Code, disabledVerify.Body.String())
	}
}

func TestChallengeSessionSingleUseAndFailureLimit(t *testing.T) {
	server, memoryStore, _ := testServer()

	response := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
		"client_id":    "demo",
		"scene":        "login",
		"captcha_type": "SLIDER",
		"route":        "/api/login",
	})
	var created struct {
		SessionID string `json:"session_id"`
	}
	decode(t, response, &created)
	session, err := memoryStore.GetSession(created.SessionID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}

	rejected := request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
		"answer":    answerForSession(session),
		"track":     trackForX(session.Answer.X),
		"route":     "/api/login",
		"tolerance": 50,
	})
	var forbidden struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	decodeAny(t, rejected, &forbidden)
	if rejected.Code != http.StatusBadRequest || forbidden.Error != "FORBIDDEN_VERIFY_FIELD" {
		t.Fatalf("expected forbidden top-level verify field rejection, got status=%d body=%+v", rejected.Code, forbidden)
	}

	rejected = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
		"answer":          answerForSession(session),
		"track":           trackForX(session.Answer.X),
		"route":           "/api/login",
		"score_threshold": 0.2,
	})
	decodeAny(t, rejected, &forbidden)
	if rejected.Code != http.StatusBadRequest || forbidden.Error != "FORBIDDEN_VERIFY_FIELD" {
		t.Fatalf("expected forbidden threshold field rejection, got status=%d body=%+v", rejected.Code, forbidden)
	}

	rejected = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
		"answer": map[string]any{
			"x":      session.Answer.X,
			"target": session.Answer.X,
		},
		"track": trackForX(session.Answer.X),
		"route": "/api/login",
	})
	decodeAny(t, rejected, &forbidden)
	if rejected.Code != http.StatusBadRequest || forbidden.Error != "FORBIDDEN_VERIFY_FIELD" {
		t.Fatalf("expected forbidden nested verify field rejection, got status=%d body=%+v", rejected.Code, forbidden)
	}

	rejected = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
		"answer": answerForSession(session),
		"track":  trackForX(session.Answer.X),
		"route":  "/api/login",
		"runtime_meta": map[string]any{
			"device_pixel_ratio": 1,
			"track_score":        100,
		},
	})
	decodeAny(t, rejected, &forbidden)
	if rejected.Code != http.StatusBadRequest || forbidden.Error != "FORBIDDEN_VERIFY_FIELD" {
		t.Fatalf("expected forbidden nested score field rejection, got status=%d body=%+v", rejected.Code, forbidden)
	}

	response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
		"answer": answerForSession(session),
		"track":  trackForX(session.Answer.X),
		"route":  "/api/login",
	})
	var verified struct {
		OK     bool   `json:"ok"`
		Ticket string `json:"ticket"`
	}
	decode(t, response, &verified)
	if !verified.OK || verified.Ticket == "" {
		t.Fatalf("expected first verify to issue ticket, got %+v", verified)
	}

	response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
		"answer": answerForSession(session),
		"track":  trackForX(session.Answer.X),
		"route":  "/api/login",
	})
	var repeated struct {
		OK         bool   `json:"ok"`
		ReasonCode string `json:"reason_code"`
	}
	decode(t, response, &repeated)
	if repeated.OK || repeated.ReasonCode != "SESSION_ALREADY_VERIFIED" {
		t.Fatalf("expected verified session reuse rejection, got %+v", repeated)
	}

	response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
		"client_id":    "demo",
		"scene":        "login",
		"captcha_type": "SLIDER",
	})
	var limited struct {
		SessionID string `json:"session_id"`
	}
	decode(t, response, &limited)
	session, err = memoryStore.GetSession(limited.SessionID)
	if err != nil {
		t.Fatalf("get limited session: %v", err)
	}
	wrongX := session.Answer.X + 100
	var failed struct {
		OK         bool           `json:"ok"`
		Decision   types.Decision `json:"decision"`
		ReasonCode string         `json:"reason_code"`
		CanRefresh bool           `json:"can_refresh"`
	}
	for i := 0; i < maxSessionFailures; i++ {
		response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+limited.SessionID+"/verify", map[string]any{
			"answer": map[string]any{"x": wrongX},
			"track":  trackForX(wrongX),
		})
		decode(t, response, &failed)
	}
	if failed.OK || failed.Decision != types.DecisionBlock || failed.ReasonCode != "TOO_MANY_FAILURES" || failed.CanRefresh {
		t.Fatalf("expected failure limit block, got %+v", failed)
	}

	response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+limited.SessionID+"/refresh", nil)
	var refresh struct {
		OK         bool   `json:"ok"`
		ReasonCode string `json:"reason_code"`
	}
	decode(t, response, &refresh)
	if refresh.OK || refresh.ReasonCode != "SESSION_NOT_ACTIVE" {
		t.Fatalf("expected expired session refresh rejection, got %+v", refresh)
	}
}

func TestFailedVerifyResponseReplacesChallenge(t *testing.T) {
	server, memoryStore, _ := testServer()

	for attempt := 0; attempt < 20; attempt++ {
		response := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
			"client_id":    "demo",
			"scene":        "login",
			"captcha_type": "SLIDER",
		})
		var created struct {
			SessionID string `json:"session_id"`
		}
		decode(t, response, &created)
		original, err := memoryStore.GetSession(created.SessionID)
		if err != nil {
			t.Fatalf("get original session: %v", err)
		}

		wrongX := original.Answer.X + 100
		response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
			"answer": map[string]any{"x": wrongX},
			"track":  trackForX(wrongX),
		})
		var failed struct {
			OK        bool                `json:"ok"`
			Challenge types.RenderPayload `json:"challenge"`
		}
		decode(t, response, &failed)
		if failed.OK || failed.Challenge.Type != types.CaptchaSlider || failed.Challenge.View.Width == 0 {
			t.Fatalf("expected failed verify to return replacement challenge, got %+v", failed)
		}
		replaced, err := memoryStore.GetSession(created.SessionID)
		if err != nil {
			t.Fatalf("get replaced session: %v", err)
		}
		if replaced.FailureCount != 1 {
			t.Fatalf("expected failed replacement to preserve failure count, got %d", replaced.FailureCount)
		}
		if absInt(original.Answer.X-replaced.Answer.X) <= 6 {
			continue
		}

		response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
			"answer": answerForSession(original),
			"track":  trackForX(original.Answer.X),
		})
		var stale struct {
			OK bool `json:"ok"`
		}
		decode(t, response, &stale)
		if stale.OK {
			t.Fatalf("expected stale answer from replaced challenge to fail")
		}
		return
	}
	t.Fatal("could not generate a distinct replacement slider answer")
}

func TestRefreshPreservesFailureCount(t *testing.T) {
	server, memoryStore, _ := testServer()

	response := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
		"client_id":    "demo",
		"scene":        "login",
		"captcha_type": "SLIDER",
	})
	var created struct {
		SessionID string `json:"session_id"`
	}
	decode(t, response, &created)

	var failed struct {
		OK         bool           `json:"ok"`
		Decision   types.Decision `json:"decision"`
		ReasonCode string         `json:"reason_code"`
		CanRefresh bool           `json:"can_refresh"`
	}
	for i := 0; i < maxSessionFailures; i++ {
		session, err := memoryStore.GetSession(created.SessionID)
		if err != nil {
			t.Fatalf("get session after %d failures: %v", i, err)
		}
		wrongX := session.Answer.X + 100 + i
		response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
			"answer": map[string]any{"x": wrongX},
			"track":  trackForX(wrongX),
		})
		decode(t, response, &failed)
		if i == maxSessionFailures-1 {
			break
		}
		if failed.OK || failed.Decision == types.DecisionBlock {
			t.Fatalf("expected retry before failure limit, got %+v", failed)
		}
		response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/refresh", nil)
		var refreshed struct {
			SessionID string `json:"session_id"`
		}
		decode(t, response, &refreshed)
		session, err = memoryStore.GetSession(created.SessionID)
		if err != nil {
			t.Fatalf("get refreshed session after %d failures: %v", i+1, err)
		}
		if session.FailureCount != i+1 {
			t.Fatalf("expected refresh to preserve %d failures, got %d", i+1, session.FailureCount)
		}
	}
	if failed.OK || failed.Decision != types.DecisionBlock || failed.ReasonCode != "TOO_MANY_FAILURES" || failed.CanRefresh {
		t.Fatalf("expected refreshed failures to hit limit, got %+v", failed)
	}
}

func TestVerifyResponsesDoNotExposeScoringDetails(t *testing.T) {
	server, memoryStore, _ := testServer()
	forbiddenKeys := []string{
		"track_bucket",
		"track_score",
		"answer_score",
		"risk_score",
		"model_score",
		"score_threshold",
		"threshold",
		"tolerance",
		"target",
	}

	failedResponse := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
		"client_id":    "demo",
		"scene":        "login",
		"captcha_type": "SLIDER",
	})
	var failedSession struct {
		SessionID string `json:"session_id"`
	}
	decode(t, failedResponse, &failedSession)
	failedStored, err := memoryStore.GetSession(failedSession.SessionID)
	if err != nil {
		t.Fatalf("get failed response session: %v", err)
	}
	wrongX := failedStored.Answer.X + 120
	failedResponse = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+failedSession.SessionID+"/verify", map[string]any{
		"answer": map[string]any{"x": wrongX},
		"track":  trackForX(wrongX),
	})
	var failedBody map[string]any
	decode(t, failedResponse, &failedBody)
	if failedBody["ok"] == true || failedBody["reason_code"] == "" {
		t.Fatalf("expected coarse failed verify response, got %+v", failedBody)
	}
	assertNoKeys(t, failedBody, forbiddenKeys...)

	successResponse := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
		"client_id":    "demo",
		"scene":        "login",
		"captcha_type": "SLIDER",
	})
	var successSession struct {
		SessionID string `json:"session_id"`
	}
	decode(t, successResponse, &successSession)
	successStored, err := memoryStore.GetSession(successSession.SessionID)
	if err != nil {
		t.Fatalf("get success response session: %v", err)
	}
	successResponse = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+successSession.SessionID+"/verify", map[string]any{
		"answer": answerForSession(successStored),
		"track":  trackForX(successStored.Answer.X),
	})
	var successBody map[string]any
	decode(t, successResponse, &successBody)
	if successBody["ok"] != true || successBody["ticket"] == "" {
		t.Fatalf("expected coarse successful verify response, got %+v", successBody)
	}
	assertNoKeys(t, successBody, forbiddenKeys...)
}

func TestSuspiciousTrackEscalatesChallengeType(t *testing.T) {
	server, memoryStore, _ := testServer()

	response := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
		"client_id":    "demo",
		"scene":        "login",
		"captcha_type": "SLIDER",
	})
	var created struct {
		SessionID string `json:"session_id"`
	}
	decode(t, response, &created)
	session, err := memoryStore.GetSession(created.SessionID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
		"answer": answerForSession(session),
		"track":  syntheticTrackForSession(session),
	})
	var escalated struct {
		OK          bool              `json:"ok"`
		Decision    types.Decision    `json:"decision"`
		ReasonCode  string            `json:"reason_code"`
		CanRefresh  bool              `json:"can_refresh"`
		CaptchaType types.CaptchaType `json:"captcha_type"`
	}
	decode(t, response, &escalated)
	if escalated.OK || escalated.Decision != types.DecisionChallengeHarder || escalated.ReasonCode != "TRACK_CHALLENGE_HARDER" || !escalated.CanRefresh || escalated.CaptchaType != types.CaptchaRotate {
		t.Fatalf("expected suspicious track to escalate challenge, got %+v", escalated)
	}
	session, err = memoryStore.GetSession(created.SessionID)
	if err != nil {
		t.Fatalf("get escalated session: %v", err)
	}
	if session.Type != types.CaptchaRotate {
		t.Fatalf("expected stored session type to escalate, got %+v", session.Type)
	}
	var snapshots []types.RiskFeatureSnapshot
	for i := 0; i < 20; i++ {
		snapshots = memoryStore.ListRiskFeatureSnapshots("demo", 10)
		if len(snapshots) > 0 && snapshots[0].AttemptID == created.SessionID {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(snapshots) == 0 {
		t.Fatal("expected risk feature snapshot")
	}
	if snapshots[0].ChallengeType != types.CaptchaSlider {
		t.Fatalf("expected failed attempt snapshot to keep attempted type, got %+v", snapshots[0].ChallengeType)
	}

	response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/refresh", nil)
	var refreshed struct {
		Challenge types.RenderPayload `json:"challenge"`
	}
	decode(t, response, &refreshed)
	if refreshed.Challenge.Type != types.CaptchaRotate {
		t.Fatalf("expected refreshed challenge to use escalated type, got %+v", refreshed.Challenge.Type)
	}
}

func TestConfiguredChallengeEscalationSequence(t *testing.T) {
	server, memoryStore, _ := testServerWithOptions(Options{
		ChallengeEscalation: []types.CaptchaType{types.CaptchaSlider, types.CaptchaWordImageClick},
	})

	response := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
		"client_id":    "demo",
		"scene":        "login",
		"captcha_type": "SLIDER",
	})
	var created struct {
		SessionID string `json:"session_id"`
	}
	decode(t, response, &created)
	session, err := memoryStore.GetSession(created.SessionID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
		"answer": answerForSession(session),
		"track":  syntheticTrackForSession(session),
	})
	var escalated struct {
		OK          bool              `json:"ok"`
		Decision    types.Decision    `json:"decision"`
		CanRefresh  bool              `json:"can_refresh"`
		CaptchaType types.CaptchaType `json:"captcha_type"`
	}
	decode(t, response, &escalated)
	if escalated.OK || escalated.Decision != types.DecisionChallengeHarder || !escalated.CanRefresh || escalated.CaptchaType != types.CaptchaWordImageClick {
		t.Fatalf("expected configured escalation to jump to word-click, got %+v", escalated)
	}
	session, err = memoryStore.GetSession(created.SessionID)
	if err != nil {
		t.Fatalf("get escalated session: %v", err)
	}
	if session.Type != types.CaptchaWordImageClick {
		t.Fatalf("expected stored session type to use configured escalation, got %+v", session.Type)
	}
}

func TestRoutePolicyChallengeEscalationSequenceOverridesPlatformDefault(t *testing.T) {
	server, memoryStore, _ := testServerWithOptions(Options{
		ChallengeEscalation: []types.CaptchaType{types.CaptchaSlider, types.CaptchaRotate},
	})
	memoryStore.UpsertRoutePolicy(types.RoutePolicy{
		ID:                  "route_custom_escalation",
		ClientID:            "demo",
		Name:                "custom escalation",
		PathPattern:         "/api/custom-escalation",
		Method:              "POST",
		Scene:               "login",
		Mode:                "always",
		ChallengeType:       types.CaptchaSlider,
		ChallengeEscalation: []types.CaptchaType{types.CaptchaSlider, types.CaptchaWordImageClick},
		FailPolicy:          "fail_close",
		Priority:            100,
		Enabled:             true,
		TokenTTLSeconds:     120,
	})

	response := request(t, server, http.MethodPost, "/api/v1/policy/evaluate", map[string]any{
		"client_id": "demo",
		"path":      "/api/custom-escalation",
		"method":    "POST",
		"ip":        "198.51.100.8",
	})
	var decision types.PolicyDecision
	decode(t, response, &decision)
	if decision.Action != types.DecisionChallenge || decision.SessionID == "" || decision.ChallengeType != types.CaptchaSlider {
		t.Fatalf("expected policy challenge session, got %+v", decision)
	}
	session, err := memoryStore.GetSession(decision.SessionID)
	if err != nil {
		t.Fatalf("get policy session: %v", err)
	}
	if got := challengepkg.FormatEscalationCSV(session.ChallengeEscalation); got != "SLIDER,WORD_IMAGE_CLICK" {
		t.Fatalf("expected route escalation on session, got %q", got)
	}

	response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+decision.SessionID+"/verify", map[string]any{
		"answer": answerForSession(session),
		"track":  syntheticTrackForSession(session),
		"route":  "/api/custom-escalation",
	})
	var escalated struct {
		OK          bool              `json:"ok"`
		Decision    types.Decision    `json:"decision"`
		CanRefresh  bool              `json:"can_refresh"`
		CaptchaType types.CaptchaType `json:"captcha_type"`
	}
	decode(t, response, &escalated)
	if escalated.OK || escalated.Decision != types.DecisionChallengeHarder || !escalated.CanRefresh || escalated.CaptchaType != types.CaptchaWordImageClick {
		t.Fatalf("expected route escalation to override platform default, got %+v", escalated)
	}
}

func TestHarderCaptchaTypeUsesConfiguredSequence(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		current    types.CaptchaType
		configured []types.CaptchaType
		want       types.CaptchaType
	}{
		{
			name:    "default sequence",
			current: types.CaptchaSlider,
			want:    types.CaptchaRotate,
		},
		{
			name:       "configured jump",
			current:    types.CaptchaSlider,
			configured: []types.CaptchaType{types.CaptchaSlider, types.CaptchaWordImageClick},
			want:       types.CaptchaWordImageClick,
		},
		{
			name:       "missing current uses next stronger configured type",
			current:    types.CaptchaRotate,
			configured: []types.CaptchaType{types.CaptchaSlider, types.CaptchaWordImageClick},
			want:       types.CaptchaWordImageClick,
		},
		{
			name:       "no downgrade from strongest type",
			current:    types.CaptchaWordImageClick,
			configured: []types.CaptchaType{types.CaptchaSlider, types.CaptchaRotate},
			want:       types.CaptchaWordImageClick,
		},
		{
			name:       "invalid configured values fall back to default",
			current:    types.CaptchaRotate,
			configured: []types.CaptchaType{"AUTO", "unknown", ""},
			want:       types.CaptchaConcat,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := challengepkg.HarderType(tc.current, tc.configured); got != tc.want {
				t.Fatalf("harderCaptchaType(%s, %+v)=%s want %s", tc.current, tc.configured, got, tc.want)
			}
		})
	}
}

func TestVerifySessionRecordsTrackFeatures(t *testing.T) {
	server, memoryStore, _ := testServer()
	model := memoryStore.UpsertRiskModelVersion(types.RiskModelVersion{
		ID:             "model_shadow_track_v1",
		Name:           "track-baseline",
		Version:        "shadow-v1",
		FeatureVersion: "track-v1",
		TrainingWindow: "2026-06-01/2026-06-20",
		ArtifactURI:    "s3://models/track/shadow-v1.json",
		Mode:           "shadow",
	})
	if _, err := memoryStore.ActivateRiskModelVersion(model.ID); err != nil {
		t.Fatalf("activate model: %v", err)
	}

	response := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
		"client_id":    "demo",
		"scene":        "login",
		"captcha_type": "SLIDER",
		"route":        "/api/login",
	})
	var created struct {
		SessionID string `json:"session_id"`
	}
	decode(t, response, &created)

	session, err := memoryStore.GetSession(created.SessionID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
		"answer": answerForSession(session),
		"track": []types.TrackPoint{
			{X: 0, Y: 20, T: 0, Type: "start"},
			{X: float64(session.Answer.X / 4), Y: 23, T: 120, Type: "move"},
			{X: float64(session.Answer.X / 2), Y: 18, T: 260, Type: "move"},
			{X: float64(session.Answer.X * 3 / 4), Y: 24, T: 410, Type: "move"},
			{X: float64(session.Answer.X), Y: 21, T: 620, Type: "end"},
		},
		"route": "/api/login",
	})
	var verified struct {
		OK bool `json:"ok"`
	}
	decode(t, response, &verified)
	if !verified.OK {
		t.Fatalf("expected verification to pass, got %+v", verified)
	}

	var snapshots []types.RiskFeatureSnapshot
	for i := 0; i < 20; i++ {
		snapshots = memoryStore.ListRiskFeatureSnapshots("demo", 10)
		if len(snapshots) > 0 && snapshots[0].AttemptID == created.SessionID {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(snapshots) == 0 {
		t.Fatal("expected risk feature snapshot")
	}
	features := snapshots[0].Features
	if features["path_length"] == nil || features["velocity_variance"] == nil || features["direction_changes"] == nil {
		t.Fatalf("expected extracted track features, got %+v", features)
	}
	resources, ok := features["resources"].([]map[string]any)
	if !ok || !hasFeatureResource(resources, "res_background") || !hasFeatureResource(resources, "res_slider") {
		t.Fatalf("expected resource hit refs without raw resource data, got %+v", features["resources"])
	}
	for _, resource := range resources {
		if resource["uri"] != nil || resource["metadata"] != nil || resource["checksum"] != nil {
			t.Fatalf("resource feature ref leaked raw resource fields: %+v", resource)
		}
	}
	shadow, ok := features["risk_model_shadow"].(map[string]any)
	if !ok {
		t.Fatalf("expected risk model shadow features, got %+v", features)
	}
	if shadow["model_id"] != model.ID || shadow["decision_effect"] != "none" || shadow["mode"] != "shadow" {
		t.Fatalf("unexpected shadow model metadata: %+v", shadow)
	}
	if _, ok := shadow["score"].(int); !ok {
		t.Fatalf("expected integer shadow score, got %+v", shadow)
	}
	if bucket, _ := shadow["bucket"].(string); bucket == "" {
		t.Fatalf("expected shadow score and bucket, got %+v", shadow)
	}
	if snapshots[0].ModelTrainable {
		t.Fatal("new captcha result should stay a training candidate by default")
	}
}

func TestVerifySessionDegradesWhenRiskFeatureStorePanics(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	panicStore := &riskFeaturePanicStore{
		MemoryStore:   memoryStore,
		featureWrites: make(chan struct{}, 1),
	}
	server := NewServerWithOptions(
		engine.New(2*time.Minute),
		policy.NewEvaluator(panicStore),
		panicStore,
		token.NewService(panicStore, 2*time.Minute),
		slog.Default(),
		Options{},
	).Handler()

	response := request(t, server, http.MethodPost, "/api/v1/challenge/sessions", map[string]any{
		"client_id":    "demo",
		"scene":        "login",
		"captcha_type": "SLIDER",
	})
	var created struct {
		SessionID string `json:"session_id"`
	}
	decode(t, response, &created)

	session, err := memoryStore.GetSession(created.SessionID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	response = request(t, server, http.MethodPost, "/api/v1/challenge/sessions/"+created.SessionID+"/verify", map[string]any{
		"answer": answerForSession(session),
		"track": []types.TrackPoint{
			{X: 0, Y: 20, T: 0, Type: "start"},
			{X: float64(session.Answer.X / 4), Y: 23, T: 120, Type: "move"},
			{X: float64(session.Answer.X / 2), Y: 18, T: 260, Type: "move"},
			{X: float64(session.Answer.X * 3 / 4), Y: 24, T: 410, Type: "move"},
			{X: float64(session.Answer.X), Y: 21, T: 620, Type: "end"},
		},
	})
	var verified struct {
		OK     bool           `json:"ok"`
		Ticket string         `json:"ticket"`
		Result types.Decision `json:"decision"`
	}
	decode(t, response, &verified)
	if !verified.OK || verified.Ticket == "" || verified.Result != types.DecisionPass {
		t.Fatalf("risk feature write panic must not block verification success, got %+v", verified)
	}

	select {
	case <-panicStore.featureWrites:
	case <-time.After(time.Second):
		t.Fatal("expected risk feature write attempt")
	}
}

func TestAdminPolicySimulationIsDryRun(t *testing.T) {
	t.Parallel()

	server, memoryStore, _ := testServer()
	beforeAudit := len(memoryStore.ListAuditEvents("demo", 100))
	response := request(t, server, http.MethodPost, "/api/v1/admin/policy/simulate", types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/comment",
		Method:   "POST",
		IP:       "198.51.100.201",
	})
	var simulation struct {
		DryRun             bool                 `json:"dry_run"`
		Decision           types.PolicyDecision `json:"decision"`
		Route              types.RoutePolicy    `json:"route"`
		RateLimitEvaluated bool                 `json:"rate_limit_evaluated"`
		SideEffects        []string             `json:"side_effects"`
		Notes              []string             `json:"notes"`
	}
	decode(t, response, &simulation)
	if !simulation.DryRun || simulation.Decision.Action != types.DecisionObserve || simulation.Decision.Reason != "RATE_LIMIT_DRY_RUN" {
		t.Fatalf("expected dry-run observe decision, got %+v", simulation)
	}
	if simulation.Route.ID != "route_comment" || simulation.Decision.ChallengeType != types.CaptchaRotate {
		t.Fatalf("expected simulated rate-limit route and captcha type, got %+v", simulation)
	}
	if simulation.RateLimitEvaluated {
		t.Fatalf("rate limit simulation must not read or increment counters: %+v", simulation)
	}
	if len(simulation.SideEffects) == 0 || len(simulation.Notes) == 0 {
		t.Fatalf("expected dry-run side effect notes, got %+v", simulation)
	}
	if afterAudit := len(memoryStore.ListAuditEvents("demo", 100)); afterAudit != beforeAudit {
		t.Fatalf("simulation should not write audit events, before=%d after=%d", beforeAudit, afterAudit)
	}

	for i := 0; i < 5; i++ {
		response = request(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
			ClientID: "demo",
			Path:     "/api/comment",
			Method:   "POST",
			IP:       "198.51.100.201",
		})
		var decision types.PolicyDecision
		decode(t, response, &decision)
		if decision.Action != types.DecisionAllow || decision.Reason != "UNDER_RATE_LIMIT" {
			t.Fatalf("simulation should not consume rate quota; request %d got %+v", i+1, decision)
		}
	}
	response = request(t, server, http.MethodPost, "/api/v1/policy/evaluate", types.PolicyEvaluateRequest{
		ClientID: "demo",
		Path:     "/api/comment",
		Method:   "POST",
		IP:       "198.51.100.201",
	})
	var decision types.PolicyDecision
	decode(t, response, &decision)
	if decision.Action != types.DecisionChallenge || decision.Reason != "RATE_LIMIT" {
		t.Fatalf("expected sixth real request to trigger rate limit, got %+v", decision)
	}
}

func TestAdminMetricsSummarizesOperationalState(t *testing.T) {
	t.Parallel()

	server, memoryStore, _ := testServer()
	memoryStore.AddAuditEvent(types.AuditEvent{
		ClientID:       "demo",
		Scene:          "login",
		Route:          "/api/login",
		Action:         types.DecisionBlock,
		DecisionReason: "IP_BLOCKLIST",
		ChallengeType:  types.CaptchaSlider,
		Result:         "block",
	})
	memoryStore.AddAuditEvent(types.AuditEvent{
		ClientID:       "demo",
		Scene:          "login",
		Route:          "/api/v1/admin/resources",
		Action:         types.DecisionObserve,
		DecisionReason: "CONFIG_RESOURCE_UPSERT",
		Result:         "config_changed",
	})
	memoryStore.AddRiskFeatureSnapshot(types.RiskFeatureSnapshot{
		AttemptID:      "attempt_metrics",
		ClientID:       "demo",
		Scene:          "login",
		ChallengeType:  types.CaptchaSlider,
		FeatureVersion: "track-v1",
		Features: map[string]any{
			"decision":  string(types.DecisionRetry),
			"result_ok": false,
			"resources": []map[string]any{
				{"id": "res_background", "resource_type": "background_image", "captcha_type": string(types.CaptchaSlider), "tag": "default"},
				{"id": "res_slider", "resource_type": "slider_template", "captcha_type": string(types.CaptchaSlider), "tag": "default"},
			},
			"track_score": 92,
		},
		Label:          "confirmed_bot",
		LabelSource:    "manual_review",
		ModelTrainable: true,
	})
	model := memoryStore.UpsertRiskModelVersion(types.RiskModelVersion{
		Name:           "track-baseline",
		Version:        "v1",
		FeatureVersion: "track-v1",
		TrainingWindow: "2026-06-01/2026-06-20",
		ArtifactURI:    "file:///models/track-baseline-v1.json",
		Mode:           "shadow",
		Status:         "candidate",
	})
	if _, err := memoryStore.ActivateRiskModelVersion(model.ID); err != nil {
		t.Fatalf("activate model: %v", err)
	}

	response := request(t, server, http.MethodGet, "/api/v1/admin/metrics?client_id=demo&limit=20", nil)
	var metrics adminMetricsResponse
	decode(t, response, &metrics)

	if metrics.ClientID != "demo" || metrics.Window.AuditLimit != 20 || metrics.Window.FeatureLimit != 20 {
		t.Fatalf("unexpected metrics scope: %+v", metrics)
	}
	if metrics.Totals.Applications != 1 || metrics.Totals.ActiveApplications != 1 {
		t.Fatalf("expected demo application totals, got %+v", metrics.Totals)
	}
	if metrics.Totals.RoutePolicies != 3 || metrics.Totals.EnabledRoutePolicies != 3 {
		t.Fatalf("expected seeded route policy totals, got %+v", metrics.Totals)
	}
	if metrics.Totals.CaptchaResources != 3 || metrics.Totals.ActiveCaptchaResources != 3 {
		t.Fatalf("expected seeded resource totals, got %+v", metrics.Totals)
	}
	if metrics.Totals.RiskFeatureSnapshots != 1 || metrics.Totals.TrainableRiskFeatures != 1 {
		t.Fatalf("expected risk feature totals, got %+v", metrics.Totals)
	}
	if metrics.Totals.RiskModelVersions != 1 || metrics.Totals.ActiveRiskModelVersions != 1 {
		t.Fatalf("expected active model totals, got %+v", metrics.Totals)
	}
	if metrics.Recent.AuditEvents != 4 || metrics.Recent.Block != 1 || metrics.Recent.Challenge != 2 || metrics.Recent.ConfigChanges != 1 {
		t.Fatalf("unexpected recent audit metrics: %+v", metrics.Recent)
	}
	if metrics.Recent.PassRate != 33.3 || metrics.Recent.BlockRate != 25 {
		t.Fatalf("unexpected rates: %+v", metrics.Recent)
	}
	if metrics.ByChallengeType[string(types.CaptchaSlider)] != 2 || metrics.ByChallengeType[string(types.CaptchaRotate)] != 1 {
		t.Fatalf("unexpected captcha type counts: %+v", metrics.ByChallengeType)
	}
	if metrics.RiskLabels["confirmed_bot"] != 1 || metrics.ResourceStatuses["active"] != 3 {
		t.Fatalf("unexpected label/status counts: labels=%+v statuses=%+v", metrics.RiskLabels, metrics.ResourceStatuses)
	}
	if len(metrics.TopScenes) == 0 || metrics.TopScenes[0].Name != "login" || metrics.TopScenes[0].Count != 3 {
		t.Fatalf("unexpected top scenes: %+v", metrics.TopScenes)
	}
	if len(metrics.TopResources) < 2 || metrics.TopResources[0].ID != "res_background" || metrics.TopResources[0].Attempts != 1 || metrics.TopResources[0].Retry != 1 || metrics.TopResources[0].FailureRate != 100 {
		t.Fatalf("unexpected top resource metrics: %+v", metrics.TopResources)
	}
}

func TestPrometheusMetricsEndpoint(t *testing.T) {
	t.Parallel()

	server, _, _ := testServer()
	response := request(t, server, http.MethodGet, "/metrics", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
		t.Fatalf("expected prometheus text content type, got %q", contentType)
	}
	body := response.Body.String()
	for _, expected := range []string{
		"# HELP captcha_applications_total",
		"captcha_applications_total 1",
		"captcha_route_policies_enabled_total 3",
		`captcha_audit_actions_recent_total{action="challenge"} 2`,
		`captcha_challenge_types_recent_total{challenge_type="SLIDER"} 1`,
		"# HELP captcha_resource_hits_recent_total",
		"captcha_metrics_generated_timestamp_seconds",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected metrics body to contain %q, got:\n%s", expected, body)
		}
	}
}

func TestPrometheusMetricsTokenAuth(t *testing.T) {
	t.Parallel()

	memoryStore := store.NewMemoryStore()
	captchaEngine := engine.New(2 * time.Minute)
	policyEvaluator := policy.NewEvaluator(memoryStore)
	tokenService := token.NewService(memoryStore, 2*time.Minute)
	server := NewServerWithOptions(captchaEngine, policyEvaluator, memoryStore, tokenService, slog.Default(), Options{MetricsToken: "metrics-secret"}).Handler()

	unauthorized := request(t, server, http.MethodGet, "/metrics", nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized metrics request, got %d %s", unauthorized.Code, unauthorized.Body.String())
	}
	authorized := requestWithHeaders(t, server, http.MethodGet, "/metrics", nil, map[string]string{
		"X-Captcha-Metrics-Token": "metrics-secret",
	})
	if authorized.Code != http.StatusOK {
		t.Fatalf("expected authorized metrics request, got %d %s", authorized.Code, authorized.Body.String())
	}
}

func TestAdminExportsRiskFeatureSnapshotsForOfflineTraining(t *testing.T) {
	t.Parallel()

	server, memoryStore, _ := testServer()
	memoryStore.AddRiskFeatureSnapshot(types.RiskFeatureSnapshot{
		AttemptID:      "attempt_trainable_bot",
		ClientID:       "demo",
		Scene:          "login",
		ChallengeType:  types.CaptchaSlider,
		FeatureVersion: "track-v1",
		Features:       map[string]any{"track_score": 14, "teleport": true},
		Label:          "confirmed_bot",
		LabelSource:    "manual_review",
		ModelTrainable: true,
	})
	memoryStore.AddRiskFeatureSnapshot(types.RiskFeatureSnapshot{
		AttemptID:      "attempt_candidate",
		ClientID:       "demo",
		Scene:          "login",
		ChallengeType:  types.CaptchaSlider,
		FeatureVersion: "track-v1",
		Features:       map[string]any{"track_score": 88},
		Label:          "captcha_pass",
		LabelSource:    "captcha_result",
		ModelTrainable: false,
	})

	response := request(t, server, http.MethodGet, "/api/v1/admin/risk-feature-snapshots/export?client_id=demo&limit=10", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/x-ndjson") {
		t.Fatalf("expected ndjson content type, got %q", contentType)
	}
	if count := response.Header().Get("X-Captcha-Export-Count"); count != "1" {
		t.Fatalf("expected one trainable export record, got count %q body=%s", count, response.Body.String())
	}
	records := decodeRiskFeatureExportRecords(t, response.Body.String())
	if len(records) != 1 || records[0].AttemptID != "attempt_trainable_bot" || !records[0].ModelTrainable {
		t.Fatalf("expected only trainable record by default, got %+v", records)
	}
	if records[0].SchemaVersion != riskFeatureExportSchemaVersion || records[0].Features["track_score"] == nil {
		t.Fatalf("expected schema and features in export record, got %+v", records[0])
	}

	response = request(t, server, http.MethodGet, "/api/v1/admin/risk-feature-snapshots/export?client_id=demo&trainable_only=false&limit=10", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if count := response.Header().Get("X-Captcha-Export-Count"); count != "2" {
		t.Fatalf("expected two export records when trainable_only=false, got count %q body=%s", count, response.Body.String())
	}
}

func testServer() (http.Handler, *store.MemoryStore, *token.Service) {
	return testServerWithOptions(Options{})
}

func testServerWithOptions(options Options) (http.Handler, *store.MemoryStore, *token.Service) {
	memoryStore := store.NewMemoryStore()
	captchaEngine := engine.New(2 * time.Minute)
	policyEvaluator := policy.NewEvaluator(memoryStore)
	tokenService := token.NewService(memoryStore, 2*time.Minute)
	server := NewServerWithOptions(captchaEngine, policyEvaluator, memoryStore, tokenService, slog.Default(), options)
	return server.Handler(), memoryStore, tokenService
}

type riskFeaturePanicStore struct {
	*store.MemoryStore
	featureWrites chan struct{}
}

func (s *riskFeaturePanicStore) AddRiskFeatureSnapshot(types.RiskFeatureSnapshot) types.RiskFeatureSnapshot {
	select {
	case s.featureWrites <- struct{}{}:
	default:
	}
	panic("risk feature store unavailable")
}

func request(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	return requestWithHeaders(t, handler, method, path, body, nil)
}

func requestWithHeaders(t *testing.T, handler http.Handler, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var payload bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&payload).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &payload)
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func multipartResourceUpload(t *testing.T, handler http.Handler, fields map[string]string, filename string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	var payload bytes.Buffer
	writer := multipart.NewWriter(&payload)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatalf("write multipart field: %v", err)
		}
	}
	part, err := writer.CreateFormFile("files", filename)
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatalf("write multipart file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/resources/upload", &payload)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, response *httptest.ResponseRecorder, out any) {
	t.Helper()
	if response.Code != http.StatusOK && response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	decodeAny(t, response, out)
}

func decodeAny(t *testing.T, response *httptest.ResponseRecorder, out any) {
	t.Helper()
	if err := json.NewDecoder(response.Body).Decode(out); err != nil {
		t.Fatalf("decode response: %v body=%s", err, response.Body.String())
	}
}

func assertNoKeys(t *testing.T, body map[string]any, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if _, ok := body[key]; ok {
			t.Fatalf("expected response not to expose %q, got %+v", key, body)
		}
	}
}

func decodeRiskFeatureExportRecords(t *testing.T, body string) []riskFeatureExportRecord {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(body), "\n")
	records := make([]riskFeatureExportRecord, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var record riskFeatureExportRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode export line %q: %v", line, err)
		}
		records = append(records, record)
	}
	return records
}

func hasRenderResource(resources []any, resourceType, id string) bool {
	for _, item := range resources {
		resource, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if resource["resource_type"] == resourceType && resource["id"] == id {
			return true
		}
	}
	return false
}

func hasFeatureResource(resources []map[string]any, id string) bool {
	for _, resource := range resources {
		if resource["id"] == id {
			return true
		}
	}
	return false
}

func trackForX(x int) []types.TrackPoint {
	return []types.TrackPoint{
		{X: 0, Y: 20, T: 0, Type: "start"},
		{X: float64(x / 4), Y: 23, T: 140, Type: "move"},
		{X: float64(x / 2), Y: 18, T: 280, Type: "move"},
		{X: float64(x * 3 / 4), Y: 24, T: 430, Type: "move"},
		{X: float64(x), Y: 21, T: 620, Type: "end"},
	}
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func syntheticTrackForSession(session types.ChallengeSession) []types.TrackPoint {
	track := make([]types.TrackPoint, 0, 10)
	for i := 0; i < 10; i++ {
		pointType := "move"
		if i == 0 {
			pointType = "start"
		}
		if i == 9 {
			pointType = "end"
		}
		track = append(track, types.TrackPoint{
			X:    float64(i) * float64(session.Answer.X) / 9,
			Y:    20,
			T:    int64(i * 100),
			Type: pointType,
		})
	}
	return track
}

func answerForSession(session types.ChallengeSession) types.VerifyAnswer {
	switch session.Type {
	case types.CaptchaGesture, types.CaptchaCurve, types.CaptchaCurve2, types.CaptchaCurve3:
		return types.VerifyAnswer{Points: session.Answer.Points}
	case types.CaptchaRotate, types.CaptchaRotateDegree:
		angle := session.Answer.Angle
		return types.VerifyAnswer{Angle: &angle}
	case types.CaptchaConcat:
		offset := session.Answer.Offset
		return types.VerifyAnswer{Offset: &offset}
	case types.CaptchaWordImageClick, types.CaptchaImageClick, types.CaptchaWordOrderClick, types.CaptchaJigsaw, types.CaptchaGridImageClick:
		return types.VerifyAnswer{Points: session.Answer.Points}
	default:
		x := session.Answer.X
		return types.VerifyAnswer{X: &x}
	}
}

func writeAPITestPNG(t *testing.T, c color.RGBA) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 40, 30))
	for y := 0; y < img.Bounds().Dy(); y++ {
		for x := 0; x < img.Bounds().Dx(); x++ {
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	path := t.TempDir() + "/background.png"
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write png: %v", err)
	}
	return path
}

func decodeAPITestPNGDataURL(t *testing.T, value string) image.Image {
	t.Helper()
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(value, prefix) {
		t.Fatalf("expected png data url, got %q", value)
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil {
		t.Fatalf("decode data url: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode png: %v", err)
	}
	return img
}

func assertAPITestPixel(t *testing.T, img image.Image, x, y int, expected color.RGBA) {
	t.Helper()
	r, g, b, a := img.At(x, y).RGBA()
	actual := color.RGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8)}
	if actual != expected {
		t.Fatalf("pixel %d,%d expected %+v, got %+v", x, y, expected, actual)
	}
}

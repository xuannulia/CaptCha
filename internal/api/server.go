package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	challengepkg "captcha/internal/challenge"
	"captcha/internal/configsync"
	"captcha/internal/engine"
	"captcha/internal/policy"
	resourcepkg "captcha/internal/resource"
	"captcha/internal/risk"
	"captcha/internal/secret"
	"captcha/internal/store"
	"captcha/internal/token"
	"captcha/internal/types"
)

type Server struct {
	engine  *engine.Engine
	policy  *policy.Evaluator
	store   store.Store
	tokens  *token.Service
	logger  *slog.Logger
	options Options
}

type Options struct {
	RuntimeBaseURL          string
	AdminToken              string
	MetricsToken            string
	ResourceUploadDir       string
	AllowedOrigins          []string
	AllowedReturnURLOrigins []string
	ChallengeEscalation     []types.CaptchaType
	ConfigNotifier          *configsync.Notifier
	RiskInferencer          risk.Inferencer
}

const maxSessionFailures = 5

var errForbiddenVerifyField = errors.New("forbidden verify field")

func NewServer(engine *engine.Engine, policy *policy.Evaluator, store store.Store, tokens *token.Service, logger *slog.Logger) *Server {
	return NewServerWithOptions(engine, policy, store, tokens, logger, Options{})
}

func NewServerWithOptions(engine *engine.Engine, policy *policy.Evaluator, store store.Store, tokens *token.Service, logger *slog.Logger, options Options) *Server {
	return &Server{engine: engine, policy: policy, store: store, tokens: tokens, logger: logger, options: options}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /metrics", s.handlePrometheusMetrics)
	mux.HandleFunc("POST /api/v1/challenge/sessions", s.handleCreateSession)
	mux.HandleFunc("GET /api/v1/challenge/sessions/{id}", s.handleGetSession)
	mux.HandleFunc("POST /api/v1/challenge/sessions/{id}/verify", s.handleVerifySession)
	mux.HandleFunc("POST /api/v1/challenge/sessions/{id}/refresh", s.handleRefreshSession)
	mux.HandleFunc("POST /api/v1/tickets/verify", s.handleVerifyTicket)
	mux.HandleFunc("POST /api/v1/policy/evaluate", s.handleEvaluatePolicy)
	mux.HandleFunc("GET /api/v1/admin/applications", s.handleListApplications)
	mux.HandleFunc("POST /api/v1/admin/applications", s.handleUpsertApplication)
	mux.HandleFunc("POST /api/v1/admin/applications/{client_id}/secret", s.handleRotateApplicationSecret)
	mux.HandleFunc("GET /api/v1/admin/route-policies", s.handleListRoutePolicies)
	mux.HandleFunc("POST /api/v1/admin/route-policies", s.handleUpsertRoutePolicy)
	mux.HandleFunc("POST /api/v1/admin/policy/simulate", s.handleSimulatePolicy)
	mux.HandleFunc("GET /api/v1/admin/ip-policies", s.handleListIPPolicies)
	mux.HandleFunc("POST /api/v1/admin/ip-policies", s.handleUpsertIPPolicy)
	mux.HandleFunc("GET /api/v1/admin/metrics", s.handleAdminMetrics)
	mux.HandleFunc("GET /api/v1/admin/resources", s.handleListResources)
	mux.HandleFunc("POST /api/v1/admin/resources", s.handleUpsertResource)
	mux.HandleFunc("POST /api/v1/admin/resources/upload", s.handleUploadResources)
	mux.HandleFunc("GET /api/v1/admin/audit-events", s.handleListAuditEvents)
	mux.HandleFunc("GET /api/v1/admin/risk-feature-snapshots", s.handleListRiskFeatureSnapshots)
	mux.HandleFunc("GET /api/v1/admin/risk-feature-snapshots/export", s.handleExportRiskFeatureSnapshots)
	mux.HandleFunc("POST /api/v1/admin/risk-feature-snapshots/{id}/label", s.handleUpdateRiskFeatureSnapshotLabel)
	mux.HandleFunc("GET /api/v1/admin/risk-model-versions", s.handleListRiskModelVersions)
	mux.HandleFunc("POST /api/v1/admin/risk-model-versions", s.handleUpsertRiskModelVersion)
	mux.HandleFunc("POST /api/v1/admin/risk-model-versions/{id}/activate", s.handleActivateRiskModelVersion)
	mux.HandleFunc("POST /api/v1/admin/risk-model-versions/{id}/rollback", s.handleRollbackRiskModelVersion)
	mux.HandleFunc("POST /api/v1/events/report", s.handleReportEvents)
	var handler http.Handler = mux
	if s.options.AdminToken != "" {
		handler = withAdminAuth(handler, s.options.AdminToken)
	}
	return withCORS(withJSON(handler), s.options.AllowedOrigins)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

type createSessionRequest struct {
	ClientID     string            `json:"client_id"`
	Scene        string            `json:"scene"`
	CaptchaType  types.CaptchaType `json:"captcha_type"`
	Route        string            `json:"route"`
	ReturnURL    string            `json:"return_url"`
	RequestNonce string            `json:"request_nonce"`
	ResourceTag  string            `json:"resource_tag"`
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req createSessionRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	if req.ClientID == "" || req.Scene == "" {
		writeError(w, http.StatusBadRequest, "CLIENT_AND_SCENE_REQUIRED")
		return
	}
	if !s.requireActiveApplication(w, req.ClientID) {
		return
	}
	returnURL, ok := s.normalizeReturnURL(req.ReturnURL)
	if !ok {
		writeError(w, http.StatusBadRequest, "INVALID_RETURN_URL")
		return
	}
	captchaType := resourcepkg.ChooseCaptchaType(s.store.ListResources(req.ClientID), req.CaptchaType, req.Scene, req.ResourceTag, nil)
	session, err := s.engine.NewSession(req.ClientID, req.Scene, captchaType)
	if err != nil {
		s.logger.Error("create session", "error", err)
		writeError(w, http.StatusInternalServerError, "CREATE_SESSION_FAILED")
		return
	}
	session.ChallengeEscalation = s.newSessionEscalation(nil)
	session.RenderPayload = resourcepkg.ApplyVisualsAndAttachForStore(s.store, session.RenderPayload, session.Answer, session.ClientID, session.Scene, session.Type, req.ResourceTag)
	session.Route = req.Route
	session.RequestNonce = req.RequestNonce
	session.ResourceTag = req.ResourceTag
	session.ReturnURL = returnURL
	s.store.PutSession(session)
	writeJSON(w, http.StatusCreated, map[string]any{
		"session_id":    session.ID,
		"challenge_url": s.challengeURL(session.ID, req.Route, req.RequestNonce, req.ResourceTag, returnURL),
		"captcha_type":  session.Type,
		"expire_in":     int(session.ExpiresAt.Sub(session.CreatedAt).Seconds()),
		"route":         session.Route,
		"request_nonce": session.RequestNonce,
		"resource_tag":  session.ResourceTag,
		"return_url":    session.ReturnURL,
	})
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	session, ok := s.loadSession(w, r)
	if !ok {
		return
	}
	if !s.requireActiveApplication(w, session.ClientID) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":    session.ID,
		"client_id":     session.ClientID,
		"scene":         session.Scene,
		"expire_at":     session.ExpiresAt,
		"route":         session.Route,
		"request_nonce": session.RequestNonce,
		"resource_tag":  session.ResourceTag,
		"return_url":    session.ReturnURL,
		"challenge":     session.RenderPayload,
	})
}

type verifySessionRequest struct {
	Answer      types.VerifyAnswer `json:"answer"`
	Track       []types.TrackPoint `json:"track"`
	Viewport    map[string]any     `json:"viewport"`
	RuntimeMeta map[string]any     `json:"runtime_meta"`
	Route       string             `json:"route"`
}

func (s *Server) handleVerifySession(w http.ResponseWriter, r *http.Request) {
	session, ok := s.loadSession(w, r)
	if !ok {
		return
	}
	if !s.requireActiveApplication(w, session.ClientID) {
		return
	}
	var req verifySessionRequest
	if err := readVerifySessionRequest(r, &req); err != nil {
		if errors.Is(err, errForbiddenVerifyField) {
			writeError(w, http.StatusBadRequest, "FORBIDDEN_VERIFY_FIELD")
			return
		}
		writeError(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	if !s.requireActiveSession(w, session) {
		return
	}
	route, routeOK := verifyRouteForSession(session, req.Route)
	if !routeOK {
		req.Route = route
		result := types.VerifyResult{
			OK:         false,
			Decision:   types.DecisionRetry,
			ReasonCode: "ROUTE_MISMATCH",
			TrackScore: types.TrackScore{Bucket: "low", PointCount: len(req.Track)},
		}
		s.recordFailedVerification(w, session, req, result)
		return
	}
	req.Route = route
	if session.RequestNonce != "" && requestNonceFromMeta(req.RuntimeMeta) != session.RequestNonce {
		result := types.VerifyResult{
			OK:         false,
			Decision:   types.DecisionRetry,
			ReasonCode: "REQUEST_NONCE_MISMATCH",
			TrackScore: types.TrackScore{Bucket: "low", PointCount: len(req.Track)},
		}
		s.recordFailedVerification(w, session, req, result)
		return
	}
	result := s.engine.Verify(session, req.Answer, req.Track)
	if !result.OK {
		s.recordFailedVerification(w, session, req, result)
		return
	}
	ticket, err := s.tokens.Issue(session.ClientID, session.Scene, req.Route, session.RequestNonce, session.IPHash, session.UserAgentHash)
	if err != nil {
		s.logger.Error("issue ticket", "error", err)
		writeError(w, http.StatusInternalServerError, "ISSUE_TICKET_FAILED")
		return
	}
	session.Status = types.SessionVerified
	s.store.UpdateSession(session)
	s.recordRiskFeatureSnapshot(session, req, result)
	s.store.AddAuditEvent(types.AuditEvent{
		ClientID:       session.ClientID,
		Scene:          session.Scene,
		Route:          req.Route,
		AccountIDHash:  session.AccountIDHash,
		DeviceIDHash:   session.DeviceIDHash,
		Action:         result.Decision,
		DecisionReason: result.ReasonCode,
		ChallengeType:  session.Type,
		Result:         "pass",
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"decision":      result.Decision,
		"ticket":        ticket.Value,
		"expire_in":     int(ticket.ExpiresAt.Sub(ticket.CreatedAt).Seconds()),
		"route":         req.Route,
		"request_nonce": session.RequestNonce,
		"resource_tag":  session.ResourceTag,
		"return_url":    session.ReturnURL,
	})
}

func (s *Server) handleEvaluatePolicy(w http.ResponseWriter, r *http.Request) {
	var req types.PolicyEvaluateRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	if req.ClientID == "" {
		req.ClientID = "demo"
	}
	if decision, blocked := s.applicationPolicyDecision(req); blocked {
		s.store.AddAuditEvent(types.AuditEvent{
			ClientID:       req.ClientID,
			Scene:          req.Scene,
			Route:          req.Path,
			AccountIDHash:  req.AccountIDHash,
			DeviceIDHash:   req.DeviceIDHash,
			Action:         decision.Action,
			DecisionReason: decision.Reason,
			Result:         string(decision.Action),
		})
		writeJSON(w, http.StatusOK, decision)
		return
	}
	if !s.requireClientSecret(w, r, req.ClientID, false) {
		return
	}
	if req.IP == "" {
		req.IP = remoteIP(r)
	}
	if decision, ok := s.ipPolicyDecision(req); ok {
		s.auditPolicyDecision(req, decision)
		writeJSON(w, http.StatusOK, decision)
		return
	}
	if req.Clearance != "" {
		if clearance, err := s.store.VerifyClearance(req.Clearance, req.ClientID, req.Scene, hashValue(req.IP), hashValue(req.UserAgent), req.AccountIDHash, req.DeviceIDHash); err == nil {
			decision := types.PolicyDecision{
				Action:              types.DecisionAllow,
				Reason:              "CLEARANCE_VALID",
				Scene:               clearance.Scene,
				ClearanceToken:      clearance.Value,
				ClearanceTTLSeconds: int(time.Until(clearance.ExpiresAt).Seconds()),
			}
			s.auditPolicyDecision(req, decision)
			writeJSON(w, http.StatusOK, decision)
			return
		}
	}
	if req.Ticket != "" {
		if _, err := s.store.VerifyTicket(req.Ticket, req.ClientID, req.Scene, req.Path, req.RequestNonce, hashValue(req.IP), hashValue(req.UserAgent), true); err == nil {
			s.store.AddAuditEvent(types.AuditEvent{
				ClientID:       req.ClientID,
				Scene:          req.Scene,
				Route:          req.Path,
				AccountIDHash:  req.AccountIDHash,
				DeviceIDHash:   req.DeviceIDHash,
				Action:         types.DecisionAllow,
				DecisionReason: "TICKET_CONSUMED",
				Result:         "allow",
			})
			writeJSON(w, http.StatusOK, s.withClearance(types.PolicyDecision{Action: types.DecisionAllow, Reason: "TICKET_CONSUMED", Scene: req.Scene}, req))
			return
		} else {
			reason := errorCode(err)
			s.store.AddAuditEvent(types.AuditEvent{
				ClientID:       req.ClientID,
				Scene:          req.Scene,
				Route:          req.Path,
				AccountIDHash:  req.AccountIDHash,
				DeviceIDHash:   req.DeviceIDHash,
				Action:         types.DecisionBlock,
				DecisionReason: reason,
				Result:         "block",
			})
			writeJSON(w, http.StatusOK, types.PolicyDecision{Action: types.DecisionBlock, Reason: reason, Scene: req.Scene})
			return
		}
	}

	if err := risk.EnrichPolicyRequest(r.Context(), s.options.RiskInferencer, s.store, &req); err != nil {
		s.logger.Warn("risk inference failed", "client_id", req.ClientID, "error", err)
	}
	evaluation := s.policy.Evaluate(req)
	decision := policyDecisionFromEvaluation(req, evaluation)
	if evaluation.Action == types.DecisionChallenge {
		scene := req.Scene
		if evaluation.Route != nil && evaluation.Route.Scene != "" {
			scene = evaluation.Route.Scene
		}
		session, err := s.engine.NewSession(req.ClientID, scene, evaluation.ChallengeType)
		if err != nil {
			s.logger.Error("policy challenge session", "error", err)
			writeError(w, http.StatusInternalServerError, "CREATE_SESSION_FAILED")
			return
		}
		session.ChallengeEscalation = s.newSessionEscalation(evaluation.ChallengeEscalation)
		session.RenderPayload = resourcepkg.ApplyVisualsAndAttachForStore(s.store, session.RenderPayload, session.Answer, session.ClientID, session.Scene, session.Type, req.ResourceTag)
		session.Route = req.Path
		session.RequestNonce = req.RequestNonce
		session.ResourceTag = req.ResourceTag
		session.IPHash = hashValue(req.IP)
		session.UserAgentHash = hashValue(req.UserAgent)
		session.AccountIDHash = req.AccountIDHash
		session.DeviceIDHash = req.DeviceIDHash
		s.store.PutSession(session)
		decision.SessionID = session.ID
		decision.ChallengeURL = s.challengeURL(session.ID, req.Path, req.RequestNonce, req.ResourceTag, "")
		decision.TTLSeconds = int(session.ExpiresAt.Sub(session.CreatedAt).Seconds())
	}
	s.store.AddAuditEvent(types.AuditEvent{
		ClientID:       req.ClientID,
		Scene:          decision.Scene,
		Route:          req.Path,
		AccountIDHash:  req.AccountIDHash,
		DeviceIDHash:   req.DeviceIDHash,
		Action:         evaluation.Action,
		DecisionReason: evaluation.Reason,
		ChallengeType:  evaluation.ChallengeType,
		Result:         string(evaluation.Action),
	})
	writeJSON(w, http.StatusOK, decision)
}

type policySimulationResponse struct {
	DryRun             bool                        `json:"dry_run"`
	Request            types.PolicyEvaluateRequest `json:"request"`
	Decision           types.PolicyDecision        `json:"decision"`
	Route              *types.RoutePolicy          `json:"route,omitempty"`
	RateLimitEvaluated bool                        `json:"rate_limit_evaluated"`
	SideEffects        []string                    `json:"side_effects"`
	Notes              []string                    `json:"notes,omitempty"`
}

func (s *Server) handleSimulatePolicy(w http.ResponseWriter, r *http.Request) {
	var req types.PolicyEvaluateRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	if req.ClientID == "" {
		req.ClientID = "demo"
	}
	if req.IP == "" {
		req.IP = remoteIP(r)
	}
	if decision, blocked := s.applicationPolicyDecision(req); blocked {
		writeJSON(w, http.StatusOK, policySimulationResponse{
			DryRun:             true,
			Request:            req,
			Decision:           decision,
			RateLimitEvaluated: true,
			SideEffects:        policySimulationSideEffects(),
			Notes:              []string{"application_gate"},
		})
		return
	}
	evaluation := s.policy.EvaluateDryRun(req)
	decision := policyDecisionFromEvaluation(req, evaluation)
	rateLimitEvaluated := true
	notes := make([]string, 0, 1)
	if evaluation.Route != nil && strings.EqualFold(evaluation.Route.Mode, "rate_limit") {
		rateLimitEvaluated = false
		notes = append(notes, "rate_limit_counter_not_read_or_incremented")
	}
	writeJSON(w, http.StatusOK, policySimulationResponse{
		DryRun:             true,
		Request:            req,
		Decision:           decision,
		Route:              evaluation.Route,
		RateLimitEvaluated: rateLimitEvaluated,
		SideEffects:        policySimulationSideEffects(),
		Notes:              notes,
	})
}

func policyDecisionFromEvaluation(req types.PolicyEvaluateRequest, evaluation policy.Evaluation) types.PolicyDecision {
	decision := types.PolicyDecision{
		Action:        evaluation.Action,
		Reason:        evaluation.Reason,
		Scene:         req.Scene,
		ChallengeType: evaluation.ChallengeType,
		TTLSeconds:    evaluation.TTLSeconds,
	}
	if evaluation.Route != nil {
		decision.Scene = evaluation.Route.Scene
	}
	return decision
}

func (s *Server) ipPolicyDecision(req types.PolicyEvaluateRequest) (types.PolicyDecision, bool) {
	action, reason, ok := s.policy.EvaluateIP(req)
	if !ok {
		return types.PolicyDecision{}, false
	}
	return types.PolicyDecision{Action: action, Reason: reason, Scene: req.Scene}, true
}

func (s *Server) auditPolicyDecision(req types.PolicyEvaluateRequest, decision types.PolicyDecision) {
	s.store.AddAuditEvent(types.AuditEvent{
		ClientID:       req.ClientID,
		Scene:          firstNonEmpty(decision.Scene, req.Scene),
		Route:          req.Path,
		AccountIDHash:  req.AccountIDHash,
		DeviceIDHash:   req.DeviceIDHash,
		Action:         decision.Action,
		DecisionReason: decision.Reason,
		ChallengeType:  decision.ChallengeType,
		Result:         string(decision.Action),
	})
}

func (s *Server) withClearance(decision types.PolicyDecision, req types.PolicyEvaluateRequest) types.PolicyDecision {
	scene := firstNonEmpty(decision.Scene, req.Scene)
	if scene == "" || s.tokens == nil {
		return decision
	}
	ipHash := hashValue(req.IP)
	userAgentHash := hashValue(req.UserAgent)
	if ipHash == "" || userAgentHash == "" {
		return decision
	}
	clearance, err := s.tokens.IssueClearance(req.ClientID, scene, ipHash, userAgentHash, req.AccountIDHash, req.DeviceIDHash)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("issue clearance", "client_id", req.ClientID, "scene", scene, "error", err)
		}
		return decision
	}
	if decision.Scene == "" {
		decision.Scene = scene
	}
	decision.ClearanceToken = clearance.Value
	decision.ClearanceTTLSeconds = ttlSeconds(clearance.ExpiresAt, clearance.CreatedAt)
	return decision
}

func (s *Server) addClearanceFields(body map[string]any, req types.PolicyEvaluateRequest, alreadyHashedContext bool) {
	if s.tokens == nil || req.Scene == "" {
		return
	}
	ipHash := hashValue(req.IP)
	userAgentHash := hashValue(req.UserAgent)
	if alreadyHashedContext {
		ipHash = req.IP
		userAgentHash = req.UserAgent
	}
	if ipHash == "" || userAgentHash == "" {
		return
	}
	clearance, err := s.tokens.IssueClearance(req.ClientID, req.Scene, ipHash, userAgentHash, req.AccountIDHash, req.DeviceIDHash)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("issue clearance", "client_id", req.ClientID, "scene", req.Scene, "error", err)
		}
		return
	}
	body["clearance_token"] = clearance.Value
	body["clearance_expire_at"] = clearance.ExpiresAt
	body["clearance_ttl_seconds"] = ttlSeconds(clearance.ExpiresAt, clearance.CreatedAt)
}

func ttlSeconds(expiresAt, createdAt time.Time) int {
	ttl := int(expiresAt.Sub(createdAt).Seconds())
	if ttl < 0 {
		return 0
	}
	return ttl
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func policySimulationSideEffects() []string {
	return []string{
		"no_ticket_consumed",
		"no_challenge_session_created",
		"no_rate_counter_incremented",
		"no_audit_event_written",
	}
}

func (s *Server) handleListApplications(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.store.ListApplications()})
}

func (s *Server) handleUpsertApplication(w http.ResponseWriter, r *http.Request) {
	var application types.Application
	if err := readJSON(r, &application); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	if application.ClientID == "" || application.Name == "" {
		writeError(w, http.StatusBadRequest, "CLIENT_AND_NAME_REQUIRED")
		return
	}
	saved := s.store.UpsertApplication(application)
	s.recordConfigAuditEvent(r, saved.ClientID, "CONFIG_APPLICATION_UPSERT", r.URL.Path, "", "")
	s.notifyConfigChanged()
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleRotateApplicationSecret(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("client_id")
	if clientID == "" {
		writeError(w, http.StatusBadRequest, "CLIENT_REQUIRED")
		return
	}
	value, hash, err := secret.NewClientSecret()
	if err != nil {
		s.logger.Error("generate client secret", "error", err)
		writeError(w, http.StatusInternalServerError, "SECRET_GENERATION_FAILED")
		return
	}
	application, err := s.store.RotateApplicationSecret(clientID, hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "APPLICATION_NOT_FOUND")
			return
		}
		s.logger.Error("rotate client secret", "error", err)
		writeError(w, http.StatusInternalServerError, "SECRET_ROTATION_FAILED")
		return
	}
	s.recordConfigAuditEvent(r, application.ClientID, "CONFIG_APPLICATION_SECRET_ROTATE", r.URL.Path, "", "")
	writeJSON(w, http.StatusOK, map[string]any{
		"client_secret": value,
		"application":   application,
	})
}

func (s *Server) handleListRoutePolicies(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.store.ListRoutePolicies(r.URL.Query().Get("client_id"))})
}

func (s *Server) handleUpsertRoutePolicy(w http.ResponseWriter, r *http.Request) {
	var route types.RoutePolicy
	if err := readJSON(r, &route); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	if route.ClientID == "" {
		route.ClientID = "demo"
	}
	saved := s.store.UpsertRoutePolicy(route)
	s.recordConfigAuditEvent(r, saved.ClientID, "CONFIG_ROUTE_POLICY_UPSERT", saved.PathPattern, saved.Scene, saved.ChallengeType)
	s.notifyConfigChanged()
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleListIPPolicies(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.store.ListIPPolicies(r.URL.Query().Get("client_id"))})
}

func (s *Server) handleUpsertIPPolicy(w http.ResponseWriter, r *http.Request) {
	var policy types.IPPolicy
	if err := readJSON(r, &policy); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	if policy.ClientID == "" {
		policy.ClientID = "demo"
	}
	saved := s.store.UpsertIPPolicy(policy)
	s.recordConfigAuditEvent(r, saved.ClientID, "CONFIG_IP_POLICY_UPSERT", r.URL.Path, "", "")
	s.notifyConfigChanged()
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleListResources(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.store.ListResources(r.URL.Query().Get("client_id"))})
}

func (s *Server) handleUpsertResource(w http.ResponseWriter, r *http.Request) {
	var resource types.CaptchaResource
	if err := readJSON(r, &resource); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	normalized, err := resourcepkg.ValidateAndNormalize(resource)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_RESOURCE")
		return
	}
	saved := s.store.UpsertResource(normalized)
	s.recordConfigAuditEvent(r, saved.ClientID, "CONFIG_RESOURCE_UPSERT", r.URL.Path, saved.Scene, saved.CaptchaType)
	s.notifyConfigChanged()
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleListAuditEvents(w http.ResponseWriter, r *http.Request) {
	filter := auditEventFilterFromQuery(r)
	limit := normalizedListLimit(filter.Limit)
	filter.Limit = limit + 1
	items := s.store.ListAuditEventsFiltered(filter)
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": filter.Offset, "has_more": hasMore})
}

func (s *Server) handleListRiskFeatureSnapshots(w http.ResponseWriter, r *http.Request) {
	filter := riskFeatureSnapshotFilterFromQuery(r)
	limit := normalizedListLimit(filter.Limit)
	filter.Limit = limit + 1
	items := s.store.ListRiskFeatureSnapshotsFiltered(filter)
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": filter.Offset, "has_more": hasMore})
}

type updateRiskFeatureLabelRequest struct {
	Label          string `json:"label"`
	LabelSource    string `json:"label_source"`
	ModelTrainable bool   `json:"model_trainable"`
}

func (s *Server) handleUpdateRiskFeatureSnapshotLabel(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "FEATURE_ID_REQUIRED")
		return
	}
	var req updateRiskFeatureLabelRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	label, labelSource, ok := normalizeRiskFeatureLabelUpdate(req)
	if !ok {
		writeError(w, http.StatusBadRequest, "INVALID_RISK_FEATURE_LABEL")
		return
	}
	snapshot, err := s.store.UpdateRiskFeatureSnapshotLabel(id, label, labelSource, req.ModelTrainable)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "RISK_FEATURE_SNAPSHOT_NOT_FOUND")
			return
		}
		s.logger.Error("update risk feature label", "error", err)
		writeError(w, http.StatusInternalServerError, "RISK_FEATURE_LABEL_UPDATE_FAILED")
		return
	}
	s.recordRiskFeatureLabelAuditEvent(r, snapshot)
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) handleListRiskModelVersions(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	writeJSON(w, http.StatusOK, map[string]any{"items": s.store.ListRiskModelVersions(r.URL.Query().Get("name"), limit)})
}

func (s *Server) handleUpsertRiskModelVersion(w http.ResponseWriter, r *http.Request) {
	var version types.RiskModelVersion
	if err := readJSON(r, &version); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	if !validRiskModelVersion(version) {
		writeError(w, http.StatusBadRequest, "INVALID_RISK_MODEL_VERSION")
		return
	}
	if strings.EqualFold(version.Status, "active") {
		writeError(w, http.StatusBadRequest, "USE_ACTIVATE_ENDPOINT")
		return
	}
	saved := s.store.UpsertRiskModelVersion(version)
	s.recordConfigAuditEvent(r, "platform", "CONFIG_RISK_MODEL_UPSERT", r.URL.Path, "", "")
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleActivateRiskModelVersion(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "MODEL_ID_REQUIRED")
		return
	}
	version, err := s.store.ActivateRiskModelVersion(id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "RISK_MODEL_VERSION_NOT_FOUND")
			return
		}
		s.logger.Error("activate risk model version", "error", err)
		writeError(w, http.StatusInternalServerError, "RISK_MODEL_ACTIVATION_FAILED")
		return
	}
	s.recordConfigAuditEvent(r, "platform", "CONFIG_RISK_MODEL_ACTIVATE", r.URL.Path, "", "")
	writeJSON(w, http.StatusOK, version)
}

func (s *Server) handleRollbackRiskModelVersion(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "MODEL_ID_REQUIRED")
		return
	}
	version, err := s.store.RollbackRiskModelVersion(id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "RISK_MODEL_ROLLBACK_TARGET_NOT_FOUND")
			return
		}
		s.logger.Error("rollback risk model version", "error", err)
		writeError(w, http.StatusInternalServerError, "RISK_MODEL_ROLLBACK_FAILED")
		return
	}
	s.recordConfigAuditEvent(r, "platform", "CONFIG_RISK_MODEL_ROLLBACK", r.URL.Path, "", "")
	writeJSON(w, http.StatusOK, version)
}

func (s *Server) handleReportEvents(w http.ResponseWriter, r *http.Request) {
	var batch types.EventBatch
	if err := readJSON(r, &batch); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	if !validEventBatch(w, batch) {
		return
	}
	if !s.requireEventClientSecrets(w, r, batch) {
		return
	}
	accepted := 0
	for _, event := range batch.Events {
		event = sanitizeReportedAuditEvent(event)
		s.store.AddAuditEvent(event)
		accepted++
	}
	writeJSON(w, http.StatusOK, types.ReportResult{Accepted: accepted})
}

func (s *Server) handleRefreshSession(w http.ResponseWriter, r *http.Request) {
	session, ok := s.loadSession(w, r)
	if !ok {
		return
	}
	if !s.requireActiveApplication(w, session.ClientID) {
		return
	}
	if !s.requireActiveSession(w, session) {
		return
	}
	refreshed, err := s.engine.Refresh(session)
	if err != nil {
		s.logger.Error("refresh session", "error", err)
		writeError(w, http.StatusInternalServerError, "REFRESH_FAILED")
		return
	}
	refreshed.RenderPayload = resourcepkg.ApplyVisualsAndAttachForStore(s.store, refreshed.RenderPayload, refreshed.Answer, refreshed.ClientID, refreshed.Scene, refreshed.Type, refreshed.ResourceTag)
	s.store.UpdateSession(refreshed)
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":    refreshed.ID,
		"expire_at":     refreshed.ExpiresAt,
		"route":         refreshed.Route,
		"request_nonce": refreshed.RequestNonce,
		"resource_tag":  refreshed.ResourceTag,
		"return_url":    refreshed.ReturnURL,
		"challenge":     refreshed.RenderPayload,
	})
}

func (s *Server) recordRiskFeatureSnapshot(session types.ChallengeSession, req verifySessionRequest, result types.VerifyResult) {
	features := map[string]any{
		"answer_has_angle":    req.Answer.Angle != nil,
		"answer_has_offset":   req.Answer.Offset != nil,
		"answer_has_points":   len(req.Answer.Points) > 0,
		"answer_has_x":        req.Answer.X != nil,
		"answer_has_y":        req.Answer.Y != nil,
		"decision":            string(result.Decision),
		"duration_ms":         result.TrackScore.DurationMS,
		"failure_count":       session.FailureCount,
		"point_count":         result.TrackScore.PointCount,
		"reason_code":         result.ReasonCode,
		"result_ok":           result.OK,
		"track_bucket":        result.TrackScore.Bucket,
		"track_reason_count":  len(result.TrackScore.Reasons),
		"track_score":         result.TrackScore.Score,
		"track_submit_points": len(req.Track),
	}
	if resources := resourceFeatureRefs(session.RenderPayload); len(resources) > 0 {
		features["resources"] = resources
	}
	for key, value := range engine.ExtractTrackFeatures(req.Track) {
		features[key] = value
	}
	snapshot := types.RiskFeatureSnapshot{
		AttemptID:      session.ID,
		ClientID:       session.ClientID,
		Scene:          session.Scene,
		ChallengeType:  session.Type,
		FeatureVersion: "track-v1",
		Features:       features,
		Label:          riskFeatureLabel(result),
		LabelSource:    "captcha_result",
		ModelTrainable: false,
	}
	go func(snapshot types.RiskFeatureSnapshot) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("risk feature snapshot panic", "panic", recovered)
			}
		}()
		s.attachRiskModelShadowScore(&snapshot)
		s.store.AddRiskFeatureSnapshot(snapshot)
	}(snapshot)
}

func resourceFeatureRefs(payload types.RenderPayload) []map[string]any {
	if payload.Parameters == nil {
		return nil
	}
	value, ok := payload.Parameters["resources"]
	if !ok {
		return nil
	}
	switch resources := value.(type) {
	case []resourcepkg.RenderResource:
		refs := make([]map[string]any, 0, len(resources))
		for _, item := range resources {
			if ref := resourceFeatureRef(item.ID, item.ResourceType, item.StorageType, string(item.CaptchaType), item.Scene, item.Tag); ref != nil {
				refs = append(refs, ref)
			}
		}
		return refs
	case []any:
		refs := make([]map[string]any, 0, len(resources))
		for _, item := range resources {
			switch typed := item.(type) {
			case map[string]any:
				if ref := resourceFeatureRef(
					stringValue(typed["id"]),
					stringValue(typed["resource_type"]),
					stringValue(typed["storage_type"]),
					stringValue(typed["captcha_type"]),
					stringValue(typed["scene"]),
					stringValue(typed["tag"]),
				); ref != nil {
					refs = append(refs, ref)
				}
			}
		}
		return refs
	default:
		data, err := json.Marshal(value)
		if err != nil {
			return nil
		}
		var decodedResources []map[string]any
		if err := json.Unmarshal(data, &decodedResources); err != nil {
			return nil
		}
		refs := make([]map[string]any, 0, len(decodedResources))
		for _, item := range decodedResources {
			if ref := resourceFeatureRef(
				stringValue(item["id"]),
				stringValue(item["resource_type"]),
				stringValue(item["storage_type"]),
				stringValue(item["captcha_type"]),
				stringValue(item["scene"]),
				stringValue(item["tag"]),
			); ref != nil {
				refs = append(refs, ref)
			}
		}
		return refs
	}
}

func resourceFeatureRef(id, resourceType, storageType, captchaType, scene, tag string) map[string]any {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	ref := map[string]any{
		"id": id,
	}
	if resourceType = strings.TrimSpace(resourceType); resourceType != "" {
		ref["resource_type"] = resourceType
	}
	if storageType = strings.TrimSpace(storageType); storageType != "" {
		ref["storage_type"] = storageType
	}
	if captchaType = strings.TrimSpace(captchaType); captchaType != "" {
		ref["captcha_type"] = captchaType
	}
	if scene = strings.TrimSpace(scene); scene != "" {
		ref["scene"] = scene
	}
	if tag = strings.TrimSpace(tag); tag != "" {
		ref["tag"] = tag
	}
	return ref
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case types.CaptchaType:
		return string(typed)
	default:
		return ""
	}
}

func (s *Server) recordConfigAuditEvent(r *http.Request, clientID, reason, target, scene string, challengeType types.CaptchaType) {
	if clientID == "" {
		clientID = "demo"
	}
	s.store.AddAuditEvent(types.AuditEvent{
		ClientID:       clientID,
		Scene:          scene,
		Route:          target,
		IPHash:         hashValue(remoteIP(r)),
		Action:         types.DecisionObserve,
		DecisionReason: reason,
		ChallengeType:  challengeType,
		Result:         "config_changed",
	})
}

func (s *Server) recordRiskFeatureLabelAuditEvent(r *http.Request, snapshot types.RiskFeatureSnapshot) {
	s.store.AddAuditEvent(types.AuditEvent{
		ClientID:       snapshot.ClientID,
		Scene:          snapshot.Scene,
		Route:          r.URL.Path,
		IPHash:         hashValue(remoteIP(r)),
		Action:         types.DecisionObserve,
		DecisionReason: "RISK_FEATURE_LABEL_UPDATE",
		ChallengeType:  snapshot.ChallengeType,
		Result:         "training_feedback",
	})
}

func (s *Server) recordFailedVerification(w http.ResponseWriter, session types.ChallengeSession, req verifySessionRequest, result types.VerifyResult) {
	session.FailureCount++
	attemptedSession := session
	nextType := session.Type
	if result.Decision == types.DecisionChallengeHarder {
		nextType = challengepkg.HarderType(session.Type, s.sessionEscalation(session))
		session.Type = nextType
	}
	if session.FailureCount >= maxSessionFailures {
		session.Status = types.SessionExpired
		attemptedSession.Status = types.SessionExpired
		result.Decision = types.DecisionBlock
		result.ReasonCode = "TOO_MANY_FAILURES"
		if result.TrackScore.Bucket == "" {
			result.TrackScore.Bucket = "low"
		}
	}
	s.store.UpdateSession(session)
	s.recordRiskFeatureSnapshot(attemptedSession, req, result)
	auditResult := "retry"
	if result.Decision == types.DecisionBlock {
		auditResult = "block"
	}
	s.store.AddAuditEvent(types.AuditEvent{
		ClientID:       session.ClientID,
		Scene:          session.Scene,
		Route:          req.Route,
		AccountIDHash:  session.AccountIDHash,
		DeviceIDHash:   session.DeviceIDHash,
		Action:         result.Decision,
		DecisionReason: result.ReasonCode,
		ChallengeType:  session.Type,
		Result:         auditResult,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           false,
		"decision":     result.Decision,
		"reason_code":  result.ReasonCode,
		"can_refresh":  canRefreshAfterFailure(session, result),
		"captcha_type": nextType,
	})
}

func canRefreshAfterFailure(session types.ChallengeSession, result types.VerifyResult) bool {
	if session.Status != types.SessionActive || session.FailureCount >= maxSessionFailures {
		return false
	}
	return result.Decision == types.DecisionChallengeHarder || session.FailureCount >= 3
}

func (s *Server) newSessionEscalation(routeEscalation []types.CaptchaType) []types.CaptchaType {
	if len(routeEscalation) > 0 {
		return challengepkg.NormalizeConfiguredEscalation(routeEscalation)
	}
	return challengepkg.NormalizeConfiguredEscalation(s.options.ChallengeEscalation)
}

func (s *Server) sessionEscalation(session types.ChallengeSession) []types.CaptchaType {
	if len(session.ChallengeEscalation) > 0 {
		return session.ChallengeEscalation
	}
	return s.options.ChallengeEscalation
}

func (s *Server) challengeURL(sessionID, route, requestNonce, resourceTag, returnURL string) string {
	values := url.Values{"session_id": []string{sessionID}}
	if route != "" {
		values.Set("route", route)
	}
	if requestNonce != "" {
		values.Set("request_nonce", requestNonce)
	}
	if resourceTag != "" {
		values.Set("resource_tag", resourceTag)
	}
	if returnURL != "" {
		values.Set("return_url", returnURL)
	}
	path := "/challenge?" + values.Encode()
	if s.options.RuntimeBaseURL == "" {
		return path
	}
	return strings.TrimRight(s.options.RuntimeBaseURL, "/") + path
}

func (s *Server) normalizeReturnURL(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", true
	}
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil {
		return "", false
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return "", false
	}
	allowedOrigins := s.options.AllowedReturnURLOrigins
	if len(allowedOrigins) == 0 {
		allowedOrigins = s.options.AllowedOrigins
	}
	if !returnURLAllowedOrigin(parsed, normalizeAllowedOrigins(allowedOrigins)) {
		return "", false
	}
	return parsed.String(), true
}

func returnURLAllowedOrigin(returnURL *url.URL, allowedOrigins []string) bool {
	origin := canonicalOrigin(returnURL)
	for _, allowed := range allowedOrigins {
		if allowed == "*" {
			return true
		}
		parsed, err := url.Parse(strings.TrimRight(allowed, "/"))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		if strings.EqualFold(origin, canonicalOrigin(parsed)) {
			return true
		}
	}
	return false
}

func canonicalOrigin(value *url.URL) string {
	return strings.ToLower(value.Scheme) + "://" + strings.ToLower(value.Host)
}

func (s *Server) notifyConfigChanged() {
	if s.options.ConfigNotifier != nil {
		s.options.ConfigNotifier.Notify()
	}
}

func riskFeatureLabel(result types.VerifyResult) string {
	if result.OK {
		return "captcha_pass"
	}
	return "captcha_retry"
}

type verifyTicketRequest struct {
	Ticket        string `json:"ticket"`
	ClientID      string `json:"client_id"`
	Scene         string `json:"scene"`
	Route         string `json:"route"`
	RequestNonce  string `json:"request_nonce"`
	IPHash        string `json:"ip_hash"`
	UserAgentHash string `json:"user_agent_hash"`
	AccountIDHash string `json:"account_id_hash"`
	DeviceIDHash  string `json:"device_id_hash"`
	Consume       bool   `json:"consume"`
}

func (s *Server) handleVerifyTicket(w http.ResponseWriter, r *http.Request) {
	var req verifyTicketRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	if req.Ticket == "" || req.ClientID == "" || req.Scene == "" {
		writeError(w, http.StatusBadRequest, "TICKET_CLIENT_SCENE_REQUIRED")
		return
	}
	if reason, blocked := s.applicationTicketRejection(req.ClientID); blocked {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":  false,
			"reason": reason,
		})
		return
	}
	if !s.requireClientSecret(w, r, req.ClientID, false) {
		return
	}
	ticket, err := s.store.VerifyTicket(req.Ticket, req.ClientID, req.Scene, req.Route, req.RequestNonce, req.IPHash, req.UserAgentHash, req.Consume)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":  false,
			"reason": errorCode(err),
		})
		return
	}
	body := map[string]any{
		"valid":           true,
		"client_id":       ticket.ClientID,
		"scene":           ticket.Scene,
		"route":           ticket.Route,
		"request_nonce":   ticket.RequestNonce,
		"ip_hash":         ticket.IPHash,
		"user_agent_hash": ticket.UserAgentHash,
		"expire_at":       ticket.ExpiresAt,
		"consumed":        req.Consume,
	}
	if req.Consume {
		s.addClearanceFields(body, types.PolicyEvaluateRequest{
			ClientID:      req.ClientID,
			Scene:         req.Scene,
			IP:            req.IPHash,
			UserAgent:     req.UserAgentHash,
			AccountIDHash: req.AccountIDHash,
			DeviceIDHash:  req.DeviceIDHash,
		}, true)
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) loadSession(w http.ResponseWriter, r *http.Request) (types.ChallengeSession, bool) {
	id := r.PathValue("id")
	session, err := s.store.GetSession(id)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     false,
			"reason": errorCode(err),
		})
		return types.ChallengeSession{}, false
	}
	return session, true
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func readVerifySessionRequest(r *http.Request, req *verifySessionRequest) error {
	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if containsForbiddenVerifyField(data) {
		return errForbiddenVerifyField
	}
	return json.Unmarshal(data, req)
}

func containsForbiddenVerifyField(data []byte) bool {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return false
	}
	return containsForbiddenVerifyKey(value)
}

func containsForbiddenVerifyKey(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if forbiddenVerifyKey(key) || containsForbiddenVerifyKey(nested) {
				return true
			}
		}
	case []any:
		for _, nested := range typed {
			if containsForbiddenVerifyKey(nested) {
				return true
			}
		}
	}
	return false
}

func forbiddenVerifyKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "tolerance", "target", "answer_seed",
		"verify_rule", "verify_rules", "score_rule", "score_rules", "scoring_rule", "scoring_rules",
		"threshold", "thresholds", "score_threshold", "pass_threshold", "risk_threshold", "track_threshold", "answer_threshold", "verify_threshold", "decision_threshold",
		"answer_tolerance", "target_tolerance", "max_deviation",
		"answer_score", "track_score", "risk_score", "model_score", "min_score", "max_score":
		return true
	default:
		return false
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{
		"ok":    false,
		"error": code,
	})
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "NOT_FOUND"
	case errors.Is(err, store.ErrExpired):
		return "EXPIRED"
	case errors.Is(err, store.ErrConsumed):
		return "CONSUMED"
	default:
		return "UNKNOWN"
	}
}

func (s *Server) requireEventClientSecrets(w http.ResponseWriter, r *http.Request, batch types.EventBatch) bool {
	seen := make(map[string]struct{})
	for _, event := range batch.Events {
		if _, ok := seen[event.ClientID]; ok {
			continue
		}
		seen[event.ClientID] = struct{}{}
		if !s.requireClientSecret(w, r, event.ClientID, true) {
			return false
		}
	}
	return true
}

func validEventBatch(w http.ResponseWriter, batch types.EventBatch) bool {
	for _, event := range batch.Events {
		if strings.TrimSpace(event.ClientID) == "" {
			writeError(w, http.StatusBadRequest, "EVENT_CLIENT_ID_REQUIRED")
			return false
		}
	}
	return true
}

func sanitizeReportedAuditEvent(event types.AuditEvent) types.AuditEvent {
	event.ID = ""
	event.CreatedAt = time.Time{}
	return event
}

func (s *Server) applicationPolicyDecision(req types.PolicyEvaluateRequest) (types.PolicyDecision, bool) {
	application, ok := s.applicationByClientID(req.ClientID)
	if !ok {
		return types.PolicyDecision{
			Action: types.DecisionBlock,
			Reason: "APPLICATION_NOT_FOUND",
			Scene:  req.Scene,
		}, true
	}
	if !isActiveApplication(application) {
		return types.PolicyDecision{
			Action: types.DecisionBlock,
			Reason: "APPLICATION_DISABLED",
			Scene:  req.Scene,
		}, true
	}
	return types.PolicyDecision{}, false
}

func (s *Server) applicationTicketRejection(clientID string) (string, bool) {
	application, ok := s.applicationByClientID(clientID)
	if !ok {
		return "APPLICATION_NOT_FOUND", true
	}
	if !isActiveApplication(application) {
		return "APPLICATION_DISABLED", true
	}
	return "", false
}

func (s *Server) requireActiveApplication(w http.ResponseWriter, clientID string) bool {
	application, ok := s.applicationByClientID(clientID)
	if !ok {
		writeError(w, http.StatusNotFound, "APPLICATION_NOT_FOUND")
		return false
	}
	if !isActiveApplication(application) {
		writeError(w, http.StatusForbidden, "APPLICATION_DISABLED")
		return false
	}
	return true
}

func (s *Server) requireActiveSession(w http.ResponseWriter, session types.ChallengeSession) bool {
	switch session.Status {
	case types.SessionActive, "":
		return true
	case types.SessionVerified:
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":           false,
			"decision":     types.DecisionBlock,
			"reason_code":  "SESSION_ALREADY_VERIFIED",
			"can_refresh":  false,
			"track_bucket": "low",
		})
		return false
	default:
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":           false,
			"decision":     types.DecisionBlock,
			"reason_code":  "SESSION_NOT_ACTIVE",
			"can_refresh":  false,
			"track_bucket": "low",
		})
		return false
	}
}

func (s *Server) requireClientSecret(w http.ResponseWriter, r *http.Request, clientID string, requireActive bool) bool {
	application, ok := s.applicationByClientID(clientID)
	if !ok {
		writeError(w, http.StatusNotFound, "APPLICATION_NOT_FOUND")
		return false
	}
	if requireActive && !isActiveApplication(application) {
		writeError(w, http.StatusForbidden, "APPLICATION_DISABLED")
		return false
	}
	if application.SecretHash == "" {
		return true
	}
	value := clientSecretFromRequest(r)
	if secret.VerifyClientSecret(application.SecretHash, value) {
		return true
	}
	writeError(w, http.StatusUnauthorized, "CLIENT_UNAUTHORIZED")
	return false
}

func (s *Server) applicationByClientID(clientID string) (types.Application, bool) {
	for _, application := range s.store.ListApplications() {
		if application.ClientID == clientID {
			return application, true
		}
	}
	return types.Application{}, false
}

func isActiveApplication(application types.Application) bool {
	return strings.EqualFold(application.Status, "active")
}

func clientSecretFromRequest(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Captcha-Client-Secret")); value != "" {
		return value
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[len("bearer "):])
	}
	return ""
}

func requestNonceFromMeta(meta map[string]any) string {
	if meta == nil {
		return ""
	}
	value, _ := meta["request_nonce"].(string)
	return value
}

func verifyRouteForSession(session types.ChallengeSession, submittedRoute string) (string, bool) {
	if session.Route == "" {
		return submittedRoute, true
	}
	if submittedRoute != "" && submittedRoute != session.Route {
		return session.Route, false
	}
	return session.Route, true
}

func validRiskModelVersion(version types.RiskModelVersion) bool {
	return strings.TrimSpace(version.Name) != "" &&
		strings.TrimSpace(version.Version) != "" &&
		strings.TrimSpace(version.FeatureVersion) != "" &&
		strings.TrimSpace(version.TrainingWindow) != "" &&
		strings.TrimSpace(version.ArtifactURI) != ""
}

func normalizeRiskFeatureLabelUpdate(req updateRiskFeatureLabelRequest) (string, string, bool) {
	label := strings.ToLower(strings.TrimSpace(req.Label))
	if label == "" {
		label = "unknown"
	}
	labelSource := strings.ToLower(strings.TrimSpace(req.LabelSource))
	if labelSource == "" {
		labelSource = "manual_review"
	}
	if !allowedRiskFeatureLabel(label) || !allowedRiskFeatureLabelSource(labelSource) {
		return "", "", false
	}
	if req.ModelTrainable && !trainableRiskFeatureLabel(label) {
		return "", "", false
	}
	if !req.ModelTrainable && label == "unknown" {
		labelSource = ""
	}
	return label, labelSource, true
}

func allowedRiskFeatureLabel(label string) bool {
	switch label {
	case "unknown", "captcha_pass", "captcha_retry", "likely_human", "likely_bot", "confirmed_human", "confirmed_bot":
		return true
	default:
		return false
	}
}

func trainableRiskFeatureLabel(label string) bool {
	switch label {
	case "likely_human", "likely_bot", "confirmed_human", "confirmed_bot":
		return true
	default:
		return false
	}
}

func allowedRiskFeatureLabelSource(source string) bool {
	switch source {
	case "", "captcha_result", "manual_review", "business_feedback":
		return true
	default:
		return false
	}
}

func auditEventFilterFromQuery(r *http.Request) types.AuditEventFilter {
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	offset, _ := strconv.Atoi(query.Get("offset"))
	return types.AuditEventFilter{
		ClientID:       strings.TrimSpace(query.Get("client_id")),
		Scene:          strings.TrimSpace(query.Get("scene")),
		Action:         types.Decision(strings.TrimSpace(query.Get("action"))),
		Result:         strings.TrimSpace(query.Get("result")),
		DecisionReason: strings.TrimSpace(query.Get("decision_reason")),
		AccountIDHash:  strings.TrimSpace(query.Get("account_id_hash")),
		DeviceIDHash:   strings.TrimSpace(query.Get("device_id_hash")),
		Limit:          limit,
		Offset:         normalizedListOffset(offset),
	}
}

func riskFeatureSnapshotFilterFromQuery(r *http.Request) types.RiskFeatureSnapshotFilter {
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	offset, _ := strconv.Atoi(query.Get("offset"))
	filter := types.RiskFeatureSnapshotFilter{
		ClientID:      strings.TrimSpace(query.Get("client_id")),
		Scene:         strings.TrimSpace(query.Get("scene")),
		ChallengeType: types.CaptchaType(strings.TrimSpace(query.Get("challenge_type"))),
		Label:         strings.TrimSpace(query.Get("label")),
		Limit:         limit,
		Offset:        normalizedListOffset(offset),
	}
	if value := strings.TrimSpace(query.Get("model_trainable")); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err == nil {
			filter.ModelTrainable = &parsed
		}
	}
	return filter
}

func normalizedListLimit(limit int) int {
	if limit <= 0 || limit > 200 {
		return 100
	}
	return limit
}

func normalizedListOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func hashValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	encoded := hex.EncodeToString(sum[:])
	return "sha256:" + encoded[:32]
}

func withJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		next.ServeHTTP(w, r)
	})
}

func withCORS(next http.Handler, allowedOrigins []string) http.Handler {
	origins := normalizeAllowedOrigins(allowedOrigins)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allowed := allowedOrigin(r.Header.Get("Origin"), origins); allowed != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowed)
			if allowed != "*" {
				w.Header().Add("Vary", "Origin")
			}
		}
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Captcha-Admin-Token, X-Captcha-Scene, X-Captcha-Ticket, X-Captcha-Clearance, X-Captcha-Request-Nonce, X-Captcha-Resource-Tag, X-Captcha-Account-ID-Hash, X-Captcha-Device-ID-Hash")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if strings.EqualFold(r.Method, http.MethodOptions) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func normalizeAllowedOrigins(origins []string) []string {
	if len(origins) == 0 {
		return []string{"*"}
	}
	out := make([]string, 0, len(origins))
	for _, origin := range origins {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			out = append(out, origin)
		}
	}
	if len(out) == 0 {
		return []string{"*"}
	}
	return out
}

func allowedOrigin(origin string, allowedOrigins []string) string {
	for _, allowed := range allowedOrigins {
		if allowed == "*" {
			return "*"
		}
		if origin != "" && strings.EqualFold(origin, allowed) {
			return origin
		}
	}
	return ""
}

func withAdminAuth(next http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/admin/") || strings.EqualFold(r.Method, http.MethodOptions) {
			next.ServeHTTP(w, r)
			return
		}
		if !validAdminToken(r, token) {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validAdminToken(r *http.Request, expected string) bool {
	return validNamedToken(r, "X-Captcha-Admin-Token", expected)
}

func validNamedToken(r *http.Request, headerName, expected string) bool {
	actual := r.Header.Get(headerName)
	if actual == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			actual = strings.TrimSpace(auth[len("Bearer "):])
		}
	}
	if actual == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

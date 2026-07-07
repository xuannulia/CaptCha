package grpcserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	captchav1 "captcha/gen/captcha/v1"
	"captcha/internal/configsync"
	"captcha/internal/engine"
	"captcha/internal/grpccontract"
	"captcha/internal/policy"
	"captcha/internal/resource"
	"captcha/internal/risk"
	"captcha/internal/secret"
	"captcha/internal/store"
	"captcha/internal/token"
	"captcha/internal/types"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Dependencies struct {
	Engine         *engine.Engine
	Policy         *policy.Evaluator
	Store          store.Store
	Logger         *slog.Logger
	RuntimeBaseURL string
	GRPCToken      string
	Tokens         *token.Service
	RiskInferencer risk.Inferencer
	ConfigNotifier *configsync.Notifier
}

type Server struct {
	captchav1.UnimplementedPolicyServiceServer
	captchav1.UnimplementedTicketServiceServer
	captchav1.UnimplementedConfigServiceServer
	captchav1.UnimplementedEventServiceServer

	deps Dependencies
	grpc *grpc.Server
}

func New(deps Dependencies) *Server {
	s := &Server{deps: deps}
	s.grpc = grpc.NewServer(
		grpc.UnaryInterceptor(s.unaryAuthInterceptor),
		grpc.StreamInterceptor(s.streamAuthInterceptor),
	)
	captchav1.RegisterPolicyServiceServer(s.grpc, s)
	captchav1.RegisterTicketServiceServer(s.grpc, s)
	captchav1.RegisterConfigServiceServer(s.grpc, s)
	captchav1.RegisterEventServiceServer(s.grpc, s)
	return s
}

func (s *Server) Serve(listener net.Listener) error {
	return s.grpc.Serve(listener)
}

func (s *Server) Stop() {
	s.grpc.GracefulStop()
}

func (s *Server) unaryAuthInterceptor(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	if err := s.requireGRPCToken(ctx); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (s *Server) streamAuthInterceptor(
	srv any,
	stream grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	if err := s.requireGRPCToken(stream.Context()); err != nil {
		return err
	}
	return handler(srv, stream)
}

func (s *Server) Evaluate(ctx context.Context, req *captchav1.EvaluateRequest) (*captchav1.EvaluateResponse, error) {
	internalReq := grpccontract.PolicyEvaluateRequestFromProto(req)
	decision, err := s.evaluatePolicy(ctx, &internalReq)
	if err != nil {
		return nil, err
	}
	return grpccontract.PolicyDecisionToProto(*decision), nil
}

func (s *Server) evaluatePolicy(ctx context.Context, req *types.PolicyEvaluateRequest) (*types.PolicyDecision, error) {
	if req.ClientID == "" {
		req.ClientID = "demo"
	}
	if decision, blocked := s.applicationPolicyDecision(req); blocked {
		s.deps.Store.AddAuditEvent(types.AuditEvent{
			ClientID:       req.ClientID,
			Scene:          req.Scene,
			Route:          req.Path,
			AccountIDHash:  req.AccountIDHash,
			DeviceIDHash:   req.DeviceIDHash,
			Action:         decision.Action,
			DecisionReason: decision.Reason,
			Result:         string(decision.Action),
		})
		return decision, nil
	}
	if _, err := s.requireClientSecret(ctx, req.ClientID, false); err != nil {
		return nil, err
	}
	if decision, ok := s.ipPolicyDecision(*req); ok {
		s.auditPolicyDecision(*req, *decision)
		return decision, nil
	}
	if req.Ticket != "" {
		if _, err := s.deps.Store.VerifyTicket(req.Ticket, req.ClientID, req.Scene, req.Path, req.RequestNonce, hashValue(req.IP), hashValue(req.UserAgent), true); err == nil {
			return s.withClearance(types.PolicyDecision{Action: types.DecisionAllow, Reason: "TICKET_CONSUMED", Scene: req.Scene}, *req), nil
		} else {
			reason := errorCode(err)
			s.deps.Store.AddAuditEvent(types.AuditEvent{
				ClientID:       req.ClientID,
				Scene:          req.Scene,
				Route:          req.Path,
				AccountIDHash:  req.AccountIDHash,
				DeviceIDHash:   req.DeviceIDHash,
				Action:         types.DecisionBlock,
				DecisionReason: reason,
				Result:         "block",
			})
			return &types.PolicyDecision{Action: types.DecisionBlock, Reason: reason, Scene: req.Scene}, nil
		}
	}
	if req.Clearance != "" {
		if evaluation, ok := s.deps.Policy.EvaluateClearanceOverride(*req); ok {
			decision, err := s.policyDecisionWithChallengeSession(*req, evaluation)
			if err != nil {
				return nil, err
			}
			s.auditPolicyEvaluation(*req, *decision, evaluation)
			return decision, nil
		}
		if clearance, err := s.deps.Store.VerifyClearance(req.Clearance, req.ClientID, req.Scene, hashValue(req.IP), hashValue(req.UserAgent), req.AccountIDHash, req.DeviceIDHash); err == nil {
			decision := &types.PolicyDecision{
				Action:              types.DecisionAllow,
				Reason:              "CLEARANCE_VALID",
				Scene:               clearance.Scene,
				ClearanceToken:      clearance.Value,
				ClearanceTTLSeconds: ttlSeconds(clearance.ExpiresAt, clearance.CreatedAt),
			}
			s.auditPolicyDecision(*req, *decision)
			return decision, nil
		}
	}

	if err := risk.EnrichPolicyRequest(ctx, s.deps.RiskInferencer, s.deps.Store, req); err != nil && s.deps.Logger != nil {
		s.deps.Logger.Warn("risk inference failed", "client_id", req.ClientID, "error", err)
	}
	evaluation := s.deps.Policy.Evaluate(*req)
	decision, err := s.policyDecisionWithChallengeSession(*req, evaluation)
	if err != nil {
		return nil, err
	}
	s.auditPolicyEvaluation(*req, *decision, evaluation)
	return decision, nil
}

func (s *Server) policyDecisionWithChallengeSession(req types.PolicyEvaluateRequest, evaluation policy.Evaluation) (*types.PolicyDecision, error) {
	decision := &types.PolicyDecision{
		Action:             evaluation.Action,
		Reason:             evaluation.Reason,
		Scene:              req.Scene,
		ChallengeType:      evaluation.ChallengeType,
		TTLSeconds:         evaluation.TTLSeconds,
		CooldownSeconds:    evaluation.CooldownSeconds,
		BusinessVerifyType: evaluation.BusinessVerifyType,
	}
	if evaluation.Route != nil {
		decision.Scene = evaluation.Route.Scene
	}
	if !types.IsChallengeLikeDecision(evaluation.Action) {
		return decision, nil
	}
	scene := req.Scene
	if evaluation.Route != nil && evaluation.Route.Scene != "" {
		scene = evaluation.Route.Scene
	}
	session, err := s.deps.Engine.NewSession(req.ClientID, scene, evaluation.ChallengeType)
	if err != nil {
		return nil, err
	}
	session.ChallengeEscalation = evaluation.ChallengeEscalation
	session.RenderPayload = resource.ApplyVisualsAndAttachForStore(s.deps.Store, session.RenderPayload, session.Answer, session.ClientID, session.Scene, session.Type, req.ResourceTag)
	session.Route = req.Path
	session.RequestNonce = req.RequestNonce
	session.ResourceTag = req.ResourceTag
	session.IPHash = hashValue(req.IP)
	session.UserAgentHash = hashValue(req.UserAgent)
	session.AccountIDHash = req.AccountIDHash
	session.DeviceIDHash = req.DeviceIDHash
	s.deps.Store.PutSession(session)
	decision.SessionID = session.ID
	decision.ChallengeURL = challengeURL(s.deps.RuntimeBaseURL, session.ID, req.Path, req.RequestNonce, req.ResourceTag)
	decision.TTLSeconds = int(session.ExpiresAt.Sub(session.CreatedAt).Seconds())
	return decision, nil
}

func (s *Server) auditPolicyEvaluation(req types.PolicyEvaluateRequest, decision types.PolicyDecision, evaluation policy.Evaluation) {
	s.deps.Store.AddAuditEvent(types.AuditEvent{
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
}

func (s *Server) VerifyTicket(ctx context.Context, req *captchav1.VerifyTicketRequest) (*captchav1.VerifyTicketResponse, error) {
	internalReq := grpccontract.TicketVerifyRequestFromProto(req)
	response, err := s.verifyTicketRPC(ctx, &internalReq, false)
	if err != nil {
		return nil, err
	}
	return grpccontract.TicketVerifyResponseToProto(*response), nil
}

func (s *Server) ConsumeTicket(ctx context.Context, req *captchav1.VerifyTicketRequest) (*captchav1.VerifyTicketResponse, error) {
	internalReq := grpccontract.TicketVerifyRequestFromProto(req)
	response, err := s.verifyTicketRPC(ctx, &internalReq, true)
	if err != nil {
		return nil, err
	}
	return grpccontract.TicketVerifyResponseToProto(*response), nil
}

func (s *Server) verifyTicketRPC(ctx context.Context, req *types.TicketVerifyRequest, consume bool) (*types.TicketVerifyResponse, error) {
	if response, blocked := s.applicationTicketRejection(req.ClientID); blocked {
		return response, nil
	}
	if _, err := s.requireClientSecret(ctx, req.ClientID, false); err != nil {
		return nil, err
	}
	return s.verifyTicket(req, consume), nil
}

func (s *Server) verifyTicket(req *types.TicketVerifyRequest, consume bool) *types.TicketVerifyResponse {
	ticket, err := s.deps.Store.VerifyTicket(req.Ticket, req.ClientID, req.Scene, req.Route, req.RequestNonce, req.IPHash, req.UserAgentHash, consume)
	if err != nil {
		return &types.TicketVerifyResponse{Valid: false, Reason: errorCode(err)}
	}
	response := &types.TicketVerifyResponse{
		Valid:         true,
		ClientID:      ticket.ClientID,
		Scene:         ticket.Scene,
		Route:         ticket.Route,
		RequestNonce:  ticket.RequestNonce,
		IPHash:        ticket.IPHash,
		UserAgentHash: ticket.UserAgentHash,
		ExpireAt:      ticket.ExpiresAt,
	}
	if consume {
		s.addClearanceToTicketResponse(response, req)
	}
	return response
}

func (s *Server) ipPolicyDecision(req types.PolicyEvaluateRequest) (*types.PolicyDecision, bool) {
	action, reason, ok := s.deps.Policy.EvaluateIP(req)
	if !ok {
		return nil, false
	}
	return &types.PolicyDecision{Action: action, Reason: reason, Scene: req.Scene}, true
}

func (s *Server) auditPolicyDecision(req types.PolicyEvaluateRequest, decision types.PolicyDecision) {
	s.deps.Store.AddAuditEvent(types.AuditEvent{
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

func (s *Server) withClearance(decision types.PolicyDecision, req types.PolicyEvaluateRequest) *types.PolicyDecision {
	scene := firstNonEmpty(decision.Scene, req.Scene)
	if scene == "" || s.deps.Tokens == nil {
		return &decision
	}
	ipHash := hashValue(req.IP)
	userAgentHash := hashValue(req.UserAgent)
	if ipHash == "" || userAgentHash == "" {
		return &decision
	}
	clearance, err := s.deps.Tokens.IssueClearanceWithTTL(req.ClientID, scene, ipHash, userAgentHash, req.AccountIDHash, req.DeviceIDHash, s.clearanceTTLForPolicyRequest(req))
	if err != nil {
		if s.deps.Logger != nil {
			s.deps.Logger.Warn("issue grpc clearance", "client_id", req.ClientID, "scene", scene, "error", err)
		}
		return &decision
	}
	if decision.Scene == "" {
		decision.Scene = scene
	}
	decision.ClearanceToken = clearance.Value
	decision.ClearanceTTLSeconds = ttlSeconds(clearance.ExpiresAt, clearance.CreatedAt)
	return &decision
}

func (s *Server) addClearanceToTicketResponse(response *types.TicketVerifyResponse, req *types.TicketVerifyRequest) {
	if s.deps.Tokens == nil || req.Scene == "" {
		return
	}
	if req.IPHash == "" || req.UserAgentHash == "" {
		return
	}
	clearance, err := s.deps.Tokens.IssueClearanceWithTTL(req.ClientID, req.Scene, req.IPHash, req.UserAgentHash, req.AccountIDHash, req.DeviceIDHash, s.clearanceTTLForTicketRequest(req))
	if err != nil {
		if s.deps.Logger != nil {
			s.deps.Logger.Warn("issue grpc clearance", "client_id", req.ClientID, "scene", req.Scene, "error", err)
		}
		return
	}
	response.ClearanceToken = clearance.Value
	response.ClearanceExpireAt = clearance.ExpiresAt
	response.ClearanceTTLSeconds = ttlSeconds(clearance.ExpiresAt, clearance.CreatedAt)
}

func (s *Server) clearanceTTLForPolicyRequest(req types.PolicyEvaluateRequest) time.Duration {
	if s.deps.Policy == nil {
		return 0
	}
	route := s.deps.Policy.MatchRoute(req)
	if route == nil || route.TokenTTLSeconds <= 0 {
		return 0
	}
	return time.Duration(route.TokenTTLSeconds) * time.Second
}

func (s *Server) clearanceTTLForTicketRequest(req *types.TicketVerifyRequest) time.Duration {
	if req == nil {
		return 0
	}
	return s.clearanceTTLForPolicyRequest(types.PolicyEvaluateRequest{
		ClientID:      req.ClientID,
		Scene:         req.Scene,
		Path:          req.Route,
		AccountIDHash: req.AccountIDHash,
		DeviceIDHash:  req.DeviceIDHash,
	})
}

func (s *Server) GetConfig(ctx context.Context, req *captchav1.ConfigRequest) (*captchav1.ConfigSnapshot, error) {
	snapshot, err := s.getConfig(ctx, &types.ConfigRequest{ClientID: req.GetClientId()})
	if err != nil {
		return nil, err
	}
	return grpccontract.ConfigSnapshotToProto(*snapshot), nil
}

func (s *Server) getConfig(ctx context.Context, req *types.ConfigRequest) (*types.ConfigSnapshot, error) {
	clientID := req.ClientID
	if clientID == "" {
		clientID = "demo"
	}
	application, err := s.requireClientSecret(ctx, clientID, false)
	if err != nil {
		return nil, err
	}
	return &types.ConfigSnapshot{
		ClientID:          clientID,
		ApplicationStatus: application.Status,
		Routes:            s.deps.Store.ListRoutePolicies(clientID),
		PolicyRules:       s.deps.Store.ListPolicyRules(clientID),
		IPPolicies:        s.deps.Store.ListIPPolicies(clientID),
		Resources:         s.deps.Store.ListResources(clientID),
		Version:           s.configVersion(),
	}, nil
}

func (s *Server) WatchConfig(req *captchav1.ConfigRequest, stream captchav1.ConfigService_WatchConfigServer) error {
	updates, unsubscribe := s.subscribeConfigUpdates()
	defer unsubscribe()
	internalReq := &types.ConfigRequest{ClientID: req.GetClientId()}
	snapshot, err := s.getConfig(stream.Context(), internalReq)
	if err != nil {
		return err
	}
	if err := stream.Send(grpccontract.ConfigSnapshotToProto(*snapshot)); err != nil {
		return err
	}
	lastVersion := snapshot.Version
	for {
		select {
		case version, ok := <-updates:
			if !ok {
				<-stream.Context().Done()
				return stream.Context().Err()
			}
			if version <= lastVersion {
				continue
			}
			snapshot, err := s.getConfig(stream.Context(), internalReq)
			if err != nil {
				return err
			}
			if snapshot.Version < version {
				snapshot.Version = version
			}
			if err := stream.Send(grpccontract.ConfigSnapshotToProto(*snapshot)); err != nil {
				return err
			}
			lastVersion = snapshot.Version
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (s *Server) Report(ctx context.Context, req *captchav1.EventBatch) (*captchav1.ReportResult, error) {
	batch := grpccontract.EventBatchFromProto(req)
	if err := validEventBatch(&batch); err != nil {
		return nil, err
	}
	if err := s.requireEventClientSecrets(ctx, &batch); err != nil {
		return nil, err
	}
	accepted := 0
	for _, event := range batch.Events {
		s.deps.Store.AddAuditEvent(event)
		accepted++
	}
	return grpccontract.ReportResultToProto(types.ReportResult{Accepted: accepted}), nil
}

func challengeURL(runtimeBaseURL, sessionID, route, requestNonce, resourceTag string) string {
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
	path := "/challenge?" + values.Encode()
	if runtimeBaseURL == "" {
		return path
	}
	return strings.TrimRight(runtimeBaseURL, "/") + path
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

func (s *Server) configVersion() int64 {
	if s.deps.ConfigNotifier != nil {
		return s.deps.ConfigNotifier.Version()
	}
	return time.Now().Unix()
}

func (s *Server) requireEventClientSecrets(ctx context.Context, batch *types.EventBatch) error {
	seen := make(map[string]struct{})
	for _, event := range batch.Events {
		if _, ok := seen[event.ClientID]; ok {
			continue
		}
		seen[event.ClientID] = struct{}{}
		if _, err := s.requireClientSecret(ctx, event.ClientID, true); err != nil {
			return err
		}
	}
	return nil
}

func validEventBatch(batch *types.EventBatch) error {
	if batch == nil {
		return nil
	}
	for _, event := range batch.Events {
		if strings.TrimSpace(event.ClientID) == "" {
			return status.Error(codes.InvalidArgument, "EVENT_CLIENT_ID_REQUIRED")
		}
	}
	return nil
}

func (s *Server) applicationPolicyDecision(req *types.PolicyEvaluateRequest) (*types.PolicyDecision, bool) {
	application, ok := s.applicationByClientID(req.ClientID)
	if !ok {
		return &types.PolicyDecision{
			Action: types.DecisionBlock,
			Reason: "APPLICATION_NOT_FOUND",
			Scene:  req.Scene,
		}, true
	}
	if !isActiveApplication(application) {
		return &types.PolicyDecision{
			Action: types.DecisionBlock,
			Reason: "APPLICATION_DISABLED",
			Scene:  req.Scene,
		}, true
	}
	return nil, false
}

func (s *Server) applicationTicketRejection(clientID string) (*types.TicketVerifyResponse, bool) {
	application, ok := s.applicationByClientID(clientID)
	if !ok {
		return &types.TicketVerifyResponse{Valid: false, Reason: "APPLICATION_NOT_FOUND"}, true
	}
	if !isActiveApplication(application) {
		return &types.TicketVerifyResponse{Valid: false, Reason: "APPLICATION_DISABLED"}, true
	}
	return nil, false
}

func (s *Server) requireClientSecret(ctx context.Context, clientID string, requireActive bool) (types.Application, error) {
	application, ok := s.applicationByClientID(clientID)
	if !ok {
		return types.Application{}, status.Error(codes.NotFound, "APPLICATION_NOT_FOUND")
	}
	if requireActive && !isActiveApplication(application) {
		return types.Application{}, status.Error(codes.PermissionDenied, "APPLICATION_DISABLED")
	}
	if application.SecretHash == "" {
		return application, nil
	}
	if secret.VerifyClientSecret(application.SecretHash, clientSecretFromContext(ctx)) {
		return application, nil
	}
	return types.Application{}, status.Error(codes.Unauthenticated, "CLIENT_UNAUTHORIZED")
}

func (s *Server) requireGRPCToken(ctx context.Context) error {
	expected := strings.TrimSpace(s.deps.GRPCToken)
	if expected == "" {
		return nil
	}
	actual := platformTokenFromContext(ctx)
	if actual == "" || subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return status.Error(codes.Unauthenticated, "GRPC_UNAUTHORIZED")
	}
	return nil
}

func (s *Server) applicationByClientID(clientID string) (types.Application, bool) {
	for _, application := range s.deps.Store.ListApplications() {
		if application.ClientID == clientID {
			return application, true
		}
	}
	return types.Application{}, false
}

func isActiveApplication(application types.Application) bool {
	return strings.EqualFold(application.Status, "active")
}

func clientSecretFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if values := md.Get("x-captcha-client-secret"); len(values) > 0 {
		return strings.TrimSpace(values[0])
	}
	if values := md.Get("authorization"); len(values) > 0 {
		auth := strings.TrimSpace(values[0])
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			return strings.TrimSpace(auth[len("bearer "):])
		}
	}
	return ""
}

func platformTokenFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if values := md.Get("x-captcha-grpc-token"); len(values) > 0 {
		return strings.TrimSpace(values[0])
	}
	if values := md.Get("authorization"); len(values) > 0 {
		auth := strings.TrimSpace(values[0])
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			return strings.TrimSpace(auth[len("bearer "):])
		}
	}
	return ""
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

func (s *Server) subscribeConfigUpdates() (<-chan int64, func()) {
	if s.deps.ConfigNotifier == nil {
		ch := make(chan int64)
		return ch, func() {
			close(ch)
		}
	}
	return s.deps.ConfigNotifier.Subscribe()
}

func errorCode(err error) string {
	switch err {
	case store.ErrNotFound:
		return "NOT_FOUND"
	case store.ErrExpired:
		return "EXPIRED"
	case store.ErrConsumed:
		return "CONSUMED"
	default:
		return "UNKNOWN"
	}
}

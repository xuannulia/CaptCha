package store

import (
	"time"

	"captcha/internal/types"
)

type HybridStore struct {
	sessions   SessionStore
	tickets    TicketStore
	clearances ClearanceStore
	rates      RateStore
	control    ControlStore
	audit      AuditStore
	features   FeatureStore
}

func NewHybridStore(transient interface {
	SessionStore
	TicketStore
	ClearanceStore
	RateStore
}, control interface {
	ControlStore
	AuditStore
	FeatureStore
}) *HybridStore {
	return &HybridStore{
		sessions:   transient,
		tickets:    transient,
		clearances: transient,
		rates:      transient,
		control:    control,
		audit:      control,
		features:   control,
	}
}

func (s *HybridStore) PutSession(session types.ChallengeSession) {
	s.sessions.PutSession(session)
}

func (s *HybridStore) GetSession(id string) (types.ChallengeSession, error) {
	return s.sessions.GetSession(id)
}

func (s *HybridStore) UpdateSession(session types.ChallengeSession) {
	s.sessions.UpdateSession(session)
}

func (s *HybridStore) PutTicket(ticket types.Ticket) {
	s.tickets.PutTicket(ticket)
}

func (s *HybridStore) VerifyTicket(value, clientID, scene, route, requestNonce, ipHash, userAgentHash string, consume bool) (types.Ticket, error) {
	return s.tickets.VerifyTicket(value, clientID, scene, route, requestNonce, ipHash, userAgentHash, consume)
}

func (s *HybridStore) PutClearance(clearance types.Clearance) {
	s.clearances.PutClearance(clearance)
}

func (s *HybridStore) VerifyClearance(value, clientID, scene, ipHash, userAgentHash, accountIDHash, deviceIDHash string) (types.Clearance, error) {
	return s.clearances.VerifyClearance(value, clientID, scene, ipHash, userAgentHash, accountIDHash, deviceIDHash)
}

func (s *HybridStore) IncrementRate(key string, window time.Duration, maxRequests int, strategy ...string) int {
	return s.rates.IncrementRate(key, window, maxRequests, strategy...)
}

func (s *HybridStore) ListApplications() []types.Application {
	return s.control.ListApplications()
}

func (s *HybridStore) UpsertApplication(application types.Application) types.Application {
	return s.control.UpsertApplication(application)
}

func (s *HybridStore) RotateApplicationSecret(clientID, secretHash string) (types.Application, error) {
	return s.control.RotateApplicationSecret(clientID, secretHash)
}

func (s *HybridStore) ListRoutePolicies(clientID string) []types.RoutePolicy {
	return s.control.ListRoutePolicies(clientID)
}

func (s *HybridStore) UpsertRoutePolicy(route types.RoutePolicy) types.RoutePolicy {
	return s.control.UpsertRoutePolicy(route)
}

func (s *HybridStore) ListIPPolicies(clientID string) []types.IPPolicy {
	return s.control.ListIPPolicies(clientID)
}

func (s *HybridStore) UpsertIPPolicy(policy types.IPPolicy) types.IPPolicy {
	return s.control.UpsertIPPolicy(policy)
}

func (s *HybridStore) ListResources(clientID string) []types.CaptchaResource {
	return s.control.ListResources(clientID)
}

func (s *HybridStore) UpsertResource(resource types.CaptchaResource) types.CaptchaResource {
	return s.control.UpsertResource(resource)
}

func (s *HybridStore) DeleteResources(clientID string, ids []string) int {
	return s.control.DeleteResources(clientID, ids)
}

func (s *HybridStore) AddAuditEvent(event types.AuditEvent) types.AuditEvent {
	return s.audit.AddAuditEvent(event)
}

func (s *HybridStore) ListAuditEvents(clientID string, limit int) []types.AuditEvent {
	return s.audit.ListAuditEvents(clientID, limit)
}

func (s *HybridStore) ListAuditEventsFiltered(filter types.AuditEventFilter) []types.AuditEvent {
	return s.audit.ListAuditEventsFiltered(filter)
}

func (s *HybridStore) AddRiskFeatureSnapshot(snapshot types.RiskFeatureSnapshot) types.RiskFeatureSnapshot {
	return s.features.AddRiskFeatureSnapshot(snapshot)
}

func (s *HybridStore) ListRiskFeatureSnapshots(clientID string, limit int) []types.RiskFeatureSnapshot {
	return s.features.ListRiskFeatureSnapshots(clientID, limit)
}

func (s *HybridStore) ListRiskFeatureSnapshotsFiltered(filter types.RiskFeatureSnapshotFilter) []types.RiskFeatureSnapshot {
	return s.features.ListRiskFeatureSnapshotsFiltered(filter)
}

func (s *HybridStore) UpdateRiskFeatureSnapshotLabel(id, label, labelSource string, modelTrainable bool) (types.RiskFeatureSnapshot, error) {
	return s.features.UpdateRiskFeatureSnapshotLabel(id, label, labelSource, modelTrainable)
}

func (s *HybridStore) ListRiskModelVersions(name string, limit int) []types.RiskModelVersion {
	return s.features.ListRiskModelVersions(name, limit)
}

func (s *HybridStore) UpsertRiskModelVersion(version types.RiskModelVersion) types.RiskModelVersion {
	return s.features.UpsertRiskModelVersion(version)
}

func (s *HybridStore) ActivateRiskModelVersion(id string) (types.RiskModelVersion, error) {
	return s.features.ActivateRiskModelVersion(id)
}

func (s *HybridStore) RollbackRiskModelVersion(id string) (types.RiskModelVersion, error) {
	return s.features.RollbackRiskModelVersion(id)
}

var _ Store = (*HybridStore)(nil)

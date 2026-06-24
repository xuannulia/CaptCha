package store

import (
	"time"

	"captcha/internal/types"
)

type Store interface {
	SessionStore
	TicketStore
	ClearanceStore
	ControlStore
	AuditStore
	FeatureStore
	RateStore
}

type SessionStore interface {
	PutSession(session types.ChallengeSession)
	GetSession(id string) (types.ChallengeSession, error)
	UpdateSession(session types.ChallengeSession)
}

type TicketStore interface {
	PutTicket(ticket types.Ticket)
	VerifyTicket(value, clientID, scene, route, requestNonce, ipHash, userAgentHash string, consume bool) (types.Ticket, error)
}

type ClearanceStore interface {
	PutClearance(clearance types.Clearance)
	VerifyClearance(value, clientID, scene, ipHash, userAgentHash, accountIDHash, deviceIDHash string) (types.Clearance, error)
}

type ControlStore interface {
	ListApplications() []types.Application
	UpsertApplication(application types.Application) types.Application
	RotateApplicationSecret(clientID, secretHash string) (types.Application, error)
	ListRoutePolicies(clientID string) []types.RoutePolicy
	UpsertRoutePolicy(route types.RoutePolicy) types.RoutePolicy
	DeleteRoutePolicies(clientID string, ids []string) int
	ListIPPolicies(clientID string) []types.IPPolicy
	UpsertIPPolicy(policy types.IPPolicy) types.IPPolicy
	DeleteIPPolicies(clientID string, ids []string) int
	ListResources(clientID string) []types.CaptchaResource
	UpsertResource(resource types.CaptchaResource) types.CaptchaResource
	DeleteResources(clientID string, ids []string) int
}

type AuditStore interface {
	AddAuditEvent(event types.AuditEvent) types.AuditEvent
	ListAuditEvents(clientID string, limit int) []types.AuditEvent
	ListAuditEventsFiltered(filter types.AuditEventFilter) []types.AuditEvent
}

type FeatureStore interface {
	AddRiskFeatureSnapshot(snapshot types.RiskFeatureSnapshot) types.RiskFeatureSnapshot
	ListRiskFeatureSnapshots(clientID string, limit int) []types.RiskFeatureSnapshot
	ListRiskFeatureSnapshotsFiltered(filter types.RiskFeatureSnapshotFilter) []types.RiskFeatureSnapshot
	UpdateRiskFeatureSnapshotLabel(id, label, labelSource string, modelTrainable bool) (types.RiskFeatureSnapshot, error)
	ListRiskModelVersions(name string, limit int) []types.RiskModelVersion
	UpsertRiskModelVersion(version types.RiskModelVersion) types.RiskModelVersion
	ActivateRiskModelVersion(id string) (types.RiskModelVersion, error)
	RollbackRiskModelVersion(id string) (types.RiskModelVersion, error)
}

type RateStore interface {
	IncrementRate(key string, window time.Duration, maxRequests int, strategy ...string) int
}

var _ Store = (*MemoryStore)(nil)

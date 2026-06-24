package store

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	challengepkg "captcha/internal/challenge"
	"captcha/internal/routepolicy"
	"captcha/internal/types"
)

var (
	ErrNotFound = errors.New("not found")
	ErrExpired  = errors.New("expired")
	ErrConsumed = errors.New("consumed")
)

type MemoryStore struct {
	mu           sync.Mutex
	sessions     map[string]types.ChallengeSession
	tickets      map[string]types.Ticket
	clearances   map[string]types.Clearance
	applications map[string]types.Application
	routes       map[string]types.RoutePolicy
	ipPolicies   map[string]types.IPPolicy
	resources    map[string]types.CaptchaResource
	resourcePath string
	auditEvents  []types.AuditEvent
	features     []types.RiskFeatureSnapshot
	models       map[string]types.RiskModelVersion
	rateCounters map[string]rateCounter
}

type rateCounter struct {
	Count       int
	WindowStart time.Time
	Hits        []time.Time
	Tokens      float64
	LastRefill  time.Time
}

func NewMemoryStore() *MemoryStore {
	return newMemoryStore("")
}

func NewMemoryStoreWithResourcePersistence(path string) *MemoryStore {
	return newMemoryStore(strings.TrimSpace(path))
}

func newMemoryStore(resourcePath string) *MemoryStore {
	now := time.Now()
	s := &MemoryStore{
		sessions:     make(map[string]types.ChallengeSession),
		tickets:      make(map[string]types.Ticket),
		clearances:   make(map[string]types.Clearance),
		applications: make(map[string]types.Application),
		routes:       make(map[string]types.RoutePolicy),
		ipPolicies:   make(map[string]types.IPPolicy),
		resources:    make(map[string]types.CaptchaResource),
		auditEvents:  make([]types.AuditEvent, 0, 64),
		features:     make([]types.RiskFeatureSnapshot, 0, 128),
		models:       make(map[string]types.RiskModelVersion),
		rateCounters: make(map[string]rateCounter),
		resourcePath: resourcePath,
	}
	s.seed(now)
	s.loadResourcesFromDisk()
	return s
}

func (s *MemoryStore) PutSession(session types.ChallengeSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
}

func (s *MemoryStore) GetSession(id string) (types.ChallengeSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[id]
	if !ok {
		return types.ChallengeSession{}, ErrNotFound
	}
	if time.Now().After(session.ExpiresAt) {
		session.Status = types.SessionExpired
		s.sessions[id] = session
		return types.ChallengeSession{}, ErrExpired
	}
	return session, nil
}

func (s *MemoryStore) UpdateSession(session types.ChallengeSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
}

func (s *MemoryStore) PutTicket(ticket types.Ticket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tickets[ticket.Value] = ticket
}

func (s *MemoryStore) VerifyTicket(value, clientID, scene, route, requestNonce, ipHash, userAgentHash string, consume bool) (types.Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ticket, ok := s.tickets[value]
	if !ok {
		return types.Ticket{}, ErrNotFound
	}
	if time.Now().After(ticket.ExpiresAt) {
		return types.Ticket{}, ErrExpired
	}
	if ticket.Consumed {
		return types.Ticket{}, ErrConsumed
	}
	if ticket.ClientID != clientID || ticket.Scene != scene {
		return types.Ticket{}, ErrNotFound
	}
	if ticket.Route != "" && ticket.Route != route {
		return types.Ticket{}, ErrNotFound
	}
	if ticket.RequestNonce != "" && ticket.RequestNonce != requestNonce {
		return types.Ticket{}, ErrNotFound
	}
	if ticket.IPHash != "" && ticket.IPHash != ipHash {
		return types.Ticket{}, ErrNotFound
	}
	if ticket.UserAgentHash != "" && ticket.UserAgentHash != userAgentHash {
		return types.Ticket{}, ErrNotFound
	}
	if consume {
		now := time.Now()
		ticket.Consumed = true
		ticket.ConsumedAt = &now
		s.tickets[value] = ticket
	}
	return ticket, nil
}

func (s *MemoryStore) PutClearance(clearance types.Clearance) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearances[clearance.Value] = clearance
}

func (s *MemoryStore) VerifyClearance(value, clientID, scene, ipHash, userAgentHash, accountIDHash, deviceIDHash string) (types.Clearance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	clearance, ok := s.clearances[value]
	if !ok {
		return types.Clearance{}, ErrNotFound
	}
	if err := validateClearance(clearance, clientID, scene, ipHash, userAgentHash, accountIDHash, deviceIDHash); err != nil {
		if errors.Is(err, ErrExpired) {
			delete(s.clearances, value)
		}
		return types.Clearance{}, err
	}
	return clearance, nil
}

func (s *MemoryStore) ListApplications() []types.Application {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]types.Application, 0, len(s.applications))
	for _, app := range s.applications {
		app.HasSecret = app.SecretHash != ""
		out = append(out, app)
	}
	return out
}

func (s *MemoryStore) UpsertApplication(application types.Application) types.Application {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if application.ID == "" {
		for _, existing := range s.applications {
			if existing.ClientID == application.ClientID {
				application.ID = existing.ID
				application.CreatedAt = existing.CreatedAt
				break
			}
		}
	}
	if application.ID == "" {
		application.ID = newID("app")
	}
	if application.ClientID == "" {
		application.ClientID = application.ID
	}
	if application.Name == "" {
		application.Name = application.ClientID
	}
	if application.Status == "" {
		application.Status = "active"
	}
	if application.DefaultFailPolicy == "" {
		application.DefaultFailPolicy = "fail_open"
	}
	if existing, ok := s.applications[application.ID]; ok && application.CreatedAt.IsZero() {
		application.CreatedAt = existing.CreatedAt
		if application.SecretHash == "" {
			application.SecretHash = existing.SecretHash
		}
	}
	if application.CreatedAt.IsZero() {
		application.CreatedAt = now
	}
	application.UpdatedAt = now
	application.HasSecret = application.SecretHash != ""
	s.applications[application.ID] = application
	return application
}

func (s *MemoryStore) RotateApplicationSecret(clientID, secretHash string) (types.Application, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, application := range s.applications {
		if application.ClientID != clientID {
			continue
		}
		application.SecretHash = secretHash
		application.HasSecret = secretHash != ""
		application.UpdatedAt = time.Now().UTC()
		s.applications[id] = application
		return application, nil
	}
	return types.Application{}, ErrNotFound
}

func (s *MemoryStore) ListRoutePolicies(clientID string) []types.RoutePolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]types.RoutePolicy, 0, len(s.routes))
	for _, route := range s.routes {
		if clientID == "" || route.ClientID == clientID {
			out = append(out, route)
		}
	}
	return out
}

func (s *MemoryStore) UpsertRoutePolicy(route types.RoutePolicy) types.RoutePolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if route.ID == "" {
		route.ID = "route_" + now.Format("20060102150405.000000000")
		route.CreatedAt = now
	}
	route.ChallengeEscalation = challengepkg.NormalizeConfiguredEscalation(route.ChallengeEscalation)
	route.RolloutPercent = routepolicy.NormalizeRolloutPercent(route.RolloutPercent)
	route.UpdatedAt = now
	s.routes[route.ID] = route
	return route
}

func (s *MemoryStore) DeleteRoutePolicies(clientID string, ids []string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	deleted := 0
	for _, id := range ids {
		route, ok := s.routes[id]
		if !ok {
			continue
		}
		if clientID != "" && route.ClientID != clientID {
			continue
		}
		delete(s.routes, id)
		deleted++
	}
	return deleted
}

func (s *MemoryStore) ListIPPolicies(clientID string) []types.IPPolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]types.IPPolicy, 0, len(s.ipPolicies))
	for _, policy := range s.ipPolicies {
		if clientID == "" || policy.ClientID == clientID {
			out = append(out, policy)
		}
	}
	return out
}

func (s *MemoryStore) UpsertIPPolicy(policy types.IPPolicy) types.IPPolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if policy.ID == "" {
		policy.ID = "ip_" + now.Format("20060102150405.000000000")
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now
	s.ipPolicies[policy.ID] = policy
	return policy
}

func (s *MemoryStore) DeleteIPPolicies(clientID string, ids []string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	deleted := 0
	for _, id := range ids {
		policy, ok := s.ipPolicies[id]
		if !ok {
			continue
		}
		if clientID != "" && policy.ClientID != clientID {
			continue
		}
		delete(s.ipPolicies, id)
		deleted++
	}
	return deleted
}

func (s *MemoryStore) ListResources(clientID string) []types.CaptchaResource {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]types.CaptchaResource, 0, len(s.resources))
	for _, resource := range s.resources {
		if clientID == "" || resource.ClientID == clientID {
			out = append(out, resource)
		}
	}
	return out
}

func (s *MemoryStore) UpsertResource(resource types.CaptchaResource) types.CaptchaResource {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if resource.ID == "" {
		resource.ID = "res_" + now.Format("20060102150405.000000000")
		resource.CreatedAt = now
	}
	resource.UpdatedAt = now
	s.resources[resource.ID] = resource
	s.persistResourcesLocked()
	return resource
}

func (s *MemoryStore) DeleteResources(clientID string, ids []string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	deleted := 0
	for _, id := range ids {
		resource, ok := s.resources[id]
		if !ok {
			continue
		}
		if clientID != "" && resource.ClientID != clientID {
			continue
		}
		delete(s.resources, id)
		deleted++
	}
	if deleted > 0 {
		s.persistResourcesLocked()
	}
	return deleted
}

type memoryResourceState struct {
	Resources []types.CaptchaResource `json:"resources"`
}

func (s *MemoryStore) loadResourcesFromDisk() {
	if s.resourcePath == "" {
		return
	}
	data, err := os.ReadFile(s.resourcePath)
	if err != nil {
		return
	}
	var state memoryResourceState
	if json.Unmarshal(data, &state) != nil {
		return
	}
	resources := make(map[string]types.CaptchaResource, len(state.Resources))
	for _, resource := range state.Resources {
		if resource.ID == "" {
			continue
		}
		resources[resource.ID] = resource
	}
	s.resources = resources
}

func (s *MemoryStore) persistResourcesLocked() {
	if s.resourcePath == "" {
		return
	}
	resources := make([]types.CaptchaResource, 0, len(s.resources))
	for _, resource := range s.resources {
		resources = append(resources, resource)
	}
	sort.SliceStable(resources, func(i, j int) bool {
		return resources[i].ID < resources[j].ID
	})
	data, err := json.MarshalIndent(memoryResourceState{Resources: resources}, "", "  ")
	if err != nil {
		return
	}
	dir := filepath.Dir(s.resourcePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	tmp := s.resourcePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, s.resourcePath)
}

func (s *MemoryStore) AddAuditEvent(event types.AuditEvent) types.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if event.ID == "" {
		event.ID = "audit_" + now.Format("20060102150405.000000000")
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = now
	}
	s.auditEvents = append([]types.AuditEvent{event}, s.auditEvents...)
	if len(s.auditEvents) > 500 {
		s.auditEvents = s.auditEvents[:500]
	}
	return event
}

func (s *MemoryStore) ListAuditEvents(clientID string, limit int) []types.AuditEvent {
	return s.ListAuditEventsFiltered(types.AuditEventFilter{ClientID: clientID, Limit: limit})
}

func (s *MemoryStore) ListAuditEventsFiltered(filter types.AuditEventFilter) []types.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := normalizedListFetchLimit(filter.Limit)
	offset := normalizedOffset(filter.Offset)
	out := make([]types.AuditEvent, 0, limit)
	skipped := 0
	for _, event := range s.auditEvents {
		if !matchesAuditFilter(event, filter) {
			continue
		}
		if skipped < offset {
			skipped++
			continue
		}
		out = append(out, event)
		if len(out) == limit {
			break
		}
	}
	return out
}

func (s *MemoryStore) AddRiskFeatureSnapshot(snapshot types.RiskFeatureSnapshot) types.RiskFeatureSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot = prepareRiskFeatureSnapshot(snapshot)
	s.features = append([]types.RiskFeatureSnapshot{snapshot}, s.features...)
	if len(s.features) > 1000 {
		s.features = s.features[:1000]
	}
	return snapshot
}

func (s *MemoryStore) ListRiskFeatureSnapshots(clientID string, limit int) []types.RiskFeatureSnapshot {
	return s.ListRiskFeatureSnapshotsFiltered(types.RiskFeatureSnapshotFilter{ClientID: clientID, Limit: limit})
}

func (s *MemoryStore) ListRiskFeatureSnapshotsFiltered(filter types.RiskFeatureSnapshotFilter) []types.RiskFeatureSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := normalizedListFetchLimit(filter.Limit)
	offset := normalizedOffset(filter.Offset)
	out := make([]types.RiskFeatureSnapshot, 0, limit)
	skipped := 0
	for _, snapshot := range s.features {
		if !matchesRiskFeatureFilter(snapshot, filter) {
			continue
		}
		if skipped < offset {
			skipped++
			continue
		}
		out = append(out, snapshot)
		if len(out) == limit {
			break
		}
	}
	return out
}

func matchesAuditFilter(event types.AuditEvent, filter types.AuditEventFilter) bool {
	if filter.ClientID != "" && event.ClientID != filter.ClientID {
		return false
	}
	if filter.Scene != "" && event.Scene != filter.Scene {
		return false
	}
	if filter.Action != "" && event.Action != filter.Action {
		return false
	}
	if filter.Result != "" && event.Result != filter.Result {
		return false
	}
	if filter.DecisionReason != "" && event.DecisionReason != filter.DecisionReason {
		return false
	}
	if filter.AccountIDHash != "" && event.AccountIDHash != filter.AccountIDHash {
		return false
	}
	if filter.DeviceIDHash != "" && event.DeviceIDHash != filter.DeviceIDHash {
		return false
	}
	return true
}

func matchesRiskFeatureFilter(snapshot types.RiskFeatureSnapshot, filter types.RiskFeatureSnapshotFilter) bool {
	if filter.ClientID != "" && snapshot.ClientID != filter.ClientID {
		return false
	}
	if filter.Scene != "" && snapshot.Scene != filter.Scene {
		return false
	}
	if filter.ChallengeType != "" && snapshot.ChallengeType != filter.ChallengeType {
		return false
	}
	if filter.Label != "" && snapshot.Label != filter.Label {
		return false
	}
	if filter.ModelTrainable != nil && snapshot.ModelTrainable != *filter.ModelTrainable {
		return false
	}
	return true
}

func normalizedOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}

func normalizedListFetchLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 5000 {
		return 5000
	}
	return limit
}

func (s *MemoryStore) UpdateRiskFeatureSnapshotLabel(id, label, labelSource string, modelTrainable bool) (types.RiskFeatureSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, snapshot := range s.features {
		if snapshot.ID != id {
			continue
		}
		snapshot.Label = label
		snapshot.LabelSource = labelSource
		snapshot.ModelTrainable = modelTrainable
		s.features[i] = snapshot
		return snapshot, nil
	}
	return types.RiskFeatureSnapshot{}, ErrNotFound
}

func (s *MemoryStore) ListRiskModelVersions(name string, limit int) []types.RiskModelVersion {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	out := make([]types.RiskModelVersion, 0, limit)
	for _, version := range s.modelsByCreatedDesc() {
		if name != "" && version.Name != name {
			continue
		}
		out = append(out, version)
		if len(out) == limit {
			break
		}
	}
	return out
}

func (s *MemoryStore) UpsertRiskModelVersion(version types.RiskModelVersion) types.RiskModelVersion {
	s.mu.Lock()
	defer s.mu.Unlock()
	version = prepareRiskModelVersion(version)
	if existing, ok := s.models[version.ID]; ok && !existing.CreatedAt.IsZero() {
		version.CreatedAt = existing.CreatedAt
		if version.ActivatedAt == nil {
			version.ActivatedAt = existing.ActivatedAt
		}
	}
	if version.Status == "active" {
		s.retireActiveModels(version.Name, version.ID)
		if version.ActivatedAt == nil {
			now := time.Now().UTC()
			version.ActivatedAt = &now
		}
	}
	s.models[version.ID] = version
	return version
}

func (s *MemoryStore) ActivateRiskModelVersion(id string) (types.RiskModelVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	version, ok := s.models[id]
	if !ok {
		return types.RiskModelVersion{}, ErrNotFound
	}
	version = prepareRiskModelVersion(version)
	now := time.Now().UTC()
	s.retireActiveModels(version.Name, version.ID)
	version.Status = "active"
	version.ActivatedAt = &now
	s.models[version.ID] = version
	return version, nil
}

func (s *MemoryStore) RollbackRiskModelVersion(id string) (types.RiskModelVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.models[id]
	if !ok {
		return types.RiskModelVersion{}, ErrNotFound
	}
	var candidate types.RiskModelVersion
	for _, version := range s.modelsByActivationDesc() {
		if version.ID == current.ID || version.Name != current.Name || version.Status != "retired" {
			continue
		}
		candidate = version
		break
	}
	if candidate.ID == "" {
		return types.RiskModelVersion{}, ErrNotFound
	}
	now := time.Now().UTC()
	for _, version := range s.models {
		if version.Name == current.Name && version.Status == "active" {
			version.Status = "rolled_back"
			s.models[version.ID] = version
		}
	}
	candidate.Status = "active"
	candidate.ActivatedAt = &now
	s.models[candidate.ID] = candidate
	return candidate, nil
}

func (s *MemoryStore) retireActiveModels(name, excludeID string) {
	for _, version := range s.models {
		if version.Name == name && version.ID != excludeID && version.Status == "active" {
			version.Status = "retired"
			s.models[version.ID] = version
		}
	}
}

func (s *MemoryStore) modelsByCreatedDesc() []types.RiskModelVersion {
	versions := make([]types.RiskModelVersion, 0, len(s.models))
	for _, version := range s.models {
		versions = append(versions, version)
	}
	sortRiskModelsByCreatedDesc(versions)
	return versions
}

func (s *MemoryStore) modelsByActivationDesc() []types.RiskModelVersion {
	versions := make([]types.RiskModelVersion, 0, len(s.models))
	for _, version := range s.models {
		versions = append(versions, version)
	}
	sortRiskModelsByActivationDesc(versions)
	return versions
}

func (s *MemoryStore) IncrementRate(key string, window time.Duration, maxRequests int, strategy ...string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	switch rateStrategy(strategy...) {
	case "sliding_window":
		counter := s.rateCounters[key]
		cutoff := now.Add(-window)
		hits := counter.Hits[:0]
		for _, hit := range counter.Hits {
			if hit.After(cutoff) {
				hits = append(hits, hit)
			}
		}
		hits = append(hits, now)
		counter.Hits = hits
		counter.Count = len(hits)
		counter.WindowStart = now
		s.rateCounters[key] = counter
		return counter.Count
	case "token_bucket":
		return s.incrementTokenBucketRate(key, now, window, maxRequests)
	}
	counter := s.rateCounters[key]
	if counter.WindowStart.IsZero() || now.Sub(counter.WindowStart) >= window {
		counter = rateCounter{WindowStart: now}
	}
	counter.Count++
	s.rateCounters[key] = counter
	return counter.Count
}

func (s *MemoryStore) incrementTokenBucketRate(key string, now time.Time, window time.Duration, maxRequests int) int {
	if maxRequests <= 0 || window <= 0 {
		return 1
	}
	counter := s.rateCounters[key]
	capacity := float64(maxRequests)
	if counter.LastRefill.IsZero() {
		counter.Tokens = capacity
		counter.LastRefill = now
	}
	elapsed := now.Sub(counter.LastRefill)
	if elapsed > 0 {
		refill := elapsed.Seconds() * capacity / window.Seconds()
		counter.Tokens = math.Min(capacity, counter.Tokens+refill)
		counter.LastRefill = now
	}
	if counter.Tokens < 1 {
		counter.Count = maxRequests + 1
		s.rateCounters[key] = counter
		return counter.Count
	}
	counter.Tokens--
	counter.Count = int(math.Ceil(capacity - counter.Tokens))
	if counter.Count < 1 {
		counter.Count = 1
	}
	s.rateCounters[key] = counter
	return counter.Count
}

func rateStrategy(values ...string) string {
	if len(values) == 0 || values[0] == "" {
		return "fixed_window"
	}
	switch strings.ToLower(strings.TrimSpace(values[0])) {
	case "sliding_window":
		return "sliding_window"
	case "token_bucket":
		return "token_bucket"
	default:
		return "fixed_window"
	}
}

func (s *MemoryStore) seed(now time.Time) {
	s.applications["app_demo"] = types.Application{
		ID:                "app_demo",
		ClientID:          "demo",
		Name:              "demo-app",
		Status:            "active",
		DefaultFailPolicy: "fail_open",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	s.routes["route_login"] = types.RoutePolicy{
		ID:              "route_login",
		ClientID:        "demo",
		Name:            "login",
		PathPattern:     "/api/login",
		Method:          "POST",
		Scene:           "login",
		Mode:            "risk_based",
		ChallengeType:   types.CaptchaSlider,
		FailPolicy:      "fail_close",
		Priority:        10,
		Enabled:         true,
		TokenTTLSeconds: 120,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	s.routes["route_register"] = types.RoutePolicy{
		ID:              "route_register",
		ClientID:        "demo",
		Name:            "register",
		PathPattern:     "/api/register",
		Method:          "POST",
		Scene:           "register",
		Mode:            "always",
		ChallengeType:   types.CaptchaWordImageClick,
		FailPolicy:      "fail_close",
		Priority:        20,
		Enabled:         true,
		TokenTTLSeconds: 120,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	s.routes["route_comment"] = types.RoutePolicy{
		ID:              "route_comment",
		ClientID:        "demo",
		Name:            "comment",
		PathPattern:     "/api/comment",
		Method:          "POST",
		Scene:           "comment",
		Mode:            "rate_limit",
		ChallengeType:   types.CaptchaRotate,
		FailPolicy:      "fail_open",
		Priority:        30,
		Enabled:         true,
		TokenTTLSeconds: 120,
		RateLimit:       &types.RateLimit{WindowSeconds: 60, MaxRequests: 5},
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	s.ipPolicies["ip_internal"] = types.IPPolicy{
		ID:        "ip_internal",
		ClientID:  "demo",
		Type:      "allowlist",
		CIDR:      "10.0.0.0/8",
		Action:    types.DecisionAllow,
		Reason:    "internal",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.ipPolicies["ip_abuse"] = types.IPPolicy{
		ID:        "ip_abuse",
		ClientID:  "demo",
		Type:      "blocklist",
		CIDR:      "203.0.113.0/24",
		Action:    types.DecisionBlock,
		Reason:    "abuse",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.resources["res_background"] = types.CaptchaResource{
		ID:           "res_background",
		ClientID:     "demo",
		CaptchaType:  types.CaptchaAuto,
		ResourceType: "background_image",
		StorageType:  "embedded",
		URI:          "embedded://default-backgrounds",
		Tag:          "default",
		Status:       "active",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.resources["res_slider"] = types.CaptchaResource{
		ID:           "res_slider",
		ClientID:     "demo",
		CaptchaType:  types.CaptchaSlider,
		ResourceType: "slider_template",
		StorageType:  "embedded",
		URI:          "embedded://slider-template",
		Tag:          "default",
		Status:       "active",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.resources["res_font"] = types.CaptchaResource{
		ID:           "res_font",
		ClientID:     "demo",
		CaptchaType:  types.CaptchaWordImageClick,
		ResourceType: "font",
		StorageType:  "embedded",
		URI:          "embedded://default-font",
		Tag:          "word",
		Status:       "active",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.auditEvents = append(s.auditEvents,
		types.AuditEvent{ID: "audit_seed_1", ClientID: "demo", Scene: "login", Route: "/api/login", Action: types.DecisionChallenge, DecisionReason: "RISK_BASED", ChallengeType: types.CaptchaSlider, Result: "pass", CreatedAt: now},
		types.AuditEvent{ID: "audit_seed_2", ClientID: "demo", Scene: "comment", Route: "/api/comment", Action: types.DecisionChallenge, DecisionReason: "RATE_LIMIT", ChallengeType: types.CaptchaRotate, Result: "retry", CreatedAt: now},
	)
}

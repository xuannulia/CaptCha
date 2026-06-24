package api

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"captcha/internal/types"
)

type adminMetricsResponse struct {
	ClientID         string         `json:"client_id,omitempty"`
	GeneratedAt      time.Time      `json:"generated_at"`
	Window           metricsWindow  `json:"window"`
	Totals           metricsTotals  `json:"totals"`
	Recent           recentMetrics  `json:"recent"`
	ByAction         map[string]int `json:"by_action"`
	ByResult         map[string]int `json:"by_result"`
	ByChallengeType  map[string]int `json:"by_challenge_type"`
	ResourceStatuses map[string]int `json:"resource_statuses"`
	RiskLabels       map[string]int `json:"risk_labels"`
	TopScenes        []metricCount  `json:"top_scenes"`
	TopReasons       []metricCount  `json:"top_reasons"`
	TopResources     []resourceHit  `json:"top_resources"`
}

type metricsWindow struct {
	AuditLimit   int `json:"audit_limit"`
	FeatureLimit int `json:"feature_limit"`
}

type metricsTotals struct {
	Applications            int `json:"applications"`
	ActiveApplications      int `json:"active_applications"`
	RoutePolicies           int `json:"route_policies"`
	EnabledRoutePolicies    int `json:"enabled_route_policies"`
	IPPolicies              int `json:"ip_policies"`
	EnabledIPPolicies       int `json:"enabled_ip_policies"`
	CaptchaResources        int `json:"captcha_resources"`
	ActiveCaptchaResources  int `json:"active_captcha_resources"`
	RiskFeatureSnapshots    int `json:"risk_feature_snapshots"`
	TrainableRiskFeatures   int `json:"trainable_risk_features"`
	RiskModelVersions       int `json:"risk_model_versions"`
	ActiveRiskModelVersions int `json:"active_risk_model_versions"`
}

type recentMetrics struct {
	AuditEvents      int     `json:"audit_events"`
	Allow            int     `json:"allow"`
	Challenge        int     `json:"challenge"`
	Block            int     `json:"block"`
	Observe          int     `json:"observe"`
	Pass             int     `json:"pass"`
	Retry            int     `json:"retry"`
	ConfigChanges    int     `json:"config_changes"`
	TrainingFeedback int     `json:"training_feedback"`
	PassRate         float64 `json:"pass_rate"`
	BlockRate        float64 `json:"block_rate"`
}

type metricCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type resourceHit struct {
	ID           string  `json:"id"`
	ResourceType string  `json:"resource_type,omitempty"`
	CaptchaType  string  `json:"captcha_type,omitempty"`
	Tag          string  `json:"tag,omitempty"`
	Attempts     int     `json:"attempts"`
	Pass         int     `json:"pass"`
	Retry        int     `json:"retry"`
	Block        int     `json:"block"`
	Unknown      int     `json:"unknown"`
	FailureRate  float64 `json:"failure_rate"`
}

func (s *Server) handleAdminMetrics(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	clientID := strings.TrimSpace(query.Get("client_id"))
	limit, _ := strconv.Atoi(query.Get("limit"))
	limit = normalizedListLimit(limit)
	writeJSON(w, http.StatusOK, s.buildAdminMetrics(clientID, limit))
}

func (s *Server) buildAdminMetrics(clientID string, limit int) adminMetricsResponse {
	applications := applicationsForMetrics(s.store.ListApplications(), clientID)
	routes := s.store.ListRoutePolicies(clientID)
	ipPolicies := s.store.ListIPPolicies(clientID)
	resources := s.store.ListResources(clientID)
	auditEvents := s.store.ListAuditEventsFiltered(types.AuditEventFilter{ClientID: clientID, Limit: limit})
	features := s.store.ListRiskFeatureSnapshotsFiltered(types.RiskFeatureSnapshotFilter{ClientID: clientID, Limit: limit})
	models := s.store.ListRiskModelVersions("", 200)

	response := adminMetricsResponse{
		ClientID:         clientID,
		GeneratedAt:      time.Now().UTC(),
		Window:           metricsWindow{AuditLimit: limit, FeatureLimit: limit},
		ByAction:         make(map[string]int),
		ByResult:         make(map[string]int),
		ByChallengeType:  initialCaptchaTypeMetrics(),
		ResourceStatuses: make(map[string]int),
		RiskLabels:       make(map[string]int),
	}
	response.Totals.Applications = len(applications)
	for _, application := range applications {
		if isActiveApplication(application) {
			response.Totals.ActiveApplications++
		}
	}
	response.Totals.RoutePolicies = len(routes)
	for _, route := range routes {
		if route.Enabled {
			response.Totals.EnabledRoutePolicies++
		}
	}
	response.Totals.IPPolicies = len(ipPolicies)
	for _, policy := range ipPolicies {
		if policy.Enabled {
			response.Totals.EnabledIPPolicies++
		}
	}
	response.Totals.CaptchaResources = len(resources)
	for _, resource := range resources {
		status := normalizedMetricName(resource.Status, "active")
		response.ResourceStatuses[status]++
		if strings.EqualFold(status, "active") {
			response.Totals.ActiveCaptchaResources++
		}
	}

	sceneCounts := make(map[string]int)
	reasonCounts := make(map[string]int)
	for _, event := range auditEvents {
		response.Recent.AuditEvents++
		action := normalizedMetricName(string(event.Action), "unknown")
		result := normalizedMetricName(event.Result, "unknown")
		response.ByAction[action]++
		response.ByResult[result]++
		switch event.Action {
		case types.DecisionAllow:
			response.Recent.Allow++
		case types.DecisionChallenge:
			response.Recent.Challenge++
		case types.DecisionBlock:
			response.Recent.Block++
		case types.DecisionObserve:
			response.Recent.Observe++
		}
		switch result {
		case "pass":
			response.Recent.Pass++
		case "retry":
			response.Recent.Retry++
		case "config_changed":
			response.Recent.ConfigChanges++
		case "training_feedback":
			response.Recent.TrainingFeedback++
		}
		if event.ChallengeType != "" {
			response.ByChallengeType[string(event.ChallengeType)]++
		}
		if event.Scene != "" {
			sceneCounts[event.Scene]++
		}
		if event.DecisionReason != "" {
			reasonCounts[event.DecisionReason]++
		}
	}
	verificationEvents := response.Recent.Pass + response.Recent.Retry + response.ByResult["block"]
	response.Recent.PassRate = percentage(response.Recent.Pass, verificationEvents)
	response.Recent.BlockRate = percentage(response.Recent.Block, response.Recent.AuditEvents)
	response.TopScenes = topMetricCounts(sceneCounts, 6)
	response.TopReasons = topMetricCounts(reasonCounts, 6)

	response.Totals.RiskFeatureSnapshots = len(features)
	for _, feature := range features {
		label := normalizedMetricName(feature.Label, "unknown")
		response.RiskLabels[label]++
		if feature.ModelTrainable {
			response.Totals.TrainableRiskFeatures++
		}
	}
	response.TopResources = topResourceHits(features, 8)
	response.Totals.RiskModelVersions = len(models)
	for _, model := range models {
		if strings.EqualFold(model.Status, "active") {
			response.Totals.ActiveRiskModelVersions++
		}
	}
	return response
}

func (s *Server) handlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.requireMetricsToken(w, r) {
		return
	}
	query := r.URL.Query()
	clientID := strings.TrimSpace(query.Get("client_id"))
	limit, _ := strconv.Atoi(query.Get("limit"))
	limit = normalizedListLimit(limit)
	metrics := s.buildAdminMetrics(clientID, limit)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(prometheusMetrics(metrics)))
}

func prometheusMetrics(metrics adminMetricsResponse) string {
	var out strings.Builder
	writePrometheusGauge(&out, "captcha_applications_total", "Configured applications.", nil, metrics.Totals.Applications)
	writePrometheusGauge(&out, "captcha_applications_active_total", "Active applications.", nil, metrics.Totals.ActiveApplications)
	writePrometheusGauge(&out, "captcha_route_policies_total", "Configured route policies.", nil, metrics.Totals.RoutePolicies)
	writePrometheusGauge(&out, "captcha_route_policies_enabled_total", "Enabled route policies.", nil, metrics.Totals.EnabledRoutePolicies)
	writePrometheusGauge(&out, "captcha_ip_policies_total", "Configured IP policies.", nil, metrics.Totals.IPPolicies)
	writePrometheusGauge(&out, "captcha_ip_policies_enabled_total", "Enabled IP policies.", nil, metrics.Totals.EnabledIPPolicies)
	writePrometheusGauge(&out, "captcha_resources_total", "Configured captcha resources.", nil, metrics.Totals.CaptchaResources)
	writePrometheusGauge(&out, "captcha_resources_active_total", "Active captcha resources.", nil, metrics.Totals.ActiveCaptchaResources)
	writePrometheusGauge(&out, "captcha_risk_feature_snapshots_recent_total", "Risk feature snapshots in the recent metrics window.", nil, metrics.Totals.RiskFeatureSnapshots)
	writePrometheusGauge(&out, "captcha_risk_feature_snapshots_trainable_recent_total", "Trainable risk feature snapshots in the recent metrics window.", nil, metrics.Totals.TrainableRiskFeatures)
	writePrometheusGauge(&out, "captcha_risk_model_versions_total", "Registered risk model versions.", nil, metrics.Totals.RiskModelVersions)
	writePrometheusGauge(&out, "captcha_risk_model_versions_active_total", "Active risk model versions.", nil, metrics.Totals.ActiveRiskModelVersions)
	writePrometheusGauge(&out, "captcha_audit_events_recent_total", "Audit events in the recent metrics window.", nil, metrics.Recent.AuditEvents)
	writePrometheusGauge(&out, "captcha_verify_pass_rate_recent_percent", "Verification pass rate in the recent metrics window.", nil, metrics.Recent.PassRate)
	writePrometheusGauge(&out, "captcha_decision_block_rate_recent_percent", "Block decision rate in the recent metrics window.", nil, metrics.Recent.BlockRate)
	writePrometheusGauge(&out, "captcha_metrics_generated_timestamp_seconds", "Unix timestamp when metrics were generated.", nil, metrics.GeneratedAt.Unix())
	writePrometheusMetricMap(&out, "captcha_audit_actions_recent_total", "Audit actions in the recent metrics window.", "action", metrics.ByAction)
	writePrometheusMetricMap(&out, "captcha_audit_results_recent_total", "Audit results in the recent metrics window.", "result", metrics.ByResult)
	writePrometheusMetricMap(&out, "captcha_challenge_types_recent_total", "Challenge types in the recent metrics window.", "challenge_type", metrics.ByChallengeType)
	writePrometheusMetricMap(&out, "captcha_resource_statuses_total", "Captcha resource statuses.", "status", metrics.ResourceStatuses)
	writePrometheusMetricMap(&out, "captcha_risk_feature_labels_recent_total", "Risk feature labels in the recent metrics window.", "label", metrics.RiskLabels)
	writePrometheusResourceHits(&out, metrics.TopResources)
	return out.String()
}

func writePrometheusResourceHits(out *strings.Builder, resources []resourceHit) {
	writePrometheusHelp(out, "captcha_resource_hits_recent_total", "Captcha resource hits in the recent metrics window.")
	for _, resource := range resources {
		writePrometheusGaugeValue(out, "captcha_resource_hits_recent_total", resourcePrometheusLabels(resource), resource.Attempts)
	}
	writePrometheusHelp(out, "captcha_resource_failures_recent_total", "Captcha resource failed attempts in the recent metrics window.")
	for _, resource := range resources {
		writePrometheusGaugeValue(out, "captcha_resource_failures_recent_total", resourcePrometheusLabels(resource), resource.Retry+resource.Block)
	}
	writePrometheusHelp(out, "captcha_resource_failure_rate_recent_percent", "Captcha resource failure rate in the recent metrics window.")
	for _, resource := range resources {
		writePrometheusGaugeValue(out, "captcha_resource_failure_rate_recent_percent", resourcePrometheusLabels(resource), resource.FailureRate)
	}
}

func resourcePrometheusLabels(resource resourceHit) map[string]string {
	labels := map[string]string{"resource_id": resource.ID}
	if resource.ResourceType != "" {
		labels["resource_type"] = resource.ResourceType
	}
	if resource.CaptchaType != "" {
		labels["challenge_type"] = resource.CaptchaType
	}
	if resource.Tag != "" {
		labels["tag"] = resource.Tag
	}
	return labels
}

func writePrometheusMetricMap(out *strings.Builder, name, help, labelName string, values map[string]int) {
	writePrometheusHelp(out, name, help)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		writePrometheusGaugeValue(out, name, map[string]string{labelName: key}, values[key])
	}
}

func writePrometheusGauge(out *strings.Builder, name, help string, labels map[string]string, value any) {
	writePrometheusHelp(out, name, help)
	writePrometheusGaugeValue(out, name, labels, value)
}

func writePrometheusHelp(out *strings.Builder, name, help string) {
	fmt.Fprintf(out, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
}

func writePrometheusGaugeValue(out *strings.Builder, name string, labels map[string]string, value any) {
	out.WriteString(name)
	if len(labels) > 0 {
		keys := make([]string, 0, len(labels))
		for key := range labels {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteString("{")
		for i, key := range keys {
			if i > 0 {
				out.WriteString(",")
			}
			fmt.Fprintf(out, `%s="%s"`, key, prometheusLabelValue(labels[key]))
		}
		out.WriteString("}")
	}
	fmt.Fprintf(out, " %v\n", value)
}

func prometheusLabelValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value
}

func (s *Server) requireMetricsToken(w http.ResponseWriter, r *http.Request) bool {
	if s.options.MetricsToken == "" {
		return true
	}
	if validNamedToken(r, "X-Captcha-Metrics-Token", s.options.MetricsToken) {
		return true
	}
	writeError(w, http.StatusUnauthorized, "UNAUTHORIZED")
	return false
}

func applicationsForMetrics(applications []types.Application, clientID string) []types.Application {
	if clientID == "" {
		return applications
	}
	out := make([]types.Application, 0, 1)
	for _, application := range applications {
		if application.ClientID == clientID {
			out = append(out, application)
		}
	}
	return out
}

func initialCaptchaTypeMetrics() map[string]int {
	return map[string]int{
		string(types.CaptchaGesture):        0,
		string(types.CaptchaCurve):          0,
		string(types.CaptchaCurve2):         0,
		string(types.CaptchaCurve3):         0,
		string(types.CaptchaSlider):         0,
		string(types.CaptchaSlider2):        0,
		string(types.CaptchaRotate):         0,
		string(types.CaptchaConcat):         0,
		string(types.CaptchaRotateDegree):   0,
		string(types.CaptchaWordImageClick): 0,
		string(types.CaptchaImageClick):     0,
		string(types.CaptchaJigsaw):         0,
		string(types.CaptchaGridImageClick): 0,
	}
}

func normalizedMetricName(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func percentage(part, total int) float64 {
	if total <= 0 {
		return 0
	}
	return math.Round(float64(part)*1000/float64(total)) / 10
}

func topMetricCounts(counts map[string]int, limit int) []metricCount {
	items := make([]metricCount, 0, len(counts))
	for name, count := range counts {
		items = append(items, metricCount{Name: name, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Name < items[j].Name
	})
	if len(items) > limit {
		return items[:limit]
	}
	return items
}

func topResourceHits(features []types.RiskFeatureSnapshot, limit int) []resourceHit {
	byID := make(map[string]*resourceHit)
	for _, feature := range features {
		outcome := resourceFeatureOutcome(feature)
		for _, ref := range featureResourceRefs(feature.Features) {
			item := byID[ref.ID]
			if item == nil {
				item = &resourceHit{
					ID:           ref.ID,
					ResourceType: ref.ResourceType,
					CaptchaType:  ref.CaptchaType,
					Tag:          ref.Tag,
				}
				byID[ref.ID] = item
			}
			item.Attempts++
			switch outcome {
			case "pass":
				item.Pass++
			case "retry":
				item.Retry++
			case "block":
				item.Block++
			default:
				item.Unknown++
			}
		}
	}
	items := make([]resourceHit, 0, len(byID))
	for _, item := range byID {
		item.FailureRate = percentage(item.Retry+item.Block, item.Attempts)
		items = append(items, *item)
	}
	sort.Slice(items, func(i, j int) bool {
		leftFailures := items[i].Retry + items[i].Block
		rightFailures := items[j].Retry + items[j].Block
		if leftFailures != rightFailures {
			return leftFailures > rightFailures
		}
		if items[i].FailureRate != items[j].FailureRate {
			return items[i].FailureRate > items[j].FailureRate
		}
		if items[i].Attempts != items[j].Attempts {
			return items[i].Attempts > items[j].Attempts
		}
		return items[i].ID < items[j].ID
	})
	if len(items) > limit {
		return items[:limit]
	}
	return items
}

type resourceFeatureRefMetric struct {
	ID           string
	ResourceType string
	CaptchaType  string
	Tag          string
}

func featureResourceRefs(features map[string]any) []resourceFeatureRefMetric {
	if len(features) == 0 {
		return nil
	}
	value, ok := features["resources"]
	if !ok {
		return nil
	}
	switch resources := value.(type) {
	case []map[string]any:
		return mapFeatureResourceRefs(resources)
	case []any:
		maps := make([]map[string]any, 0, len(resources))
		for _, item := range resources {
			if typed, ok := item.(map[string]any); ok {
				maps = append(maps, typed)
			}
		}
		return mapFeatureResourceRefs(maps)
	default:
		return nil
	}
}

func mapFeatureResourceRefs(resources []map[string]any) []resourceFeatureRefMetric {
	refs := make([]resourceFeatureRefMetric, 0, len(resources))
	seen := make(map[string]struct{}, len(resources))
	for _, item := range resources {
		id := strings.TrimSpace(metricString(item["id"]))
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		refs = append(refs, resourceFeatureRefMetric{
			ID:           id,
			ResourceType: strings.TrimSpace(metricString(item["resource_type"])),
			CaptchaType:  strings.TrimSpace(metricString(item["captcha_type"])),
			Tag:          strings.TrimSpace(metricString(item["tag"])),
		})
	}
	return refs
}

func metricString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case types.CaptchaType:
		return string(typed)
	default:
		return ""
	}
}

func resourceFeatureOutcome(feature types.RiskFeatureSnapshot) string {
	if ok, _ := feature.Features["result_ok"].(bool); ok {
		return "pass"
	}
	switch strings.ToLower(strings.TrimSpace(metricString(feature.Features["decision"]))) {
	case "pass":
		return "pass"
	case "retry", "challenge_harder":
		return "retry"
	case "block":
		return "block"
	}
	switch strings.ToLower(strings.TrimSpace(feature.Label)) {
	case "captcha_pass", "likely_human", "confirmed_human":
		return "pass"
	case "captcha_retry", "likely_bot", "confirmed_bot":
		return "retry"
	default:
		return "unknown"
	}
}

package risk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"captcha/internal/types"
)

type Inferencer interface {
	Infer(context.Context, types.PolicyEvaluateRequest, types.RiskModelVersion) (Inference, error)
}

type ModelStore interface {
	ListRiskModelVersions(name string, limit int) []types.RiskModelVersion
}

type Inference struct {
	Score     *int     `json:"score,omitempty"`
	RiskScore *int     `json:"risk_score,omitempty"`
	RiskLevel string   `json:"risk_level,omitempty"`
	Mode      string   `json:"mode,omitempty"`
	Reasons   []string `json:"reasons,omitempty"`
}

type HTTPInferencer struct {
	Endpoint string
	Token    string
	Timeout  time.Duration
	Client   *http.Client
}

func NewHTTPInferencer(endpoint, token string, timeout time.Duration) *HTTPInferencer {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	return &HTTPInferencer{Endpoint: endpoint, Token: strings.TrimSpace(token), Timeout: timeout}
}

func EnrichPolicyRequest(ctx context.Context, inferencer Inferencer, models ModelStore, req *types.PolicyEvaluateRequest) error {
	if inferencer == nil || models == nil || req == nil || req.Ticket != "" {
		return nil
	}
	if req.ModelScore > 0 || strings.TrimSpace(req.ModelMode) != "" {
		return nil
	}
	model, ok := ActiveModel(models)
	if !ok {
		return nil
	}
	inference, err := inferencer.Infer(ctx, *req, model)
	if err != nil {
		return err
	}
	if score, ok := inferenceScore(inference); ok {
		req.ModelScore = clampScore(score)
	}
	mode := strings.TrimSpace(inference.Mode)
	if mode == "" {
		mode = model.Mode
	}
	req.ModelMode = mode
	if req.RiskLevel == "" && inference.RiskLevel != "" {
		req.RiskLevel = strings.TrimSpace(inference.RiskLevel)
	}
	return nil
}

func ActiveModel(models ModelStore) (types.RiskModelVersion, bool) {
	versions := models.ListRiskModelVersions("", 100)
	var selected types.RiskModelVersion
	for _, version := range versions {
		if version.Status != "active" || !inferenceMode(version.Mode) {
			continue
		}
		if selected.ID == "" || activatedAfter(version, selected) {
			selected = version
		}
	}
	return selected, selected.ID != ""
}

func (c *HTTPInferencer) Infer(ctx context.Context, req types.PolicyEvaluateRequest, model types.RiskModelVersion) (Inference, error) {
	if c == nil || strings.TrimSpace(c.Endpoint) == "" {
		return Inference{}, errors.New("risk inference endpoint is empty")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	body, err := json.Marshal(inferenceRequestFromPolicy(req, model))
	if err != nil {
		return Inference{}, err
	}
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return Inference{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	}
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(httpReq)
	if err != nil {
		return Inference{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Inference{}, fmt.Errorf("risk inference status %d", response.StatusCode)
	}
	var inference Inference
	if err := json.NewDecoder(response.Body).Decode(&inference); err != nil {
		return Inference{}, err
	}
	return inference, nil
}

type inferenceRequest struct {
	ClientID      string         `json:"client_id"`
	Scene         string         `json:"scene,omitempty"`
	Path          string         `json:"path,omitempty"`
	Method        string         `json:"method,omitempty"`
	IPHash        string         `json:"ip_hash,omitempty"`
	UserAgentHash string         `json:"user_agent_hash,omitempty"`
	AccountIDHash string         `json:"account_id_hash,omitempty"`
	DeviceIDHash  string         `json:"device_id_hash,omitempty"`
	RiskScore     int            `json:"risk_score,omitempty"`
	RiskLevel     string         `json:"risk_level,omitempty"`
	Model         inferenceModel `json:"model"`
}

type inferenceModel struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Version        string         `json:"version"`
	FeatureVersion string         `json:"feature_version"`
	Mode           string         `json:"mode"`
	Metrics        map[string]any `json:"metrics,omitempty"`
}

func inferenceRequestFromPolicy(req types.PolicyEvaluateRequest, model types.RiskModelVersion) inferenceRequest {
	return inferenceRequest{
		ClientID:      req.ClientID,
		Scene:         req.Scene,
		Path:          req.Path,
		Method:        req.Method,
		IPHash:        hashValue(req.IP),
		UserAgentHash: hashValue(req.UserAgent),
		AccountIDHash: req.AccountIDHash,
		DeviceIDHash:  req.DeviceIDHash,
		RiskScore:     req.RiskScore,
		RiskLevel:     req.RiskLevel,
		Model: inferenceModel{
			ID:             model.ID,
			Name:           model.Name,
			Version:        model.Version,
			FeatureVersion: model.FeatureVersion,
			Mode:           model.Mode,
			Metrics:        model.Metrics,
		},
	}
}

func inferenceScore(inference Inference) (int, bool) {
	if inference.Score != nil {
		return *inference.Score, true
	}
	if inference.RiskScore != nil {
		return *inference.RiskScore, true
	}
	return 0, false
}

func inferenceMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "shadow", "observe", "enforce":
		return true
	default:
		return false
	}
}

func activatedAfter(left, right types.RiskModelVersion) bool {
	leftAt := time.Time{}
	if left.ActivatedAt != nil {
		leftAt = *left.ActivatedAt
	}
	rightAt := time.Time{}
	if right.ActivatedAt != nil {
		rightAt = *right.ActivatedAt
	}
	if !leftAt.Equal(rightAt) {
		return leftAt.After(rightAt)
	}
	return left.CreatedAt.After(right.CreatedAt)
}

func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
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

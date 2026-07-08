package types

import "time"

type CaptchaType string

const (
	CaptchaAuto           CaptchaType = "AUTO"
	CaptchaGesture        CaptchaType = "GESTURE"
	CaptchaCurve          CaptchaType = "CURVE"
	CaptchaCurve2         CaptchaType = "CURVE_V2"
	CaptchaCurve3         CaptchaType = "CURVE_V3"
	CaptchaSlider         CaptchaType = "SLIDER"
	CaptchaSlider2        CaptchaType = "SLIDER_V2"
	CaptchaRotate         CaptchaType = "ROTATE"
	CaptchaConcat         CaptchaType = "CONCAT"
	CaptchaRotateDegree   CaptchaType = "ROTATE_DEGREE"
	CaptchaWordImageClick CaptchaType = "WORD_IMAGE_CLICK"
	CaptchaImageClick     CaptchaType = "IMAGE_CLICK"
	CaptchaWordOrderClick CaptchaType = "WORD_ORDER_IMAGE_CLICK"
	CaptchaJigsaw         CaptchaType = "JIGSAW"
	CaptchaGridImageClick CaptchaType = "GRID_IMAGE_CLICK"
)

type Decision string

const (
	DecisionAllow           Decision = "allow"
	DecisionChallenge       Decision = "challenge"
	DecisionPass            Decision = "pass"
	DecisionRetry           Decision = "retry"
	DecisionChallengeHarder Decision = "challenge_harder"
	DecisionBlock           Decision = "block"
	DecisionObserve         Decision = "observe"
	DecisionSkipChallenge   Decision = "skip_challenge"
	DecisionStepUpChallenge Decision = "step_up_challenge"
	DecisionRateLimit       Decision = "rate_limit"
	DecisionCooldown        Decision = "cooldown"
	DecisionBusinessVerify  Decision = "require_business_verify"
)

func IsAllowLikeDecision(decision Decision) bool {
	switch decision {
	case DecisionAllow, DecisionPass, DecisionObserve, DecisionSkipChallenge:
		return true
	default:
		return false
	}
}

func IsChallengeLikeDecision(decision Decision) bool {
	switch decision {
	case DecisionChallenge, DecisionChallengeHarder, DecisionStepUpChallenge, DecisionRateLimit:
		return true
	default:
		return false
	}
}

func IsBlockLikeDecision(decision Decision) bool {
	switch decision {
	case DecisionBlock, DecisionCooldown, DecisionBusinessVerify:
		return true
	default:
		return false
	}
}

type SessionStatus string

const (
	SessionActive   SessionStatus = "active"
	SessionVerified SessionStatus = "verified"
	SessionExpired  SessionStatus = "expired"
)

type ChallengeSession struct {
	ID                  string
	ClientID            string
	Scene               string
	Type                CaptchaType
	ChallengeEscalation []CaptchaType
	Route               string
	RequestNonce        string
	ResourceTag         string
	ReturnURL           string
	IPHash              string
	UserAgentHash       string
	AccountIDHash       string
	DeviceIDHash        string
	Answer              Answer
	RenderPayload       RenderPayload
	FailureCount        int
	Status              SessionStatus
	ExpiresAt           time.Time
	CreatedAt           time.Time
}

type Answer struct {
	X      int
	Y      int
	Angle  int
	Offset int
	Points []Point
	Token  string
}

type Point struct {
	X int `json:"x"`
	Y int `json:"y"`
}

type RenderPayload struct {
	Type       CaptchaType    `json:"type"`
	Prompt     string         `json:"prompt"`
	View       View           `json:"view"`
	Image      string         `json:"image,omitempty"`
	Piece      string         `json:"piece,omitempty"`
	Words      []string       `json:"words,omitempty"`
	Parameters map[string]any `json:"parameters,omitempty"`
}

type View struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

type TrackPoint struct {
	X    float64 `json:"x"`
	Y    float64 `json:"y"`
	T    int64   `json:"t"`
	Type string  `json:"type"`
}

type VerifyAnswer struct {
	X         *int    `json:"x,omitempty"`
	Y         *int    `json:"y,omitempty"`
	Angle     *int    `json:"angle,omitempty"`
	Offset    *int    `json:"offset,omitempty"`
	Points    []Point `json:"points,omitempty"`
	TileOrder []int   `json:"tile_order,omitempty"`
}

type TrackScore struct {
	Score      int      `json:"score"`
	Bucket     string   `json:"bucket"`
	Reasons    []string `json:"reasons,omitempty"`
	DurationMS int64    `json:"durationMs"`
	PointCount int      `json:"pointCount"`
}

type VerifyResult struct {
	OK          bool
	Decision    Decision
	ReasonCode  string
	TrackScore  TrackScore
	IssueTicket bool
}

type Ticket struct {
	Value         string
	ClientID      string
	Scene         string
	Route         string
	RequestNonce  string
	IPHash        string
	UserAgentHash string
	AccountIDHash string
	DeviceIDHash  string
	Consumed      bool
	ExpiresAt     time.Time
	CreatedAt     time.Time
	ConsumedAt    *time.Time
}

type Clearance struct {
	Value         string
	ClientID      string
	Scene         string
	IPHash        string
	UserAgentHash string
	AccountIDHash string
	DeviceIDHash  string
	ExpiresAt     time.Time
	CreatedAt     time.Time
}

type Application struct {
	ID                string    `json:"id"`
	ClientID          string    `json:"client_id"`
	Name              string    `json:"name"`
	SecretHash        string    `json:"-"`
	HasSecret         bool      `json:"has_secret"`
	Status            string    `json:"status"`
	DefaultFailPolicy string    `json:"default_fail_policy"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type RoutePolicy struct {
	ID                  string        `json:"id"`
	ClientID            string        `json:"client_id"`
	Name                string        `json:"name"`
	PathPattern         string        `json:"path_pattern"`
	Method              string        `json:"method"`
	Scene               string        `json:"scene"`
	Mode                string        `json:"mode"`
	ChallengeType       CaptchaType   `json:"challenge_type"`
	RiskChallengeType   CaptchaType   `json:"risk_challenge_type,omitempty"`
	ChallengeEscalation []CaptchaType `json:"challenge_escalation,omitempty"`
	FailPolicy          string        `json:"fail_policy"`
	Priority            int           `json:"priority"`
	Enabled             bool          `json:"enabled"`
	RolloutPercent      int           `json:"rollout_percent"`
	TokenTTLSeconds     int           `json:"token_ttl_seconds"`
	RiskChallengeScore  int           `json:"risk_challenge_score,omitempty"`
	RiskBlockScore      int           `json:"risk_block_score,omitempty"`
	RiskObserveScore    int           `json:"risk_observe_score,omitempty"`
	RateLimit           *RateLimit    `json:"rate_limit,omitempty"`
	CreatedAt           time.Time     `json:"created_at"`
	UpdatedAt           time.Time     `json:"updated_at"`
}

type RateLimit struct {
	WindowSeconds int    `json:"window_seconds"`
	MaxRequests   int    `json:"max_requests"`
	Strategy      string `json:"strategy,omitempty"`
}

type PolicyRule struct {
	ID             string                `json:"id"`
	ClientID       string                `json:"client_id"`
	Name           string                `json:"name"`
	Description    string                `json:"description,omitempty"`
	Priority       int                   `json:"priority"`
	Enabled        bool                  `json:"enabled"`
	Status         string                `json:"status,omitempty"`
	Version        string                `json:"version,omitempty"`
	Scope          PolicyRuleScope       `json:"scope,omitempty"`
	Conditions     PolicyCondition       `json:"conditions,omitempty"`
	Aggregation    PolicyRuleAggregation `json:"aggregation,omitempty"`
	Action         PolicyRuleAction      `json:"action"`
	RolloutPercent int                   `json:"rollout_percent,omitempty"`
	CreatedAt      time.Time             `json:"created_at"`
	UpdatedAt      time.Time             `json:"updated_at"`
}

type PolicyRuleScope struct {
	ClientID       string     `json:"client_id,omitempty"`
	Scenes         []string   `json:"scenes,omitempty"`
	PathPatterns   []string   `json:"path_patterns,omitempty"`
	Methods        []string   `json:"methods,omitempty"`
	ResourceTags   []string   `json:"resource_tags,omitempty"`
	ActiveFrom     *time.Time `json:"active_from,omitempty"`
	ActiveUntil    *time.Time `json:"active_until,omitempty"`
	RolloutPercent int        `json:"rollout_percent,omitempty"`
}

type PolicyCondition struct {
	All    []PolicyCondition `json:"all,omitempty"`
	Any    []PolicyCondition `json:"any,omitempty"`
	Not    *PolicyCondition  `json:"not,omitempty"`
	Field  string            `json:"field,omitempty"`
	Op     string            `json:"op,omitempty"`
	Value  any               `json:"value,omitempty"`
	Values []any             `json:"values,omitempty"`
}

type PolicyRuleAggregation struct {
	Dimensions      []string `json:"dimensions,omitempty"`
	WindowSeconds   int      `json:"window_seconds,omitempty"`
	MaxRequests     int      `json:"max_requests,omitempty"`
	Strategy        string   `json:"strategy,omitempty"`
	CooldownSeconds int      `json:"cooldown_seconds,omitempty"`
}

type PolicyRuleAction struct {
	Type                Decision      `json:"type"`
	Reason              string        `json:"reason,omitempty"`
	ChallengeType       CaptchaType   `json:"challenge_type,omitempty"`
	ChallengeEscalation []CaptchaType `json:"challenge_escalation,omitempty"`
	TTLSeconds          int           `json:"ttl_seconds,omitempty"`
	CooldownSeconds     int           `json:"cooldown_seconds,omitempty"`
	BusinessVerifyType  string        `json:"business_verify_type,omitempty"`
}

type IPPolicy struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"client_id"`
	Type      string    `json:"type"`
	CIDR      string    `json:"cidr"`
	Action    Decision  `json:"action"`
	Reason    string    `json:"reason"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type CaptchaResource struct {
	ID           string         `json:"id"`
	ClientID     string         `json:"client_id"`
	Scene        string         `json:"scene"`
	CaptchaType  CaptchaType    `json:"captcha_type"`
	ResourceType string         `json:"resource_type"`
	StorageType  string         `json:"storage_type"`
	URI          string         `json:"uri"`
	Tag          string         `json:"tag"`
	Checksum     string         `json:"checksum,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	Status       string         `json:"status"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

type AuditEvent struct {
	ID             string      `json:"id"`
	ClientID       string      `json:"client_id"`
	Scene          string      `json:"scene"`
	Route          string      `json:"route"`
	IPHash         string      `json:"ip_hash"`
	AccountIDHash  string      `json:"account_id_hash"`
	DeviceIDHash   string      `json:"device_id_hash"`
	Action         Decision    `json:"action"`
	DecisionReason string      `json:"decision_reason"`
	ChallengeType  CaptchaType `json:"challenge_type"`
	Result         string      `json:"result"`
	CreatedAt      time.Time   `json:"created_at"`
}

type AuditEventFilter struct {
	ClientID       string
	Scene          string
	Action         Decision
	Result         string
	DecisionReason string
	AccountIDHash  string
	DeviceIDHash   string
	Limit          int
	Offset         int
}

type PolicyEvaluateRequest struct {
	ClientID      string            `json:"client_id"`
	Scene         string            `json:"scene"`
	Path          string            `json:"path"`
	Method        string            `json:"method"`
	IP            string            `json:"ip"`
	UserAgent     string            `json:"user_agent"`
	AccountIDHash string            `json:"account_id_hash"`
	DeviceIDHash  string            `json:"device_id_hash"`
	Ticket        string            `json:"ticket"`
	Clearance     string            `json:"clearance,omitempty"`
	RequestNonce  string            `json:"request_nonce"`
	ResourceTag   string            `json:"resource_tag"`
	RiskScore     int               `json:"risk_score,omitempty"`
	RiskLevel     string            `json:"risk_level,omitempty"`
	ModelScore    int               `json:"model_score,omitempty"`
	ModelMode     string            `json:"model_mode,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
}

type PolicyDecision struct {
	Action              Decision    `json:"action"`
	Reason              string      `json:"reason"`
	ChallengeURL        string      `json:"challenge_url,omitempty"`
	SessionID           string      `json:"session_id,omitempty"`
	Scene               string      `json:"scene,omitempty"`
	ChallengeType       CaptchaType `json:"challenge_type,omitempty"`
	TTLSeconds          int         `json:"ttl_seconds,omitempty"`
	CooldownSeconds     int         `json:"cooldown_seconds,omitempty"`
	BusinessVerifyType  string      `json:"business_verify_type,omitempty"`
	ClearanceToken      string      `json:"clearance_token,omitempty"`
	ClearanceTTLSeconds int         `json:"clearance_ttl_seconds,omitempty"`
}

type TicketVerifyRequest struct {
	Ticket        string `json:"ticket"`
	ClientID      string `json:"client_id"`
	Scene         string `json:"scene"`
	Route         string `json:"route"`
	RequestNonce  string `json:"request_nonce"`
	IPHash        string `json:"ip_hash"`
	UserAgentHash string `json:"user_agent_hash"`
	AccountIDHash string `json:"account_id_hash,omitempty"`
	DeviceIDHash  string `json:"device_id_hash,omitempty"`
}

type TicketVerifyResponse struct {
	Valid               bool      `json:"valid"`
	Reason              string    `json:"reason,omitempty"`
	ClientID            string    `json:"client_id,omitempty"`
	Scene               string    `json:"scene,omitempty"`
	Route               string    `json:"route,omitempty"`
	RequestNonce        string    `json:"request_nonce,omitempty"`
	IPHash              string    `json:"ip_hash,omitempty"`
	UserAgentHash       string    `json:"user_agent_hash,omitempty"`
	ExpireAt            time.Time `json:"expire_at,omitempty"`
	ClearanceToken      string    `json:"clearance_token,omitempty"`
	ClearanceExpireAt   time.Time `json:"clearance_expire_at,omitempty"`
	ClearanceTTLSeconds int       `json:"clearance_ttl_seconds,omitempty"`
}

type ConfigRequest struct {
	ClientID string `json:"client_id"`
}

type ConfigSnapshot struct {
	ClientID          string            `json:"client_id"`
	ApplicationStatus string            `json:"application_status,omitempty"`
	Routes            []RoutePolicy     `json:"routes"`
	PolicyRules       []PolicyRule      `json:"policy_rules,omitempty"`
	IPPolicies        []IPPolicy        `json:"ip_policies"`
	Resources         []CaptchaResource `json:"resources,omitempty"`
	Version           int64             `json:"version"`
}

type EventBatch struct {
	Events []AuditEvent `json:"events"`
}

type ReportResult struct {
	Accepted int `json:"accepted"`
}

type RiskFeatureSnapshot struct {
	ID             string         `json:"id"`
	AttemptID      string         `json:"attempt_id"`
	ClientID       string         `json:"client_id"`
	Scene          string         `json:"scene"`
	ChallengeType  CaptchaType    `json:"challenge_type"`
	FeatureVersion string         `json:"feature_version"`
	FeaturesDigest string         `json:"features_digest"`
	FeaturesRef    string         `json:"features_ref"`
	Features       map[string]any `json:"features,omitempty"`
	Label          string         `json:"label"`
	LabelSource    string         `json:"label_source"`
	ModelTrainable bool           `json:"model_trainable"`
	CreatedAt      time.Time      `json:"created_at"`
}

type RiskFeatureSnapshotFilter struct {
	ClientID       string
	Scene          string
	ChallengeType  CaptchaType
	Label          string
	ModelTrainable *bool
	Limit          int
	Offset         int
}

type RiskModelVersion struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Version        string         `json:"version"`
	FeatureVersion string         `json:"feature_version"`
	TrainingWindow string         `json:"training_window"`
	ArtifactURI    string         `json:"artifact_uri"`
	Metrics        map[string]any `json:"metrics,omitempty"`
	Mode           string         `json:"mode"`
	Status         string         `json:"status"`
	CreatedAt      time.Time      `json:"created_at"`
	ActivatedAt    *time.Time     `json:"activated_at,omitempty"`
}

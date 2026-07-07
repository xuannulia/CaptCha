package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"strings"
	"time"

	"captcha/internal/engine"
	"captcha/internal/types"
)

const (
	SyntheticBotTrackSchemaVersion    = "risk-feature-export-v1"
	SyntheticBotTrackFeatureVersion   = "track-v1"
	SyntheticBotTrackGeneratorVersion = "bot-track-v2"
)

type BotTrackFamily string

const (
	BotTrackPerfectLinear   BotTrackFamily = "perfect_linear"
	BotTrackLowPointJump    BotTrackFamily = "low_point_jump"
	BotTrackTeleport        BotTrackFamily = "teleport"
	BotTrackTimestampSkew   BotTrackFamily = "timestamp_skew"
	BotTrackEasedLinear     BotTrackFamily = "eased_linear"
	BotTrackBezierScript    BotTrackFamily = "bezier_script"
	BotTrackReplayShift     BotTrackFamily = "replay_shift"
	BotTrackQuantizedGrid   BotTrackFamily = "quantized_grid"
	BotTrackSnapEnd         BotTrackFamily = "snap_end"
	BotTrackHyperDense      BotTrackFamily = "hyper_dense"
	BotTrackMechanicalPause BotTrackFamily = "mechanical_pause"
	BotTrackSegmentedLinear BotTrackFamily = "segmented_linear"
	BotTrackNoisyEase       BotTrackFamily = "noisy_ease"
	BotTrackOvershootReturn BotTrackFamily = "overshoot_return"
	BotTrackBrowserMouse    BotTrackFamily = "browser_mouse"
	BotTrackDomSnap         BotTrackFamily = "dom_snap"
	BotTrackTouchFlick      BotTrackFamily = "touch_flick"
)

type BotTrackOptions struct {
	Count          int
	Seed           int64
	ClientID       string
	Scene          string
	ChallengeTypes []types.CaptchaType
	CreatedAt      time.Time
	MinTargetX     int
	MaxTargetX     int
	BaselineY      float64
}

type SyntheticTrackRecord struct {
	SchemaVersion  string             `json:"schema_version"`
	ID             string             `json:"id"`
	AttemptID      string             `json:"attempt_id"`
	ClientID       string             `json:"client_id"`
	Scene          string             `json:"scene"`
	ChallengeType  types.CaptchaType  `json:"challenge_type"`
	FeatureVersion string             `json:"feature_version"`
	FeaturesDigest string             `json:"features_digest"`
	FeaturesRef    string             `json:"features_ref,omitempty"`
	Features       map[string]any     `json:"features"`
	Label          string             `json:"label"`
	LabelSource    string             `json:"label_source"`
	ModelTrainable bool               `json:"model_trainable"`
	CreatedAt      time.Time          `json:"created_at"`
	Track          []types.TrackPoint `json:"track"`
}

func DefaultBotTrackFamilies() []BotTrackFamily {
	return []BotTrackFamily{
		BotTrackPerfectLinear,
		BotTrackLowPointJump,
		BotTrackTeleport,
		BotTrackTimestampSkew,
		BotTrackEasedLinear,
		BotTrackBezierScript,
		BotTrackReplayShift,
		BotTrackQuantizedGrid,
		BotTrackSnapEnd,
		BotTrackHyperDense,
		BotTrackMechanicalPause,
		BotTrackSegmentedLinear,
		BotTrackNoisyEase,
		BotTrackOvershootReturn,
		BotTrackBrowserMouse,
		BotTrackDomSnap,
		BotTrackTouchFlick,
	}
}

func DefaultBotTrackChallengeTypes() []types.CaptchaType {
	return []types.CaptchaType{
		types.CaptchaSlider,
		types.CaptchaSlider2,
		types.CaptchaCurve,
		types.CaptchaCurve2,
		types.CaptchaCurve3,
		types.CaptchaConcat,
	}
}

func GenerateSyntheticBotTrackRecords(options BotTrackOptions) ([]SyntheticTrackRecord, error) {
	options = normalizeBotTrackOptions(options)
	rng := rand.New(rand.NewSource(options.Seed))
	families := DefaultBotTrackFamilies()
	records := make([]SyntheticTrackRecord, 0, options.Count)
	for i := 0; i < options.Count; i++ {
		family := families[i%len(families)]
		targetX := float64(options.MinTargetX)
		if options.MaxTargetX > options.MinTargetX {
			targetX += rng.Float64() * float64(options.MaxTargetX-options.MinTargetX)
		}
		baselineY := options.BaselineY + rng.Float64()*8 - 4
		track := buildBotTrack(family, rng, targetX, baselineY)
		challengeType := options.ChallengeTypes[i%len(options.ChallengeTypes)]
		createdAt := options.CreatedAt.Add(time.Duration(i) * time.Second)
		record := syntheticBotTrackRecord(i+1, options, challengeType, family, targetX, track, createdAt)
		records = append(records, record)
	}
	return records, nil
}

func WriteSyntheticTrackJSONL(w io.Writer, records []SyntheticTrackRecord) error {
	encoder := json.NewEncoder(w)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			return err
		}
	}
	return nil
}

func ParseCaptchaTypes(value string) ([]types.CaptchaType, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return DefaultBotTrackChallengeTypes(), nil
	}
	parts := strings.Split(value, ",")
	out := make([]types.CaptchaType, 0, len(parts))
	for _, part := range parts {
		item := strings.ToUpper(strings.TrimSpace(part))
		if item == "" {
			continue
		}
		out = append(out, types.CaptchaType(item))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("captcha types cannot be empty")
	}
	return out, nil
}

func normalizeBotTrackOptions(options BotTrackOptions) BotTrackOptions {
	if options.Count <= 0 {
		options.Count = 220
	}
	if options.Seed == 0 {
		options.Seed = 20260627
	}
	if strings.TrimSpace(options.ClientID) == "" {
		options.ClientID = "synthetic"
	}
	if strings.TrimSpace(options.Scene) == "" {
		options.Scene = "track-training"
	}
	if len(options.ChallengeTypes) == 0 {
		options.ChallengeTypes = DefaultBotTrackChallengeTypes()
	}
	if options.CreatedAt.IsZero() {
		options.CreatedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if options.MinTargetX <= 0 {
		options.MinTargetX = 90
	}
	if options.MaxTargetX <= options.MinTargetX {
		options.MaxTargetX = 300
	}
	if options.BaselineY == 0 {
		options.BaselineY = 22
	}
	return options
}

func syntheticBotTrackRecord(index int, options BotTrackOptions, challengeType types.CaptchaType, family BotTrackFamily, targetX float64, track []types.TrackPoint, createdAt time.Time) SyntheticTrackRecord {
	score := engine.ScoreTrack(track)
	features := engine.ExtractTrackFeatures(track)
	decision := string(types.DecisionPass)
	reasonCode := "OK"
	resultOK := true
	if score.Score < 45 {
		decision = string(types.DecisionChallengeHarder)
		reasonCode = "TRACK_CHALLENGE_HARDER"
		resultOK = false
	}
	features["answer_has_angle"] = false
	features["answer_has_offset"] = false
	features["answer_has_points"] = false
	features["answer_has_x"] = true
	features["answer_has_y"] = false
	features["bot_family"] = string(family)
	features["challenge_type"] = string(challengeType)
	features["decision"] = decision
	features["generator_version"] = SyntheticBotTrackGeneratorVersion
	features["input_device_hint"] = syntheticBotInputDevice(index)
	features["input_device_inferred"] = syntheticBotInputDevice(index)
	features["label_hint"] = "confirmed_bot"
	features["pointer_type"] = syntheticBotPointerType(index)
	features["reason_code"] = reasonCode
	features["result_ok"] = resultOK
	features["source"] = "synthetic_bot_track"
	features["target_x"] = roundSynthetic(targetX)
	features["track_bucket"] = score.Bucket
	features["track_reason_count"] = len(score.Reasons)
	features["track_reasons"] = score.Reasons
	features["track_score"] = score.Score
	features["track_submit_points"] = len(track)
	features["touch_capable"] = syntheticBotInputDevice(index) == "touch"

	digest := digestSyntheticFeatures(features)
	idSuffix := digest
	if len(idSuffix) > 14 {
		idSuffix = idSuffix[:14]
	}
	return SyntheticTrackRecord{
		SchemaVersion:  SyntheticBotTrackSchemaVersion,
		ID:             fmt.Sprintf("synthetic_bot_%06d_%s", index, idSuffix),
		AttemptID:      fmt.Sprintf("synthetic_attempt_%06d_%s", index, idSuffix),
		ClientID:       options.ClientID,
		Scene:          options.Scene,
		ChallengeType:  challengeType,
		FeatureVersion: SyntheticBotTrackFeatureVersion,
		FeaturesDigest: digest,
		FeaturesRef:    "inline",
		Features:       features,
		Label:          "confirmed_bot",
		LabelSource:    "synthetic_bot_generator",
		ModelTrainable: true,
		CreatedAt:      createdAt.UTC(),
		Track:          track,
	}
}

func buildBotTrack(family BotTrackFamily, rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	switch family {
	case BotTrackPerfectLinear:
		return perfectLinearTrack(rng, targetX, baselineY)
	case BotTrackLowPointJump:
		return lowPointJumpTrack(rng, targetX, baselineY)
	case BotTrackTeleport:
		return teleportTrack(rng, targetX, baselineY)
	case BotTrackTimestampSkew:
		return timestampSkewTrack(rng, targetX, baselineY)
	case BotTrackEasedLinear:
		return easedLinearTrack(rng, targetX, baselineY)
	case BotTrackBezierScript:
		return bezierScriptTrack(rng, targetX, baselineY)
	case BotTrackReplayShift:
		return replayShiftTrack(rng, targetX, baselineY)
	case BotTrackQuantizedGrid:
		return quantizedGridTrack(rng, targetX, baselineY)
	case BotTrackSnapEnd:
		return snapEndTrack(rng, targetX, baselineY)
	case BotTrackHyperDense:
		return hyperDenseTrack(rng, targetX, baselineY)
	case BotTrackMechanicalPause:
		return mechanicalPauseTrack(rng, targetX, baselineY)
	case BotTrackSegmentedLinear:
		return segmentedLinearTrack(rng, targetX, baselineY)
	case BotTrackNoisyEase:
		return noisyEaseTrack(rng, targetX, baselineY)
	case BotTrackOvershootReturn:
		return overshootReturnTrack(rng, targetX, baselineY)
	case BotTrackBrowserMouse:
		return browserMouseTrack(rng, targetX, baselineY)
	case BotTrackDomSnap:
		return domSnapTrack(rng, targetX, baselineY)
	case BotTrackTouchFlick:
		return touchFlickTrack(rng, targetX, baselineY)
	default:
		return perfectLinearTrack(rng, targetX, baselineY)
	}
}

func perfectLinearTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	points := 9 + rng.Intn(8)
	stepT := int64(54 + rng.Intn(40))
	return sampledTrack(points, func(t float64, i int) (float64, float64, int64) {
		return targetX * t, baselineY, int64(i) * stepT
	})
}

func lowPointJumpTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	midT := int64(20 + rng.Intn(40))
	endT := midT + int64(20+rng.Intn(40))
	if rng.Intn(2) == 0 {
		return typedTrack([]types.TrackPoint{
			{X: 0, Y: baselineY, T: 0},
			{X: targetX, Y: baselineY + rng.Float64()*2 - 1, T: endT},
		})
	}
	return typedTrack([]types.TrackPoint{
		{X: 0, Y: baselineY, T: 0},
		{X: targetX * 0.18, Y: baselineY, T: midT},
		{X: targetX, Y: baselineY, T: endT},
	})
}

func teleportTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	jumpFrom := maxFloat(8, targetX*0.18)
	jumpTo := targetX - 4 - rng.Float64()*8
	return typedTrack([]types.TrackPoint{
		{X: 0, Y: baselineY, T: 0},
		{X: jumpFrom, Y: baselineY + 1, T: 72},
		{X: jumpTo, Y: baselineY + 1, T: 82},
		{X: targetX - 1, Y: baselineY + 1, T: 120},
		{X: targetX, Y: baselineY + 1, T: 148},
	})
}

func timestampSkewTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	points := 10 + rng.Intn(6)
	track := sampledTrack(points, func(t float64, i int) (float64, float64, int64) {
		return targetX * t, baselineY + math.Sin(t*math.Pi)*0.4, int64(i * 58)
	})
	skewAt := 3 + rng.Intn(max(points-5, 1))
	track[skewAt].T = track[skewAt-1].T - int64(1+rng.Intn(24))
	return typedTrack(track)
}

func easedLinearTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	points := 12 + rng.Intn(9)
	stepT := int64(38 + rng.Intn(18))
	return sampledTrack(points, func(t float64, i int) (float64, float64, int64) {
		eased := easeInOutCubic(t)
		return targetX * eased, baselineY + math.Sin(t*math.Pi*2)*0.35, int64(i) * stepT
	})
}

func bezierScriptTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	points := 18 + rng.Intn(9)
	cp1x := targetX * (0.22 + rng.Float64()*0.08)
	cp2x := targetX * (0.72 + rng.Float64()*0.08)
	cp1y := baselineY - 14 - rng.Float64()*8
	cp2y := baselineY + 10 + rng.Float64()*8
	endY := baselineY + rng.Float64()*0.2
	stepT := int64(42 + rng.Intn(20))
	return sampledTrack(points, func(t float64, i int) (float64, float64, int64) {
		x := cubicBezier(0, cp1x, cp2x, targetX, t)
		y := cubicBezier(baselineY, cp1y, cp2y, endY, t)
		return x, y, int64(i) * stepT
	})
}

func replayShiftTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	base := []struct {
		X float64
		Y float64
		T int64
	}{
		{0, 0, 0},
		{0.06, 0.1, 96},
		{0.18, -0.2, 178},
		{0.34, 0.25, 266},
		{0.51, -0.1, 346},
		{0.69, 0.16, 430},
		{0.86, -0.18, 514},
		{0.98, 0.08, 604},
		{1, 0, 690},
	}
	scaleY := 5 + rng.Float64()*4
	timeShift := int64(rng.Intn(8))
	track := make([]types.TrackPoint, 0, len(base))
	for _, p := range base {
		track = append(track, types.TrackPoint{
			X: targetX * p.X,
			Y: baselineY + p.Y*scaleY,
			T: p.T + timeShift,
		})
	}
	return typedTrack(track)
}

func quantizedGridTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	points := 14 + rng.Intn(10)
	grid := float64(4 + rng.Intn(5))
	stepT := int64(48 + rng.Intn(10))
	return sampledTrack(points, func(t float64, i int) (float64, float64, int64) {
		x := math.Round((targetX*t)/grid) * grid
		y := math.Round((baselineY+math.Sin(t*math.Pi*4)*5)/grid) * grid
		return x, y, int64(i) * stepT
	})
}

func snapEndTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	points := 8 + rng.Intn(5)
	track := sampledTrack(points, func(t float64, i int) (float64, float64, int64) {
		x := targetX * 0.72 * t
		return x, baselineY + math.Sin(t*math.Pi)*2, int64(i * 92)
	})
	lastT := track[len(track)-1].T
	track = append(track,
		types.TrackPoint{X: targetX - 2, Y: baselineY + 1, T: lastT + 10},
		types.TrackPoint{X: targetX, Y: baselineY + 1, T: lastT + 32},
	)
	return typedTrack(track)
}

func hyperDenseTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	points := 280 + rng.Intn(40)
	return sampledTrack(points, func(t float64, i int) (float64, float64, int64) {
		return targetX * t, baselineY + math.Sin(t*math.Pi*6)*0.7, int64(i * 4)
	})
}

func mechanicalPauseTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	track := []types.TrackPoint{
		{X: 0, Y: baselineY, T: 0},
		{X: targetX * 0.18, Y: baselineY, T: 90},
		{X: targetX * 0.18, Y: baselineY, T: 420},
		{X: targetX * 0.48, Y: baselineY, T: 510},
		{X: targetX * 0.48, Y: baselineY, T: 860},
		{X: targetX * 0.82, Y: baselineY, T: 950},
		{X: targetX * 0.82, Y: baselineY, T: 1260},
		{X: targetX, Y: baselineY, T: 1340},
	}
	if rng.Intn(2) == 0 {
		track[3].Y += 1
		track[5].Y -= 1
	}
	return typedTrack(track)
}

func segmentedLinearTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	segments := 4 + rng.Intn(4)
	track := make([]types.TrackPoint, 0, segments+1)
	at := int64(0)
	for i := 0; i <= segments; i++ {
		t := float64(i) / float64(segments)
		if i > 0 {
			at += int64(86 + rng.Intn(38))
		}
		stepBias := (rng.Float64() - 0.5) * 0.018
		x := targetX * clampSynthetic(t+stepBias, 0, 1)
		if i == 0 {
			x = 0
		}
		if i == segments {
			x = targetX
		}
		track = append(track, types.TrackPoint{X: x, Y: baselineY + float64((i%2)*2-1), T: at})
	}
	return typedTrack(track)
}

func noisyEaseTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	points := 28 + rng.Intn(18)
	total := int64(620 + rng.Intn(420))
	phase := rng.Float64() * math.Pi * 2
	return sampledTrack(points, func(t float64, i int) (float64, float64, int64) {
		eased := easeOutQuint(t)
		xNoise := math.Sin(t*math.Pi*10+phase) * (0.7 + rng.Float64()*0.8)
		yNoise := math.Sin(t*math.Pi*7+phase) * (1.2 + rng.Float64()*1.6)
		return targetX*eased + xNoise, baselineY + yNoise, int64(float64(total) * t)
	})
}

func overshootReturnTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	points := 22 + rng.Intn(12)
	overshoot := 8 + rng.Float64()*22
	total := int64(720 + rng.Intn(520))
	return sampledTrack(points, func(t float64, i int) (float64, float64, int64) {
		var x float64
		if t < 0.82 {
			x = (targetX + overshoot) * easeOutCubic(t/0.82)
		} else {
			back := (t - 0.82) / 0.18
			x = targetX + overshoot*(1-easeOutCubic(back))
		}
		y := baselineY + math.Sin(t*math.Pi*3)*2.5
		return x, y, int64(float64(total) * t)
	})
}

func browserMouseTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	points := 16 + rng.Intn(20)
	total := int64(280 + rng.Intn(460))
	curve := 0.6 + rng.Float64()*1.2
	return sampledTrack(points, func(t float64, i int) (float64, float64, int64) {
		x := targetX * math.Pow(t, curve)
		if rng.Intn(4) == 0 {
			x = math.Round(x)
		}
		y := baselineY + math.Sin(t*math.Pi*2)*0.8
		at := int64(float64(total) * t)
		if i > 0 && rng.Intn(5) == 0 {
			at += int64(rng.Intn(14))
		}
		return x, y, at
	})
}

func domSnapTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	points := 10 + rng.Intn(8)
	track := sampledTrack(points, func(t float64, i int) (float64, float64, int64) {
		x := targetX * 0.9 * t
		return x, baselineY + math.Sin(t*math.Pi)*0.6, int64(i * (44 + rng.Intn(18)))
	})
	lastT := track[len(track)-1].T
	track = append(track,
		types.TrackPoint{X: targetX - 18 - rng.Float64()*8, Y: baselineY, T: lastT + 9},
		types.TrackPoint{X: targetX, Y: baselineY, T: lastT + 22},
	)
	return typedTrack(track)
}

func touchFlickTrack(rng *rand.Rand, targetX, baselineY float64) []types.TrackPoint {
	points := 7 + rng.Intn(6)
	total := int64(118 + rng.Intn(150))
	ySlope := rng.Float64()*8 - 4
	return sampledTrack(points, func(t float64, i int) (float64, float64, int64) {
		x := targetX * easeOutQuint(t)
		y := baselineY + ySlope*t + math.Sin(t*math.Pi)*2
		return x, y, int64(float64(total) * t)
	})
}

func sampledTrack(points int, sampler func(t float64, i int) (float64, float64, int64)) []types.TrackPoint {
	track := make([]types.TrackPoint, 0, points)
	for i := 0; i < points; i++ {
		t := 0.0
		if points > 1 {
			t = float64(i) / float64(points-1)
		}
		x, y, at := sampler(t, i)
		track = append(track, types.TrackPoint{X: x, Y: y, T: at})
	}
	return typedTrack(track)
}

func typedTrack(track []types.TrackPoint) []types.TrackPoint {
	for i := range track {
		track[i].X = roundSynthetic(track[i].X)
		track[i].Y = roundSynthetic(track[i].Y)
		track[i].Type = "move"
		if i == 0 {
			track[i].Type = "start"
		}
		if i == len(track)-1 {
			track[i].Type = "end"
		}
	}
	return track
}

func easeInOutCubic(t float64) float64 {
	if t < 0.5 {
		return 4 * t * t * t
	}
	return 1 - math.Pow(-2*t+2, 3)/2
}

func easeOutCubic(t float64) float64 {
	return 1 - math.Pow(1-t, 3)
}

func easeOutQuint(t float64) float64 {
	return 1 - math.Pow(1-t, 5)
}

func cubicBezier(a, b, c, d, t float64) float64 {
	u := 1 - t
	return u*u*u*a + 3*u*u*t*b + 3*u*t*t*c + t*t*t*d
}

func digestSyntheticFeatures(features map[string]any) string {
	data, err := json.Marshal(features)
	if err != nil {
		data = []byte("{}")
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func roundSynthetic(value float64) float64 {
	return math.Round(value*1000) / 1000
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func clampSynthetic(value, minValue, maxValue float64) float64 {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func syntheticBotInputDevice(index int) string {
	switch index % 6 {
	case 0, 3:
		return "mouse"
	case 1, 4:
		return "trackpad"
	case 2:
		return "touch"
	default:
		return "unknown"
	}
}

func syntheticBotPointerType(index int) string {
	if syntheticBotInputDevice(index) == "touch" {
		return "touch"
	}
	return "mouse"
}

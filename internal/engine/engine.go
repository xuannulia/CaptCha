package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"math/big"
	"strings"
	"time"

	"captcha/internal/types"
)

type Options struct {
	PreGenerateSize int
}

type Engine struct {
	sessionTTL      time.Duration
	preGenerateSize int
	preGenerated    map[types.CaptchaType]chan generatedChallenge
}

type generatedChallenge struct {
	Type          types.CaptchaType
	Answer        types.Answer
	RenderPayload types.RenderPayload
}

type curveDrivePoint struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

type curveRenderPoint struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

const (
	maxTrackPoints     = 256
	sliderPieceSize    = 48
	slider2PieceSize   = 44
	concatMaxMovement  = 160
	concatPieceWidth   = 320 + concatMaxMovement
	jigsawTileCols     = 4
	jigsawTileRows     = 4
	jigsawTileWidth    = 80
	jigsawTileHeight   = 40
	gridImageCols      = 3
	gridImageRows      = 3
	gridImageTileSize  = 100
	curveViewWidth     = 300
	curveViewHeight    = 180
	curveAnswerSlack   = 10
	curveTrackSlack    = 13
	wordClickTolerance = 28
	powMaxNonce        = 120000
)

type trackAnalysis struct {
	PointCount           int
	OriginalPointCount   int
	DurationMS           int64
	DistanceX            float64
	DistanceY            float64
	DirectDistance       float64
	PathLength           float64
	Straightness         float64
	AvgVelocity          float64
	MaxVelocity          float64
	VelocityVariance     float64
	AccelerationVariance float64
	JerkVariance         float64
	YJitter              float64
	DirectionChanges     int
	MicroCorrections     int
	OvershootCount       int
	PauseCount           int
	StartDelayMS         float64
	EndStability         float64
	TooFewPoints         bool
	TooFast              bool
	TimestampAnomaly     bool
	PerfectLine          bool
	Teleport             bool
	ConstantVelocity     bool
	SyntheticCurve       bool
	Truncated            bool
}

func New(sessionTTL time.Duration) *Engine {
	return NewWithOptions(sessionTTL, Options{})
}

func NewWithOptions(sessionTTL time.Duration, options Options) *Engine {
	engine := &Engine{sessionTTL: sessionTTL}
	if options.PreGenerateSize > 0 {
		engine.preGenerateSize = options.PreGenerateSize
		engine.preGenerated = make(map[types.CaptchaType]chan generatedChallenge, len(supportedTypes))
		for _, captchaType := range supportedTypes {
			engine.preGenerated[captchaType] = make(chan generatedChallenge, options.PreGenerateSize)
		}
	}
	return engine
}

func (e *Engine) StartPreGeneration(ctx context.Context) {
	if e.preGenerateSize <= 0 {
		return
	}
	_ = e.WarmPreGeneration()
	for _, captchaType := range supportedTypes {
		ch := e.preGenerated[captchaType]
		go e.fillPreGenerated(ctx, captchaType, ch)
	}
}

func (e *Engine) WarmPreGeneration() error {
	if e.preGenerateSize <= 0 {
		return nil
	}
	for _, captchaType := range supportedTypes {
		ch := e.preGenerated[captchaType]
		for len(ch) < cap(ch) {
			challenge, err := e.generateChallenge(captchaType)
			if err != nil {
				return err
			}
			ch <- challenge
		}
	}
	return nil
}

func (e *Engine) PreGenerationDepths() map[types.CaptchaType]int {
	depths := make(map[types.CaptchaType]int, len(e.preGenerated))
	for _, captchaType := range supportedTypes {
		if ch, ok := e.preGenerated[captchaType]; ok {
			depths[captchaType] = len(ch)
		}
	}
	return depths
}

func (e *Engine) NewSession(clientID, scene string, requested types.CaptchaType) (types.ChallengeSession, error) {
	captchaType := normalizeType(requested)
	now := time.Now()
	id, err := randomID("cap_sess_", 24)
	if err != nil {
		return types.ChallengeSession{}, err
	}
	challenge, err := e.takeChallenge(captchaType)
	if err != nil {
		return types.ChallengeSession{}, err
	}
	return types.ChallengeSession{
		ID:            id,
		ClientID:      clientID,
		Scene:         scene,
		Type:          challenge.Type,
		Answer:        challenge.Answer,
		RenderPayload: challenge.RenderPayload,
		Status:        types.SessionActive,
		ExpiresAt:     now.Add(e.sessionTTL),
		CreatedAt:     now,
	}, nil
}

func (e *Engine) Refresh(session types.ChallengeSession) (types.ChallengeSession, error) {
	challenge, err := e.takeChallenge(session.Type)
	if err != nil {
		return types.ChallengeSession{}, err
	}
	if session.Type == types.CaptchaGesture {
		previousFamily := session.Answer.Token
		for i := 0; i < 8 && previousFamily != "" && challenge.Answer.Token == previousFamily; i++ {
			next, nextErr := e.generateChallenge(session.Type)
			if nextErr != nil {
				return types.ChallengeSession{}, nextErr
			}
			challenge = next
		}
	}
	session.Type = challenge.Type
	session.Answer = challenge.Answer
	session.RenderPayload = challenge.RenderPayload
	session.FailureCount = 0
	session.Status = types.SessionActive
	session.ExpiresAt = time.Now().Add(e.sessionTTL)
	return session, nil
}

func (e *Engine) Verify(session types.ChallengeSession, answer types.VerifyAnswer, track []types.TrackPoint) types.VerifyResult {
	trackScore := ScoreTrack(track)
	answerOK, reason := verifyAnswer(session, answer)
	if !answerOK {
		return types.VerifyResult{
			OK:         false,
			Decision:   types.DecisionRetry,
			ReasonCode: reason,
			TrackScore: trackScore,
		}
	}
	if isCurveCaptchaType(session.Type) && !sliderAnswerMatchesTrack(answer.X, track, curveTrackSlack) {
		return types.VerifyResult{
			OK:         false,
			Decision:   types.DecisionRetry,
			ReasonCode: "TRACK_ANSWER_MISMATCH",
			TrackScore: trackScore,
		}
	}
	if isTrackOptionalCaptcha(session.Type) {
		return types.VerifyResult{
			OK:          true,
			Decision:    types.DecisionPass,
			ReasonCode:  "OK",
			TrackScore:  trackScore,
			IssueTicket: true,
		}
	}
	if trackScore.Score < 45 {
		return types.VerifyResult{
			OK:         false,
			Decision:   types.DecisionChallengeHarder,
			ReasonCode: "TRACK_CHALLENGE_HARDER",
			TrackScore: trackScore,
		}
	}
	return types.VerifyResult{
		OK:          true,
		Decision:    types.DecisionPass,
		ReasonCode:  "OK",
		TrackScore:  trackScore,
		IssueTicket: true,
	}
}

func isPointClickCaptcha(captchaType types.CaptchaType) bool {
	switch captchaType {
	case types.CaptchaWordImageClick, types.CaptchaImageClick, types.CaptchaJigsaw, types.CaptchaGridImageClick:
		return true
	default:
		return false
	}
}

func isCurveCaptchaType(captchaType types.CaptchaType) bool {
	switch captchaType {
	case types.CaptchaCurve, types.CaptchaCurve2, types.CaptchaCurve3:
		return true
	default:
		return false
	}
}

func isTrackOptionalCaptcha(captchaType types.CaptchaType) bool {
	return captchaType == types.CaptchaProofOfWork || isPointClickCaptcha(captchaType)
}

func ScoreTrack(track []types.TrackPoint) types.TrackScore {
	analysis := analyzeTrack(track)
	score := 100
	reasons := make([]string, 0)

	if analysis.TooFewPoints {
		score -= 35
		reasons = append(reasons, "TRACK_TOO_FEW_POINTS")
	}
	if analysis.TooFast {
		score -= 30
		reasons = append(reasons, "TRACK_TOO_FAST")
	}
	if analysis.TimestampAnomaly {
		score -= 25
		reasons = append(reasons, "TRACK_TIMESTAMP_ANOMALY")
	}
	if analysis.PerfectLine && analysis.PointCount > 3 {
		score -= 20
		reasons = append(reasons, "TRACK_TOO_STRAIGHT")
	}
	if analysis.Teleport {
		score -= 20
		reasons = append(reasons, "TRACK_TELEPORT")
	}
	if analysis.ConstantVelocity && analysis.PointCount >= 6 {
		score -= 15
		reasons = append(reasons, "TRACK_CONSTANT_VELOCITY")
	}
	if analysis.SyntheticCurve {
		score -= 25
		reasons = append(reasons, "TRACK_SYNTHETIC_CURVE")
	}
	if analysis.Truncated {
		score -= 10
		reasons = append(reasons, "TRACK_TOO_MANY_POINTS")
	}
	if score < 0 {
		score = 0
	}
	bucket := "high"
	if score < 45 {
		bucket = "low"
	} else if score < 75 {
		bucket = "medium"
	}
	return types.TrackScore{
		Score:      score,
		Bucket:     bucket,
		Reasons:    reasons,
		DurationMS: analysis.DurationMS,
		PointCount: analysis.PointCount,
	}
}

func ExtractTrackFeatures(track []types.TrackPoint) map[string]any {
	analysis := analyzeTrack(track)
	return map[string]any{
		"duration_ms":           analysis.DurationMS,
		"point_count":           analysis.PointCount,
		"original_point_count":  analysis.OriginalPointCount,
		"distance_x":            round2(analysis.DistanceX),
		"distance_y":            round2(analysis.DistanceY),
		"direct_distance":       round2(analysis.DirectDistance),
		"path_length":           round2(analysis.PathLength),
		"straightness":          round4(analysis.Straightness),
		"avg_velocity":          round2(analysis.AvgVelocity),
		"max_velocity":          round2(analysis.MaxVelocity),
		"velocity_variance":     round2(analysis.VelocityVariance),
		"acceleration_variance": round2(analysis.AccelerationVariance),
		"jerk_variance":         round2(analysis.JerkVariance),
		"y_jitter":              round2(analysis.YJitter),
		"direction_changes":     analysis.DirectionChanges,
		"micro_corrections":     analysis.MicroCorrections,
		"overshoot_count":       analysis.OvershootCount,
		"pause_count":           analysis.PauseCount,
		"start_delay_ms":        round2(analysis.StartDelayMS),
		"end_stability":         round2(analysis.EndStability),
		"too_few_points":        analysis.TooFewPoints,
		"too_fast":              analysis.TooFast,
		"timestamp_anomaly":     analysis.TimestampAnomaly,
		"perfect_line":          analysis.PerfectLine,
		"teleport":              analysis.Teleport,
		"constant_velocity":     analysis.ConstantVelocity,
		"synthetic_curve":       analysis.SyntheticCurve,
		"track_truncated":       analysis.Truncated,
	}
}

func verifyAnswer(session types.ChallengeSession, answer types.VerifyAnswer) (bool, string) {
	switch session.Type {
	case types.CaptchaProofOfWork:
		if answer.X == nil {
			return false, "ANSWER_MISSING"
		}
		if verifyProofOfWork(session.Answer.Token, *answer.X, session.Answer.Offset, session.Answer.Y) {
			return true, "OK"
		}
		return false, "ANSWER_MISMATCH"
	case types.CaptchaGesture:
		return verifyGesturePathSequence(session.Answer.Points, answer.Points, 14)
	case types.CaptchaCurve, types.CaptchaCurve2, types.CaptchaCurve3:
		if answer.X == nil {
			return false, "ANSWER_MISSING"
		}
		if abs(*answer.X-session.Answer.X) <= curveAnswerSlack {
			return true, "OK"
		}
		return false, "ANSWER_MISMATCH"
	case types.CaptchaSlider, types.CaptchaSlider2:
		if answer.X == nil {
			return false, "ANSWER_MISSING"
		}
		if abs(*answer.X-session.Answer.X) <= 6 {
			return true, "OK"
		}
		return false, "ANSWER_MISMATCH"
	case types.CaptchaRotate:
		if answer.Angle == nil {
			return false, "ANSWER_MISSING"
		}
		diff := angleDiff(*answer.Angle, session.Answer.Angle)
		if diff <= 8 {
			return true, "OK"
		}
		return false, "ANSWER_MISMATCH"
	case types.CaptchaRotateDegree:
		if answer.Angle == nil {
			return false, "ANSWER_MISSING"
		}
		diff := angleDiff(*answer.Angle, session.Answer.Angle)
		if diff <= 7 {
			return true, "OK"
		}
		return false, "ANSWER_MISMATCH"
	case types.CaptchaConcat:
		if answer.Offset == nil {
			return false, "ANSWER_MISSING"
		}
		if abs(*answer.Offset-session.Answer.Offset) <= 6 {
			return true, "OK"
		}
		return false, "ANSWER_MISMATCH"
	case types.CaptchaWordImageClick, types.CaptchaImageClick:
		return verifyPointSequence(session.Answer.Points, answer.Points)
	case types.CaptchaJigsaw:
		return verifyJigsawSwap(session.Answer.Points, answer.Points, session.RenderPayload)
	case types.CaptchaGridImageClick:
		return verifyGridImageSelection(session.Answer.Points, answer.Points, session.RenderPayload)
	default:
		return false, "UNSUPPORTED_CAPTCHA_TYPE"
	}
}

func (e *Engine) generate(captchaType types.CaptchaType) (types.Answer, types.RenderPayload, error) {
	switch captchaType {
	case types.CaptchaProofOfWork:
		seed, err := randomID("pow_", 12)
		if err != nil {
			return types.Answer{}, types.RenderPayload{}, err
		}
		difficulty := 2
		return types.Answer{Token: seed, Offset: difficulty, Y: powMaxNonce}, types.RenderPayload{
			Type:   types.CaptchaProofOfWork,
			Prompt: "正在进行安全计算",
			View:   types.View{Width: 320, Height: 120},
			Image:  pngDataURL(drawProofOfWorkImage()),
			Parameters: map[string]any{
				"pow_seed":   seed,
				"difficulty": difficulty,
				"max_nonce":  powMaxNonce,
			},
		}, nil
	case types.CaptchaGesture:
		family, points := gesturePath()
		return types.Answer{Points: points, Token: family}, types.RenderPayload{
			Type:   types.CaptchaGesture,
			Prompt: "按提示描绘图形",
			View:   types.View{Width: 320, Height: 160},
			Image:  pngDataURL(drawPathChallenge(points, 0)),
			Words:  []string{"path"},
		}, nil
	case types.CaptchaCurve:
		targetX := mustRandomInt(72, 176)
		points := curvePath(1)
		return types.Answer{X: targetX}, types.RenderPayload{
			Type:   types.CaptchaCurve,
			Prompt: "拖动滑块使曲线匹配",
			View:   types.View{Width: curveViewWidth, Height: curveViewHeight},
			Image:  pngDataURL(drawCurveMatchBackground(1, points)),
			Parameters: map[string]any{
				"min":           0,
				"max":           curveViewWidth - 63,
				"curve_profile": curveProfilePayload(1, points, targetX),
			},
		}, nil
	case types.CaptchaCurve2:
		targetX := mustRandomInt(78, 184)
		points := curvePath(2)
		return types.Answer{X: targetX}, types.RenderPayload{
			Type:   types.CaptchaCurve2,
			Prompt: "拖动滑块使增强曲线匹配",
			View:   types.View{Width: curveViewWidth, Height: curveViewHeight},
			Image:  pngDataURL(drawCurveMatchBackground(2, points)),
			Parameters: map[string]any{
				"min":           0,
				"max":           curveViewWidth - 63,
				"curve_profile": curveProfilePayload(2, points, targetX),
			},
		}, nil
	case types.CaptchaCurve3:
		targetX := mustRandomInt(82, 192)
		points := curvePath(3)
		return types.Answer{X: targetX}, types.RenderPayload{
			Type:   types.CaptchaCurve3,
			Prompt: "拖动滑块使圆环曲线匹配",
			View:   types.View{Width: curveViewWidth, Height: curveViewHeight},
			Image:  pngDataURL(drawCurveMatchBackground(3, points)),
			Parameters: map[string]any{
				"min":           0,
				"max":           curveViewWidth - 63,
				"curve_profile": curveProfilePayload(3, points, targetX),
			},
		}, nil
	case types.CaptchaSlider:
		x := mustRandomInt(82, 238)
		y := mustRandomInt(38, 88)
		image, piece := drawSliderChallenge(x, y, sliderPieceSize)
		return types.Answer{X: x, Y: y}, types.RenderPayload{
			Type:   types.CaptchaSlider,
			Prompt: "拖动滑块完成拼图",
			View:   types.View{Width: 320, Height: 160},
			Image:  pngDataURL(image),
			Piece:  pngDataURL(piece),
			Parameters: map[string]any{
				"min":        0,
				"max":        320 - sliderPieceSize,
				"piece_y":    y,
				"piece_size": sliderPieceSize,
			},
		}, nil
	case types.CaptchaSlider2:
		x := mustRandomInt(82, 238)
		y := mustRandomInt(38, 88)
		image, piece := drawSlider2Challenge(x, y, slider2PieceSize)
		return types.Answer{X: x, Y: y}, types.RenderPayload{
			Type:   types.CaptchaSlider2,
			Prompt: "拖动增强滑块完成拼图",
			View:   types.View{Width: 320, Height: 160},
			Image:  pngDataURL(image),
			Piece:  pngDataURL(piece),
			Parameters: map[string]any{
				"min":        0,
				"max":        320 - slider2PieceSize,
				"piece_y":    y,
				"piece_size": slider2PieceSize,
			},
		}, nil
	case types.CaptchaRotate:
		start := mustRandomInt(35, 325)
		answer := (360 - start) % 360
		image := pngDataURL(drawRotateImage(0))
		return types.Answer{Angle: answer}, types.RenderPayload{
			Type:   types.CaptchaRotate,
			Prompt: "旋转图形至正向",
			View:   types.View{Width: 220, Height: 220},
			Image:  image,
			Parameters: map[string]any{
				"min":           0,
				"max":           359,
				"step":          1,
				"initial_angle": start,
			},
		}, nil
	case types.CaptchaConcat:
		offset := mustRandomInt(45, 120)
		splitY := mustRandomInt(58, 102)
		scene := drawConcatScene()
		return types.Answer{Offset: offset}, types.RenderPayload{
			Type:   types.CaptchaConcat,
			Prompt: "拖动滑块完成拼图",
			View:   types.View{Width: 320, Height: 160},
			Image:  pngDataURL(drawConcatBackground(scene, splitY)),
			Piece:  pngDataURL(drawConcatPiece(scene, offset, splitY)),
			Parameters: map[string]any{
				"min":         0,
				"max":         concatControlMax(offset, 320, 0, concatPieceWidth),
				"piece_width": concatPieceWidth,
				"split_y":     splitY,
			},
		}, nil
	case types.CaptchaRotateDegree:
		target := mustRandomInt(30, 330)
		return types.Answer{Angle: target}, types.RenderPayload{
			Type:   types.CaptchaRotateDegree,
			Prompt: "拖动指针指向红色刻度",
			View:   types.View{Width: 220, Height: 220},
			Image:  pngDataURL(drawDegreeImage(target)),
			Parameters: map[string]any{
				"min":  0,
				"max":  359,
				"step": 1,
			},
		}, nil
	case types.CaptchaWordImageClick:
		words := []string{"A", "B", "C"}
		points := spacedClickPoints()
		return types.Answer{Points: points}, types.RenderPayload{
			Type:   types.CaptchaWordImageClick,
			Prompt: "依次点击：A、B、C",
			View:   types.View{Width: 320, Height: 160},
			Image:  pngDataURL(drawWordImage(words, points)),
			Words:  words,
		}, nil
	case types.CaptchaImageClick:
		words := []string{"圆形", "方形", "三角"}
		points := spacedClickPoints()
		return types.Answer{Points: points}, types.RenderPayload{
			Type:   types.CaptchaImageClick,
			Prompt: "依次点击：圆形、方形、三角",
			View:   types.View{Width: 320, Height: 160},
			Image:  pngDataURL(drawIconClickImage(points)),
			Words:  words,
		}, nil
	case types.CaptchaJigsaw:
		points := jigsawSwapPoints()
		return types.Answer{Points: points}, types.RenderPayload{
			Type:   types.CaptchaJigsaw,
			Prompt: "拖动或点击交换错位拼图",
			View:   types.View{Width: 320, Height: 160},
			Image:  pngDataURL(drawJigsawImage(points)),
			Words:  []string{"1", "2"},
			Parameters: map[string]any{
				"tile_cols":   jigsawTileCols,
				"tile_rows":   jigsawTileRows,
				"tile_width":  jigsawTileWidth,
				"tile_height": jigsawTileHeight,
			},
		}, nil
	case types.CaptchaGridImageClick:
		points := gridImageTargetPoints()
		words := make([]string, len(points))
		for i := range words {
			words[i] = "蓝色圆形"
		}
		return types.Answer{Points: points}, types.RenderPayload{
			Type:   types.CaptchaGridImageClick,
			Prompt: "选择所有包含蓝色圆形的图片",
			View:   types.View{Width: gridImageCols * gridImageTileSize, Height: gridImageRows * gridImageTileSize},
			Image:  pngDataURL(drawGridImageChallenge(points)),
			Words:  words,
			Parameters: map[string]any{
				"tile_cols":    gridImageCols,
				"tile_rows":    gridImageRows,
				"tile_width":   gridImageTileSize,
				"tile_height":  gridImageTileSize,
				"target_count": len(points),
				"target_label": "蓝色圆形",
			},
		}, nil
	default:
		return types.Answer{}, types.RenderPayload{}, fmt.Errorf("unsupported captcha type %s", captchaType)
	}
}

func (e *Engine) fillPreGenerated(ctx context.Context, captchaType types.CaptchaType, ch chan<- generatedChallenge) {
	for {
		challenge, err := e.generateChallenge(captchaType)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(250 * time.Millisecond):
				continue
			}
		}
		select {
		case ch <- challenge:
		case <-ctx.Done():
			return
		}
	}
}

func (e *Engine) takeChallenge(captchaType types.CaptchaType) (generatedChallenge, error) {
	if ch, ok := e.preGenerated[captchaType]; ok {
		select {
		case challenge := <-ch:
			return challenge, nil
		default:
		}
	}
	return e.generateChallenge(captchaType)
}

func (e *Engine) generateChallenge(captchaType types.CaptchaType) (generatedChallenge, error) {
	answer, payload, err := e.generate(captchaType)
	if err != nil {
		return generatedChallenge{}, err
	}
	return generatedChallenge{Type: captchaType, Answer: answer, RenderPayload: payload}, nil
}

var supportedTypes = []types.CaptchaType{
	types.CaptchaProofOfWork,
	types.CaptchaGesture,
	types.CaptchaCurve,
	types.CaptchaCurve2,
	types.CaptchaCurve3,
	types.CaptchaSlider,
	types.CaptchaSlider2,
	types.CaptchaRotate,
	types.CaptchaConcat,
	types.CaptchaRotateDegree,
	types.CaptchaWordImageClick,
	types.CaptchaImageClick,
	types.CaptchaJigsaw,
	types.CaptchaGridImageClick,
}

func normalizeType(t types.CaptchaType) types.CaptchaType {
	normalized := types.CaptchaType(strings.ToUpper(strings.TrimSpace(string(t))))
	switch normalized {
	case "POW":
		return types.CaptchaProofOfWork
	case "SLIDER2":
		return types.CaptchaSlider2
	case "CURVE2":
		return types.CaptchaCurve2
	case "CURVE3":
		return types.CaptchaCurve3
	case types.CaptchaWordOrderClick:
		return types.CaptchaWordImageClick
	case types.CaptchaProofOfWork, types.CaptchaGesture, types.CaptchaCurve, types.CaptchaCurve2, types.CaptchaCurve3, types.CaptchaSlider, types.CaptchaSlider2, types.CaptchaRotate, types.CaptchaConcat, types.CaptchaRotateDegree, types.CaptchaWordImageClick, types.CaptchaImageClick, types.CaptchaJigsaw, types.CaptchaGridImageClick:
		return normalized
	default:
		return types.CaptchaSlider
	}
}

func randomID(prefix string, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

func mustRandomInt(min, max int) int {
	if max <= min {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}

func pngDataURL(img image.Image) string {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

func drawSliderChallenge(targetX, targetY, size int) (image.Image, image.Image) {
	base := drawSliderScene()
	bg := copyRGBA(base)
	piece := newCanvas(size, size, color.RGBA{A: 0})
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if !insidePuzzlePiece(x, y, size) {
				continue
			}
			gx, gy := targetX+x, targetY+y
			source := rgbaAt(base, gx, gy)
			if puzzleBorder(x, y, size) {
				bg.Set(gx, gy, color.RGBA{R: 15, G: 23, B: 42, A: 235})
				piece.Set(x, y, color.RGBA{R: 37, G: 99, B: 235, A: 255})
				continue
			}
			bg.Set(gx, gy, mixRGBA(source, color.RGBA{R: 255, G: 255, B: 255, A: 255}, 0.62))
			piece.Set(x, y, mixRGBA(source, color.RGBA{R: 255, G: 255, B: 255, A: 255}, 0.08))
		}
	}
	return bg, piece
}

func drawSlider2Challenge(targetX, targetY, size int) (image.Image, image.Image) {
	bg, piece := drawSliderChallenge(targetX, targetY, size)
	bgRGBA := copyRGBA(bg)
	for _, decoy := range []image.Point{{X: 46, Y: 38}, {X: 244, Y: 92}} {
		if abs(decoy.X-targetX) < 42 && abs(decoy.Y-targetY) < 42 {
			continue
		}
		drawPuzzleOutline(bgRGBA, decoy.X, decoy.Y, size, color.RGBA{R: 59, G: 130, B: 246, A: 170})
	}
	return bgRGBA, piece
}

func drawPuzzleOutline(img *image.RGBA, ox, oy, size int, c color.RGBA) {
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if puzzleBorder(x, y, size) {
				img.Set(ox+x, oy+y, c)
			}
		}
	}
}

func drawProofOfWorkImage() image.Image {
	img := newCanvas(320, 120, color.RGBA{R: 248, G: 250, B: 252, A: 255})
	for i := 0; i < 9; i++ {
		x := 34 + i*30
		h := 24 + (i%4)*10
		fillRect(img, x, 72-h, 18, h, color.RGBA{R: 37, G: 99, B: 235, A: 210})
		drawCircle(img, x+9, 84, 8, color.RGBA{R: 14, G: 165, B: 233, A: 180})
	}
	drawPolyline(img, []image.Point{{30, 92}, {290, 92}}, 3, color.RGBA{R: 203, G: 213, B: 225, A: 255})
	drawCircle(img, 274, 36, 18, color.RGBA{R: 250, G: 204, B: 21, A: 255})
	return img
}

func gesturePath() (string, []types.Point) {
	family := ""
	var points []types.Point
	switch mustRandomInt(0, 5) {
	case 0:
		family = "soft_wave"
		points = gestureSoftWavePath()
	case 1:
		family = "arch"
		points = gestureArchPath()
	case 2:
		family = "s_curve"
		points = gestureSCurvePath()
	case 3:
		family = "soft_hook"
		points = gestureSoftHookPath()
	case 4:
		family = "open_loop"
		points = gestureOpenLoopPath()
	default:
		family = "lazy_loop"
		points = gestureLazyLoopPath()
	}
	return family, jitterGesturePath(points)
}

func gestureSoftWavePath() []types.Point {
	points := make([]types.Point, 0, 44)
	baseY := mustRandomInt(72, 92)
	amplitude := mustRandomInt(22, 34)
	cycles := 1.15 + float64(mustRandomInt(0, 45))/100
	phase := float64(mustRandomInt(-18, 18)) / 100
	for i := 0; i < 44; i++ {
		t := float64(i) / 43
		x := 38 + int(math.Round(t*244))
		y := baseY + int(math.Round(math.Sin((t+phase)*math.Pi*2*cycles)*float64(amplitude)))
		points = append(points, types.Point{X: x, Y: y})
	}
	return points
}

func gestureArchPath() []types.Point {
	return pointsFromImage(cubicPolyline(
		image.Point{X: mustRandomInt(38, 52), Y: mustRandomInt(104, 122)},
		image.Point{X: mustRandomInt(78, 104), Y: mustRandomInt(28, 48)},
		image.Point{X: mustRandomInt(206, 238), Y: mustRandomInt(28, 48)},
		image.Point{X: mustRandomInt(270, 286), Y: mustRandomInt(98, 124)},
		40,
	))
}

func gestureSCurvePath() []types.Point {
	join := image.Point{X: mustRandomInt(150, 174), Y: mustRandomInt(72, 92)}
	return pointsFromImage(cubicPolyline(
		image.Point{X: mustRandomInt(38, 52), Y: mustRandomInt(52, 78)},
		image.Point{X: mustRandomInt(84, 118), Y: mustRandomInt(26, 44)},
		image.Point{X: mustRandomInt(112, 144), Y: mustRandomInt(112, 132)},
		join,
		28,
	), cubicPolyline(
		join,
		image.Point{X: mustRandomInt(188, 218), Y: mustRandomInt(34, 56)},
		image.Point{X: mustRandomInt(216, 250), Y: mustRandomInt(112, 132)},
		image.Point{X: mustRandomInt(270, 288), Y: mustRandomInt(72, 100)},
		28,
	))
}

func gestureSoftHookPath() []types.Point {
	turn := image.Point{X: mustRandomInt(184, 214), Y: mustRandomInt(86, 112)}
	return pointsFromImage(cubicPolyline(
		image.Point{X: mustRandomInt(40, 54), Y: mustRandomInt(80, 106)},
		image.Point{X: mustRandomInt(86, 118), Y: mustRandomInt(34, 56)},
		image.Point{X: mustRandomInt(148, 184), Y: mustRandomInt(38, 62)},
		turn,
		30,
	), cubicPolyline(
		turn,
		image.Point{X: mustRandomInt(214, 238), Y: mustRandomInt(124, 134)},
		image.Point{X: mustRandomInt(246, 274), Y: mustRandomInt(112, 132)},
		image.Point{X: mustRandomInt(266, 288), Y: mustRandomInt(66, 96)},
		32,
	))
}

func gestureOpenLoopPath() []types.Point {
	start := image.Point{X: mustRandomInt(226, 252), Y: mustRandomInt(48, 70)}
	upperLeft := image.Point{X: mustRandomInt(104, 132), Y: mustRandomInt(36, 56)}
	lowerLeft := image.Point{X: mustRandomInt(72, 98), Y: mustRandomInt(96, 120)}
	lowerRight := image.Point{X: mustRandomInt(212, 244), Y: mustRandomInt(112, 132)}
	end := image.Point{X: mustRandomInt(276, 292), Y: mustRandomInt(76, 104)}
	return pointsFromImage(cubicPolyline(
		start,
		image.Point{X: mustRandomInt(190, 222), Y: mustRandomInt(30, 46)},
		image.Point{X: mustRandomInt(142, 170), Y: mustRandomInt(30, 48)},
		upperLeft,
		22,
	), cubicPolyline(
		upperLeft,
		image.Point{X: mustRandomInt(72, 98), Y: mustRandomInt(58, 80)},
		image.Point{X: mustRandomInt(60, 86), Y: mustRandomInt(80, 106)},
		lowerLeft,
		18,
	), cubicPolyline(
		lowerLeft,
		image.Point{X: mustRandomInt(110, 140), Y: mustRandomInt(130, 134)},
		image.Point{X: mustRandomInt(174, 206), Y: mustRandomInt(130, 134)},
		lowerRight,
		24,
	), cubicPolyline(
		lowerRight,
		image.Point{X: mustRandomInt(248, 268), Y: mustRandomInt(112, 130)},
		image.Point{X: mustRandomInt(266, 286), Y: mustRandomInt(96, 118)},
		end,
		16,
	))
}

func gestureLazyLoopPath() []types.Point {
	first := image.Point{X: mustRandomInt(42, 58), Y: mustRandomInt(86, 110)}
	mid := image.Point{X: mustRandomInt(154, 176), Y: mustRandomInt(82, 106)}
	return pointsFromImage(cubicPolyline(
		first,
		image.Point{X: mustRandomInt(76, 104), Y: mustRandomInt(38, 56)},
		image.Point{X: mustRandomInt(126, 150), Y: mustRandomInt(118, 134)},
		mid,
		30,
	), cubicPolyline(
		mid,
		image.Point{X: mustRandomInt(198, 226), Y: mustRandomInt(34, 58)},
		image.Point{X: mustRandomInt(234, 260), Y: mustRandomInt(112, 132)},
		image.Point{X: mustRandomInt(268, 288), Y: mustRandomInt(68, 98)},
		30,
	))
}

func jitterGesturePath(base []types.Point) []types.Point {
	points := make([]types.Point, 0, len(base))
	offsetX := mustRandomInt(-5, 5)
	offsetY := mustRandomInt(-5, 5)
	for i, point := range base {
		jitterX := mustRandomInt(-1, 1)
		jitterY := mustRandomInt(-1, 1)
		if i == 0 || i == len(base)-1 {
			jitterX = 0
			jitterY = 0
		}
		points = append(points, types.Point{
			X: min(296, max(24, point.X+offsetX+jitterX)),
			Y: min(134, max(26, point.Y+offsetY+jitterY)),
		})
	}
	return points
}

func curvePath(variant int) []types.Point {
	if variant == 3 {
		return curveRingPath()
	}

	left := mustRandomInt(58, 76)
	right := curveViewWidth - mustRandomInt(28, 52)
	span := right - left
	leftY := mustRandomInt(32, 54)
	rightY := mustRandomInt(30, 54)
	lowY := mustRandomInt(112, 142)
	midY := mustRandomInt(78, 104)
	mk := func(x, y int) image.Point {
		return image.Point{
			X: clampInt(x, 18, curveViewWidth-12),
			Y: clampInt(y, 22, curveViewHeight-18),
		}
	}

	switch variant {
	case 2:
		firstJoin := mk(left+span/4+mustRandomInt(-12, 10), lowY+mustRandomInt(-8, 14))
		secondJoin := mk(left+(span*2)/3+mustRandomInt(-10, 12), midY+mustRandomInt(-18, 16))
		return pointsFromImage(cubicPolyline(
			mk(left, leftY),
			mk(left-span/6, leftY+mustRandomInt(28, 52)),
			mk(left-span/6, lowY+mustRandomInt(-12, 10)),
			firstJoin,
			24,
		), cubicPolyline(
			firstJoin,
			mk(left+span/3, lowY+mustRandomInt(12, 24)),
			mk(left+span/2, leftY+mustRandomInt(26, 48)),
			secondJoin,
			26,
		), cubicPolyline(
			secondJoin,
			mk(right-span/5, lowY+mustRandomInt(-8, 18)),
			mk(right-span/8, rightY+mustRandomInt(18, 42)),
			mk(right, rightY),
			22,
		))
	default:
		if mustRandomInt(0, 1) == 0 {
			join := mk(left+span/2+mustRandomInt(-14, 14), midY+mustRandomInt(-16, 18))
			return pointsFromImage(cubicPolyline(
				mk(left, leftY),
				mk(left-span/5, leftY+mustRandomInt(46, 70)),
				mk(left+span/5, lowY+mustRandomInt(-10, 14)),
				join,
				28,
			), cubicPolyline(
				join,
				mk(right-span/3, lowY+mustRandomInt(-10, 18)),
				mk(right-span/6, rightY+mustRandomInt(24, 48)),
				mk(right, rightY),
				26,
			))
		}
		return pointsFromImage(cubicPolyline(
			mk(left, leftY),
			mk(left-span/4, leftY+mustRandomInt(56, 82)),
			mk(right-span/3, lowY+mustRandomInt(-8, 16)),
			mk(right, rightY),
			58,
		))
	}
}

func curveRingPath() []types.Point {
	const steps = 96
	centerX := float64(mustRandomInt(138, 164))
	centerY := float64(mustRandomInt(82, 100))
	radiusX := float64(mustRandomInt(66, 88))
	radiusY := float64(mustRandomInt(32, 47))
	tilt := float64(mustRandomInt(-16, 16)) * math.Pi / 180
	phase := float64(mustRandomInt(0, 359)) * math.Pi / 180
	cosTilt := math.Cos(tilt)
	sinTilt := math.Sin(tilt)
	points := make([]types.Point, 0, steps+1)
	for i := 0; i <= steps; i++ {
		theta := 2 * math.Pi * float64(i) / steps
		wobbleX := 1 + 0.09*math.Sin(3*theta+phase)
		wobbleY := 1 + 0.16*math.Cos(2*theta-phase)
		localX := radiusX*wobbleX*math.Cos(theta) + 8*math.Sin(2*theta+phase)
		localY := radiusY*wobbleY*math.Sin(theta) + 7*math.Sin(theta-phase)*math.Cos(theta)
		x := centerX + localX*cosTilt - localY*sinTilt
		y := centerY + localX*sinTilt + localY*cosTilt
		points = append(points, types.Point{
			X: clampInt(int(math.Round(x)), 30, curveViewWidth-30),
			Y: clampInt(int(math.Round(y)), 28, curveViewHeight-28),
		})
	}
	if len(points) > 1 {
		points[len(points)-1] = points[0]
	}
	return points
}

func curveProfilePayload(variant int, points []types.Point, targetX int) map[string]any {
	fixed := curveRenderPoints(points)
	drive := curveDrivePoints(points, variant, targetX)
	return map[string]any{
		"variant":       variant,
		"visual_style":  curveVisualStyle(variant),
		"moving_points": applyCurveDrive(fixed, drive, float64(targetX)),
		"drive_points":  drive,
		"endpoint_mode": curveEndpointMode(variant),
	}
}

func curveVisualStyle(variant int) string {
	switch variant {
	case 2:
		return "dual-noise"
	case 3:
		return "ring-deform"
	default:
		return "single-rope"
	}
}

func curveEndpointMode(variant int) string {
	return "hidden"
}

func curveDrivePoints(points []types.Point, variant, targetX int) []curveDrivePoint {
	out := make([]curveDrivePoint, 0, len(points))
	if len(points) == 0 {
		return out
	}
	answerScale := math.Max(1, float64(targetX))
	lateralPixels := float64(mustRandomInt(22, 38))
	verticalPixels := float64(mustRandomInt(46, 68))
	wavePixels := float64(mustRandomInt(14, 24))
	phase := float64(mustRandomInt(-18, 18)) / 100
	if variant == 3 {
		phaseAngle := phase * math.Pi
		for i := range points {
			t := 0.0
			if len(points) > 1 {
				t = float64(i) / float64(len(points)-1)
			}
			theta := 2 * math.Pi * t
			pixelX := math.Sin(theta+phaseAngle)*lateralPixels + math.Sin(2*theta-phaseAngle)*wavePixels*0.75
			pixelY := math.Cos(theta-phaseAngle)*verticalPixels*0.72 + math.Sin(3*theta+phaseAngle)*wavePixels*0.85
			out = append(out, curveDrivePoint{
				X: pixelX / answerScale,
				Y: pixelY / answerScale,
			})
		}
		if len(out) > 1 {
			out[len(out)-1] = out[0]
		}
		return out
	}
	for i := range points {
		t := 0.0
		if len(points) > 1 {
			t = float64(i) / float64(len(points)-1)
		}
		envelope := math.Sin(math.Pi * t)
		direction := 1.0
		if variant == 2 {
			direction = -1
		}
		wave := math.Sin((t*2.7 + float64(variant)*0.23 + phase) * math.Pi)
		cross := math.Cos((t*1.8 + float64(variant)*0.19 - phase) * math.Pi)
		pixelX := envelope * wave * lateralPixels * direction
		pixelY := envelope * (verticalPixels*direction + cross*wavePixels)
		if i == 0 || i == len(points)-1 {
			pixelX = 0
			pixelY = 0
		}
		out = append(out, curveDrivePoint{
			X: pixelX / answerScale,
			Y: pixelY / answerScale,
		})
	}
	return out
}

func curveRenderPoints(points []types.Point) []curveRenderPoint {
	out := make([]curveRenderPoint, 0, len(points))
	for _, point := range points {
		out = append(out, curveRenderPoint{
			X: float64(point.X),
			Y: float64(point.Y),
		})
	}
	return out
}

func applyCurveDrive(points []curveRenderPoint, drive []curveDrivePoint, scale float64) []curveRenderPoint {
	out := make([]curveRenderPoint, 0, len(points))
	for _, point := range points {
		index := len(out)
		vector := curveDrivePoint{}
		if index < len(drive) {
			vector = drive[index]
		}
		out = append(out, curveRenderPoint{
			X: point.X + vector.X*scale,
			Y: point.Y + vector.Y*scale,
		})
	}
	return out
}

func pointsFromImage(segments ...[]image.Point) []types.Point {
	points := make([]types.Point, 0)
	for _, segment := range segments {
		for i, point := range segment {
			if len(points) > 0 && i == 0 {
				continue
			}
			points = append(points, types.Point{X: point.X, Y: point.Y})
		}
	}
	return points
}

func drawPathChallenge(points []types.Point, variant int) image.Image {
	img := newCanvas(320, 160, color.RGBA{R: 248, G: 250, B: 252, A: 255})
	for i := 0; i < 18; i++ {
		drawCircle(img, mustRandomInt(12, 308), mustRandomInt(12, 148), mustRandomInt(1, 2), color.RGBA{R: 203, G: 213, B: 225, A: 255})
	}
	polyline := imagePoints(points)
	guideColor := color.RGBA{R: 37, G: 99, B: 235, A: 220}
	if variant == 0 {
		guideColor = color.RGBA{R: 124, G: 58, B: 237, A: 220}
	}
	if variant == 2 {
		drawPolyline(img, polyline, 18, color.RGBA{R: 219, G: 234, B: 254, A: 255})
	}
	if variant == 3 {
		drawPolyline(img, polyline, 20, color.RGBA{R: 254, G: 226, B: 226, A: 230})
	}
	drawPolyline(img, polyline, 9, guideColor)
	drawCircle(img, points[0].X, points[0].Y, 12, color.RGBA{R: 20, G: 184, B: 166, A: 255})
	end := points[len(points)-1]
	drawCircle(img, end.X, end.Y, 14, color.RGBA{R: 244, G: 63, B: 94, A: 255})
	drawCircle(img, end.X, end.Y, 7, color.RGBA{R: 255, G: 255, B: 255, A: 235})
	return img
}

func drawCurveMatchBackground(variant int, points []types.Point) image.Image {
	img := newCanvas(curveViewWidth, curveViewHeight, color.RGBA{R: 17, G: 24, B: 39, A: 255})
	switch variant {
	case 2:
		drawCurveSunsetScene(img)
	case 3:
		drawCurveRibbonScene(img)
	default:
		drawCurveNightScene(img)
	}
	drawCurveImageTexture(img, variant)
	drawCurveTarget(img, variant, imagePoints(points))
	return img
}

func drawCurveNightScene(img *image.RGBA) {
	height := img.Bounds().Dy()
	width := img.Bounds().Dx()
	for y := 0; y < height; y++ {
		ratio := float64(y) / float64(height-1)
		c := mixRGBA(color.RGBA{R: 31, G: 28, B: 72, A: 255}, color.RGBA{R: 17, G: 83, B: 127, A: 255}, ratio)
		fillRect(img, 0, y, width, 1, c)
	}
	drawCircle(img, 256, 52, 18, color.RGBA{R: 226, G: 232, B: 240, A: 255})
	drawCircle(img, 248, 48, 18, color.RGBA{R: 45, G: 61, B: 111, A: 255})
	drawCurveStars(img, 18, color.RGBA{R: 226, G: 232, B: 240, A: 255})
	fillPolygon(img, []image.Point{{0, height}, {0, 112}, {58, 82}, {118, 136}, {170, 96}, {226, 128}, {width, 86}, {width, height}}, color.RGBA{R: 31, G: 41, B: 74, A: 255})
	fillPolygon(img, []image.Point{{0, height}, {0, 132}, {82, 104}, {150, 145}, {230, 112}, {width, 134}, {width, height}}, color.RGBA{R: 15, G: 23, B: 42, A: 255})
}

func drawCurveSunsetScene(img *image.RGBA) {
	height := img.Bounds().Dy()
	width := img.Bounds().Dx()
	for y := 0; y < height; y++ {
		ratio := float64(y) / float64(height-1)
		c := mixRGBA(color.RGBA{R: 42, G: 35, B: 92, A: 255}, color.RGBA{R: 168, G: 78, B: 69, A: 255}, ratio)
		fillRect(img, 0, y, width, 1, c)
	}
	for x := 0; x < width; x += 64 {
		tint := color.RGBA{R: uint8(28 + (x/64)*12), G: 30, B: uint8(68 + (x/64)*10), A: 255}
		fillRect(img, x, 0, 64, height, tint)
	}
	drawCircle(img, 212, 76, 20, color.RGBA{R: 248, G: 250, B: 252, A: 255})
	fillPolygon(img, []image.Point{{0, height}, {0, 120}, {72, 94}, {138, 136}, {208, 104}, {width, 128}, {width, height}}, color.RGBA{R: 49, G: 39, B: 72, A: 255})
	fillPolygon(img, []image.Point{{0, height}, {0, 138}, {92, 112}, {180, 148}, {258, 118}, {width, 134}, {width, height}}, color.RGBA{R: 30, G: 27, B: 54, A: 255})
	drawCurveStars(img, 10, color.RGBA{R: 253, G: 186, B: 116, A: 255})
}

func drawCurveRibbonScene(img *image.RGBA) {
	height := img.Bounds().Dy()
	width := img.Bounds().Dx()
	for y := 0; y < height; y++ {
		ratio := float64(y) / float64(height-1)
		c := mixRGBA(color.RGBA{R: 248, G: 113, B: 113, A: 255}, color.RGBA{R: 252, G: 250, B: 246, A: 255}, ratio)
		fillRect(img, 0, y, width, 1, c)
	}
	for x := 0; x < width; x += 58 {
		fillRect(img, x, 0, 34, height, color.RGBA{R: 251, G: 113, B: 133, A: 255})
	}
	drawCircle(img, 242, 48, 18, color.RGBA{R: 251, G: 191, B: 36, A: 255})
	fillPolygon(img, []image.Point{{0, height}, {0, 126}, {62, 102}, {132, 132}, {196, 108}, {width, 130}, {width, height}}, color.RGBA{R: 88, G: 80, B: 118, A: 255})
	fillPolygon(img, []image.Point{{0, height}, {0, 140}, {90, 118}, {160, 148}, {238, 122}, {width, 136}, {width, height}}, color.RGBA{R: 48, G: 45, B: 78, A: 255})
}

func drawCurveImageTexture(img *image.RGBA, variant int) {
	width := img.Bounds().Dx()
	height := img.Bounds().Dy()
	for i := 0; i < 90; i++ {
		x := mustRandomInt(0, width-1)
		y := mustRandomInt(0, height-1)
		base := rgbaAt(img, x, y)
		noise := mustRandomInt(-10, 10)
		c := color.RGBA{
			R: uint8(clampInt(int(base.R)+noise, 0, 255)),
			G: uint8(clampInt(int(base.G)+noise, 0, 255)),
			B: uint8(clampInt(int(base.B)+noise, 0, 255)),
			A: 255,
		}
		drawCircle(img, x, y, mustRandomInt(1, 2), c)
	}
	if variant == 2 {
		for x := 42; x < width; x += 82 {
			drawPolyline(img, []image.Point{{X: x, Y: 0}, {X: x + mustRandomInt(-10, 10), Y: height}}, 2, color.RGBA{R: 255, G: 255, B: 255, A: 32})
		}
	}
	if variant == 3 {
		for y := 26; y < height; y += 36 {
			drawPolyline(img, []image.Point{{X: 0, Y: y}, {X: width, Y: y + mustRandomInt(-14, 14)}}, 2, color.RGBA{R: 255, G: 255, B: 255, A: 36})
		}
	}
}

func drawCurveTarget(img *image.RGBA, variant int, points []image.Point) {
	switch variant {
	case 2:
		drawPolyline(img, offsetImagePoints(points, 0, -3), 14, color.RGBA{R: 255, G: 92, B: 173, A: 255})
		drawPolyline(img, points, 7, color.RGBA{R: 192, G: 132, B: 252, A: 255})
	case 3:
		drawPolyline(img, offsetImagePoints(points, 0, -2), 13, color.RGBA{R: 255, G: 255, B: 255, A: 255})
		drawPolyline(img, points, 7, color.RGBA{R: 248, G: 113, B: 113, A: 255})
	default:
		drawPolyline(img, offsetImagePoints(points, 0, 5), 13, color.RGBA{R: 75, G: 85, B: 132, A: 255})
		drawPolyline(img, points, 8, color.RGBA{R: 125, G: 211, B: 252, A: 255})
	}
}

func drawCurveForeground(img *image.RGBA, variant int, points []image.Point) {
	if len(points) == 0 {
		return
	}
	switch variant {
	case 2:
		drawPolyline(img, points, 17, color.RGBA{R: 255, G: 255, B: 255, A: 180})
		drawPolyline(img, points, 8, color.RGBA{R: 255, G: 69, B: 144, A: 235})
	case 3:
		drawPolyline(img, points, 17, color.RGBA{R: 255, G: 255, B: 255, A: 205})
		drawPolyline(img, points, 8, color.RGBA{R: 239, G: 68, B: 68, A: 235})
	default:
		drawPolyline(img, points, 18, color.RGBA{R: 255, G: 255, B: 255, A: 210})
		drawPolyline(img, points, 8, color.RGBA{R: 226, G: 232, B: 240, A: 245})
	}
	first := points[0]
	last := points[len(points)-1]
	drawCircle(img, first.X, first.Y, 11, color.RGBA{R: 255, G: 255, B: 255, A: 245})
	drawCircle(img, first.X, first.Y, 6, color.RGBA{R: 226, G: 232, B: 240, A: 245})
	drawCircle(img, last.X, last.Y, 11, color.RGBA{R: 255, G: 255, B: 255, A: 245})
	drawCircle(img, last.X, last.Y, 6, color.RGBA{R: 226, G: 232, B: 240, A: 245})
}

func drawCurveStars(img *image.RGBA, count int, c color.RGBA) {
	for i := 0; i < count; i++ {
		x := mustRandomInt(12, 308)
		y := mustRandomInt(12, 118)
		drawCircle(img, x, y, mustRandomInt(1, 2), c)
	}
}

func offsetImagePoints(points []image.Point, dx, dy int) []image.Point {
	out := make([]image.Point, 0, len(points))
	for _, point := range points {
		out = append(out, image.Point{X: point.X + dx, Y: point.Y + dy})
	}
	return out
}

func imagePoints(points []types.Point) []image.Point {
	out := make([]image.Point, 0, len(points))
	for _, point := range points {
		out = append(out, image.Point{X: point.X, Y: point.Y})
	}
	return out
}

func drawSliderScene() *image.RGBA {
	img := newCanvas(320, 160, color.RGBA{R: 232, G: 242, B: 255, A: 255})
	fillRect(img, 0, 114, 320, 46, color.RGBA{R: 135, G: 180, B: 132, A: 255})
	drawCircle(img, 266, 36, 18, color.RGBA{R: 245, G: 197, B: 66, A: 255})
	drawPolyline(img, []image.Point{{0, 122}, {62, 101}, {112, 132}, {160, 112}, {230, 91}, {320, 116}}, 8, color.RGBA{R: 91, G: 137, B: 104, A: 255})
	drawPolyline(img, []image.Point{{0, 128}, {62, 107}, {112, 138}, {160, 118}, {230, 97}, {320, 122}}, 3, color.RGBA{R: 66, G: 107, B: 83, A: 180})
	fillRect(img, 38, 50, 34, 8, color.RGBA{R: 255, G: 255, B: 255, A: 190})
	fillRect(img, 52, 42, 58, 10, color.RGBA{R: 255, G: 255, B: 255, A: 150})
	return img
}

func insidePuzzlePiece(x, y, size int) bool {
	margin := 5
	radius := 8
	center := size / 2
	body := x >= margin && x < size-margin && y >= margin && y < size-margin
	topTab := square(x-center)+square(y-margin) <= square(radius) && y < margin+radius
	rightTab := square(x-(size-margin))+square(y-center) <= square(radius) && x >= size-margin-radius
	leftNotch := square(x-margin)+square(y-center) <= square(radius) && x < margin+radius+1
	return (body || topTab || rightTab) && !leftNotch
}

func puzzleBorder(x, y, size int) bool {
	if !insidePuzzlePiece(x, y, size) {
		return false
	}
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			if !insidePuzzlePiece(x+dx, y+dy, size) {
				return true
			}
		}
	}
	return false
}

func drawRotateImage(start int) image.Image {
	img := newCanvas(220, 220, color.RGBA{R: 248, G: 250, B: 252, A: 255})
	drawCircle(img, 110, 110, 89, color.RGBA{R: 203, G: 213, B: 225, A: 255})
	drawCircle(img, 110, 110, 83, color.RGBA{R: 248, G: 250, B: 252, A: 255})
	shape := []image.Point{
		rotatePoint(0, -72, start, 110, 110),
		rotatePoint(62, 42, start, 110, 110),
		rotatePoint(0, 16, start, 110, 110),
		rotatePoint(-62, 42, start, 110, 110),
	}
	fillPolygon(img, shape, color.RGBA{R: 37, G: 99, B: 235, A: 255})
	drawCircle(img, 110, 110, 22, color.RGBA{R: 250, G: 204, B: 21, A: 255})
	return img
}

func drawDegreeImage(target int) image.Image {
	img := newCanvas(220, 220, color.RGBA{R: 248, G: 250, B: 252, A: 255})
	drawCircle(img, 110, 110, 92, color.RGBA{R: 226, G: 232, B: 240, A: 255})
	drawCircle(img, 110, 110, 82, color.RGBA{R: 248, G: 250, B: 252, A: 255})
	for angle := 0; angle < 360; angle += 30 {
		outer := rotatePoint(0, -86, angle, 110, 110)
		inner := rotatePoint(0, -74, angle, 110, 110)
		drawPolyline(img, []image.Point{outer, inner}, 3, color.RGBA{R: 148, G: 163, B: 184, A: 255})
	}
	targetOuter := rotatePoint(0, -91, target, 110, 110)
	targetInner := rotatePoint(0, -62, target, 110, 110)
	drawPolyline(img, []image.Point{targetOuter, targetInner}, 6, color.RGBA{R: 239, G: 68, B: 68, A: 255})
	drawCircle(img, 110, 110, 9, color.RGBA{R: 15, G: 23, B: 42, A: 255})
	return img
}

func drawConcatBackground(scene *image.RGBA, splitY int) image.Image {
	img := newCanvas(320, 160, color.RGBA{A: 0})
	splitY = clampInt(splitY, 1, 158)
	for y := 0; y < 160; y++ {
		for x := 0; x < 320; x++ {
			if y < splitY {
				img.Set(x, y, concatCoverPixel(x, y))
				continue
			}
			img.Set(x, y, opaqueRGBA(rgbaAt(scene, x, y)))
		}
	}
	drawConcatDivider(img, splitY, color.RGBA{R: 148, G: 163, B: 184, A: 255})
	return img
}

func drawConcatPiece(scene *image.RGBA, offset, splitY int) image.Image {
	splitY = clampInt(splitY, 1, 158)
	offset = clampInt(offset, 0, concatMaxMovement)
	piece := newCanvas(concatPieceWidth, 160, color.RGBA{A: 0})
	for x := 0; x < concatPieceWidth; x++ {
		sourceX := (x - (concatMaxMovement - offset)) % 320
		if sourceX < 0 {
			sourceX += 320
		}
		for y := 0; y < splitY; y++ {
			piece.Set(x, y, opaqueRGBA(rgbaAt(scene, sourceX, y)))
		}
	}
	return piece
}

func concatControlMax(offset, viewWidth, splitX, pieceWidth int) int {
	_ = offset
	_ = splitX
	_ = pieceWidth
	return min(viewWidth, concatMaxMovement)
}

func drawConcatDivider(img *image.RGBA, splitY int, c color.RGBA) {
	width := img.Bounds().Dx()
	height := img.Bounds().Dy()
	if width <= 0 || height <= 0 {
		return
	}
	y := clampInt(splitY, 1, height-2)
	for x := 0; x < width; x++ {
		img.Set(x, y, mixRGBA(rgbaAt(img, x, y), c, 0.18))
	}
}

func concatCoverPixel(x, y int) color.RGBA {
	noise := uint8((x*37 + y*19 + (x*y)%29) % 12)
	base := color.RGBA{R: 234 + noise/3, G: 239 + noise/4, B: 246, A: 255}
	if (x+y)%23 == 0 {
		return color.RGBA{R: 224, G: 231, B: 242, A: 255}
	}
	return base
}

func opaqueRGBA(c color.RGBA) color.RGBA {
	c.A = 255
	return c
}

func drawConcatScene() *image.RGBA {
	img := newCanvas(320, 160, color.RGBA{R: 226, G: 239, B: 249, A: 255})
	for y := 0; y < 160; y++ {
		ratio := float64(y) / 159
		c := mixRGBA(color.RGBA{R: 218, G: 238, B: 250, A: 255}, color.RGBA{R: 236, G: 246, B: 228, A: 255}, ratio)
		fillRect(img, 0, y, 320, 1, c)
	}
	drawPolyline(img, []image.Point{{-20, 116}, {52, 86}, {116, 108}, {172, 78}, {238, 112}, {340, 82}}, 42, color.RGBA{R: 82, G: 126, B: 145, A: 180})
	drawPolyline(img, []image.Point{{-20, 132}, {72, 106}, {136, 128}, {214, 98}, {340, 128}}, 44, color.RGBA{R: 118, G: 158, B: 124, A: 235})
	drawPolyline(img, cubicPolyline(
		image.Point{X: -18, Y: 58},
		image.Point{X: 74, Y: 118},
		image.Point{X: 134, Y: 38},
		image.Point{X: 204, Y: 96},
		52,
	), 20, color.RGBA{R: 37, G: 99, B: 235, A: 232})
	drawPolyline(img, cubicPolyline(
		image.Point{X: 204, Y: 96},
		image.Point{X: 246, Y: 124},
		image.Point{X: 278, Y: 48},
		image.Point{X: 344, Y: 88},
		40,
	), 20, color.RGBA{R: 37, G: 99, B: 235, A: 232})
	drawPolyline(img, cubicPolyline(
		image.Point{X: -12, Y: 101},
		image.Point{X: 88, Y: 76},
		image.Point{X: 154, Y: 141},
		image.Point{X: 246, Y: 84},
		44,
	), 8, color.RGBA{R: 245, G: 158, B: 11, A: 230})
	drawPolyline(img, []image.Point{{24, 136}, {76, 120}, {122, 142}, {184, 122}, {250, 146}, {322, 128}}, 5, color.RGBA{R: 45, G: 85, B: 74, A: 210})
	for i := 0; i < 20; i++ {
		x := mustRandomInt(12, 308)
		y := mustRandomInt(10, 142)
		radius := mustRandomInt(1, 3)
		drawCircle(img, x, y, radius, color.RGBA{R: 255, G: 255, B: 255, A: uint8(mustRandomInt(70, 155))})
	}
	drawCircle(img, 262, 34, 17, color.RGBA{R: 250, G: 204, B: 21, A: 245})
	drawCircle(img, 82, 54, 13, color.RGBA{R: 20, G: 184, B: 166, A: 230})
	return img
}

func drawWordImage(words []string, points []types.Point) image.Image {
	img := newCanvas(320, 160, color.RGBA{R: 248, G: 250, B: 252, A: 255})
	for i := 0; i < 18; i++ {
		drawCircle(img, mustRandomInt(10, 310), mustRandomInt(10, 150), mustRandomInt(1, 3), color.RGBA{R: 203, G: 213, B: 225, A: 255})
	}
	colors := []color.RGBA{
		{R: 31, G: 41, B: 55, A: 255},
		{R: 37, G: 99, B: 235, A: 255},
		{R: 190, G: 24, B: 93, A: 255},
	}
	for i, word := range words {
		if i >= len(points) {
			break
		}
		drawBlockGlyph(img, word, points[i].X, points[i].Y, 5, colors[i%len(colors)])
	}
	return img
}

func drawIconClickImage(points []types.Point) image.Image {
	img := newCanvas(320, 160, color.RGBA{R: 248, G: 250, B: 252, A: 255})
	for i := 0; i < 16; i++ {
		drawCircle(img, mustRandomInt(12, 308), mustRandomInt(12, 148), mustRandomInt(1, 3), color.RGBA{R: 203, G: 213, B: 225, A: 255})
	}
	if len(points) >= 1 {
		drawCircle(img, points[0].X, points[0].Y, 17, color.RGBA{R: 37, G: 99, B: 235, A: 255})
	}
	if len(points) >= 2 {
		fillRect(img, points[1].X-17, points[1].Y-17, 34, 34, color.RGBA{R: 20, G: 184, B: 166, A: 255})
		strokeRect(img, points[1].X-17, points[1].Y-17, 34, 34, 3, color.RGBA{R: 15, G: 118, B: 110, A: 255})
	}
	if len(points) >= 3 {
		fillPolygon(img, []image.Point{
			{X: points[2].X, Y: points[2].Y - 22},
			{X: points[2].X + 22, Y: points[2].Y + 19},
			{X: points[2].X - 22, Y: points[2].Y + 19},
		}, color.RGBA{R: 225, G: 29, B: 72, A: 255})
	}
	return img
}

func drawJigsawImage(points []types.Point) image.Image {
	base := drawJigsawBase()
	out := newCanvas(320, 160, color.RGBA{R: 248, G: 250, B: 252, A: 255})
	draw.Draw(out, out.Bounds(), base, image.Point{}, draw.Src)
	if len(points) >= 2 {
		first := jigsawTileRect(points[0])
		second := jigsawTileRect(points[1])
		draw.Draw(out, first, base, second.Min, draw.Src)
		draw.Draw(out, second, base, first.Min, draw.Src)
	}
	for x := jigsawTileWidth; x < 320; x += jigsawTileWidth {
		drawPolyline(out, []image.Point{{X: x, Y: 0}, {X: x, Y: 160}}, 1, color.RGBA{R: 255, G: 255, B: 255, A: 170})
	}
	for y := jigsawTileHeight; y < 160; y += jigsawTileHeight {
		drawPolyline(out, []image.Point{{X: 0, Y: y}, {X: 320, Y: y}}, 1, color.RGBA{R: 255, G: 255, B: 255, A: 170})
	}
	strokeRect(out, 0, 0, 320, 160, 1, color.RGBA{R: 203, G: 213, B: 225, A: 255})
	return out
}

func drawJigsawBase() *image.RGBA {
	base := newCanvas(320, 160, color.RGBA{R: 224, G: 242, B: 254, A: 255})
	for y := 0; y < 160; y++ {
		for x := 0; x < 320; x++ {
			base.SetRGBA(x, y, color.RGBA{
				R: uint8(214 + x/18),
				G: uint8(232 + y/14),
				B: uint8(246 - y/12),
				A: 255,
			})
		}
	}
	fillRect(base, 0, 102, 320, 58, color.RGBA{R: 134, G: 239, B: 172, A: 255})
	drawPolyline(base, []image.Point{{0, 118}, {58, 86}, {108, 110}, {164, 72}, {226, 104}, {320, 78}}, 14, color.RGBA{R: 34, G: 197, B: 94, A: 255})
	drawPolyline(base, []image.Point{{0, 126}, {58, 94}, {108, 118}, {164, 80}, {226, 112}, {320, 86}}, 5, color.RGBA{R: 22, G: 101, B: 52, A: 150})
	drawCircle(base, 270, 32, 17, color.RGBA{R: 250, G: 204, B: 21, A: 255})
	drawCircle(base, 76, 58, 19, color.RGBA{R: 37, G: 99, B: 235, A: 235})
	fillRect(base, 190, 98, 48, 30, color.RGBA{R: 245, G: 158, B: 11, A: 245})
	drawPolyline(base, []image.Point{{38, 140}, {82, 130}, {132, 146}, {204, 132}, {284, 144}}, 4, color.RGBA{R: 21, G: 128, B: 61, A: 210})
	return base
}

func jigsawSwapPoints() []types.Point {
	pairs := [][2]int{
		{0, 15}, {3, 12}, {1, 14}, {4, 11}, {7, 8}, {2, 13},
	}
	pair := pairs[mustRandomInt(0, len(pairs)-1)]
	return []types.Point{
		jigsawTileCenter(pair[0]),
		jigsawTileCenter(pair[1]),
	}
}

func jigsawTileCenter(index int) types.Point {
	col := index % jigsawTileCols
	row := index / jigsawTileCols
	return types.Point{
		X: col*jigsawTileWidth + jigsawTileWidth/2,
		Y: row*jigsawTileHeight + jigsawTileHeight/2,
	}
}

func jigsawTileRect(center types.Point) image.Rectangle {
	x := (center.X / jigsawTileWidth) * jigsawTileWidth
	y := (center.Y / jigsawTileHeight) * jigsawTileHeight
	return image.Rect(x, y, x+jigsawTileWidth, y+jigsawTileHeight)
}

func gridImageTargetPoints() []types.Point {
	pool := make([]int, 0, gridImageCols*gridImageRows)
	for i := 0; i < gridImageCols*gridImageRows; i++ {
		pool = append(pool, i)
	}
	points := make([]types.Point, 0, 3)
	for len(points) < 3 && len(pool) > 0 {
		pick := mustRandomInt(0, len(pool)-1)
		index := pool[pick]
		pool = append(pool[:pick], pool[pick+1:]...)
		points = append(points, gridImageTileCenter(index))
	}
	return points
}

func gridImageTileCenter(index int) types.Point {
	col := index % gridImageCols
	row := index / gridImageCols
	return types.Point{
		X: col*gridImageTileSize + gridImageTileSize/2,
		Y: row*gridImageTileSize + gridImageTileSize/2,
	}
}

func drawGridImageChallenge(points []types.Point) image.Image {
	width := gridImageCols * gridImageTileSize
	height := gridImageRows * gridImageTileSize
	img := newCanvas(width, height, color.RGBA{R: 248, G: 250, B: 252, A: 255})
	targets := make(map[int]struct{}, len(points))
	for _, point := range points {
		col := clampInt(point.X/gridImageTileSize, 0, gridImageCols-1)
		row := clampInt(point.Y/gridImageTileSize, 0, gridImageRows-1)
		targets[row*gridImageCols+col] = struct{}{}
	}
	for row := 0; row < gridImageRows; row++ {
		for col := 0; col < gridImageCols; col++ {
			index := row*gridImageCols + col
			x := col * gridImageTileSize
			y := row * gridImageTileSize
			fillRect(img, x, y, gridImageTileSize, gridImageTileSize, gridTileBackground(index))
			centerX := x + gridImageTileSize/2
			centerY := y + gridImageTileSize/2
			if _, ok := targets[index]; ok {
				drawCircle(img, centerX, centerY, 27, color.RGBA{R: 37, G: 99, B: 235, A: 255})
				drawCircle(img, centerX-9, centerY-8, 8, color.RGBA{R: 147, G: 197, B: 253, A: 210})
				continue
			}
			drawGridDecoy(img, index, centerX, centerY)
		}
	}
	for x := gridImageTileSize; x < width; x += gridImageTileSize {
		drawPolyline(img, []image.Point{{X: x, Y: 0}, {X: x, Y: height}}, 3, color.RGBA{R: 255, G: 255, B: 255, A: 255})
	}
	for y := gridImageTileSize; y < height; y += gridImageTileSize {
		drawPolyline(img, []image.Point{{X: 0, Y: y}, {X: width, Y: y}}, 3, color.RGBA{R: 255, G: 255, B: 255, A: 255})
	}
	strokeRect(img, 0, 0, width, height, 1, color.RGBA{R: 203, G: 213, B: 225, A: 255})
	return img
}

func gridTileBackground(index int) color.RGBA {
	palette := []color.RGBA{
		{R: 240, G: 249, B: 255, A: 255},
		{R: 240, G: 253, B: 244, A: 255},
		{R: 255, G: 251, B: 235, A: 255},
		{R: 253, G: 244, B: 255, A: 255},
		{R: 245, G: 245, B: 244, A: 255},
	}
	return palette[index%len(palette)]
}

func drawGridDecoy(img *image.RGBA, index, centerX, centerY int) {
	switch index % 6 {
	case 0:
		fillRect(img, centerX-24, centerY-24, 48, 48, color.RGBA{R: 20, G: 184, B: 166, A: 255})
		strokeRect(img, centerX-24, centerY-24, 48, 48, 3, color.RGBA{R: 15, G: 118, B: 110, A: 255})
	case 1:
		drawCircle(img, centerX, centerY, 25, color.RGBA{R: 245, G: 158, B: 11, A: 255})
	case 2:
		fillPolygon(img, []image.Point{{X: centerX, Y: centerY - 30}, {X: centerX + 30, Y: centerY + 24}, {X: centerX - 30, Y: centerY + 24}}, color.RGBA{R: 225, G: 29, B: 72, A: 255})
	case 3:
		fillPolygon(img, []image.Point{{X: centerX, Y: centerY - 31}, {X: centerX + 31, Y: centerY}, {X: centerX, Y: centerY + 31}, {X: centerX - 31, Y: centerY}}, color.RGBA{R: 132, G: 204, B: 22, A: 255})
	case 4:
		fillRect(img, centerX-30, centerY-16, 60, 32, color.RGBA{R: 99, G: 102, B: 241, A: 255})
		drawCircle(img, centerX-18, centerY+20, 7, color.RGBA{R: 15, G: 23, B: 42, A: 255})
		drawCircle(img, centerX+18, centerY+20, 7, color.RGBA{R: 15, G: 23, B: 42, A: 255})
	default:
		drawPolyline(img, []image.Point{{X: centerX - 28, Y: centerY + 20}, {X: centerX - 8, Y: centerY - 20}, {X: centerX + 12, Y: centerY + 18}, {X: centerX + 30, Y: centerY - 14}}, 8, color.RGBA{R: 168, G: 85, B: 247, A: 255})
	}
}

func spacedClickPoints() []types.Point {
	return jitterClickPoints([]types.Point{
		{X: 72, Y: 80},
		{X: 160, Y: 80},
		{X: 248, Y: 80},
	}, 8, 22)
}

func orderedWordClickPoints() map[string]types.Point {
	points := jitterClickPoints([]types.Point{
		{X: 72, Y: 80},
		{X: 160, Y: 80},
		{X: 248, Y: 80},
	}, 8, 22)
	return map[string]types.Point{
		"A": points[0],
		"B": points[1],
		"C": points[2],
	}
}

func jitterClickPoints(anchors []types.Point, jitterX, jitterY int) []types.Point {
	points := make([]types.Point, 0, len(anchors))
	for _, anchor := range anchors {
		points = append(points, types.Point{
			X: anchor.X + mustRandomInt(-jitterX, jitterX),
			Y: anchor.Y + mustRandomInt(-jitterY, jitterY),
		})
	}
	return points
}

func verifyPointSequence(expected, actual []types.Point) (bool, string) {
	if len(actual) != len(expected) {
		return false, "ANSWER_MISSING"
	}
	for i := range expected {
		if distance(actual[i], expected[i]) > wordClickTolerance {
			return false, "ANSWER_MISMATCH"
		}
	}
	return true, "OK"
}

func verifyJigsawSwap(expected, actual []types.Point, payload types.RenderPayload) (bool, string) {
	if len(actual) != len(expected) {
		return false, "ANSWER_MISSING"
	}
	tileWidth := renderIntParam(payload, "tile_width", jigsawTileWidth)
	tileHeight := renderIntParam(payload, "tile_height", jigsawTileHeight)
	matched := make([]bool, len(expected))
	for _, point := range actual {
		found := false
		for i, expectedPoint := range expected {
			if matched[i] {
				continue
			}
			if pointInTile(point, expectedPoint, tileWidth, tileHeight) {
				matched[i] = true
				found = true
				break
			}
		}
		if !found {
			return false, "ANSWER_MISMATCH"
		}
	}
	return true, "OK"
}

func verifyGridImageSelection(expected, actual []types.Point, payload types.RenderPayload) (bool, string) {
	if len(actual) != len(expected) {
		return false, "ANSWER_MISSING"
	}
	tileWidth := renderIntParam(payload, "tile_width", gridImageTileSize)
	tileHeight := renderIntParam(payload, "tile_height", gridImageTileSize)
	matched := make([]bool, len(expected))
	for _, point := range actual {
		found := false
		for i, expectedPoint := range expected {
			if matched[i] {
				continue
			}
			if pointInTile(point, expectedPoint, tileWidth, tileHeight) {
				matched[i] = true
				found = true
				break
			}
		}
		if !found {
			return false, "ANSWER_MISMATCH"
		}
	}
	return true, "OK"
}

func pointInTile(point, center types.Point, width, height int) bool {
	if width <= 0 || height <= 0 {
		return distance(point, center) <= wordClickTolerance
	}
	return abs(point.X-center.X) <= width/2 && abs(point.Y-center.Y) <= height/2
}

func renderIntParam(payload types.RenderPayload, key string, fallback int) int {
	value := payload.Parameters[key]
	switch typed := value.(type) {
	case int:
		if typed > 0 {
			return typed
		}
	case int64:
		if typed > 0 {
			return int(typed)
		}
	case float64:
		if typed > 0 {
			return int(typed)
		}
	}
	return fallback
}

func verifyGesturePathSequence(expected, actual []types.Point, tolerance float64) (bool, string) {
	if len(actual) < 4 || len(expected) < 2 {
		return false, "ANSWER_MISSING"
	}
	expectedLength := pointPathLength(expected)
	actualLength := pointPathLength(actual)
	chord := distance(expected[0], expected[len(expected)-1])
	if expectedLength <= 0 || chord <= 0 {
		return false, "ANSWER_MISMATCH"
	}
	if actualLength < chord*0.92 || actualLength > expectedLength*2.25 {
		return false, "ANSWER_MISMATCH"
	}
	expectedBendRatio := expectedLength / chord
	actualBendRatio := actualLength / chord
	if expectedBendRatio > 1.08 && actualBendRatio < 1+(expectedBendRatio-1)*0.45 {
		return false, "ANSWER_MISMATCH"
	}
	ok, reason := verifyPathSequence(expected, actual, tolerance)
	if !ok {
		return false, reason
	}
	if !hasMonotonicPathProgress(expected, actual, expectedLength*0.24) {
		return false, "ANSWER_MISMATCH"
	}
	return true, "OK"
}

func verifyCurvePathSequence(expected, actual []types.Point, tolerance float64) (bool, string) {
	ok, reason := verifyPathSequence(expected, actual, tolerance)
	if !ok {
		return false, reason
	}
	if len(actual) < max(8, len(expected)/4) {
		return false, "ANSWER_MISMATCH"
	}
	if !coversExpectedKeypoints(expected, actual, tolerance*1.2) {
		return false, "ANSWER_MISMATCH"
	}
	expectedLength := pointPathLength(expected)
	actualLength := pointPathLength(actual)
	if expectedLength <= 0 || actualLength < expectedLength*0.86 || actualLength > expectedLength*1.75 {
		return false, "ANSWER_MISMATCH"
	}
	if !hasMonotonicPathProgress(expected, actual, expectedLength*0.12) {
		return false, "ANSWER_MISMATCH"
	}
	return true, "OK"
}

func curveAnswerMatchesTrack(answer []types.Point, track []types.TrackPoint, tolerance float64) bool {
	trackPath := pointsFromTrack(track)
	if len(answer) < 4 || len(trackPath) < 4 {
		return false
	}
	answerLength := pointPathLength(answer)
	trackLength := pointPathLength(trackPath)
	if answerLength <= 0 || trackLength < answerLength*0.72 || trackLength > answerLength*1.35 {
		return false
	}
	ok, _ := verifyPathSequence(answer, trackPath, tolerance)
	return ok
}

func sliderAnswerMatchesTrack(answer *int, track []types.TrackPoint, tolerance float64) bool {
	if answer == nil || len(track) < 2 {
		return false
	}
	for i := len(track) - 1; i >= 0; i-- {
		point := track[i]
		if math.IsNaN(point.X) || math.IsInf(point.X, 0) {
			continue
		}
		return math.Abs(point.X-float64(*answer)) <= tolerance
	}
	return false
}

func pointsFromTrack(track []types.TrackPoint) []types.Point {
	points := make([]types.Point, 0, len(track))
	for _, point := range track {
		if math.IsNaN(point.X) || math.IsNaN(point.Y) || math.IsInf(point.X, 0) || math.IsInf(point.Y, 0) {
			continue
		}
		points = append(points, types.Point{
			X: int(math.Round(point.X)),
			Y: int(math.Round(point.Y)),
		})
	}
	return points
}

func verifyPathSequence(expected, actual []types.Point, tolerance float64) (bool, string) {
	if len(actual) < 4 || len(expected) < 2 {
		return false, "ANSWER_MISSING"
	}
	if distance(actual[0], expected[0]) > tolerance*1.8 {
		return false, "ANSWER_MISMATCH"
	}
	if distance(actual[len(actual)-1], expected[len(expected)-1]) > tolerance*1.8 {
		return false, "ANSWER_MISMATCH"
	}
	total := 0.0
	maxDistance := 0.0
	for _, point := range actual {
		d := minDistanceToPath(point, expected)
		total += d
		if d > maxDistance {
			maxDistance = d
		}
	}
	averageActualDistance := total / float64(len(actual))
	expectedSamples := resamplePath(expected, 18)
	actualSamples := resamplePath(actual, 18)
	expectedTotal := 0.0
	expectedMax := 0.0
	pairTotal := 0.0
	pairMax := 0.0
	for i, point := range expectedSamples {
		d := minDistanceToPath(point, actual)
		expectedTotal += d
		if d > expectedMax {
			expectedMax = d
		}
		pairDistance := distance(point, actualSamples[i])
		pairTotal += pairDistance
		if pairDistance > pairMax {
			pairMax = pairDistance
		}
	}
	averageExpectedDistance := expectedTotal / float64(len(expectedSamples))
	averagePairDistance := pairTotal / float64(len(expectedSamples))
	if averageActualDistance <= tolerance*1.6 &&
		maxDistance <= tolerance*4.2 &&
		averageExpectedDistance <= tolerance*1.8 &&
		expectedMax <= tolerance*4.4 &&
		averagePairDistance <= tolerance*2.2 &&
		pairMax <= tolerance*4.8 {
		return true, "OK"
	}
	return false, "ANSWER_MISMATCH"
}

func resamplePath(points []types.Point, count int) []types.Point {
	if count <= 0 {
		return nil
	}
	if len(points) == 0 {
		return make([]types.Point, count)
	}
	if len(points) == 1 {
		resampled := make([]types.Point, count)
		for i := range resampled {
			resampled[i] = points[0]
		}
		return resampled
	}
	totalLength := pointPathLength(points)
	if totalLength == 0 {
		resampled := make([]types.Point, count)
		for i := range resampled {
			resampled[i] = points[0]
		}
		return resampled
	}
	if count == 1 {
		return []types.Point{points[0]}
	}
	resampled := make([]types.Point, 0, count)
	segmentIndex := 1
	segmentStartLength := 0.0
	for i := 0; i < count; i++ {
		target := totalLength * float64(i) / float64(count-1)
		for segmentIndex < len(points)-1 {
			segmentLength := distance(points[segmentIndex-1], points[segmentIndex])
			if segmentStartLength+segmentLength >= target {
				break
			}
			segmentStartLength += segmentLength
			segmentIndex++
		}
		a := points[segmentIndex-1]
		b := points[segmentIndex]
		segmentLength := distance(a, b)
		t := 0.0
		if segmentLength > 0 {
			t = (target - segmentStartLength) / segmentLength
		}
		t = math.Max(0, math.Min(1, t))
		resampled = append(resampled, types.Point{
			X: int(math.Round(float64(a.X) + float64(b.X-a.X)*t)),
			Y: int(math.Round(float64(a.Y) + float64(b.Y-a.Y)*t)),
		})
	}
	return resampled
}

func coversExpectedKeypoints(expected, actual []types.Point, tolerance float64) bool {
	for _, expectedPoint := range expected {
		best := math.MaxFloat64
		for _, actualPoint := range actual {
			d := distance(actualPoint, expectedPoint)
			if d < best {
				best = d
			}
		}
		if best > tolerance {
			return false
		}
	}
	return true
}

func hasMonotonicPathProgress(expected, actual []types.Point, allowedBacktrack float64) bool {
	if len(expected) < 2 || len(actual) < 2 {
		return false
	}
	previous := -math.MaxFloat64
	for _, point := range actual {
		progress := pathProgressAtNearestPoint(point, expected)
		if previous > 0 && progress+allowedBacktrack < previous {
			return false
		}
		if progress > previous {
			previous = progress
		}
	}
	return true
}

func pathProgressAtNearestPoint(point types.Point, path []types.Point) float64 {
	bestDistance := math.MaxFloat64
	bestProgress := 0.0
	progressBeforeSegment := 0.0
	for i := 1; i < len(path); i++ {
		a, b := path[i-1], path[i]
		segmentLength := distance(a, b)
		if segmentLength == 0 {
			continue
		}
		t, d := projectedPointDistance(point, a, b)
		if d < bestDistance {
			bestDistance = d
			bestProgress = progressBeforeSegment + segmentLength*t
		}
		progressBeforeSegment += segmentLength
	}
	return bestProgress
}

func projectedPointDistance(point, a, b types.Point) (float64, float64) {
	px, py := float64(point.X), float64(point.Y)
	ax, ay := float64(a.X), float64(a.Y)
	bx, by := float64(b.X), float64(b.Y)
	dx, dy := bx-ax, by-ay
	if dx == 0 && dy == 0 {
		return 0, math.Hypot(px-ax, py-ay)
	}
	t := ((px-ax)*dx + (py-ay)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	x := ax + t*dx
	y := ay + t*dy
	return t, math.Hypot(px-x, py-y)
}

func pointPathLength(points []types.Point) float64 {
	total := 0.0
	for i := 1; i < len(points); i++ {
		total += distance(points[i-1], points[i])
	}
	return total
}

func minDistanceToPath(point types.Point, path []types.Point) float64 {
	best := math.MaxFloat64
	for i := 1; i < len(path); i++ {
		d := pointSegmentDistance(point, path[i-1], path[i])
		if d < best {
			best = d
		}
	}
	return best
}

func pointSegmentDistance(point, a, b types.Point) float64 {
	px, py := float64(point.X), float64(point.Y)
	ax, ay := float64(a.X), float64(a.Y)
	bx, by := float64(b.X), float64(b.Y)
	dx, dy := bx-ax, by-ay
	if dx == 0 && dy == 0 {
		return math.Hypot(px-ax, py-ay)
	}
	t := ((px-ax)*dx + (py-ay)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	x := ax + t*dx
	y := ay + t*dy
	return math.Hypot(px-x, py-y)
}

func verifyProofOfWork(seed string, nonce, difficulty, maxNonce int) bool {
	if seed == "" || nonce < 0 || nonce > maxNonce || difficulty <= 0 || difficulty > 6 {
		return false
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", seed, nonce)))
	encoded := fmt.Sprintf("%x", sum[:])
	return strings.HasPrefix(encoded, strings.Repeat("0", difficulty))
}

func newCanvas(width, height int, bg color.RGBA) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.Draw(img, img.Bounds(), &image.Uniform{C: bg}, image.Point{}, draw.Src)
	return img
}

func copyRGBA(src image.Image) *image.RGBA {
	bounds := src.Bounds()
	dst := image.NewRGBA(bounds)
	draw.Draw(dst, bounds, src, bounds.Min, draw.Src)
	return dst
}

func rgbaAt(img image.Image, x, y int) color.RGBA {
	return color.RGBAModel.Convert(img.At(x, y)).(color.RGBA)
}

func mixRGBA(a, b color.RGBA, ratio float64) color.RGBA {
	ratio = math.Max(0, math.Min(1, ratio))
	keep := 1 - ratio
	return color.RGBA{
		R: uint8(float64(a.R)*keep + float64(b.R)*ratio),
		G: uint8(float64(a.G)*keep + float64(b.G)*ratio),
		B: uint8(float64(a.B)*keep + float64(b.B)*ratio),
		A: uint8(float64(a.A)*keep + float64(b.A)*ratio),
	}
}

func square(v int) int {
	return v * v
}

func fillRect(img *image.RGBA, x, y, width, height int, c color.RGBA) {
	draw.Draw(img, image.Rect(x, y, x+width, y+height).Intersect(img.Bounds()), &image.Uniform{C: c}, image.Point{}, draw.Over)
}

func strokeRect(img *image.RGBA, x, y, width, height, thickness int, c color.RGBA) {
	fillRect(img, x, y, width, thickness, c)
	fillRect(img, x, y+height-thickness, width, thickness, c)
	fillRect(img, x, y, thickness, height, c)
	fillRect(img, x+width-thickness, y, thickness, height, c)
}

func drawCircle(img *image.RGBA, cx, cy, radius int, c color.RGBA) {
	bounds := img.Bounds()
	r2 := radius * radius
	for y := cy - radius; y <= cy+radius; y++ {
		for x := cx - radius; x <= cx+radius; x++ {
			if x < bounds.Min.X || x >= bounds.Max.X || y < bounds.Min.Y || y >= bounds.Max.Y {
				continue
			}
			dx, dy := x-cx, y-cy
			if dx*dx+dy*dy <= r2 {
				img.Set(x, y, c)
			}
		}
	}
}

func drawPolyline(img *image.RGBA, points []image.Point, thickness int, c color.RGBA) {
	for i := 1; i < len(points); i++ {
		drawLine(img, points[i-1], points[i], thickness, c)
	}
}

func drawLine(img *image.RGBA, a, b image.Point, thickness int, c color.RGBA) {
	steps := max(abs(b.X-a.X), abs(b.Y-a.Y))
	if steps == 0 {
		drawCircle(img, a.X, a.Y, max(1, thickness/2), c)
		return
	}
	radius := max(1, thickness/2)
	for i := 0; i <= steps; i++ {
		t := float64(i) / float64(steps)
		x := int(math.Round(float64(a.X) + float64(b.X-a.X)*t))
		y := int(math.Round(float64(a.Y) + float64(b.Y-a.Y)*t))
		drawCircle(img, x, y, radius, c)
	}
}

func cubicPolyline(p0, p1, p2, p3 image.Point, steps int) []image.Point {
	points := make([]image.Point, 0, steps+1)
	for i := 0; i <= steps; i++ {
		t := float64(i) / float64(steps)
		mt := 1 - t
		x := mt*mt*mt*float64(p0.X) + 3*mt*mt*t*float64(p1.X) + 3*mt*t*t*float64(p2.X) + t*t*t*float64(p3.X)
		y := mt*mt*mt*float64(p0.Y) + 3*mt*mt*t*float64(p1.Y) + 3*mt*t*t*float64(p2.Y) + t*t*t*float64(p3.Y)
		points = append(points, image.Point{X: int(math.Round(x)), Y: int(math.Round(y))})
	}
	return points
}

func rotatePoint(x, y, angle, cx, cy int) image.Point {
	radians := float64(angle) * math.Pi / 180
	sin, cos := math.Sin(radians), math.Cos(radians)
	rx := float64(x)*cos - float64(y)*sin
	ry := float64(x)*sin + float64(y)*cos
	return image.Point{X: cx + int(math.Round(rx)), Y: cy + int(math.Round(ry))}
}

func fillPolygon(img *image.RGBA, points []image.Point, c color.RGBA) {
	if len(points) < 3 {
		return
	}
	minX, maxX := points[0].X, points[0].X
	minY, maxY := points[0].Y, points[0].Y
	for _, point := range points[1:] {
		if point.X < minX {
			minX = point.X
		}
		if point.X > maxX {
			maxX = point.X
		}
		if point.Y < minY {
			minY = point.Y
		}
		if point.Y > maxY {
			maxY = point.Y
		}
	}
	bounds := img.Bounds()
	for y := max(minY, bounds.Min.Y); y <= min(maxY, bounds.Max.Y-1); y++ {
		for x := max(minX, bounds.Min.X); x <= min(maxX, bounds.Max.X-1); x++ {
			if pointInPolygon(x, y, points) {
				img.Set(x, y, c)
			}
		}
	}
}

func pointInPolygon(x, y int, points []image.Point) bool {
	inside := false
	j := len(points) - 1
	for i := range points {
		yi, yj := points[i].Y, points[j].Y
		xi, xj := points[i].X, points[j].X
		if (yi > y) != (yj > y) {
			crossX := float64(xj-xi)*float64(y-yi)/float64(yj-yi) + float64(xi)
			if float64(x) < crossX {
				inside = !inside
			}
		}
		j = i
	}
	return inside
}

func drawBlockGlyph(img *image.RGBA, value string, cx, cy, scale int, c color.RGBA) {
	pattern, ok := glyphPatterns[value]
	if !ok {
		return
	}
	width := len(pattern[0]) * scale
	height := len(pattern) * scale
	startX := cx - width/2
	startY := cy - height/2
	shadow := color.RGBA{R: 255, G: 255, B: 255, A: 230}
	for row, line := range pattern {
		for col, pixel := range line {
			if pixel != '1' {
				continue
			}
			x := startX + col*scale
			y := startY + row*scale
			fillRect(img, x+2, y+2, scale, scale, shadow)
			fillRect(img, x, y, scale, scale, c)
		}
	}
}

var glyphPatterns = map[string][]string{
	"A": {
		"01110",
		"10001",
		"10001",
		"11111",
		"10001",
		"10001",
		"10001",
	},
	"B": {
		"11110",
		"10001",
		"10001",
		"11110",
		"10001",
		"10001",
		"11110",
	},
	"C": {
		"01111",
		"10000",
		"10000",
		"10000",
		"10000",
		"10000",
		"01111",
	},
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func clampInt(value, lower, upper int) int {
	return min(upper, max(lower, value))
}

func angleDiff(a, b int) int {
	a = ((a % 360) + 360) % 360
	b = ((b % 360) + 360) % 360
	diff := abs(a - b)
	if diff > 180 {
		return 360 - diff
	}
	return diff
}

func distance(a, b types.Point) float64 {
	return math.Hypot(float64(a.X-b.X), float64(a.Y-b.Y))
}

func analyzeTrack(track []types.TrackPoint) trackAnalysis {
	analysis := trackAnalysis{OriginalPointCount: len(track)}
	if len(track) > maxTrackPoints {
		track = track[:maxTrackPoints]
		analysis.Truncated = true
	}
	analysis.PointCount = len(track)
	analysis.TooFewPoints = analysis.PointCount < 3
	if analysis.PointCount == 0 {
		return analysis
	}

	analysis.TimestampAnomaly = hasTimestampAnomaly(track)
	analysis.PerfectLine = isPerfectLine(track)
	analysis.Teleport = hasTeleport(track)
	if analysis.PointCount < 2 {
		return analysis
	}

	first := track[0]
	last := track[analysis.PointCount-1]
	analysis.DurationMS = last.T - first.T
	if analysis.DurationMS < 0 {
		analysis.DurationMS = 0
	}
	analysis.TooFast = analysis.DurationMS > 0 && analysis.DurationMS < 180
	analysis.DistanceX = last.X - first.X
	analysis.DistanceY = last.Y - first.Y
	analysis.DirectDistance = math.Hypot(analysis.DistanceX, analysis.DistanceY)

	minY, maxY := first.Y, first.Y
	velocities := make([]float64, 0, max(analysis.PointCount-1, 0))
	accelerations := make([]float64, 0, max(analysis.PointCount-2, 0))
	jerks := make([]float64, 0, max(analysis.PointCount-3, 0))
	lastDXSign := 0
	moveStarted := false
	var previousVelocity float64
	var previousAcceleration float64
	direction := signFloat(analysis.DistanceX)
	if direction == 0 {
		direction = 1
	}

	for i := 1; i < analysis.PointCount; i++ {
		prev := track[i-1]
		current := track[i]
		dx := current.X - prev.X
		dy := current.Y - prev.Y
		dt := current.T - prev.T
		dist := math.Hypot(dx, dy)
		analysis.PathLength += dist
		if current.Y < minY {
			minY = current.Y
		}
		if current.Y > maxY {
			maxY = current.Y
		}
		if !moveStarted && math.Hypot(current.X-first.X, current.Y-first.Y) > 2 {
			analysis.StartDelayMS = float64(current.T - first.T)
			if analysis.StartDelayMS < 0 {
				analysis.StartDelayMS = 0
			}
			moveStarted = true
		}
		if dt >= 180 && dist < 4 {
			analysis.PauseCount++
		}
		dxSign := signFloat(dx)
		if math.Abs(dx) >= 1 {
			if lastDXSign != 0 && dxSign != 0 && dxSign != lastDXSign {
				analysis.DirectionChanges++
			}
			if dxSign != 0 {
				lastDXSign = dxSign
			}
		}
		if math.Abs(dx) > 0 && math.Abs(dx) < 5 && dt >= 30 {
			analysis.MicroCorrections++
		}
		if direction > 0 && current.X > last.X+6 {
			analysis.OvershootCount++
		}
		if direction < 0 && current.X < last.X-6 {
			analysis.OvershootCount++
		}
		if dt > 0 {
			seconds := float64(dt) / 1000
			velocity := dist / seconds
			velocities = append(velocities, velocity)
			if velocity > analysis.MaxVelocity {
				analysis.MaxVelocity = velocity
			}
			if len(velocities) > 1 {
				acceleration := (velocity - previousVelocity) / seconds
				accelerations = append(accelerations, acceleration)
				if len(accelerations) > 1 {
					jerk := (acceleration - previousAcceleration) / seconds
					jerks = append(jerks, jerk)
				}
				previousAcceleration = acceleration
			}
			previousVelocity = velocity
		}
	}

	if analysis.PathLength > 0 {
		analysis.Straightness = analysis.DirectDistance / analysis.PathLength
	}
	analysis.YJitter = maxY - minY
	analysis.AvgVelocity = average(velocities)
	analysis.VelocityVariance = variance(velocities)
	analysis.AccelerationVariance = variance(accelerations)
	analysis.JerkVariance = variance(jerks)
	analysis.EndStability = endStability(track)
	if len(velocities) >= 4 && analysis.AvgVelocity > 0 {
		cv := math.Sqrt(analysis.VelocityVariance) / analysis.AvgVelocity
		analysis.ConstantVelocity = cv < 0.03
	}
	analysis.SyntheticCurve = analysis.PointCount >= 5 && analysis.PerfectLine && analysis.ConstantVelocity && analysis.YJitter < 1
	return analysis
}

func hasTimestampAnomaly(track []types.TrackPoint) bool {
	for i := 1; i < len(track); i++ {
		if track[i].T < track[i-1].T {
			return true
		}
	}
	return false
}

func isPerfectLine(track []types.TrackPoint) bool {
	if len(track) < 4 {
		return false
	}
	first := track[0]
	last := track[len(track)-1]
	dx := last.X - first.X
	dy := last.Y - first.Y
	if dx == 0 && dy == 0 {
		return true
	}
	maxDeviation := 0.0
	for _, p := range track[1 : len(track)-1] {
		deviation := math.Abs(dy*p.X-dx*p.Y+last.X*first.Y-last.Y*first.X) / math.Hypot(dx, dy)
		if deviation > maxDeviation {
			maxDeviation = deviation
		}
	}
	return maxDeviation < 0.5
}

func hasTeleport(track []types.TrackPoint) bool {
	for i := 1; i < len(track); i++ {
		dt := track[i].T - track[i-1].T
		dist := math.Hypot(track[i].X-track[i-1].X, track[i].Y-track[i-1].Y)
		if dt >= 0 && dt < 16 && dist > 90 {
			return true
		}
	}
	return false
}

func endStability(track []types.TrackPoint) float64 {
	if len(track) < 2 {
		return 0
	}
	last := track[len(track)-1]
	total := 0.0
	for i := len(track) - 1; i > 0; i-- {
		if last.T-track[i-1].T > 120 {
			break
		}
		total += math.Hypot(track[i].X-track[i-1].X, track[i].Y-track[i-1].Y)
	}
	return total
}

func average(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	total := 0.0
	for _, value := range values {
		total += value
	}
	return total / float64(len(values))
}

func variance(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	mean := average(values)
	total := 0.0
	for _, value := range values {
		delta := value - mean
		total += delta * delta
	}
	return total / float64(len(values))
}

func signFloat(value float64) int {
	switch {
	case value > 0:
		return 1
	case value < 0:
		return -1
	default:
		return 0
	}
}

func round2(value float64) float64 {
	return math.Round(value*100) / 100
}

func round4(value float64) float64 {
	return math.Round(value*10000) / 10000
}

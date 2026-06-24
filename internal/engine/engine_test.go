package engine

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"strings"
	"testing"
	"time"

	"captcha/internal/types"
)

func TestGenerateAndVerifyAllCaptchaTypes(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	cases := []types.CaptchaType{
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

	for _, captchaType := range cases {
		captchaType := captchaType
		t.Run(string(captchaType), func(t *testing.T) {
			t.Parallel()

			session, err := e.NewSession("app_test", "login", captchaType)
			if err != nil {
				t.Fatalf("new session: %v", err)
			}
			answer := answerFor(session)
			result := e.Verify(session, answer, trackForSession(session))
			if !result.OK {
				t.Fatalf("expected verification to pass, decision=%s reason=%s score=%+v", result.Decision, result.ReasonCode, result.TrackScore)
			}
			if !result.IssueTicket {
				t.Fatal("expected successful verification to issue ticket")
			}
		})
	}
}

func TestSyntheticFastTrackIsRejected(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	session, err := e.NewSession("app_test", "login", types.CaptchaSlider)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}

	result := e.Verify(session, answerFor(session), []types.TrackPoint{
		{X: 0, Y: 20, T: 0, Type: "start"},
		{X: float64(session.Answer.X), Y: 20, T: 20, Type: "end"},
	})
	if result.OK {
		t.Fatal("expected very fast sparse track to be rejected")
	}
	if result.Decision != types.DecisionChallengeHarder || result.ReasonCode != "TRACK_CHALLENGE_HARDER" {
		t.Fatalf("unexpected challenge escalation result: %+v", result)
	}
	if !containsReason(result.TrackScore.Reasons, "TRACK_TOO_FEW_POINTS") {
		t.Fatalf("expected sparse track reason, got %+v", result.TrackScore)
	}
}

func TestGeneratedPayloadsUsePNGDataURLs(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	for _, captchaType := range []types.CaptchaType{
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
	} {
		session, err := e.NewSession("app_test", "login", captchaType)
		if err != nil {
			t.Fatalf("new session %s: %v", captchaType, err)
		}
		assertPNGDataURL(t, session.RenderPayload.Image)
		if strings.Contains(session.RenderPayload.Image, "svg+xml") {
			t.Fatalf("challenge image should not expose inspectable SVG: %s", captchaType)
		}
		if captchaType == types.CaptchaSlider || captchaType == types.CaptchaSlider2 || captchaType == types.CaptchaConcat {
			assertPNGDataURL(t, session.RenderPayload.Piece)
		}
	}
}

func TestSliderChallengesUseLargeSVGPiecesInBounds(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	cases := map[types.CaptchaType]int{
		types.CaptchaSlider:  sliderPieceSize,
		types.CaptchaSlider2: slider2PieceSize,
	}
	for captchaType, expectedSize := range cases {
		captchaType := captchaType
		expectedSize := expectedSize
		t.Run(string(captchaType), func(t *testing.T) {
			t.Parallel()

			for i := 0; i < 20; i++ {
				session, err := e.NewSession("app_test", "login", captchaType)
				if err != nil {
					t.Fatalf("new session: %v", err)
				}
				size := intParam(t, session.RenderPayload.Parameters, "piece_size")
				if size != expectedSize {
					t.Fatalf("expected piece size %d, got %d", expectedSize, size)
				}
				if session.Answer.X < 0 || session.Answer.X+size > session.RenderPayload.View.Width {
					t.Fatalf("slider x out of bounds: answer=%+v size=%d view=%+v", session.Answer, size, session.RenderPayload.View)
				}
				if session.Answer.Y < 0 || session.Answer.Y+size > session.RenderPayload.View.Height {
					t.Fatalf("slider y out of bounds: answer=%+v size=%d view=%+v", session.Answer, size, session.RenderPayload.View)
				}
				piece := decodePNGDataURL(t, session.RenderPayload.Piece)
				if piece.Bounds().Dx() != size || piece.Bounds().Dy() != size {
					t.Fatalf("piece PNG dimensions should match piece_size: bounds=%+v size=%d", piece.Bounds(), size)
				}
			}
		})
	}
}

func TestRotateChallengeDoesNotExposeAnswerEquivalentInitialAngle(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	session, err := e.NewSession("app_test", "login", types.CaptchaRotate)
	if err != nil {
		t.Fatalf("new rotate session: %v", err)
	}
	if _, ok := session.RenderPayload.Parameters["initial_angle"]; ok {
		t.Fatalf("rotate challenge must not expose answer-equivalent initial_angle: %+v", session.RenderPayload.Parameters)
	}
	visualAnswer := inferRotateAnswerFromImage(t, decodePNGDataURL(t, session.RenderPayload.Image))
	if angleDiff(visualAnswer, session.Answer.Angle) > 4 {
		t.Fatalf("rotate image should encode the server answer visually, visual=%d answer=%d", visualAnswer, session.Answer.Angle)
	}
}

func TestConcatChallengeUsesOneMovingHorizontalLayer(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	session, err := e.NewSession("app_test", "login", types.CaptchaConcat)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}

	pieceWidth := intParam(t, session.RenderPayload.Parameters, "piece_width")
	if pieceWidth != session.RenderPayload.View.Width+concatMaxMovement {
		t.Fatalf("concat moving layer should span the full view width: piece=%d view=%+v", pieceWidth, session.RenderPayload.View)
	}
	splitY := intParam(t, session.RenderPayload.Parameters, "split_y")
	if splitY <= 0 || splitY >= session.RenderPayload.View.Height {
		t.Fatalf("concat restore split_y should divide moving and static layers: split=%d view=%+v", splitY, session.RenderPayload.View)
	}
	if _, ok := session.RenderPayload.Parameters["split_x"]; ok {
		t.Fatalf("concat restore should not expose legacy vertical split_x: %+v", session.RenderPayload.Parameters)
	}
	if _, ok := session.RenderPayload.Parameters["initial_offset"]; ok {
		t.Fatalf("concat restore should not expose answer-equivalent initial_offset: %+v", session.RenderPayload.Parameters)
	}
	if got := intParam(t, session.RenderPayload.Parameters, "max"); got != concatMaxMovement {
		t.Fatalf("concat max should be fixed and not answer-derived: max=%d answer=%d", got, session.Answer.Offset)
	}
	piece := decodePNGDataURL(t, session.RenderPayload.Piece)
	if piece.Bounds().Dx() != pieceWidth || piece.Bounds().Dy() != session.RenderPayload.View.Height {
		t.Fatalf("unexpected concat piece bounds: got %s want %dx%d", piece.Bounds(), pieceWidth, session.RenderPayload.View.Height)
	}
	background := decodePNGDataURL(t, session.RenderPayload.Image)
	for _, point := range []image.Point{
		{X: session.RenderPayload.View.Width / 2, Y: max(0, splitY-1)},
		{X: session.RenderPayload.View.Width / 2, Y: splitY},
		{X: session.RenderPayload.View.Width / 2, Y: min(session.RenderPayload.View.Height-1, splitY+1)},
	} {
		if alphaAt(t, background, point.X, point.Y) < 250 {
			t.Fatalf("concat background should not expose a transparent gap at %+v", point)
		}
	}
	if alphaAt(t, piece, pieceWidth/2, max(0, splitY-18)) == 0 {
		t.Fatal("expected concat moving piece to contain opaque pixels above the split")
	}
	if alphaAt(t, piece, pieceWidth/2, session.RenderPayload.View.Height-2) != 0 {
		t.Fatal("expected concat moving piece bottom to stay transparent")
	}
	minEdge, maxEdge := pieceAlphaEdgeRange(t, piece)
	if maxEdge-minEdge > 1 {
		t.Fatalf("expected concat moving piece to use a straight horizontal split, edge range=%d..%d", minEdge, maxEdge)
	}
}

func TestGestureChallengesAreDynamicAndRejectStraightLines(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	first, err := e.NewSession("app_test", "verify", types.CaptchaGesture)
	if err != nil {
		t.Fatalf("new first gesture session: %v", err)
	}
	var changed bool
	for i := 0; i < 8; i++ {
		next, err := e.NewSession("app_test", "verify", types.CaptchaGesture)
		if err != nil {
			t.Fatalf("new gesture session: %v", err)
		}
		if !samePoints(first.Answer.Points, next.Answer.Points) {
			changed = true
			break
		}
	}
	if !changed {
		t.Fatalf("expected gesture path to vary across refreshes, got %v", first.Answer.Points)
	}

	straight := straightLinePoints(
		first.Answer.Points[0],
		first.Answer.Points[len(first.Answer.Points)-1],
		len(first.Answer.Points)+3,
	)
	result := e.Verify(first, types.VerifyAnswer{Points: straight}, normalTrack())
	if result.OK || result.ReasonCode != "ANSWER_MISMATCH" {
		t.Fatalf("expected straight gesture shortcut to fail, got %+v", result)
	}

	result = e.Verify(first, types.VerifyAnswer{Points: first.Answer.Points}, normalTrack())
	if !result.OK {
		t.Fatalf("expected correct gesture path to pass, got %+v", result)
	}
}

func TestGestureChallengesUseDifferentPathFamilies(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	signatures := make(map[string]struct{})
	for i := 0; i < 24; i++ {
		session, err := e.NewSession("app_test", "verify", types.CaptchaGesture)
		if err != nil {
			t.Fatalf("new gesture session: %v", err)
		}
		signatures[gesturePathSignature(session.Answer.Points)] = struct{}{}
	}
	if len(signatures) < 4 {
		t.Fatalf("expected gesture challenges to use multiple path families, got %d signatures: %+v", len(signatures), signatures)
	}
}

func TestGestureRefreshAvoidsSamePathFamily(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	session, err := e.NewSession("app_test", "verify", types.CaptchaGesture)
	if err != nil {
		t.Fatalf("new gesture session: %v", err)
	}
	if session.Answer.Token == "" {
		t.Fatal("expected gesture answer to store server-side path family")
	}
	for i := 0; i < 12; i++ {
		previous := session.Answer.Token
		session, err = e.Refresh(session)
		if err != nil {
			t.Fatalf("refresh gesture session: %v", err)
		}
		if session.Answer.Token == previous {
			t.Fatalf("expected refresh to avoid same gesture path family %q", previous)
		}
	}
}

func TestGestureSameFamilyStillVaries(t *testing.T) {
	t.Parallel()

	families := map[string]func() []types.Point{
		"soft_wave": gestureSoftWavePath,
		"arch":      gestureArchPath,
		"s_curve":   gestureSCurvePath,
		"soft_hook": gestureSoftHookPath,
		"open_loop": gestureOpenLoopPath,
		"lazy_loop": gestureLazyLoopPath,
	}
	for name, generate := range families {
		name := name
		generate := generate
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			signatures := make(map[string]struct{})
			for i := 0; i < 8; i++ {
				signatures[gestureGeometrySignature(jitterGesturePath(generate()))] = struct{}{}
			}
			if len(signatures) < 2 {
				t.Fatalf("expected gesture family %s to vary internally, got signatures %+v", name, signatures)
			}
		})
	}
}

func TestGestureDrawableCurvesPassAndStraightShortcutsFail(t *testing.T) {
	t.Parallel()

	families := map[string]func() []types.Point{
		"soft_wave": gestureSoftWavePath,
		"arch":      gestureArchPath,
		"s_curve":   gestureSCurvePath,
		"soft_hook": gestureSoftHookPath,
		"open_loop": gestureOpenLoopPath,
		"lazy_loop": gestureLazyLoopPath,
	}
	for name, generate := range families {
		name := name
		generate := generate
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			expected := jitterGesturePath(generate())
			drawn := approximateDrawableGesturePath(expected)
			if ok, reason := verifyGesturePathSequence(expected, drawn, 14); !ok {
				t.Fatalf("expected drawable %s gesture curve to pass, reason=%s expected=%v drawn=%v", name, reason, expected, drawn)
			}
			straight := straightLinePoints(expected[0], expected[len(expected)-1], len(drawn))
			if ok, reason := verifyGesturePathSequence(expected, straight, 14); ok || reason != "ANSWER_MISMATCH" {
				t.Fatalf("expected straight %s gesture shortcut to fail, ok=%v reason=%s expected=%v straight=%v", name, ok, reason, expected, straight)
			}
		})
	}
}

func TestCurveChallengesAreSlidingMatchWithoutNakedAnswerFields(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	for _, captchaType := range []types.CaptchaType{
		types.CaptchaCurve,
		types.CaptchaCurve2,
		types.CaptchaCurve3,
	} {
		captchaType := captchaType
		t.Run(string(captchaType), func(t *testing.T) {
			t.Parallel()

			first, err := e.NewSession("app_test", "verify", captchaType)
			if err != nil {
				t.Fatalf("new first curve session: %v", err)
			}
			if _, ok := first.RenderPayload.Parameters["curve_path"]; ok {
				t.Fatalf("curve_path must not be exposed in render parameters: %+v", first.RenderPayload.Parameters)
			}
			for _, forbidden := range []string{"curve_start", "curve_end", "target_x", "answer_x", "split_x", "initial_offset", "piece_width"} {
				if _, ok := first.RenderPayload.Parameters[forbidden]; ok {
					t.Fatalf("%s must not be exposed in render parameters: %+v", forbidden, first.RenderPayload.Parameters)
				}
			}
			if first.RenderPayload.Piece != "" {
				t.Fatal("curve match challenge should render with canvas profile, not a movable image piece")
			}
			profile, ok := first.RenderPayload.Parameters["curve_profile"].(map[string]any)
			if !ok {
				t.Fatalf("expected curve_profile parameter, got %+v", first.RenderPayload.Parameters)
			}
			if _, ok := profile["fixed_points"]; ok {
				t.Fatalf("curve profile must not expose target curve points: %+v", profile)
			}
			moving, ok := profile["moving_points"].([]curveRenderPoint)
			if !ok || len(moving) < 12 {
				t.Fatalf("expected moving curve points for canvas rendering, got %+v", profile["moving_points"])
			}
			drives, ok := profile["drive_points"].([]curveDrivePoint)
			if !ok || len(drives) < 12 {
				t.Fatalf("expected curve drive points for canvas rendering, got %+v", profile["drive_points"])
			}
			if len(moving) != len(drives) {
				t.Fatalf("curve profile lengths should match: moving=%d drives=%d", len(moving), len(drives))
			}
			targetPoints := fixedCurvePointsFromProfile(moving, drives, first.Answer.X)
			targetHits := curveTargetGhostHits(decodePNGDataURL(t, first.RenderPayload.Image), captchaType, targetPoints)
			if targetHits < max(8, len(targetPoints)*3/4) {
				t.Fatalf("curve target ghost should be rendered into backend PNG, hits=%d points=%d type=%s", targetHits, len(targetPoints), captchaType)
			}
			if captchaType == types.CaptchaCurve3 && math.Hypot(moving[0].X-moving[len(moving)-1].X, moving[0].Y-moving[len(moving)-1].Y) > 1 {
				t.Fatalf("curve v3 should use a closed ring path, first=%+v last=%+v", moving[0], moving[len(moving)-1])
			}
			averageOffset, maxOffset := curveDriveOffsetStats(drives, first.Answer.X)
			if averageOffset < 22 || maxOffset < 34 {
				t.Fatalf("expected visible initial curve separation, average=%.2f max=%.2f profile=%+v", averageOffset, maxOffset, profile)
			}
			mode, ok := profile["endpoint_mode"].(string)
			if !ok || mode == "" {
				t.Fatalf("expected curve endpoint mode, got %+v", profile["endpoint_mode"])
			}
			if mode != "hidden" {
				t.Fatalf("curve target endpoints are rendered in PNG and should not be exposed as DOM positions, got %q", mode)
			}
			if style, ok := profile["visual_style"].(string); !ok || style != expectedCurveVisualStyle(captchaType) {
				t.Fatalf("expected curve visual style %q, got %+v", expectedCurveVisualStyle(captchaType), profile["visual_style"])
			}
			if intParam(t, first.RenderPayload.Parameters, "max") < first.Answer.X {
				t.Fatalf("curve max should allow reaching answer: params=%+v answer=%+v", first.RenderPayload.Parameters, first.Answer)
			}
			if len(first.Answer.Points) != 0 {
				t.Fatalf("curve match should not use path answer points, got %+v", first.Answer.Points)
			}

			var changed bool
			var profileChanged bool
			firstProfileSignature := fmt.Sprintf("%+v", first.RenderPayload.Parameters["curve_profile"])
			for i := 0; i < 8; i++ {
				next, err := e.NewSession("app_test", "verify", captchaType)
				if err != nil {
					t.Fatalf("new curve session: %v", err)
				}
				if first.Answer.X != next.Answer.X {
					changed = true
				}
				if fmt.Sprintf("%+v", next.RenderPayload.Parameters["curve_profile"]) != firstProfileSignature {
					profileChanged = true
				}
				if changed && profileChanged {
					break
				}
			}
			if !changed {
				t.Fatalf("expected %s match target to vary across refreshes, got %+v", captchaType, first.Answer)
			}
			if !profileChanged {
				t.Fatalf("expected %s curve profile to vary across refreshes", captchaType)
			}
		})
	}
}

func TestCurveChallengesVerifyMatchOffset(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	for _, captchaType := range []types.CaptchaType{
		types.CaptchaCurve,
		types.CaptchaCurve2,
		types.CaptchaCurve3,
	} {
		captchaType := captchaType
		t.Run(string(captchaType), func(t *testing.T) {
			t.Parallel()

			session, err := e.NewSession("app_test", "verify", captchaType)
			if err != nil {
				t.Fatalf("new curve session: %v", err)
			}
			result := e.Verify(session, types.VerifyAnswer{Points: []types.Point{{X: session.Answer.X, Y: 80}}}, normalTrack())
			if result.OK || result.ReasonCode != "ANSWER_MISSING" {
				t.Fatalf("expected path-style curve answer to fail, got %+v", result)
			}

			wrong := session.Answer.X + 24
			if wrong > intParam(t, session.RenderPayload.Parameters, "max") {
				wrong = session.Answer.X - 24
			}
			result = e.Verify(session, types.VerifyAnswer{X: &wrong}, trackFromSliderValue(wrong))
			if result.OK || result.ReasonCode != "ANSWER_MISMATCH" {
				t.Fatalf("expected wrong curve match offset to fail, got %+v", result)
			}

			near := session.Answer.X + 14
			if near > intParam(t, session.RenderPayload.Parameters, "max") {
				near = session.Answer.X - 14
			}
			result = e.Verify(session, types.VerifyAnswer{X: &near}, trackFromSliderValue(near))
			if !result.OK {
				t.Fatalf("expected near-overlap curve match offset to pass, got %+v", result)
			}

			result = e.Verify(session, types.VerifyAnswer{X: &session.Answer.X}, trackFromSliderValue(session.Answer.X))
			if !result.OK {
				t.Fatalf("expected correct curve match offset to pass, got %+v", result)
			}
		})
	}
}

func TestCurveChallengesRejectAnswerTrackMismatch(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	for _, captchaType := range []types.CaptchaType{
		types.CaptchaCurve,
		types.CaptchaCurve2,
		types.CaptchaCurve3,
	} {
		captchaType := captchaType
		t.Run(string(captchaType), func(t *testing.T) {
			t.Parallel()

			session, err := e.NewSession("app_test", "verify", captchaType)
			if err != nil {
				t.Fatalf("new curve session: %v", err)
			}
			result := e.Verify(session, types.VerifyAnswer{X: &session.Answer.X}, trackFromSliderValue(max(0, session.Answer.X-48)))
			if result.OK || result.ReasonCode != "TRACK_ANSWER_MISMATCH" {
				t.Fatalf("expected mismatched answer and track to fail, got %+v", result)
			}
		})
	}
}

func TestJigsawAcceptsClicksInsideSwappedTiles(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	session, err := e.NewSession("app_test", "verify", types.CaptchaJigsaw)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}

	tileWidth := intParam(t, session.RenderPayload.Parameters, "tile_width")
	tileHeight := intParam(t, session.RenderPayload.Parameters, "tile_height")
	if tileWidth != jigsawTileWidth || tileHeight != jigsawTileHeight {
		t.Fatalf("unexpected jigsaw tile size: %dx%d", tileWidth, tileHeight)
	}
	if len(session.Answer.Points) != 2 {
		t.Fatalf("expected two swapped jigsaw tiles, got %v", session.Answer.Points)
	}
	insideTileCorners := types.VerifyAnswer{Points: []types.Point{
		{X: session.Answer.Points[0].X + tileWidth/2 - 3, Y: session.Answer.Points[0].Y},
		{X: session.Answer.Points[1].X - tileWidth/2 + 3, Y: session.Answer.Points[1].Y},
	}}
	result := e.Verify(session, insideTileCorners, normalTrack())
	if !result.OK {
		t.Fatalf("expected clicks inside swapped jigsaw tiles to pass, got %+v", result)
	}

	wrongTiles := types.VerifyAnswer{Points: jigsawWrongTilePoints(session.Answer.Points)}
	result = e.Verify(session, wrongTiles, normalTrack())
	if result.OK || result.ReasonCode != "ANSWER_MISMATCH" {
		t.Fatalf("expected wrong jigsaw tiles to fail, got %+v", result)
	}
}

func TestJigsawSwapTilesAreDynamic(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	first, err := e.NewSession("app_test", "verify", types.CaptchaJigsaw)
	if err != nil {
		t.Fatalf("new first jigsaw session: %v", err)
	}
	var changed bool
	for i := 0; i < 12; i++ {
		next, err := e.NewSession("app_test", "verify", types.CaptchaJigsaw)
		if err != nil {
			t.Fatalf("new jigsaw session: %v", err)
		}
		if !samePoints(first.Answer.Points, next.Answer.Points) {
			changed = true
			break
		}
	}
	if !changed {
		t.Fatalf("expected jigsaw swapped tiles to vary across refreshes, got %v", first.Answer.Points)
	}
}

func TestGridImageClickAcceptsUnorderedTargetTiles(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	session, err := e.NewSession("app_test", "verify", types.CaptchaGridImageClick)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	if len(session.Answer.Points) != 3 {
		t.Fatalf("expected three grid targets, got %v", session.Answer.Points)
	}
	reversed := []types.Point{
		session.Answer.Points[2],
		session.Answer.Points[1],
		session.Answer.Points[0],
	}
	result := e.Verify(session, types.VerifyAnswer{Points: reversed}, normalTrack())
	if !result.OK {
		t.Fatalf("expected unordered grid target clicks to pass, got %+v", result)
	}

	wrong := gridWrongTilePoints(session.Answer.Points)
	result = e.Verify(session, types.VerifyAnswer{Points: wrong}, normalTrack())
	if result.OK || result.ReasonCode != "ANSWER_MISMATCH" {
		t.Fatalf("expected wrong grid tiles to fail, got %+v", result)
	}

	missing := types.VerifyAnswer{Points: session.Answer.Points[:len(session.Answer.Points)-1]}
	result = e.Verify(session, missing, normalTrack())
	if result.OK || result.ReasonCode != "ANSWER_MISSING" {
		t.Fatalf("expected missing grid tile to fail, got %+v", result)
	}
}

func TestPointClickCaptchasUseSeparatedTargets(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	for _, captchaType := range []types.CaptchaType{
		types.CaptchaWordImageClick,
		types.CaptchaImageClick,
		types.CaptchaGridImageClick,
	} {
		captchaType := captchaType
		t.Run(string(captchaType), func(t *testing.T) {
			t.Parallel()

			for i := 0; i < 80; i++ {
				session, err := e.NewSession("app_test", "register", captchaType)
				if err != nil {
					t.Fatalf("new session: %v", err)
				}
				points := session.Answer.Points
				if len(points) != len(session.RenderPayload.Words) {
					t.Fatalf("answer points should match target count: points=%d words=%d", len(points), len(session.RenderPayload.Words))
				}
				assertReadableTargets(t, session.RenderPayload.View, points)
			}
		})
	}
}

func TestCaptchaIconSVGAssetsAreEmbeddedAndFiltered(t *testing.T) {
	t.Parallel()

	for _, icon := range iconClickLibrary {
		if strings.HasPrefix(icon.ID, "pintu") || icon.ID == "huiliuqujinkoushipin" {
			t.Fatalf("image click library must exclude slider-only svg icon %q", icon.ID)
		}
		assertEmbeddedSVGMask(t, icon.SVGFile(), 42, 90)
	}
	assertEmbeddedSVGMask(t, string(sliderMaskPuzzle), sliderPieceSize, 360)
	assertEmbeddedSVGMask(t, string(sliderMaskPlane), sliderPieceSize, 140)
}

func TestSyntheticConstantLineTrackIsRejected(t *testing.T) {
	t.Parallel()

	e := New(2 * time.Minute)
	session, err := e.NewSession("app_test", "login", types.CaptchaSlider)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	track := make([]types.TrackPoint, 0, 10)
	for i := 0; i < 10; i++ {
		pointType := "move"
		if i == 0 {
			pointType = "start"
		}
		if i == 9 {
			pointType = "end"
		}
		track = append(track, types.TrackPoint{
			X:    float64(i) * float64(session.Answer.X) / 9,
			Y:    20,
			T:    int64(i * 100),
			Type: pointType,
		})
	}

	result := e.Verify(session, answerFor(session), track)
	if result.OK {
		t.Fatal("expected synthetic constant line track to be rejected")
	}
	if result.Decision != types.DecisionChallengeHarder || result.ReasonCode != "TRACK_CHALLENGE_HARDER" {
		t.Fatalf("unexpected challenge escalation result: %+v", result)
	}
	if !containsReason(result.TrackScore.Reasons, "TRACK_SYNTHETIC_CURVE") {
		t.Fatalf("expected synthetic reason, got %+v", result.TrackScore)
	}
}

func TestExtractTrackFeatures(t *testing.T) {
	t.Parallel()

	features := ExtractTrackFeatures(normalTrack())
	if features["point_count"] != 5 {
		t.Fatalf("expected point_count 5, got %+v", features["point_count"])
	}
	if features["path_length"].(float64) <= 0 {
		t.Fatalf("expected path_length feature, got %+v", features)
	}
	if _, ok := features["velocity_variance"]; !ok {
		t.Fatalf("expected velocity_variance feature, got %+v", features)
	}
	if features["timestamp_anomaly"].(bool) {
		t.Fatalf("normal track should not have timestamp anomaly: %+v", features)
	}
}

func TestPreGeneratedChallengePool(t *testing.T) {
	t.Parallel()

	e := NewWithOptions(2*time.Minute, Options{PreGenerateSize: 2})
	if err := e.WarmPreGeneration(); err != nil {
		t.Fatalf("warm pre-generation: %v", err)
	}
	depths := e.PreGenerationDepths()
	if depths[types.CaptchaSlider] != 2 {
		t.Fatalf("expected slider pool depth 2, got %+v", depths)
	}

	session, err := e.NewSession("app_test", "login", types.CaptchaSlider)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	depths = e.PreGenerationDepths()
	if depths[types.CaptchaSlider] != 1 {
		t.Fatalf("expected slider pool depth 1 after take, got %+v", depths)
	}
	result := e.Verify(session, answerFor(session), normalTrack())
	if !result.OK {
		t.Fatalf("expected pre-generated challenge to verify, got %+v", result)
	}
}

func answerFor(session types.ChallengeSession) types.VerifyAnswer {
	switch session.Type {
	case types.CaptchaProofOfWork:
		nonce := solveProofOfWorkForTest(session.Answer.Token, session.Answer.Offset, session.Answer.Y)
		return types.VerifyAnswer{X: &nonce}
	case types.CaptchaGesture:
		return types.VerifyAnswer{Points: session.Answer.Points}
	case types.CaptchaCurve, types.CaptchaCurve2, types.CaptchaCurve3:
		return types.VerifyAnswer{X: &session.Answer.X}
	case types.CaptchaSlider, types.CaptchaSlider2:
		return types.VerifyAnswer{X: &session.Answer.X}
	case types.CaptchaRotate:
		return types.VerifyAnswer{Angle: &session.Answer.Angle}
	case types.CaptchaRotateDegree:
		return types.VerifyAnswer{Angle: &session.Answer.Angle}
	case types.CaptchaConcat:
		return types.VerifyAnswer{Offset: &session.Answer.Offset}
	case types.CaptchaWordImageClick, types.CaptchaImageClick, types.CaptchaJigsaw, types.CaptchaGridImageClick:
		return types.VerifyAnswer{Points: session.Answer.Points}
	default:
		return types.VerifyAnswer{}
	}
}

func samePoints(a, b []types.Point) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func straightLinePoints(start, end types.Point, count int) []types.Point {
	if count < 2 {
		count = 2
	}
	points := make([]types.Point, 0, count)
	for i := 0; i < count; i++ {
		t := float64(i) / float64(count-1)
		points = append(points, types.Point{
			X: int(math.Round(float64(start.X) + float64(end.X-start.X)*t)),
			Y: int(math.Round(float64(start.Y) + float64(end.Y-start.Y)*t)),
		})
	}
	return points
}

func trackForSession(session types.ChallengeSession) []types.TrackPoint {
	if isCurveCaptchaType(session.Type) {
		return trackFromSliderValue(session.Answer.X)
	}
	return normalTrack()
}

func trackFromSliderValue(value int) []types.TrackPoint {
	return []types.TrackPoint{
		{X: 0, Y: 20, T: 0, Type: "start"},
		{X: float64(max(8, value/4)), Y: 23, T: 150, Type: "move"},
		{X: float64(max(12, value/2)), Y: 18, T: 320, Type: "move"},
		{X: float64(max(16, (value*3)/4)), Y: 21, T: 520, Type: "move"},
		{X: float64(value), Y: 20, T: 760, Type: "end"},
	}
}

func trackFromPoints(points []types.Point) []types.TrackPoint {
	track := make([]types.TrackPoint, 0, len(points))
	timestamp := int64(0)
	for i, point := range points {
		pointType := "move"
		if i == 0 {
			pointType = "start"
		}
		if i == len(points)-1 {
			pointType = "end"
		}
		if i > 0 {
			timestamp += int64(70 + (i%5)*17)
		}
		track = append(track, types.TrackPoint{
			X:    float64(point.X),
			Y:    float64(point.Y),
			T:    timestamp,
			Type: pointType,
		})
	}
	return track
}

func approximateDrawableGesturePath(expected []types.Point) []types.Point {
	points := resamplePath(expected, 22)
	if len(points) < 3 {
		return points
	}
	drawn := make([]types.Point, 0, len(points))
	for i, point := range points {
		if i == 0 || i == len(points)-1 {
			drawn = append(drawn, point)
			continue
		}
		previous := points[i-1]
		next := points[i+1]
		dx := float64(next.X - previous.X)
		dy := float64(next.Y - previous.Y)
		length := math.Hypot(dx, dy)
		normalX, normalY := 0.0, 0.0
		if length > 0 {
			normalX = -dy / length
			normalY = dx / length
		}
		t := float64(i) / float64(len(points)-1)
		wobble := math.Sin(t*math.Pi*2.7)*5 + math.Cos(t*math.Pi*5.1)*2
		drawn = append(drawn, types.Point{
			X: clampInt(int(math.Round(float64(point.X)+normalX*wobble)), 20, 300),
			Y: clampInt(int(math.Round(float64(point.Y)+normalY*wobble)), 20, 140),
		})
	}
	return drawn
}

func gesturePathSignature(points []types.Point) string {
	if len(points) < 3 {
		return "short"
	}
	verticalTurns := 0
	horizontalTurns := 0
	backtracks := 0
	prevDY := 0
	prevDX := 0
	for i := 1; i < len(points); i++ {
		dx := points[i].X - points[i-1].X
		dy := points[i].Y - points[i-1].Y
		if dx < -6 {
			backtracks++
		}
		if abs(dx) > 6 {
			sign := 1
			if dx < 0 {
				sign = -1
			}
			if prevDX != 0 && sign != prevDX {
				horizontalTurns++
			}
			prevDX = sign
		}
		if abs(dy) > 6 {
			sign := 1
			if dy < 0 {
				sign = -1
			}
			if prevDY != 0 && sign != prevDY {
				verticalTurns++
			}
			prevDY = sign
		}
	}
	spanX := 0
	spanY := 0
	minX, maxX := points[0].X, points[0].X
	minY, maxY := points[0].Y, points[0].Y
	for _, point := range points {
		minX = min(minX, point.X)
		maxX = max(maxX, point.X)
		minY = min(minY, point.Y)
		maxY = max(maxY, point.Y)
	}
	spanX = (maxX - minX) / 32
	spanY = (maxY - minY) / 24
	return fmt.Sprintf("n%d-v%d-h%d-b%d-x%d-y%d", len(points)/8, verticalTurns, horizontalTurns, backtracks, spanX, spanY)
}

func gestureGeometrySignature(points []types.Point) string {
	if len(points) < 2 {
		return "short"
	}
	parts := make([]string, 0, 7)
	for i := 0; i < 7; i++ {
		index := int(math.Round(float64(i) * float64(len(points)-1) / 6))
		point := points[index]
		parts = append(parts, fmt.Sprintf("%d:%d", point.X/12, point.Y/10))
	}
	return strings.Join(parts, "|")
}

func curveDriveOffsetStats(drives []curveDrivePoint, scale int) (float64, float64) {
	if len(drives) == 0 {
		return 0, 0
	}
	total := 0.0
	maximum := 0.0
	count := 0
	for index := 1; index < len(drives)-1; index++ {
		distance := math.Hypot(drives[index].X*float64(scale), drives[index].Y*float64(scale))
		total += distance
		maximum = math.Max(maximum, distance)
		count++
	}
	if count == 0 {
		return 0, maximum
	}
	return total / float64(count), maximum
}

func expectedCurveVisualStyle(captchaType types.CaptchaType) string {
	switch captchaType {
	case types.CaptchaCurve2:
		return "dual-noise"
	case types.CaptchaCurve3:
		return "ring-deform"
	default:
		return "single-rope"
	}
}

func curveTargetGhostHits(img image.Image, captchaType types.CaptchaType, points []types.Point) int {
	hits := 0
	bounds := img.Bounds()
	for _, point := range points {
		found := false
		for dy := -4; dy <= 4 && !found; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x := point.X + dx
				y := point.Y + dy
				if x < bounds.Min.X || x >= bounds.Max.X || y < bounds.Min.Y || y >= bounds.Max.Y {
					continue
				}
				if curveTargetGhostPixel(rgbaAt(img, x, y), captchaType) {
					found = true
					break
				}
			}
		}
		if found {
			hits++
		}
	}
	return hits
}

func fixedCurvePointsFromProfile(moving []curveRenderPoint, drives []curveDrivePoint, targetX int) []types.Point {
	points := make([]types.Point, 0, min(len(moving), len(drives)))
	for i := 0; i < len(moving) && i < len(drives); i++ {
		points = append(points, types.Point{
			X: int(math.Round(moving[i].X - drives[i].X*float64(targetX))),
			Y: int(math.Round(moving[i].Y - drives[i].Y*float64(targetX))),
		})
	}
	return points
}

func curveTargetGhostPixel(c color.RGBA, captchaType types.CaptchaType) bool {
	if c.A < 180 {
		return false
	}
	switch captchaType {
	case types.CaptchaCurve2:
		return (c.R > 230 && c.G >= 55 && c.G <= 130 && c.B >= 145 && c.B <= 220) ||
			(c.R >= 170 && c.R <= 215 && c.G >= 105 && c.G <= 155 && c.B > 225)
	case types.CaptchaCurve3:
		return c.R >= 238 && c.G >= 90 && c.G <= 140 && c.B >= 90 && c.B <= 130
	default:
		return c.R >= 95 && c.R <= 150 && c.G >= 185 && c.B >= 225
	}
}

func inferRotateAnswerFromImage(t *testing.T, img image.Image) int {
	t.Helper()
	bounds := img.Bounds()
	observed := make([]bool, bounds.Dx()*bounds.Dy())
	observedCount := 0
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			if rotateBluePixel(rgbaAt(img, x, y)) {
				observed[(y-bounds.Min.Y)*bounds.Dx()+x-bounds.Min.X] = true
				observedCount++
			}
		}
	}
	if observedCount < 400 {
		t.Fatalf("expected enough blue rotate pixels, got %d", observedCount)
	}
	bestStart := 0
	bestMismatch := int(^uint(0) >> 1)
	for candidate := 0; candidate < 360; candidate++ {
		model := drawRotateImage(candidate, bounds.Dx())
		mismatch := 0
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				index := (y-bounds.Min.Y)*bounds.Dx() + x - bounds.Min.X
				if observed[index] != rotateBluePixel(rgbaAt(model, x, y)) {
					mismatch++
				}
			}
		}
		if mismatch < bestMismatch {
			bestMismatch = mismatch
			bestStart = candidate
		}
	}
	return (360 - bestStart) % 360
}

func rotateBluePixel(c color.RGBA) bool {
	return c.A > 180 && c.B > 160 && c.G > 60 && c.G < 150 && c.R < 90 && int(c.B)-int(c.R) > 100
}

func jigsawWrongTilePoints(answer []types.Point) []types.Point {
	points := make([]types.Point, 0, 2)
	for index := 0; index < jigsawTileCols*jigsawTileRows && len(points) < 2; index++ {
		candidate := jigsawTileCenter(index)
		matchesAnswer := false
		for _, point := range answer {
			if pointInTile(candidate, point, jigsawTileWidth, jigsawTileHeight) {
				matchesAnswer = true
				break
			}
		}
		if !matchesAnswer {
			points = append(points, candidate)
		}
	}
	return points
}

func gridWrongTilePoints(answer []types.Point) []types.Point {
	points := make([]types.Point, 0, len(answer))
	for index := 0; index < gridImageCols*gridImageRows && len(points) < len(answer); index++ {
		candidate := gridImageTileCenter(index)
		matchesAnswer := false
		for _, point := range answer {
			if pointInTile(candidate, point, gridImageTileSize, gridImageTileSize) {
				matchesAnswer = true
				break
			}
		}
		if !matchesAnswer {
			points = append(points, candidate)
		}
	}
	return points
}

func solveProofOfWorkForTest(seed string, difficulty, maxNonce int) int {
	for nonce := 0; nonce <= maxNonce; nonce++ {
		if verifyProofOfWork(seed, nonce, difficulty, maxNonce) {
			return nonce
		}
	}
	return -1
}

func normalTrack() []types.TrackPoint {
	return []types.TrackPoint{
		{X: 0, Y: 20, T: 0, Type: "start"},
		{X: 38, Y: 22, T: 180, Type: "move"},
		{X: 91, Y: 19, T: 360, Type: "move"},
		{X: 154, Y: 23, T: 540, Type: "move"},
		{X: 202, Y: 21, T: 720, Type: "end"},
	}
}

func containsReason(reasons []string, expected string) bool {
	for _, reason := range reasons {
		if reason == expected {
			return true
		}
	}
	return false
}

func assertPNGDataURL(t *testing.T, value string) {
	t.Helper()
	if !strings.HasPrefix(value, "data:image/png;base64,") {
		t.Fatalf("expected PNG data URL, got %q", value[:min(len(value), 32)])
	}
}

func decodePNGDataURL(t *testing.T, value string) image.Image {
	t.Helper()
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(value, prefix) {
		t.Fatalf("expected PNG data URL, got %q", value[:min(len(value), 32)])
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil {
		t.Fatalf("decode PNG data URL: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode PNG: %v", err)
	}
	return img
}

func alphaAt(t *testing.T, img image.Image, x, y int) uint8 {
	t.Helper()
	_, _, _, a := img.At(x, y).RGBA()
	return uint8(a >> 8)
}

func assertEmbeddedSVGMask(t *testing.T, filename string, size, minOpaque int) {
	t.Helper()
	data, err := captchaIconAssets.ReadFile("assets/icons/" + filename)
	if err != nil {
		t.Fatalf("read embedded svg %s: %v", filename, err)
	}
	if !bytes.Contains(data, []byte("<svg")) || !bytes.Contains(data, []byte("<path")) {
		t.Fatalf("embedded icon %s should be svg path data", filename)
	}
	mask := svgIconMask(filename, size)
	opaque := 0
	bounds := mask.Bounds()
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			if alphaAt(t, mask, x, y) > 35 {
				opaque++
			}
		}
	}
	if opaque < minOpaque {
		t.Fatalf("embedded svg %s rendered too few opaque pixels: %d < %d", filename, opaque, minOpaque)
	}
}

func pieceAlphaEdgeRange(t *testing.T, img image.Image) (int, int) {
	t.Helper()
	bounds := img.Bounds()
	minEdge := bounds.Dy()
	maxEdge := 0
	for x := bounds.Min.X; x < bounds.Max.X; x += 11 {
		edge := bounds.Dy()
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			if alphaAt(t, img, x, y) == 0 {
				edge = y
				break
			}
		}
		minEdge = min(minEdge, edge)
		maxEdge = max(maxEdge, edge)
	}
	return minEdge, maxEdge
}

func intParam(t *testing.T, parameters map[string]any, key string) int {
	t.Helper()
	value, ok := parameters[key]
	if !ok {
		t.Fatalf("missing parameter %s in %+v", key, parameters)
	}
	number, ok := value.(int)
	if !ok {
		t.Fatalf("parameter %s should be int, got %T", key, value)
	}
	return number
}

func pointParam(t *testing.T, parameters map[string]any, key string) types.Point {
	t.Helper()
	value, ok := parameters[key]
	if !ok {
		t.Fatalf("missing parameter %s in %+v", key, parameters)
	}
	point, ok := value.(types.Point)
	if !ok {
		t.Fatalf("parameter %s should be types.Point, got %T", key, value)
	}
	return point
}

func assertReadableTargets(t *testing.T, view types.View, points []types.Point) {
	t.Helper()
	margin := wordClickTolerance + 6
	for i, point := range points {
		if point.X < margin || point.X > view.Width-margin || point.Y < margin || point.Y > view.Height-margin {
			t.Fatalf("target %d is too close to the edge: point=%+v view=%+v", i, point, view)
		}
		for j := i + 1; j < len(points); j++ {
			if distance(point, points[j]) < float64(wordClickTolerance*2+12) {
				t.Fatalf("targets are too close: %d=%+v %d=%+v", i, point, j, points[j])
			}
		}
	}
}

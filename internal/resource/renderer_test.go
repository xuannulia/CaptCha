package resource

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"captcha/internal/types"
)

func TestApplyVisualsUsesLocalFileBackground(t *testing.T) {
	t.Parallel()

	background := color.RGBA{R: 12, G: 180, B: 90, A: 255}
	path, checksum := writeTestPNG(t, 40, 30, background)
	payload := types.RenderPayload{
		Type:       types.CaptchaSlider,
		View:       types.View{Width: 120, Height: 80},
		Image:      "fallback-image",
		Piece:      "fallback-piece",
		Parameters: map[string]any{"piece_size": 48},
	}

	composed := ApplyVisuals(payload, types.Answer{X: 60, Y: 20}, []types.CaptchaResource{
		{
			ID:           "res_local_background",
			ResourceType: "background_image",
			StorageType:  "file",
			URI:          path,
			Checksum:     checksum,
			Status:       "active",
		},
	})

	if composed.Image == payload.Image || composed.Piece == payload.Piece {
		t.Fatalf("expected local resource to replace generated image and piece")
	}
	image := decodePNGDataURL(t, composed.Image)
	assertPixel(t, image, 5, 5, background)
	piece := decodePNGDataURL(t, composed.Piece)
	if piece.Bounds().Dx() != 48 || piece.Bounds().Dy() != 48 {
		t.Fatalf("expected slider piece size 48x48, got %s", piece.Bounds())
	}
}

func TestApplyVisualsUsesRemoteURLBackground(t *testing.T) {
	background := color.RGBA{R: 38, G: 100, B: 210, A: 255}
	path, checksum := writeTestPNG(t, 40, 30, background)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read png: %v", err)
	}
	withResourceHTTPClient(t, &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://cdn.example.test/background.png" {
			t.Fatalf("unexpected resource url %s", req.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"image/png"}},
			Body:       io.NopCloser(bytes.NewReader(data)),
			Request:    req,
		}, nil
	})})

	payload := types.RenderPayload{
		Type:       types.CaptchaSlider,
		View:       types.View{Width: 120, Height: 80},
		Image:      "fallback-image",
		Piece:      "fallback-piece",
		Parameters: map[string]any{"piece_size": 48},
	}
	composed := ApplyVisuals(payload, types.Answer{X: 60, Y: 20}, []types.CaptchaResource{
		{
			ID:           "res_remote_background",
			ResourceType: "background_image",
			StorageType:  "url",
			URI:          "https://cdn.example.test/background.png",
			Checksum:     checksum,
			Metadata:     map[string]any{"mime_type": "image/png"},
			Status:       "active",
		},
	})

	if composed.Image == payload.Image || composed.Piece == payload.Piece {
		t.Fatalf("expected remote resource to replace generated image and piece")
	}
	image := decodePNGDataURL(t, composed.Image)
	assertPixel(t, image, 5, 5, background)
}

func TestApplyVisualsUsesClasspathBackground(t *testing.T) {
	root := t.TempDir()
	background := color.RGBA{R: 180, G: 84, B: 24, A: 255}
	path := filepath.Join(root, "assets", "background.png")
	checksum := writeTestPNGAt(t, path, 40, 30, background)
	t.Setenv("CAPTCHA_RESOURCE_CLASSPATH_DIRS", root)

	payload := types.RenderPayload{
		Type:       types.CaptchaSlider,
		View:       types.View{Width: 120, Height: 80},
		Image:      "fallback-image",
		Piece:      "fallback-piece",
		Parameters: map[string]any{"piece_size": 48},
	}
	composed := ApplyVisuals(payload, types.Answer{X: 60, Y: 20}, []types.CaptchaResource{
		{
			ID:           "res_classpath_background",
			ResourceType: "background_image",
			StorageType:  "classpath",
			URI:          "classpath://assets/background.png",
			Checksum:     checksum,
			Metadata:     map[string]any{"mime_type": "image/png", "width": 40, "height": 30},
			Status:       "active",
		},
	})

	if composed.Image == payload.Image || composed.Piece == payload.Piece {
		t.Fatalf("expected classpath resource to replace generated image and piece")
	}
	image := decodePNGDataURL(t, composed.Image)
	assertPixel(t, image, 5, 5, background)
}

func TestApplyVisualsUsesDatabaseBase64Background(t *testing.T) {
	t.Parallel()

	background := color.RGBA{R: 77, G: 24, B: 180, A: 255}
	path, checksum := writeTestPNG(t, 40, 30, background)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read png: %v", err)
	}
	payload := types.RenderPayload{
		Type:  types.CaptchaSlider,
		View:  types.View{Width: 120, Height: 80},
		Image: "fallback-image",
		Piece: "fallback-piece",
	}

	composed := ApplyVisuals(payload, types.Answer{X: 60, Y: 20}, []types.CaptchaResource{
		{
			ID:           "res_database_background",
			ResourceType: "background_image",
			StorageType:  "database",
			URI:          "db://captcha_resources/background",
			Checksum:     checksum,
			Metadata: map[string]any{
				"data_url":  "data:image/png;base64," + base64.StdEncoding.EncodeToString(data),
				"mime_type": "image/png",
			},
			Status: "active",
		},
	})

	if composed.Image == payload.Image || composed.Piece == payload.Piece {
		t.Fatalf("expected database resource to replace generated image and piece")
	}
	image := decodePNGDataURL(t, composed.Image)
	assertPixel(t, image, 5, 5, background)
}

func TestApplyVisualsUsesObjectStorageEndpointBackground(t *testing.T) {
	background := color.RGBA{R: 16, G: 95, B: 185, A: 255}
	path, checksum := writeTestPNG(t, 40, 30, background)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read png: %v", err)
	}
	withResourceHTTPClient(t, &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://objects.example.test/prefix/captcha-assets/login/background.png" {
			t.Fatalf("unexpected object storage url %s", req.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"image/png"}},
			Body:       io.NopCloser(bytes.NewReader(data)),
			Request:    req,
		}, nil
	})})
	payload := types.RenderPayload{
		Type:  types.CaptchaSlider,
		View:  types.View{Width: 120, Height: 80},
		Image: "fallback-image",
		Piece: "fallback-piece",
	}

	composed := ApplyVisuals(payload, types.Answer{X: 60, Y: 20}, []types.CaptchaResource{
		{
			ID:           "res_object_storage_background",
			ResourceType: "background_image",
			StorageType:  "object_storage",
			URI:          "s3://captcha-assets/login/background.png",
			Checksum:     checksum,
			Metadata: map[string]any{
				"endpoint":  "https://objects.example.test/prefix",
				"mime_type": "image/png",
			},
			Status: "active",
		},
	})

	if composed.Image == payload.Image || composed.Piece == payload.Piece {
		t.Fatalf("expected object storage resource to replace generated image and piece")
	}
	image := decodePNGDataURL(t, composed.Image)
	assertPixel(t, image, 5, 5, background)
}

func TestApplyVisualsUsesObjectStorageVirtualHostedEndpoint(t *testing.T) {
	background := color.RGBA{R: 116, G: 45, B: 185, A: 255}
	path, checksum := writeTestPNG(t, 40, 30, background)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read png: %v", err)
	}
	withResourceHTTPClient(t, &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://captcha-assets.objects.example.test/login/background.png" {
			t.Fatalf("unexpected virtual-hosted object storage url %s", req.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"image/png"}},
			Body:       io.NopCloser(bytes.NewReader(data)),
			Request:    req,
		}, nil
	})})
	payload := types.RenderPayload{
		Type:  types.CaptchaSlider,
		View:  types.View{Width: 120, Height: 80},
		Image: "fallback-image",
		Piece: "fallback-piece",
	}

	composed := ApplyVisuals(payload, types.Answer{X: 60, Y: 20}, []types.CaptchaResource{
		{
			ID:           "res_object_storage_virtual",
			ResourceType: "background_image",
			StorageType:  "object_storage",
			URI:          "oss://captcha-assets/login/background.png",
			Checksum:     checksum,
			Metadata: map[string]any{
				"endpoint":         "https://objects.example.test",
				"addressing_style": "virtual_hosted",
				"mime_type":        "image/png",
			},
			Status: "active",
		},
	})

	if composed.Image == payload.Image || composed.Piece == payload.Piece {
		t.Fatalf("expected virtual-hosted object storage resource to replace generated image and piece")
	}
	image := decodePNGDataURL(t, composed.Image)
	assertPixel(t, image, 5, 5, background)
}

func TestApplyVisualsRejectsUnsafeObjectStorageEndpoint(t *testing.T) {
	called := false
	withResourceHTTPClient(t, &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})})
	payload := types.RenderPayload{
		Type:  types.CaptchaSlider,
		View:  types.View{Width: 120, Height: 80},
		Image: "fallback-image",
		Piece: "fallback-piece",
	}

	composed := ApplyVisuals(payload, types.Answer{X: 60, Y: 20}, []types.CaptchaResource{
		{
			ID:           "res_object_storage_unsafe",
			ResourceType: "background_image",
			StorageType:  "object_storage",
			URI:          "minio://captcha-assets/login/background.png",
			Metadata:     map[string]any{"endpoint": "http://127.0.0.1:9000"},
			Status:       "active",
		},
	})

	if called {
		t.Fatalf("unsafe object storage endpoint should not be requested")
	}
	if composed.Image != payload.Image || composed.Piece != payload.Piece {
		t.Fatalf("expected unsafe object storage endpoint to keep fallback payload, got %+v", composed)
	}
}

func TestApplyVisualsUsesSliderTemplateMask(t *testing.T) {
	t.Parallel()

	backgroundPath, _ := writeTestPNG(t, 60, 60, color.RGBA{R: 18, G: 160, B: 75, A: 255})
	templatePath := writeSliderMaskPNG(t)
	payload := types.RenderPayload{
		Type:       types.CaptchaSlider,
		View:       types.View{Width: 120, Height: 80},
		Image:      "fallback-image",
		Piece:      "fallback-piece",
		Parameters: map[string]any{"piece_size": 48},
	}

	composed := ApplyVisuals(payload, types.Answer{X: 40, Y: 20}, []types.CaptchaResource{
		{
			ID:           "res_background",
			ResourceType: "background_image",
			StorageType:  "file",
			URI:          backgroundPath,
			Status:       "active",
		},
		{
			ID:           "res_slider_template",
			ResourceType: "slider_template",
			StorageType:  "file",
			URI:          templatePath,
			Status:       "active",
		},
	})

	piece := decodePNGDataURL(t, composed.Piece)
	if piece.Bounds().Dx() != 48 || piece.Bounds().Dy() != 48 {
		t.Fatalf("expected slider resource piece to honor piece_size, got %s", piece.Bounds())
	}
	if alphaAt(t, piece, 0, 0) != 0 {
		t.Fatalf("expected transparent corner from slider template mask")
	}
	if alphaAt(t, piece, 24, 24) == 0 {
		t.Fatalf("expected opaque center from slider template mask")
	}
}

func TestApplyVisualsUsesDefaultSliderMaskWhenTemplateMissing(t *testing.T) {
	t.Parallel()

	backgroundPath, _ := writeTestPNG(t, 60, 60, color.RGBA{R: 18, G: 160, B: 75, A: 255})
	payload := types.RenderPayload{
		Type:       types.CaptchaSlider,
		View:       types.View{Width: 120, Height: 80},
		Image:      "fallback-image",
		Piece:      "fallback-piece",
		Parameters: map[string]any{"piece_size": 48},
	}

	composed := ApplyVisuals(payload, types.Answer{X: 40, Y: 20}, []types.CaptchaResource{
		{
			ID:           "res_background",
			ResourceType: "background_image",
			StorageType:  "file",
			URI:          backgroundPath,
			Status:       "active",
		},
	})

	piece := decodePNGDataURL(t, composed.Piece)
	if alphaAt(t, piece, 0, 0) != 0 {
		t.Fatalf("expected default slider fallback to keep transparent corners")
	}
	if alphaAt(t, piece, 24, 24) == 0 {
		t.Fatalf("expected default slider fallback to draw an opaque body")
	}
}

func TestApplyVisualsKeepsSliderFallbackSizeAlignedWithEngine(t *testing.T) {
	t.Parallel()

	backgroundPath, _ := writeTestPNG(t, 320, 160, color.RGBA{R: 18, G: 160, B: 75, A: 255})
	resources := []types.CaptchaResource{
		{
			ID:           "res_background",
			ResourceType: "background_image",
			StorageType:  "file",
			URI:          backgroundPath,
			Status:       "active",
		},
	}
	cases := []struct {
		name        string
		captchaType types.CaptchaType
		wantSize    int
	}{
		{name: "slider", captchaType: types.CaptchaSlider, wantSize: 47},
		{name: "slider v2", captchaType: types.CaptchaSlider2, wantSize: 47},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			payload := types.RenderPayload{
				Type:  tt.captchaType,
				View:  types.View{Width: 320, Height: 160},
				Image: "fallback-image",
				Piece: "fallback-piece",
			}

			composed := ApplyVisuals(payload, types.Answer{X: 140, Y: 60}, resources)
			piece := decodePNGDataURL(t, composed.Piece)
			if piece.Bounds().Dx() != tt.wantSize || piece.Bounds().Dy() != tt.wantSize {
				t.Fatalf("expected %s fallback piece size %dx%d, got %s", tt.captchaType, tt.wantSize, tt.wantSize, piece.Bounds())
			}
			if got := renderParameterInt(composed.Parameters, "piece_size", 0); got != tt.wantSize {
				t.Fatalf("expected %s payload piece_size %d, got %d", tt.captchaType, tt.wantSize, got)
			}
		})
	}
}

func TestApplyVisualsUsesOneDefaultSliderTemplateForSlider2(t *testing.T) {
	backgroundPath, _ := writeTestPNG(t, 320, 180, color.RGBA{R: 92, G: 132, B: 190, A: 255})
	resources := []types.CaptchaResource{
		{
			ID:           "res_background",
			ResourceType: "background_image",
			StorageType:  "file",
			URI:          backgroundPath,
			Status:       "active",
		},
	}
	previousFactory := defaultSliderTemplateFactory
	calls := 0
	defaultSliderTemplateFactory = func(size int) image.Image {
		calls++
		mask, ok := renderEmbeddedSliderMask("dianzan.svg", size)
		if !ok {
			t.Fatalf("expected embedded slider mask to render")
		}
		return mask
	}
	t.Cleanup(func() {
		defaultSliderTemplateFactory = previousFactory
	})

	payload := types.RenderPayload{
		Type:  types.CaptchaSlider2,
		View:  types.View{Width: 320, Height: 180},
		Image: "fallback-image",
		Piece: "fallback-piece",
	}
	composed := ApplyVisuals(payload, types.Answer{X: 140, Y: 70}, resources)

	if composed.Image == payload.Image || composed.Piece == payload.Piece {
		t.Fatalf("expected slider v2 to compose image and piece")
	}
	if calls != 1 {
		t.Fatalf("slider v2 should select one default template shared by piece and decoys, got %d calls", calls)
	}
}

func TestSlider2DecoyUsesBlackTransparentMaskWithoutAmbientShadow(t *testing.T) {
	t.Parallel()

	size := sliderPieceSizeFallback
	mask, ok := renderEmbeddedSliderMask("dianzan.svg", size)
	if !ok {
		t.Fatalf("expected embedded slider mask to render")
	}
	img := image.NewRGBA(image.Rect(0, 0, 160, 100))
	fillRect(img, 0, 0, 160, 100, color.RGBA{R: 92, G: 132, B: 190, A: 255})
	before := cloneRGBA(img)
	origin := image.Point{X: 18, Y: 24}

	drawSliderMaskGhost(img, mask, origin.X, origin.Y, size, sliderMaskOpacity)

	inside, ambient := sliderGhostChangeCounts(t, before, img, origin, size, func(x, y int) uint8 {
		if x < 0 || y < 0 || x >= size || y >= size {
			return 0
		}
		return colorAlpha(mask.At(x, y))
	})
	if inside < size*size/4 {
		t.Fatalf("slider v2 decoy should render the puzzle body, changed inside pixels=%d", inside)
	}
	if ambient != 0 {
		t.Fatalf("slider v2 decoy should not render ambient shadow outside mask, changed ambient pixels=%d", ambient)
	}
}

func TestComposedSliderPieceHasNoOutsideShadow(t *testing.T) {
	t.Parallel()

	size := sliderPieceSizeFallback
	mask, ok := renderEmbeddedSliderMask("dianzan.svg", size)
	if !ok {
		t.Fatalf("expected embedded slider mask to render")
	}
	base := image.NewRGBA(image.Rect(0, 0, 160, 100))
	fillRect(base, 0, 0, 160, 100, color.RGBA{R: 92, G: 132, B: 190, A: 255})
	target := image.Point{X: 60, Y: 30}
	_, piece := composeSlider(base, types.Answer{X: target.X, Y: target.Y}, mask, size)
	actualMask := resizeAlphaMask(mask, size, size)

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if colorAlpha(actualMask.At(x, y)) > 4 {
				continue
			}
			if alphaAt(t, piece, x, y) != 0 {
				t.Fatalf("slider piece should not contain outside shadow at %d,%d alpha=%d", x, y, alphaAt(t, piece, x, y))
			}
		}
	}

	assertSliderPieceHasInnerBorder(t, piece, base, target, size, func(x, y int) uint8 {
		if x < 0 || y < 0 || x >= size || y >= size {
			return 0
		}
		return colorAlpha(actualMask.At(x, y))
	}, func(x, y int) float64 {
		return sliderTemplateEdgeBandStrength(actualMask, x, y, sliderBorderRadius)
	})
}

func TestDefaultSliderTemplatesHaveConsistentVisibleSize(t *testing.T) {
	t.Parallel()

	if slider2PieceSizeFallback != sliderPieceSizeFallback {
		t.Fatalf("slider fallbacks should share one visual piece size: slider=%d slider2=%d", sliderPieceSizeFallback, slider2PieceSizeFallback)
	}
	minVisible, maxVisible := sliderPieceSizeFallback, 0
	for _, filename := range defaultSliderMaskFiles {
		mask, ok := renderEmbeddedSliderMask(filename, sliderPieceSizeFallback)
		if !ok {
			t.Fatalf("expected embedded slider mask %s to render", filename)
		}
		visible, ok := testAlphaBounds(t, mask, 35)
		if !ok {
			t.Fatalf("slider mask %s should have visible pixels", filename)
		}
		visibleMaxSide := max(visible.Dx(), visible.Dy())
		if visibleMaxSide < sliderPieceSizeFallback-12 || visibleMaxSide > sliderPieceSizeFallback-2 {
			t.Fatalf("slider mask %s visible size should stay near %d, got bounds=%s", filename, sliderPieceSizeFallback, visible)
		}
		minVisible = min(minVisible, visibleMaxSide)
		maxVisible = max(maxVisible, visibleMaxSide)
	}
	if maxVisible-minVisible > 4 {
		t.Fatalf("slider masks should have consistent visible sizes, min=%d max=%d", minVisible, maxVisible)
	}
}

func TestDefaultSliderTemplatesUseEmbeddedSVGShapePool(t *testing.T) {
	t.Parallel()

	if len(defaultSliderMaskFiles) != 11 {
		t.Fatalf("expected 11 embedded default slider masks, got %d", len(defaultSliderMaskFiles))
	}
	for _, filename := range defaultSliderMaskFiles {
		mask, ok := renderEmbeddedSliderMask(filename, 48)
		if !ok {
			t.Fatalf("expected embedded slider mask %s to render", filename)
		}
		opaque := 0
		bounds := mask.Bounds()
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				if alphaAt(t, mask, x, y) > 35 {
					opaque++
				}
			}
		}
		if opaque < 90 {
			t.Fatalf("embedded slider mask %s rendered too few opaque pixels: %d", filename, opaque)
		}
	}
}

func TestEmbeddedHeartDefaultSliderMaskKeepsHeartSilhouette(t *testing.T) {
	t.Parallel()

	mask, ok := renderEmbeddedSliderMask("heart-fill.svg", sliderPieceSizeFallback)
	if !ok {
		t.Fatalf("expected embedded heart slider mask to render")
	}
	assertHeartMaskSilhouette(t, mask)
}

func TestApplyVisualsUsesRotateTemplateOverlay(t *testing.T) {
	t.Parallel()

	backgroundPath, _ := writeTestPNG(t, 40, 40, color.RGBA{R: 38, G: 100, B: 210, A: 255})
	templatePath := writeOverlayPNG(t, 90, 90, color.RGBA{R: 250, G: 40, B: 40, A: 255})
	payload := types.RenderPayload{
		Type:  types.CaptchaRotate,
		View:  types.View{Width: 90, Height: 90},
		Image: "fallback-image",
	}

	composed := ApplyVisuals(payload, types.Answer{Angle: 90}, []types.CaptchaResource{
		{
			ID:           "res_background",
			ResourceType: "background_image",
			StorageType:  "file",
			URI:          backgroundPath,
			Status:       "active",
		},
		{
			ID:           "res_rotate_template",
			ResourceType: "rotate_template",
			StorageType:  "file",
			URI:          templatePath,
			Status:       "active",
		},
	})

	image := decodePNGDataURL(t, composed.Image)
	assertPixel(t, image, 0, 0, color.RGBA{R: 250, G: 40, B: 40, A: 255})
}

func TestApplyVisualsUsesRotateLibraryCircularCrop(t *testing.T) {
	t.Parallel()

	rotatePath, _ := writeTestPNG(t, 90, 90, color.RGBA{R: 38, G: 100, B: 210, A: 255})
	payload := types.RenderPayload{
		Type:       types.CaptchaRotate,
		View:       types.View{Width: 90, Height: 90},
		Image:      "fallback-image",
		Parameters: map[string]any{"initial_angle": 270, "stale": "keep"},
	}

	composed := ApplyVisuals(payload, types.Answer{Angle: 0}, []types.CaptchaResource{
		{
			ID:           "res_rotate_library",
			ResourceType: "rotate_library",
			StorageType:  "file",
			URI:          rotatePath,
			Status:       "active",
		},
	})

	image := decodePNGDataURL(t, composed.Image)
	assertPixel(t, image, 45, 45, color.RGBA{R: 38, G: 100, B: 210, A: 255})
	if alphaAt(t, image, 0, 0) != 0 {
		t.Fatalf("expected rotate crop outside the circle to stay transparent")
	}
	if _, ok := composed.Parameters["initial_angle"]; ok {
		t.Fatalf("rotate payload must not expose initial_angle")
	}
	if composed.Parameters["stale"] != "keep" {
		t.Fatalf("expected unrelated rotate parameter to be retained")
	}
}

func TestApplyVisualsUsesConcatTemplateJSON(t *testing.T) {
	t.Parallel()

	backgroundPath, _ := writeTestPNG(t, 100, 40, color.RGBA{R: 210, G: 210, B: 210, A: 255})
	templatePath := filepath.Join(t.TempDir(), "concat.json")
	if err := os.WriteFile(templatePath, []byte(`{"split_y":12,"gap_color":"#112233","border_color":"#445566"}`), 0o600); err != nil {
		t.Fatalf("write concat template: %v", err)
	}
	payload := types.RenderPayload{
		Type:       types.CaptchaConcat,
		View:       types.View{Width: 100, Height: 40},
		Image:      "fallback-image",
		Piece:      "fallback-piece",
		Parameters: map[string]any{"stale": "keep"},
	}

	composed := ApplyVisuals(payload, types.Answer{Offset: 10}, []types.CaptchaResource{
		{
			ID:           "res_background",
			ResourceType: "background_image",
			StorageType:  "file",
			URI:          backgroundPath,
			Status:       "active",
		},
		{
			ID:           "res_concat_template",
			ResourceType: "concat_template",
			StorageType:  "file",
			URI:          templatePath,
			Status:       "active",
		},
	})

	image := decodePNGDataURL(t, composed.Image)
	seamChanged := false
	for y := 8; y <= 16 && !seamChanged; y++ {
		for x := 0; x < 100; x++ {
			r, g, b, a := image.At(x, y).RGBA()
			if (color.RGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8)}) != (color.RGBA{R: 210, G: 210, B: 210, A: 255}) {
				seamChanged = true
				break
			}
		}
	}
	if !seamChanged {
		t.Fatal("expected concat split seam to be visually processed")
	}
	assertPixel(t, image, 50, 20, color.RGBA{R: 210, G: 210, B: 210, A: 255})
	if composed.Piece == payload.Piece {
		t.Fatal("expected concat piece to be composed from resource background")
	}
	piece := decodePNGDataURL(t, composed.Piece)
	if piece.Bounds().Dx() != 260 || piece.Bounds().Dy() != 40 {
		t.Fatalf("unexpected concat piece size: %s", piece.Bounds())
	}
	if alphaAt(t, piece, 130, 2) == 0 {
		t.Fatal("expected concat piece to contain opaque pixels above the split")
	}
	if alphaAt(t, piece, 130, 38) != 0 {
		t.Fatal("expected concat piece bottom to stay transparent")
	}
	minEdge, maxEdge := alphaEdgeRange(t, piece)
	if maxEdge-minEdge > 1 {
		t.Fatalf("expected concat piece to use a straight horizontal split, edge range=%d..%d", minEdge, maxEdge)
	}
	if composed.Parameters["stale"] != "keep" ||
		composed.Parameters["split_y"] != 12 ||
		composed.Parameters["piece_width"] != 260 ||
		composed.Parameters["max"] != 100 {
		t.Fatalf("unexpected concat parameters: %+v", composed.Parameters)
	}
	if _, ok := composed.Parameters["initial_offset"]; ok {
		t.Fatalf("concat resource rendering should not expose answer-equivalent initial_offset: %+v", composed.Parameters)
	}
	if _, ok := composed.Parameters["split_x"]; ok {
		t.Fatalf("concat resource rendering should not expose legacy vertical split_x: %+v", composed.Parameters)
	}
}

func TestApplyVisualsUsesFontMetadata(t *testing.T) {
	t.Parallel()

	backgroundPath, _ := writeTestPNG(t, 80, 60, color.RGBA{R: 245, G: 245, B: 245, A: 255})
	payload := types.RenderPayload{
		Type:  types.CaptchaWordImageClick,
		View:  types.View{Width: 80, Height: 60},
		Image: "fallback-image",
		Words: []string{"A"},
	}

	composed := ApplyVisuals(payload, types.Answer{Points: []types.Point{{X: 30, Y: 30}}}, []types.CaptchaResource{
		{
			ID:           "res_background",
			ResourceType: "background_image",
			StorageType:  "file",
			URI:          backgroundPath,
			Status:       "active",
		},
		{
			ID:           "res_font",
			ResourceType: "font",
			StorageType:  "embedded",
			URI:          "embedded://block-font",
			Metadata: map[string]any{
				"glyph_scale": 4,
				"palette":     []any{"#ff0000"},
				"glyphs": map[string]any{
					"A": []any{"1"},
				},
			},
			Status: "active",
		},
	})

	image := decodePNGDataURL(t, composed.Image)
	assertPixel(t, image, 28, 28, color.RGBA{R: 255, G: 0, B: 0, A: 255})
}

func TestApplyVisualsDrawsChineseWordGlyphs(t *testing.T) {
	t.Parallel()

	background := color.RGBA{R: 245, G: 245, B: 245, A: 255}
	backgroundPath, _ := writeTestPNG(t, 100, 80, background)
	payload := types.RenderPayload{
		Type:  types.CaptchaWordImageClick,
		View:  types.View{Width: 100, Height: 80},
		Image: "fallback-image",
		Words: []string{"文", "王", "火", "水"},
	}

	composed := ApplyVisuals(payload, types.Answer{Points: []types.Point{
		{X: 24, Y: 24},
		{X: 74, Y: 24},
		{X: 24, Y: 58},
		{X: 74, Y: 58},
	}}, []types.CaptchaResource{
		{
			ID:           "res_background",
			ResourceType: "background_image",
			StorageType:  "file",
			URI:          backgroundPath,
			Status:       "active",
		},
	})

	image := decodePNGDataURL(t, composed.Image)
	assertRegionChanged(t, image, 8, 8, 32, 32, background)
	assertRegionChanged(t, image, 58, 8, 32, 32, background)
	assertRegionChanged(t, image, 8, 42, 32, 32, background)
	assertRegionChanged(t, image, 58, 42, 32, 32, background)
}

func TestApplyVisualsRejectsClasspathTraversal(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	background := color.RGBA{R: 180, G: 84, B: 24, A: 255}
	writeTestPNGAt(t, filepath.Join(outside, "background.png"), 40, 30, background)
	t.Setenv("CAPTCHA_RESOURCE_CLASSPATH_DIRS", root)

	payload := types.RenderPayload{
		Type:  types.CaptchaSlider,
		View:  types.View{Width: 120, Height: 80},
		Image: "fallback-image",
		Piece: "fallback-piece",
	}
	composed := ApplyVisuals(payload, types.Answer{X: 60, Y: 20}, []types.CaptchaResource{
		{
			ID:           "res_classpath_traversal",
			ResourceType: "background_image",
			StorageType:  "classpath",
			URI:          "classpath://../background.png",
			Status:       "active",
		},
	})

	if composed.Image != payload.Image || composed.Piece != payload.Piece {
		t.Fatalf("expected classpath traversal to keep fallback payload, got %+v", composed)
	}
}

func TestApplyVisualsRejectsUnsafeRemoteURL(t *testing.T) {
	called := false
	withResourceHTTPClient(t, &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})})
	payload := types.RenderPayload{
		Type:  types.CaptchaSlider,
		View:  types.View{Width: 120, Height: 80},
		Image: "fallback-image",
		Piece: "fallback-piece",
	}

	composed := ApplyVisuals(payload, types.Answer{X: 60, Y: 20}, []types.CaptchaResource{
		{
			ID:           "res_unsafe_background",
			ResourceType: "background_image",
			StorageType:  "url",
			URI:          "http://localhost/background.png",
			Status:       "active",
		},
	})

	if called {
		t.Fatalf("unsafe remote resource should not be requested")
	}
	if composed.Image != payload.Image || composed.Piece != payload.Piece {
		t.Fatalf("expected unsafe url to keep fallback payload, got %+v", composed)
	}
}

func TestApplyVisualsFallsBackOnDeclaredDimensionMismatch(t *testing.T) {
	t.Parallel()

	path, _ := writeTestPNG(t, 40, 30, color.RGBA{R: 12, G: 180, B: 90, A: 255})
	payload := types.RenderPayload{
		Type:  types.CaptchaSlider,
		View:  types.View{Width: 120, Height: 80},
		Image: "fallback-image",
		Piece: "fallback-piece",
	}

	composed := ApplyVisuals(payload, types.Answer{X: 60, Y: 20}, []types.CaptchaResource{
		{
			ID:           "res_dimension_mismatch",
			ResourceType: "background_image",
			StorageType:  "file",
			URI:          path,
			Metadata:     map[string]any{"width": 41, "height": 30},
			Status:       "active",
		},
	})

	if composed.Image != payload.Image || composed.Piece != payload.Piece {
		t.Fatalf("expected dimension mismatch to keep fallback payload, got %+v", composed)
	}
}

func TestApplyVisualsFallsBackOnDeclaredMIMEMismatch(t *testing.T) {
	t.Parallel()

	path, _ := writeTestPNG(t, 40, 30, color.RGBA{R: 12, G: 180, B: 90, A: 255})
	payload := types.RenderPayload{
		Type:  types.CaptchaSlider,
		View:  types.View{Width: 120, Height: 80},
		Image: "fallback-image",
		Piece: "fallback-piece",
	}

	composed := ApplyVisuals(payload, types.Answer{X: 60, Y: 20}, []types.CaptchaResource{
		{
			ID:           "res_mime_mismatch",
			ResourceType: "background_image",
			StorageType:  "file",
			URI:          path,
			Metadata:     map[string]any{"mime_type": "image/jpeg"},
			Status:       "active",
		},
	})

	if composed.Image != payload.Image || composed.Piece != payload.Piece {
		t.Fatalf("expected declared MIME mismatch to keep fallback payload, got %+v", composed)
	}
}

func TestApplyVisualsFallsBackOnRemoteContentTypeMismatch(t *testing.T) {
	path, _ := writeTestPNG(t, 40, 30, color.RGBA{R: 38, G: 100, B: 210, A: 255})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read png: %v", err)
	}
	withResourceHTTPClient(t, &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"image/jpeg"}},
			Body:       io.NopCloser(bytes.NewReader(data)),
			Request:    req,
		}, nil
	})})
	payload := types.RenderPayload{
		Type:  types.CaptchaSlider,
		View:  types.View{Width: 120, Height: 80},
		Image: "fallback-image",
		Piece: "fallback-piece",
	}

	composed := ApplyVisuals(payload, types.Answer{X: 60, Y: 20}, []types.CaptchaResource{
		{
			ID:           "res_content_type_mismatch",
			ResourceType: "background_image",
			StorageType:  "url",
			URI:          "https://cdn.example.test/background.png",
			Status:       "active",
		},
	})

	if composed.Image != payload.Image || composed.Piece != payload.Piece {
		t.Fatalf("expected remote content type mismatch to keep fallback payload, got %+v", composed)
	}
}

func TestApplyVisualsFallsBackOnChecksumMismatch(t *testing.T) {
	t.Parallel()

	path, _ := writeTestPNG(t, 40, 30, color.RGBA{R: 12, G: 180, B: 90, A: 255})
	payload := types.RenderPayload{
		Type:  types.CaptchaSlider,
		View:  types.View{Width: 120, Height: 80},
		Image: "fallback-image",
		Piece: "fallback-piece",
	}

	composed := ApplyVisuals(payload, types.Answer{X: 60, Y: 20}, []types.CaptchaResource{
		{
			ID:           "res_bad_checksum",
			ResourceType: "background_image",
			StorageType:  "file",
			URI:          path,
			Checksum:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Status:       "active",
		},
	})

	if composed.Image != payload.Image || composed.Piece != payload.Piece {
		t.Fatalf("expected checksum mismatch to keep fallback payload, got %+v", composed)
	}
}

func TestApplyVisualsComposesSupportedCaptchaTypes(t *testing.T) {
	t.Parallel()

	path, _ := writeTestPNG(t, 40, 30, color.RGBA{R: 25, G: 120, B: 210, A: 255})
	resources := []types.CaptchaResource{
		{
			ID:           "res_local_background",
			ResourceType: "background_image",
			StorageType:  "file",
			URI:          path,
			Status:       "active",
		},
	}
	cases := []struct {
		name    string
		payload types.RenderPayload
		answer  types.Answer
	}{
		{
			name: "slider",
			payload: types.RenderPayload{
				Type:  types.CaptchaSlider,
				View:  types.View{Width: 120, Height: 80},
				Image: "fallback-image",
				Piece: "fallback-piece",
			},
			answer: types.Answer{X: 50, Y: 20},
		},
		{
			name: "slider v2",
			payload: types.RenderPayload{
				Type:  types.CaptchaSlider2,
				View:  types.View{Width: 120, Height: 80},
				Image: "fallback-image",
				Piece: "fallback-piece",
			},
			answer: types.Answer{X: 50, Y: 20},
		},
		{
			name: "curve",
			payload: types.RenderPayload{
				Type:  types.CaptchaCurve,
				View:  types.View{Width: 120, Height: 80},
				Image: "fallback-image",
				Parameters: map[string]any{
					"curve_profile": map[string]any{
						"variant":       1,
						"moving_points": []map[string]float64{{"x": 22, "y": 28}, {"x": 62, "y": 48}, {"x": 100, "y": 34}},
						"drive_points":  []map[string]float64{{"x": 0.1, "y": 0}, {"x": 0.1, "y": 0}, {"x": 0.1, "y": 0}},
					},
				},
			},
			answer: types.Answer{X: 20},
		},
		{
			name: "rotate",
			payload: types.RenderPayload{
				Type:  types.CaptchaRotate,
				View:  types.View{Width: 90, Height: 90},
				Image: "fallback-image",
			},
			answer: types.Answer{Angle: 90},
		},
		{
			name: "concat",
			payload: types.RenderPayload{
				Type:  types.CaptchaConcat,
				View:  types.View{Width: 120, Height: 80},
				Image: "fallback-image",
				Piece: "fallback-piece",
			},
			answer: types.Answer{Offset: 30},
		},
		{
			name: "word image click",
			payload: types.RenderPayload{
				Type:  types.CaptchaWordImageClick,
				View:  types.View{Width: 120, Height: 80},
				Image: "fallback-image",
				Words: []string{"A", "B", "C"},
			},
			answer: types.Answer{Points: []types.Point{{X: 25, Y: 40}, {X: 60, Y: 40}, {X: 95, Y: 40}}},
		},
		{
			name: "image click",
			payload: types.RenderPayload{
				Type:  types.CaptchaImageClick,
				View:  types.View{Width: 120, Height: 80},
				Image: "fallback-image",
				Words: []string{"饮料", "书籍", "苹果"},
			},
			answer: types.Answer{Points: []types.Point{{X: 25, Y: 40}, {X: 60, Y: 40}, {X: 95, Y: 40}}},
		},
		{
			name: "jigsaw",
			payload: types.RenderPayload{
				Type:  types.CaptchaJigsaw,
				View:  types.View{Width: 120, Height: 80},
				Image: "fallback-image",
				Words: []string{"1", "2"},
				Parameters: map[string]any{
					"tile_cols":   2,
					"tile_rows":   2,
					"tile_width":  60,
					"tile_height": 40,
				},
			},
			answer: types.Answer{Points: []types.Point{{X: 30, Y: 20}, {X: 90, Y: 60}}},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			composed := ApplyVisuals(tc.payload, tc.answer, resources)
			if composed.Image == tc.payload.Image {
				t.Fatalf("expected %s image to be composed from local resource", tc.name)
			}
			decodePNGDataURL(t, composed.Image)
			if tc.payload.Type == types.CaptchaSlider || tc.payload.Type == types.CaptchaSlider2 || tc.payload.Type == types.CaptchaConcat {
				if composed.Piece == tc.payload.Piece {
					t.Fatalf("expected %s piece to be composed from local resource", tc.name)
				}
				decodePNGDataURL(t, composed.Piece)
			}
		})
	}
}

func TestApplyVisualsUsesBackgroundLibrary(t *testing.T) {
	t.Parallel()

	path, _ := writeTestPNG(t, 40, 30, color.RGBA{R: 10, G: 120, B: 200, A: 255})
	payload := types.RenderPayload{
		Type:  types.CaptchaRotate,
		View:  types.View{Width: 80, Height: 80},
		Image: "fallback-image",
	}

	composed := ApplyVisuals(payload, types.Answer{Angle: 90}, []types.CaptchaResource{
		{
			ID:           "res_background_library",
			ResourceType: "background_library",
			StorageType:  "file",
			URI:          path,
			Status:       "active",
		},
	})

	if composed.Image == payload.Image {
		t.Fatalf("expected background library to compose image")
	}
	decodePNGDataURL(t, composed.Image)
}

func TestApplyVisualsRendersSVGIconLibrary(t *testing.T) {
	t.Parallel()

	backgroundPath, _ := writeTestPNG(t, 80, 60, color.RGBA{R: 240, G: 248, B: 255, A: 255})
	iconPath, checksum := writeTestSVG(t, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><path d="M50 8 L92 92 L8 92 Z" fill="#000"/></svg>`)
	payload := types.RenderPayload{
		Type:   types.CaptchaImageClick,
		Prompt: "依次点击：旧图标",
		View:   types.View{Width: 80, Height: 60},
		Image:  "fallback-image",
		Words:  []string{"旧图标"},
	}

	composed := ApplyVisuals(payload, types.Answer{Points: []types.Point{{X: 40, Y: 30}}}, []types.CaptchaResource{
		{
			ID:           "res_background",
			ResourceType: "background_image",
			StorageType:  "file",
			URI:          backgroundPath,
			Status:       "active",
		},
		{
			ID:           "res_svg_icon",
			ResourceType: "icon_library",
			StorageType:  "file",
			URI:          iconPath,
			Checksum:     checksum,
			Metadata:     map[string]any{"mime_type": "image/svg+xml", "label": "三角形"},
			Status:       "active",
		},
	})

	if composed.Image == payload.Image {
		t.Fatalf("expected svg icon library to compose image")
	}
	if len(composed.Words) != 1 || composed.Words[0] != "三角形" || composed.Prompt != "依次点击：三角形" {
		t.Fatalf("expected icon labels to come from resource metadata, got prompt=%q words=%v", composed.Prompt, composed.Words)
	}
	image := decodePNGDataURL(t, composed.Image)
	assertRegionChanged(t, image, 24, 14, 32, 32, color.RGBA{R: 240, G: 248, B: 255, A: 255})
}

func TestApplyVisualsPreservesBuiltInIconObjectsWithoutIconLibrary(t *testing.T) {
	t.Parallel()

	background := color.RGBA{R: 12, G: 120, B: 80, A: 255}
	backgroundPath, _ := writeTestPNG(t, 80, 60, background)
	native := image.NewRGBA(image.Rect(0, 0, 80, 60))
	fillRect(native, 0, 0, 80, 60, color.RGBA{R: 248, G: 250, B: 252, A: 255})
	fillRect(native, 30, 20, 20, 20, color.RGBA{R: 37, G: 99, B: 235, A: 255})
	payload := types.RenderPayload{
		Type:   types.CaptchaImageClick,
		Prompt: "依次点击：电脑",
		View:   types.View{Width: 80, Height: 60},
		Image:  pngDataURL(native),
		Words:  []string{"电脑"},
	}

	composed := ApplyVisuals(payload, types.Answer{Points: []types.Point{{X: 40, Y: 30}}}, []types.CaptchaResource{
		{
			ID:           "res_background",
			ResourceType: "background_image",
			StorageType:  "file",
			URI:          backgroundPath,
			Status:       "active",
		},
	})

	image := decodePNGDataURL(t, composed.Image)
	assertPixel(t, image, 4, 4, background)
	assertPixel(t, image, 40, 30, color.RGBA{R: 37, G: 99, B: 235, A: 255})
	if composed.Prompt != payload.Prompt || len(composed.Words) != 1 || composed.Words[0] != "电脑" {
		t.Fatalf("expected built-in icon labels to be retained, got prompt=%q words=%v", composed.Prompt, composed.Words)
	}
}

func TestApplyVisualsUsesGridCategoryLibrary(t *testing.T) {
	t.Parallel()

	carPath, _ := writeTestPNG(t, 100, 100, color.RGBA{R: 220, G: 40, B: 40, A: 255})
	busPath, _ := writeTestPNG(t, 100, 100, color.RGBA{R: 40, G: 180, B: 80, A: 255})
	payload := types.RenderPayload{
		Type:   types.CaptchaGridImageClick,
		Prompt: "选择所有包含蓝色圆形的图片",
		View:   types.View{Width: 300, Height: 300},
		Image:  "fallback-image",
		Parameters: map[string]any{
			"tile_cols":   3,
			"tile_rows":   3,
			"tile_width":  100,
			"tile_height": 100,
		},
	}
	answer := types.Answer{Points: []types.Point{
		{X: 50, Y: 50},
		{X: 150, Y: 150},
		{X: 250, Y: 250},
	}}

	composed := ApplyVisuals(payload, answer, []types.CaptchaResource{
		{
			ID:           "res_grid_car",
			ResourceType: "grid_category_library",
			StorageType:  "file",
			URI:          carPath,
			Metadata:     map[string]any{"category": "car", "label": "汽车"},
			Status:       "active",
		},
		{
			ID:           "res_grid_bus",
			ResourceType: "grid_category_library",
			StorageType:  "file",
			URI:          busPath,
			Metadata:     map[string]any{"category": "bus", "label": "巴士"},
			Status:       "active",
		},
	})

	if composed.Image == payload.Image {
		t.Fatalf("expected grid category library to compose image")
	}
	img := decodePNGDataURL(t, composed.Image)
	targetColor := color.RGBA{R: 220, G: 40, B: 40, A: 255}
	decoyColor := color.RGBA{R: 40, G: 180, B: 80, A: 255}
	if composed.Prompt == "选择所有包含巴士的图片" {
		targetColor, decoyColor = decoyColor, targetColor
	} else if composed.Prompt != "选择所有包含汽车的图片" {
		t.Fatalf("unexpected grid prompt %q", composed.Prompt)
	}
	assertPixel(t, img, 50, 50, targetColor)
	assertPixel(t, img, 150, 150, targetColor)
	assertPixel(t, img, 250, 250, targetColor)
	assertPixel(t, img, 250, 50, decoyColor)
}

func writeTestPNG(t *testing.T, width, height int, c color.RGBA) (string, string) {
	t.Helper()
	path := t.TempDir() + "/background.png"
	return path, writeTestPNGAt(t, path, width, height, c)
}

func writeTestPNGAt(t *testing.T, path string, width, height int, c color.RGBA) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create png dir: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write png: %v", err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeTestSVG(t *testing.T, body string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "icon.svg")
	data := []byte(body)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write svg: %v", err)
	}
	sum := sha256.Sum256(data)
	return path, "sha256:" + hex.EncodeToString(sum[:])
}

func writeSliderMaskPNG(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "slider-template.png")
	img := image.NewRGBA(image.Rect(0, 0, 42, 42))
	for y := 10; y < 32; y++ {
		for x := 10; x < 32; x++ {
			img.Set(x, y, color.RGBA{R: 255, G: 255, B: 255, A: 255})
		}
	}
	writePNGImage(t, path, img)
	return path
}

func writeOverlayPNG(t *testing.T, width, height int, c color.RGBA) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "overlay.png")
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	img.Set(0, 0, c)
	writePNGImage(t, path, img)
	return path
}

func writePNGImage(t *testing.T, path string, img image.Image) {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create png dir: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write png: %v", err)
	}
}

func decodePNGDataURL(t *testing.T, value string) image.Image {
	t.Helper()
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(value, prefix) {
		t.Fatalf("expected png data url, got %q", value)
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil {
		t.Fatalf("decode data url: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode png: %v", err)
	}
	return img
}

func alphaAt(t *testing.T, img image.Image, x, y int) uint8 {
	t.Helper()
	_, _, _, a := img.At(x, y).RGBA()
	return uint8(a >> 8)
}

func sliderGhostChangeCounts(t *testing.T, before, after image.Image, origin image.Point, size int, maskAlphaAt func(int, int) uint8) (inside, ambient int) {
	t.Helper()
	for y := -6; y < size+6; y++ {
		for x := -6; x < size+6; x++ {
			gx, gy := origin.X+x, origin.Y+y
			if !image.Pt(gx, gy).In(after.Bounds()) {
				continue
			}
			if rgbaDelta(rgbaAt(before, gx, gy), rgbaAt(after, gx, gy)) <= 12 {
				continue
			}
			alpha := maskAlphaAt(x, y)
			switch {
			case alpha > 35:
				inside++
			case alpha <= 8 && testNearMaskAlpha(maskAlphaAt, x, y, 5):
				ambient++
			}
		}
	}
	return inside, ambient
}

func testNearMaskAlpha(maskAlphaAt func(int, int) uint8, x, y, radius int) bool {
	for dy := -radius; dy <= radius; dy++ {
		for dx := -radius; dx <= radius; dx++ {
			if dx == 0 && dy == 0 {
				continue
			}
			if math.Hypot(float64(dx), float64(dy)) > float64(radius) {
				continue
			}
			if maskAlphaAt(x+dx, y+dy) > 24 {
				return true
			}
		}
	}
	return false
}

func rgbaDelta(a, b color.RGBA) int {
	return absInt(int(a.R)-int(b.R)) + absInt(int(a.G)-int(b.G)) + absInt(int(a.B)-int(b.B)) + absInt(int(a.A)-int(b.A))
}

func assertSliderPieceHasInnerBorder(t *testing.T, piece, source image.Image, sourceOrigin image.Point, size int, maskAlphaAt func(int, int) uint8, edgeAt func(int, int) float64) {
	t.Helper()
	borderPixels := 0
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if maskAlphaAt(x, y) < 140 || edgeAt(x, y) < 0.15 {
				continue
			}
			sourcePixel := rgbaAt(source, sourceOrigin.X+x, sourceOrigin.Y+y)
			piecePixel := rgbaAt(piece, x, y)
			if luminance(sourcePixel)-luminance(piecePixel) > 8 {
				borderPixels++
			}
		}
	}
	if borderPixels < size/2 {
		t.Fatalf("slider piece should have a semi-transparent inner border, darkened edge pixels=%d", borderPixels)
	}
}

func luminance(c color.RGBA) float64 {
	return 0.299*float64(c.R) + 0.587*float64(c.G) + 0.114*float64(c.B)
}

func testAlphaBounds(t *testing.T, img image.Image, threshold uint8) (image.Rectangle, bool) {
	t.Helper()
	bounds := img.Bounds()
	minX, minY := bounds.Max.X, bounds.Max.Y
	maxX, maxY := bounds.Min.X, bounds.Min.Y
	var ok bool
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			if alphaAt(t, img, x, y) <= threshold {
				continue
			}
			minX = min(minX, x)
			minY = min(minY, y)
			maxX = max(maxX, x)
			maxY = max(maxY, y)
			ok = true
		}
	}
	if !ok {
		return image.Rectangle{}, false
	}
	return image.Rect(minX, minY, maxX+1, maxY+1), true
}

func assertHeartMaskSilhouette(t *testing.T, img image.Image) {
	t.Helper()
	visible, ok := testAlphaBounds(t, img, 35)
	if !ok {
		t.Fatalf("heart mask should have visible pixels")
	}
	midX := visible.Min.X + visible.Dx()/2
	foundNotch := false
	for y := visible.Min.Y; y < visible.Min.Y+visible.Dy()/3; y++ {
		left := maxAlphaInRect(t, img, image.Rect(visible.Min.X, y, midX-3, y+1))
		center := maxAlphaInRect(t, img, image.Rect(midX-2, y, midX+3, y+1))
		right := maxAlphaInRect(t, img, image.Rect(midX+3, y, visible.Max.X, y+1))
		if left > 35 && right > 35 && center < min(left, right)/2 {
			foundNotch = true
			break
		}
	}
	if !foundNotch {
		t.Fatalf("heart mask should keep two upper lobes with a center notch, visible=%s", visible)
	}
	lowerPoint := maxAlphaInRect(t, img, image.Rect(midX-3, visible.Max.Y-visible.Dy()/5, midX+4, visible.Max.Y))
	if lowerPoint <= 35 {
		t.Fatalf("heart mask should keep a lower center point, visible=%s lower=%d", visible, lowerPoint)
	}
}

func maxAlphaInRect(t *testing.T, img image.Image, rect image.Rectangle) uint8 {
	t.Helper()
	rect = rect.Intersect(img.Bounds())
	var result uint8
	for y := rect.Min.Y; y < rect.Max.Y; y++ {
		for x := rect.Min.X; x < rect.Max.X; x++ {
			result = max(result, alphaAt(t, img, x, y))
		}
	}
	return result
}

func alphaEdgeRange(t *testing.T, img image.Image) (int, int) {
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

func assertPixel(t *testing.T, img image.Image, x, y int, expected color.RGBA) {
	t.Helper()
	r, g, b, a := img.At(x, y).RGBA()
	actual := color.RGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8)}
	if actual != expected {
		t.Fatalf("pixel %d,%d expected %+v, got %+v", x, y, expected, actual)
	}
}

func assertRegionChanged(t *testing.T, img image.Image, x, y, width, height int, background color.RGBA) {
	t.Helper()
	for yy := y; yy < y+height; yy++ {
		for xx := x; xx < x+width; xx++ {
			r, g, b, a := img.At(xx, yy).RGBA()
			actual := color.RGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8)}
			if actual != background {
				return
			}
		}
	}
	t.Fatalf("expected region %d,%d %dx%d to differ from background %+v", x, y, width, height, background)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func withResourceHTTPClient(t *testing.T, client *http.Client) {
	t.Helper()
	previous := resourceHTTPClient
	resourceHTTPClient = client
	t.Cleanup(func() {
		resourceHTTPClient = previous
	})
}

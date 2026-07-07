package resource

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/color"
	"image/draw"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"io"
	"math"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"captcha/internal/glyphs"
	"captcha/internal/types"

	"github.com/srwiley/oksvg"
	"github.com/srwiley/rasterx"
	xfont "golang.org/x/image/font"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
	_ "golang.org/x/image/webp"
)

const maxResourceImageBytes = 20 * 1024 * 1024
const (
	sliderPieceSizeFallback  = 47
	slider2PieceSizeFallback = sliderPieceSizeFallback
	sliderRenderScale        = 2
	sliderMaskOpacity        = 0.46
	sliderMaskSolidAlpha     = 72
	sliderBorderRadius       = 2
	sliderBorderFalloff      = 1.25
	sliderPieceBorderOpacity = 0.75
	sliderBorderOutsideAlpha = 8
	iconClickRenderScale     = 2
	wordClickRenderScale     = 2
	iconClickResourceSize    = 44
	iconClickEdgeRadius      = 2
	iconClickEdgeDarken      = 0.24
	wordGlyphDefaultDistort  = 0.18
	wordBlockGlyphMaxDistort = 0.04
	rotateRenderScale        = 2
	concatMaxMovement        = 160
)

var resourceHTTPClient = &http.Client{
	Timeout: 3 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || unsafeRemoteURL(req.URL) {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

var wordFontFileCache sync.Map

//go:embed assets/slider/*.svg
var sliderMaskAssets embed.FS

var defaultSliderMaskFiles = []string{
	"dianzan.svg",
	"pintu.svg",
	"shoucang.svg",
	"logobg.svg",
	"huiliuqujinkoushipin.svg",
	"yazi_duck.svg",
	"heart-fill.svg",
	"babianxing.svg",
	"fangzi222.svg",
	"jidan1.svg",
	"yuanjiao-rect.svg",
}

var defaultSliderTemplateFactory = defaultSliderTemplate

// ApplyVisuals composes server-side challenge images from selected local resources.
// It deliberately falls back to the engine generated payload when a resource cannot
// be decoded, so resource rollout cannot break the verification path.
func ApplyVisuals(payload types.RenderPayload, answer types.Answer, resources []types.CaptchaResource) types.RenderPayload {
	if payload.View.Width <= 0 || payload.View.Height <= 0 {
		return payload
	}

	if payload.Type == types.CaptchaGridImageClick {
		if composed, label, ok := composeGridImageFromCategoryLibrary(payload, answer, resources); ok {
			payload.Image = pngDataURL(composed)
			payload.Prompt = "选择所有包含" + label + "的图片"
			payload.Words = []string{label}
			parameters := cloneParameters(payload.Parameters)
			parameters["target_count"] = len(answer.Points)
			parameters["target_label"] = label
			payload.Parameters = parameters
			return payload
		}
	}

	switch payload.Type {
	case types.CaptchaGesture:
		background, ok := loadBackgroundResourceImage(resources)
		if !ok {
			return payload
		}
		base := coverResizeNearest(background, payload.View.Width, payload.View.Height)
		payload.Image = pngDataURL(composeGestureImage(base, answer.Points, payload.View))
	case types.CaptchaSlider, types.CaptchaSlider2:
		background, ok := loadBackgroundResourceImage(resources)
		if !ok {
			return payload
		}
		renderScale := sliderRenderScale
		renderWidth := max(1, payload.View.Width*renderScale)
		renderHeight := max(1, payload.View.Height*renderScale)
		base := coverResizeBilinear(background, renderWidth, renderHeight)
		sliderTemplate, _ := loadResourceImageByType(resources, "slider_template")
		size := sliderPieceSize(payload.Parameters, sliderPieceSizeFallbackFor(payload.Type))
		renderSize := size * renderScale
		renderAnswer := scaleSliderAnswer(answer, renderScale)
		if sliderTemplate == nil {
			sliderTemplate = defaultSliderTemplateFactory(renderSize)
		}
		composed, piece := composeSlider(base, renderAnswer, sliderTemplate, renderSize)
		if payload.Type == types.CaptchaSlider2 {
			composed = composeSliderDecoys(composed, renderAnswer, sliderTemplate, renderSize)
		}
		payload.Image = pngDataURL(composed)
		payload.Piece = pngDataURL(piece)
		parameters := cloneParameters(payload.Parameters)
		parameters["piece_size"] = size
		payload.Parameters = parameters
	case types.CaptchaCurve, types.CaptchaCurve2, types.CaptchaCurve3:
		background, ok := loadBackgroundResourceImage(resources)
		if !ok {
			return payload
		}
		base := coverResizeNearest(background, payload.View.Width, payload.View.Height)
		payload.Image = pngDataURL(composeCurveImage(base, payload, answer))
	case types.CaptchaRotate:
		rotateSource, ok := loadRotateResourceImage(resources)
		if !ok {
			return payload
		}
		renderWidth := max(1, payload.View.Width*rotateRenderScale)
		renderHeight := max(1, payload.View.Height*rotateRenderScale)
		base := cropCircularRotateImage(rotateSource, renderWidth, renderHeight)
		start := ((360-answer.Angle)%360 + 360) % 360
		rotated := rotateImage(base, start)
		if rotateTemplate, ok := loadResourceImageByType(resources, "rotate_template"); ok {
			rotated = overlayTemplate(rotated, resizeNearest(rotateTemplate, renderWidth, renderHeight))
		}
		payload.Image = pngDataURL(rotated)
		parameters := cloneParameters(payload.Parameters)
		delete(parameters, "initial_angle")
		payload.Parameters = parameters
	case types.CaptchaConcat:
		background, ok := loadConcatBackgroundResourceImage(resources)
		if !ok {
			return payload
		}
		base := coverResizeNearest(background, payload.View.Width, payload.View.Height)
		composed, piece, splitY := composeConcat(base, answer.Offset, loadConcatTemplate(resources))
		payload.Image = pngDataURL(composed)
		payload.Piece = pngDataURL(piece)
		parameters := cloneParameters(payload.Parameters)
		delete(parameters, "split_x")
		delete(parameters, "initial_offset")
		parameters["min"] = 0
		parameters["max"] = concatControlMax(answer.Offset, payload.View.Width, 0, payload.View.Width)
		parameters["piece_width"] = payload.View.Width + concatMaxMovement
		parameters["split_y"] = splitY
		payload.Parameters = parameters
	case types.CaptchaWordImageClick:
		background, ok := loadBackgroundResourceImage(resources)
		if !ok {
			return payload
		}
		base := coverResizeBilinear(background, payload.View.Width*wordClickRenderScale, payload.View.Height*wordClickRenderScale)
		payload.Image = pngDataURL(composeWordImage(base, payload.Words, scalePoints(answer.Points, wordClickRenderScale), loadFontOptions(resources)))
	case types.CaptchaImageClick:
		background, ok := loadBackgroundResourceImage(resources)
		if !ok {
			return payload
		}
		base := coverResizeBilinear(background, payload.View.Width*iconClickRenderScale, payload.View.Height*iconClickRenderScale)
		image, words := composeIconClickImage(base, payload, answer.Points, resources)
		payload.Image = pngDataURL(image)
		if len(words) > 0 {
			payload.Words = words
			payload.Prompt = "依次点击：" + strings.Join(words, "、")
		}
	case types.CaptchaJigsaw:
		background, ok := loadJigsawBackgroundResourceImage(resources)
		if !ok {
			return payload
		}
		base := coverResizeNearest(background, payload.View.Width, payload.View.Height)
		payload.Image = pngDataURL(composeJigsawImage(base, answer, payload.Parameters))
	}
	return payload
}

func loadResourceImageByType(resources []types.CaptchaResource, resourceType string) (image.Image, bool) {
	items := loadResourceImagesByType(resources, resourceType)
	if len(items) == 0 {
		return nil, false
	}
	return items[randomIndex(len(items))].Image, true
}

func loadBackgroundResourceImage(resources []types.CaptchaResource) (image.Image, bool) {
	return loadTypedBackgroundResourceImage(resources, "background_image", "background_library")
}

func loadConcatBackgroundResourceImage(resources []types.CaptchaResource) (image.Image, bool) {
	return loadTypedBackgroundResourceImage(resources, "concat_background_image", "concat_background_library")
}

func loadJigsawBackgroundResourceImage(resources []types.CaptchaResource) (image.Image, bool) {
	return loadTypedBackgroundResourceImage(resources, "jigsaw_background_image", "jigsaw_background_library")
}

func loadTypedBackgroundResourceImage(resources []types.CaptchaResource, singleType, libraryType string) (image.Image, bool) {
	singleItems := loadResourceImagesByType(resources, singleType)
	libraryItems := loadResourceImagesByType(resources, libraryType)
	if img, ok := chooseLoadedImage(nonEmbeddedResources(singleItems)); ok {
		return img, true
	}
	if img, ok := chooseLoadedImage(nonEmbeddedResources(libraryItems)); ok {
		return img, true
	}
	if img, ok := chooseLoadedImage(singleItems); ok {
		return img, true
	}
	return chooseLoadedImage(libraryItems)
}

func loadRotateResourceImage(resources []types.CaptchaResource) (image.Image, bool) {
	if img, ok := loadResourceImageByType(resources, "rotate_library"); ok {
		return img, true
	}
	return loadBackgroundResourceImage(resources)
}

type loadedImageResource struct {
	Resource types.CaptchaResource
	Image    image.Image
}

func loadResourceImagesByType(resources []types.CaptchaResource, resourceType string) []loadedImageResource {
	images := make([]loadedImageResource, 0)
	for _, item := range resources {
		if item.ResourceType != resourceType || !strings.EqualFold(item.Status, "active") {
			continue
		}
		img, ok := loadStoredResourceImage(item)
		if ok {
			images = append(images, loadedImageResource{Resource: item, Image: img})
		}
	}
	return images
}

func chooseLoadedImage(items []loadedImageResource) (image.Image, bool) {
	if len(items) == 0 {
		return nil, false
	}
	return items[randomIndex(len(items))].Image, true
}

func nonEmbeddedResources(items []loadedImageResource) []loadedImageResource {
	out := make([]loadedImageResource, 0, len(items))
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Resource.StorageType), "embedded") {
			continue
		}
		out = append(out, item)
	}
	return out
}

func composeGridImageFromCategoryLibrary(payload types.RenderPayload, answer types.Answer, resources []types.CaptchaResource) (image.Image, string, bool) {
	library := loadResourceImagesByType(resources, "grid_category_library")
	if len(library) < 2 {
		return nil, "", false
	}

	byCategory := make(map[string][]loadedImageResource)
	labels := make(map[string]string)
	for _, item := range library {
		category, label, ok := gridResourceCategory(item.Resource.Metadata)
		if !ok {
			continue
		}
		byCategory[category] = append(byCategory[category], item)
		if labels[category] == "" {
			labels[category] = label
		}
	}
	if len(byCategory) < 2 {
		return nil, "", false
	}

	cols := renderParameterInt(payload.Parameters, "tile_cols", 3)
	rows := renderParameterInt(payload.Parameters, "tile_rows", 3)
	if cols <= 0 || rows <= 0 {
		return nil, "", false
	}
	tileWidth := renderParameterInt(payload.Parameters, "tile_width", payload.View.Width/cols)
	tileHeight := renderParameterInt(payload.Parameters, "tile_height", payload.View.Height/rows)
	if tileWidth <= 0 || tileHeight <= 0 {
		return nil, "", false
	}
	width := cols * tileWidth
	height := rows * tileHeight
	targets := gridTargetIndexes(answer.Points, cols, rows, tileWidth, tileHeight)
	if len(targets) == 0 || len(targets) >= cols*rows {
		return nil, "", false
	}

	targetCategory, ok := chooseGridTargetCategory(byCategory)
	if !ok {
		return nil, "", false
	}
	targetLabel := labels[targetCategory]
	if targetLabel == "" {
		targetLabel = targetCategory
	}
	decoys := make([]loadedImageResource, 0, len(library))
	for category, items := range byCategory {
		if category == targetCategory {
			continue
		}
		decoys = append(decoys, items...)
	}
	if len(decoys) == 0 {
		return nil, "", false
	}

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	fillRect(img, 0, 0, width, height, color.RGBA{R: 248, G: 250, B: 252, A: 255})
	targetImages := chooseGridImages(byCategory[targetCategory], len(targets))
	decoyImages := chooseGridImages(decoys, cols*rows-len(targets))
	targetIndex := 0
	decoyIndex := 0
	for row := 0; row < rows; row++ {
		for col := 0; col < cols; col++ {
			index := row*cols + col
			rect := image.Rect(col*tileWidth, row*tileHeight, (col+1)*tileWidth, (row+1)*tileHeight)
			if _, ok := targets[index]; ok {
				tile := targetImages[targetIndex]
				targetIndex++
				draw.Draw(img, rect, resizeNearest(tile.Image, tileWidth, tileHeight), image.Point{}, draw.Src)
				continue
			}
			tile := decoyImages[decoyIndex]
			decoyIndex++
			draw.Draw(img, rect, resizeNearest(tile.Image, tileWidth, tileHeight), image.Point{}, draw.Src)
		}
	}
	for x := tileWidth; x < width; x += tileWidth {
		fillRect(img, x-1, 0, 3, height, color.RGBA{R: 255, G: 255, B: 255, A: 255})
	}
	for y := tileHeight; y < height; y += tileHeight {
		fillRect(img, 0, y-1, width, 3, color.RGBA{R: 255, G: 255, B: 255, A: 255})
	}
	strokeRect(img, 0, 0, width, height, 1, color.RGBA{R: 203, G: 213, B: 225, A: 255})
	return img, targetLabel, true
}

func chooseGridImages(pool []loadedImageResource, count int) []loadedImageResource {
	if len(pool) == 0 || count <= 0 {
		return nil
	}
	out := make([]loadedImageResource, 0, count)
	for _, index := range randomIndexes(len(pool), min(count, len(pool))) {
		out = append(out, pool[index])
	}
	for len(out) < count {
		out = append(out, pool[randomIndex(len(pool))])
	}
	return out
}

func gridResourceCategory(metadata map[string]any) (string, string, bool) {
	category, ok := metadataString(metadata, "category", "class", "object", "name")
	if !ok {
		return "", "", false
	}
	category = strings.TrimSpace(category)
	if category == "" {
		return "", "", false
	}
	label, ok := metadataString(metadata, "label", "title", "display_name")
	if !ok || strings.TrimSpace(label) == "" {
		label = category
	}
	return strings.ToLower(category), strings.TrimSpace(label), true
}

func gridTargetIndexes(points []types.Point, cols, rows, tileWidth, tileHeight int) map[int]struct{} {
	targets := make(map[int]struct{}, len(points))
	for _, point := range points {
		col := clamp(point.X/tileWidth, 0, cols-1)
		row := clamp(point.Y/tileHeight, 0, rows-1)
		targets[row*cols+col] = struct{}{}
	}
	return targets
}

func chooseGridTargetCategory(byCategory map[string][]loadedImageResource) (string, bool) {
	candidates := make([]string, 0, len(byCategory))
	for category, items := range byCategory {
		if len(items) > 0 {
			candidates = append(candidates, category)
		}
	}
	if len(candidates) == 0 {
		return "", false
	}
	return candidates[randomIndex(len(candidates))], true
}

func loadStoredResourceImage(resource types.CaptchaResource) (image.Image, bool) {
	if strings.EqualFold(strings.TrimSpace(resource.StorageType), "embedded") {
		return loadEmbeddedResourceImage(resource)
	}
	data, contentType, ok := loadStoredResourceBytes(resource)
	if !ok {
		return nil, false
	}
	return decodeResourceImage(resource, data, contentType)
}

func loadStoredResourceBytes(resource types.CaptchaResource) ([]byte, string, bool) {
	switch strings.ToLower(strings.TrimSpace(resource.StorageType)) {
	case "embedded":
		return loadEmbeddedResourceBytes(resource)
	case "file":
		return loadFileResourceBytes(resource)
	case "classpath":
		return loadClasspathResourceBytes(resource)
	case "url":
		return loadURLResourceBytes(resource)
	case "object_storage":
		return loadObjectStorageResourceBytes(resource)
	case "database":
		return loadDatabaseResourceBytes(resource)
	default:
		return nil, "", false
	}
}

func StoredResourceBytes(resource types.CaptchaResource) ([]byte, string, bool) {
	return loadStoredResourceBytes(resource)
}

func scaleSliderAnswer(answer types.Answer, scale int) types.Answer {
	if scale <= 1 {
		return answer
	}
	answer.X *= scale
	answer.Y *= scale
	return answer
}

func loadEmbeddedResourceImage(resource types.CaptchaResource) (image.Image, bool) {
	name, ok := embeddedResourceName(resource.URI)
	if !ok {
		return nil, false
	}
	width, height := embeddedResourceSize(resource)
	switch name {
	case "default-backgrounds", "backgrounds":
		return drawEmbeddedDefaultBackground(width, height), true
	case "concat-backgrounds":
		return drawEmbeddedConcatBackground(width, height), true
	case "jigsaw-backgrounds":
		return drawEmbeddedJigsawBackground(width, height), true
	case "rotate-backgrounds":
		size := min(width, height)
		return drawEmbeddedRotateBackground(size), true
	case "slider-template":
		return defaultSliderTemplateFactory(min(width, height)), true
	default:
		return nil, false
	}
}

func loadEmbeddedResourceBytes(resource types.CaptchaResource) ([]byte, string, bool) {
	name, ok := embeddedResourceName(resource.URI)
	if !ok {
		return nil, "", false
	}
	if name == "concat-template" {
		return []byte(`{"split_ratio":0.5,"gap_color":"#e2e8f0","border_color":"#6366f1"}`), "application/json", true
	}
	img, ok := loadEmbeddedResourceImage(resource)
	if !ok {
		return nil, "", false
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, "", false
	}
	return buf.Bytes(), "image/png", true
}

func embeddedResourceName(uri string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(uri))
	if err != nil || !strings.EqualFold(parsed.Scheme, "embedded") || parsed.User != nil {
		return "", false
	}
	parts := make([]string, 0, 2)
	if parsed.Host != "" {
		parts = append(parts, parsed.Host)
	}
	if path := strings.Trim(strings.TrimPrefix(parsed.Path, "/"), "/"); path != "" {
		parts = append(parts, path)
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.ToLower(strings.Join(parts, "/")), true
}

func embeddedResourceSize(resource types.CaptchaResource) (int, int) {
	width := 0
	height := 0
	if value, ok, err := metadataInt(cloneMetadata(resource.Metadata), "width"); err == nil && ok {
		width = int(value)
	}
	if value, ok, err := metadataInt(cloneMetadata(resource.Metadata), "height"); err == nil && ok {
		height = int(value)
	}
	if width > 0 && height > 0 {
		return clamp(width, 32, 1024), clamp(height, 32, 1024)
	}
	switch strings.ToLower(strings.TrimSpace(resource.ResourceType)) {
	case "rotate_library":
		return 220, 220
	case "slider_template":
		return 96, 96
	case "grid_category_library":
		return 120, 120
	default:
		return 320, 180
	}
}

func drawEmbeddedDefaultBackground(width, height int) *image.RGBA {
	img := gradientCanvas(width, height, color.RGBA{R: 75, G: 97, B: 176, A: 255}, color.RGBA{R: 247, G: 209, B: 151, A: 255})
	drawCircleOver(img, int(float64(width)*0.78), int(float64(height)*0.30), max(8, width/18), color.RGBA{R: 255, G: 234, B: 156, A: 230})
	fillPolygonOver(img, []image.Point{
		{X: 0, Y: int(float64(height) * 0.70)},
		{X: int(float64(width) * 0.30), Y: int(float64(height) * 0.42)},
		{X: int(float64(width) * 0.60), Y: int(float64(height) * 0.73)},
		{X: width, Y: int(float64(height) * 0.48)},
		{X: width, Y: height},
		{X: 0, Y: height},
	}, color.RGBA{R: 39, G: 56, B: 112, A: 210})
	fillPolygonOver(img, []image.Point{
		{X: 0, Y: int(float64(height) * 0.82)},
		{X: int(float64(width) * 0.42), Y: int(float64(height) * 0.58)},
		{X: int(float64(width) * 0.74), Y: int(float64(height) * 0.80)},
		{X: width, Y: int(float64(height) * 0.68)},
		{X: width, Y: height},
		{X: 0, Y: height},
	}, color.RGBA{R: 21, G: 31, B: 62, A: 205})
	for i := 0; i < 26; i++ {
		x := randomIndex(max(1, width))
		y := randomIndex(max(1, int(float64(height)*0.58)))
		drawCircleOver(img, x, y, max(1, width/180), color.RGBA{R: 255, G: 255, B: 255, A: uint8(90 + randomIndex(120))})
	}
	return img
}

func drawEmbeddedConcatBackground(width, height int) *image.RGBA {
	img := gradientCanvas(width, height, color.RGBA{R: 236, G: 246, B: 255, A: 255}, color.RGBA{R: 210, G: 229, B: 247, A: 255})
	horizon := int(float64(height) * 0.56)
	fillPolygonOver(img, []image.Point{
		{X: 0, Y: horizon + height/12},
		{X: width / 5, Y: horizon - height/8},
		{X: width / 2, Y: horizon + height/10},
		{X: width * 3 / 4, Y: horizon - height/7},
		{X: width, Y: horizon + height/12},
		{X: width, Y: height},
		{X: 0, Y: height},
	}, color.RGBA{R: 116, G: 136, B: 164, A: 95})
	drawPolylineOver(img, smoothWave(width, horizon, height/13, 12), max(3, height/30), color.RGBA{R: 67, G: 92, B: 124, A: 135})
	drawPolylineOver(img, smoothWave(width, horizon+height/12, height/16, 10), max(2, height/42), color.RGBA{R: 255, G: 255, B: 255, A: 180})
	drawCircleOver(img, width*72/100, horizon-height/8, max(8, height/9), color.RGBA{R: 246, G: 173, B: 85, A: 175})
	for i := 0; i < 7; i++ {
		x := width * (10 + i*13) / 100
		fillRectOver(img, x, 0, max(1, width/90), height, color.RGBA{R: 255, G: 255, B: 255, A: 36})
	}
	return img
}

func drawEmbeddedJigsawBackground(width, height int) *image.RGBA {
	img := gradientCanvas(width, height, color.RGBA{R: 241, G: 245, B: 249, A: 255}, color.RGBA{R: 219, G: 234, B: 254, A: 255})
	palette := []color.RGBA{
		{R: 37, G: 99, B: 235, A: 180},
		{R: 20, G: 184, B: 166, A: 172},
		{R: 245, G: 158, B: 11, A: 176},
		{R: 225, G: 29, B: 72, A: 160},
		{R: 126, G: 34, B: 206, A: 156},
	}
	drawCircleOver(img, width/5, height/3, max(12, height/8), palette[0])
	fillRectOver(img, width*3/5, height/7, width/5, height/4, palette[1])
	fillPolygonOver(img, []image.Point{{X: width * 3 / 10, Y: height * 3 / 4}, {X: width / 2, Y: height / 2}, {X: width * 7 / 10, Y: height * 3 / 4}}, palette[2])
	drawPolylineOver(img, []image.Point{{X: width / 12, Y: height * 5 / 6}, {X: width / 4, Y: height * 2 / 3}, {X: width * 2 / 5, Y: height * 7 / 8}, {X: width * 5 / 6, Y: height * 3 / 5}}, max(5, height/18), palette[3])
	drawCircleOutlineOver(img, width*83/100, height*70/100, max(14, height/7), max(3, height/45), palette[4])
	for i := 0; i < 16; i++ {
		drawCircleOver(img, randomIndex(max(1, width)), randomIndex(max(1, height)), max(1, height/80), color.RGBA{R: 15, G: 23, B: 42, A: 55})
	}
	return img
}

func drawEmbeddedRotateBackground(size int) *image.RGBA {
	img := gradientCanvas(size, size, color.RGBA{R: 234, G: 249, B: 255, A: 255}, color.RGBA{R: 255, G: 237, B: 213, A: 255})
	cx, cy := size/2, size/2
	drawCircleOver(img, cx, cy, size*38/100, color.RGBA{R: 255, G: 255, B: 255, A: 150})
	drawPolylineOver(img, []image.Point{{X: cx - size/5, Y: cy + size/4}, {X: cx, Y: cy - size/3}, {X: cx + size/4, Y: cy + size/5}}, max(6, size/28), color.RGBA{R: 37, G: 99, B: 235, A: 220})
	drawCircleOver(img, cx+size/8, cy-size/12, max(8, size/12), color.RGBA{R: 245, G: 158, B: 11, A: 220})
	fillPolygonOver(img, []image.Point{{X: cx - size/9, Y: cy - size/7}, {X: cx + size/3, Y: cy}, {X: cx - size/12, Y: cy + size/6}}, color.RGBA{R: 20, G: 184, B: 166, A: 190})
	return img
}

func gradientCanvas(width, height int, top, bottom color.RGBA) *image.RGBA {
	width = max(1, width)
	height = max(1, height)
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	denom := max(1, height-1)
	for y := 0; y < height; y++ {
		ratio := float64(y) / float64(denom)
		c := mixRGBA(top, bottom, ratio)
		fillRect(img, 0, y, width, 1, c)
	}
	return img
}

func smoothWave(width, centerY, amplitude, steps int) []image.Point {
	steps = max(2, steps)
	points := make([]image.Point, 0, steps+1)
	for i := 0; i <= steps; i++ {
		x := width * i / steps
		y := centerY + int(math.Round(math.Sin(float64(i)*math.Pi*2/float64(steps))*float64(amplitude)))
		points = append(points, image.Point{X: x, Y: y})
	}
	return points
}

func loadFileResourceBytes(resource types.CaptchaResource) ([]byte, string, bool) {
	path, ok := localFilePath(resource.URI)
	if !ok {
		return nil, "", false
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, "", false
	}
	defer file.Close()

	data, ok := readBoundedResourceBytes(file)
	if !ok {
		return nil, "", false
	}
	if resource.Checksum != "" && !matchesSHA256(data, resource.Checksum) {
		return nil, "", false
	}
	return data, "", true
}

func loadClasspathResourceBytes(resource types.CaptchaResource) ([]byte, string, bool) {
	name, ok := classpathResourceName(resource.URI)
	if !ok {
		return nil, "", false
	}
	for _, root := range classpathRoots() {
		path, ok := safeJoinClasspathRoot(root, name)
		if !ok {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		data, ok := readBoundedResourceBytes(file)
		_ = file.Close()
		if !ok {
			continue
		}
		if resource.Checksum != "" && !matchesSHA256(data, resource.Checksum) {
			continue
		}
		return data, "", true
	}
	return nil, "", false
}

func loadURLResourceBytes(resource types.CaptchaResource) ([]byte, string, bool) {
	return loadRemoteResourceBytes(resource, resource.URI)
}

func loadRemoteResourceBytes(resource types.CaptchaResource, rawURL string) ([]byte, string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || unsafeRemoteURL(parsed) {
		return nil, "", false
	}
	req, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, "", false
	}
	req.Header.Set("Accept", "image/png,image/jpeg,image/webp,image/gif,application/json;q=0.8,*/*;q=0.1")
	response, err := resourceHTTPClient.Do(req)
	if err != nil {
		return nil, "", false
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, "", false
	}
	contentType := response.Header.Get("Content-Type")
	if !allowedResourceContentType(resource, contentType) {
		return nil, "", false
	}
	data, ok := readBoundedResourceBytes(response.Body)
	if !ok {
		return nil, "", false
	}
	if resource.Checksum != "" && !matchesSHA256(data, resource.Checksum) {
		return nil, "", false
	}
	return data, contentType, true
}

func loadObjectStorageResourceBytes(resource types.CaptchaResource) ([]byte, string, bool) {
	if directURL, ok := metadataString(resource.Metadata, "public_url", "signed_url", "presigned_url", "object_url"); ok {
		return loadRemoteResourceBytes(resource, directURL)
	}
	httpURL, ok := objectStorageHTTPURL(resource)
	if !ok {
		return nil, "", false
	}
	return loadRemoteResourceBytes(resource, httpURL)
}

func objectStorageHTTPURL(resource types.CaptchaResource) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(resource.URI))
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return "", false
	}
	bucket := parsed.Hostname()
	if !validObjectStorageBucket(bucket) {
		return "", false
	}
	objectKey := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if objectKey == "" {
		return "", false
	}
	endpoint, ok := metadataString(resource.Metadata, "endpoint", "endpoint_url", "base_url", "public_endpoint")
	if !ok {
		return "", false
	}
	base, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || unsafeRemoteURL(base) {
		return "", false
	}
	if useVirtualHostedObjectStyle(resource.Metadata) {
		base.Host = bucket + "." + base.Host
		base.Path = joinURLPath(base.EscapedPath(), objectKey)
	} else {
		base.Path = joinURLPath(base.EscapedPath(), bucket, objectKey)
	}
	return base.String(), true
}

func validObjectStorageBucket(bucket string) bool {
	if bucket == "" || len(bucket) > 128 {
		return false
	}
	for _, char := range bucket {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' {
			continue
		}
		return false
	}
	return true
}

func useVirtualHostedObjectStyle(metadata map[string]any) bool {
	value, ok := metadataString(metadata, "addressing_style", "style")
	if !ok {
		return false
	}
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized == "virtual" || normalized == "virtual_host" || normalized == "virtual_hosted" || normalized == "virtual-hosted"
}

func joinURLPath(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.Trim(part, "/")
		if part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return "/"
	}
	return "/" + strings.Join(out, "/")
}

func loadDatabaseResourceBytes(resource types.CaptchaResource) ([]byte, string, bool) {
	if dataURL, ok := metadataString(resource.Metadata, "data_url", "data_uri"); ok {
		data, contentType, ok := parseDataURL(dataURL)
		if !ok || len(data) == 0 || len(data) > maxResourceImageBytes {
			return nil, "", false
		}
		if resource.Checksum != "" && !matchesSHA256(data, resource.Checksum) {
			return nil, "", false
		}
		return data, contentType, true
	}
	encoded, ok := metadataString(resource.Metadata, "base64", "data_base64", "content_base64")
	if !ok {
		return nil, "", false
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, "", false
	}
	if len(data) == 0 || len(data) > maxResourceImageBytes {
		return nil, "", false
	}
	if resource.Checksum != "" && !matchesSHA256(data, resource.Checksum) {
		return nil, "", false
	}
	contentType, _ := metadataString(resource.Metadata, "mime_type", "content_type")
	return data, contentType, true
}

func parseDataURL(value string) ([]byte, string, bool) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "data:") {
		return nil, "", false
	}
	parts := strings.SplitN(strings.TrimPrefix(value, "data:"), ",", 2)
	if len(parts) != 2 {
		return nil, "", false
	}
	header := parts[0]
	contentType := ""
	if header != "" {
		fields := strings.Split(header, ";")
		contentType = fields[0]
	}
	if !strings.Contains(header, ";base64") {
		return nil, "", false
	}
	data, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", false
	}
	return data, contentType, true
}

func unsafeRemoteURL(parsed *url.URL) bool {
	return parsed == nil ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.Hostname() == "" ||
		parsed.User != nil ||
		isUnsafeRemoteHost(parsed.Hostname())
}

func allowedResourceContentType(resource types.CaptchaResource, value string) bool {
	if strings.TrimSpace(value) == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	if err := validateMIMEType(resource.ResourceType, mediaType); err != nil {
		return false
	}
	if expected, ok := metadataString(resource.Metadata, "mime_type", "content_type"); ok {
		return strings.EqualFold(strings.TrimSpace(expected), mediaType)
	}
	return true
}

func decodeResourceImage(resource types.CaptchaResource, data []byte, contentType string) (image.Image, bool) {
	if looksLikeSVG(data, contentType, resource.Metadata) {
		return decodeSVGResourceImage(resource, data, contentType)
	}
	img, format, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	actualMIME := imageFormatMIME(format)
	if actualMIME == "" {
		return nil, false
	}
	if err := validateMIMEType(resource.ResourceType, actualMIME); err != nil {
		return nil, false
	}
	if mediaType := normalizedMediaType(contentType); mediaType != "" && !strings.EqualFold(mediaType, actualMIME) {
		return nil, false
	}
	if expected, ok := metadataString(resource.Metadata, "mime_type", "content_type"); ok && !strings.EqualFold(strings.TrimSpace(expected), actualMIME) {
		return nil, false
	}
	if !matchesDeclaredDimension(resource.Metadata, "width", img.Bounds().Dx()) {
		return nil, false
	}
	if !matchesDeclaredDimension(resource.Metadata, "height", img.Bounds().Dy()) {
		return nil, false
	}
	return img, true
}

func looksLikeSVG(data []byte, contentType string, metadata map[string]any) bool {
	if strings.EqualFold(normalizedMediaType(contentType), "image/svg+xml") {
		return true
	}
	if expected, ok := metadataString(metadata, "mime_type", "content_type"); ok && strings.EqualFold(strings.TrimSpace(expected), "image/svg+xml") {
		return true
	}
	sniff := strings.ToLower(string(data[:min(len(data), 256)]))
	return strings.Contains(sniff, "<svg")
}

func decodeSVGResourceImage(resource types.CaptchaResource, data []byte, contentType string) (image.Image, bool) {
	const actualMIME = "image/svg+xml"
	if err := validateMIMEType(resource.ResourceType, actualMIME); err != nil {
		return nil, false
	}
	if mediaType := normalizedMediaType(contentType); mediaType != "" && !strings.EqualFold(mediaType, actualMIME) {
		return nil, false
	}
	if expected, ok := metadataString(resource.Metadata, "mime_type", "content_type"); ok && !strings.EqualFold(strings.TrimSpace(expected), actualMIME) {
		return nil, false
	}
	size := svgRenderSize(resource)
	icon, err := oksvg.ReadIconStream(bytes.NewReader(data), oksvg.StrictErrorMode)
	if err != nil {
		return nil, false
	}
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	padding := math.Max(0, math.Round(float64(size)*0.04))
	icon.SetTarget(padding, padding, float64(size)-padding*2, float64(size)-padding*2)
	scanner := rasterx.NewScannerGV(size, size, img, img.Bounds())
	raster := rasterx.NewDasher(size, size, scanner)
	icon.Draw(raster, 1)
	return img, true
}

func svgRenderSize(resource types.CaptchaResource) int {
	if value, ok, err := metadataInt(cloneMetadata(resource.Metadata), "width", "height", "size"); err == nil && ok && value > 0 {
		return clamp(int(value), 16, 512)
	}
	switch strings.ToLower(strings.TrimSpace(resource.ResourceType)) {
	case "background_image", "background_library", "concat_background_image", "concat_background_library", "jigsaw_background_image", "jigsaw_background_library":
		return 320
	case "rotate_library":
		return 220
	case "grid_category_library":
		return 120
	default:
		return 128
	}
}

func imageFormatMIME(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "gif":
		return "image/gif"
	case "jpeg":
		return "image/jpeg"
	case "png":
		return "image/png"
	case "webp":
		return "image/webp"
	default:
		return ""
	}
}

func normalizedMediaType(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(mediaType))
}

func matchesDeclaredDimension(metadata map[string]any, key string, actual int) bool {
	if len(metadata) == 0 {
		return true
	}
	expected, ok, err := metadataInt(cloneMetadata(metadata), key)
	if err != nil {
		return false
	}
	return !ok || int(expected) == actual
}

func readBoundedResourceBytes(reader io.Reader) ([]byte, bool) {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(reader, maxResourceImageBytes+1)); err != nil {
		return nil, false
	}
	data := buf.Bytes()
	return data, len(data) > 0 && len(data) <= maxResourceImageBytes
}

func classpathResourceName(value string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "classpath" || parsed.User != nil {
		return "", false
	}
	parts := make([]string, 0, 2)
	if parsed.Host != "" {
		parts = append(parts, parsed.Host)
	}
	if path := strings.TrimPrefix(parsed.Path, "/"); path != "" {
		parts = append(parts, path)
	}
	if len(parts) == 0 {
		return "", false
	}
	name, err := url.PathUnescape(strings.Join(parts, "/"))
	if err != nil {
		return "", false
	}
	name = filepath.Clean(filepath.FromSlash(name))
	if name == "." || filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
		return "", false
	}
	return name, true
}

func classpathRoots() []string {
	configured := strings.TrimSpace(os.Getenv("CAPTCHA_RESOURCE_CLASSPATH_DIRS"))
	if configured == "" {
		return []string{"resources", "configs/resources"}
	}
	fields := strings.FieldsFunc(configured, func(r rune) bool {
		return r == ',' || r == rune(os.PathListSeparator)
	})
	roots := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			roots = append(roots, field)
		}
	}
	if len(roots) == 0 {
		return []string{"resources", "configs/resources"}
	}
	return roots
}

func safeJoinClasspathRoot(root, name string) (string, bool) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", false
	}
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	candidate, err := filepath.Abs(filepath.Join(cleanRoot, name))
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(cleanRoot, candidate)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return candidate, true
}

func localFilePath(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	if strings.HasPrefix(value, "file://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Path == "" || parsed.Host != "" {
			return "", false
		}
		return parsed.Path, true
	}
	if strings.HasPrefix(value, "/") {
		return value, true
	}
	return "", false
}

func matchesSHA256(data []byte, checksum string) bool {
	checksum = strings.ToLower(strings.TrimSpace(checksum))
	checksum = strings.TrimPrefix(checksum, "sha256:")
	if len(checksum) != 64 {
		return false
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == checksum
}

func resizeNearest(src image.Image, width, height int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	bounds := src.Bounds()
	srcWidth := bounds.Dx()
	srcHeight := bounds.Dy()
	if srcWidth <= 0 || srcHeight <= 0 {
		return dst
	}
	for y := 0; y < height; y++ {
		sy := bounds.Min.Y + y*srcHeight/height
		for x := 0; x < width; x++ {
			sx := bounds.Min.X + x*srcWidth/width
			dst.Set(x, y, src.At(sx, sy))
		}
	}
	return dst
}

func coverResizeNearest(src image.Image, width, height int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	crop := coverCropRect(src.Bounds(), width, height)
	cropWidth := crop.Dx()
	cropHeight := crop.Dy()
	if width <= 0 || height <= 0 || cropWidth <= 0 || cropHeight <= 0 {
		return dst
	}
	for y := 0; y < height; y++ {
		sy := crop.Min.Y + y*cropHeight/height
		for x := 0; x < width; x++ {
			sx := crop.Min.X + x*cropWidth/width
			dst.Set(x, y, src.At(sx, sy))
		}
	}
	return dst
}

func resizeBilinear(src image.Image, width, height int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	bounds := src.Bounds()
	srcWidth := bounds.Dx()
	srcHeight := bounds.Dy()
	if width <= 0 || height <= 0 || srcWidth <= 0 || srcHeight <= 0 {
		return dst
	}
	for y := 0; y < height; y++ {
		sy := float64(bounds.Min.Y) + (float64(y)+0.5)*float64(srcHeight)/float64(height) - 0.5
		for x := 0; x < width; x++ {
			sx := float64(bounds.Min.X) + (float64(x)+0.5)*float64(srcWidth)/float64(width) - 0.5
			dst.SetRGBA(x, y, sampleBilinearRGBA(src, sx, sy))
		}
	}
	return dst
}

func coverResizeBilinear(src image.Image, width, height int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	crop := coverCropRect(src.Bounds(), width, height)
	cropWidth := crop.Dx()
	cropHeight := crop.Dy()
	if width <= 0 || height <= 0 || cropWidth <= 0 || cropHeight <= 0 {
		return dst
	}
	for y := 0; y < height; y++ {
		sy := float64(crop.Min.Y) + (float64(y)+0.5)*float64(cropHeight)/float64(height) - 0.5
		for x := 0; x < width; x++ {
			sx := float64(crop.Min.X) + (float64(x)+0.5)*float64(cropWidth)/float64(width) - 0.5
			dst.SetRGBA(x, y, sampleBilinearRGBA(src, sx, sy))
		}
	}
	return dst
}

func coverCropRect(bounds image.Rectangle, width, height int) image.Rectangle {
	srcWidth := bounds.Dx()
	srcHeight := bounds.Dy()
	if width <= 0 || height <= 0 || srcWidth <= 0 || srcHeight <= 0 {
		return image.Rect(bounds.Min.X, bounds.Min.Y, bounds.Min.X, bounds.Min.Y)
	}
	targetRatio := float64(width) / float64(height)
	sourceRatio := float64(srcWidth) / float64(srcHeight)
	if sourceRatio > targetRatio {
		cropWidth := clamp(int(math.Round(float64(srcHeight)*targetRatio)), 1, srcWidth)
		x0 := bounds.Min.X + (srcWidth-cropWidth)/2
		return image.Rect(x0, bounds.Min.Y, x0+cropWidth, bounds.Max.Y)
	}
	cropHeight := clamp(int(math.Round(float64(srcWidth)/targetRatio)), 1, srcHeight)
	y0 := bounds.Min.Y + (srcHeight-cropHeight)/2
	return image.Rect(bounds.Min.X, y0, bounds.Max.X, y0+cropHeight)
}

func resizeAlphaMask(src image.Image, width, height int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	bounds := src.Bounds()
	srcWidth := bounds.Dx()
	srcHeight := bounds.Dy()
	if width <= 0 || height <= 0 || srcWidth <= 0 || srcHeight <= 0 {
		return dst
	}
	scaleX := float64(srcWidth) / float64(width)
	scaleY := float64(srcHeight) / float64(height)
	for y := 0; y < height; y++ {
		sourceY := (float64(y)+0.5)*scaleY - 0.5
		y0 := clamp(bounds.Min.Y+int(math.Floor(sourceY)), bounds.Min.Y, bounds.Max.Y-1)
		y1 := clamp(y0+1, bounds.Min.Y, bounds.Max.Y-1)
		wy := sourceY - math.Floor(sourceY)
		for x := 0; x < width; x++ {
			sourceX := (float64(x)+0.5)*scaleX - 0.5
			x0 := clamp(bounds.Min.X+int(math.Floor(sourceX)), bounds.Min.X, bounds.Max.X-1)
			x1 := clamp(x0+1, bounds.Min.X, bounds.Max.X-1)
			wx := sourceX - math.Floor(sourceX)
			alpha := bilinearAlpha(src, x0, y0, x1, y1, wx, wy)
			dst.SetRGBA(x, y, color.RGBA{R: alpha, G: alpha, B: alpha, A: alpha})
		}
	}
	return dst
}

func bilinearAlpha(src image.Image, x0, y0, x1, y1 int, wx, wy float64) uint8 {
	a00 := float64(colorAlpha(src.At(x0, y0)))
	a10 := float64(colorAlpha(src.At(x1, y0)))
	a01 := float64(colorAlpha(src.At(x0, y1)))
	a11 := float64(colorAlpha(src.At(x1, y1)))
	top := a00*(1-wx) + a10*wx
	bottom := a01*(1-wx) + a11*wx
	return uint8(math.Round(top*(1-wy) + bottom*wy))
}

func composeSlider(base *image.RGBA, answer types.Answer, template image.Image, size int) (*image.RGBA, *image.RGBA) {
	img := cloneRGBA(base)
	size = clamp(size, 16, min(img.Bounds().Dx(), img.Bounds().Dy()))
	x := clamp(answer.X, 0, img.Bounds().Dx()-size)
	y := clamp(answer.Y, 0, img.Bounds().Dy()-size)
	if template == nil {
		template = defaultSliderTemplateFactory(size)
	}
	mask := resizeAlphaMask(template, size, size)
	piece := image.NewRGBA(image.Rect(0, 0, size, size))
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			alpha := colorAlpha(mask.At(px, py))
			if alpha <= 4 {
				continue
			}
			source := rgbaAt(base, x+px, y+py)
			if alpha > sliderMaskSolidAlpha {
				img.Set(x+px, y+py, sliderBlackMaskPixel(source, sliderMaskOpacity))
			}
			border := sliderTemplateEdgeBandStrength(mask, px, py, sliderBorderRadius)
			piecePixel := sliderPiecePixel(source, border)
			piece.Set(px, py, color.NRGBA{R: piecePixel.R, G: piecePixel.G, B: piecePixel.B, A: alpha})
		}
	}
	return img, piece
}

func sliderBlackMaskPixel(source color.RGBA, opacity float64) color.RGBA {
	return mixRGBA(source, color.RGBA{A: 255}, clampFloat(opacity, 0, 1))
}

func sliderPiecePixel(source color.RGBA, border float64) color.RGBA {
	if border > 0 {
		return mixRGBA(source, color.RGBA{A: 255}, clampFloat(border*sliderPieceBorderOpacity, 0, sliderPieceBorderOpacity))
	}
	return source
}

func drawSliderGapAmbient(img *image.RGBA, ox, oy, size int, alphaAt func(int, int) uint8) {
	radius := 5
	bounds := img.Bounds()
	for y := -radius; y < size+radius; y++ {
		for x := -radius; x < size+radius; x++ {
			if alphaAt(x, y) > 8 {
				continue
			}
			gx, gy := ox+x, oy+y
			if gx < bounds.Min.X || gx >= bounds.Max.X || gy < bounds.Min.Y || gy >= bounds.Max.Y {
				continue
			}
			strength := 0.0
			for dy := -radius; dy <= radius; dy++ {
				for dx := -radius; dx <= radius; dx++ {
					distance := math.Hypot(float64(dx), float64(dy))
					if distance <= 0 || distance > float64(radius) {
						continue
					}
					alpha := alphaAt(x+dx, y+dy)
					if alpha <= 24 {
						continue
					}
					candidate := float64(alpha) / 255 * (float64(radius) + 0.5 - distance) / float64(radius)
					if candidate > strength {
						strength = candidate
					}
				}
			}
			if strength <= 0 {
				continue
			}
			source := rgbaAt(img, gx, gy)
			lowerRight := clampFloat(0.68+float64(x+y)/(float64(size)*3), 0.52, 1.0)
			pixel := mixRGBA(source, color.RGBA{R: 18, G: 18, B: 18, A: 255}, math.Min(0.22, strength*0.17*lowerRight))
			if x+y < size/2 {
				pixel = mixRGBA(pixel, color.RGBA{R: 255, G: 255, B: 255, A: 255}, strength*0.035)
			}
			img.Set(gx, gy, pixel)
		}
	}
}

func drawSliderPieceShadow(img *image.RGBA, size int, alphaAt func(int, int) uint8) {
	radius := 6
	offsetX := 2
	offsetY := 3
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if alphaAt(x, y) > 8 {
				continue
			}
			strength := 0.0
			for dy := -radius; dy <= radius; dy++ {
				for dx := -radius; dx <= radius; dx++ {
					distance := math.Hypot(float64(dx), float64(dy))
					if distance <= 0 || distance > float64(radius) {
						continue
					}
					alpha := alphaAt(x-offsetX+dx, y-offsetY+dy)
					if alpha <= 24 {
						continue
					}
					candidate := float64(alpha) / 255 * (float64(radius) + 0.5 - distance) / float64(radius)
					if candidate > strength {
						strength = candidate
					}
				}
			}
			if strength <= 0 {
				continue
			}
			alpha := uint8(math.Round(clampFloat(strength*86, 0, 72)))
			img.Set(x, y, color.NRGBA{R: 24, G: 24, B: 24, A: alpha})
		}
	}
}

func composeSliderDecoys(img *image.RGBA, answer types.Answer, template image.Image, size int) *image.RGBA {
	size = clamp(size, 16, min(img.Bounds().Dx(), img.Bounds().Dy()))
	if template == nil {
		template = defaultSliderTemplateFactory(size)
	}
	mask := resizeAlphaMask(template, size, size)
	for _, decoy := range sliderDecoyPointsForImage(img, size) {
		if absInt(decoy.X-answer.X) < size && absInt(decoy.Y-answer.Y) < size {
			continue
		}
		drawSliderMaskGhost(img, mask, decoy.X, decoy.Y, size, sliderMaskOpacity)
	}
	return img
}

func sliderDecoyPointsForImage(img image.Image, size int) []image.Point {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	sideMargin := max(8, int(math.Round(float64(size)*0.38)))
	topMargin := max(8, int(math.Round(float64(size)*0.51)))
	bottomMargin := max(8, int(math.Round(float64(size)*0.47)))
	lowerBand := max(size+bottomMargin, height*8/9)
	return []image.Point{
		{X: sideMargin, Y: topMargin},
		{X: max(0, width-size-sideMargin), Y: max(0, lowerBand-size-bottomMargin)},
	}
}

func drawSliderMaskGhost(img *image.RGBA, mask image.Image, ox, oy, size int, opacity float64) {
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			alpha := colorAlpha(mask.At(x, y))
			gx, gy := ox+x, oy+y
			if !image.Pt(gx, gy).In(img.Bounds()) {
				continue
			}
			if alpha <= sliderMaskSolidAlpha {
				continue
			}
			source := rgbaAt(img, gx, gy)
			img.Set(gx, gy, sliderBlackMaskPixel(source, opacity))
		}
	}
}

func defaultSliderTemplate(size int) image.Image {
	size = clamp(size, 16, 256)
	if len(defaultSliderMaskFiles) > 0 {
		filename := defaultSliderMaskFiles[randomIndex(len(defaultSliderMaskFiles))]
		if mask, ok := renderEmbeddedSliderMask(filename, size); ok {
			return mask
		}
	}
	mask := image.NewRGBA(image.Rect(0, 0, size, size))
	scale := float64(size)
	for y := 0; y < size; y++ {
		ny := (float64(y) + 0.5) / scale
		for x := 0; x < size; x++ {
			nx := (float64(x) + 0.5) / scale
			body := roundedUnitRect(nx, ny, 0.08, 0.18, 0.74, 0.68, 0.12)
			rightKnob := math.Hypot(nx-0.78, ny-0.50) <= 0.17
			topKnob := math.Hypot(nx-0.48, ny-0.18) <= 0.13
			leftBite := math.Hypot(nx-0.09, ny-0.50) <= 0.14
			if (body || rightKnob || topKnob) && !leftBite {
				mask.SetRGBA(x, y, color.RGBA{R: 255, G: 255, B: 255, A: 255})
			}
		}
	}
	return mask
}

func renderEmbeddedSliderMask(filename string, size int) (image.Image, bool) {
	file, err := sliderMaskAssets.Open("assets/slider/" + filename)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	icon, err := oksvg.ReadIconStream(file, oksvg.StrictErrorMode)
	if err != nil {
		return nil, false
	}
	const scale = 6
	renderSize := size * scale
	mask := image.NewRGBA(image.Rect(0, 0, renderSize, renderSize))
	icon.SetTarget(0, 0, float64(renderSize), float64(renderSize))
	scanner := rasterx.NewScannerGV(renderSize, renderSize, mask, mask.Bounds())
	raster := rasterx.NewDasher(renderSize, renderSize, scanner)
	icon.Draw(raster, 1)
	padding := int(math.Max(2, math.Round(float64(renderSize)*0.06)))
	return resizeAlphaMask(normalizeSliderMaskAlpha(mask, padding), size, size), true
}

func normalizeSliderMaskAlpha(src *image.RGBA, padding int) *image.RGBA {
	bounds := src.Bounds()
	dst := image.NewRGBA(bounds)
	minX, minY, maxX, maxY, ok := sliderMaskAlphaBounds(src, 8)
	if !ok {
		return src
	}
	targetMax := min(bounds.Dx(), bounds.Dy()) - padding*2
	if targetMax <= 0 {
		return src
	}
	sourceWidth := maxX - minX + 1
	sourceHeight := maxY - minY + 1
	scale := math.Min(float64(targetMax)/float64(sourceWidth), float64(targetMax)/float64(sourceHeight))
	if scale <= 0 {
		return src
	}
	targetWidth := max(1, int(math.Round(float64(sourceWidth)*scale)))
	targetHeight := max(1, int(math.Round(float64(sourceHeight)*scale)))
	offsetX := bounds.Min.X + (bounds.Dx()-targetWidth)/2
	offsetY := bounds.Min.Y + (bounds.Dy()-targetHeight)/2
	for y := 0; y < targetHeight; y++ {
		sourceY := float64(minY) + (float64(y)+0.5)/scale - 0.5
		for x := 0; x < targetWidth; x++ {
			sourceX := float64(minX) + (float64(x)+0.5)/scale - 0.5
			alpha := sampleMaskAlphaBilinear(src, sourceX, sourceY)
			dst.SetRGBA(offsetX+x, offsetY+y, color.RGBA{R: alpha, G: alpha, B: alpha, A: alpha})
		}
	}
	return dst
}

func sliderMaskAlphaBounds(src image.Image, threshold uint8) (minX, minY, maxX, maxY int, ok bool) {
	bounds := src.Bounds()
	minX, minY = bounds.Max.X, bounds.Max.Y
	maxX, maxY = bounds.Min.X, bounds.Min.Y
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			if colorAlpha(src.At(x, y)) <= threshold {
				continue
			}
			if x < minX {
				minX = x
			}
			if x > maxX {
				maxX = x
			}
			if y < minY {
				minY = y
			}
			if y > maxY {
				maxY = y
			}
			ok = true
		}
	}
	return minX, minY, maxX, maxY, ok
}

func sampleMaskAlphaBilinear(src image.Image, x, y float64) uint8 {
	bounds := src.Bounds()
	x = clampFloat(x, float64(bounds.Min.X), float64(bounds.Max.X-1))
	y = clampFloat(y, float64(bounds.Min.Y), float64(bounds.Max.Y-1))
	xFloor := math.Floor(x)
	yFloor := math.Floor(y)
	x0 := clamp(int(xFloor), bounds.Min.X, bounds.Max.X-1)
	y0 := clamp(int(yFloor), bounds.Min.Y, bounds.Max.Y-1)
	x1 := clamp(x0+1, bounds.Min.X, bounds.Max.X-1)
	y1 := clamp(y0+1, bounds.Min.Y, bounds.Max.Y-1)
	wx := x - xFloor
	wy := y - yFloor
	return bilinearAlpha(src, x0, y0, x1, y1, wx, wy)
}

func roundedUnitRect(x, y, left, top, width, height, radius float64) bool {
	right := left + width
	bottom := top + height
	if x < left || x > right || y < top || y > bottom {
		return false
	}
	innerLeft := left + radius
	innerRight := right - radius
	innerTop := top + radius
	innerBottom := bottom - radius
	if (x >= innerLeft && x <= innerRight) || (y >= innerTop && y <= innerBottom) {
		return true
	}
	cx := innerLeft
	if x > innerRight {
		cx = innerRight
	}
	cy := innerTop
	if y > innerBottom {
		cy = innerBottom
	}
	return math.Hypot(x-cx, y-cy) <= radius
}

func colorAlpha(c color.Color) uint8 {
	_, _, _, alpha := c.RGBA()
	return uint8(alpha >> 8)
}

func cropCircularRotateImage(src image.Image, width, height int) *image.RGBA {
	if width <= 0 || height <= 0 {
		return image.NewRGBA(image.Rect(0, 0, max(1, width), max(1, height)))
	}
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	diameter := min(width, height)
	bounds := src.Bounds()
	srcSize := min(bounds.Dx(), bounds.Dy())
	if diameter <= 0 || srcSize <= 0 {
		return dst
	}
	srcX0 := bounds.Min.X + (bounds.Dx()-srcSize)/2
	srcY0 := bounds.Min.Y + (bounds.Dy()-srcSize)/2
	x0 := (width - diameter) / 2
	y0 := (height - diameter) / 2
	radius := float64(diameter) / 2
	cx := float64(x0) + radius - 0.5
	cy := float64(y0) + radius - 0.5
	for y := 0; y < diameter; y++ {
		dy := float64(y0+y) - cy
		for x := 0; x < diameter; x++ {
			dx := float64(x0+x) - cx
			if math.Hypot(dx, dy) > radius {
				continue
			}
			sx := float64(srcX0) + (float64(x)+0.5)*float64(srcSize)/float64(diameter) - 0.5
			sy := float64(srcY0) + (float64(y)+0.5)*float64(srcSize)/float64(diameter) - 0.5
			dst.Set(x0+x, y0+y, sampleBilinearRGBA(src, sx, sy))
		}
	}
	return dst
}

func sliderTemplateEdgeBandStrength(mask image.Image, x, y, radius int) float64 {
	if radius <= 0 || colorAlpha(mask.At(x, y)) <= 4 {
		return 0
	}
	best := float64(radius + 1)
	for dy := -radius; dy <= radius; dy++ {
		for dx := -radius; dx <= radius; dx++ {
			distance := math.Hypot(float64(dx), float64(dy))
			if distance > float64(radius) || distance >= best {
				continue
			}
			if colorAlpha(mask.At(x+dx, y+dy)) <= sliderBorderOutsideAlpha {
				best = distance
			}
		}
	}
	return sliderInnerBorderStrength(best, radius)
}

func sliderInnerBorderStrength(distance float64, radius int) float64 {
	if radius <= 0 || distance > float64(radius) {
		return 0
	}
	strength := clampFloat((float64(radius)+0.35-distance)/float64(radius), 0, 1)
	return math.Pow(strength, sliderBorderFalloff)
}

func rotateImage(src *image.RGBA, angle int) *image.RGBA {
	bounds := src.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	cx := float64(width-1) / 2
	cy := float64(height-1) / 2
	radians := -float64(angle) * math.Pi / 180
	cosine := math.Cos(radians)
	sine := math.Sin(radians)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			dx := float64(x) - cx
			dy := float64(y) - cy
			sx := cx + dx*cosine - dy*sine
			sy := cy + dx*sine + dy*cosine
			if sx >= 0 && sx <= float64(width-1) && sy >= 0 && sy <= float64(height-1) {
				dst.Set(x, y, sampleBilinearRGBA(src, sx, sy))
			}
		}
	}
	return dst
}

func sampleBilinearRGBA(src image.Image, x, y float64) color.RGBA {
	bounds := src.Bounds()
	x0 := clamp(int(math.Floor(x)), bounds.Min.X, bounds.Max.X-1)
	y0 := clamp(int(math.Floor(y)), bounds.Min.Y, bounds.Max.Y-1)
	x1 := clamp(x0+1, bounds.Min.X, bounds.Max.X-1)
	y1 := clamp(y0+1, bounds.Min.Y, bounds.Max.Y-1)
	wx := x - math.Floor(x)
	wy := y - math.Floor(y)
	c00 := rgbaAt(src, x0, y0)
	c10 := rgbaAt(src, x1, y0)
	c01 := rgbaAt(src, x0, y1)
	c11 := rgbaAt(src, x1, y1)
	return color.RGBA{
		R: uint8(math.Round(bilinearChannel(c00.R, c10.R, c01.R, c11.R, wx, wy))),
		G: uint8(math.Round(bilinearChannel(c00.G, c10.G, c01.G, c11.G, wx, wy))),
		B: uint8(math.Round(bilinearChannel(c00.B, c10.B, c01.B, c11.B, wx, wy))),
		A: uint8(math.Round(bilinearChannel(c00.A, c10.A, c01.A, c11.A, wx, wy))),
	}
}

func bilinearChannel(c00, c10, c01, c11 uint8, wx, wy float64) float64 {
	top := float64(c00)*(1-wx) + float64(c10)*wx
	bottom := float64(c01)*(1-wx) + float64(c11)*wx
	return top*(1-wy) + bottom*wy
}

type concatTemplateOptions struct {
	SplitY      int
	SplitRatio  float64
	GapColor    color.RGBA
	BorderColor color.RGBA
}

func loadConcatTemplate(resources []types.CaptchaResource) concatTemplateOptions {
	options := concatTemplateOptions{
		SplitRatio:  0.5,
		GapColor:    color.RGBA{R: 226, G: 232, B: 240, A: 255},
		BorderColor: color.RGBA{R: 99, G: 102, B: 241, A: 180},
	}
	for _, item := range resources {
		if item.ResourceType != "concat_template" || !strings.EqualFold(item.Status, "active") {
			continue
		}
		options = mergeConcatTemplateMetadata(options, item.Metadata)
		if data, _, ok := loadStoredResourceBytes(item); ok {
			var metadata map[string]any
			if json.Unmarshal(data, &metadata) == nil {
				options = mergeConcatTemplateMetadata(options, metadata)
			}
		}
		break
	}
	return options
}

func mergeConcatTemplateMetadata(options concatTemplateOptions, metadata map[string]any) concatTemplateOptions {
	if len(metadata) == 0 {
		return options
	}
	if splitY, ok, err := metadataInt(cloneMetadata(metadata), "split_y"); err == nil && ok {
		options.SplitY = int(splitY)
	}
	if ratio, ok := metadataFloat(metadata, "split_ratio", "ratio"); ok && ratio > 0 && ratio < 1 {
		options.SplitRatio = ratio
	}
	if value, ok := metadataString(metadata, "gap_color"); ok {
		if c, ok := parseHexColor(value); ok {
			options.GapColor = c
		}
	}
	if value, ok := metadataString(metadata, "border_color", "piece_border_color"); ok {
		if c, ok := parseHexColor(value); ok {
			options.BorderColor = c
		}
	}
	return options
}

func composeConcat(base *image.RGBA, offset int, options concatTemplateOptions) (*image.RGBA, *image.RGBA, int) {
	bounds := base.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	splitY := options.SplitY
	if splitY <= 0 {
		splitY = int(math.Round(float64(height) * options.SplitRatio))
	}
	splitY = clamp(splitY, min(1, height), max(1, height-2))
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			if y < splitY {
				dst.Set(x, y, concatCoverPixel(x, y, options.GapColor))
				continue
			}
			dst.Set(x, y, opaqueRGBA(rgbaAt(base, x, y)))
		}
	}
	drawConcatDivider(dst, splitY, options.BorderColor)

	pieceWidth := width + concatMaxMovement
	offset = clamp(offset, 0, concatMaxMovement)
	piece := image.NewRGBA(image.Rect(0, 0, pieceWidth, height))
	for x := 0; x < pieceWidth; x++ {
		sourceX := (x - (concatMaxMovement - offset)) % width
		if sourceX < 0 {
			sourceX += width
		}
		for y := 0; y < splitY; y++ {
			piece.Set(x, y, opaqueRGBA(rgbaAt(base, sourceX, y)))
		}
	}
	return dst, piece, splitY
}

func drawConcatDivider(img *image.RGBA, splitY int, c color.RGBA) {
	width := img.Bounds().Dx()
	height := img.Bounds().Dy()
	if width <= 0 || height <= 0 {
		return
	}
	y := clamp(splitY, 1, height-2)
	for x := 0; x < width; x++ {
		img.Set(x, y, mixRGBA(rgbaAt(img, x, y), c, 0.18))
	}
}

func concatCoverPixel(x, y int, base color.RGBA) color.RGBA {
	noise := uint8((x*37 + y*19 + (x*y)%29) % 12)
	c := color.RGBA{
		R: uint8(clamp(int(base.R)+int(noise/3)-3, 0, 255)),
		G: uint8(clamp(int(base.G)+int(noise/4)-2, 0, 255)),
		B: uint8(clamp(int(base.B)+int(noise/5)-1, 0, 255)),
		A: 255,
	}
	if (x+y)%23 == 0 {
		return mixRGBA(c, color.RGBA{R: 148, G: 163, B: 184, A: 255}, 0.24)
	}
	return c
}

func composeCurveImage(base *image.RGBA, payload types.RenderPayload, answer types.Answer) *image.RGBA {
	img := cloneRGBA(base)
	profile, ok := payload.Parameters["curve_profile"]
	if !ok {
		return img
	}
	points := fixedCurvePointsFromProfile(profile, answer.X)
	if len(points) < 2 {
		return img
	}
	drawCurveResourceTarget(img, curveVariant(payload.Type, profile), points)
	return img
}

type renderCurvePoint struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

func fixedCurvePointsFromProfile(profile any, answerX int) []image.Point {
	profileMap, ok := profile.(map[string]any)
	if !ok {
		return nil
	}
	moving := curvePointsFromAny(profileMap["moving_points"])
	drives := curvePointsFromAny(profileMap["drive_points"])
	if len(moving) < 2 || len(drives) < 2 {
		return nil
	}
	count := min(len(moving), len(drives))
	points := make([]image.Point, 0, count)
	scale := float64(answerX)
	for i := 0; i < count; i++ {
		x := moving[i].X - drives[i].X*scale
		y := moving[i].Y - drives[i].Y*scale
		if !math.IsNaN(x) && !math.IsNaN(y) && !math.IsInf(x, 0) && !math.IsInf(y, 0) {
			points = append(points, image.Point{X: int(math.Round(x)), Y: int(math.Round(y))})
		}
	}
	return points
}

func curvePointsFromAny(value any) []renderCurvePoint {
	if value == nil {
		return nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var points []renderCurvePoint
	if err := json.Unmarshal(data, &points); err != nil {
		return nil
	}
	return points
}

func curveVariant(captchaType types.CaptchaType, profile any) int {
	if profileMap, ok := profile.(map[string]any); ok {
		if variant := anyInt(profileMap["variant"], 0); variant > 0 {
			return variant
		}
	}
	switch captchaType {
	case types.CaptchaCurve2:
		return 2
	case types.CaptchaCurve3:
		return 3
	default:
		return 1
	}
}

func drawCurveResourceTarget(img *image.RGBA, variant int, points []image.Point) {
	switch variant {
	case 2:
		drawPolylineOver(img, offsetImagePoints(points, 0, -4), 18, color.RGBA{R: 255, G: 255, B: 255, A: 178})
		drawPolylineOver(img, offsetImagePoints(points, 0, -3), 13, color.RGBA{R: 255, G: 92, B: 173, A: 220})
		drawPolylineOver(img, points, 7, color.RGBA{R: 192, G: 132, B: 252, A: 245})
	case 3:
		drawPolylineOver(img, offsetImagePoints(points, 0, -2), 17, color.RGBA{R: 255, G: 255, B: 255, A: 205})
		drawPolylineOver(img, points, 8, color.RGBA{R: 248, G: 113, B: 113, A: 235})
	default:
		drawPolylineOver(img, offsetImagePoints(points, 0, 5), 16, color.RGBA{R: 15, G: 23, B: 42, A: 118})
		drawPolylineOver(img, points, 10, color.RGBA{R: 125, G: 211, B: 252, A: 230})
		drawPolylineOver(img, points, 4, color.RGBA{R: 224, G: 242, B: 254, A: 245})
	}
}

func composeGestureImage(base *image.RGBA, points []types.Point, view types.View) *image.RGBA {
	img := cloneRGBA(base)
	scaleX, scaleY := renderScaleForView(img, view)
	polyline := make([]image.Point, 0, len(points))
	for _, point := range points {
		polyline = append(polyline, image.Point{X: scalePointX(point, scaleX), Y: scalePointY(point, scaleY)})
	}
	if len(polyline) == 0 {
		return img
	}
	drawPolylineOver(img, polyline, 16, color.RGBA{R: 255, G: 255, B: 255, A: 205})
	drawPolylineOver(img, polyline, 12, color.RGBA{R: 15, G: 23, B: 42, A: 88})
	drawPolylineOver(img, polyline, 8, color.RGBA{R: 146, G: 80, B: 42, A: 240})
	start := polyline[0]
	end := polyline[len(polyline)-1]
	drawCircleOver(img, start.X, start.Y, 13, color.RGBA{R: 45, G: 212, B: 191, A: 235})
	drawCircleOver(img, end.X, end.Y, 15, color.RGBA{R: 244, G: 63, B: 94, A: 235})
	drawCircleOver(img, end.X, end.Y, 7, color.RGBA{R: 15, G: 23, B: 42, A: 245})
	return img
}

func composeIconClickImage(base *image.RGBA, payload types.RenderPayload, points []types.Point, resources []types.CaptchaResource) (*image.RGBA, []string) {
	img := cloneRGBA(base)
	icons := loadResourceImagesByType(resources, "icon_library")
	labels := make([]string, 0, min(len(payload.Words), len(points)))
	scaleX, scaleY := renderScaleForView(base, payload.View)
	iconSize := max(1, int(math.Round(float64(iconClickResourceSize)*math.Min(scaleX, scaleY))))
	if len(icons) > 0 {
		for i, point := range points {
			icon := icons[i%len(icons)]
			drawResourceIcon(img, icon.Image, scalePointX(point, scaleX), scalePointY(point, scaleY), iconSize, clickPalette(i))
			label := resourceDisplayLabel(icon.Resource, "")
			if label == "" && i < len(payload.Words) {
				label = payload.Words[i]
			}
			if label != "" {
				labels = append(labels, label)
			}
		}
		return img, labels
	}
	if overlayPayloadIconObjects(img, payload.Image) {
		return img, payload.Words
	}
	for i, point := range points {
		drawGenericIconMarker(img, scalePointX(point, scaleX), scalePointY(point, scaleY), i, clickPalette(i), iconSize)
		if i < len(payload.Words) {
			labels = append(labels, payload.Words[i])
		}
	}
	return img, labels
}

func overlayPayloadIconObjects(dst *image.RGBA, dataURL string) bool {
	src, ok := decodePNGDataURLImage(dataURL)
	if !ok {
		return false
	}
	src = resizeBilinear(src, dst.Bounds().Dx(), dst.Bounds().Dy())
	changed := false
	for y := 0; y < src.Bounds().Dy(); y++ {
		for x := 0; x < src.Bounds().Dx(); x++ {
			pixel := rgbaAt(src, x, y)
			if !isLikelyIconPixel(pixel) {
				continue
			}
			blendPixelOver(dst, x, y, pixel)
			changed = true
		}
	}
	return changed
}

func decodePNGDataURLImage(value string) (*image.RGBA, bool) {
	data, contentType, ok := parseDataURL(value)
	if !ok || !strings.EqualFold(contentType, "image/png") {
		return nil, false
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	if rgba, ok := img.(*image.RGBA); ok {
		return rgba, true
	}
	out := image.NewRGBA(img.Bounds())
	draw.Draw(out, out.Bounds(), img, img.Bounds().Min, draw.Src)
	return out, true
}

func isLikelyIconPixel(c color.RGBA) bool {
	if c.A <= 12 {
		return false
	}
	maxChannel := max(int(c.R), max(int(c.G), int(c.B)))
	minChannel := min(int(c.R), min(int(c.G), int(c.B)))
	luma := 0.299*float64(c.R) + 0.587*float64(c.G) + 0.114*float64(c.B)
	return maxChannel-minChannel > 28 || luma < 150
}

func drawResourceIcon(img *image.RGBA, icon image.Image, cx, cy, size int, accent color.RGBA) {
	resized := resizeBilinear(icon, size, size)
	originX := cx - size/2
	originY := cy - size/2
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			src := rgbaAt(resized, x, y)
			if src.A <= 8 {
				continue
			}
			c := src
			if iconLooksMonochrome(src) {
				c = accent
				c.A = src.A
			}
			edge := imageAlphaEdgeStrength(resized, x, y, scaledIconEdgeRadius(size, iconClickResourceSize))
			c = mixRGBA(c, color.RGBA{R: 15, G: 23, B: 42, A: 255}, edge*iconClickEdgeDarken)
			blendPixelOver(img, originX+x, originY+y, c)
		}
	}
}

func renderScaleForView(img image.Image, view types.View) (float64, float64) {
	if view.Width <= 0 || view.Height <= 0 {
		return 1, 1
	}
	bounds := img.Bounds()
	return float64(bounds.Dx()) / float64(view.Width), float64(bounds.Dy()) / float64(view.Height)
}

func scalePoints(points []types.Point, factor int) []types.Point {
	if factor <= 1 || len(points) == 0 {
		return points
	}
	out := make([]types.Point, 0, len(points))
	for _, point := range points {
		out = append(out, types.Point{X: point.X * factor, Y: point.Y * factor})
	}
	return out
}

func scalePointX(point types.Point, scale float64) int {
	return int(math.Round(float64(point.X) * scale))
}

func scalePointY(point types.Point, scale float64) int {
	return int(math.Round(float64(point.Y) * scale))
}

func scaledIconEdgeRadius(size, baseSize int) int {
	if baseSize <= 0 {
		return iconClickEdgeRadius
	}
	return max(1, int(math.Round(float64(size)*float64(iconClickEdgeRadius)/float64(baseSize))))
}

func iconLooksMonochrome(c color.RGBA) bool {
	return absInt(int(c.R)-int(c.G)) < 10 && absInt(int(c.G)-int(c.B)) < 10
}

func imageAlphaEdgeStrength(img image.Image, x, y, radius int) float64 {
	if radius <= 0 || colorAlpha(img.At(x, y)) <= 10 {
		return 0
	}
	best := float64(radius + 1)
	for dy := -radius; dy <= radius; dy++ {
		for dx := -radius; dx <= radius; dx++ {
			distance := math.Hypot(float64(dx), float64(dy))
			if distance > float64(radius) || distance >= best {
				continue
			}
			if colorAlpha(img.At(x+dx, y+dy)) <= 8 {
				best = distance
			}
		}
	}
	return sliderInnerBorderStrength(best, radius)
}

func resourceDisplayLabel(resource types.CaptchaResource, fallback string) string {
	if label, ok := metadataString(resource.Metadata, "label", "title", "display_name", "category", "name"); ok && strings.TrimSpace(label) != "" {
		return strings.TrimSpace(label)
	}
	if fallback != "" {
		return fallback
	}
	if resource.Tag != "" && resource.Tag != "default" {
		return resource.Tag
	}
	return ""
}

func drawGenericIconMarker(img *image.RGBA, cx, cy, index int, c color.RGBA, size int) {
	scale := float64(size) / float64(iconClickResourceSize)
	drawCircleOver(img, cx+int(math.Round(2*scale)), cy+int(math.Round(3*scale)), int(math.Round(28*scale)), color.RGBA{R: 15, G: 23, B: 42, A: 68})
	drawCircleOver(img, cx, cy, int(math.Round(27*scale)), color.RGBA{R: 255, G: 255, B: 255, A: 228})
	switch index % 4 {
	case 0:
		drawCircleOver(img, cx, cy, int(math.Round(15*scale)), c)
	case 1:
		unit := int(math.Round(15 * scale))
		fillRectOver(img, cx-unit, cy-unit, unit*2, unit*2, c)
	case 2:
		top := int(math.Round(18 * scale))
		side := int(math.Round(18 * scale))
		bottom := int(math.Round(14 * scale))
		fillPolygonOver(img, []image.Point{{X: cx, Y: cy - top}, {X: cx + side, Y: cy + bottom}, {X: cx - side, Y: cy + bottom}}, c)
	default:
		radius := int(math.Round(18 * scale))
		fillPolygonOver(img, []image.Point{{X: cx, Y: cy - radius}, {X: cx + radius, Y: cy}, {X: cx, Y: cy + radius}, {X: cx - radius, Y: cy}}, c)
	}
}

func clickPalette(index int) color.RGBA {
	palette := []color.RGBA{
		{R: 37, G: 99, B: 235, A: 255},
		{R: 20, G: 184, B: 166, A: 255},
		{R: 225, G: 29, B: 72, A: 255},
		{R: 126, G: 34, B: 206, A: 255},
	}
	return palette[index%len(palette)]
}

func composeJigsawImage(base *image.RGBA, answer types.Answer, parameters map[string]any) *image.RGBA {
	out := cloneRGBA(base)
	width := out.Bounds().Dx()
	height := out.Bounds().Dy()
	cols := max(1, renderParameterInt(parameters, "tile_cols", 2))
	rows := max(1, renderParameterInt(parameters, "tile_rows", 2))
	tileWidth := renderParameterInt(parameters, "tile_width", width/cols)
	tileHeight := renderParameterInt(parameters, "tile_height", height/rows)
	if tileWidth <= 0 {
		tileWidth = max(1, width/cols)
	}
	if tileHeight <= 0 {
		tileHeight = max(1, height/rows)
	}
	if order, ok := decodeJigsawResourceSourceOrder(answer.Token, cols*rows); ok {
		for targetIndex, sourceIndex := range order {
			target := jigsawResourceTileRectByIndex(targetIndex, width, height, tileWidth, tileHeight)
			source := jigsawResourceTileRectByIndex(sourceIndex, width, height, tileWidth, tileHeight)
			draw.Draw(out, target, base, source.Min, draw.Src)
		}
	} else if len(answer.Points) >= 2 {
		first := jigsawResourceTileRect(answer.Points[0], width, height, tileWidth, tileHeight)
		second := jigsawResourceTileRect(answer.Points[1], width, height, tileWidth, tileHeight)
		draw.Draw(out, first, base, second.Min, draw.Src)
		draw.Draw(out, second, base, first.Min, draw.Src)
	}
	for x := tileWidth; x < width; x += tileWidth {
		fillRectOver(out, x-1, 0, 2, height, color.RGBA{R: 100, G: 116, B: 139, A: 255})
	}
	for y := tileHeight; y < height; y += tileHeight {
		fillRectOver(out, 0, y-1, width, 2, color.RGBA{R: 100, G: 116, B: 139, A: 255})
	}
	strokeRect(out, 0, 0, width, height, 1, color.RGBA{R: 148, G: 163, B: 184, A: 255})
	return out
}

func decodeJigsawResourceSourceOrder(answerToken string, count int) ([]int, bool) {
	expected, ok := decodeJigsawResourceOrder(answerToken, count)
	if !ok {
		return nil, false
	}
	return invertJigsawResourceOrder(expected), true
}

func decodeJigsawResourceOrder(value string, count int) ([]int, bool) {
	parts := strings.Split(strings.TrimSpace(value), ",")
	if len(parts) != count {
		return nil, false
	}
	order := make([]int, count)
	seen := make([]bool, count)
	for i, part := range parts {
		parsed, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || parsed < 0 || parsed >= count || seen[parsed] {
			return nil, false
		}
		order[i] = parsed
		seen[parsed] = true
	}
	return order, true
}

func invertJigsawResourceOrder(order []int) []int {
	out := make([]int, len(order))
	for i := range out {
		out[i] = i
	}
	for target, source := range order {
		if source >= 0 && source < len(out) {
			out[source] = target
		}
	}
	return out
}

func jigsawResourceTileRect(point types.Point, width, height, tileWidth, tileHeight int) image.Rectangle {
	x := clamp(point.X/tileWidth, 0, max(0, width/tileWidth-1)) * tileWidth
	y := clamp(point.Y/tileHeight, 0, max(0, height/tileHeight-1)) * tileHeight
	return image.Rect(x, y, min(width, x+tileWidth), min(height, y+tileHeight))
}

func jigsawResourceTileRectByIndex(index, width, height, tileWidth, tileHeight int) image.Rectangle {
	if tileWidth <= 0 || tileHeight <= 0 {
		return image.Rect(0, 0, width, height)
	}
	cols := max(1, width/tileWidth)
	rows := max(1, height/tileHeight)
	index = clamp(index, 0, cols*rows-1)
	x := (index % cols) * tileWidth
	y := (index / cols) * tileHeight
	return image.Rect(x, y, min(width, x+tileWidth), min(height, y+tileHeight))
}

func opaqueRGBA(c color.RGBA) color.RGBA {
	c.A = 255
	return c
}

func cloneParameters(parameters map[string]any) map[string]any {
	cloned := make(map[string]any, len(parameters)+5)
	for key, value := range parameters {
		cloned[key] = value
	}
	return cloned
}

func sliderPieceSize(parameters map[string]any, fallback int) int {
	return renderParameterInt(parameters, "piece_size", fallback)
}

func sliderPieceSizeFallbackFor(captchaType types.CaptchaType) int {
	if captchaType == types.CaptchaSlider2 {
		return slider2PieceSizeFallback
	}
	return sliderPieceSizeFallback
}

func renderParameterInt(parameters map[string]any, key string, fallback int) int {
	if len(parameters) == 0 {
		return fallback
	}
	value, ok := parameters[key]
	if !ok {
		return fallback
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(math.Round(typed))
	case json.Number:
		parsed, err := typed.Int64()
		if err == nil {
			return int(parsed)
		}
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func randomIndex(length int) int {
	if length <= 1 {
		return 0
	}
	index, err := rand.Int(rand.Reader, big.NewInt(int64(length)))
	if err != nil {
		return 0
	}
	return int(index.Int64())
}

func randomIndexes(length, count int) []int {
	if length <= 0 || count <= 0 {
		return nil
	}
	indexes := make([]int, length)
	for i := range indexes {
		indexes[i] = i
	}
	for i := 0; i < length; i++ {
		j := i + randomIndex(length-i)
		indexes[i], indexes[j] = indexes[j], indexes[i]
	}
	return indexes[:min(count, length)]
}

func randomJitter(minValue, maxValue int) int {
	if maxValue <= minValue {
		return minValue
	}
	return minValue + randomIndex(maxValue-minValue+1)
}

func concatControlMax(offset, viewWidth, splitX, pieceWidth int) int {
	_ = offset
	_ = splitX
	_ = pieceWidth
	return min(viewWidth, concatMaxMovement)
}

type fontOptions struct {
	Scale              int
	FontSize           float64
	FontPath           string
	FontBytes          []byte
	Colors             []color.RGBA
	Glyphs             map[string][]string
	DistortionStrength float64
}

func loadFontOptions(resources []types.CaptchaResource) fontOptions {
	options := fontOptions{Scale: 5, DistortionStrength: wordGlyphDefaultDistort}
	for _, item := range resources {
		if item.ResourceType != "font" || !strings.EqualFold(item.Status, "active") {
			continue
		}
		options = mergeFontMetadata(options, item.Metadata)
		if !strings.EqualFold(strings.TrimSpace(item.StorageType), "embedded") {
			if data, contentType, ok := loadStoredResourceBytes(item); ok && looksLikeFontBytes(data, contentType) {
				options.FontBytes = data
			}
		}
		break
	}
	return options
}

func mergeFontMetadata(options fontOptions, metadata map[string]any) fontOptions {
	if len(metadata) == 0 {
		return options
	}
	if scale, ok, err := metadataInt(cloneMetadata(metadata), "glyph_scale", "scale"); err == nil && ok {
		options.Scale = clamp(int(scale), 2, 12)
	}
	if size, ok := metadataFloat(metadata, "font_size", "text_size", "size"); ok {
		options.FontSize = clampFloat(size, 18, 96)
	}
	if path, ok := metadataString(metadata, "font_path", "path", "file_path"); ok {
		options.FontPath = strings.TrimSpace(path)
	}
	if colors := metadataColors(metadata, "palette", "colors"); len(colors) > 0 {
		options.Colors = colors
	}
	if glyphs := metadataGlyphs(metadata, "glyphs", "patterns"); len(glyphs) > 0 {
		options.Glyphs = glyphs
	}
	if strength, ok := metadataFloat(metadata, "distortion_strength", "warp_strength", "distortion"); ok {
		options.DistortionStrength = clampFloat(strength, 0, 1.5)
	}
	if enabled, ok := metadataBool(metadata, "distortion_enabled", "warp_enabled", "distort"); ok {
		if !enabled {
			options.DistortionStrength = 0
		} else if options.DistortionStrength <= 0 {
			options.DistortionStrength = wordGlyphDefaultDistort
		}
	}
	return options
}

func composeWordImage(base *image.RGBA, words []string, points []types.Point, options fontOptions) *image.RGBA {
	img := cloneRGBA(base)
	colors := defaultWordTextColors()
	if len(options.Colors) > 0 {
		colors = options.Colors
	}
	scale := options.Scale * wordImageRenderScale(img.Bounds())
	if scale <= 0 {
		scale = 5
	}
	decoyWords := randomGlyphWordsExcluding(glyphs.WordClickBank, 2+randomIndex(3), words)
	decoyPoints := wordDecoyPoints(img.Bounds().Dx(), img.Bounds().Dy(), points, len(decoyWords))
	allWords := append(append([]string{}, words...), decoyWords...)
	wordColors := shuffledWordTextColors(colors, len(allWords))
	if len(options.Glyphs) == 0 {
		if face, ok := loadWordFontFace(options, allWords, img.Bounds()); ok {
			defer face.Close()
			for i, word := range decoyWords {
				if i >= len(decoyPoints) {
					break
				}
				drawFontGlyph(img, word, decoyPoints[i].X, decoyPoints[i].Y, face, wordColors[len(words)+i], options.DistortionStrength)
			}
			for i, word := range words {
				if i >= len(points) {
					break
				}
				drawFontGlyph(img, word, points[i].X, points[i].Y, face, wordColors[i], options.DistortionStrength)
			}
			return img
		}
	}
	for i, word := range decoyWords {
		if i >= len(decoyPoints) {
			break
		}
		drawBlockGlyph(img, word, decoyPoints[i].X, decoyPoints[i].Y, max(2, scale-1), wordColors[len(words)+i], options.Glyphs, options.DistortionStrength)
	}
	for i, word := range words {
		if i >= len(points) {
			break
		}
		drawBlockGlyph(img, word, points[i].X, points[i].Y, scale, wordColors[i], options.Glyphs, options.DistortionStrength)
	}
	return img
}

func defaultWordTextColors() []color.RGBA {
	return []color.RGBA{
		{R: 255, G: 255, B: 255, A: 252},
		{R: 254, G: 240, B: 138, A: 252},
		{R: 125, G: 211, B: 252, A: 252},
		{R: 94, G: 234, B: 212, A: 252},
		{R: 134, G: 239, B: 172, A: 252},
		{R: 253, G: 186, B: 116, A: 252},
		{R: 252, G: 165, B: 165, A: 252},
		{R: 216, G: 180, B: 254, A: 252},
	}
}

func shuffledWordTextColors(colors []color.RGBA, count int) []color.RGBA {
	if count <= 0 {
		return nil
	}
	if len(colors) == 0 {
		colors = defaultWordTextColors()
	}
	out := make([]color.RGBA, 0, count)
	order := randomIndexes(len(colors), len(colors))
	for len(out) < count {
		if len(out) > 0 {
			order = randomIndexes(len(colors), len(colors))
		}
		for _, index := range order {
			out = append(out, colors[index%len(colors)])
			if len(out) >= count {
				break
			}
		}
	}
	return out
}

func looksLikeFontBytes(data []byte, contentType string) bool {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	if strings.Contains(contentType, "font") || strings.Contains(contentType, "opentype") || strings.Contains(contentType, "truetype") {
		return true
	}
	if len(data) < 4 {
		return false
	}
	header := string(data[:4])
	return header == "\x00\x01\x00\x00" || header == "OTTO" || header == "ttcf" || header == "true"
}

func loadWordFontFace(options fontOptions, words []string, bounds image.Rectangle) (xfont.Face, bool) {
	size := wordFontSize(options, bounds)
	if len(options.FontBytes) > 0 {
		if face, ok := newWordFontFace(options.FontBytes, size, words); ok {
			return face, true
		}
	}
	if options.FontPath != "" {
		if data, ok := readWordFontFile(options.FontPath); ok {
			if face, ok := newWordFontFace(data, size, words); ok {
				return face, true
			}
		}
	}
	for _, path := range systemCJKFontPaths() {
		if data, ok := readWordFontFile(path); ok {
			if face, ok := newWordFontFace(data, size, words); ok {
				return face, true
			}
		}
	}
	return nil, false
}

func wordFontSize(options fontOptions, bounds image.Rectangle) float64 {
	if options.FontSize > 0 {
		return clampFloat(options.FontSize, 18, 96)
	}
	return clampFloat(float64(bounds.Dy())*0.20, 22, 76)
}

func readWordFontFile(path string) ([]byte, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false
	}
	if cached, ok := wordFontFileCache.Load(path); ok {
		data, ok := cached.([]byte)
		return data, ok && len(data) > 0
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil, false
	}
	wordFontFileCache.Store(path, data)
	return data, true
}

func newWordFontFace(data []byte, size float64, words []string) (xfont.Face, bool) {
	collection, err := opentype.ParseCollection(data)
	if err == nil {
		for i := 0; i < collection.NumFonts(); i++ {
			font, err := collection.Font(i)
			if err != nil {
				continue
			}
			face, err := opentype.NewFace(font, &opentype.FaceOptions{
				Size:    size,
				DPI:     96,
				Hinting: xfont.HintingNone,
			})
			if err != nil {
				continue
			}
			if fontFaceSupports(face, words) {
				return face, true
			}
			face.Close()
		}
	}
	font, err := opentype.Parse(data)
	if err != nil {
		return nil, false
	}
	face, err := opentype.NewFace(font, &opentype.FaceOptions{
		Size:    size,
		DPI:     96,
		Hinting: xfont.HintingNone,
	})
	if err != nil {
		return nil, false
	}
	if !fontFaceSupports(face, words) {
		face.Close()
		return nil, false
	}
	return face, true
}

func fontFaceSupports(face xfont.Face, words []string) bool {
	for _, word := range words {
		for _, r := range word {
			if r == ' ' {
				continue
			}
			if _, ok := face.GlyphAdvance(r); !ok {
				return false
			}
		}
	}
	return true
}

func systemCJKFontPaths() []string {
	return []string{
		"/System/Library/Fonts/STHeiti Medium.ttc",
		"/System/Library/Fonts/Hiragino Sans GB.ttc",
		"/System/Library/Fonts/STHeiti Light.ttc",
		"/Library/Fonts/Arial Unicode.ttf",
		"/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
		"/System/Library/Fonts/Supplemental/Songti.ttc",
		"/System/Library/Fonts/PingFang.ttc",
		"/Library/Fonts/NotoSansCJK-Regular.ttc",
		"/Library/Fonts/SourceHanSansSC-Regular.otf",
		"/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
		"/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.otf",
		"/usr/share/fonts/noto/NotoSansCJK-Regular.ttc",
		"/usr/share/fonts/noto/NotoSansCJK-Regular.otf",
		"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
		"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.otf",
		"/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
		"/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.otf",
		"/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
		"/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
		"/usr/share/fonts/truetype/arphic/uming.ttc",
		`C:\Windows\Fonts\msyh.ttc`,
		`C:\Windows\Fonts\simhei.ttf`,
		`C:\Windows\Fonts\simsun.ttc`,
	}
}

func drawFontGlyph(img *image.RGBA, value string, cx, cy int, face xfont.Face, c color.RGBA, distortionStrength float64) bool {
	if strings.TrimSpace(value) == "" || !fontFaceSupports(face, []string{value}) {
		return false
	}
	textBounds, _ := xfont.BoundString(face, value)
	if textBounds.Empty() {
		return false
	}
	textWidth := max(1, (textBounds.Max.X - textBounds.Min.X).Ceil())
	textHeight := max(1, (textBounds.Max.Y - textBounds.Min.Y).Ceil())
	pad := max(12, int(math.Ceil(float64(max(textWidth, textHeight))*0.28)))
	layer := image.NewRGBA(image.Rect(0, 0, textWidth+pad*2, textHeight+pad*2))
	dot := fixed.Point26_6{
		X: fixed.I(pad) - textBounds.Min.X,
		Y: fixed.I(pad) - textBounds.Min.Y,
	}
	shadow := color.RGBA{R: 15, G: 23, B: 42, A: 80}
	edge := color.RGBA{R: 15, G: 23, B: 42, A: 190}
	for _, offset := range []image.Point{{X: 2, Y: 2}} {
		drawStringAt(layer, value, face, moveFixedPoint(dot, offset.X, offset.Y), shadow)
	}
	for dy := -1; dy <= 1; dy++ {
		for dx := -1; dx <= 1; dx++ {
			if dx == 0 && dy == 0 {
				continue
			}
			drawStringAt(layer, value, face, moveFixedPoint(dot, dx, dy), edge)
		}
	}
	drawStringAt(layer, value, face, dot, c)
	distorted := distortWordGlyphLayer(layer, randomWordGlyphDistortion(distortionStrength, max(textWidth, textHeight)))
	blendGlyphLayerAt(img, distorted, cx, cy)
	return true
}

func blockGlyphDistortionStrength(strength float64) float64 {
	if strength <= 0 {
		return 0
	}
	return clampFloat(strength, 0, wordBlockGlyphMaxDistort)
}

func wordImageRenderScale(bounds image.Rectangle) int {
	return max(1, int(math.Round(float64(bounds.Dx())/float64(320))))
}

func clampTextDot(bounds image.Rectangle, textBounds fixed.Rectangle26_6, dot fixed.Point26_6) fixed.Point26_6 {
	pad := fixed.I(5)
	minX := fixed.I(bounds.Min.X) + pad
	maxX := fixed.I(bounds.Max.X) - pad
	minY := fixed.I(bounds.Min.Y) + pad
	maxY := fixed.I(bounds.Max.Y) - pad
	left := dot.X + textBounds.Min.X
	right := dot.X + textBounds.Max.X
	top := dot.Y + textBounds.Min.Y
	bottom := dot.Y + textBounds.Max.Y
	if left < minX {
		dot.X += minX - left
	}
	if right > maxX {
		dot.X -= right - maxX
	}
	if top < minY {
		dot.Y += minY - top
	}
	if bottom > maxY {
		dot.Y -= bottom - maxY
	}
	return dot
}

func moveFixedPoint(point fixed.Point26_6, dx, dy int) fixed.Point26_6 {
	return fixed.Point26_6{X: point.X + fixed.I(dx), Y: point.Y + fixed.I(dy)}
}

func drawStringAt(img *image.RGBA, value string, face xfont.Face, dot fixed.Point26_6, c color.RGBA) {
	drawer := xfont.Drawer{
		Dst:  img,
		Src:  image.NewUniform(c),
		Face: face,
		Dot:  dot,
	}
	drawer.DrawString(value)
}

func randomGlyphWordsExcluding(pool []string, count int, excluded []string) []string {
	blocked := make(map[string]struct{}, len(excluded))
	for _, item := range excluded {
		blocked[item] = struct{}{}
	}
	candidates := make([]string, 0, len(pool))
	for _, item := range pool {
		if _, ok := blocked[item]; ok {
			continue
		}
		candidates = append(candidates, item)
	}
	indexes := randomIndexes(len(candidates), min(count, len(candidates)))
	out := make([]string, 0, len(indexes))
	for _, index := range indexes {
		out = append(out, candidates[index])
	}
	return out
}

func wordDecoyPoints(width, height int, targetPoints []types.Point, count int) []types.Point {
	if count <= 0 {
		return nil
	}
	anchors := []types.Point{
		{X: width / 6, Y: height / 4},
		{X: width / 2, Y: height / 4},
		{X: width * 5 / 6, Y: height / 4},
		{X: width / 6, Y: height / 2},
		{X: width / 2, Y: height / 2},
		{X: width * 5 / 6, Y: height / 2},
		{X: width / 6, Y: height * 3 / 4},
		{X: width / 2, Y: height * 3 / 4},
		{X: width * 5 / 6, Y: height * 3 / 4},
	}
	indexes := randomIndexes(len(anchors), len(anchors))
	out := make([]types.Point, 0, count)
	minDistance := wordPointMinDistance(width)
	for _, index := range indexes {
		point := anchors[index]
		point.X = clamp(point.X+randomJitter(-4, 4), 20, max(20, width-20))
		point.Y = clamp(point.Y+randomJitter(-4, 4), 20, max(20, height-20))
		if tooCloseToWordPoint(point, targetPoints, minDistance) || tooCloseToWordPoint(point, out, minDistance) {
			continue
		}
		out = append(out, point)
		if len(out) >= count {
			return out
		}
	}
	return out
}

func wordPointMinDistance(width int) float64 {
	return math.Max(52, float64(width)*0.16)
}

func tooCloseToWordPoint(point types.Point, others []types.Point, minDistance float64) bool {
	for _, other := range others {
		if pointDistance(point, other) < minDistance {
			return true
		}
	}
	return false
}

func pointDistance(a, b types.Point) float64 {
	return math.Hypot(float64(a.X-b.X), float64(a.Y-b.Y))
}

func cloneRGBA(src *image.RGBA) *image.RGBA {
	dst := image.NewRGBA(src.Bounds())
	draw.Draw(dst, dst.Bounds(), src, src.Bounds().Min, draw.Src)
	return dst
}

func pngDataURL(img image.Image) string {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

func fillRect(img *image.RGBA, x, y, width, height int, c color.RGBA) {
	draw.Draw(img, image.Rect(x, y, x+width, y+height).Intersect(img.Bounds()), &image.Uniform{C: c}, image.Point{}, draw.Over)
}

func fillRectOver(img *image.RGBA, x, y, width, height int, c color.RGBA) {
	fillRect(img, x, y, width, height, c)
}

func strokeRect(img *image.RGBA, x, y, width, height, thickness int, c color.RGBA) {
	for i := 0; i < thickness; i++ {
		fillRect(img, x+i, y+i, width-2*i, 1, c)
		fillRect(img, x+i, y+height-1-i, width-2*i, 1, c)
		fillRect(img, x+i, y+i, 1, height-2*i, c)
		fillRect(img, x+width-1-i, y+i, 1, height-2*i, c)
	}
}

func rgbaAt(img image.Image, x, y int) color.RGBA {
	return color.RGBAModel.Convert(img.At(x, y)).(color.RGBA)
}

func grayscaleRGBA(c color.RGBA) color.RGBA {
	luma := uint8(math.Round(0.299*float64(c.R) + 0.587*float64(c.G) + 0.114*float64(c.B)))
	return color.RGBA{R: luma, G: luma, B: luma, A: c.A}
}

func mixRGBA(a, b color.RGBA, ratio float64) color.RGBA {
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}
	return color.RGBA{
		R: uint8(float64(a.R)*(1-ratio) + float64(b.R)*ratio),
		G: uint8(float64(a.G)*(1-ratio) + float64(b.G)*ratio),
		B: uint8(float64(a.B)*(1-ratio) + float64(b.B)*ratio),
		A: uint8(float64(a.A)*(1-ratio) + float64(b.A)*ratio),
	}
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

func drawCircleOver(img *image.RGBA, cx, cy, radius int, c color.RGBA) {
	bounds := img.Bounds()
	r2 := radius * radius
	for y := cy - radius; y <= cy+radius; y++ {
		for x := cx - radius; x <= cx+radius; x++ {
			if x < bounds.Min.X || x >= bounds.Max.X || y < bounds.Min.Y || y >= bounds.Max.Y {
				continue
			}
			dx, dy := x-cx, y-cy
			if dx*dx+dy*dy <= r2 {
				blendPixelOver(img, x, y, c)
			}
		}
	}
}

func drawCircleOutlineOver(img *image.RGBA, cx, cy, radius, thickness int, c color.RGBA) {
	bounds := img.Bounds()
	outer := radius * radius
	innerRadius := max(0, radius-thickness)
	inner := innerRadius * innerRadius
	for y := cy - radius; y <= cy+radius; y++ {
		for x := cx - radius; x <= cx+radius; x++ {
			if x < bounds.Min.X || x >= bounds.Max.X || y < bounds.Min.Y || y >= bounds.Max.Y {
				continue
			}
			dx, dy := x-cx, y-cy
			d2 := dx*dx + dy*dy
			if d2 <= outer && d2 >= inner {
				blendPixelOver(img, x, y, c)
			}
		}
	}
}

func drawPolylineOver(img *image.RGBA, points []image.Point, width int, c color.RGBA) {
	if len(points) == 0 {
		return
	}
	if len(points) == 1 {
		drawCircleOver(img, points[0].X, points[0].Y, max(1, width/2), c)
		return
	}
	for i := 1; i < len(points); i++ {
		drawLineOver(img, points[i-1], points[i], width, c)
	}
}

func drawLineOver(img *image.RGBA, a, b image.Point, width int, c color.RGBA) {
	steps := max(absInt(b.X-a.X), absInt(b.Y-a.Y))
	if steps == 0 {
		drawCircleOver(img, a.X, a.Y, max(1, width/2), c)
		return
	}
	radius := max(1, width/2)
	for i := 0; i <= steps; i++ {
		t := float64(i) / float64(steps)
		x := int(math.Round(float64(a.X)*(1-t) + float64(b.X)*t))
		y := int(math.Round(float64(a.Y)*(1-t) + float64(b.Y)*t))
		drawCircleOver(img, x, y, radius, c)
	}
}

func fillPolygonOver(img *image.RGBA, points []image.Point, c color.RGBA) {
	if len(points) < 3 {
		return
	}
	minX, maxX := points[0].X, points[0].X
	minY, maxY := points[0].Y, points[0].Y
	for _, point := range points[1:] {
		minX = min(minX, point.X)
		maxX = max(maxX, point.X)
		minY = min(minY, point.Y)
		maxY = max(maxY, point.Y)
	}
	bounds := img.Bounds()
	minX = clamp(minX, bounds.Min.X, bounds.Max.X-1)
	maxX = clamp(maxX, bounds.Min.X, bounds.Max.X-1)
	minY = clamp(minY, bounds.Min.Y, bounds.Max.Y-1)
	maxY = clamp(maxY, bounds.Min.Y, bounds.Max.Y-1)
	for y := minY; y <= maxY; y++ {
		for x := minX; x <= maxX; x++ {
			if pointInPolygon(float64(x)+0.5, float64(y)+0.5, points) {
				blendPixelOver(img, x, y, c)
			}
		}
	}
}

func pointInPolygon(x, y float64, points []image.Point) bool {
	inside := false
	j := len(points) - 1
	for i := range points {
		xi, yi := float64(points[i].X), float64(points[i].Y)
		xj, yj := float64(points[j].X), float64(points[j].Y)
		if (yi > y) != (yj > y) && x < (xj-xi)*(y-yi)/(yj-yi)+xi {
			inside = !inside
		}
		j = i
	}
	return inside
}

func offsetImagePoints(points []image.Point, dx, dy int) []image.Point {
	out := make([]image.Point, 0, len(points))
	for _, point := range points {
		out = append(out, image.Point{X: point.X + dx, Y: point.Y + dy})
	}
	return out
}

func blendPixelOver(img *image.RGBA, x, y int, c color.RGBA) {
	bounds := img.Bounds()
	if x < bounds.Min.X || x >= bounds.Max.X || y < bounds.Min.Y || y >= bounds.Max.Y {
		return
	}
	alpha := float64(c.A) / 255
	if alpha <= 0 {
		return
	}
	dst := rgbaAt(img, x, y)
	img.SetRGBA(x, y, color.RGBA{
		R: uint8(math.Round(float64(c.R)*alpha + float64(dst.R)*(1-alpha))),
		G: uint8(math.Round(float64(c.G)*alpha + float64(dst.G)*(1-alpha))),
		B: uint8(math.Round(float64(c.B)*alpha + float64(dst.B)*(1-alpha))),
		A: 255,
	})
}

func overlayTemplate(base *image.RGBA, template *image.RGBA) *image.RGBA {
	dst := cloneRGBA(base)
	draw.Draw(dst, dst.Bounds(), template, image.Point{}, draw.Over)
	return dst
}

func metadataFloat(metadata map[string]any, keys ...string) (float64, bool) {
	for _, key := range keys {
		value, ok := metadata[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case float64:
			return typed, true
		case float32:
			return float64(typed), true
		case int:
			return float64(typed), true
		case int64:
			return float64(typed), true
		case json.Number:
			parsed, err := typed.Float64()
			return parsed, err == nil
		case string:
			parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
			return parsed, err == nil
		default:
			return 0, false
		}
	}
	return 0, false
}

func metadataBool(metadata map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		value, ok := metadata[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case bool:
			return typed, true
		case string:
			parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
			return parsed, err == nil
		default:
			return false, false
		}
	}
	return false, false
}

func metadataColors(metadata map[string]any, keys ...string) []color.RGBA {
	for _, key := range keys {
		value, ok := metadata[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case []string:
			return parseColorList(typed)
		case []any:
			values := make([]string, 0, len(typed))
			for _, item := range typed {
				if str, ok := item.(string); ok {
					values = append(values, str)
				}
			}
			return parseColorList(values)
		case string:
			return parseColorList(strings.FieldsFunc(typed, func(r rune) bool { return r == ',' || r == ';' }))
		}
	}
	return nil
}

func metadataGlyphs(metadata map[string]any, keys ...string) map[string][]string {
	for _, key := range keys {
		value, ok := metadata[key]
		if !ok {
			continue
		}
		out := map[string][]string{}
		switch typed := value.(type) {
		case map[string][]string:
			for glyph, pattern := range typed {
				if validGlyphPattern(pattern) {
					out[glyph] = pattern
				}
			}
		case map[string]any:
			for glyph, raw := range typed {
				switch pattern := raw.(type) {
				case []string:
					if validGlyphPattern(pattern) {
						out[glyph] = pattern
					}
				case []any:
					lines := make([]string, 0, len(pattern))
					for _, line := range pattern {
						if str, ok := line.(string); ok {
							lines = append(lines, str)
						}
					}
					if validGlyphPattern(lines) {
						out[glyph] = lines
					}
				}
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

func parseColorList(values []string) []color.RGBA {
	colors := make([]color.RGBA, 0, len(values))
	for _, value := range values {
		if c, ok := parseHexColor(value); ok {
			colors = append(colors, c)
		}
	}
	return colors
}

func parseHexColor(value string) (color.RGBA, bool) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "#")
	if len(value) != 6 {
		return color.RGBA{}, false
	}
	parsed, err := strconv.ParseUint(value, 16, 32)
	if err != nil {
		return color.RGBA{}, false
	}
	return color.RGBA{
		R: uint8(parsed >> 16),
		G: uint8(parsed >> 8),
		B: uint8(parsed),
		A: 255,
	}, true
}

func validGlyphPattern(pattern []string) bool {
	if len(pattern) == 0 {
		return false
	}
	width := len(pattern[0])
	if width == 0 {
		return false
	}
	for _, line := range pattern {
		if len(line) != width {
			return false
		}
		for _, pixel := range line {
			if pixel != '0' && pixel != '1' {
				return false
			}
		}
	}
	return true
}

func drawBlockGlyph(img *image.RGBA, value string, cx, cy, scale int, c color.RGBA, custom map[string][]string, distortionStrength float64) {
	distortionStrength = blockGlyphDistortionStrength(distortionStrength)
	pattern, ok := custom[value]
	if !ok {
		pattern, ok = glyphs.Pattern(value)
	}
	if !ok {
		return
	}
	width, height := blockGlyphSize(pattern, scale)
	if width <= 0 || height <= 0 {
		return
	}
	pad := max(8, scale*2)
	layer := image.NewRGBA(image.Rect(0, 0, width+pad*2, height+pad*2))
	startX := pad
	startY := pad
	shadow := color.RGBA{R: 255, G: 255, B: 255, A: 235}
	halo := color.RGBA{R: 255, G: 255, B: 255, A: 170}
	darkEdge := color.RGBA{R: 15, G: 23, B: 42, A: 96}
	for row, line := range pattern {
		for col, pixel := range line {
			if pixel != '1' {
				continue
			}
			x := startX + col*scale
			y := startY + row*scale
			fillRect(layer, x-2, y, scale, scale, halo)
			fillRect(layer, x+2, y, scale, scale, halo)
			fillRect(layer, x, y-2, scale, scale, halo)
			fillRect(layer, x, y+2, scale, scale, halo)
			fillRect(layer, x-1, y, scale, scale, darkEdge)
			fillRect(layer, x+1, y, scale, scale, darkEdge)
			fillRect(layer, x, y-1, scale, scale, darkEdge)
			fillRect(layer, x, y+1, scale, scale, darkEdge)
			fillRect(layer, x+2, y+2, scale, scale, shadow)
			fillRect(layer, x, y, scale, scale, c)
		}
	}
	distorted := distortWordGlyphLayer(layer, randomWordGlyphDistortion(distortionStrength, max(width, height)))
	blendGlyphLayerAt(img, distorted, cx, cy)
}

type wordGlyphDistortionStyle struct {
	Strength   float64
	Angle      float64
	ShearX     float64
	ShearY     float64
	ScaleX     float64
	ScaleY     float64
	WaveX      float64
	WaveY      float64
	WaveLength float64
	PhaseX     float64
	PhaseY     float64
}

func randomWordGlyphDistortion(strength float64, glyphSize int) wordGlyphDistortionStyle {
	strength = clampFloat(strength, 0, 1.5)
	if strength <= 0 {
		return wordGlyphDistortionStyle{ScaleX: 1, ScaleY: 1}
	}
	sizeScale := math.Max(1, float64(glyphSize)/32)
	return wordGlyphDistortionStyle{
		Strength:   strength,
		Angle:      randomFloat(-0.32, 0.32) * strength,
		ShearX:     randomFloat(-0.20, 0.20) * strength,
		ShearY:     randomFloat(-0.12, 0.12) * strength,
		ScaleX:     1 + randomFloat(-0.10, 0.14)*strength,
		ScaleY:     1 + randomFloat(-0.10, 0.12)*strength,
		WaveX:      randomFloat(-2.0, 2.0) * sizeScale * strength,
		WaveY:      randomFloat(-1.4, 1.4) * sizeScale * strength,
		WaveLength: randomFloat(14, 28) * sizeScale,
		PhaseX:     randomFloat(0, math.Pi*2),
		PhaseY:     randomFloat(0, math.Pi*2),
	}
}

func distortWordGlyphLayer(src *image.RGBA, style wordGlyphDistortionStyle) *image.RGBA {
	if style.Strength <= 0 {
		return src
	}
	bounds := src.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if width <= 0 || height <= 0 {
		return src
	}
	pad := max(5, int(math.Ceil(float64(max(width, height))*0.24*style.Strength))+5)
	dst := image.NewRGBA(image.Rect(0, 0, width+pad*2, height+pad*2))
	sin, cos := math.Sin(style.Angle), math.Cos(style.Angle)
	a := cos*style.ScaleX - sin*style.ShearY
	b := cos*style.ShearX - sin*style.ScaleY
	c := sin*style.ScaleX + cos*style.ShearY
	d := sin*style.ShearX + cos*style.ScaleY
	det := a*d - b*c
	if math.Abs(det) < 0.0001 {
		return src
	}
	srcCX := float64(bounds.Min.X) + float64(width)/2
	srcCY := float64(bounds.Min.Y) + float64(height)/2
	dstCX := float64(dst.Bounds().Dx()) / 2
	dstCY := float64(dst.Bounds().Dy()) / 2
	for y := 0; y < dst.Bounds().Dy(); y++ {
		for x := 0; x < dst.Bounds().Dx(); x++ {
			dx := float64(x) + 0.5 - dstCX
			dy := float64(y) + 0.5 - dstCY
			sx := (d*dx - b*dy) / det
			sy := (-c*dx + a*dy) / det
			if style.WaveLength > 0 {
				sx += style.WaveX * math.Sin((sy+style.PhaseX)/style.WaveLength)
				sy += style.WaveY * math.Sin((sx+style.PhaseY)/style.WaveLength)
			}
			pixel := sampleWordGlyphPixel(src, srcCX+sx, srcCY+sy)
			if pixel.A > 0 {
				dst.SetRGBA(x, y, pixel)
			}
		}
	}
	return dst
}

func sampleWordGlyphPixel(src *image.RGBA, x, y float64) color.RGBA {
	bounds := src.Bounds()
	if x < float64(bounds.Min.X) || y < float64(bounds.Min.Y) || x > float64(bounds.Max.X-1) || y > float64(bounds.Max.Y-1) {
		return color.RGBA{}
	}
	x0 := int(math.Floor(x))
	y0 := int(math.Floor(y))
	x1 := min(x0+1, bounds.Max.X-1)
	y1 := min(y0+1, bounds.Max.Y-1)
	tx := x - float64(x0)
	ty := y - float64(y0)
	c00 := rgbaAt(src, x0, y0)
	c10 := rgbaAt(src, x1, y0)
	c01 := rgbaAt(src, x0, y1)
	c11 := rgbaAt(src, x1, y1)
	return color.RGBA{
		R: bilinearByte(c00.R, c10.R, c01.R, c11.R, tx, ty),
		G: bilinearByte(c00.G, c10.G, c01.G, c11.G, tx, ty),
		B: bilinearByte(c00.B, c10.B, c01.B, c11.B, tx, ty),
		A: bilinearByte(c00.A, c10.A, c01.A, c11.A, tx, ty),
	}
}

func bilinearByte(c00, c10, c01, c11 uint8, tx, ty float64) uint8 {
	top := float64(c00)*(1-tx) + float64(c10)*tx
	bottom := float64(c01)*(1-tx) + float64(c11)*tx
	return uint8(math.Round(top*(1-ty) + bottom*ty))
}

func blendGlyphLayerAt(dst *image.RGBA, layer *image.RGBA, cx, cy int) {
	bounds := dst.Bounds()
	layerBounds := layer.Bounds()
	originX, originY := glyphLayerOrigin(bounds, layerBounds.Dx(), layerBounds.Dy(), cx, cy)
	paintBounds := bounds.Inset(1)
	for y := layerBounds.Min.Y; y < layerBounds.Max.Y; y++ {
		for x := layerBounds.Min.X; x < layerBounds.Max.X; x++ {
			pixel := rgbaAt(layer, x, y)
			if pixel.A == 0 {
				continue
			}
			gx := originX + x - layerBounds.Min.X
			gy := originY + y - layerBounds.Min.Y
			if gx < paintBounds.Min.X || gx >= paintBounds.Max.X || gy < paintBounds.Min.Y || gy >= paintBounds.Max.Y {
				continue
			}
			blendPixelOver(dst, gx, gy, pixel)
		}
	}
}

func glyphLayerOrigin(bounds image.Rectangle, layerWidth, layerHeight, cx, cy int) (int, int) {
	const pad = 3
	minX := bounds.Min.X + pad
	maxX := bounds.Max.X - pad - layerWidth
	minY := bounds.Min.Y + pad
	maxY := bounds.Max.Y - pad - layerHeight
	if maxX < minX {
		minX, maxX = bounds.Min.X, bounds.Max.X-layerWidth
	}
	if maxY < minY {
		minY, maxY = bounds.Min.Y, bounds.Max.Y-layerHeight
	}
	return clamp(cx-layerWidth/2, minX, maxX), clamp(cy-layerHeight/2, minY, maxY)
}

func randomFloat(minValue, maxValue float64) float64 {
	if maxValue <= minValue {
		return minValue
	}
	return minValue + (maxValue-minValue)*float64(randomIndex(10001))/10000
}

func blockGlyphSize(pattern []string, scale int) (int, int) {
	if scale <= 0 || len(pattern) == 0 {
		return 0, 0
	}
	cols := 0
	for _, line := range pattern {
		if len(line) > cols {
			cols = len(line)
		}
	}
	return cols * scale, len(pattern) * scale
}

func clampBlockGlyphCenter(bounds image.Rectangle, glyphWidth, glyphHeight, cx, cy int) (int, int) {
	const pad = 3
	minX := bounds.Min.X + pad + glyphWidth/2
	maxX := bounds.Max.X - pad - (glyphWidth - glyphWidth/2)
	minY := bounds.Min.Y + pad + glyphHeight/2
	maxY := bounds.Max.Y - pad - (glyphHeight - glyphHeight/2)
	if maxX < minX {
		minX, maxX = bounds.Min.X, bounds.Max.X
	}
	if maxY < minY {
		minY, maxY = bounds.Min.Y, bounds.Max.Y
	}
	return clamp(cx, minX, maxX), clamp(cy, minY, maxY)
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
	"山": {
		"000010000",
		"000010000",
		"100010001",
		"100010001",
		"100010001",
		"100010001",
		"111111111",
		"100000001",
		"100000001",
	},
	"水": {
		"000010000",
		"100010001",
		"010010010",
		"001010100",
		"000111000",
		"001010100",
		"010010010",
		"100010001",
		"000010000",
	},
	"火": {
		"000010000",
		"010010010",
		"010010010",
		"001010100",
		"000111000",
		"001010100",
		"010000010",
		"100000001",
		"000000000",
	},
	"木": {
		"000010000",
		"000010000",
		"000010000",
		"111111111",
		"001010100",
		"010010010",
		"100010001",
		"000010000",
		"000010000",
	},
	"田": {
		"111111111",
		"100010001",
		"100010001",
		"111111111",
		"100010001",
		"100010001",
		"100010001",
		"111111111",
		"000000000",
	},
	"日": {
		"111111111",
		"100000001",
		"100000001",
		"111111111",
		"100000001",
		"100000001",
		"100000001",
		"111111111",
		"000000000",
	},
	"月": {
		"011111100",
		"010000100",
		"010000100",
		"011111100",
		"010000100",
		"010000100",
		"010000100",
		"100001100",
		"000000000",
	},
	"口": {
		"111111111",
		"100000001",
		"100000001",
		"100000001",
		"100000001",
		"100000001",
		"100000001",
		"111111111",
		"000000000",
	},
	"中": {
		"000010000",
		"111111111",
		"100010001",
		"100010001",
		"111111111",
		"000010000",
		"000010000",
		"000010000",
		"000010000",
	},
	"王": {
		"111111111",
		"000010000",
		"000010000",
		"011111110",
		"000010000",
		"000010000",
		"000010000",
		"111111111",
		"000000000",
	},
	"文": {
		"000010000",
		"000010000",
		"111111111",
		"000010000",
		"000101000",
		"001000100",
		"010000010",
		"100000001",
		"000000000",
	},
}

func anyInt(value any, fallback int) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(math.Round(typed))
	case json.Number:
		parsed, err := typed.Int64()
		if err == nil {
			return int(parsed)
		}
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func clamp(value, min, max int) int {
	if max < min {
		return min
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func clampFloat(value, min, max float64) float64 {
	if max < min {
		return min
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

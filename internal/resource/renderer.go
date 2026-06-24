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
	"time"

	"captcha/internal/types"

	"github.com/srwiley/oksvg"
	"github.com/srwiley/rasterx"
	_ "golang.org/x/image/webp"
)

const maxResourceImageBytes = 20 * 1024 * 1024
const (
	sliderPieceSizeFallback  = 47
	slider2PieceSizeFallback = sliderPieceSizeFallback
	sliderMaskOpacity        = 0.46
	sliderPieceBorder        = 0.42
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
			return payload
		}
	}

	switch payload.Type {
	case types.CaptchaSlider, types.CaptchaSlider2:
		background, ok := loadBackgroundResourceImage(resources)
		if !ok {
			return payload
		}
		base := resizeNearest(background, payload.View.Width, payload.View.Height)
		sliderTemplate, _ := loadResourceImageByType(resources, "slider_template")
		size := sliderPieceSize(payload.Parameters, sliderPieceSizeFallbackFor(payload.Type))
		if sliderTemplate == nil {
			sliderTemplate = defaultSliderTemplateFactory(size)
		}
		composed, piece := composeSlider(base, answer, sliderTemplate, size)
		if payload.Type == types.CaptchaSlider2 {
			composed = composeSliderDecoys(composed, answer, sliderTemplate, size)
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
		base := resizeNearest(background, payload.View.Width, payload.View.Height)
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
		background, ok := loadBackgroundResourceImage(resources)
		if !ok {
			return payload
		}
		base := resizeNearest(background, payload.View.Width, payload.View.Height)
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
		base := resizeNearest(background, payload.View.Width, payload.View.Height)
		payload.Image = pngDataURL(composeWordImage(base, payload.Words, answer.Points, loadFontOptions(resources)))
	case types.CaptchaImageClick:
		background, ok := loadBackgroundResourceImage(resources)
		if !ok {
			return payload
		}
		base := resizeNearest(background, payload.View.Width, payload.View.Height)
		image, words := composeIconClickImage(base, payload, answer.Points, resources)
		payload.Image = pngDataURL(image)
		if len(words) > 0 {
			payload.Words = words
			payload.Prompt = "依次点击：" + strings.Join(words, "、")
		}
	case types.CaptchaJigsaw:
		background, ok := loadBackgroundResourceImage(resources)
		if !ok {
			return payload
		}
		base := resizeNearest(background, payload.View.Width, payload.View.Height)
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
	if img, ok := loadResourceImageByType(resources, "background_image"); ok {
		return img, true
	}
	return loadResourceImageByType(resources, "background_library")
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
	targetImages := byCategory[targetCategory]
	for row := 0; row < rows; row++ {
		for col := 0; col < cols; col++ {
			index := row*cols + col
			rect := image.Rect(col*tileWidth, row*tileHeight, (col+1)*tileWidth, (row+1)*tileHeight)
			choices := decoys
			if _, ok := targets[index]; ok {
				choices = targetImages
			}
			tile := choices[randomIndex(len(choices))]
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
	data, contentType, ok := loadStoredResourceBytes(resource)
	if !ok {
		return nil, false
	}
	return decodeResourceImage(resource, data, contentType)
}

func loadStoredResourceBytes(resource types.CaptchaResource) ([]byte, string, bool) {
	switch strings.ToLower(strings.TrimSpace(resource.StorageType)) {
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
	case "background_image", "background_library":
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
	return softenAlphaMask(dst)
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

func softenAlphaMask(src *image.RGBA) *image.RGBA {
	bounds := src.Bounds()
	dst := image.NewRGBA(bounds)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			var weighted, weight int
			for dy := -1; dy <= 1; dy++ {
				for dx := -1; dx <= 1; dx++ {
					sx, sy := x+dx, y+dy
					if sx < bounds.Min.X || sx >= bounds.Max.X || sy < bounds.Min.Y || sy >= bounds.Max.Y {
						continue
					}
					w := 1
					if dx == 0 && dy == 0 {
						w = 4
					} else if dx == 0 || dy == 0 {
						w = 2
					}
					weighted += int(colorAlpha(src.At(sx, sy))) * w
					weight += w
				}
			}
			if weight == 0 {
				continue
			}
			alpha := uint8(weighted / weight)
			dst.SetRGBA(x, y, color.RGBA{R: alpha, G: alpha, B: alpha, A: alpha})
		}
	}
	return dst
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
			img.Set(x+px, y+py, sliderBlackMaskPixel(source, alpha, sliderMaskOpacity))
			border := sliderTemplateEdgeBandStrength(mask, px, py, 2)
			piecePixel := sliderPieceBorderPixel(source, border)
			piece.Set(px, py, color.NRGBA{R: piecePixel.R, G: piecePixel.G, B: piecePixel.B, A: alpha})
		}
	}
	return img, piece
}

func sliderBlackMaskPixel(source color.RGBA, alpha uint8, opacity float64) color.RGBA {
	return mixRGBA(source, color.RGBA{A: 255}, clampFloat(opacity*float64(alpha)/255, 0, 1))
}

func sliderPieceBorderPixel(source color.RGBA, border float64) color.RGBA {
	return mixRGBA(source, color.RGBA{A: 255}, clampFloat(border*sliderPieceBorder, 0, sliderPieceBorder))
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
	return []image.Point{
		{X: 18, Y: 24},
		{X: max(0, width-size-18), Y: max(0, height-size-22)},
	}
}

func drawSliderMaskGhost(img *image.RGBA, mask image.Image, ox, oy, size int, opacity float64) {
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			alpha := colorAlpha(mask.At(x, y))
			if alpha <= 4 {
				continue
			}
			gx, gy := ox+x, oy+y
			if !image.Pt(gx, gy).In(img.Bounds()) {
				continue
			}
			source := rgbaAt(img, gx, gy)
			img.Set(gx, gy, sliderBlackMaskPixel(source, alpha, opacity))
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
	return softenAlphaMask(mask)
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
			if colorAlpha(mask.At(x+dx, y+dy)) <= 42 {
				best = distance
			}
		}
	}
	if best > float64(radius) {
		return 0
	}
	return math.Max(0, math.Min(1, (float64(radius)+0.5-best)/float64(radius)))
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

func composeIconClickImage(base *image.RGBA, payload types.RenderPayload, points []types.Point, resources []types.CaptchaResource) (*image.RGBA, []string) {
	img := cloneRGBA(base)
	icons := loadResourceImagesByType(resources, "icon_library")
	labels := make([]string, 0, min(len(payload.Words), len(points)))
	if len(icons) > 0 {
		for i, point := range points {
			icon := icons[i%len(icons)]
			drawResourceIcon(img, icon.Image, point.X, point.Y, 44, clickPalette(i))
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
		drawGenericIconMarker(img, point.X, point.Y, i, clickPalette(i))
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
	src = resizeNearest(src, dst.Bounds().Dx(), dst.Bounds().Dy())
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
	drawCircleOver(img, cx+2, cy+3, size/2+7, color.RGBA{R: 15, G: 23, B: 42, A: 60})
	drawCircleOver(img, cx, cy, size/2+6, color.RGBA{R: 255, G: 255, B: 255, A: 224})
	resized := resizeNearest(icon, size, size)
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
			blendPixelOver(img, originX+x, originY+y, c)
		}
	}
	drawCircleOutlineOver(img, cx, cy, size/2+7, 2, color.RGBA{R: 255, G: 255, B: 255, A: 180})
}

func iconLooksMonochrome(c color.RGBA) bool {
	return absInt(int(c.R)-int(c.G)) < 10 && absInt(int(c.G)-int(c.B)) < 10
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

func drawGenericIconMarker(img *image.RGBA, cx, cy, index int, c color.RGBA) {
	drawCircleOver(img, cx+2, cy+3, 28, color.RGBA{R: 15, G: 23, B: 42, A: 68})
	drawCircleOver(img, cx, cy, 27, color.RGBA{R: 255, G: 255, B: 255, A: 228})
	switch index % 4 {
	case 0:
		drawCircleOver(img, cx, cy, 15, c)
	case 1:
		fillRectOver(img, cx-15, cy-15, 30, 30, c)
	case 2:
		fillPolygonOver(img, []image.Point{{X: cx, Y: cy - 18}, {X: cx + 18, Y: cy + 14}, {X: cx - 18, Y: cy + 14}}, c)
	default:
		fillPolygonOver(img, []image.Point{{X: cx, Y: cy - 18}, {X: cx + 18, Y: cy}, {X: cx, Y: cy + 18}, {X: cx - 18, Y: cy}}, c)
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
		fillRectOver(out, x-1, 0, 2, height, color.RGBA{R: 255, G: 255, B: 255, A: 145})
	}
	for y := tileHeight; y < height; y += tileHeight {
		fillRectOver(out, 0, y-1, width, 2, color.RGBA{R: 255, G: 255, B: 255, A: 145})
	}
	strokeRect(out, 0, 0, width, height, 1, color.RGBA{R: 203, G: 213, B: 225, A: 190})
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

func concatControlMax(offset, viewWidth, splitX, pieceWidth int) int {
	_ = offset
	_ = splitX
	_ = pieceWidth
	return min(viewWidth, concatMaxMovement)
}

type fontOptions struct {
	Scale  int
	Colors []color.RGBA
	Glyphs map[string][]string
}

func loadFontOptions(resources []types.CaptchaResource) fontOptions {
	options := fontOptions{Scale: 5}
	for _, item := range resources {
		if item.ResourceType != "font" || !strings.EqualFold(item.Status, "active") {
			continue
		}
		options = mergeFontMetadata(options, item.Metadata)
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
	if colors := metadataColors(metadata, "palette", "colors"); len(colors) > 0 {
		options.Colors = colors
	}
	if glyphs := metadataGlyphs(metadata, "glyphs", "patterns"); len(glyphs) > 0 {
		options.Glyphs = glyphs
	}
	return options
}

func composeWordImage(base *image.RGBA, words []string, points []types.Point, options fontOptions) *image.RGBA {
	img := cloneRGBA(base)
	colors := []color.RGBA{
		{R: 31, G: 41, B: 55, A: 255},
		{R: 37, G: 99, B: 235, A: 255},
		{R: 190, G: 24, B: 93, A: 255},
	}
	if len(options.Colors) > 0 {
		colors = options.Colors
	}
	scale := options.Scale
	if scale <= 0 {
		scale = 5
	}
	for i, word := range words {
		if i >= len(points) {
			break
		}
		drawBlockGlyph(img, word, points[i].X, points[i].Y, scale, colors[i%len(colors)], options.Glyphs)
	}
	return img
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

func drawBlockGlyph(img *image.RGBA, value string, cx, cy, scale int, c color.RGBA, custom map[string][]string) {
	pattern, ok := custom[value]
	if !ok {
		pattern, ok = glyphPatterns[value]
	}
	if !ok {
		return
	}
	width := len(pattern[0]) * scale
	height := len(pattern) * scale
	startX := cx - width/2
	startY := cy - height/2
	shadow := color.RGBA{R: 255, G: 255, B: 255, A: 235}
	darkEdge := color.RGBA{R: 15, G: 23, B: 42, A: 84}
	for row, line := range pattern {
		for col, pixel := range line {
			if pixel != '1' {
				continue
			}
			x := startX + col*scale
			y := startY + row*scale
			fillRect(img, x-1, y, scale, scale, darkEdge)
			fillRect(img, x+1, y, scale, scale, darkEdge)
			fillRect(img, x, y-1, scale, scale, darkEdge)
			fillRect(img, x, y+1, scale, scale, darkEdge)
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

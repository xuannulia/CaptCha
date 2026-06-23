package resource

import (
	"bytes"
	"crypto/sha256"
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
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"captcha/internal/types"
)

const maxResourceImageBytes = 20 * 1024 * 1024
const sliderTemplateSize = 42
const concatMaxMovement = 160

var resourceHTTPClient = &http.Client{
	Timeout: 3 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || unsafeRemoteURL(req.URL) {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// ApplyVisuals composes server-side challenge images from selected local resources.
// It deliberately falls back to the engine generated payload when a resource cannot
// be decoded, so resource rollout cannot break the verification path.
func ApplyVisuals(payload types.RenderPayload, answer types.Answer, resources []types.CaptchaResource) types.RenderPayload {
	if payload.View.Width <= 0 || payload.View.Height <= 0 {
		return payload
	}
	background, ok := loadResourceImageByType(resources, "background_image")
	if !ok {
		return payload
	}
	base := resizeNearest(background, payload.View.Width, payload.View.Height)
	switch payload.Type {
	case types.CaptchaSlider:
		sliderTemplate, _ := loadResourceImageByType(resources, "slider_template")
		composed, piece := composeSlider(base, answer, sliderTemplate)
		payload.Image = pngDataURL(composed)
		payload.Piece = pngDataURL(piece)
	case types.CaptchaRotate:
		start := ((360-answer.Angle)%360 + 360) % 360
		rotated := rotateImage(base, start)
		if rotateTemplate, ok := loadResourceImageByType(resources, "rotate_template"); ok {
			rotated = overlayTemplate(rotated, resizeNearest(rotateTemplate, payload.View.Width, payload.View.Height))
		}
		payload.Image = pngDataURL(rotated)
	case types.CaptchaConcat:
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
		payload.Image = pngDataURL(composeWordImage(base, payload.Words, answer.Points, loadFontOptions(resources)))
	}
	return payload
}

func loadResourceImageByType(resources []types.CaptchaResource, resourceType string) (image.Image, bool) {
	for _, item := range resources {
		if item.ResourceType != resourceType || !strings.EqualFold(item.Status, "active") {
			continue
		}
		img, ok := loadStoredResourceImage(item)
		if ok {
			return img, true
		}
	}
	return nil, false
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

func imageFormatMIME(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "gif":
		return "image/gif"
	case "jpeg":
		return "image/jpeg"
	case "png":
		return "image/png"
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

func composeSlider(base *image.RGBA, answer types.Answer, template image.Image) (*image.RGBA, *image.RGBA) {
	img := cloneRGBA(base)
	size := sliderTemplateSize
	x := clamp(answer.X, 0, img.Bounds().Dx()-size)
	y := clamp(answer.Y, 0, img.Bounds().Dy()-size)
	if template != nil {
		mask := resizeNearest(template, size, size)
		piece := image.NewRGBA(image.Rect(0, 0, size, size))
		for py := 0; py < size; py++ {
			for px := 0; px < size; px++ {
				alpha := colorAlpha(mask.At(px, py))
				if alpha <= 12 {
					continue
				}
				baseColor := color.NRGBAModel.Convert(base.At(x+px, y+py)).(color.NRGBA)
				baseColor.A = alpha
				piece.Set(px, py, baseColor)
				fillRect(img, x+px, y+py, 1, 1, color.RGBA{R: 15, G: 23, B: 42, A: uint8(int(alpha) * 110 / 255)})
			}
		}
		strokeRect(img, x, y, size, size, 2, color.RGBA{R: 248, G: 250, B: 252, A: 220})
		return img, piece
	}
	piece := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.Draw(piece, piece.Bounds(), base, image.Point{X: x, Y: y}, draw.Src)
	strokeRect(piece, 0, 0, size, size, 3, color.RGBA{R: 37, G: 99, B: 235, A: 255})

	fillRect(img, x, y, size, size, color.RGBA{R: 15, G: 23, B: 42, A: 110})
	strokeRect(img, x, y, size, size, 3, color.RGBA{R: 248, G: 250, B: 252, A: 230})
	return img, piece
}

func colorAlpha(c color.Color) uint8 {
	_, _, _, alpha := c.RGBA()
	return uint8(alpha >> 8)
}

func rotateImage(src *image.RGBA, angle int) *image.RGBA {
	bounds := src.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	fillRect(dst, 0, 0, width, height, color.RGBA{R: 248, G: 250, B: 252, A: 255})
	cx := float64(width-1) / 2
	cy := float64(height-1) / 2
	radians := -float64(angle) * math.Pi / 180
	cosine := math.Cos(radians)
	sine := math.Sin(radians)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			dx := float64(x) - cx
			dy := float64(y) - cy
			sx := int(math.Round(cx + dx*cosine - dy*sine))
			sy := int(math.Round(cy + dx*sine + dy*cosine))
			if sx >= 0 && sx < width && sy >= 0 && sy < height {
				dst.Set(x, y, src.At(sx, sy))
			}
		}
	}
	return dst
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

package resource

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"captcha/internal/types"
)

const (
	maxResourceDimension = 4096
	maxResourceSizeBytes = 20 * 1024 * 1024
)

var allowedResourceTypes = map[string]struct{}{
	"background_image":          {},
	"background_library":        {},
	"concat_background_image":   {},
	"concat_background_library": {},
	"jigsaw_background_image":   {},
	"jigsaw_background_library": {},
	"rotate_library":            {},
	"grid_category_library":     {},
	"slider_template":           {},
	"rotate_template":           {},
	"concat_template":           {},
	"font":                      {},
	"icon":                      {},
	"icon_library":              {},
	"degree_template":           {},
	"curve_template":            {},
	"gesture_template":          {},
	"jigsaw_template":           {},
}

var allowedStorageTypes = map[string]struct{}{
	"embedded":       {},
	"classpath":      {},
	"file":           {},
	"url":            {},
	"object_storage": {},
	"database":       {},
}

var allowedCaptchaTypes = map[types.CaptchaType]struct{}{
	types.CaptchaAuto:           {},
	types.CaptchaGesture:        {},
	types.CaptchaCurve:          {},
	types.CaptchaCurve2:         {},
	types.CaptchaCurve3:         {},
	types.CaptchaSlider:         {},
	types.CaptchaSlider2:        {},
	types.CaptchaRotate:         {},
	types.CaptchaConcat:         {},
	types.CaptchaRotateDegree:   {},
	types.CaptchaWordImageClick: {},
	types.CaptchaImageClick:     {},
	types.CaptchaJigsaw:         {},
	types.CaptchaGridImageClick: {},
}

var allowedStatuses = map[string]struct{}{
	"active":   {},
	"disabled": {},
}

var imageMIMETypes = map[string]struct{}{
	"image/gif":     {},
	"image/jpeg":    {},
	"image/png":     {},
	"image/svg+xml": {},
	"image/webp":    {},
}

var fontMIMETypes = map[string]struct{}{
	"application/font-woff":  {},
	"application/font-woff2": {},
	"application/x-font-otf": {},
	"application/x-font-ttf": {},
	"font/otf":               {},
	"font/sfnt":              {},
	"font/ttf":               {},
	"font/woff":              {},
	"font/woff2":             {},
}

// ValidateAndNormalize prepares an admin-created resource for storage.
// It validates declarative metadata only; it does not fetch remote content.
func ValidateAndNormalize(input types.CaptchaResource) (types.CaptchaResource, error) {
	resource := input
	resource.ClientID = trimDefault(resource.ClientID, "demo")
	resource.Scene = strings.TrimSpace(resource.Scene)
	resource.ResourceType = strings.ToLower(strings.TrimSpace(resource.ResourceType))
	resource.StorageType = strings.ToLower(strings.TrimSpace(resource.StorageType))
	resource.URI = strings.TrimSpace(resource.URI)
	resource.Tag = strings.TrimSpace(resource.Tag)
	resource.Status = strings.ToLower(strings.TrimSpace(resource.Status))
	resource.Checksum = strings.TrimSpace(resource.Checksum)

	if resource.CaptchaType == "" {
		resource.CaptchaType = types.CaptchaAuto
	}
	if resource.StorageType == "" {
		resource.StorageType = "embedded"
	}
	if resource.Status == "" {
		resource.Status = "active"
	}
	if _, ok := allowedCaptchaTypes[resource.CaptchaType]; !ok {
		return types.CaptchaResource{}, fmt.Errorf("unsupported captcha_type %q", resource.CaptchaType)
	}
	if _, ok := allowedResourceTypes[resource.ResourceType]; !ok {
		return types.CaptchaResource{}, fmt.Errorf("unsupported resource_type %q", resource.ResourceType)
	}
	if _, ok := allowedStorageTypes[resource.StorageType]; !ok {
		return types.CaptchaResource{}, fmt.Errorf("unsupported storage_type %q", resource.StorageType)
	}
	if _, ok := allowedStatuses[resource.Status]; !ok {
		return types.CaptchaResource{}, fmt.Errorf("unsupported status %q", resource.Status)
	}
	if resource.URI == "" {
		return types.CaptchaResource{}, fmt.Errorf("resource uri is required")
	}
	scheme, err := validateResourceURI(resource.StorageType, resource.URI)
	if err != nil {
		return types.CaptchaResource{}, err
	}
	metadata, err := normalizeMetadata(resource.ResourceType, resource.Metadata)
	if err != nil {
		return types.CaptchaResource{}, err
	}
	checksum, err := normalizeChecksum(resource.Checksum, metadata)
	if err != nil {
		return types.CaptchaResource{}, err
	}
	resource.Checksum = checksum
	if metadata == nil {
		metadata = make(map[string]any, 2)
	}
	metadata["resource_family"] = resourceFamily(resource.ResourceType)
	metadata["uri_scheme"] = scheme
	resource.Metadata = metadata
	return resource, nil
}

func trimDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func validateResourceURI(storageType, rawURI string) (string, error) {
	parsed, err := url.Parse(rawURI)
	if err != nil {
		return "", fmt.Errorf("invalid resource uri")
	}
	switch storageType {
	case "embedded":
		if parsed.Scheme != "embedded" || parsed.Host == "" {
			return "", fmt.Errorf("embedded resources must use embedded:// uri")
		}
		return parsed.Scheme, nil
	case "classpath":
		if parsed.Scheme != "classpath" || (parsed.Host == "" && parsed.Path == "") {
			return "", fmt.Errorf("classpath resources must use classpath:// uri")
		}
		return parsed.Scheme, nil
	case "url":
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return "", fmt.Errorf("url resources must use http or https")
		}
		if parsed.Hostname() == "" || isUnsafeRemoteHost(parsed.Hostname()) {
			return "", fmt.Errorf("url resource host is not allowed")
		}
		return parsed.Scheme, nil
	case "object_storage":
		if !oneOf(parsed.Scheme, "s3", "oss", "cos", "obs", "minio") || parsed.Host == "" || parsed.Path == "" || parsed.User != nil {
			return "", fmt.Errorf("object storage resources must use s3/oss/cos/obs/minio uri")
		}
		return parsed.Scheme, nil
	case "database":
		if !oneOf(parsed.Scheme, "db", "database", "resource") || parsed.Host == "" {
			return "", fmt.Errorf("database resources must use db/database/resource uri")
		}
		return parsed.Scheme, nil
	case "file":
		if parsed.Scheme == "file" {
			if parsed.Host != "" || parsed.Path == "" || !filepath.IsAbs(parsed.Path) {
				return "", fmt.Errorf("file resources must use local absolute file uri")
			}
			return parsed.Scheme, nil
		}
		if filepath.IsAbs(rawURI) {
			return "file", nil
		}
		return "", fmt.Errorf("file resources must use an absolute path")
	default:
		return "", fmt.Errorf("unsupported storage_type %q", storageType)
	}
}

func isUnsafeRemoteHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast()
}

func normalizeMetadata(resourceType string, input map[string]any) (map[string]any, error) {
	metadata := cloneMetadata(input)
	if width, ok, err := metadataInt(metadata, "width"); err != nil {
		return nil, err
	} else if ok && (width <= 0 || width > maxResourceDimension) {
		return nil, fmt.Errorf("resource width out of range")
	}
	if height, ok, err := metadataInt(metadata, "height"); err != nil {
		return nil, err
	} else if ok && (height <= 0 || height > maxResourceDimension) {
		return nil, fmt.Errorf("resource height out of range")
	}
	if size, ok, err := metadataInt(metadata, "size_bytes", "size"); err != nil {
		return nil, err
	} else if ok && (size <= 0 || size > maxResourceSizeBytes) {
		return nil, fmt.Errorf("resource size out of range")
	}
	if value, ok := metadataString(metadata, "mime_type", "content_type"); ok {
		mimeType := strings.ToLower(strings.TrimSpace(value))
		if err := validateMIMEType(resourceType, mimeType); err != nil {
			return nil, err
		}
		metadata["mime_type"] = mimeType
		delete(metadata, "content_type")
	}
	return metadata, nil
}

func cloneMetadata(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	metadata := make(map[string]any, len(input))
	for key, value := range input {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		metadata[key] = value
	}
	return metadata
}

func metadataInt(metadata map[string]any, keys ...string) (int64, bool, error) {
	if len(metadata) == 0 {
		return 0, false, nil
	}
	for _, key := range keys {
		value, ok := metadata[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case int:
			return int64(typed), true, nil
		case int64:
			return typed, true, nil
		case float64:
			if typed != float64(int64(typed)) {
				return 0, true, fmt.Errorf("metadata %s must be an integer", key)
			}
			return int64(typed), true, nil
		case json.Number:
			parsed, err := typed.Int64()
			if err != nil {
				return 0, true, fmt.Errorf("metadata %s must be an integer", key)
			}
			return parsed, true, nil
		case string:
			parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
			if err != nil {
				return 0, true, fmt.Errorf("metadata %s must be an integer", key)
			}
			metadata[key] = parsed
			return parsed, true, nil
		default:
			return 0, true, fmt.Errorf("metadata %s must be an integer", key)
		}
	}
	return 0, false, nil
}

func metadataString(metadata map[string]any, keys ...string) (string, bool) {
	for _, key := range keys {
		value, ok := metadata[key]
		if !ok {
			continue
		}
		str, ok := value.(string)
		if !ok {
			return "", false
		}
		return str, true
	}
	return "", false
}

func validateMIMEType(resourceType, mimeType string) error {
	if mimeType == "" {
		return nil
	}
	switch resourceType {
	case "font":
		if _, ok := fontMIMETypes[mimeType]; !ok {
			return fmt.Errorf("unsupported font mime_type")
		}
	case "concat_template":
		if mimeType == "application/json" {
			return nil
		}
		fallthrough
	default:
		if _, ok := imageMIMETypes[mimeType]; !ok {
			return fmt.Errorf("unsupported image mime_type")
		}
	}
	return nil
}

func normalizeChecksum(checksum string, metadata map[string]any) (string, error) {
	if checksum == "" {
		if value, ok := metadataString(metadata, "sha256", "checksum"); ok {
			checksum = value
		}
	}
	checksum = strings.ToLower(strings.TrimSpace(checksum))
	if checksum == "" {
		return "", nil
	}
	checksum = strings.TrimPrefix(checksum, "sha256:")
	if len(checksum) != 64 {
		return "", fmt.Errorf("checksum must be sha256 hex")
	}
	for _, char := range checksum {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return "", fmt.Errorf("checksum must be sha256 hex")
		}
	}
	return "sha256:" + checksum, nil
}

func resourceFamily(resourceType string) string {
	if resourceType == "font" {
		return "font"
	}
	if strings.HasSuffix(resourceType, "_template") {
		return "template"
	}
	return "image"
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

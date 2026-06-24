package api

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	resourcepkg "captcha/internal/resource"
	"captcha/internal/types"

	_ "golang.org/x/image/webp"
)

const (
	maxUploadFileBytes    = 20 * 1024 * 1024
	maxUploadArchiveBytes = 100 * 1024 * 1024
	maxUploadFiles        = 300
)

func (s *Server) handleUploadResources(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxUploadArchiveBytes); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_UPLOAD")
		return
	}
	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		files = r.MultipartForm.File["file"]
	}
	if len(files) == 0 {
		writeError(w, http.StatusBadRequest, "UPLOAD_FILES_REQUIRED")
		return
	}

	dir, err := s.resourceUploadDir()
	if err != nil {
		s.logger.Error("prepare resource upload dir", "error", err)
		writeError(w, http.StatusInternalServerError, "UPLOAD_DIR_FAILED")
		return
	}

	base := resourceFromMultipart(r)
	saved := make([]types.CaptchaResource, 0, len(files))
	for _, header := range files {
		items, err := readUploadedResourceItems(header)
		if err != nil {
			s.logger.Warn("read uploaded resource", "filename", header.Filename, "error", err)
			writeError(w, http.StatusBadRequest, "INVALID_UPLOAD_FILE")
			return
		}
		for _, item := range items {
			if len(saved) >= maxUploadFiles {
				writeError(w, http.StatusBadRequest, "TOO_MANY_UPLOAD_FILES")
				return
			}
			resource, err := saveUploadedResource(dir, base, item)
			if err != nil {
				s.logger.Warn("save uploaded resource", "filename", item.Name, "error", err)
				writeError(w, http.StatusBadRequest, "INVALID_UPLOAD_FILE")
				return
			}
			normalized, err := resourcepkg.ValidateAndNormalize(resource)
			if err != nil {
				s.logger.Warn("validate uploaded resource", "filename", item.Name, "error", err)
				writeError(w, http.StatusBadRequest, "INVALID_RESOURCE")
				return
			}
			saved = append(saved, s.store.UpsertResource(normalized))
		}
	}
	if len(saved) == 0 {
		writeError(w, http.StatusBadRequest, "NO_VALID_UPLOAD_FILES")
		return
	}

	s.recordConfigAuditEvent(r, base.ClientID, "CONFIG_RESOURCE_UPLOAD", r.URL.Path, base.Scene, base.CaptchaType)
	s.notifyConfigChanged()
	writeJSON(w, http.StatusOK, map[string]any{"items": saved})
}

func (s *Server) resourceUploadDir() (string, error) {
	dir := strings.TrimSpace(s.options.ResourceUploadDir)
	if dir == "" {
		dir = "./data/resources"
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return "", err
	}
	return absolute, nil
}

type uploadBaseResource struct {
	ClientID     string
	Scene        string
	CaptchaType  types.CaptchaType
	ResourceType string
	Tag          string
	Status       string
	Category     string
	Label        string
	Weight       string
}

func resourceFromMultipart(r *http.Request) uploadBaseResource {
	captchaType := types.CaptchaType(strings.TrimSpace(r.FormValue("captcha_type")))
	if captchaType == "" {
		captchaType = types.CaptchaAuto
	}
	return uploadBaseResource{
		ClientID:     trimDefault(r.FormValue("client_id"), "demo"),
		Scene:        strings.TrimSpace(r.FormValue("scene")),
		CaptchaType:  captchaType,
		ResourceType: trimDefault(r.FormValue("resource_type"), "background_library"),
		Tag:          trimDefault(r.FormValue("tag"), "default"),
		Status:       trimDefault(r.FormValue("status"), "active"),
		Category:     strings.TrimSpace(r.FormValue("category")),
		Label:        strings.TrimSpace(r.FormValue("label")),
		Weight:       strings.TrimSpace(r.FormValue("weight")),
	}
}

func trimDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

type uploadedResourceItem struct {
	Name string
	Data []byte
}

func readUploadedResourceItems(header *multipart.FileHeader) ([]uploadedResourceItem, error) {
	file, err := header.Open()
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := readBoundedUpload(file, maxUploadArchiveBytes)
	if err != nil {
		return nil, err
	}
	if isZipUpload(header.Filename, data) {
		return readZipUploadItems(data)
	}
	if len(data) > maxUploadFileBytes {
		return nil, fmt.Errorf("upload file too large")
	}
	if !supportedUploadImageName(header.Filename) {
		return nil, fmt.Errorf("unsupported upload type")
	}
	return []uploadedResourceItem{{Name: filepath.Base(header.Filename), Data: data}}, nil
}

func readZipUploadItems(data []byte) ([]uploadedResourceItem, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	items := make([]uploadedResourceItem, 0, len(reader.File))
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || strings.HasPrefix(filepath.Base(file.Name), ".") || !supportedUploadImageName(file.Name) {
			continue
		}
		if file.UncompressedSize64 > maxUploadFileBytes {
			return nil, fmt.Errorf("zip entry too large")
		}
		entry, err := file.Open()
		if err != nil {
			return nil, err
		}
		content, readErr := readBoundedUpload(entry, maxUploadFileBytes)
		closeErr := entry.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		items = append(items, uploadedResourceItem{Name: filepath.Base(file.Name), Data: content})
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("zip contains no supported images")
	}
	if len(items) > maxUploadFiles {
		return nil, fmt.Errorf("zip contains too many files")
	}
	return items, nil
}

func readBoundedUpload(reader io.Reader, limit int64) ([]byte, error) {
	var buf bytes.Buffer
	written, err := io.Copy(&buf, io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if written > limit {
		return nil, fmt.Errorf("upload exceeds limit")
	}
	return buf.Bytes(), nil
}

func isZipUpload(filename string, data []byte) bool {
	return strings.EqualFold(filepath.Ext(filename), ".zip") || bytes.HasPrefix(data, []byte("PK\x03\x04"))
}

func supportedUploadImageName(filename string) bool {
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg":
		return true
	default:
		return false
	}
}

func saveUploadedResource(dir string, base uploadBaseResource, item uploadedResourceItem) (types.CaptchaResource, error) {
	contentType, width, height, thumbnail := inspectUploadedImage(item)
	if contentType == "" {
		return types.CaptchaResource{}, fmt.Errorf("unsupported image content")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return types.CaptchaResource{}, err
	}
	id := "res_" + randomUploadID()
	ext := uploadExtension(item.Name, contentType)
	path := filepath.Join(dir, id+ext)
	if err := os.WriteFile(path, item.Data, 0o600); err != nil {
		return types.CaptchaResource{}, err
	}
	sum := sha256.Sum256(item.Data)
	metadata := map[string]any{
		"mime_type":          contentType,
		"size_bytes":         len(item.Data),
		"original_filename":  filepath.Base(item.Name),
		"uploaded_at":        time.Now().UTC().Format(time.RFC3339),
		"thumbnail_data_url": thumbnail,
	}
	if width > 0 {
		metadata["width"] = width
	}
	if height > 0 {
		metadata["height"] = height
	}
	if base.Category != "" {
		metadata["category"] = base.Category
	}
	if base.Label != "" {
		metadata["label"] = base.Label
	}
	if base.Weight != "" {
		if weight, err := strconv.Atoi(base.Weight); err == nil && weight > 0 {
			metadata["weight"] = weight
		}
	}
	return types.CaptchaResource{
		ID:           id,
		ClientID:     base.ClientID,
		Scene:        base.Scene,
		CaptchaType:  base.CaptchaType,
		ResourceType: base.ResourceType,
		StorageType:  "file",
		URI:          fileURI(path),
		Tag:          base.Tag,
		Status:       base.Status,
		Checksum:     "sha256:" + hex.EncodeToString(sum[:]),
		Metadata:     metadata,
	}, nil
}

func inspectUploadedImage(item uploadedResourceItem) (string, int, int, string) {
	if strings.EqualFold(filepath.Ext(item.Name), ".svg") || bytes.Contains(item.Data[:min(len(item.Data), 256)], []byte("<svg")) {
		thumbnail := ""
		if len(item.Data) <= 128*1024 {
			thumbnail = "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(item.Data)
		}
		return "image/svg+xml", 0, 0, thumbnail
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(item.Data))
	if err != nil {
		return "", 0, 0, ""
	}
	contentType := imageFormatMIME(format)
	if contentType == "" {
		contentType = http.DetectContentType(item.Data)
	}
	return contentType, config.Width, config.Height, thumbnailDataURL(item.Data)
}

func imageFormatMIME(format string) string {
	switch strings.ToLower(format) {
	case "png":
		return "image/png"
	case "jpeg":
		return "image/jpeg"
	case "gif":
		return "image/gif"
	case "webp":
		return "image/webp"
	default:
		return ""
	}
}

func thumbnailDataURL(data []byte) string {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return ""
	}
	thumb := resizeImageFit(img, 160, 120)
	var buf bytes.Buffer
	if err := png.Encode(&buf, thumb); err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

func resizeImageFit(src image.Image, maxWidth, maxHeight int) *image.RGBA {
	bounds := src.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	if width <= 0 || height <= 0 {
		return image.NewRGBA(image.Rect(0, 0, 1, 1))
	}
	scale := minFloat(float64(maxWidth)/float64(width), float64(maxHeight)/float64(height))
	if scale > 1 {
		scale = 1
	}
	dstWidth := max(1, int(float64(width)*scale))
	dstHeight := max(1, int(float64(height)*scale))
	dst := image.NewRGBA(image.Rect(0, 0, dstWidth, dstHeight))
	for y := 0; y < dstHeight; y++ {
		for x := 0; x < dstWidth; x++ {
			srcX := bounds.Min.X + min(width-1, int(float64(x)/scale))
			srcY := bounds.Min.Y + min(height-1, int(float64(y)/scale))
			dst.Set(x, y, src.At(srcX, srcY))
		}
	}
	return dst
}

func uploadExtension(filename, contentType string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	if supportedUploadImageName("x" + ext) {
		return ext
	}
	extensions, _ := mime.ExtensionsByType(contentType)
	if len(extensions) > 0 {
		return extensions[0]
	}
	return ".img"
}

func fileURI(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = path
	}
	return (&url.URL{Scheme: "file", Path: absolute}).String()
}

func randomUploadID() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

package resource

import (
	"crypto/rand"
	"math/big"
	"sort"
	"strings"

	"captcha/internal/types"
)

type Store interface {
	ListResources(clientID string) []types.CaptchaResource
}

type RenderResource struct {
	ID           string            `json:"id"`
	CaptchaType  types.CaptchaType `json:"captcha_type"`
	Scene        string            `json:"scene,omitempty"`
	ResourceType string            `json:"resource_type"`
	StorageType  string            `json:"storage_type"`
	URI          string            `json:"uri"`
	Tag          string            `json:"tag,omitempty"`
	Checksum     string            `json:"checksum,omitempty"`
	Metadata     map[string]any    `json:"metadata,omitempty"`
	Status       string            `json:"status"`
}

func AttachForStore(store Store, payload types.RenderPayload, clientID, scene string, captchaType types.CaptchaType, tag string) types.RenderPayload {
	if store == nil {
		return payload
	}
	return Attach(payload, Select(store.ListResources(clientID), captchaType, scene, tag))
}

func ApplyVisualsAndAttachForStore(store Store, payload types.RenderPayload, answer types.Answer, clientID, scene string, captchaType types.CaptchaType, tag string) types.RenderPayload {
	if store == nil {
		return payload
	}
	selected := Select(store.ListResources(clientID), captchaType, scene, tag)
	return Attach(ApplyVisuals(payload, answer, selected), selected)
}

func Attach(payload types.RenderPayload, resources []types.CaptchaResource) types.RenderPayload {
	if len(resources) == 0 {
		return payload
	}
	if payload.Parameters == nil {
		payload.Parameters = make(map[string]any, 1)
	}
	renderResources := make([]RenderResource, 0, len(resources))
	for _, item := range resources {
		renderResources = append(renderResources, RenderResource{
			ID:           item.ID,
			CaptchaType:  item.CaptchaType,
			Scene:        item.Scene,
			ResourceType: item.ResourceType,
			StorageType:  item.StorageType,
			URI:          item.URI,
			Tag:          item.Tag,
			Checksum:     item.Checksum,
			Metadata:     safeRenderMetadata(item.Metadata),
			Status:       item.Status,
		})
	}
	payload.Parameters["resources"] = renderResources
	return payload
}

func safeRenderMetadata(metadata map[string]any) map[string]any {
	if len(metadata) == 0 {
		return nil
	}
	out := make(map[string]any, len(metadata))
	for key, value := range metadata {
		if isSensitiveRenderMetadataKey(key) {
			continue
		}
		sanitized, ok := sanitizeRenderMetadataValue(value)
		if !ok {
			continue
		}
		out[key] = sanitized
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeRenderMetadataValue(value any) (any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		return nonEmptyRenderMetadata(safeRenderMetadata(typed))
	case map[string]string:
		out := make(map[string]string, len(typed))
		for key, nested := range typed {
			if isSensitiveRenderMetadataKey(key) {
				continue
			}
			out[key] = nested
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			sanitized, ok := sanitizeRenderMetadataValue(item)
			if ok {
				out = append(out, sanitized)
			}
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	case []map[string]any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			sanitized := safeRenderMetadata(item)
			if len(sanitized) > 0 {
				out = append(out, sanitized)
			}
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	default:
		return value, true
	}
}

func nonEmptyRenderMetadata(metadata map[string]any) (any, bool) {
	if len(metadata) == 0 {
		return nil, false
	}
	return metadata, true
}

func isSensitiveRenderMetadataKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	normalized = strings.ReplaceAll(normalized, " ", "_")
	switch normalized {
	case "answer",
		"answers",
		"correct_answer",
		"correct_answers",
		"expected",
		"expected_answer",
		"solution",
		"solutions",
		"target",
		"targets",
		"target_x",
		"target_y",
		"target_position",
		"target_offset",
		"answer_seed",
		"tolerance",
		"min_tolerance",
		"max_tolerance",
		"verify_rule",
		"verify_rules",
		"verification_rule",
		"score_rule",
		"score_rules",
		"rule",
		"rules",
		"secret",
		"client_secret",
		"token",
		"access_token",
		"refresh_token",
		"authorization",
		"api_key",
		"apikey",
		"access_key",
		"access_key_id",
		"secret_key",
		"private_key",
		"signing_key",
		"hmac_key",
		"password",
		"credential",
		"credentials",
		"salt":
		return true
	default:
		return false
	}
}

func ChooseCaptchaType(resources []types.CaptchaResource, requested types.CaptchaType, scene, tag string, preferences []types.CaptchaType) types.CaptchaType {
	requested = normalizeRequestedCaptchaType(requested)
	if requested == "RANDOM" {
		return chooseRandomCaptchaType(resources, scene, tag)
	}
	if isConcreteCaptchaType(requested) {
		return requested
	}
	preferences = normalizeCaptchaPreferences(preferences)
	available := AvailableCaptchaTypes(resources, scene, tag)
	for _, captchaType := range preferences {
		if available[captchaType] {
			return captchaType
		}
	}
	return preferences[0]
}

func chooseRandomCaptchaType(resources []types.CaptchaResource, scene, tag string) types.CaptchaType {
	available := AvailableCaptchaTypes(resources, scene, tag)
	candidates := make([]types.CaptchaType, 0, len(randomCaptchaTypePreference))
	for _, captchaType := range randomCaptchaTypePreference {
		if available[captchaType] {
			candidates = append(candidates, captchaType)
		}
	}
	if len(candidates) == 0 {
		return types.CaptchaSlider
	}
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
	if err != nil {
		return candidates[0]
	}
	return candidates[int(index.Int64())]
}

func AvailableCaptchaTypes(resources []types.CaptchaResource, scene, tag string) map[types.CaptchaType]bool {
	available := make(map[types.CaptchaType]bool, len(randomCaptchaTypePreference))
	for _, captchaType := range randomCaptchaTypePreference {
		available[captchaType] = len(resources) == 0 || SupportsCaptchaType(resources, captchaType, scene, tag)
	}
	return available
}

func SupportsCaptchaType(resources []types.CaptchaResource, captchaType types.CaptchaType, scene, tag string) bool {
	requirements := requiredResourceTypeGroups(captchaType)
	if len(requirements) == 0 {
		return false
	}
	selected := Select(resources, captchaType, scene, tag)
	selectedTypes := make(map[string]struct{}, len(selected))
	for _, item := range selected {
		selectedTypes[item.ResourceType] = struct{}{}
	}
	for _, alternatives := range requirements {
		if !hasAnySelectedResourceType(selectedTypes, alternatives) {
			return false
		}
	}
	return true
}

func hasAnySelectedResourceType(selectedTypes map[string]struct{}, alternatives []string) bool {
	for _, resourceType := range alternatives {
		if _, ok := selectedTypes[resourceType]; ok {
			return true
		}
	}
	return false
}

func Select(resources []types.CaptchaResource, captchaType types.CaptchaType, scene, tag string) []types.CaptchaResource {
	selectedByType := make(map[string]types.CaptchaResource)
	collectionByType := make(map[string][]types.CaptchaResource)
	collectionScoreByType := make(map[string]int)
	for _, item := range resources {
		if !isActive(item.Status) || !matchesType(item.CaptchaType, captchaType) || !matchesScene(item.Scene, scene) || !matchesTag(item.Tag, tag) || item.ResourceType == "" || item.URI == "" {
			continue
		}
		if isCollectionResourceType(item.ResourceType) {
			score := resourceScore(item, captchaType, scene, tag)
			currentScore, ok := collectionScoreByType[item.ResourceType]
			if !ok || score > currentScore {
				collectionScoreByType[item.ResourceType] = score
				collectionByType[item.ResourceType] = []types.CaptchaResource{item}
				continue
			}
			if score == currentScore {
				collectionByType[item.ResourceType] = append(collectionByType[item.ResourceType], item)
			}
			continue
		}
		current, ok := selectedByType[item.ResourceType]
		if !ok || better(item, current, captchaType, scene, tag) {
			selectedByType[item.ResourceType] = item
		}
	}
	selected := make([]types.CaptchaResource, 0, len(selectedByType))
	for _, item := range selectedByType {
		selected = append(selected, item)
	}
	for _, items := range collectionByType {
		selected = append(selected, items...)
	}
	sort.SliceStable(selected, func(i, j int) bool {
		if selected[i].ResourceType != selected[j].ResourceType {
			return selected[i].ResourceType < selected[j].ResourceType
		}
		return selected[i].ID < selected[j].ID
	})
	return selected
}

func isCollectionResourceType(resourceType string) bool {
	switch strings.ToLower(strings.TrimSpace(resourceType)) {
	case "background_library", "rotate_library", "grid_category_library", "icon_library":
		return true
	default:
		return false
	}
}

func better(candidate, current types.CaptchaResource, captchaType types.CaptchaType, scene, tag string) bool {
	candidateScore := resourceScore(candidate, captchaType, scene, tag)
	currentScore := resourceScore(current, captchaType, scene, tag)
	if candidateScore != currentScore {
		return candidateScore > currentScore
	}
	return candidate.ID < current.ID
}

func resourceScore(item types.CaptchaResource, captchaType types.CaptchaType, scene, tag string) int {
	score := 0
	if item.CaptchaType == captchaType {
		score += 100
	}
	if scene != "" && strings.EqualFold(item.Scene, scene) {
		score += 50
	}
	if tag != "" && strings.EqualFold(item.Tag, tag) {
		score += 30
	}
	if strings.EqualFold(item.Tag, "default") {
		score += 10
	}
	return score
}

func matchesType(candidate, captchaType types.CaptchaType) bool {
	return candidate == captchaType || candidate == types.CaptchaAuto || candidate == ""
}

func matchesScene(candidate, scene string) bool {
	return candidate == "" || (scene != "" && strings.EqualFold(candidate, scene))
}

func matchesTag(candidate, tag string) bool {
	if tag == "" {
		return true
	}
	return candidate == "" || strings.EqualFold(candidate, "default") || strings.EqualFold(candidate, tag)
}

func isActive(status string) bool {
	return status == "" || strings.EqualFold(status, "active")
}

var captchaTypePreference = []types.CaptchaType{
	types.CaptchaSlider,
	types.CaptchaRotate,
	types.CaptchaConcat,
	types.CaptchaWordImageClick,
}

var randomCaptchaTypePreference = []types.CaptchaType{
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

func normalizeCaptchaPreferences(preferences []types.CaptchaType) []types.CaptchaType {
	out := make([]types.CaptchaType, 0, len(preferences)+len(captchaTypePreference))
	seen := make(map[types.CaptchaType]struct{}, len(captchaTypePreference))
	for _, captchaType := range preferences {
		if !isConcreteCaptchaType(captchaType) {
			continue
		}
		if _, ok := seen[captchaType]; ok {
			continue
		}
		seen[captchaType] = struct{}{}
		out = append(out, captchaType)
	}
	for _, captchaType := range captchaTypePreference {
		if _, ok := seen[captchaType]; ok {
			continue
		}
		out = append(out, captchaType)
	}
	return out
}

func isConcreteCaptchaType(captchaType types.CaptchaType) bool {
	switch normalizeRequestedCaptchaType(captchaType) {
	case types.CaptchaGesture, types.CaptchaCurve, types.CaptchaCurve2, types.CaptchaCurve3, types.CaptchaSlider, types.CaptchaSlider2, types.CaptchaRotate, types.CaptchaConcat, types.CaptchaRotateDegree, types.CaptchaWordImageClick, types.CaptchaImageClick, types.CaptchaJigsaw, types.CaptchaGridImageClick:
		return true
	default:
		return false
	}
}

func requiredResourceTypes(captchaType types.CaptchaType) []string {
	groups := requiredResourceTypeGroups(captchaType)
	out := make([]string, 0, len(groups))
	for _, group := range groups {
		if len(group) > 0 {
			out = append(out, group[0])
		}
	}
	return out
}

func requiredResourceTypeGroups(captchaType types.CaptchaType) [][]string {
	switch normalizeRequestedCaptchaType(captchaType) {
	case types.CaptchaGesture:
		return [][]string{{"background_image", "background_library"}, {"gesture_template"}}
	case types.CaptchaCurve, types.CaptchaCurve2, types.CaptchaCurve3:
		return [][]string{{"background_image", "background_library"}, {"curve_template"}}
	case types.CaptchaSlider:
		return [][]string{{"background_image", "background_library"}, {"slider_template"}}
	case types.CaptchaSlider2:
		return [][]string{{"background_image", "background_library"}, {"slider_template"}}
	case types.CaptchaRotate:
		return [][]string{{"rotate_library"}}
	case types.CaptchaConcat:
		return [][]string{{"background_image", "background_library"}, {"concat_template"}}
	case types.CaptchaWordImageClick:
		return [][]string{{"background_image", "background_library"}, {"font"}}
	case types.CaptchaImageClick:
		return [][]string{{"background_image", "background_library"}, {"icon", "icon_library"}}
	case types.CaptchaRotateDegree:
		return [][]string{{"background_image", "background_library"}, {"degree_template"}}
	case types.CaptchaGridImageClick:
		return [][]string{{"grid_category_library"}}
	default:
		return nil
	}
}

func normalizeRequestedCaptchaType(captchaType types.CaptchaType) types.CaptchaType {
	switch types.CaptchaType(strings.ToUpper(strings.TrimSpace(string(captchaType)))) {
	case "SLIDER2":
		return types.CaptchaSlider2
	case "CURVE2":
		return types.CaptchaCurve2
	case "CURVE3":
		return types.CaptchaCurve3
	case types.CaptchaWordOrderClick:
		return types.CaptchaWordImageClick
	default:
		return types.CaptchaType(strings.ToUpper(strings.TrimSpace(string(captchaType))))
	}
}

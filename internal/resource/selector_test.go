package resource

import (
	"testing"

	"captcha/internal/types"
)

func TestSelectResourcesPrefersExactActiveResources(t *testing.T) {
	t.Parallel()

	resources := []types.CaptchaResource{
		{
			ID:           "res_auto_background",
			CaptchaType:  types.CaptchaAuto,
			ResourceType: "background_image",
			StorageType:  "url",
			URI:          "https://cdn.example.test/auto.png",
			Tag:          "default",
			Status:       "active",
		},
		{
			ID:           "res_slider_background",
			CaptchaType:  types.CaptchaSlider,
			ResourceType: "background_image",
			StorageType:  "url",
			URI:          "https://cdn.example.test/slider.png",
			Tag:          "default",
			Status:       "active",
		},
		{
			ID:           "res_disabled_piece",
			CaptchaType:  types.CaptchaSlider,
			ResourceType: "slider_template",
			StorageType:  "url",
			URI:          "https://cdn.example.test/disabled-piece.png",
			Tag:          "default",
			Status:       "disabled",
		},
		{
			ID:           "res_auto_piece",
			CaptchaType:  types.CaptchaAuto,
			ResourceType: "slider_template",
			StorageType:  "embedded",
			URI:          "embedded://slider-template",
			Tag:          "default",
			Status:       "active",
		},
	}

	selected := Select(resources, types.CaptchaSlider, "", "")
	if len(selected) != 2 {
		t.Fatalf("expected two selected resources, got %+v", selected)
	}
	if selected[0].ResourceType != "background_image" || selected[0].ID != "res_slider_background" {
		t.Fatalf("expected exact background to win over AUTO, got %+v", selected)
	}
	if selected[1].ResourceType != "slider_template" || selected[1].ID != "res_auto_piece" {
		t.Fatalf("expected active AUTO fallback for template, got %+v", selected)
	}
}

func TestSelectResourcesPrefersSceneAndRequestedTag(t *testing.T) {
	t.Parallel()

	resources := []types.CaptchaResource{
		{
			ID:           "res_default_background",
			CaptchaType:  types.CaptchaSlider,
			ResourceType: "background_image",
			StorageType:  "url",
			URI:          "https://cdn.example.test/default.png",
			Tag:          "default",
			Status:       "active",
		},
		{
			ID:           "res_register_campaign_background",
			Scene:        "register",
			CaptchaType:  types.CaptchaSlider,
			ResourceType: "background_image",
			StorageType:  "url",
			URI:          "https://cdn.example.test/register.png",
			Tag:          "campaign",
			Status:       "active",
		},
		{
			ID:           "res_login_campaign_background",
			Scene:        "login",
			CaptchaType:  types.CaptchaSlider,
			ResourceType: "background_image",
			StorageType:  "url",
			URI:          "https://cdn.example.test/login.png",
			Tag:          "campaign",
			Status:       "active",
		},
	}

	selected := Select(resources, types.CaptchaSlider, "login", "campaign")
	if len(selected) != 1 {
		t.Fatalf("expected one selected resource, got %+v", selected)
	}
	if selected[0].ID != "res_login_campaign_background" {
		t.Fatalf("expected exact scene and tag resource, got %+v", selected)
	}

	selected = Select(resources, types.CaptchaSlider, "", "campaign")
	if len(selected) != 1 || selected[0].ID != "res_default_background" {
		t.Fatalf("scene-specific resources should not match empty scene, got %+v", selected)
	}
}

func TestSelectKeepsScopedLibraryResources(t *testing.T) {
	t.Parallel()

	resources := []types.CaptchaResource{
		{
			ID:           "res_default_background_library",
			CaptchaType:  types.CaptchaSlider,
			ResourceType: "background_library",
			StorageType:  "url",
			URI:          "https://cdn.example.test/default.png",
			Tag:          "default",
			Status:       "active",
		},
		{
			ID:           "res_campaign_background_library_a",
			CaptchaType:  types.CaptchaSlider,
			ResourceType: "background_library",
			StorageType:  "url",
			URI:          "https://cdn.example.test/campaign-a.png",
			Tag:          "campaign",
			Status:       "active",
		},
		{
			ID:           "res_campaign_background_library_b",
			CaptchaType:  types.CaptchaSlider,
			ResourceType: "background_library",
			StorageType:  "url",
			URI:          "https://cdn.example.test/campaign-b.png",
			Tag:          "campaign",
			Status:       "active",
		},
		{
			ID:           "res_slider_template",
			CaptchaType:  types.CaptchaSlider,
			ResourceType: "slider_template",
			StorageType:  "url",
			URI:          "https://cdn.example.test/template.png",
			Tag:          "campaign",
			Status:       "active",
		},
	}

	selected := Select(resources, types.CaptchaSlider, "", "campaign")
	if len(selected) != 3 {
		t.Fatalf("expected two library resources and template, got %+v", selected)
	}
	seen := map[string]bool{}
	for _, item := range selected {
		seen[item.ID] = true
	}
	if !seen["res_campaign_background_library_a"] || !seen["res_campaign_background_library_b"] || seen["res_default_background_library"] {
		t.Fatalf("expected scoped library resources to be kept, got %+v", selected)
	}
}

func TestChooseCaptchaTypeUsesResourceAvailability(t *testing.T) {
	t.Parallel()

	resources := []types.CaptchaResource{
		{
			ID:           "res_rotate_library",
			CaptchaType:  types.CaptchaRotate,
			ResourceType: "rotate_library",
			StorageType:  "url",
			URI:          "https://cdn.example.test/rotate.png",
			Status:       "active",
		},
	}

	chosen := ChooseCaptchaType(resources, types.CaptchaAuto, "login", "", []types.CaptchaType{
		types.CaptchaSlider,
		types.CaptchaRotate,
	})
	if chosen != types.CaptchaRotate {
		t.Fatalf("expected rotate because slider resources are incomplete, got %s", chosen)
	}
	if !SupportsCaptchaType(resources, types.CaptchaRotate, "login", "") {
		t.Fatalf("expected rotate to be resource-supported")
	}
	if SupportsCaptchaType(resources, types.CaptchaSlider, "login", "") {
		t.Fatalf("slider should require a slider template")
	}
}

func TestSupportsGridImageClickWithCategoryLibrary(t *testing.T) {
	t.Parallel()

	resources := []types.CaptchaResource{
		{
			ID:           "res_car",
			CaptchaType:  types.CaptchaGridImageClick,
			ResourceType: "grid_category_library",
			StorageType:  "url",
			URI:          "https://cdn.example.test/car.png",
			Metadata:     map[string]any{"category": "car", "label": "汽车"},
			Status:       "active",
		},
	}

	if !SupportsCaptchaType(resources, types.CaptchaGridImageClick, "verify", "") {
		t.Fatalf("expected grid image click to be supported by category library")
	}
}

func TestConcatAndJigsawRequireDedicatedBackgroundLibraries(t *testing.T) {
	t.Parallel()

	genericConcatResources := []types.CaptchaResource{
		{
			ID:           "res_generic_background",
			CaptchaType:  types.CaptchaConcat,
			ResourceType: "background_library",
			StorageType:  "url",
			URI:          "https://cdn.example.test/generic.png",
			Status:       "active",
		},
		{
			ID:           "res_concat_template",
			CaptchaType:  types.CaptchaConcat,
			ResourceType: "concat_template",
			StorageType:  "url",
			URI:          "https://cdn.example.test/concat-template.json",
			Status:       "active",
		},
	}
	if SupportsCaptchaType(genericConcatResources, types.CaptchaConcat, "login", "") {
		t.Fatalf("concat should not be resource-supported by the generic background library")
	}

	dedicatedResources := append(genericConcatResources,
		types.CaptchaResource{
			ID:           "res_concat_background_a",
			CaptchaType:  types.CaptchaConcat,
			ResourceType: "concat_background_library",
			StorageType:  "url",
			URI:          "https://cdn.example.test/concat-a.png",
			Status:       "active",
		},
		types.CaptchaResource{
			ID:           "res_concat_background_b",
			CaptchaType:  types.CaptchaConcat,
			ResourceType: "concat_background_library",
			StorageType:  "url",
			URI:          "https://cdn.example.test/concat-b.png",
			Status:       "active",
		},
	)
	selected := Select(dedicatedResources, types.CaptchaConcat, "login", "")
	if !hasSelectedResource(selected, "concat_background_library", "res_concat_background_a") ||
		!hasSelectedResource(selected, "concat_background_library", "res_concat_background_b") ||
		hasSelectedResource(selected, "background_library", "res_generic_background") {
		t.Fatalf("expected concat to keep only dedicated background libraries, got %+v", selected)
	}
	if !SupportsCaptchaType(dedicatedResources, types.CaptchaConcat, "login", "") {
		t.Fatalf("concat should be supported by dedicated background library plus template")
	}

	jigsawResources := []types.CaptchaResource{
		{
			ID:           "res_generic_jigsaw_background",
			CaptchaType:  types.CaptchaJigsaw,
			ResourceType: "background_library",
			StorageType:  "url",
			URI:          "https://cdn.example.test/generic-jigsaw.png",
			Status:       "active",
		},
	}
	if SupportsCaptchaType(jigsawResources, types.CaptchaJigsaw, "login", "") {
		t.Fatalf("jigsaw should not be resource-supported by the generic background library")
	}
	jigsawResources = append(jigsawResources, types.CaptchaResource{
		ID:           "res_jigsaw_background",
		CaptchaType:  types.CaptchaJigsaw,
		ResourceType: "jigsaw_background_library",
		StorageType:  "url",
		URI:          "https://cdn.example.test/jigsaw.png",
		Status:       "active",
	})
	selected = Select(jigsawResources, types.CaptchaJigsaw, "login", "")
	if !hasSelectedResource(selected, "jigsaw_background_library", "res_jigsaw_background") ||
		hasSelectedResource(selected, "background_library", "res_generic_jigsaw_background") {
		t.Fatalf("expected jigsaw to keep only dedicated background libraries, got %+v", selected)
	}
	if !SupportsCaptchaType(jigsawResources, types.CaptchaJigsaw, "login", "") {
		t.Fatalf("jigsaw should be supported by dedicated background library")
	}
}

func TestChooseCaptchaTypeRespectsExplicitType(t *testing.T) {
	t.Parallel()

	chosen := ChooseCaptchaType(nil, types.CaptchaConcat, "login", "", []types.CaptchaType{types.CaptchaSlider})
	if chosen != types.CaptchaConcat {
		t.Fatalf("expected explicit concat to win, got %s", chosen)
	}
}

func hasSelectedResource(resources []types.CaptchaResource, resourceType, id string) bool {
	for _, item := range resources {
		if item.ResourceType == resourceType && item.ID == id {
			return true
		}
	}
	return false
}

func TestAttachSanitizesRenderMetadata(t *testing.T) {
	t.Parallel()

	nested := map[string]any{
		"mime_type": "image/png",
		"token":     "do-not-render",
	}
	steps := []any{
		map[string]any{
			"width":  40,
			"target": 120,
		},
	}
	metadata := map[string]any{
		"width":      320,
		"height":     160,
		"answer":     "42",
		"target_x":   88,
		"secret_key": "do-not-render",
		"nested":     nested,
		"steps":      steps,
	}

	payload := Attach(types.RenderPayload{}, []types.CaptchaResource{
		{
			ID:           "res_background",
			CaptchaType:  types.CaptchaSlider,
			ResourceType: "background_image",
			StorageType:  "url",
			URI:          "https://cdn.example.test/background.png",
			Metadata:     metadata,
			Status:       "active",
		},
	})

	renderResources, ok := payload.Parameters["resources"].([]RenderResource)
	if !ok || len(renderResources) != 1 {
		t.Fatalf("expected one render resource, got %+v", payload.Parameters["resources"])
	}
	renderMetadata := renderResources[0].Metadata
	if renderMetadata["width"] != 320 || renderMetadata["height"] != 160 {
		t.Fatalf("expected safe render metadata to keep dimensions, got %+v", renderMetadata)
	}
	if _, ok := renderMetadata["answer"]; ok {
		t.Fatalf("expected answer to be removed from render metadata, got %+v", renderMetadata)
	}
	if _, ok := renderMetadata["target_x"]; ok {
		t.Fatalf("expected target_x to be removed from render metadata, got %+v", renderMetadata)
	}
	if _, ok := renderMetadata["secret_key"]; ok {
		t.Fatalf("expected secret_key to be removed from render metadata, got %+v", renderMetadata)
	}
	renderNested, ok := renderMetadata["nested"].(map[string]any)
	if !ok || renderNested["mime_type"] != "image/png" {
		t.Fatalf("expected nested safe metadata to be preserved, got %+v", renderMetadata["nested"])
	}
	if _, ok := renderNested["token"]; ok {
		t.Fatalf("expected nested token to be removed, got %+v", renderNested)
	}
	renderSteps, ok := renderMetadata["steps"].([]any)
	if !ok || len(renderSteps) != 1 {
		t.Fatalf("expected sanitized steps, got %+v", renderMetadata["steps"])
	}
	step, ok := renderSteps[0].(map[string]any)
	if !ok || step["width"] != 40 {
		t.Fatalf("expected step width to be preserved, got %+v", renderSteps[0])
	}
	if _, ok := step["target"]; ok {
		t.Fatalf("expected step target to be removed, got %+v", step)
	}
	if metadata["answer"] != "42" || nested["token"] != "do-not-render" {
		t.Fatalf("expected original metadata to remain unchanged, got metadata=%+v nested=%+v", metadata, nested)
	}
}

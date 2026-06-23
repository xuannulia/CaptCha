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

func TestChooseCaptchaTypeUsesResourceAvailability(t *testing.T) {
	t.Parallel()

	resources := []types.CaptchaResource{
		{
			ID:           "res_background",
			CaptchaType:  types.CaptchaAuto,
			ResourceType: "background_image",
			StorageType:  "url",
			URI:          "https://cdn.example.test/background.png",
			Status:       "active",
		},
		{
			ID:           "res_rotate_template",
			CaptchaType:  types.CaptchaRotate,
			ResourceType: "rotate_template",
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

func TestChooseCaptchaTypeRespectsExplicitType(t *testing.T) {
	t.Parallel()

	chosen := ChooseCaptchaType(nil, types.CaptchaConcat, "login", "", []types.CaptchaType{types.CaptchaSlider})
	if chosen != types.CaptchaConcat {
		t.Fatalf("expected explicit concat to win, got %s", chosen)
	}
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

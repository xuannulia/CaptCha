package store

import (
	"path/filepath"
	"testing"

	"captcha/internal/types"
)

func TestMemoryStorePersistsCaptchaResources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resource-state.json")
	first := NewMemoryStoreWithResourcePersistence(path)
	resource := types.CaptchaResource{
		ID:           "res_uploaded_background",
		ClientID:     "demo",
		CaptchaType:  types.CaptchaSlider,
		ResourceType: "background_library",
		StorageType:  "file",
		URI:          "file:///tmp/background.png",
		Tag:          "default",
		Status:       "active",
		Metadata:     map[string]any{"label": "背景"},
	}
	first.UpsertResource(resource)

	second := NewMemoryStoreWithResourcePersistence(path)
	resources := second.ListResources("demo")
	for _, item := range resources {
		if item.ID == resource.ID && item.URI == resource.URI && item.ResourceType == resource.ResourceType {
			return
		}
	}
	t.Fatalf("expected persisted resource %s after memory store restart, got %+v", resource.ID, resources)
}

func TestMemoryStorePersistsResourceDeletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resource-state.json")
	first := NewMemoryStoreWithResourcePersistence(path)
	first.DeleteResources("demo", []string{"res_background"})

	second := NewMemoryStoreWithResourcePersistence(path)
	for _, item := range second.ListResources("demo") {
		if item.ID == "res_background" {
			t.Fatalf("expected deleted seed resource to stay deleted after restart, got %+v", item)
		}
	}
}

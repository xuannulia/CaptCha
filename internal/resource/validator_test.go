package resource

import (
	"testing"

	"captcha/internal/types"
)

func TestValidateAndNormalizeResource(t *testing.T) {
	t.Parallel()

	resource, err := ValidateAndNormalize(types.CaptchaResource{
		ClientID:     " demo ",
		CaptchaType:  types.CaptchaSlider,
		ResourceType: "BACKGROUND_IMAGE",
		StorageType:  "URL",
		URI:          "https://cdn.example.test/captcha/login.png",
		Checksum:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Metadata: map[string]any{
			"width":        "320",
			"height":       160,
			"content_type": "IMAGE/PNG",
			"size_bytes":   float64(4096),
		},
	})
	if err != nil {
		t.Fatalf("validate resource: %v", err)
	}
	if resource.ClientID != "demo" || resource.ResourceType != "background_image" || resource.StorageType != "url" {
		t.Fatalf("expected normalized fields, got %+v", resource)
	}
	if resource.Status != "active" || resource.CaptchaType != types.CaptchaSlider {
		t.Fatalf("expected default status and captcha type, got %+v", resource)
	}
	if resource.Checksum != "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("expected normalized checksum, got %q", resource.Checksum)
	}
	if resource.Metadata["mime_type"] != "image/png" || resource.Metadata["uri_scheme"] != "https" || resource.Metadata["resource_family"] != "image" {
		t.Fatalf("unexpected metadata: %+v", resource.Metadata)
	}
}

func TestValidateAndNormalizeDedicatedBackgroundResourceTypes(t *testing.T) {
	t.Parallel()

	for _, resourceType := range []string{
		"concat_background_image",
		"concat_background_library",
		"jigsaw_background_image",
		"jigsaw_background_library",
	} {
		resourceType := resourceType
		t.Run(resourceType, func(t *testing.T) {
			t.Parallel()

			resource, err := ValidateAndNormalize(types.CaptchaResource{
				CaptchaType:  types.CaptchaConcat,
				ResourceType: resourceType,
				StorageType:  "url",
				URI:          "https://cdn.example.test/background.png",
				Metadata: map[string]any{
					"mime_type": "image/png",
				},
			})
			if err != nil {
				t.Fatalf("validate dedicated background resource: %v", err)
			}
			if resource.ResourceType != resourceType || resource.Metadata["resource_family"] != "image" {
				t.Fatalf("unexpected normalized resource: %+v", resource)
			}
			if resource.Metadata["difficulty"] != "medium" {
				t.Fatalf("expected default material difficulty, got %+v", resource.Metadata)
			}
		})
	}
}

func TestValidateAndNormalizeResourceNormalizesDifficulty(t *testing.T) {
	t.Parallel()

	resource, err := ValidateAndNormalize(types.CaptchaResource{
		CaptchaType:  types.CaptchaJigsaw,
		ResourceType: "jigsaw_background_library",
		StorageType:  "url",
		URI:          "https://cdn.example.test/jigsaw.png",
		Metadata: map[string]any{
			"difficulty": "HARD",
		},
	})
	if err != nil {
		t.Fatalf("validate difficulty: %v", err)
	}
	if resource.Metadata["difficulty"] != "hard" ||
		resource.Metadata["usage_profile"] != "jigsaw_shuffle" ||
		resource.Metadata["suitability"] != "tile_distinctiveness" {
		t.Fatalf("unexpected dedicated background metadata: %+v", resource.Metadata)
	}
}

func TestValidateAndNormalizeResourceRejectsUnsafeValues(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		resource types.CaptchaResource
	}{
		{
			name: "unsupported resource type",
			resource: types.CaptchaResource{
				ResourceType: "script",
				StorageType:  "url",
				URI:          "https://cdn.example.test/a.js",
			},
		},
		{
			name: "private url host",
			resource: types.CaptchaResource{
				ResourceType: "background_image",
				StorageType:  "url",
				URI:          "http://10.0.0.8/private.png",
			},
		},
		{
			name: "oversized image declaration",
			resource: types.CaptchaResource{
				ResourceType: "background_image",
				StorageType:  "url",
				URI:          "https://cdn.example.test/huge.png",
				Metadata: map[string]any{
					"width": 8192,
				},
			},
		},
		{
			name: "wrong font mime",
			resource: types.CaptchaResource{
				ResourceType: "font",
				StorageType:  "url",
				URI:          "https://cdn.example.test/font.exe",
				Metadata: map[string]any{
					"mime_type": "application/x-msdownload",
				},
			},
		},
		{
			name: "invalid difficulty",
			resource: types.CaptchaResource{
				ResourceType: "jigsaw_background_library",
				StorageType:  "url",
				URI:          "https://cdn.example.test/jigsaw.png",
				Metadata: map[string]any{
					"difficulty": "impossible",
				},
			},
		},
		{
			name: "object storage userinfo",
			resource: types.CaptchaResource{
				ResourceType: "background_image",
				StorageType:  "object_storage",
				URI:          "s3://user@captcha-assets/login.png",
			},
		},
		{
			name: "object storage missing key",
			resource: types.CaptchaResource{
				ResourceType: "background_image",
				StorageType:  "object_storage",
				URI:          "s3://captcha-assets",
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ValidateAndNormalize(tc.resource); err == nil {
				t.Fatalf("expected validation error for %+v", tc.resource)
			}
		})
	}
}

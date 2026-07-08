package store

import (
	"fmt"
	"time"

	"captcha/internal/types"
)

type demoImageCategory struct {
	key   string
	label string
}

type demoBackgroundImage struct {
	id        string
	label     string
	width     int
	height    int
	directory string
}

var demoGridCategories = []demoImageCategory{
	{key: "cat", label: "猫"},
	{key: "dog", label: "狗"},
	{key: "panda", label: "熊猫"},
	{key: "bird", label: "鸟"},
}

var demoBackgroundImages = []demoBackgroundImage{
	{id: "01", label: "猫", width: 640, height: 360, directory: "backgrounds"},
	{id: "02", label: "狗", width: 640, height: 360, directory: "backgrounds"},
	{id: "03", label: "熊猫", width: 640, height: 360, directory: "backgrounds"},
	{id: "04", label: "鸟", width: 640, height: 360, directory: "backgrounds"},
}

var demoConcatBackgroundImages = []demoBackgroundImage{
	{id: "01", label: "猫", width: 640, height: 360, directory: "concat"},
	{id: "02", label: "狗", width: 640, height: 360, directory: "concat"},
	{id: "03", label: "熊猫", width: 640, height: 360, directory: "concat"},
	{id: "04", label: "鸟", width: 640, height: 360, directory: "concat"},
}

var demoJigsawBackgroundImages = []demoBackgroundImage{
	{id: "01", label: "猫", width: 600, height: 360, directory: "jigsaw"},
	{id: "02", label: "狗", width: 600, height: 360, directory: "jigsaw"},
	{id: "03", label: "熊猫", width: 600, height: 360, directory: "jigsaw"},
	{id: "04", label: "鸟", width: 600, height: 360, directory: "jigsaw"},
}

var demoRotateCategories = []demoImageCategory{
	{key: "city", label: "城市"},
}

func demoClasspathImageResources(now time.Time) []types.CaptchaResource {
	resources := make([]types.CaptchaResource, 0, len(demoBackgroundImages)+len(demoConcatBackgroundImages)+len(demoJigsawBackgroundImages)+len(demoRotateCategories)*9+len(demoGridCategories)*9)
	for _, item := range demoBackgroundImages {
		resources = append(resources, classpathImageResource(
			fmt.Sprintf("res_demo_bg_%s", item.id),
			types.CaptchaAuto,
			"background_library",
			fmt.Sprintf("classpath://captcha-demo/%s/bg-%s.jpg", item.directory, item.id),
			map[string]any{
				"label":     item.label,
				"mime_type": "image/jpeg",
				"width":     item.width,
				"height":    item.height,
			},
			now,
		))
	}
	for _, item := range demoConcatBackgroundImages {
		resources = append(resources, classpathImageResource(
			fmt.Sprintf("res_demo_concat_bg_%s", item.id),
			types.CaptchaConcat,
			"concat_background_library",
			fmt.Sprintf("classpath://captcha-demo/%s/bg-%s.jpg", item.directory, item.id),
			map[string]any{
				"label":         item.label,
				"mime_type":     "image/jpeg",
				"width":         item.width,
				"height":        item.height,
				"usage_profile": "concat_restore",
			},
			now,
		))
	}
	for _, item := range demoJigsawBackgroundImages {
		resources = append(resources, classpathImageResource(
			fmt.Sprintf("res_demo_jigsaw_bg_%s", item.id),
			types.CaptchaJigsaw,
			"jigsaw_background_library",
			fmt.Sprintf("classpath://captcha-demo/%s/bg-%s.jpg", item.directory, item.id),
			map[string]any{
				"label":         item.label,
				"mime_type":     "image/jpeg",
				"width":         item.width,
				"height":        item.height,
				"usage_profile": "jigsaw_shuffle",
			},
			now,
		))
	}
	for _, category := range demoRotateCategories {
		for index := 1; index <= 9; index++ {
			resources = append(resources, classpathImageResource(
				fmt.Sprintf("res_demo_rotate_%s_%02d", category.key, index),
				types.CaptchaRotate,
				"rotate_library",
				fmt.Sprintf("classpath://captcha-demo/rotate/%s-%02d.jpg", category.key, index),
				map[string]any{
					"label":     category.label,
					"mime_type": "image/jpeg",
					"width":     320,
					"height":    320,
				},
				now,
			))
		}
	}
	for _, category := range demoGridCategories {
		for index := 1; index <= 9; index++ {
			resources = append(resources, classpathImageResource(
				fmt.Sprintf("res_demo_grid_%s_%02d", category.key, index),
				types.CaptchaGridImageClick,
				"grid_category_library",
				fmt.Sprintf("classpath://captcha-demo/grid/%s/%s-%02d.jpg", category.key, category.key, index),
				map[string]any{
					"category":  category.key,
					"label":     category.label,
					"mime_type": "image/jpeg",
					"width":     320,
					"height":    320,
				},
				now,
			))
		}
	}
	return resources
}

func classpathImageResource(id string, captchaType types.CaptchaType, resourceType, uri string, metadata map[string]any, now time.Time) types.CaptchaResource {
	return types.CaptchaResource{
		ID:           id,
		ClientID:     "demo",
		CaptchaType:  captchaType,
		ResourceType: resourceType,
		StorageType:  "classpath",
		URI:          uri,
		Tag:          "default",
		Status:       "active",
		Metadata:     metadata,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

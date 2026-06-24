#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

concrete_types=(GESTURE CURVE CURVE_V2 CURVE_V3 SLIDER SLIDER_V2 ROTATE CONCAT ROTATE_DEGREE WORD_IMAGE_CLICK IMAGE_CLICK JIGSAW GRID_IMAGE_CLICK)
go_constants=(CaptchaGesture CaptchaCurve CaptchaCurve2 CaptchaCurve3 CaptchaSlider CaptchaSlider2 CaptchaRotate CaptchaConcat CaptchaRotateDegree CaptchaWordImageClick CaptchaImageClick CaptchaJigsaw CaptchaGridImageClick)

grep -Eq 'CaptchaAuto[[:space:]]+CaptchaType[[:space:]]*=[[:space:]]*"AUTO"' internal/types/types.go ||
	fail "Go captcha type constants must include AUTO"

for i in "${!concrete_types[@]}"; do
	captcha_type="${concrete_types[$i]}"
	go_constant="${go_constants[$i]}"

	grep -Fq "$captcha_type" docs/architecture-design.md ||
		fail "docs/architecture-design.md must document $captcha_type"
	grep -Eq "${go_constant}[[:space:]]+CaptchaType[[:space:]]*=[[:space:]]*\"${captcha_type}\"" internal/types/types.go ||
		fail "internal/types/types.go must define $go_constant as $captcha_type"
	grep -Fq "types.${go_constant}" internal/engine/engine.go ||
		fail "internal/engine/engine.go must reference types.$go_constant"
	grep -Fq "\"${captcha_type}\"" web/runtime/src/main.tsx ||
		fail "web/runtime/src/main.tsx must support rendered type $captcha_type"
	grep -Fq "\"${captcha_type}\"" web/admin/src/main.tsx ||
		fail "web/admin/src/main.tsx must expose admin option $captcha_type"
done

supported_block="$(awk '
	/var supportedTypes = \[\]types\.CaptchaType\{/ { in_block = 1 }
	in_block { print }
	in_block && /^\}/ { exit }
' internal/engine/engine.go)"

for go_constant in "${go_constants[@]}"; do
	grep -Fq "types.${go_constant}" <<<"$supported_block" ||
		fail "engine supportedTypes must include types.$go_constant"
done

if grep -Fq "types.CaptchaAuto" <<<"$supported_block"; then
	fail "engine supportedTypes must not include AUTO; AUTO should resolve before generation"
fi

grep -Fq 'captcha_type: CaptchaType | "AUTO"' web/runtime/src/main.tsx ||
	fail "runtime session creation request must allow AUTO"
grep -Fq 'const captchaTypes = [' web/admin/src/main.tsx ||
	fail "admin must centralize concrete captcha type options"
grep -Fq 'function galleryUploadDefaults' web/admin/src/main.tsx ||
	fail "admin resource upload must derive captcha/resource defaults from gallery type"
grep -Fq 'captchaType: "AUTO", resourceType: "background_library"' web/admin/src/main.tsx ||
	fail "admin background gallery upload must default captcha type to AUTO"
for resource_type in background_library concat_background_library jigsaw_background_library grid_category_library icon icon_library degree_template curve_template gesture_template jigsaw_template; do
	grep -Eq "(\"${resource_type}\"|${resource_type}:)" internal/resource/validator.go ||
		fail "resource validator must allow $resource_type"
	grep -Eq "(\"${resource_type}\"|${resource_type}:)" web/admin/src/main.tsx ||
		fail "admin resource type selector must expose $resource_type"
done

echo "PASS: captcha type contract is aligned"

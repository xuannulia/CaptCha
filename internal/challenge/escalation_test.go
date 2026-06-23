package challenge

import (
	"testing"

	"captcha/internal/types"
)

func TestHarderTypeUsesConfiguredSequence(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		current    types.CaptchaType
		configured []types.CaptchaType
		want       types.CaptchaType
	}{
		{name: "default sequence", current: types.CaptchaSlider, want: types.CaptchaRotate},
		{name: "configured jump", current: types.CaptchaSlider, configured: []types.CaptchaType{types.CaptchaSlider, types.CaptchaWordImageClick}, want: types.CaptchaWordImageClick},
		{name: "missing current uses next stronger configured type", current: types.CaptchaRotate, configured: []types.CaptchaType{types.CaptchaSlider, types.CaptchaWordImageClick}, want: types.CaptchaWordImageClick},
		{name: "no downgrade from strongest type", current: types.CaptchaWordImageClick, configured: []types.CaptchaType{types.CaptchaSlider, types.CaptchaRotate}, want: types.CaptchaWordImageClick},
		{name: "invalid configured values fall back to default", current: types.CaptchaRotate, configured: []types.CaptchaType{"AUTO", "unknown", ""}, want: types.CaptchaConcat},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := HarderType(tc.current, tc.configured); got != tc.want {
				t.Fatalf("HarderType(%s, %+v)=%s want %s", tc.current, tc.configured, got, tc.want)
			}
		})
	}
}

func TestParseAndFormatEscalationCSV(t *testing.T) {
	t.Parallel()

	sequence := ParseEscalationCSV(" slider,ROTATE,ROTATE,unknown,word_image_click ")
	if got := FormatEscalationCSV(sequence); got != "SLIDER,ROTATE,WORD_IMAGE_CLICK" {
		t.Fatalf("unexpected formatted sequence: %q", got)
	}
	if got := FormatEscalationCSV(ParseEscalationCSV("AUTO,unknown")); got != "" {
		t.Fatalf("expected invalid configured sequence to stay empty, got %q", got)
	}
}

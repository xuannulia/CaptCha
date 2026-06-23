package challenge

import (
	"strings"

	"captcha/internal/types"
)

func HarderType(current types.CaptchaType, configured []types.CaptchaType) types.CaptchaType {
	sequence := NormalizeEscalation(configured)
	for index, captchaType := range sequence {
		if captchaType == current {
			if index+1 < len(sequence) {
				return sequence[index+1]
			}
			return current
		}
	}
	currentRank, ok := captchaTypeRank(current)
	if !ok {
		return sequence[len(sequence)-1]
	}
	for _, captchaType := range sequence {
		if rank, ok := captchaTypeRank(captchaType); ok && rank > currentRank {
			return captchaType
		}
	}
	return current
}

func NormalizeEscalation(configured []types.CaptchaType) []types.CaptchaType {
	sequence := NormalizeConfiguredEscalation(configured)
	if len(sequence) == 0 {
		return DefaultEscalation()
	}
	return sequence
}

func NormalizeConfiguredEscalation(configured []types.CaptchaType) []types.CaptchaType {
	if len(configured) == 0 {
		return nil
	}
	seen := make(map[types.CaptchaType]struct{}, len(configured))
	sequence := make([]types.CaptchaType, 0, len(configured))
	for _, captchaType := range configured {
		captchaType = normalizeType(captchaType)
		if _, ok := captchaTypeRank(captchaType); !ok {
			continue
		}
		if _, ok := seen[captchaType]; ok {
			continue
		}
		seen[captchaType] = struct{}{}
		sequence = append(sequence, captchaType)
	}
	return sequence
}

func ParseEscalationCSV(value string) []types.CaptchaType {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	sequence := make([]types.CaptchaType, 0, len(parts))
	for _, part := range parts {
		sequence = append(sequence, types.CaptchaType(part))
	}
	return NormalizeConfiguredEscalation(sequence)
}

func FormatEscalationCSV(sequence []types.CaptchaType) string {
	sequence = NormalizeConfiguredEscalation(sequence)
	if len(sequence) == 0 {
		return ""
	}
	parts := make([]string, 0, len(sequence))
	for _, captchaType := range sequence {
		parts = append(parts, string(captchaType))
	}
	return strings.Join(parts, ",")
}

func DefaultEscalation() []types.CaptchaType {
	return []types.CaptchaType{
		types.CaptchaSlider,
		types.CaptchaRotate,
		types.CaptchaConcat,
		types.CaptchaWordImageClick,
	}
}

func normalizeType(captchaType types.CaptchaType) types.CaptchaType {
	normalized := types.CaptchaType(strings.ToUpper(strings.TrimSpace(string(captchaType))))
	switch normalized {
	case "POW":
		return types.CaptchaProofOfWork
	case "SLIDER2":
		return types.CaptchaSlider2
	case "CURVE2":
		return types.CaptchaCurve2
	case "CURVE3":
		return types.CaptchaCurve3
	default:
		return normalized
	}
}

func captchaTypeRank(captchaType types.CaptchaType) (int, bool) {
	switch captchaType {
	case types.CaptchaProofOfWork:
		return 0, true
	case types.CaptchaSlider:
		return 1, true
	case types.CaptchaSlider2:
		return 2, true
	case types.CaptchaRotate:
		return 3, true
	case types.CaptchaConcat:
		return 4, true
	case types.CaptchaGesture:
		return 5, true
	case types.CaptchaCurve:
		return 6, true
	case types.CaptchaCurve2:
		return 7, true
	case types.CaptchaCurve3:
		return 8, true
	case types.CaptchaRotateDegree:
		return 9, true
	case types.CaptchaWordImageClick:
		return 10, true
	case types.CaptchaImageClick:
		return 11, true
	case types.CaptchaJigsaw:
		return 12, true
	case types.CaptchaGridImageClick:
		return 13, true
	default:
		return 0, false
	}
}

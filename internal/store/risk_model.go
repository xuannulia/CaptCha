package store

import (
	"sort"
	"strings"
	"time"

	"captcha/internal/types"
)

func prepareRiskModelVersion(version types.RiskModelVersion) types.RiskModelVersion {
	if version.ID == "" {
		version.ID = newID("model")
	}
	version.Name = strings.TrimSpace(version.Name)
	version.Version = strings.TrimSpace(version.Version)
	if version.FeatureVersion == "" {
		version.FeatureVersion = "track-v1"
	}
	if version.Metrics == nil {
		version.Metrics = map[string]any{}
	}
	version.Mode = normalizeModelMode(version.Mode)
	version.Status = normalizeModelStatus(version.Status)
	if version.CreatedAt.IsZero() {
		version.CreatedAt = time.Now().UTC()
	}
	return version
}

func normalizeModelMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "shadow", "observe", "enforce":
		return mode
	default:
		return "shadow"
	}
}

func normalizeModelStatus(status string) string {
	status = strings.ToLower(strings.TrimSpace(status))
	switch status {
	case "candidate", "active", "retired", "rolled_back":
		return status
	default:
		return "candidate"
	}
}

func validateRiskModelVersion(version types.RiskModelVersion) bool {
	return strings.TrimSpace(version.Name) != "" &&
		strings.TrimSpace(version.Version) != "" &&
		strings.TrimSpace(version.FeatureVersion) != "" &&
		strings.TrimSpace(version.TrainingWindow) != "" &&
		strings.TrimSpace(version.ArtifactURI) != ""
}

func sortRiskModelsByCreatedDesc(versions []types.RiskModelVersion) {
	sort.SliceStable(versions, func(i, j int) bool {
		if !versions[i].CreatedAt.Equal(versions[j].CreatedAt) {
			return versions[i].CreatedAt.After(versions[j].CreatedAt)
		}
		return versions[i].ID < versions[j].ID
	})
}

func sortRiskModelsByActivationDesc(versions []types.RiskModelVersion) {
	sort.SliceStable(versions, func(i, j int) bool {
		left := modelActivatedAt(versions[i])
		right := modelActivatedAt(versions[j])
		if !left.Equal(right) {
			return left.After(right)
		}
		if !versions[i].CreatedAt.Equal(versions[j].CreatedAt) {
			return versions[i].CreatedAt.After(versions[j].CreatedAt)
		}
		return versions[i].ID < versions[j].ID
	})
}

func modelActivatedAt(version types.RiskModelVersion) time.Time {
	if version.ActivatedAt == nil {
		return time.Time{}
	}
	return *version.ActivatedAt
}

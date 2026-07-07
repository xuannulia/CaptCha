package risk

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestGenerateSyntheticBotTrackRecords(t *testing.T) {
	records, err := GenerateSyntheticBotTrackRecords(BotTrackOptions{
		Count:     len(DefaultBotTrackFamilies()) * 2,
		Seed:      7,
		ClientID:  "demo",
		Scene:     "login",
		CreatedAt: time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != len(DefaultBotTrackFamilies())*2 {
		t.Fatalf("unexpected record count %d", len(records))
	}

	families := map[string]bool{}
	hasRejectedBot := false
	hasPassThroughBot := false
	for _, record := range records {
		if record.SchemaVersion != SyntheticBotTrackSchemaVersion {
			t.Fatalf("unexpected schema version %q", record.SchemaVersion)
		}
		if record.FeatureVersion != SyntheticBotTrackFeatureVersion {
			t.Fatalf("unexpected feature version %q", record.FeatureVersion)
		}
		if record.Label != "confirmed_bot" || record.LabelSource != "synthetic_bot_generator" || !record.ModelTrainable {
			t.Fatalf("unexpected label metadata: %+v", record)
		}
		if record.FeaturesDigest == "" || record.FeaturesRef != "inline" {
			t.Fatalf("expected inline features digest, got %+v", record)
		}
		if len(record.Track) < 2 {
			t.Fatalf("expected raw track points, got %+v", record.Track)
		}
		if record.Track[0].Type != "start" || record.Track[len(record.Track)-1].Type != "end" {
			t.Fatalf("expected typed track endpoints, got %+v", record.Track)
		}
		family, _ := record.Features["bot_family"].(string)
		if family == "" {
			t.Fatalf("expected bot family feature: %+v", record.Features)
		}
		families[family] = true
		if record.Features["source"] != "synthetic_bot_track" {
			t.Fatalf("expected synthetic source feature: %+v", record.Features)
		}
		if record.Features["generator_version"] != SyntheticBotTrackGeneratorVersion {
			t.Fatalf("expected generator version feature: %+v", record.Features)
		}
		score, ok := intFeatureForTest(record.Features["track_score"])
		if !ok {
			t.Fatalf("expected numeric track score: %+v", record.Features["track_score"])
		}
		if score < 45 {
			hasRejectedBot = true
		} else {
			hasPassThroughBot = true
		}
	}
	if len(families) != len(DefaultBotTrackFamilies()) {
		t.Fatalf("expected all families, got %v", families)
	}
	if !hasRejectedBot || !hasPassThroughBot {
		t.Fatalf("expected both rejected and pass-through bot samples")
	}
}

func TestGenerateSyntheticBotTrackRecordsDeterministic(t *testing.T) {
	options := BotTrackOptions{Count: 12, Seed: 42}
	left, err := GenerateSyntheticBotTrackRecords(options)
	if err != nil {
		t.Fatal(err)
	}
	right, err := GenerateSyntheticBotTrackRecords(options)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(left, right) {
		t.Fatal("expected deterministic records for the same seed")
	}
}

func TestWriteSyntheticTrackJSONL(t *testing.T) {
	records, err := GenerateSyntheticBotTrackRecords(BotTrackOptions{Count: 3, Seed: 99})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := WriteSyntheticTrackJSONL(&out, records); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(out.Bytes()), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("expected 3 jsonl lines, got %d", len(lines))
	}
	for _, line := range lines {
		var record SyntheticTrackRecord
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("decode line %q: %v", line, err)
		}
		if record.Label != "confirmed_bot" || len(record.Track) == 0 {
			t.Fatalf("unexpected record: %+v", record)
		}
	}
}

func intFeatureForTest(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	default:
		return 0, false
	}
}

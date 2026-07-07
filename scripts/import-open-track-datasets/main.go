package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"captcha/internal/engine"
	"captcha/internal/types"
)

type exportRecord struct {
	SchemaVersion  string             `json:"schema_version"`
	ID             string             `json:"id"`
	AttemptID      string             `json:"attempt_id"`
	ClientID       string             `json:"client_id"`
	Scene          string             `json:"scene"`
	ChallengeType  types.CaptchaType  `json:"challenge_type"`
	FeatureVersion string             `json:"feature_version"`
	FeaturesDigest string             `json:"features_digest"`
	FeaturesRef    string             `json:"features_ref"`
	Features       map[string]any     `json:"features"`
	Label          string             `json:"label"`
	LabelSource    string             `json:"label_source"`
	ModelTrainable bool               `json:"model_trainable"`
	CreatedAt      string             `json:"created_at"`
	Track          []types.TrackPoint `json:"track,omitempty"`
}

type captchaSolveRecord struct {
	Index      int                 `json:"index"`
	TickInputs []captchaSolveInput `json:"tickInputs"`
}

type captchaSolveInput struct {
	IsDown      bool    `json:"isDown"`
	SampleIndex int64   `json:"sampleIndex"`
	X           float64 `json:"x"`
	Y           float64 `json:"y"`
}

func main() {
	delbotDir := flag.String("delbot-dir", "", "Path to extracted DELBOT-Mouse dataset directory.")
	captchaSolveJSONL := flag.String("captchasolve-jsonl", "", "Path to CaptchaSolve30k JSONL file or sampled head file.")
	outDir := flag.String("out-dir", "output/training/open-datasets", "Directory for converted JSONL files.")
	maxCaptchaSolve := flag.Int("max-captchasolve", 2000, "Maximum CaptchaSolve30k lines to convert.")
	trainableExternal := flag.Bool("trainable-external", false, "Mark external records trainable. Default false avoids accidental training pollution.")
	flag.Parse()

	if *delbotDir == "" && *captchaSolveJSONL == "" {
		fatalf("provide at least --delbot-dir or --captchasolve-jsonl")
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatalf("create out dir: %v", err)
	}

	if *delbotDir != "" {
		if err := convertDELBOT(*delbotDir, *outDir, *trainableExternal); err != nil {
			fatalf("convert DELBOT: %v", err)
		}
	}
	if *captchaSolveJSONL != "" {
		if err := convertCaptchaSolve(*captchaSolveJSONL, *outDir, *maxCaptchaSolve, *trainableExternal); err != nil {
			fatalf("convert CaptchaSolve30k: %v", err)
		}
	}
}

func convertDELBOT(root, outDir string, trainable bool) error {
	files, err := listFiles(root, ".txt")
	if err != nil {
		return err
	}
	humanPath := filepath.Join(outDir, "external-delbot-human-candidates.jsonl")
	botPath := filepath.Join(outDir, "external-delbot-bot-tracks.jsonl")
	humanOut, err := os.Create(humanPath)
	if err != nil {
		return err
	}
	defer humanOut.Close()
	botOut, err := os.Create(botPath)
	if err != nil {
		return err
	}
	defer botOut.Close()

	var humanCount, botCount, skipped int
	for _, path := range files {
		track, resolution, err := readDELBOTTrack(path)
		if err != nil || len(track) < 2 {
			skipped++
			continue
		}
		group := filepath.Base(filepath.Dir(path))
		isBot := strings.Contains(group, "_bot_")
		label := "likely_human"
		labelSource := "external_delbot_human"
		writer := humanOut
		if isBot {
			label = "confirmed_bot"
			labelSource = "external_delbot_bot"
			writer = botOut
		}
		device := delbotDeviceHint(group)
		record := buildRecord(buildRecordOptions{
			SourceID:       strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
			Dataset:        "delbot_mouse",
			Family:         group,
			Scene:          "external-delbot",
			ChallengeType:  types.CaptchaSlider,
			TaskType:       "slider_external_motion",
			InputDevice:    device,
			PointerType:    pointerTypeForDevice(device),
			Label:          label,
			LabelSource:    labelSource,
			ModelTrainable: trainable,
			Track:          normalizeTrack(track),
			Extra: map[string]any{
				"external_resolution": resolution,
			},
		})
		if err := writeJSONLine(writer, record); err != nil {
			return err
		}
		if isBot {
			botCount++
		} else {
			humanCount++
		}
	}
	fmt.Printf("DELBOT converted: human=%d bot=%d skipped=%d\n", humanCount, botCount, skipped)
	fmt.Printf("  %s\n  %s\n", humanPath, botPath)
	return nil
}

func convertCaptchaSolve(path, outDir string, maxRows int, trainable bool) error {
	outPath := filepath.Join(outDir, "external-captchasolve30k-human-candidates.jsonl")
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	var converted, skipped int
	for scanner.Scan() {
		if maxRows > 0 && converted >= maxRows {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var raw captchaSolveRecord
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			skipped++
			continue
		}
		track := captchaSolveTrack(raw.TickInputs)
		if len(track) < 2 {
			skipped++
			continue
		}
		record := buildRecord(buildRecordOptions{
			SourceID:       strconv.Itoa(raw.Index),
			Dataset:        "captchasolve30k",
			Family:         "tick_inputs",
			Scene:          "external-captchasolve30k",
			ChallengeType:  types.CaptchaSlider,
			TaskType:       "slider_external_captcha",
			InputDevice:    "mouse",
			PointerType:    "mouse",
			Label:          "likely_human",
			LabelSource:    "external_captchasolve30k",
			ModelTrainable: trainable,
			Track:          normalizeTrack(track),
			Extra: map[string]any{
				"external_index": raw.Index,
			},
		})
		if err := writeJSONLine(out, record); err != nil {
			return err
		}
		converted++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	fmt.Printf("CaptchaSolve30k converted: human=%d skipped=%d\n", converted, skipped)
	fmt.Printf("  %s\n", outPath)
	return nil
}

type buildRecordOptions struct {
	SourceID       string
	Dataset        string
	Family         string
	Scene          string
	ChallengeType  types.CaptchaType
	TaskType       string
	InputDevice    string
	PointerType    string
	Label          string
	LabelSource    string
	ModelTrainable bool
	Track          []types.TrackPoint
	Extra          map[string]any
}

func buildRecord(options buildRecordOptions) exportRecord {
	score := engine.ScoreTrack(options.Track)
	features := engine.ExtractTrackFeatures(options.Track)
	features["collector_task_type"] = options.TaskType
	features["decision"] = "observe"
	features["external_dataset"] = options.Dataset
	features["external_family"] = options.Family
	features["input_device_hint"] = options.InputDevice
	features["input_device_inferred"] = options.InputDevice
	features["label_hint"] = options.Label
	features["pointer_type"] = options.PointerType
	features["reason_code"] = "EXTERNAL_TRACK_DATASET"
	features["result_ok"] = options.Label == "likely_human"
	features["source"] = "external_track_dataset"
	features["track_bucket"] = score.Bucket
	features["track_reason_count"] = len(score.Reasons)
	features["track_reasons"] = score.Reasons
	features["track_score"] = score.Score
	features["track_score_duration"] = score.DurationMS
	features["track_submit_points"] = len(options.Track)
	for key, value := range options.Extra {
		features[key] = value
	}
	digest := digestFeatures(features)
	idSeed := fmt.Sprintf("%s:%s:%s", options.Dataset, options.Family, options.SourceID)
	id := shortDigest(idSeed)
	return exportRecord{
		SchemaVersion:  "risk-feature-export-v1",
		ID:             "external_" + id,
		AttemptID:      "external:" + options.Dataset + ":" + options.SourceID,
		ClientID:       "external-dataset",
		Scene:          options.Scene,
		ChallengeType:  options.ChallengeType,
		FeatureVersion: "track-v1",
		FeaturesDigest: digest,
		FeaturesRef:    "inline",
		Features:       features,
		Label:          options.Label,
		LabelSource:    options.LabelSource,
		ModelTrainable: options.ModelTrainable,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		Track:          options.Track,
	}
}

func readDELBOTTrack(path string) ([]types.TrackPoint, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var width, height float64
	var points []types.TrackPoint
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "resolution:") {
			parts := strings.Split(strings.TrimPrefix(line, "resolution:"), ",")
			if len(parts) == 2 {
				width, _ = strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
				height, _ = strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
			}
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 4 {
			continue
		}
		t, ok1 := parseFloat(parts[0])
		event := strings.TrimSpace(parts[1])
		x, ok2 := parseFloat(parts[2])
		y, ok3 := parseFloat(parts[3])
		if !ok1 || !ok2 || !ok3 {
			continue
		}
		if width > 0 && height > 0 && math.Abs(x) <= 1.5 && math.Abs(y) <= 1.5 {
			x *= width
			y *= height
		}
		points = append(points, types.TrackPoint{X: x, Y: y, T: int64(math.Round(t)), Type: eventType(event)})
	}
	if err := scanner.Err(); err != nil {
		return nil, "", err
	}
	resolution := ""
	if width > 0 && height > 0 {
		resolution = fmt.Sprintf("%.0fx%.0f", width, height)
	}
	return points, resolution, nil
}

func captchaSolveTrack(inputs []captchaSolveInput) []types.TrackPoint {
	points := make([]types.TrackPoint, 0, len(inputs))
	started := false
	for _, input := range inputs {
		if !started {
			if input.X == 0 && input.Y == 0 && !input.IsDown {
				continue
			}
			started = true
		}
		points = append(points, types.TrackPoint{
			X:    input.X,
			Y:    input.Y,
			T:    input.SampleIndex * 16,
			Type: "move",
		})
	}
	points = collapseDuplicatePoints(points)
	if len(points) > 0 {
		points[0].Type = "start"
		points[len(points)-1].Type = "end"
	}
	return points
}

func normalizeTrack(points []types.TrackPoint) []types.TrackPoint {
	points = collapseDuplicatePoints(points)
	if len(points) == 0 {
		return nil
	}
	out := make([]types.TrackPoint, 0, len(points))
	first := points[0]
	lastT := int64(0)
	for i, point := range points {
		t := point.T - first.T
		if t < lastT {
			t = lastT
		}
		kind := point.Type
		if i == 0 {
			kind = "start"
		} else if i == len(points)-1 {
			kind = "end"
		} else {
			kind = "move"
		}
		out = append(out, types.TrackPoint{
			X:    round3(point.X - first.X),
			Y:    round3(point.Y - first.Y),
			T:    t,
			Type: kind,
		})
		lastT = t
	}
	return out
}

func collapseDuplicatePoints(points []types.TrackPoint) []types.TrackPoint {
	out := make([]types.TrackPoint, 0, len(points))
	for _, point := range points {
		if len(out) == 0 {
			out = append(out, point)
			continue
		}
		last := out[len(out)-1]
		if math.Abs(last.X-point.X) < 0.001 && math.Abs(last.Y-point.Y) < 0.001 && last.T == point.T {
			continue
		}
		out = append(out, point)
	}
	return out
}

func listFiles(root, ext string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || strings.ToLower(filepath.Ext(path)) != ext {
			return nil
		}
		files = append(files, path)
		return nil
	})
	sort.Strings(files)
	return files, err
}

func delbotDeviceHint(group string) string {
	switch {
	case strings.Contains(group, "_tel"):
		return "touch"
	case strings.Contains(group, "_pad"):
		return "trackpad"
	default:
		return "mouse"
	}
}

func pointerTypeForDevice(device string) string {
	if device == "touch" {
		return "touch"
	}
	return "mouse"
}

func eventType(event string) string {
	event = strings.ToLower(event)
	switch {
	case strings.Contains(event, "press"):
		return "start"
	case strings.Contains(event, "release"), strings.Contains(event, "up"):
		return "end"
	default:
		return "move"
	}
}

func parseFloat(value string) (float64, bool) {
	out, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || math.IsNaN(out) || math.IsInf(out, 0) {
		return 0, false
	}
	return out, true
}

func digestFeatures(features map[string]any) string {
	body, _ := json.Marshal(features)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func shortDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func writeJSONLine(w io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", encoded)
	return err
}

func round3(value float64) float64 {
	return math.Round(value*1000) / 1000
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

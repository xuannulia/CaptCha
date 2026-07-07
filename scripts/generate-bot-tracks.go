package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"captcha/internal/risk"
)

func main() {
	var (
		count          = flag.Int("count", 10000, "number of synthetic bot track records")
		seed           = flag.Int64("seed", 20260627, "deterministic random seed")
		clientID       = flag.String("client-id", "synthetic", "client id written to export records")
		scene          = flag.String("scene", "track-training", "scene written to export records")
		challengeTypes = flag.String("types", "", "comma-separated captcha types; defaults to slider-like types")
		outPath        = flag.String("out", "", "output JSONL path; stdout when empty")
		minTargetX     = flag.Int("min-x", 90, "minimum target x")
		maxTargetX     = flag.Int("max-x", 300, "maximum target x")
		baselineY      = flag.Float64("y", 22, "baseline track y")
		createdAt      = flag.String("created-at", "2026-01-01T00:00:00Z", "first record timestamp in RFC3339")
	)
	flag.Parse()

	parsedTypes, err := risk.ParseCaptchaTypes(*challengeTypes)
	if err != nil {
		exitf("parse types: %v", err)
	}
	parsedCreatedAt, err := time.Parse(time.RFC3339, *createdAt)
	if err != nil {
		exitf("parse created-at: %v", err)
	}
	records, err := risk.GenerateSyntheticBotTrackRecords(risk.BotTrackOptions{
		Count:          *count,
		Seed:           *seed,
		ClientID:       *clientID,
		Scene:          *scene,
		ChallengeTypes: parsedTypes,
		CreatedAt:      parsedCreatedAt,
		MinTargetX:     *minTargetX,
		MaxTargetX:     *maxTargetX,
		BaselineY:      *baselineY,
	})
	if err != nil {
		exitf("generate records: %v", err)
	}

	out := os.Stdout
	if *outPath != "" {
		file, err := os.Create(*outPath)
		if err != nil {
			exitf("create output: %v", err)
		}
		defer file.Close()
		out = file
	}
	if err := risk.WriteSyntheticTrackJSONL(out, records); err != nil {
		exitf("write jsonl: %v", err)
	}
}

func exitf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

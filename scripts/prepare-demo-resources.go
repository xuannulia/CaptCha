//go:build ignore

package main

import (
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	_ "image/png"
	"math"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/image/draw"
)

const (
	gridSize       = 3
	cellInset      = 4
	maxWhiteTrim   = 24
	jpegQuality    = 92
	edgeWhiteLevel = 248
)

type sourceImage struct {
	key  string
	file string
}

type outputSelection struct {
	category string
	cell     int
}

type interval struct {
	start int
	end   int
}

func main() {
	sourceDir := flag.String("source", defaultSourceDir(), "directory containing AI-generated source images")
	outputDir := flag.String("out", filepath.Join("resources", "captcha-demo"), "output captcha-demo resource directory")
	flag.Parse()

	landscapeSources := []sourceImage{
		{key: "cat", file: "成品-1 (8).png"},
		{key: "dog", file: "成品-1 (7).png"},
		{key: "panda", file: "成品-1 (6).png"},
		{key: "bird", file: "成品-1 (5).png"},
	}
	squareSources := []sourceImage{
		{key: "cat", file: "成品-1 (1).png"},
		{key: "dog", file: "成品-1 (2).png"},
		{key: "panda", file: "成品-1 (3).png"},
		{key: "bird", file: "成品-1 (4).png"},
		{key: "city", file: "成品-1.png"},
	}

	landscapeCells, err := loadCellSets(*sourceDir, landscapeSources)
	if err != nil {
		exit(err)
	}
	squareCells, err := loadCellSets(*sourceDir, squareSources)
	if err != nil {
		exit(err)
	}

	for _, source := range landscapeSources {
		cells := landscapeCells[source.key]
		for index, cell := range cells {
			path := filepath.Join(*outputDir, "grid", source.key, fmt.Sprintf("%s-%02d.jpg", source.key, index+1))
			if err := writeCoverJPEG(path, cell.image, cell.rect, 320, 320); err != nil {
				exit(err)
			}
		}
	}

	for index, cell := range squareCells["city"] {
		path := filepath.Join(*outputDir, "rotate", fmt.Sprintf("city-%02d.jpg", index+1))
		if err := writeCoverJPEG(path, cell.image, cell.rect, 320, 320); err != nil {
			exit(err)
		}
	}

	backgrounds := []outputSelection{
		{category: "cat", cell: 1},
		{category: "dog", cell: 1},
		{category: "panda", cell: 1},
		{category: "bird", cell: 1},
	}
	concat := []outputSelection{
		{category: "cat", cell: 4},
		{category: "dog", cell: 4},
		{category: "panda", cell: 4},
		{category: "bird", cell: 4},
	}
	jigsaw := []outputSelection{
		{category: "cat", cell: 7},
		{category: "dog", cell: 7},
		{category: "panda", cell: 7},
		{category: "bird", cell: 7},
	}

	writeSelections(*outputDir, "backgrounds", backgrounds, landscapeCells, 640, 360)
	writeSelections(*outputDir, "concat", concat, landscapeCells, 640, 360)
	writeSelections(*outputDir, "jigsaw", jigsaw, landscapeCells, 600, 360)

	fmt.Printf("prepared captcha demo resources in %s\n", *outputDir)
}

type cellImage struct {
	image image.Image
	rect  image.Rectangle
}

func loadCellSets(sourceDir string, sources []sourceImage) (map[string][]cellImage, error) {
	sets := make(map[string][]cellImage, len(sources))
	for _, source := range sources {
		path := filepath.Join(sourceDir, source.file)
		img, err := readImage(path)
		if err != nil {
			return nil, err
		}
		rects := detectGridCells(img)
		cells := make([]cellImage, 0, len(rects))
		for _, rect := range rects {
			cells = append(cells, cellImage{image: img, rect: rect})
		}
		sets[source.key] = cells
	}
	return sets, nil
}

func writeSelections(outputDir, directory string, selections []outputSelection, cells map[string][]cellImage, width, height int) {
	for index, selection := range selections {
		sourceCells := cells[selection.category]
		if selection.cell < 0 || selection.cell >= len(sourceCells) {
			exit(fmt.Errorf("missing cell %d for %s", selection.cell, selection.category))
		}
		cell := sourceCells[selection.cell]
		path := filepath.Join(outputDir, directory, fmt.Sprintf("bg-%02d.jpg", index+1))
		if err := writeCoverJPEG(path, cell.image, cell.rect, width, height); err != nil {
			exit(err)
		}
	}
}

func readImage(path string) (image.Image, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	img, _, err := image.Decode(file)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return img, nil
}

func detectGridCells(img image.Image) []image.Rectangle {
	bounds := img.Bounds()
	columns := splitAxis(img, true)
	rows := splitAxis(img, false)
	rects := make([]image.Rectangle, 0, gridSize*gridSize)
	for _, row := range rows {
		for _, column := range columns {
			rect := image.Rect(column.start, row.start, column.end, row.end).Intersect(bounds)
			rect = trimWhiteBorder(img, rect, maxWhiteTrim).Intersect(bounds)
			rect = insetRect(rect, cellInset).Intersect(bounds)
			rects = append(rects, rect)
		}
	}
	return rects
}

func trimWhiteBorder(img image.Image, rect image.Rectangle, maxTrim int) image.Rectangle {
	if rect.Empty() || maxTrim <= 0 {
		return rect
	}
	trimmed := rect
	for trimmed.Min.Y < trimmed.Max.Y-1 && trimmed.Min.Y-rect.Min.Y < maxTrim && rectLineWhiteRatio(img, trimmed, false, trimmed.Min.Y) >= 0.985 {
		trimmed.Min.Y++
	}
	for trimmed.Max.Y > trimmed.Min.Y+1 && rect.Max.Y-trimmed.Max.Y < maxTrim && rectLineWhiteRatio(img, trimmed, false, trimmed.Max.Y-1) >= 0.985 {
		trimmed.Max.Y--
	}
	for trimmed.Min.X < trimmed.Max.X-1 && trimmed.Min.X-rect.Min.X < maxTrim && rectLineWhiteRatio(img, trimmed, true, trimmed.Min.X) >= 0.985 {
		trimmed.Min.X++
	}
	for trimmed.Max.X > trimmed.Min.X+1 && rect.Max.X-trimmed.Max.X < maxTrim && rectLineWhiteRatio(img, trimmed, true, trimmed.Max.X-1) >= 0.985 {
		trimmed.Max.X--
	}
	return trimmed
}

func rectLineWhiteRatio(img image.Image, rect image.Rectangle, vertical bool, position int) float64 {
	total := 0
	white := 0
	if vertical {
		for y := rect.Min.Y; y < rect.Max.Y; y++ {
			total++
			if isNearlyWhite(img.At(position, y)) {
				white++
			}
		}
	} else {
		for x := rect.Min.X; x < rect.Max.X; x++ {
			total++
			if isNearlyWhite(img.At(x, position)) {
				white++
			}
		}
	}
	if total == 0 {
		return 0
	}
	return float64(white) / float64(total)
}

func splitAxis(img image.Image, vertical bool) []interval {
	bounds := img.Bounds()
	minValue, maxValue := bounds.Min.X, bounds.Max.X
	if !vertical {
		minValue, maxValue = bounds.Min.Y, bounds.Max.Y
	}
	size := maxValue - minValue
	separators := make([]interval, 0, gridSize-1)
	for index := 1; index < gridSize; index++ {
		expected := minValue + size*index/gridSize
		window := maxInt(18, size/18)
		separator, ok := findSeparator(img, vertical, expected-window, expected+window)
		if !ok {
			separator = interval{start: expected, end: expected}
		}
		separators = append(separators, separator)
	}
	sort.Slice(separators, func(i, j int) bool {
		return separators[i].start < separators[j].start
	})
	return []interval{
		{start: minValue, end: separators[0].start},
		{start: separators[0].end, end: separators[1].start},
		{start: separators[1].end, end: maxValue},
	}
}

func findSeparator(img image.Image, vertical bool, start, end int) (interval, bool) {
	bounds := img.Bounds()
	axisMin, axisMax := bounds.Min.X, bounds.Max.X
	if !vertical {
		axisMin, axisMax = bounds.Min.Y, bounds.Max.Y
	}
	start = clampInt(start, axisMin, axisMax-1)
	end = clampInt(end, start+1, axisMax)
	thresholds := []float64{0.985, 0.97, 0.94, 0.9}
	for _, threshold := range thresholds {
		var candidates []scoredInterval
		runStart := -1
		runScore := 0.0
		for position := start; position < end; position++ {
			score := lineWhiteRatio(img, vertical, position)
			if score >= threshold {
				if runStart < 0 {
					runStart = position
					runScore = 0
				}
				runScore += score
				continue
			}
			if runStart >= 0 {
				candidates = append(candidates, scoredInterval{interval: interval{start: runStart, end: position}, score: runScore / float64(position-runStart)})
				runStart = -1
			}
		}
		if runStart >= 0 {
			candidates = append(candidates, scoredInterval{interval: interval{start: runStart, end: end}, score: runScore / float64(end-runStart)})
		}
		if best, ok := bestSeparator(candidates, (start+end)/2); ok {
			return best, true
		}
	}
	return interval{}, false
}

type scoredInterval struct {
	interval interval
	score    float64
}

func bestSeparator(candidates []scoredInterval, expected int) (interval, bool) {
	if len(candidates) == 0 {
		return interval{}, false
	}
	sort.Slice(candidates, func(i, j int) bool {
		left := separatorRank(candidates[i], expected)
		right := separatorRank(candidates[j], expected)
		return left > right
	})
	best := candidates[0].interval
	if best.end-best.start > 28 {
		center := (best.start + best.end) / 2
		best.start = center - 8
		best.end = center + 8
	}
	return best, true
}

func separatorRank(candidate scoredInterval, expected int) float64 {
	center := float64(candidate.interval.start+candidate.interval.end) / 2
	width := candidate.interval.end - candidate.interval.start
	return candidate.score*1000 + float64(minInt(width, 14))*2 - math.Abs(center-float64(expected))*0.08
}

func lineWhiteRatio(img image.Image, vertical bool, position int) float64 {
	bounds := img.Bounds()
	total := 0
	white := 0
	if vertical {
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			total++
			if isNearlyWhite(img.At(position, y)) {
				white++
			}
		}
	} else {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			total++
			if isNearlyWhite(img.At(x, position)) {
				white++
			}
		}
	}
	if total == 0 {
		return 0
	}
	return float64(white) / float64(total)
}

func isNearlyWhite(value color.Color) bool {
	r, g, b, _ := value.RGBA()
	threshold := uint32(edgeWhiteLevel) * 257
	return r >= threshold && g >= threshold && b >= threshold
}

func writeCoverJPEG(path string, src image.Image, rect image.Rectangle, width, height int) error {
	if width <= 0 || height <= 0 {
		return fmt.Errorf("invalid output size %dx%d", width, height)
	}
	rect = coverRect(rect, width, height)
	if rect.Empty() {
		return fmt.Errorf("empty crop rect for %s", path)
	}
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, rect, draw.Over, nil)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return jpeg.Encode(file, dst, &jpeg.Options{Quality: jpegQuality})
}

func coverRect(rect image.Rectangle, width, height int) image.Rectangle {
	sourceWidth := rect.Dx()
	sourceHeight := rect.Dy()
	if sourceWidth <= 0 || sourceHeight <= 0 {
		return rect
	}
	targetRatio := float64(width) / float64(height)
	sourceRatio := float64(sourceWidth) / float64(sourceHeight)
	if sourceRatio > targetRatio {
		nextWidth := clampInt(int(math.Round(float64(sourceHeight)*targetRatio)), 1, sourceWidth)
		x0 := rect.Min.X + (sourceWidth-nextWidth)/2
		return image.Rect(x0, rect.Min.Y, x0+nextWidth, rect.Max.Y)
	}
	nextHeight := clampInt(int(math.Round(float64(sourceWidth)/targetRatio)), 1, sourceHeight)
	y0 := rect.Min.Y + (sourceHeight-nextHeight)/2
	return image.Rect(rect.Min.X, y0, rect.Max.X, y0+nextHeight)
}

func insetRect(rect image.Rectangle, inset int) image.Rectangle {
	if rect.Dx() <= inset*2 || rect.Dy() <= inset*2 {
		return rect
	}
	return image.Rect(rect.Min.X+inset, rect.Min.Y+inset, rect.Max.X-inset, rect.Max.Y-inset)
}

func defaultSourceDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join("Downloads", "image")
	}
	return filepath.Join(home, "Downloads", "image")
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func exit(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

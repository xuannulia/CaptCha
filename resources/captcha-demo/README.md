# CaptCha Demo Image Resources

Small AI-generated demo images loaded through classpath resources for the open-source demo.

- `backgrounds/`: 640x360 JPEG cover-cropped backgrounds for generic image captchas.
- `concat/`: 640x360 JPEG cover-cropped backgrounds for `CONCAT`.
- `jigsaw/`: 600x360 JPEG cover-cropped backgrounds for `JIGSAW`.
- `rotate/`: 320x320 JPEG city-night rotate images.
- `grid/<category>/`: 320x320 JPEG category tiles for `GRID_IMAGE_CLICK`; cat, dog, panda, and bird each include 9 tiles cropped from AI-generated 3x3 source sheets.

Run `go run ./scripts/prepare-demo-resources.go -source <source-image-dir>` to regenerate these assets. The generator detects white grid separators and trims thin white edge strips before resizing.

The source images are AI-generated and approved by the project owner for open-source release.

# Track Risk Models

This directory contains lightweight, open-source CAPTCHA trajectory-risk model artifacts.

## track-risk-open-source-v1

- Artifact: `track-risk-open-source-v1.json`
- Report: `track-risk-open-source-v1-report.json`
- Feature version: `track-v1`
- Model type: logistic regression over scalar trajectory features
- Default high-risk threshold: `0.90`

This first open-source baseline is intentionally conservative and should be run in shadow or observe mode before enforcement. At the default `0.90` high-risk threshold, the held-out test report shows low false positives (`0.59%`) but modest recall (`48.55%`), so it is better suited to material review, shadow scoring, and route-specific risk experiments than direct blocking. The report also includes a balanced threshold (`0.47`) for offline comparison; that operating point has much higher recall but a materially higher false-positive rate.

The artifact uses only lightweight trajectory features such as point count, duration, path length, velocity variance, pauses, jitter, straightness, and anomaly flags. It does not use source labels, generator family, or collection-file identity as model inputs, and it does not include raw track samples.

The local training manifest and generated human training JSONL remain under `output/training/` and are not intended to be published with the repository.

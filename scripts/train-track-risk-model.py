#!/usr/bin/env python3
import argparse
import json
import math
import random
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


NUMERIC_FEATURES = [
    "track_score",
    "track_submit_points",
    "point_count",
    "original_point_count",
    "distance_x",
    "distance_y",
    "direct_distance",
    "path_length",
    "straightness",
    "max_velocity",
    "velocity_variance",
    "acceleration_variance",
    "jerk_variance",
    "y_jitter",
    "direction_changes",
    "pause_count",
    "overshoot_count",
    "micro_corrections",
    "end_stability",
    "track_reason_count",
]

BOOLEAN_FEATURES = [
    "too_fast",
    "too_few_points",
    "perfect_line",
    "constant_velocity",
    "synthetic_curve",
    "teleport",
    "timestamp_anomaly",
    "track_truncated",
]

CATEGORICAL_FEATURES = {}


def main():
    parser = argparse.ArgumentParser(description="Train the first offline track risk model.")
    parser.add_argument("--human", default="output/training/collector-human.jsonl")
    parser.add_argument("--bot", default="output/synthetic-bot-tracks.jsonl")
    parser.add_argument("--extra-human", action="append", default=[], help="Additional likely-human JSONL file. Can be used more than once.")
    parser.add_argument("--extra-bot", action="append", default=[], help="Additional confirmed-bot JSONL file. Can be used more than once.")
    parser.add_argument("--all-human-tracks", action="store_true", help="Use all human track records instead of only collector slider_* samples.")
    parser.add_argument("--out", default="output/models/track-risk-v1.json")
    parser.add_argument("--report", default="output/models/track-risk-v1-report.json")
    parser.add_argument("--seed", type=int, default=20260627)
    parser.add_argument("--epochs", type=int, default=120)
    parser.add_argument("--learning-rate", type=float, default=0.035)
    parser.add_argument("--l2", type=float, default=0.0008)
    args = parser.parse_args()

    random.seed(args.seed)
    human_slider_only = not args.all_human_tracks
    human = load_records(Path(args.human), label=0, source_name="collector_human", slider_only=human_slider_only)
    for extra_path in args.extra_human:
        human.extend(load_records(Path(extra_path), label=0, source_name=Path(extra_path).stem, slider_only=human_slider_only))
    bots = load_records(Path(args.bot), label=1, source_name="synthetic_bot", slider_only=False)
    for extra_path in args.extra_bot:
        bots.extend(load_records(Path(extra_path), label=1, source_name=Path(extra_path).stem, slider_only=False))
    if len(human) < 100 or len(bots) < 100:
        raise SystemExit(f"not enough records: human={len(human)} bot={len(bots)}")

    rows = human + bots
    train_rows, test_rows = stratified_split(rows, test_ratio=0.2, seed=args.seed)
    spec = build_feature_spec()
    means, scales = fit_standardizer(train_rows, spec)
    weights, bias = train_logistic(train_rows, spec, means, scales, args.epochs, args.learning_rate, args.l2, args.seed)

    train_scores = score_rows(train_rows, spec, means, scales, weights, bias)
    test_scores = score_rows(test_rows, spec, means, scales, weights, bias)
    threshold, threshold_metrics = choose_threshold(test_scores)

    artifact = {
        "schema_version": "track-risk-model-v1",
        "model_type": "logistic_regression",
        "name": "track-risk-baseline",
        "version": "v1",
        "feature_version": "track-v1",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "label": {"0": "likely_human", "1": "confirmed_bot"},
        "score": {"meaning": "bot probability", "threshold": threshold},
        "features": spec,
        "standardizer": {"mean": means, "scale": scales},
        "weights": weights,
        "bias": bias,
        "metrics": {
            "train": metrics_at_threshold(train_scores, threshold),
            "test": threshold_metrics,
            "threshold": threshold,
            "sample_counts": sample_counts(rows),
        },
        "notes": [
            "First baseline trained from collector human slider samples and synthetic bot tracks.",
            "This artifact intentionally excludes source, label, bot_family, generator_version, and reason_code features.",
        ],
    }
    report = {
        "model": {"name": artifact["name"], "version": artifact["version"], "feature_version": artifact["feature_version"]},
        "threshold": threshold,
        "train": artifact["metrics"]["train"],
        "test": artifact["metrics"]["test"],
        "sample_counts": artifact["metrics"]["sample_counts"],
        "feature_count": len(spec),
        "top_weights": top_weights(spec, weights, limit=24),
    }

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


def load_records(path, label, source_name, slider_only):
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            features = record.get("features") or {}
            if slider_only:
                task_type = str(features.get("collector_task_type") or "")
                if not task_type.startswith("slider_"):
                    continue
            rows.append({
                "label": label,
                "source": source_name,
                "challenge_type": record.get("challenge_type"),
                "features": features,
            })
    return rows


def build_feature_spec():
    spec = []
    for name in NUMERIC_FEATURES:
        spec.append({"kind": "numeric", "name": name})
    for name in BOOLEAN_FEATURES:
        spec.append({"kind": "boolean", "name": name})
    for name, values in CATEGORICAL_FEATURES.items():
        for value in values:
            spec.append({"kind": "categorical", "name": name, "value": value})
    return spec


def raw_value(row, item):
    features = row["features"]
    kind = item["kind"]
    name = item["name"]
    if kind == "numeric":
        return finite_float(features.get(name))
    if kind == "boolean":
        return 1.0 if bool(features.get(name)) else 0.0
    if kind == "categorical":
        return 1.0 if str(features.get(name) or "unknown") == item["value"] else 0.0
    return 0.0


def finite_float(value):
    if value is None or isinstance(value, bool):
        return 0.0
    try:
        out = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(out):
        return 0.0
    return out


def stratified_split(rows, test_ratio, seed):
    rng = random.Random(seed)
    by_label = {0: [], 1: []}
    for row in rows:
        by_label[row["label"]].append(row)
    train, test = [], []
    for label_rows in by_label.values():
        rng.shuffle(label_rows)
        test_count = max(1, int(round(len(label_rows) * test_ratio)))
        test.extend(label_rows[:test_count])
        train.extend(label_rows[test_count:])
    rng.shuffle(train)
    rng.shuffle(test)
    return train, test


def fit_standardizer(rows, spec):
    means = []
    scales = []
    for item in spec:
        values = [raw_value(row, item) for row in rows]
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / max(len(values) - 1, 1)
        scale = math.sqrt(variance)
        if scale < 1e-9:
            scale = 1.0
        means.append(mean)
        scales.append(scale)
    return means, scales


def vectorize(row, spec, means, scales):
    return [(raw_value(row, item) - means[i]) / scales[i] for i, item in enumerate(spec)]


def train_logistic(rows, spec, means, scales, epochs, learning_rate, l2, seed):
    rng = random.Random(seed)
    weights = [0.0 for _ in spec]
    bias = 0.0
    counts = Counter(row["label"] for row in rows)
    total = len(rows)
    class_weight = {label: total / (2.0 * count) for label, count in counts.items()}
    for epoch in range(epochs):
        rng.shuffle(rows)
        lr = learning_rate / math.sqrt(1 + epoch * 0.08)
        for row in rows:
            x = vectorize(row, spec, means, scales)
            y = row["label"]
            pred = sigmoid(dot(weights, x) + bias)
            err = (pred - y) * class_weight[y]
            for i, value in enumerate(x):
                weights[i] -= lr * (err * value + l2 * weights[i])
            bias -= lr * err
    return weights, bias


def score_rows(rows, spec, means, scales, weights, bias):
    out = []
    for row in rows:
        x = vectorize(row, spec, means, scales)
        out.append({"label": row["label"], "score": sigmoid(dot(weights, x) + bias), "source": row["source"]})
    return out


def choose_threshold(scores):
    best_threshold = 0.5
    best_metrics = None
    best_value = -1
    for index in range(5, 96):
        threshold = index / 100
        metrics = metrics_at_threshold(scores, threshold)
        value = metrics["balanced_accuracy"] + metrics["f1"] * 0.15
        if value > best_value:
            best_value = value
            best_threshold = threshold
            best_metrics = metrics
    return best_threshold, best_metrics


def metrics_at_threshold(scores, threshold):
    tp = fp = tn = fn = 0
    for item in scores:
        pred = 1 if item["score"] >= threshold else 0
        label = item["label"]
        if pred == 1 and label == 1:
            tp += 1
        elif pred == 1 and label == 0:
            fp += 1
        elif pred == 0 and label == 0:
            tn += 1
        else:
            fn += 1
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    specificity = safe_div(tn, tn + fp)
    f1 = safe_div(2 * precision * recall, precision + recall)
    return {
        "threshold": threshold,
        "accuracy": safe_div(tp + tn, tp + fp + tn + fn),
        "balanced_accuracy": (recall + specificity) / 2,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "false_positive_rate": safe_div(fp, fp + tn),
        "false_negative_rate": safe_div(fn, fn + tp),
    }


def sample_counts(rows):
    labels = Counter(row["label"] for row in rows)
    sources = Counter(row["source"] for row in rows)
    devices = Counter(str(row["features"].get("input_device_hint") or "unknown") for row in rows)
    return {
        "total": len(rows),
        "human": labels[0],
        "bot": labels[1],
        "sources": dict(sources),
        "devices": dict(devices),
    }


def top_weights(spec, weights, limit):
    pairs = []
    for item, weight in zip(spec, weights):
        name = item["name"]
        if item["kind"] == "categorical":
            name = f"{name}={item['value']}"
        pairs.append({"feature": name, "weight": weight})
    pairs.sort(key=lambda item: abs(item["weight"]), reverse=True)
    return pairs[:limit]


def sigmoid(value):
    if value >= 0:
        z = math.exp(-value)
        return 1 / (1 + z)
    z = math.exp(value)
    return z / (1 + z)


def dot(left, right):
    return sum(a * b for a, b in zip(left, right))


def safe_div(left, right):
    return left / right if right else 0.0


if __name__ == "__main__":
    main()

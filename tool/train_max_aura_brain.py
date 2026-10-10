import argparse
import csv
import hashlib
import json
import math
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import _tree

ROOT = Path(__file__).resolve().parents[1]
FEATURE_ORDER = [
    "length",
    "shannon_entropy",
    "digit_ratio",
    "vowel_ratio",
    "consonant_sequence_ratio",
    "suspicious_tld",
]
SUSPICIOUS_TLDS = {
    "cam", "click", "country", "date", "download", "fit", "gq", "loan",
    "mov", "party", "review", "rest", "stream", "support", "tk", "top",
    "wang", "work", "xyz", "zip",
}
DATASET_DIR = ROOT / "data"
REPORTS_DIR = ROOT / "tool/reports"
MODEL_OUTPUT = REPORTS_DIR / "aura_brain_model.json"
METRICS_JSON = REPORTS_DIR / "metrics.json"
METRICS_MARKDOWN = REPORTS_DIR / "metrics.md"
EXPECTED_CLASSES = {0, 1}
MIN_TEST_ROWS_PER_CLASS = 500


def normalize_domain(value):
    return value.strip().lower().rstrip(".")
SEED_DATASET = [
    ("google.com", 0), ("github.com", 0), ("whatsapp.com", 0),
    ("amazon.com", 0), ("bancodevenezuela.com", 0), ("codemagic.io", 0),
    ("flutter.dev", 0), ("wikipedia.org", 0), ("microsoft.com", 0),
    ("netflix.com", 0), ("binance.com", 0), ("youtube.com", 0),
    ("stackoverflow.com", 0), ("apple.com", 0), ("linkedin.com", 0),
    ("zoom.us", 0), ("cloudflare.com", 0), ("android.com", 0),
    ("x7z9q1wplmnb.xyz", 1), ("aqwzsxedcrfv12.top", 1),
    ("free-crypto-rewards.click", 1), ("update-system-android.live", 1),
    ("cxj9812kmzsloq.cc", 1), ("malicious-payload-server.info", 1),
    ("shw28190axmzq.xyz", 1), ("get-root-bypass.top", 1),
    ("91kazmslqo1029az.biz", 1), ("free-cleaner-android.gq", 1),
    ("p0wz9172mlxozq.tk", 1), ("get-unlocked-premium.fit", 1),
]


def calculate_shannon_entropy(domain_string):
    if not domain_string:
        return 0.0
    frequencies = {}
    for character in domain_string.lower():
        frequencies[character] = frequencies.get(character, 0) + 1
    length = len(domain_string)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in frequencies.values()
    )


def extract_maximum_features(domain):
    host = normalize_domain(domain)
    length = len(host)
    if length == 0:
        return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    letters = [character for character in host if character.isascii() and character.isalpha()]
    digits = sum(character.isascii() and character.isdigit() for character in host)
    vowels = sum(character in "aeiou" for character in letters)
    letter_count = len(letters)
    run_length = 0
    consonant_sequence_characters = 0
    for character in host:
        if character.isascii() and character.isalpha() and character not in "aeiou":
            run_length += 1
        else:
            if run_length >= 3:
                consonant_sequence_characters += run_length
            run_length = 0
    if run_length >= 3:
        consonant_sequence_characters += run_length

    tld = host.rsplit(".", 1)[-1]
    return [
        float(length),
        calculate_shannon_entropy(host),
        digits / length,
        vowels / letter_count if letter_count else 0.0,
        consonant_sequence_characters / letter_count if letter_count else 0.0,
        float(tld in SUSPICIOUS_TLDS),
    ]


def read_split(path):
    if not path.is_file():
        raise FileNotFoundError(f"Dataset split is missing: {path}")
    rows = []
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        expected_header = ["domain", "label", "source", "license", "retrieved_at"]
        if reader.fieldnames != expected_header:
            raise ValueError(f"Unexpected dataset CSV schema in {path}: {reader.fieldnames}")
        for row in reader:
            domain = row["domain"].strip().lower()
            if not domain or "." not in domain or row["label"] not in {"0", "1"}:
                raise ValueError(f"Invalid dataset row in {path}: {row}")
            rows.append((domain, int(row["label"])))
    return rows


def evaluate_metrics(labels, predictions):
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = matrix.ravel()
    specificity_denominator = true_negative + false_positive
    return {
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "false_positive_rate": (
            float(false_positive / specificity_denominator)
            if specificity_denominator
            else 0.0
        ),
        "confusion_matrix": {
            "labels": ["safe", "threat"],
            "rows_actual_columns_predicted": matrix.tolist(),
            "true_negative": int(true_negative),
            "false_positive": int(false_positive),
            "false_negative": int(false_negative),
            "true_positive": int(true_positive),
        },
    }


def evaluate_serialized_node(node, features, depth=0):
    if not isinstance(node, dict) or depth > 32:
        raise ValueError("Invalid or too-deep serialized model node")
    if node.get("type") == "leaf":
        value = node.get("value")
        if value not in (0, 1):
            raise ValueError("Serialized leaf value must be binary")
        return int(value)
    feature_index = node.get("feature_index")
    threshold = node.get("threshold")
    if (
        node.get("type") != "split"
        or not isinstance(feature_index, int)
        or feature_index < 0
        or feature_index >= len(features)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(threshold)
    ):
        raise ValueError("Invalid serialized split node")
    branch = "left" if features[feature_index] <= threshold else "right"
    return evaluate_serialized_node(node.get(branch), features, depth + 1)


def predict_serialized_model(model, domain):
    trees = model.get("trees")
    if not isinstance(trees, list) or not trees:
        raise ValueError("Serialized model has no trees")
    features = extract_maximum_features(domain)
    votes = sum(evaluate_serialized_node(tree.get("root"), features) for tree in trees)
    return votes / len(trees)


def write_metrics(metrics):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write(METRICS_JSON, json.dumps(metrics, indent=2, sort_keys=True) + "\n")
    scores = metrics["test_metrics"]
    matrix = scores["confusion_matrix"]
    markdown = "\n".join(
        [
            "# Aura Random Forest Test Metrics",
            "",
            f"- Test rows: {metrics['test_rows']}",
            f"- Test class counts: safe={metrics['test_class_counts']['safe']}, threat={metrics['test_class_counts']['threat']}",
            f"- Accuracy: {scores['accuracy']:.6f}",
            f"- Precision: {scores['precision']:.6f}",
            f"- Recall: {scores['recall']:.6f}",
            f"- F1: {scores['f1']:.6f}",
            f"- False-positive rate: {scores['false_positive_rate']:.6f}",
            "",
            "## Confusion matrix",
            "",
            "| Actual \\ Predicted | Safe | Threat |",
            "|---|---:|---:|",
            f"| Safe | {matrix['true_negative']} | {matrix['false_positive']} |",
            f"| Threat | {matrix['false_negative']} | {matrix['true_positive']} |",
            "",
            "## Training run",
            "",
            f"- Samples: {metrics['training_rows']}",
            f"- Trees: {metrics['hyperparameters']['n_estimators']}",
            f"- Maximum depth: {metrics['hyperparameters']['max_depth']}",
            f"- Training time: {metrics['training_seconds']:.3f} s",
            f"- Dataset manifest SHA-256: {metrics['dataset_manifest_sha256']}",
            f"- Validation accuracy: {metrics['validation_metrics']['accuracy']:.6f}",
            "",
        ]
    )
    atomic_write(METRICS_MARKDOWN, markdown)


def serialize_tree(estimator):
    tree = estimator.tree_

    def serialize_node(node_index):
        if tree.feature[node_index] == _tree.TREE_UNDEFINED:
            class_index = int(np.argmax(tree.value[node_index][0]))
            return {"type": "leaf", "value": int(estimator.classes_[class_index])}
        return {
            "type": "split",
            "feature_index": int(tree.feature[node_index]),
            "threshold": float(tree.threshold[node_index]),
            "left": serialize_node(tree.children_left[node_index]),
            "right": serialize_node(tree.children_right[node_index]),
        }

    return {"root": serialize_node(0)}


def atomic_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as temporary:
        temporary.write(content)
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, path)


def main():
    parser = argparse.ArgumentParser(description="Entrena el bosque local de Aura.")
    parser.add_argument(
        "--allow-seed-only",
        action="store_true",
        help="Allow the documented 30-domain seed fallback when a qualified test split is unavailable.",
    )
    args = parser.parse_args()
    try:
        train_rows = read_split(DATASET_DIR / "splits/train.csv")
        val_rows = read_split(DATASET_DIR / "splits/val.csv")
        test_rows = read_split(DATASET_DIR / "splits/test.csv")
    except FileNotFoundError as error:
        if not args.allow_seed_only:
            raise SystemExit(
                f"{error}. Pass --allow-seed-only only for the documented seed fallback."
            ) from error
        train_rows, val_rows, test_rows = [], [], []
    test_counts = {label: sum(row_label == label for _, row_label in test_rows) for label in EXPECTED_CLASSES}
    inadequate_test = any(test_counts[label] < MIN_TEST_ROWS_PER_CLASS for label in EXPECTED_CLASSES)
    if inadequate_test and not args.allow_seed_only:
        raise SystemExit(
            "Test split must contain at least 500 rows per class "
            f"(safe={test_counts[0]}, threat={test_counts[1]}). "
            "Rebuild from more licensed real data or pass --allow-seed-only for the documented seed fallback."
        )

    using_seed_fallback = inadequate_test
    if using_seed_fallback:
        samples = list(SEED_DATASET)
        training_rows = samples
        evaluation_rows = samples
        validation_rows = samples
        print("WARNING: using the documented 30-domain seed-only fallback; metrics are not a real holdout evaluation.")
    else:
        training_rows = train_rows
        evaluation_rows = test_rows
        validation_rows = val_rows

    features = np.asarray([extract_maximum_features(domain) for domain, _ in training_rows])
    labels = np.asarray([label for _, label in training_rows], dtype=np.int64)
    evaluation_domains = [domain for domain, _ in evaluation_rows]
    evaluation_labels = [label for _, label in evaluation_rows]
    validation_domains = [domain for domain, _ in validation_rows]
    validation_labels = [label for _, label in validation_rows]
    print(
        f"Training Aura forest: 500 trees, max_depth=12, "
        f"train={len(training_rows)}, val={len(val_rows)}, test={len(test_rows)}."
    )
    forest = RandomForestClassifier(
        n_estimators=500,
        max_depth=12,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced_subsample",
    )
    training_started = time.perf_counter()
    forest.fit(features, labels)
    training_seconds = time.perf_counter() - training_started

    evaluation_features = np.asarray(
        [extract_maximum_features(domain) for domain in evaluation_domains]
    )
    predictions = forest.predict(evaluation_features).astype(int).tolist()
    test_metrics = evaluate_metrics(evaluation_labels, predictions)
    validation_features = np.asarray(
        [extract_maximum_features(domain) for domain in validation_domains]
    )
    validation_predictions = forest.predict(validation_features).astype(int).tolist()
    validation_metrics = evaluate_metrics(validation_labels, validation_predictions)

    model = {
        "model_name": "Aura Lexical Threat Forest",
        "model_version": "3.0.0",
        "model_type": "random_forest",
        "training_status": "heuristic_seed" if using_seed_fallback else "heuristic_seed_with_csv",
        "training_samples": len(training_rows),
        "csv_files": [str((DATASET_DIR / "splits/train.csv").relative_to(ROOT))],
        "training_config": {
            "n_estimators": 500,
            "max_depth": 12,
            "n_jobs": -1,
            "random_state": 42,
        },
        "feature_order": FEATURE_ORDER,
        "classes": {"0": "safe", "1": "threat"},
        "trees": [serialize_tree(estimator) for estimator in forest.estimators_],
    }
    if len(model["trees"]) != 500:
        raise RuntimeError("El bosque serializado no contiene exactamente 500 árboles.")

    json_bytes = (json.dumps(model, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    atomic_write(MODEL_OUTPUT, json_bytes.decode("utf-8"))
    manifest_path = DATASET_DIR / "dataset_manifest.json"
    if not manifest_path.is_file() and not using_seed_fallback:
        raise FileNotFoundError(f"Dataset manifest is missing: {manifest_path}")
    manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest() if manifest_path.is_file() else "seed-only-no-manifest"
    metrics = {
        "metrics_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "evaluation_mode": "seed-only-not-a-holdout" if using_seed_fallback else "stratified-test-split",
        "training_rows": len(training_rows),
        "validation_rows": len(validation_rows),
        "test_rows": len(evaluation_rows),
        "test_class_counts": {
            "safe": sum(label == 0 for label in evaluation_labels),
            "threat": sum(label == 1 for label in evaluation_labels),
        },
        "hyperparameters": {
            "n_estimators": 500,
            "max_depth": 12,
            "n_jobs": -1,
            "random_state": 42,
            "class_weight": "balanced_subsample",
            "feature_order": FEATURE_ORDER,
        },
        "training_seconds": training_seconds,
        "dataset_manifest_sha256": manifest_digest,
        "metrics_model_file": str(MODEL_OUTPUT.relative_to(ROOT)),
        "validation_metrics": validation_metrics,
        "test_metrics": test_metrics,
    }
    write_metrics(metrics)
    print(f"MODEL_CANDIDATE={MODEL_OUTPUT.relative_to(ROOT)}")
    print(f"METRICS_JSON={METRICS_JSON.relative_to(ROOT)}")
    print(f"METRICS_MARKDOWN={METRICS_MARKDOWN.relative_to(ROOT)}")
    print("Model candidate and metrics generated; tracked assets/model files were not modified.")


if __name__ == "__main__":
    main()

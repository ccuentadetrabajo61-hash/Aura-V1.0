#!/usr/bin/env python3
"""Benchmark warm and cold JSON-forest inference on the held-out test hosts."""

from __future__ import annotations

import csv
import json
import math
import os
import platform
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from train_max_aura_brain import FEATURE_ORDER, extract_maximum_features

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "tool/reports/aura_brain_model.json"
TEST_PATH = ROOT / "data/splits/test.csv"
REPORT_PATH = ROOT / "tool/reports/benchmark.json"
EXPECTED_TREE_COUNT = 500
WARM_INFERENCES = 10_000
COLD_INFERENCES = 500


def load_model() -> dict:
    with MODEL_PATH.open("r", encoding="utf-8") as stream:
        model = json.load(stream)
    if model.get("model_type") != "random_forest":
        raise ValueError("Model candidate is not a random_forest")
    if model.get("feature_order") != FEATURE_ORDER:
        raise ValueError("Model feature_order does not match the Dart inference contract")
    if not isinstance(model.get("trees"), list) or len(model["trees"]) != EXPECTED_TREE_COUNT:
        raise ValueError("Model candidate must contain exactly 500 trees")
    return model


def evaluate_node(node: dict, features: list[float], depth: int = 0) -> int:
    if not isinstance(node, dict) or depth > 32:
        raise ValueError("Malformed or too-deep model node")
    if node.get("type") == "leaf":
        value = node.get("value")
        if value not in (0, 1):
            raise ValueError("Tree leaf class is not binary")
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
        raise ValueError("Malformed model split node")
    branch = "left" if features[feature_index] <= threshold else "right"
    return evaluate_node(node.get(branch), features, depth + 1)


def predict_threat(model: dict, domain: str) -> bool:
    features = extract_maximum_features(domain)
    votes = sum(evaluate_node(tree.get("root"), features) for tree in model["trees"])
    return votes / len(model["trees"]) >= 0.5


def percentiles_ms(durations_seconds: list[float]) -> dict[str, float]:
    ordered = sorted(durations_seconds)

    def percentile(value: float) -> float:
        position = (len(ordered) - 1) * value
        lower = math.floor(position)
        upper = math.ceil(position)
        if lower == upper:
            return ordered[lower] * 1000.0
        return (
            ordered[lower] * (upper - position) + ordered[upper] * (position - lower)
        ) * 1000.0

    elapsed = sum(ordered)
    return {
        "p50_ms": percentile(0.50),
        "p95_ms": percentile(0.95),
        "p99_ms": percentile(0.99),
        "domains_per_second": len(ordered) / elapsed if elapsed else 0.0,
        "total_seconds": elapsed,
        "inference_count": len(ordered),
    }


def test_domains() -> list[str]:
    if not TEST_PATH.is_file():
        raise FileNotFoundError(f"Test split is missing: {TEST_PATH}")
    with TEST_PATH.open("r", encoding="utf-8", newline="") as stream:
        domains = [row["domain"] for row in csv.DictReader(stream)]
    if not domains:
        raise ValueError("Test split contains no domains")
    return domains


def hardware_report() -> dict[str, object]:
    memory_bytes = None
    if hasattr(os, "sysconf"):
        try:
            memory_bytes = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        except (ValueError, OSError):
            pass
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor() or "not-reported-by-runner",
        "logical_cpu_count": os.cpu_count(),
        "memory_bytes": memory_bytes,
        "note": "Runner measurements are not representative of mobile-device performance; device numbers may differ.",
    }


def main() -> int:
    domains = test_domains()
    model = load_model()
    for index in range(100):
        predict_threat(model, domains[index % len(domains)])

    warm_durations = []
    warm_started = time.perf_counter()
    for index in range(WARM_INFERENCES):
        started = time.perf_counter()
        predict_threat(model, domains[index % len(domains)])
        warm_durations.append(time.perf_counter() - started)
    warm_elapsed = time.perf_counter() - warm_started
    warm = percentiles_ms(warm_durations)
    warm["wall_seconds"] = warm_elapsed
    warm["wall_domains_per_second"] = WARM_INFERENCES / warm_elapsed if warm_elapsed else 0.0

    cold_durations = []
    for index in range(COLD_INFERENCES):
        started = time.perf_counter()
        cold_model = load_model()
        predict_threat(cold_model, domains[index % len(domains)])
        cold_durations.append(time.perf_counter() - started)
        del cold_model
    cold = percentiles_ms(cold_durations)

    report = {
        "benchmark_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model_file": str(MODEL_PATH.relative_to(ROOT)),
        "test_split": str(TEST_PATH.relative_to(ROOT)),
        "warm": warm,
        "cold_including_model_reload": cold,
        "hardware": hardware_report(),
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"WARM_INFERENCES={WARM_INFERENCES}")
    print(
        "WARM_MS="
        f"p50:{warm['p50_ms']:.6f},p95:{warm['p95_ms']:.6f},p99:{warm['p99_ms']:.6f} "
        f"THROUGHPUT={warm['domains_per_second']:.2f} domains/s"
    )
    print(f"COLD_INFERENCES={COLD_INFERENCES} (each includes JSON model reload)")
    print(
        "COLD_MS="
        f"p50:{cold['p50_ms']:.6f},p95:{cold['p95_ms']:.6f},p99:{cold['p99_ms']:.6f} "
        f"THROUGHPUT={cold['domains_per_second']:.2f} domains/s"
    )
    print(f"RUNNER={report['hardware']['platform']} {report['hardware']['machine']} CPUs={report['hardware']['logical_cpu_count']}")
    print("Mobile-device performance may differ; see tool/reports/benchmark.json.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

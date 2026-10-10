"""Golden contract tests for Aura's serialized random-forest model."""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tool"))
sys.path.insert(0, str(ROOT / "tool/dataset"))

from dataset.build_dataset import is_allowlisted, normalize_domain  # noqa: E402
from train_max_aura_brain import FEATURE_ORDER, predict_serialized_model  # noqa: E402

MODEL_PATH = ROOT / "tool/reports/aura_brain_model.json"
ASSET_MODEL_PATH = ROOT / "assets/model/aura_brain_model.json"
ASSET_DIGEST_PATH = ROOT / "assets/model/aura_brain_model.json.sha256"


@pytest.fixture(scope="module")
def model():
    if not MODEL_PATH.is_file():
        pytest.fail("Run python tool/train_max_aura_brain.py before the golden tests")
    return json.loads(MODEL_PATH.read_text(encoding="utf-8"))


def is_threat(model_data: dict, domain: str) -> bool:
    if is_allowlisted(domain):
        return False
    return predict_serialized_model(model_data, domain) >= 0.5


def test_known_dga_is_classified_as_threat(model):
    assert is_threat(model, "x7z9q1wplmnb.xyz")


def test_known_legitimate_domain_is_classified_as_safe(model):
    assert not is_threat(model, "netflix.com")


def test_static_allowlist_domain_is_safe(model):
    assert is_allowlisted("google.com")
    assert is_allowlisted("api.google.com")
    assert not is_allowlisted("google.com.attacker.invalid")
    assert normalize_domain("google.com") == "google.com"
    assert not is_threat(model, "google.com")


def test_malformed_host_is_rejected_without_exception():
    assert normalize_domain("http://[::1") is None
    assert normalize_domain("127.0.0.1") is None
    assert normalize_domain("-invalid.example") is None


def test_model_schema_and_original_asset_digest(model):
    original = json.loads(ASSET_MODEL_PATH.read_text(encoding="utf-8"))
    assert set(model) == set(original)
    assert model["feature_order"] == FEATURE_ORDER
    assert len(model["trees"]) == 500
    assert model["classes"] == {"0": "safe", "1": "threat"}

    def validate_node(node: object, depth: int = 0) -> None:
        assert isinstance(node, dict)
        assert depth <= 32
        if node.get("type") == "leaf":
            assert node.get("value") in {0, 1}
            return
        assert node.get("type") == "split"
        assert node.get("feature_index") in range(6)
        assert isinstance(node.get("threshold"), (int, float))
        validate_node(node.get("left"), depth + 1)
        validate_node(node.get("right"), depth + 1)

    for tree in model["trees"]:
        assert set(tree) == {"root"}
        validate_node(tree["root"])

    expected_digest = ASSET_DIGEST_PATH.read_text(encoding="ascii").strip().split()[0]
    actual_digest = hashlib.sha256(ASSET_MODEL_PATH.read_bytes()).hexdigest()
    assert actual_digest == expected_digest


def test_offline_fixture_is_within_the_row_limit():
    fixture = ROOT / "tool/dataset/fixtures/sample.csv"
    with fixture.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert 0 < len(rows) <= 200
    assert set(rows[0]) == {"domain", "label", "source", "license", "retrieved_at"}
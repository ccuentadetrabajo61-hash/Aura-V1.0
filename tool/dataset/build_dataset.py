#!/usr/bin/env python3
"""Download licensed domain sources and build deterministic Aura CSV splits."""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from sklearn.model_selection import train_test_split

from sources import DEFAULT_SAFE_SOURCE, SOURCES, SourceDefinition, iter_source_domains

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
OUTPUT_CSV = DATA_DIR / "aura_dataset.csv"
SPLIT_DIR = DATA_DIR / "splits"
MANIFEST_PATH = DATA_DIR / "dataset_manifest.json"
SPLIT_SEED = 42
NORMALIZATION_VERSION = "aura-domain-idna2003-v1"
CSV_FIELDS = ["domain", "label", "source", "license", "retrieved_at"]
STATIC_ALLOWLIST = {
    "google.com", "apple.com", "microsoft.com", "amazonaws.com",
    "cloudflare.com", "akamaiedge.net", "android.com", "github.com",
    "whatsapp.net", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "apple-dns.net", "icloud.com", "microsoftonline.com", "windows.net",
    "amazon.com", "awsstatic.com", "akamaized.net", "fastly.net",
}
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class DatasetBuildError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_domain(value: str) -> str | None:
    candidate = value.strip()
    if not candidate or any(ord(char) < 0x20 for char in candidate):
        return None
    try:
        if "://" in candidate:
            parsed = urlsplit(candidate)
            if parsed.scheme.lower() not in {"http", "https"} or parsed.username or parsed.password:
                return None
            candidate = parsed.hostname or ""
        else:
            parsed = urlsplit("//" + candidate.lstrip("/"))
            if parsed.username or parsed.password:
                return None
            candidate = parsed.hostname or ""
    except ValueError:
        return None

    candidate = candidate.rstrip(".").lower()
    if not candidate:
        return None
    try:
        candidate = candidate.encode("idna").decode("ascii").lower()
        ipaddress.ip_address(candidate)
        return None
    except ValueError:
        pass
    except UnicodeError:
        return None

    if len(candidate) > 253 or "." not in candidate:
        return None
    labels = candidate.split(".")
    if any(len(label) > 63 or not HOST_LABEL.fullmatch(label) for label in labels):
        return None
    return candidate


def is_allowlisted(domain: str) -> bool:
    return any(domain == suffix or domain.endswith("." + suffix) for suffix in STATIC_ALLOWLIST)


def parse_acceptance(raw_value: str) -> tuple[str, str]:
    source_name, separator, license_id = raw_value.partition(":")
    if not separator or not source_name or not license_id:
        raise argparse.ArgumentTypeError(
            "license acceptance must be formatted as <source>:<SPDX-id>"
        )
    return source_name, license_id


def download_source(source: SourceDefinition, raw_dir: Path) -> tuple[Path, str, int, str]:
    raw_dir.mkdir(parents=True, exist_ok=True)
    suffix = {
        "threat-urls-zip": ".zip",
        "threat-domain-lines": ".txt",
        "safe-domains-gzip-csv": ".csv.gz",
        "safe-domains-zip-csv": ".zip",
    }[source.kind]
    destination = raw_dir / f"{source.name}{suffix}"
    digest = hashlib.sha256()
    byte_count = 0
    retrieved_at = utc_now()
    request = urllib.request.Request(
        source.url,
        headers={"User-Agent": "Aura-Dataset-Pipeline/1.0 (+https://github.com/)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response, tempfile.NamedTemporaryFile(
            mode="wb", dir=raw_dir, prefix=f".{source.name}.", suffix=".download", delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
            while chunk := response.read(1024 * 1024):
                temporary.write(chunk)
                digest.update(chunk)
                byte_count += len(chunk)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, destination)
    except (OSError, urllib.error.URLError) as error:
        try:
            temporary_path.unlink(missing_ok=True)
        except (UnboundLocalError, OSError):
            pass
        raise DatasetBuildError(f"Download failed for {source.name} ({source.url}): {error}") from error
    return destination, digest.hexdigest(), byte_count, retrieved_at


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def class_counts(rows: list[dict[str, object]]) -> dict[str, int]:
    labels = Counter(int(row["label"]) for row in rows)
    return {"safe": labels.get(0, 0), "threat": labels.get(1, 0)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sources",
        required=True,
        help="Comma-separated threat sources: urlhaus, phishing_database, or explicitly accepted tranco.",
    )
    parser.add_argument(
        "--accept-license",
        action="append",
        type=parse_acceptance,
        default=[],
        metavar="SOURCE:SPDX-ID",
        help="Explicitly accept a disabled source license; may be repeated.",
    )
    parser.add_argument(
        "--max-safe-domains",
        type=int,
        default=100_000,
        help="Maximum ranked safe domains retained from the mandatory Majestic baseline.",
    )
    args = parser.parse_args()
    if args.max_safe_domains < 1:
        parser.error("--max-safe-domains must be positive")

    requested_sources = [name.strip() for name in args.sources.split(",") if name.strip()]
    if not requested_sources or len(set(requested_sources)) != len(requested_sources):
        parser.error("--sources must contain one or more unique source names")
    acceptance_map = dict(args.accept_license)
    unknown = sorted(set(requested_sources) - set(SOURCES))
    if unknown:
        parser.error(f"Unknown sources: {', '.join(unknown)}")
    for name in requested_sources:
        source = SOURCES[name]
        if source.disabled and acceptance_map.get(name) != source.license_id:
            parser.error(
                f"Source '{name}' is disabled; enable it only with "
                f"--accept-license={name}:{source.license_id}"
            )

    selected_sources = [SOURCES[name] for name in requested_sources]
    if DEFAULT_SAFE_SOURCE not in requested_sources:
        selected_sources.append(SOURCES[DEFAULT_SAFE_SOURCE])

    source_metadata: list[dict[str, object]] = []
    observations: dict[str, list[dict[str, object]]] = defaultdict(list)
    invalid_rows = Counter()
    source_domain_counts = Counter()
    safe_kept = 0
    allowlist_threat_domains: set[str] = set()
    acceptance_records: list[dict[str, str]] = []

    for source in selected_sources:
        raw_path, raw_sha256, raw_bytes, retrieved_at = download_source(source, RAW_DIR)
        if source.disabled:
            acceptance_records.append(
                {
                    "source": source.name,
                    "license_id": acceptance_map[source.name],
                    "accepted_at": utc_now(),
                    "raw_sha256": raw_sha256,
                }
            )
        label = 0 if source.name == DEFAULT_SAFE_SOURCE or source.name == "tranco" else 1
        valid_for_source: set[str] = set()
        raw_rows = 0
        for raw_domain in iter_source_domains(source, raw_path):
            raw_rows += 1
            domain = normalize_domain(raw_domain)
            if domain is None:
                invalid_rows[source.name] += 1
                continue
            if label == 1 and is_allowlisted(domain):
                allowlist_threat_domains.add(domain)
                continue
            if label == 0 and source.name in {DEFAULT_SAFE_SOURCE, "tranco"}:
                if domain not in valid_for_source and safe_kept >= args.max_safe_domains:
                    continue
            valid_for_source.add(domain)
            observations[domain].append(
                {
                    "domain": domain,
                    "label": label,
                    "source": source.name,
                    "license": source.license_id,
                    "retrieved_at": retrieved_at,
                }
            )
            if label == 0 and source.name in {DEFAULT_SAFE_SOURCE, "tranco"}:
                safe_kept += 1

        source_domain_counts[source.name] = len(valid_for_source)
        metadata: dict[str, object] = {
            "source": source.name,
            "url": source.url,
            "license": source.license_id,
            "license_url": source.license_url,
            "retrieved_at": retrieved_at,
            "raw_file": str(raw_path.relative_to(ROOT)),
            "raw_sha256": raw_sha256,
            "raw_bytes": raw_bytes,
            "raw_rows": raw_rows,
            "valid_unique_domains_selected": len(valid_for_source),
            "invalid_or_ip_rows": invalid_rows[source.name],
        }
        if source.commercial_access_note:
            metadata["commercial_access_note"] = source.commercial_access_note
        if source.disabled:
            metadata["license_acceptance"] = acceptance_records[-1]
        source_metadata.append(metadata)
        print(
            f"SOURCE={source.name} raw_rows={raw_rows} "
            f"valid_unique_domains_selected={len(valid_for_source)} "
            f"raw_sha256={raw_sha256}"
        )

    conflict_domains = {
        domain for domain, records in observations.items()
        if len({int(record["label"]) for record in records}) > 1
    }
    duplicates_removed = sum(max(0, len(records) - 1) for records in observations.values())
    final_rows: list[dict[str, object]] = []
    for domain in sorted(observations):
        if domain in conflict_domains:
            continue
        records = observations[domain]
        chosen = min(records, key=lambda row: (str(row["source"]), int(row["label"])))
        final_rows.append(chosen)

    if len({int(row["label"]) for row in final_rows}) < 2:
        raise DatasetBuildError(
            "The selected real sources produced fewer than two classes after validation and exclusions."
        )

    labels = [int(row["label"]) for row in final_rows]
    train_rows, remainder = train_test_split(
        final_rows,
        train_size=0.70,
        random_state=SPLIT_SEED,
        stratify=labels,
    )
    remainder_labels = [int(row["label"]) for row in remainder]
    val_rows, test_rows = train_test_split(
        remainder,
        test_size=0.50,
        random_state=SPLIT_SEED,
        stratify=remainder_labels,
    )
    train_rows = sorted(train_rows, key=lambda row: str(row["domain"]))
    val_rows = sorted(val_rows, key=lambda row: str(row["domain"]))
    test_rows = sorted(test_rows, key=lambda row: str(row["domain"]))

    write_csv(OUTPUT_CSV, final_rows)
    write_csv(SPLIT_DIR / "train.csv", train_rows)
    write_csv(SPLIT_DIR / "val.csv", val_rows)
    write_csv(SPLIT_DIR / "test.csv", test_rows)
    split_counts = {
        "train": {"rows": len(train_rows), "by_class": class_counts(train_rows)},
        "val": {"rows": len(val_rows), "by_class": class_counts(val_rows)},
        "test": {"rows": len(test_rows), "by_class": class_counts(test_rows)},
    }
    manifest = {
        "manifest_version": 1,
        "created_at": utc_now(),
        "schema": CSV_FIELDS,
        "label_map": {"0": "safe", "1": "threat"},
        "normalization_version": NORMALIZATION_VERSION,
        "idn_policy": "Unicode labels are encoded to lowercase IDNA2003 A-labels (xn-- punycode).",
        "split": {"ratios": {"train": 0.70, "val": 0.15, "test": 0.15}, "seed": SPLIT_SEED},
        "selection": {
            "max_safe_domains": args.max_safe_domains,
            "safe_source": DEFAULT_SAFE_SOURCE,
            "allowlist_suffixes": sorted(STATIC_ALLOWLIST),
            "allowlist_threat_domains_excluded": len(allowlist_threat_domains),
            "conflicting_domains_excluded": len(conflict_domains),
            "duplicate_observations_removed": duplicates_removed,
            "invalid_or_ip_rows_by_source": dict(sorted(invalid_rows.items())),
        },
        "provenance": source_metadata,
        "license_acceptances": acceptance_records,
        "counts": {
            "rows": len(final_rows),
            "by_class": class_counts(final_rows),
            "source_selected_unique_domains": dict(sorted(source_domain_counts.items())),
            "splits": split_counts,
        },
        "outputs": {
            "dataset": str(OUTPUT_CSV.relative_to(ROOT)),
            "train": str((SPLIT_DIR / "train.csv").relative_to(ROOT)),
            "val": str((SPLIT_DIR / "val.csv").relative_to(ROOT)),
            "test": str((SPLIT_DIR / "test.csv").relative_to(ROOT)),
        },
    }
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"THREAT_DOMAINS={class_counts(final_rows)['threat']}")
    print(f"SAFE_DOMAINS={class_counts(final_rows)['safe']}")
    print(f"ALLOWLIST_THREAT_DOMAINS_EXCLUDED={len(allowlist_threat_domains)}")
    print(f"CONFLICT_DOMAINS_EXCLUDED={len(conflict_domains)}")
    print(f"DATASET_MANIFEST={MANIFEST_PATH.relative_to(ROOT)}")
    print(f"DATASET_MANIFEST_HEADER={json.dumps({key: manifest[key] for key in ('manifest_version','created_at','schema','normalization_version','split')}, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DatasetBuildError, OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"Dataset build failed: {error}", file=sys.stderr)
        raise SystemExit(1)

"""Licensed source definitions and parsers for Aura's domain dataset."""

from __future__ import annotations

import csv
import gzip
import io
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class SourceDefinition:
    name: str
    url: str
    license_id: str
    license_url: str
    kind: str
    disabled: bool = False
    commercial_access_note: str = ""


SOURCES = {
    "urlhaus": SourceDefinition(
        name="urlhaus",
        url="https://urlhaus.abuse.ch/downloads/csv/",
        license_id="LicenseRef-abuse.ch-Platform-Terms",
        license_url="https://abuse.ch/terms-of-use/",
        kind="threat-urls-zip",
        disabled=True,
        commercial_access_note=(
            "abuse.ch terms state that commercial access may require a paid "
            "subscription; confirm entitlement with abuse.ch/Spamhaus."
        ),
    ),
    "phishing_database": SourceDefinition(
        name="phishing_database",
        url=(
            "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/"
            "master/phishing-domains-ACTIVE.txt"
        ),
        license_id="MIT",
        license_url=(
            "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/"
            "master/LICENSE"
        ),
        kind="threat-domain-lines",
    ),
    "majestic": SourceDefinition(
        name="majestic",
        url="https://downloads.majestic.com/majestic_million.csv.gz",
        license_id="CC-BY-3.0",
        license_url="https://creativecommons.org/licenses/by/3.0/",
        kind="safe-domains-gzip-csv",
    ),
    "tranco": SourceDefinition(
        name="tranco",
        url="https://tranco-list.eu/download/daily/top-1m.csv.zip",
        license_id="LicenseRef-Tranco-Mixed-Provider-Data",
        license_url="https://tranco-list.eu/",
        kind="safe-domains-zip-csv",
        disabled=True,
    ),
}

DEFAULT_SAFE_SOURCE = "majestic"


def iter_source_domains(source: SourceDefinition, raw_path: Path) -> Iterator[str]:
    if source.kind == "threat-domain-lines":
        with raw_path.open("r", encoding="utf-8-sig", errors="replace") as stream:
            for line in stream:
                value = line.strip()
                if value and not value.startswith("#"):
                    yield value
        return

    if source.kind == "threat-urls-zip":
        with zipfile.ZipFile(raw_path) as archive:
            try:
                member = archive.open("csv.txt")
            except KeyError as error:
                raise ValueError("URLhaus archive does not contain csv.txt") from error
            with member, io.TextIOWrapper(
                member, encoding="utf-8-sig", errors="replace", newline=""
            ) as stream:
                rows = (line for line in stream if not line.startswith("#") and line.strip())
                for row in csv.reader(rows):
                    if len(row) > 2:
                        yield row[2]
        return

    if source.kind == "safe-domains-gzip-csv":
        with gzip.open(raw_path, "rt", encoding="utf-8-sig", errors="replace", newline="") as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames or "Domain" not in reader.fieldnames:
                raise ValueError("Majestic CSV does not contain a Domain column")
            for row in reader:
                yield row.get("Domain", "")
        return

    if source.kind == "safe-domains-zip-csv":
        with zipfile.ZipFile(raw_path) as archive:
            csv_members = [name for name in archive.namelist() if name.lower().endswith(".csv")]
            if len(csv_members) != 1:
                raise ValueError("Tranco archive must contain exactly one CSV file")
            with archive.open(csv_members[0]) as member, io.TextIOWrapper(
                member, encoding="utf-8-sig", errors="replace", newline=""
            ) as stream:
                for row in csv.reader(stream):
                    if len(row) >= 2:
                        yield row[1]
        return

    raise ValueError(f"No parser is registered for source kind {source.kind!r}")

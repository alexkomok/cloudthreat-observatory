#!/usr/bin/env python3
"""Publish a limited list of globally routable repeat source profiles."""

from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path


DATABASE = Path(os.environ.get("GCI_ENRICHMENT_DB", "/var/lib/gci-enrichment/attacks.sqlite"))
OUTPUT = Path(os.environ.get("GCI_THREAT_INTEL_PATH", "/var/www/cloudthreat/threat-intel.json"))
MAX_PROFILES = 20


def is_public_address(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def main() -> None:
    now = datetime.now(timezone.utc)
    with sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True, timeout=20) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """SELECT source_ip, first_seen, last_seen,
                      login_attempt_count AS attempt_count,
                      country_code, country_name, asn, asn_org, cloud_provider
               FROM attacker_profiles
               WHERE login_attempt_count > 1
               ORDER BY login_attempt_count DESC, last_seen DESC
               LIMIT 200"""
        )
        profiles = []
        for row in rows:
            if not is_public_address(row["source_ip"]):
                continue
            profiles.append({
                "source_ip": row["source_ip"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "attempt_count": row["attempt_count"],
                "country_code": row["country_code"],
                "country_name": row["country_name"],
                "asn": row["asn"],
                "asn_org": row["asn_org"],
                "cloud_provider": row["cloud_provider"],
            })
            if len(profiles) >= MAX_PROFILES:
                break

    payload = {
        "generated_at_utc": now.isoformat(timespec="seconds"),
        "ranking_basis": "login_attempt_count",
        "repeat_offenders": profiles,
    }
    OUTPUT.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    encoded = (json.dumps(payload, ensure_ascii=True, indent=2) + "\n").encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=".threat-intel-", dir=OUTPUT.parent)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_name, OUTPUT)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    print(f"Updated public Threat Intel feed with {len(profiles)} repeat source profiles")


if __name__ == "__main__":
    main()

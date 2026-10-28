#!/usr/bin/env python3
"""Write a private daily summary of enriched Cowrie events."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from datetime import datetime, time, timedelta, timezone
from pathlib import Path


DATABASE = Path(os.environ.get("GCI_ENRICHMENT_DB", "/var/lib/gci-enrichment/attacks.sqlite"))
OUTPUT_DIR = Path(os.environ.get("GCI_METRICS_DIR", "/var/lib/gci-enrichment/metrics"))
TOP_N = int(os.environ.get("GCI_METRICS_TOP_N", "20"))


def top_rows(connection: sqlite3.Connection, column: str, start: str, end: str):
    # The column is selected only from the fixed allowlist below.
    if column == "country":
        sql = """SELECT country_code AS code, country_name AS name, COUNT(*) AS attempts
                 FROM attacks WHERE event_time >= ? AND event_time < ?
                   AND country_code IS NOT NULL AND country_code != ''
                 GROUP BY country_code, country_name ORDER BY attempts DESC, name LIMIT ?"""
    elif column == "password":
        sql = """SELECT password AS value, COUNT(*) AS attempts FROM attacks
                 WHERE event_time >= ? AND event_time < ? AND password IS NOT NULL AND password != ''
                 GROUP BY password ORDER BY attempts DESC, value LIMIT ?"""
    elif column == "username":
        sql = """SELECT username AS value, COUNT(*) AS attempts FROM attacks
                 WHERE event_time >= ? AND event_time < ? AND username IS NOT NULL AND username != ''
                 GROUP BY username ORDER BY attempts DESC, value LIMIT ?"""
    else:
        sql = """SELECT destination_port AS port, COUNT(*) AS attempts FROM attacks
                 WHERE event_time >= ? AND event_time < ? AND destination_port IS NOT NULL
                 GROUP BY destination_port ORDER BY attempts DESC, port LIMIT ?"""
    return [dict(row) for row in connection.execute(sql, (start, end, TOP_N))]


def main() -> None:
    now = datetime.now(timezone.utc)
    day = now.date()
    start = datetime.combine(day, time.min, tzinfo=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    end = (datetime.combine(day, time.min, tzinfo=timezone.utc) + timedelta(days=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
    with sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True, timeout=60) as connection:
        connection.row_factory = sqlite3.Row
        total, unique_sources = connection.execute(
            "SELECT COUNT(*), COUNT(DISTINCT source_ip) FROM attacks WHERE event_time >= ? AND event_time < ?",
            (start, end),
        ).fetchone()
        metrics = {
            "date_utc": day.isoformat(),
            "generated_at_utc": now.isoformat(timespec="seconds"),
            "window": {"start": start, "end_exclusive": end},
            "attack_events": total,
            "unique_source_ips": unique_sources,
            "top_countries": top_rows(connection, "country", start, end),
            "top_passwords": top_rows(connection, "password", start, end),
            "top_usernames": top_rows(connection, "username", start, end),
            "top_ports": top_rows(connection, "port", start, end),
        }

    OUTPUT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(OUTPUT_DIR, 0o700)
    payload = (json.dumps(metrics, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    for target in (OUTPUT_DIR / f"{day.isoformat()}.json", OUTPUT_DIR / "latest.json"):
        fd, temp_name = tempfile.mkstemp(prefix=".metrics-", dir=OUTPUT_DIR)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as temp_file:
                temp_file.write(payload)
                temp_file.flush()
                os.fsync(temp_file.fileno())
            os.replace(temp_name, target)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
    print(f"Wrote {day.isoformat()} metrics: {total} events, {unique_sources} unique sources")


if __name__ == "__main__":
    main()

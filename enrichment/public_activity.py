#!/usr/bin/env python3
"""Publish a small, redacted window of recent Cowrie login activity."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


DATABASE = Path(os.environ.get("GCI_ENRICHMENT_DB", "/var/lib/gci-enrichment/attacks.sqlite"))
OUTPUT = Path(os.environ.get("GCI_PUBLIC_ACTIVITY_PATH", "/var/www/cloudthreat/activity.json"))


def main() -> None:
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(hours=24)).isoformat(timespec="seconds").replace("+00:00", "Z")
    with sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True, timeout=10) as db:
        rows = db.execute(
            """SELECT event_time, eventid FROM attacks
               WHERE event_time >= ? AND eventid IN ('cowrie.login.failed', 'cowrie.login.success')
               ORDER BY event_time DESC LIMIT 10""",
            (cutoff,),
        ).fetchall()

    # Deliberately allowlist only time and a fixed event category. Never serialize
    # source addresses, usernames, passwords, sessions, or event payloads.
    events = [
        {"time_utc": event_time, "kind": "success" if eventid == "cowrie.login.success" else "failed"}
        for event_time, eventid in rows
    ]
    payload = {
        "generated_at_utc": now.isoformat(timespec="seconds"),
        "events": events,
    }
    OUTPUT.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    encoded = (json.dumps(payload, ensure_ascii=True, indent=2) + "\n").encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=".activity-", dir=OUTPUT.parent)
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
    print(f"Updated public activity feed: {len(events)} redacted login events")


if __name__ == "__main__":
    main()

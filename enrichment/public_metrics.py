#!/usr/bin/env python3
"""Export only daily aggregate metrics for the public observatory page."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from datetime import datetime, time, timedelta, timezone
from pathlib import Path


DATABASE = Path(os.environ.get("GCI_ENRICHMENT_DB", "/var/lib/gci-enrichment/attacks.sqlite"))
OUTPUT = Path(os.environ.get("GCI_PUBLIC_METRICS_PATH", "/var/www/cloudthreat/metrics.json"))


def choose_session(db: sqlite3.Connection, start: str, end: str):
    candidates = list(db.execute(
        """SELECT a.session_id, MIN(a.event_time) AS first_seen, MAX(a.event_time) AS last_seen,
                  COUNT(*) AS event_count,
                  SUM(CASE WHEN a.eventid = 'cowrie.login.failed' THEN 1 ELSE 0 END) AS login_failures,
                  SUM(CASE WHEN a.eventid = 'cowrie.login.success' THEN 1 ELSE 0 END) AS login_successes,
                  SUM(CASE WHEN a.eventid = 'cowrie.command.input' THEN 1 ELSE 0 END) AS commands,
                  SUM(CASE WHEN a.eventid = 'cowrie.session.closed' THEN 1 ELSE 0 END) AS disconnects,
                  SUM(CASE WHEN EXISTS (
                      SELECT 1 FROM command_tools AS ct WHERE ct.event_hash = a.event_hash
                  ) THEN 1 ELSE 0 END) AS tool_events
           FROM attacks AS a
           WHERE a.session_id IS NOT NULL AND a.event_time >= ? AND a.event_time < ?
           GROUP BY a.session_id
           HAVING SUM(CASE WHEN a.eventid = 'cowrie.session.connect' THEN 1 ELSE 0 END) > 0
              AND SUM(CASE WHEN a.eventid IN ('cowrie.login.failed','cowrie.login.success','cowrie.command.input')
                           THEN 1 ELSE 0 END) > 0""",
        (start, end),
    ))
    if not candidates:
        return None
    def score(row):
        return (
            6 * row["tool_events"]
            + 2 * row["commands"]
            + 4 * row["login_successes"]
            + min(4, row["login_failures"])
        )
    return max(candidates, key=lambda row: (score(row), row["tool_events"], row["commands"], row["last_seen"]))


def replay_session(db: sqlite3.Connection, summary):
    if summary is None:
        return None
    rows = list(db.execute(
        """SELECT rowid, event_hash, event_time, eventid
           FROM attacks WHERE session_id = ? ORDER BY event_time, rowid""",
        (summary["session_id"],),
    ))
    steps = []
    first_time = datetime.fromisoformat(summary["first_seen"].replace("Z", "+00:00"))
    all_tools = set()
    for row in rows:
        eventid = row["eventid"] or ""
        label = None
        kind = "activity"
        if eventid == "cowrie.session.connect":
            label, kind = "Bot connected to the honeypot", "connect"
        elif eventid == "cowrie.login.failed":
            label, kind = "Login attempt rejected · credential withheld", "login"
        elif eventid == "cowrie.login.success":
            label, kind = "Honeypot login succeeded · credential withheld", "login"
        elif eventid == "cowrie.command.input":
            tools = [item[0] for item in db.execute(
                "SELECT tool FROM command_tools WHERE event_hash = ? ORDER BY tool",
                (row["event_hash"],),
            )]
            if tools:
                all_tools.update(tools)
                label, kind = f"Used {', '.join(tools)} · command and URL withheld", "download"
            else:
                label, kind = "Ran a shell command · content withheld", "command"
        elif eventid in {"cowrie.session.closed", "cowrie.session.disconnect"}:
            label, kind = "Bot disconnected", "disconnect"
        if label is None:
            continue
        event_time = datetime.fromisoformat(row["event_time"].replace("Z", "+00:00"))
        steps.append({
            "offset_seconds": max(0, int((event_time - first_time).total_seconds())),
            "kind": kind,
            "label": label,
        })
    if len(steps) > 50:
        removed = len(steps) - 49
        steps = steps[:24] + [{"offset_seconds": steps[24]["offset_seconds"], "kind": "omitted", "label": f"{removed} intermediate actions omitted"}] + steps[-25:]
    duration = max(0, int((datetime.fromisoformat(summary["last_seen"].replace("Z", "+00:00")) - first_time).total_seconds()))
    failed = summary["login_failures"] or 0
    successes = summary["login_successes"] or 0
    commands = summary["commands"] or 0
    tool_events = summary["tool_events"] or 0
    unusual = {
        "title": "Download tooling observed" if all_tools else ("Honeypot login succeeded" if successes else "Unusually active login session"),
        "score": 6 * tool_events + 2 * commands + 4 * successes + min(4, failed),
        "event_count": summary["event_count"],
        "observed_at_utc": summary["last_seen"],
        "login_failures": failed,
        "login_successes": successes,
        "commands": commands,
        "download_tools": sorted(all_tools),
    }
    if tool_events:
        unusual["reason"] = f"{tool_events} command event(s) invoked common download tooling."
    elif successes:
        unusual["reason"] = "A honeypot login succeeded, which is unusual among observed sessions."
    else:
        unusual["reason"] = f"This session had {failed} rejected login attempt(s) and {commands} shell command(s)."
    return {
        "duration_seconds": duration,
        "event_count": summary["event_count"],
        "steps": steps,
        "weirdest_attack": unusual,
    }


def main() -> None:
    now = datetime.now(timezone.utc)
    day = now.date()
    start = datetime.combine(day, time.min, tzinfo=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    end = (datetime.combine(day, time.min, tzinfo=timezone.utc) + timedelta(days=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
    history_start_day = day - timedelta(days=89)
    history_start = datetime.combine(history_start_day, time.min, tzinfo=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    with sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True, timeout=60) as db:
        db.row_factory = sqlite3.Row
        events, sources = db.execute(
            "SELECT COUNT(*), COUNT(DISTINCT source_ip) FROM attacks WHERE event_time >= ? AND event_time < ?",
            (start, end),
        ).fetchone()
        countries = [dict(row) for row in db.execute(
            """SELECT country_code AS code, country_name AS name, COUNT(*) AS attempts
               FROM attacks WHERE event_time >= ? AND event_time < ?
                 AND country_code IS NOT NULL AND country_code != ''
               GROUP BY country_code, country_name ORDER BY attempts DESC, name LIMIT 8""",
            (start, end),
        )]
        passwords = [dict(row) for row in db.execute(
            """SELECT password AS value, COUNT(*) AS attempts FROM attacks
               WHERE event_time >= ? AND event_time < ? AND password IS NOT NULL AND password != ''
               GROUP BY password ORDER BY attempts DESC, value LIMIT 8""",
            (start, end),
        )]
        usernames = [dict(row) for row in db.execute(
            """SELECT username AS value, COUNT(*) AS attempts FROM attacks
               WHERE event_time >= ? AND event_time < ? AND username IS NOT NULL AND username != ''
               GROUP BY username ORDER BY attempts DESC, value LIMIT 8""",
            (start, end),
        )]
        ports = [dict(row) for row in db.execute(
            """SELECT destination_port AS port, COUNT(*) AS attempts FROM attacks
               WHERE event_time >= ? AND event_time < ? AND destination_port IS NOT NULL
               GROUP BY destination_port ORDER BY attempts DESC, port LIMIT 8""",
            (start, end),
        )]
        tools = [dict(row) for row in db.execute(
            """SELECT ct.tool AS tool, COUNT(*) AS commands
               FROM command_tools AS ct JOIN attacks AS a USING (event_hash)
               WHERE a.event_time >= ? AND a.event_time < ?
               GROUP BY ct.tool ORDER BY commands DESC, ct.tool""",
            (start, end),
        )]
        history = {
            row["day"]: {"date": row["day"], "attacks": row["attacks"], "unique_sources": row["unique_sources"]}
            for row in db.execute(
                """SELECT substr(event_time, 1, 10) AS day, COUNT(*) AS attacks,
                          COUNT(DISTINCT source_ip) AS unique_sources
                   FROM attacks WHERE event_time >= ? AND event_time < ?
                   GROUP BY substr(event_time, 1, 10)""",
                (history_start, end),
            )
        }
        weirdest_summary = choose_session(db, start, end)
        playback_summary = weirdest_summary or choose_session(
            db,
            datetime.combine(day - timedelta(days=6), time.min, tzinfo=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            end,
        )
        playback = replay_session(db, playback_summary)
    timeline_90d = []
    for offset in range(90):
        date = (history_start_day + timedelta(days=offset)).isoformat()
        timeline_90d.append(history.get(date, {"date": date, "attacks": 0, "unique_sources": 0}))

    public_data = {
        "date_utc": day.isoformat(),
        "generated_at_utc": now.isoformat(timespec="seconds"),
        "attack_events": events,
        "unique_source_ips": sources,
        "top_countries": countries,
        "top_passwords": passwords,
        "top_usernames": usernames,
        "top_ports": ports,
        "command_tools": tools,
        "timeline_90d": timeline_90d,
        "attack_playback": playback,
        "weirdest_attack": playback["weirdest_attack"] if playback and weirdest_summary else None,
    }
    OUTPUT.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    payload = (json.dumps(public_data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=".metrics-", dir=OUTPUT.parent)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as temp_file:
            temp_file.write(payload)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temp_name, OUTPUT)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    print(f"Updated public metrics for {day.isoformat()}: {events} events, {sources} unique sources")


if __name__ == "__main__":
    main()

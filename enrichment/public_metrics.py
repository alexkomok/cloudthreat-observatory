#!/usr/bin/env python3
"""Export daily aggregates and a redacted top-ten Cowrie session archive."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from datetime import datetime, time, timedelta, timezone
from pathlib import Path


DATABASE = Path(os.environ.get("GCI_ENRICHMENT_DB", "/var/lib/gci-enrichment/attacks.sqlite"))
OUTPUT = Path(os.environ.get("GCI_PUBLIC_METRICS_PATH", "/var/www/cloudthreat/metrics.json"))


def choose_sessions(db: sqlite3.Connection, start: str, end: str, limit: int = 10):
    candidates = list(db.execute(
        """SELECT a.session_id, MIN(a.event_time) AS first_seen, MAX(a.event_time) AS last_seen,
                  COUNT(*) AS event_count,
                  SUM(CASE WHEN a.eventid = 'cowrie.login.failed' THEN 1 ELSE 0 END) AS login_failures,
                  SUM(CASE WHEN a.eventid = 'cowrie.login.success' THEN 1 ELSE 0 END) AS login_successes,
                  SUM(CASE WHEN a.eventid = 'cowrie.command.input' THEN 1 ELSE 0 END) AS commands,
                  SUM(CASE WHEN a.eventid = 'cowrie.session.closed' THEN 1 ELSE 0 END) AS disconnects,
                  SUM(CASE WHEN a.eventid = 'cowrie.session.file_download' THEN 1 ELSE 0 END) AS downloads,
                  SUM(CASE WHEN EXISTS (
                      SELECT 1 FROM command_tools AS ct WHERE ct.event_hash = a.event_hash
                  ) THEN 1 ELSE 0 END) AS tool_events,
                  SUM(CASE WHEN a.eventid = 'cowrie.command.chpasswd'
                       OR ltrim(lower(COALESCE(a.command, ''))) LIKE 'sudo %'
                       OR ltrim(lower(COALESCE(a.command, ''))) LIKE 'su %'
                       OR ltrim(lower(COALESCE(a.command, ''))) LIKE 'doas %'
                       OR ltrim(lower(COALESCE(a.command, ''))) LIKE 'useradd %'
                       OR ltrim(lower(COALESCE(a.command, ''))) LIKE 'usermod %'
                       THEN 1 ELSE 0 END) AS privilege_events
           FROM attacks AS a
           WHERE a.session_id IS NOT NULL AND a.event_time >= ? AND a.event_time < ?
           GROUP BY a.session_id
           HAVING SUM(CASE WHEN a.eventid = 'cowrie.session.connect' THEN 1 ELSE 0 END) > 0""",
        (start, end),
    ))
    if not candidates:
        return []

    def score(row):
        return min(99, 20 * (row["downloads"] or 0)
                   + 6 * (row["tool_events"] or 0)
                   + 8 * (row["privilege_events"] or 0)
                   + 4 * (row["login_successes"] or 0)
                   + 2 * min(10, row["login_failures"] or 0)
                   + min(24, row["commands"] or 0))

    def category(row):
        if row["downloads"]:
            return "malware_download"
        if row["tool_events"]:
            return "download_attempt"
        if row["privilege_events"]:
            return "privilege_escalation"
        if (row["login_failures"] or 0) >= 5:
            return "password_guessing"
        if row["commands"]:
            return "reconnaissance"
        if row["login_successes"]:
            return "successful_login"
        if row["login_failures"]:
            return "password_guessing"
        return "reconnaissance"

    profiles = []
    for row in candidates:
        profile = dict(row)
        profile["score"] = score(row)
        profile["category"] = category(row)
        profile["duration_seconds"] = max(0, int((datetime.fromisoformat(row["last_seen"].replace("Z", "+00:00")) - datetime.fromisoformat(row["first_seen"].replace("Z", "+00:00"))).total_seconds()))
        profiles.append(profile)
    profiles.sort(key=lambda row: (
        row["score"], row["downloads"] or 0, row["tool_events"] or 0,
        row["privilege_events"] or 0, row["login_failures"] or 0, row["last_seen"]
    ), reverse=True)
    if len(profiles) <= limit:
        return profiles

    # Keep the highest-scoring story first, then add one strong example of each
    # other observed category before filling the rest by score.
    selected = [profiles[0]]
    selected_ids = {profiles[0]["session_id"]}
    selected_categories = {profiles[0]["category"]}
    for profile in profiles[1:]:
        if profile["category"] not in selected_categories:
            selected.append(profile)
            selected_ids.add(profile["session_id"])
            selected_categories.add(profile["category"])
            if len(selected) >= limit:
                return selected
    for profile in profiles:
        if profile["session_id"] not in selected_ids:
            selected.append(profile)
            if len(selected) >= limit:
                break
    return selected


def replay_session(db: sqlite3.Connection, summary):
    if summary is None:
        return None
    rows = list(db.execute(
        """SELECT rowid, event_hash, event_time, eventid, command
           FROM attacks WHERE session_id = ? AND event_time >= ? AND event_time <= ?
           ORDER BY event_time, rowid""",
        (summary["session_id"], summary["first_seen"], summary["last_seen"]),
    ))
    first_time = datetime.fromisoformat(summary["first_seen"].replace("Z", "+00:00"))
    raw_steps = []
    all_tools = set()
    for row in rows:
        eventid = row["eventid"] or ""
        label = None
        kind = "activity"
        if eventid == "cowrie.session.connect":
            label, kind = "Bot connected to the honeypot", "connect"
        elif eventid == "cowrie.login.failed":
            label, kind = "Login attempt rejected · credentials withheld", "login-failed"
        elif eventid == "cowrie.login.success":
            label, kind = "Honeypot accepted a login · credentials withheld", "login-success"
        elif eventid == "cowrie.command.input":
            command = (row["command"] or "").lstrip().lower()
            if any(command.startswith(prefix) for prefix in ("sudo ", "su ", "doas ", "useradd ", "usermod ")):
                label, kind = "Privilege-change activity · command withheld", "privilege"
            else:
                tools = [item[0] for item in db.execute(
                    "SELECT tool FROM command_tools WHERE event_hash = ? ORDER BY tool",
                    (row["event_hash"],),
                )]
                if tools:
                    all_tools.update(tools)
                    label, kind = f"Download tool used ({', '.join(tools)}) · command withheld", "download"
                else:
                    label, kind = "Shell command · content withheld", "command"
        elif eventid == "cowrie.command.chpasswd":
            label, kind = "Password-change activity · details withheld", "privilege"
        elif eventid == "cowrie.command.failed":
            label, kind = "Command rejected · content withheld", "command-failed"
        elif eventid == "cowrie.session.file_download":
            label, kind = "File download observed · URL withheld", "download"
        elif eventid in {"cowrie.session.closed", "cowrie.session.disconnect"}:
            label, kind = "Bot disconnected", "disconnect"
        if label is None:
            continue
        event_time = datetime.fromisoformat(row["event_time"].replace("Z", "+00:00"))
        raw_steps.append({
            "offset_seconds": max(0, int((event_time - first_time).total_seconds())),
            "kind": kind,
            "label": label,
        })

    steps = []
    index = 0
    while index < len(raw_steps):
        step = raw_steps[index]
        group_kind = "command-batch" if step["kind"] == "command" else ("login-batch" if step["kind"] == "login-failed" else None)
        if group_kind:
            end_index = index + 1
            while end_index < len(raw_steps) and raw_steps[end_index]["kind"] == step["kind"]:
                end_index += 1
            group = raw_steps[index:end_index]
            if len(group) > 1:
                label = f"Executed {len(group)} shell commands" if group_kind == "command-batch" else f"Rejected {len(group)} login attempts · credentials withheld"
                children = group[:12]
                if len(group) > len(children):
                    children.append({"offset_seconds": group[len(children)]["offset_seconds"], "kind": "omitted", "label": f"{len(group) - 12} additional events omitted"})
                steps.append({"offset_seconds": step["offset_seconds"], "kind": group_kind, "label": label, "children": children})
                index = end_index
                continue
        steps.append(step)
        index += 1
    if len(steps) > 80:
        removed = len(steps) - 79
        steps = steps[:39] + [{"offset_seconds": steps[39]["offset_seconds"], "kind": "omitted", "label": f"{removed} intermediate events omitted"}] + steps[-39:]

    duration = max(0, int((datetime.fromisoformat(summary["last_seen"].replace("Z", "+00:00")) - first_time).total_seconds()))
    failed = summary["login_failures"] or 0
    successes = summary["login_successes"] or 0
    commands = summary["commands"] or 0
    tool_events = summary["tool_events"] or 0
    downloads = summary["downloads"] or 0
    category = summary["category"]
    category_titles = {
        "malware_download": "File download",
        "download_attempt": "Download attempt",
        "privilege_escalation": "Privilege escalation",
        "password_guessing": "Password guessing",
        "successful_login": "Successful login",
        "reconnaissance": "Reconnaissance",
    }
    title = {
        "malware_download": "File download observed",
        "download_attempt": "Download tooling used",
        "privilege_escalation": "Privilege-change activity",
        "password_guessing": f"{failed} rejected login attempts",
        "successful_login": "Successful honeypot login",
        "reconnaissance": "Interactive shell activity",
    }[category]
    actions = []
    if successes:
        actions.append(f"{successes} successful login(s)")
    elif failed:
        actions.append(f"{failed} rejected login attempt(s)")
    if commands:
        actions.append(f"{commands} command(s)")
    if downloads:
        actions.append(f"{downloads} file download event(s)")
    elif tool_events:
        actions.append(f"{tool_events} download-tool command(s)")
    summary_text = " · ".join(actions) if actions else "Connection activity recorded"
    score = summary["score"]
    details = {
        "title": title,
        "category": category,
        "category_label": category_titles[category],
        "summary": summary_text,
        "score": score,
        "first_seen_utc": summary["first_seen"],
        "last_seen_utc": summary["last_seen"],
        "observed_at_utc": summary["first_seen"],
        "duration_seconds": duration,
        "event_count": summary["event_count"],
        "login_failures": failed,
        "login_successes": successes,
        "login_attempts": failed + successes,
        "commands": commands,
        "downloads": downloads,
        "download_tool_events": tool_events,
        "download_tools": sorted(all_tools),
        "steps": steps,
    }
    details["weirdest_attack"] = {
        "title": title,
        "category_label": category_titles[category],
        "score": score,
        "reason": summary_text,
        "event_count": summary["event_count"],
        "observed_at_utc": summary["first_seen"],
        "login_failures": failed,
        "login_successes": successes,
        "commands": commands,
        "download_tools": sorted(all_tools),
    }
    return details


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
        login_attempts = db.execute(
            """SELECT COUNT(*) FROM attacks WHERE event_time >= ? AND event_time < ?
               AND eventid IN ('cowrie.login.failed', 'cowrie.login.success')""",
            (start, end),
        ).fetchone()[0]
        sessions_today, successful_logins_today, file_downloads_today, unique_attackers_today = db.execute(
            """SELECT
                   COUNT(DISTINCT CASE WHEN eventid = 'cowrie.session.connect' THEN session_id END),
                   SUM(CASE WHEN eventid = 'cowrie.login.success' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN eventid = 'cowrie.session.file_download' THEN 1 ELSE 0 END),
                   COUNT(DISTINCT CASE WHEN eventid = 'cowrie.session.connect' THEN source_ip END)
               FROM attacks WHERE event_time >= ? AND event_time < ?""",
            (start, end),
        ).fetchone()
        session_stats = {
            "sessions_today": sessions_today or 0,
            "successful_logins_today": successful_logins_today or 0,
            "file_downloads_today": file_downloads_today or 0,
            "unique_attackers_today": unique_attackers_today or 0,
        }
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
        attack_archive = [replay_session(db, summary) for summary in choose_sessions(db, start, end)]
        playback = attack_archive[0] if attack_archive else None
    timeline_90d = []
    for offset in range(90):
        date = (history_start_day + timedelta(days=offset)).isoformat()
        timeline_90d.append(history.get(date, {"date": date, "attacks": 0, "unique_sources": 0}))

    public_data = {
        "date_utc": day.isoformat(),
        "generated_at_utc": now.isoformat(timespec="seconds"),
        "attack_events": events,
        "login_attempts": login_attempts,
        "unique_source_ips": sources,
        "session_stats": session_stats,
        "attack_archive": attack_archive,
        "top_countries": countries,
        "top_passwords": passwords,
        "top_usernames": usernames,
        "top_ports": ports,
        "command_tools": tools,
        "timeline_90d": timeline_90d,
        "attack_playback": playback,
        "weirdest_attack": playback["weirdest_attack"] if playback else None,
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

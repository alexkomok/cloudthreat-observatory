#!/usr/bin/env python3
"""Publish an aggregate, static monthly Cowrie threat report."""

from __future__ import annotations

import argparse
import html
import json
import os
import sqlite3
import tempfile
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path


DATABASE = Path(os.environ.get("GCI_ENRICHMENT_DB", "/var/lib/gci-enrichment/attacks.sqlite"))
REPORTS_DIR = Path(os.environ.get("GCI_REPORTS_DIR", "/var/www/cloudthreat/reports"))


def month_bounds(month_text: str | None) -> tuple[date, date]:
    now = datetime.now(timezone.utc).date()
    if month_text:
        first = date.fromisoformat(f"{month_text}-01")
    else:
        current_month = date(now.year, now.month, 1)
        first = current_month - timedelta(days=1)
        first = date(first.year, first.month, 1)
    next_month = date(first.year + (first.month == 12), first.month % 12 + 1, 1)
    return first, next_month


def utc_bound(value: date) -> str:
    return datetime.combine(value, time.min, tzinfo=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def atomic_write(path: Path, content: str) -> None:
    data = content.encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=".report-", dir=path.parent)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def table_rows(rows, label_key: str, value_key: str = "attempts") -> str:
    if not rows:
        return '<tr><td colspan="2" class="empty">No events recorded</td></tr>'
    return "\n".join(
        f"<tr><td>{html.escape(str(row[label_key] or 'Unknown'))}</td><td>{int(row[value_key] or 0):,}</td></tr>"
        for row in rows
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--month", help="UTC month to report in YYYY-MM form; defaults to the previous full month")
    args = parser.parse_args()
    first, next_month = month_bounds(args.month)
    start, end = utc_bound(first), utc_bound(next_month)
    period_end = (next_month - timedelta(days=1)).isoformat()
    label = first.strftime("%B %Y")

    with sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True, timeout=60) as db:
        db.row_factory = sqlite3.Row
        events, sources, sessions, failed, succeeded, commands = db.execute(
            """SELECT COUNT(*), COUNT(DISTINCT source_ip), COUNT(DISTINCT session_id),
                      SUM(CASE WHEN eventid='cowrie.login.failed' THEN 1 ELSE 0 END),
                      SUM(CASE WHEN eventid='cowrie.login.success' THEN 1 ELSE 0 END),
                      SUM(CASE WHEN eventid='cowrie.command.input' THEN 1 ELSE 0 END)
               FROM attacks WHERE event_time >= ? AND event_time < ?""",
            (start, end),
        ).fetchone()
        countries = list(db.execute(
            """SELECT country_name AS label, COUNT(*) AS attempts
               FROM attacks WHERE event_time >= ? AND event_time < ? AND country_name IS NOT NULL
               GROUP BY country_code, country_name ORDER BY attempts DESC, label LIMIT 10""",
            (start, end),
        ))
        ports = list(db.execute(
            """SELECT destination_port AS label, COUNT(*) AS attempts FROM attacks
               WHERE event_time >= ? AND event_time < ? AND destination_port IS NOT NULL
               GROUP BY destination_port ORDER BY attempts DESC, label LIMIT 10""",
            (start, end),
        ))
        tool_rows = list(db.execute(
            """SELECT ct.tool AS label, COUNT(*) AS attempts FROM command_tools AS ct
               JOIN attacks AS a USING (event_hash) WHERE a.event_time >= ? AND a.event_time < ?
               GROUP BY ct.tool ORDER BY attempts DESC, label""",
            (start, end),
        ))
        daily = list(db.execute(
            """SELECT substr(event_time,1,10) AS day, COUNT(*) AS attacks
               FROM attacks WHERE event_time >= ? AND event_time < ?
               GROUP BY substr(event_time,1,10) ORDER BY attacks DESC, day LIMIT 5""",
            (start, end),
        ))

    counts = {
        "events": events or 0,
        "source_addresses": sources or 0,
        "sessions": sessions or 0,
        "login_failures": failed or 0,
        "login_successes": succeeded or 0,
        "commands": commands or 0,
    }
    country_html = table_rows(countries, "label")
    port_html = table_rows(ports, "label")
    tool_html = table_rows(tool_rows, "label", "attempts")
    peak_html = table_rows(daily, "day", "attacks")
    report = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#080d12"><title>{html.escape(label)} Threat Summary · CloudThreat Observatory</title>
<style>
:root{{--bg:#080d12;--panel:#0e151c;--line:#202c35;--text:#ecf3f3;--muted:#93a1a7;--mint:#80e0bd;--mono:ui-monospace,Consolas,monospace}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,sans-serif}}main{{max-width:1020px;margin:auto;padding:32px 22px 60px}}a{{color:var(--mint)}}.top{{display:flex;justify-content:space-between;gap:20px;align-items:center;border-bottom:1px solid var(--line);padding-bottom:16px}}.mark{{font:12px var(--mono);letter-spacing:1px;color:var(--mint)}}.period{{font:11px var(--mono);color:var(--muted)}}h1{{font-size:clamp(30px,5vw,48px);line-height:1.12;margin:36px 0 8px}}.lede{{color:var(--muted);margin:0 0 28px}}.grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:22px 0 34px}}.card,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:17px}}.card span{{display:block;color:var(--muted);font:10px var(--mono);letter-spacing:.8px;text-transform:uppercase}}.card strong{{display:block;font-size:28px;margin-top:7px}}.panels{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}}h2{{font-size:18px;margin:0 0 12px}}table{{border-collapse:collapse;width:100%;font-size:13px}}td{{border-top:1px solid #1c2930;padding:8px 4px}}td:last-child{{text-align:right;font-family:var(--mono);color:#bdd0c9}}.empty{{color:var(--muted)}}.note{{margin:28px 0;color:var(--muted);font-size:12px}}footer{{border-top:1px solid var(--line);margin-top:30px;padding-top:18px;color:var(--muted);font-size:12px}}@media(max-width:650px){{.grid{{grid-template-columns:repeat(2,minmax(0,1fr))}}.panels{{grid-template-columns:1fr}}}}
</style></head><body><main>
<div class="top"><a href="/" class="mark">CLOUDTHREAT OBSERVATORY</a><span class="period">UTC · {first.isoformat()} — {period_end}</span></div>
<h1>{html.escape(label)} Threat Summary</h1>
<p class="lede">Monthly aggregate of unsolicited traffic recorded by the GCI Cowrie honeypot.</p>
<section class="grid" aria-label="Monthly totals">
<div class="card"><span>Attack events</span><strong>{counts['events']:,}</strong></div>
<div class="card"><span>Unique source addresses</span><strong>{counts['source_addresses']:,}</strong></div>
<div class="card"><span>Observed sessions</span><strong>{counts['sessions']:,}</strong></div>
<div class="card"><span>Rejected logins</span><strong>{counts['login_failures']:,}</strong></div>
<div class="card"><span>Successful honeypot logins</span><strong>{counts['login_successes']:,}</strong></div>
<div class="card"><span>Shell commands</span><strong>{counts['commands']:,}</strong></div>
</section>
<section class="panels">
<article class="panel"><h2>Top source countries</h2><table>{country_html}</table></article>
<article class="panel"><h2>Top destination ports</h2><table>{port_html}</table></article>
<article class="panel"><h2>Command-line download tools</h2><table>{tool_html}</table></article>
<article class="panel"><h2>Busiest days</h2><table>{peak_html}</table></article>
</section>
<p class="note">Counts are derived from Cowrie honeypot events. Source addresses, usernames, passwords, session identifiers, and raw commands are omitted. Country attribution is approximate and uses DB-IP Lite data.</p>
<footer><a href="https://db-ip.com" rel="noopener noreferrer">IP Geolocation by DB-IP</a> · <a href="/reports/">All monthly reports</a> · <a href="/">Observatory home</a></footer>
</main></body></html>"""

    REPORTS_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    os.chmod(REPORTS_DIR, 0o755)
    report_path = REPORTS_DIR / f"{first:%Y-%m}.html"
    atomic_write(report_path, report)

    files = sorted((p for p in REPORTS_DIR.glob("[0-9][0-9][0-9][0-9]-[0-9][0-9].html")), reverse=True)
    items = "\n".join(
        f'<li><a href="{p.name}">{html.escape(date.fromisoformat(p.stem + "-01").strftime("%B %Y"))} Threat Summary</a></li>'
        for p in files
    ) or '<li class="empty">No completed-month report has been published yet.</li>'
    index = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Monthly Reports · CloudThreat Observatory</title><style>body{{margin:0;background:#080d12;color:#ecf3f3;font:16px/1.6 system-ui,sans-serif}}main{{max-width:800px;margin:40px auto;padding:0 22px}}a{{color:#80e0bd}}h1{{font-size:34px}}li{{padding:9px 0}}.empty{{color:#93a1a7}}</style></head><body><main><a href="/">← Observatory</a><h1>Monthly Threat Reports</h1><ul>{items}</ul></main></body></html>"""
    atomic_write(REPORTS_DIR / "index.html", index)
    print(f"Published {first:%Y-%m} monthly report with {counts['events']} events")


if __name__ == "__main__":
    main()

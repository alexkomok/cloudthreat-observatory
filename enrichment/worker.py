#!/usr/bin/env python3
"""Enrich Cowrie JSON events locally and maintain a private SQLite store."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import shlex
import sqlite3
import time
from datetime import datetime, timezone
from functools import lru_cache
from glob import glob
from pathlib import Path, PurePosixPath
from typing import Any

import maxminddb


LOG_GLOB = os.environ.get(
    "COWRIE_LOG_GLOB", "/opt/cowrie/var/log/cowrie/cowrie.json*"
)
DB_PATH = Path(os.environ.get("ENRICHMENT_DB", "/var/lib/gci-enrichment/attacks.sqlite"))
COUNTRY_DB = Path(
    os.environ.get("GEOIP_COUNTRY_DB", "/var/lib/gci-enrichment/geoip/current/country.mmdb")
)
ASN_DB = Path(
    os.environ.get("GEOIP_ASN_DB", "/var/lib/gci-enrichment/geoip/current/asn.mmdb")
)
POLL_SECONDS = max(1, int(os.environ.get("POLL_SECONDS", "2")))
BATCH_SIZE = 500
LOGIN_EVENTS = {"cowrie.login.failed", "cowrie.login.success"}
STOP = False

LOG = logging.getLogger("gci-enrichment")

PROVIDER_BY_ASN = {
    16509: "Amazon Web Services",
    14618: "Amazon Web Services",
    8987: "Amazon Web Services",
    396982: "Google Cloud",
    15169: "Google",
    8075: "Microsoft Azure",
    8068: "Microsoft Azure",
    8069: "Microsoft Azure",
    31898: "Oracle Cloud",
    14061: "DigitalOcean",
    16276: "OVHcloud",
    24940: "Hetzner",
    20473: "Vultr",
    63949: "Akamai Connected Cloud",
    45102: "Alibaba Cloud",
    37963: "Alibaba Cloud",
    132203: "Tencent Cloud",
    45090: "Tencent Cloud",
    36351: "IBM Cloud",
    13335: "Cloudflare",
}
PROVIDER_BY_ORG = (
    ("amazon", "Amazon Web Services"),
    ("google cloud", "Google Cloud"),
    ("google llc", "Google Cloud"),
    ("microsoft azure", "Microsoft Azure"),
    ("microsoft corporation", "Microsoft Azure"),
    ("oracle cloud", "Oracle Cloud"),
    ("digitalocean", "DigitalOcean"),
    ("ovh", "OVHcloud"),
    ("hetzner", "Hetzner"),
    ("vultr", "Vultr"),
    ("linode", "Akamai Connected Cloud"),
    ("akamai", "Akamai Connected Cloud"),
    ("alibaba", "Alibaba Cloud"),
    ("tencent", "Tencent Cloud"),
    ("ibm cloud", "IBM Cloud"),
    ("cloudflare", "Cloudflare"),
    ("huawei", "Huawei Cloud"),
)
COMMAND_TOOL_NAMES = {"wget", "curl", "busybox"}
COMMAND_SPLIT_RE = re.compile(r"&&|\|\||[;&|]")


def stop_handler(_signum: int, _frame: Any) -> None:
    global STOP
    STOP = True


def open_database() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("PRAGMA busy_timeout=30000")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS attacks (
            event_hash TEXT PRIMARY KEY,
            event_time TEXT NOT NULL,
            eventid TEXT,
            source_ip TEXT,
            source_port INTEGER,
            destination_ip TEXT,
            destination_port INTEGER,
            protocol TEXT,
            username TEXT,
            password TEXT,
            command TEXT,
            session_id TEXT,
            country_code TEXT,
            country_name TEXT,
            asn INTEGER,
            asn_org TEXT,
            cloud_provider TEXT,
            provider_confidence TEXT,
            source_file TEXT NOT NULL,
            ingested_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS attacks_event_time_idx ON attacks(event_time);
        CREATE INDEX IF NOT EXISTS attacks_source_ip_idx ON attacks(source_ip);
        CREATE INDEX IF NOT EXISTS attacks_eventid_idx ON attacks(eventid);
        CREATE INDEX IF NOT EXISTS attacks_source_password_idx ON attacks(source_ip, password);

        CREATE TABLE IF NOT EXISTS attackers (
            source_ip TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            event_count INTEGER NOT NULL DEFAULT 0,
            login_attempts INTEGER NOT NULL DEFAULT 0,
            country_code TEXT,
            country_name TEXT,
            asn INTEGER,
            asn_org TEXT,
            cloud_provider TEXT,
            provider_confidence TEXT
        );

        CREATE TABLE IF NOT EXISTS countries (
            country_code TEXT PRIMARY KEY,
            country_name TEXT,
            attacker_count INTEGER NOT NULL,
            event_count INTEGER NOT NULL,
            login_attempts INTEGER NOT NULL,
            last_seen TEXT
        );

        CREATE TABLE IF NOT EXISTS asn (
            asn INTEGER PRIMARY KEY,
            asn_org TEXT,
            cloud_provider TEXT,
            provider_confidence TEXT,
            attacker_count INTEGER NOT NULL,
            event_count INTEGER NOT NULL,
            login_attempts INTEGER NOT NULL,
            last_seen TEXT
        );

        CREATE TABLE IF NOT EXISTS source_state (
            source_key TEXT PRIMARY KEY,
            source_path TEXT NOT NULL,
            byte_offset INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS command_tools (
            event_hash TEXT NOT NULL,
            tool TEXT NOT NULL CHECK (tool IN ('wget', 'curl', 'busybox')),
            PRIMARY KEY (event_hash, tool),
            FOREIGN KEY (event_hash) REFERENCES attacks(event_hash) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS command_tools_tool_idx ON command_tools(tool);

        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );

        CREATE VIEW IF NOT EXISTS malware_commands AS
        SELECT a.event_hash, a.event_time, a.source_ip, ct.tool, a.command
        FROM command_tools AS ct JOIN attacks AS a USING (event_hash);

        CREATE VIEW IF NOT EXISTS attacker_profiles AS
        SELECT
            p.source_ip,
            p.first_seen,
            p.last_seen,
            p.event_count AS attempt_count,
            p.login_attempts AS login_attempt_count,
            p.country_code,
            p.country_name,
            p.asn,
            p.asn_org,
            p.cloud_provider,
            (SELECT a.password FROM attacks AS a
             WHERE a.source_ip = p.source_ip AND a.password IS NOT NULL AND a.password != ''
             GROUP BY a.password ORDER BY COUNT(*) DESC, a.password COLLATE NOCASE ASC LIMIT 1)
                AS favorite_password
        FROM attackers AS p;
        """
    )
    connection.commit()
    migrate_command_tools(connection)
    os.chmod(DB_PATH, 0o600)
    return connection


def first_value(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return value
    return None


def as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def cloud_provider(asn: int | None, organization: str | None) -> tuple[str | None, str | None]:
    if asn in PROVIDER_BY_ASN:
        return PROVIDER_BY_ASN[asn], "asn"
    normalized = (organization or "").casefold()
    for pattern, provider in PROVIDER_BY_ORG:
        if pattern in normalized:
            return provider, "organization"
    return None, None


def extract_command_tools(command: str | None) -> set[str]:
    """Find wget/curl/busybox used as command names, not incidental arguments."""
    if not command:
        return set()
    found: set[str] = set()
    for segment in COMMAND_SPLIT_RE.split(command):
        try:
            tokens = shlex.split(segment, comments=False, posix=True)
        except ValueError:
            continue
        for index, token in enumerate(tokens):
            name = PurePosixPath(token).name.casefold()
            if name not in COMMAND_TOOL_NAMES:
                continue
            previous = tokens[index - 1].casefold() if index else ""
            if index == 0 or previous in {"sudo", "command", "exec", "env", "busybox", "timeout", "nohup"}:
                found.add(name)
    return found


def migrate_command_tools(connection: sqlite3.Connection) -> None:
    """Backfill command-tool classification once, then classify new events inline."""
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=3").fetchone():
        return
    rows = connection.execute(
        "SELECT event_hash, command FROM attacks WHERE command IS NOT NULL AND command != ''"
    )
    with connection:
        for row in rows:
            for tool in extract_command_tools(row["command"]):
                connection.execute(
                    "INSERT OR IGNORE INTO command_tools (event_hash, tool) VALUES (?, ?)",
                    (row["event_hash"], tool),
                )
        connection.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (3, ?)",
            (event_time(None),),
        )


@lru_cache(maxsize=8192)
def lookup_ip(ip_text: str) -> tuple[str | None, str | None, int | None, str | None, str | None, str | None]:
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return (None, None, None, None, None, None)
    if not ip.is_global:
        return (None, None, None, None, None, None)

    country_result = COUNTRY_READER.get(ip_text) or {}
    country_record = country_result.get("country") or {}
    country_code = country_record.get("iso_code")
    country_name = (country_record.get("names") or {}).get("en")

    asn_record = ASN_READER.get(ip_text) or {}
    asn_number = as_int(
        first_value(asn_record, "autonomous_system_number", "as_number", "number", "asn")
    )
    asn_org = first_value(
        asn_record,
        "autonomous_system_organization",
        "as_organization",
        "organization_name",
        "organization",
        "name",
    )
    provider, confidence = cloud_provider(asn_number, asn_org)
    return (country_code, country_name, asn_number, asn_org, provider, confidence)


def event_time(value: Any) -> str:
    if isinstance(value, str) and value:
        return value
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def update_attacker(
    connection: sqlite3.Connection,
    source_ip: str,
    seen_at: str,
    is_login: int,
    enrichment: tuple[str | None, str | None, int | None, str | None, str | None, str | None],
) -> None:
    country_code, country_name, asn_number, asn_org, provider, confidence = enrichment
    connection.execute(
        """
        INSERT INTO attackers (
            source_ip, first_seen, last_seen, event_count, login_attempts,
            country_code, country_name, asn, asn_org, cloud_provider, provider_confidence
        ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_ip) DO UPDATE SET
            first_seen = min(attackers.first_seen, excluded.first_seen),
            last_seen = max(attackers.last_seen, excluded.last_seen),
            event_count = attackers.event_count + 1,
            login_attempts = attackers.login_attempts + excluded.login_attempts,
            country_code = coalesce(excluded.country_code, attackers.country_code),
            country_name = coalesce(excluded.country_name, attackers.country_name),
            asn = coalesce(excluded.asn, attackers.asn),
            asn_org = coalesce(excluded.asn_org, attackers.asn_org),
            cloud_provider = coalesce(excluded.cloud_provider, attackers.cloud_provider),
            provider_confidence = coalesce(excluded.provider_confidence, attackers.provider_confidence)
        """,
        (
            source_ip,
            seen_at,
            seen_at,
            is_login,
            country_code,
            country_name,
            asn_number,
            asn_org,
            provider,
            confidence,
        ),
    )


def refresh_rollups(connection: sqlite3.Connection) -> None:
    connection.execute("DELETE FROM countries")
    connection.execute(
        """
        INSERT INTO countries (country_code, country_name, attacker_count, event_count, login_attempts, last_seen)
        SELECT country_code, max(country_name), count(*), sum(event_count), sum(login_attempts), max(last_seen)
        FROM attackers WHERE country_code IS NOT NULL GROUP BY country_code
        """
    )
    connection.execute("DELETE FROM asn")
    connection.execute(
        """
        INSERT INTO asn (asn, asn_org, cloud_provider, provider_confidence, attacker_count, event_count, login_attempts, last_seen)
        SELECT asn, max(asn_org), max(cloud_provider), max(provider_confidence),
               count(*), sum(event_count), sum(login_attempts), max(last_seen)
        FROM attackers WHERE asn IS NOT NULL GROUP BY asn
        """
    )


def persist_batch(
    connection: sqlite3.Connection,
    source_key: str,
    source_path: str,
    records: list[tuple[bytes, int]],
) -> tuple[int, int]:
    inserted = 0
    invalid = 0
    with connection:
        for raw_line, next_offset in records:
            try:
                obj = json.loads(raw_line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                invalid += 1
                connection.execute(
                    """
                    INSERT INTO source_state (source_key, source_path, byte_offset, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(source_key) DO UPDATE SET
                        source_path=excluded.source_path,
                        byte_offset=excluded.byte_offset,
                        updated_at=excluded.updated_at
                    """,
                    (source_key, source_path, next_offset, event_time(None)),
                )
                continue
            if not isinstance(obj, dict):
                invalid += 1
                connection.execute(
                    """
                    INSERT INTO source_state (source_key, source_path, byte_offset, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(source_key) DO UPDATE SET
                        source_path=excluded.source_path,
                        byte_offset=excluded.byte_offset,
                        updated_at=excluded.updated_at
                    """,
                    (source_key, source_path, next_offset, event_time(None)),
                )
                continue

            digest = hashlib.sha256(raw_line.rstrip(b"\r\n")).hexdigest()
            source_ip = obj.get("src_ip")
            if not isinstance(source_ip, str):
                source_ip = None
            enrichment = lookup_ip(source_ip) if source_ip else (None, None, None, None, None, None)
            country_code, country_name, asn_number, asn_org, provider, confidence = enrichment
            eventid = obj.get("eventid")
            if not isinstance(eventid, str):
                eventid = None
            seen_at = event_time(obj.get("timestamp"))
            is_login = int(eventid in LOGIN_EVENTS)
            command = str(obj.get("input"))[:4096] if obj.get("input") is not None else None
            fields = (
                digest,
                seen_at,
                eventid,
                source_ip,
                as_int(obj.get("src_port")),
                obj.get("dst_ip") if isinstance(obj.get("dst_ip"), str) else None,
                as_int(obj.get("dst_port")),
                obj.get("protocol") if isinstance(obj.get("protocol"), str) else None,
                str(obj.get("username"))[:512] if obj.get("username") is not None else None,
                str(obj.get("password"))[:1024] if obj.get("password") is not None else None,
                command,
                str(obj.get("session"))[:256] if obj.get("session") is not None else None,
                country_code,
                country_name,
                asn_number,
                str(asn_org)[:512] if asn_org is not None else None,
                provider,
                confidence,
                source_path,
                event_time(None),
            )
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO attacks (
                    event_hash, event_time, eventid, source_ip, source_port,
                    destination_ip, destination_port, protocol, username, password,
                    command, session_id, country_code, country_name, asn, asn_org,
                    cloud_provider, provider_confidence, source_file, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                fields,
            )
            if cursor.rowcount:
                inserted += 1
                if source_ip:
                    update_attacker(connection, source_ip, seen_at, is_login, enrichment)
                for tool in extract_command_tools(command):
                    connection.execute(
                        "INSERT OR IGNORE INTO command_tools (event_hash, tool) VALUES (?, ?)",
                        (digest, tool),
                    )

            connection.execute(
                """
                INSERT INTO source_state (source_key, source_path, byte_offset, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(source_key) DO UPDATE SET
                    source_path=excluded.source_path,
                    byte_offset=excluded.byte_offset,
                    updated_at=excluded.updated_at
                """,
                (source_key, source_path, next_offset, event_time(None)),
            )
        refresh_rollups(connection)
    return inserted, invalid


def process_file(connection: sqlite3.Connection, path: str) -> tuple[int, int, int]:
    try:
        stat = os.stat(path)
        if not os.path.isfile(path):
            return (0, 0, 0)
        source_key = f"{stat.st_dev}:{stat.st_ino}"
        row = connection.execute(
            "SELECT byte_offset FROM source_state WHERE source_key=?", (source_key,)
        ).fetchone()
        offset = int(row["byte_offset"]) if row else 0
        if offset > stat.st_size:
            offset = 0
        batches = inserted_total = invalid_total = 0
        batch: list[tuple[bytes, int]] = []
        with open(path, "rb") as stream:
            stream.seek(offset)
            while not STOP:
                line = stream.readline()
                if not line:
                    break
                batch.append((line, stream.tell()))
                if len(batch) >= BATCH_SIZE:
                    inserted, invalid = persist_batch(connection, source_key, path, batch)
                    batches += len(batch)
                    inserted_total += inserted
                    invalid_total += invalid
                    batch.clear()
            if batch:
                inserted, invalid = persist_batch(connection, source_key, path, batch)
                batches += len(batch)
                inserted_total += inserted
                invalid_total += invalid
        return (batches, inserted_total, invalid_total)
    except FileNotFoundError:
        return (0, 0, 0)
    except PermissionError:
        LOG.exception("cannot read configured Cowrie log path")
        return (0, 0, 0)


def main() -> None:
    global COUNTRY_READER, ASN_READER
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if not COUNTRY_DB.is_file() or not ASN_DB.is_file():
        raise SystemExit("GeoIP country and ASN databases are required before starting")
    COUNTRY_READER = maxminddb.open_database(str(COUNTRY_DB))
    ASN_READER = maxminddb.open_database(str(ASN_DB))
    connection = open_database()
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    LOG.info("worker started; source=%s database=%s", LOG_GLOB, DB_PATH)
    try:
        while not STOP:
            total_lines = total_inserted = total_invalid = 0
            files = sorted(p for p in glob(LOG_GLOB) if not p.endswith(".gz"))
            for path in files:
                lines, inserted, invalid = process_file(connection, path)
                total_lines += lines
                total_inserted += inserted
                total_invalid += invalid
            if total_lines or total_invalid:
                LOG.info(
                    "batch complete; lines=%d new_events=%d invalid_lines=%d files=%d",
                    total_lines,
                    total_inserted,
                    total_invalid,
                    len(files),
                )
            if not STOP:
                time.sleep(POLL_SECONDS)
    finally:
        connection.close()
        COUNTRY_READER.close()
        ASN_READER.close()
        LOG.info("worker stopped")


COUNTRY_READER: Any
ASN_READER: Any

if __name__ == "__main__":
    main()

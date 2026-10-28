#!/usr/bin/env python3
"""Fetch the current DB-IP Lite Country and ASN MMDBs without sending IPs."""

from __future__ import annotations

import gzip
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import maxminddb


ROOT = Path(os.environ.get("GEOIP_ROOT", "/var/lib/gci-enrichment/geoip"))
USER_AGENT = "GCI-Threat-Observatory/1.0 (local GeoIP database updater)"


def month_candidates() -> list[str]:
    now = datetime.now(timezone.utc)
    current = f"{now.year:04d}-{now.month:02d}"
    previous_year, previous_month = (now.year - 1, 12) if now.month == 1 else (now.year, now.month - 1)
    previous = f"{previous_year:04d}-{previous_month:02d}"
    return [current, previous]


def download_mmdb(kind: str, month: str, destination: Path) -> None:
    url = f"https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=90) as response:
        with gzip.GzipFile(fileobj=response) as compressed, destination.open("wb") as output:
            shutil.copyfileobj(compressed, output, length=1024 * 1024)


def validate_database(path: Path, sample_ip: str) -> None:
    with maxminddb.open_database(str(path)) as reader:
        if reader.get(sample_ip) is None:
            raise RuntimeError(f"MMDB has no record for validation IP {sample_ip}")


def main() -> int:
    ROOT.mkdir(mode=0o755, parents=True, exist_ok=True)
    current = ROOT / "current"
    current_month = datetime.now(timezone.utc).strftime("%Y-%m")
    try:
        if current.resolve() == (ROOT / current_month).resolve():
            if (current / "country.mmdb").is_file() and (current / "asn.mmdb").is_file():
                print(f"DB-IP Lite databases for {current_month} are already installed")
                return 0
    except FileNotFoundError:
        pass
    last_error: Exception | None = None
    for month in month_candidates():
        staging = Path(tempfile.mkdtemp(prefix=".geoip-stage-", dir=ROOT))
        try:
            country = staging / "country.mmdb"
            asn = staging / "asn.mmdb"
            download_mmdb("country", month, country)
            download_mmdb("asn", month, asn)
            validate_database(country, "8.8.8.8")
            validate_database(asn, "8.8.8.8")
            version_dir = ROOT / month
            if version_dir.exists():
                shutil.rmtree(version_dir)
            os.chmod(country, 0o644)
            os.chmod(asn, 0o644)
            os.chmod(staging, 0o755)
            staging.rename(version_dir)
            link_tmp = ROOT / ".current.new"
            try:
                link_tmp.unlink()
            except FileNotFoundError:
                pass
            link_tmp.symlink_to(month, target_is_directory=True)
            os.replace(link_tmp, ROOT / "current")
            print(f"Installed DB-IP Lite Country and ASN databases for {month}")
            unit = "gci-enrichment.service"
            if subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0:
                subprocess.run(["systemctl", "try-restart", unit], check=False)
            return 0
        except Exception as exc:  # preserve the current database if a release is unavailable
            last_error = exc
            shutil.rmtree(staging, ignore_errors=True)
    print(f"GeoIP update failed; existing database remains in place: {last_error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

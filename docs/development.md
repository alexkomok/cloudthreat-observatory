# Development

## Files and dependencies

The website is a static HTML/CSS/JavaScript page with no build system. The
enrichment scripts use Python 3, SQLite from the standard library, and
`maxminddb` for offline MMDB lookups. The VM package is `python3-maxminddb`.

## Preview

Run a static server from the repository root:

```sh
python3 -m http.server 8080
```

The page fetches `metrics.json` from its own origin. If no local feed exists, it
shows a waiting state; it does not synthesize attack data. Do not copy the
private `/var/lib/gci-enrichment/metrics/latest.json` into a public web root.

## Enrichment worker

Configuration is supplied through environment variables documented in
`enrichment/worker.py`: `COWRIE_LOG_GLOB`, `ENRICHMENT_DB`, `GEOIP_COUNTRY_DB`,
`GEOIP_ASN_DB`, and `POLL_SECONDS`. The service uses defaults matching the GCI
VM paths. `source_state` and event hashes allow safe restarts and log rotation.

## Generated files to keep out of Git

Do not commit live Cowrie JSON logs, SQLite databases, GeoIP MMDB/CSV files,
public/private metrics snapshots, monthly generated reports, credentials, SSH
keys, or cloud exports. The repository `.gitignore` excludes these paths.

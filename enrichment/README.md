# GCI Cowrie enrichment

`worker.py` reads Cowrie JSON logs locally, enriches source IPs from offline
country and ASN MMDBs, and stores events and rollups in SQLite. Source IPs are
not sent to a lookup API.

The database is `/var/lib/gci-enrichment/attacks.sqlite` and has four reporting
tables (`attacks`, `attackers`, `countries`, and `asn`) plus `source_state` for
restart-safe log offsets. Initial startup backfills readable Cowrie JSON files;
subsequent runs continue from stored byte offsets. Event hashes prevent
duplicate inserts during restarts or log rotation.

Cloud-provider values are best-effort classifications from a small curated ASN
map and ASN organization-name matches. They are not authoritative ownership
claims. `provider_confidence` is `asn` for a direct ASN mapping and
`organization` for a name match.

## Data source and attribution

Country and ASN data come from the free DB-IP Lite monthly databases, licensed
under CC BY 4.0. If a dashboard or website displays these enrichment results,
include a visible link to [IP Geolocation by DB-IP](https://db-ip.com). The
Lite databases have reduced coverage and accuracy versus the commercial data.

## VM paths and services

- Worker: `/opt/gci-enrichment/worker.py`
- Update utility: `/opt/gci-enrichment/update_geoip.py`
- SQLite: `/var/lib/gci-enrichment/attacks.sqlite`
- GeoIP files: `/var/lib/gci-enrichment/geoip/current/`
- Worker unit: `gci-enrichment.service`
- Monthly updater: `gci-geoip-update.timer`

## Daily analytics

`daily_analytics.py` generates the top 20 countries, passwords, and usernames,
plus all destination ports for the current UTC day. It also records total events
and unique source IP counts. The daily timer runs at 00:10 UTC and keeps a
date-stamped JSON snapshot plus `latest.json` under
`/var/lib/gci-enrichment/metrics/`.

The analytics files contain captured password and username values. They are
kept on the VM in a private directory and written with mode `0600`; do not serve
them directly from a public web root.

- Analytics worker: `/opt/gci-enrichment/daily_analytics.py`
- Analytics timer: `gci-daily-analytics.timer`
- Output: `/var/lib/gci-enrichment/metrics/`

## Public observatory feed

The standalone page in the workspace reads `metrics.json` from the same web
origin and refreshes it every five minutes. `public_metrics.py` builds the
public projection from today's UTC events and writes only counts and ranked
aggregate values: up to eight countries, usernames, and ports, and only the
single most common password. It never exports source IPs, sessions, commands,
or individual event records. Since the requested top password is intentionally
public, its aggregate value is visible to page visitors.

`public_activity.py` publishes a separate `activity.json` with the latest ten
login event timestamps and fixed success/failure labels. It excludes source
addresses, usernames, and submitted passwords. Its systemd timer updates the
file every 30 seconds; the browser polls it every 15 seconds.

The public feed also contains a 90-day daily event/source-count series and
today's counts of command events invoking `wget`, `curl`, or `busybox`. The UI
switches the chart between 7, 30, and 90 days. Raw command strings remain
private in SQLite. The `attacker_profiles` SQL view contains first/last seen,
event and login counts, enrichment, and favorite password for each source IP;
it is private and must never be added to the public feed.

`worker.py` maintains `command_tools` and a private `malware_commands` view.
Schema migration 3 classifies existing command inputs once, then classifies new
command events as they arrive. `attacker_profiles` is a queryable SQL view over
the existing attacker rollup and attack records; its `attempt_count` counts all
events, while `login_attempt_count` counts failed and successful logins.

## Session playback and monthly reports

The public feed includes one redacted replay candidate and a daily unusual-session
highlight. The selector scores command-tool use, shell activity, successful
honeypot logins, and rejected logins. Replay steps omit source addresses,
credentials, raw command strings, and download URLs.

`monthly_report.py` generates a standalone HTML report for the previous complete
UTC month. `gci-monthly-report.timer` runs at 00:30 UTC on the first of each
month and publishes the report plus `/reports/` index. Reports contain only
monthly aggregates and omit source addresses, usernames, passwords, session IDs,
and raw commands.

The intended GCI paths are `/opt/gci-enrichment/public_metrics.py` and
`/var/www/cloudthreat/metrics.json`, scheduled by
`gci-public-metrics.timer`. The page files are `index.html`, `styles.css`, and
`app.js` in the workspace. Serve the page and JSON feed from the same origin so
the browser can fetch the feed without cross-origin access.

Install `public_activity.py`, `gci-public-activity.service`, and
`gci-public-activity.timer` alongside the existing public metrics exporter,
then enable and start `gci-public-activity.timer`.

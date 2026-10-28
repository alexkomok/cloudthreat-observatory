# Architecture and data flow

## Collection and enrichment

Cowrie records events as JSON under
`/opt/cowrie/var/log/cowrie/cowrie.json*`. The dedicated `gci-enricher` service
follows readable, uncompressed JSON files, stores byte offsets in `source_state`,
and hashes each source line to prevent duplicate inserts after restarts. It
enriches globally routable source addresses using local DB-IP Lite Country and
ASN MMDB files.

The worker updates these SQLite structures:

- `attacks`: event rows, including source/destination, login values, command,
  session, and enrichment fields.
- `attackers`: first/last seen, event and login counts, and latest enrichment by
  source address.
- `countries`, `asn`: event and attacker rollups.
- `source_state`: source-file byte offsets for restart-safe ingestion.
- `command_tools`: per-event classification for `wget`, `curl`, and `busybox`.
- `attacker_profiles`, `malware_commands`: private SQL views over the event and
  attacker tables. The profile view computes each address’s most frequent
  submitted password.
- `schema_migrations`: one-time classification/backfill markers.

Cloud-provider classifications are heuristic mappings from ASN and ASN
organization names. They are not authoritative ownership claims. DB-IP Lite has
reduced coverage and requires attribution when its data is displayed; the site
links to [DB-IP](https://db-ip.com).

## Log search

Alloy independently reads Cowrie JSON logs and sends them to Loki. Grafana
queries Loki for login attempts, failed-password events, and source-IP counts.
The Grafana dashboard is provisioned on the VM and is not part of this static
site. Grafana and Loki listen on loopback only.

## Public observatory

`public_metrics.py` reads only aggregate SQL results and atomically writes
`/var/www/cloudthreat/metrics.json` with mode `0644`. Nginx serves the static
page and JSON files from the same origin. The browser refreshes aggregate
metrics every five minutes. A small activity exporter writes
`/var/www/cloudthreat/activity.json` every 30 seconds; the browser polls that
redacted login-event feed every 15 seconds.

The public payload contains:

- Current UTC-day totals, total login attempts, and top country/password/username/port rankings.
- A daily count and unique-source count for each of the most recent 90 days.
- Daily counts of events invoking the tracked download tools.
- One redacted session reconstruction and a daily unusual-session summary.

`metrics.json` contains no source address, session ID, full command, or download URL. The
top eight password values are deliberately included as aggregate rankings
because they are a stated observatory requirement. Do not add attacker profiles
or raw events to this payload.

`public_threat_intel.py` writes the separate `/var/www/cloudthreat/threat-intel.json`
projection. It contains up to 20 globally routable repeat sources with address,
first/last seen, login-attempt count, country, ASN organization, and cloud-provider
classification. It excludes passwords, usernames, session IDs, and raw events.
The page labels these as observed network endpoints; enrichment is heuristic
and does not identify an operator. `gci-public-threat-intel.timer` refreshes it
every five minutes.

The activity feed contains only the latest ten login event timestamps and a
fixed success/failure category. It deliberately omits source addresses and
submitted usernames/passwords. `public_activity.py` writes this feed atomically
and is scheduled by `gci-public-activity.timer`.

## Monthly reports

On the first day of each month, `monthly_report.py` queries the previous
completed UTC month and writes a self-contained HTML report under
`/var/www/cloudthreat/reports/`. It also refreshes the report index. Reports
contain only monthly aggregates and omit source addresses, usernames, passwords,
session identifiers, and raw command strings.

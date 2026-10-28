# Data handling and security boundaries

## Private VM data

Cowrie records untrusted remote behavior and may include:

- Source and destination IP addresses and ports.
- Event timestamps, protocols, and session identifiers.
- Submitted usernames and passwords.
- Shell commands and download URLs.
- Country, ASN, organization, and heuristic cloud-provider enrichment.

The database lives at `/var/lib/gci-enrichment/attacks.sqlite`, is mode `0600`,
and is owned by `gci-enricher`. The worker has read access to Cowrie logs and
writes to the enrichment directory. `attacker_profiles` contains source IPs and
favorite passwords. `malware_commands` joins command-tool classifications to
the raw command. Both views must remain private.

The private daily snapshot under `/var/lib/gci-enrichment/metrics/` contains
top passwords and usernames and also must not be served from a public web root.

## Public data

The site and its JSON endpoints are public. `metrics.json` includes daily
aggregates, country names, username counts, a single top-password aggregate,
command-tool counts, and a daily event/source-count series. `activity.json`
contains up to ten recent Cowrie login event timestamps and a fixed event type,
refreshed every 30 seconds. It never includes source IPs, usernames, submitted
passwords, session IDs, raw command strings, or download URLs.

The live activity list shows UTC event times and whether a login was accepted
by the honeypot or rejected; it withholds the submitted identity and source.
Attack playback is reconstructed from Cowrie event types but replaces
credentials, usernames, commands, and URLs with redacted labels. The
“weirdest attack” summary reports only a heuristic score and aggregate signals.
Monthly static reports omit source addresses, usernames, passwords, session
identifiers, and raw command strings.

Public top-password and username values are honeypot submissions, not verified
credentials. They are still untrusted input and must continue to be rendered
as text, never HTML or executable content.

## Network and access

- Cowrie is the public-facing honeypot; real management SSH uses the configured
  management port and the `gci` SSH alias.
- Nginx serves the observatory over HTTP on port 80.
- Grafana and Loki are loopback-only and should be reached through an SSH tunnel.
- UFW is currently inactive. GCP VPC firewall policy controls external reachability.

## GeoIP attribution

Country and ASN lookups use local DB-IP Lite databases. Source addresses are not
sent to an external lookup API. The public site and monthly report link to
[IP Geolocation by DB-IP](https://db-ip.com) for attribution.

## Retention

This project currently has no automated event-database retention or backup
policy. Database and Cowrie log storage can grow over time. Decide on retention,
backup, and deletion policies before operating the sensor long term.

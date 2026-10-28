# Operations

## Paths

| Item | VM path |
| --- | --- |
| Cowrie JSON logs | `/opt/cowrie/var/log/cowrie/` |
| Enrichment worker and scripts | `/opt/gci-enrichment/` |
| SQLite database | `/var/lib/gci-enrichment/attacks.sqlite` |
| Offline GeoIP files | `/var/lib/gci-enrichment/geoip/current/` |
| Private daily analytics | `/var/lib/gci-enrichment/metrics/` |
| Public site and current feed | `/var/www/cloudthreat/` |
| Public monthly reports | `/var/www/cloudthreat/reports/` |

## Service status

Use SSH alias `gci` for management access. Check services and timers with:

```sh
sudo systemctl status cowrie gci-enrichment alloy loki grafana-server nginx
systemctl list-timers --all
```

Read service logs without displaying private event values:

```sh
sudo journalctl -u gci-enrichment.service --since today --no-pager
sudo journalctl -u gci-public-metrics.service --since today --no-pager
```

The enrichment service runs continuously. A restart resumes from stored file
offsets and deduplicates events by source-line hash. The public metrics timer
runs every five minutes. GeoIP data updates monthly. Daily private analytics
run at 00:10 UTC. Monthly report generation runs at 00:30 UTC on the first day
of each month.

## Grafana

Grafana and Loki are intended to remain loopback-only. From a trusted workstation
with the `gci` SSH alias, forward port 3000:

```sh
ssh -N -L 3000:127.0.0.1:3000 gci
```

Then open `http://127.0.0.1:3000`. The GCI dashboard includes login attempts,
failed-password events, and source-IP counts. Keep Loki's port 3100 private.

## Public site and firewall

Nginx serves the site on TCP 80. GCP VPC ingress must permit TCP 80 to the
`gci-web` target tag on this VM. The VM's UFW service is currently inactive;
do not enable it without adding explicit management SSH and web rules first.
The site currently uses HTTP and has no TLS certificate.

## Monthly reports

Open `/reports/` on the observatory site for the archive. Reports are generated
for the prior complete UTC month. The first report is created after the first
month boundary following deployment.

## Resource and storage notes

The deployment targets a small GCP VM. Check disk and memory use periodically:

```sh
df -h /var/lib/gci-enrichment /var/www/cloudthreat
free -h
systemctl show gci-enrichment.service -p MemoryCurrent -p CPUUsageNSec
```

No database retention or automated backup policy is configured in this
repository. Cowrie logs and SQLite events include sensitive captured values;
plan retention and backups before expanding collection or publishing raw data.

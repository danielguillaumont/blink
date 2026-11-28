# Operations: daemon, alerts, ledger and metrics

PCI DSS 11.6.1 asks for a mechanism that detects unauthorized changes to payment pages, runs
at least weekly, and alerts personnel. `blink daemon` is that mechanism; the ledger is the
evidence that it ran.

## Schedule

```yaml
schedule:                 # defaults for every target
  interval: 1d            # or cron: "0 3 * * *" (UTC). Default when neither is set: weekly
  jitter: 5m              # random delay so many sites don't scan at the same second
  retries: 2              # retries of a failed capture, with exponential backoff
  retry_backoff: 1m       # 1m, 2m, 4m, ...
  max_gap: 36h            # optional; see "Missed evaluations"
targets:
  - name: checkout
    url: https://shop.example/checkout
    schedule: {cron: "0 */6 * * *"}   # per-target override of any field
```

Durations accept `30s`, `15m`, `6h`, `1d`, `1w`. The weekday field of `cron` follows crontab
(0 or 7 = Sunday, `1-5` = Monday to Friday); names such as `mon-fri` work too.

```bash
blink daemon                          # run until stopped (SIGTERM or Ctrl+C)
blink daemon --concurrency 4          # parallel scans (default 2)
blink daemon --metrics-port 9464      # Prometheus /metrics on 127.0.0.1:9464
blink daemon --once                   # scan everything now, check the schedule, exit (cron/CI)
```

Each target is one job; a job never overlaps itself and late runs are coalesced. A capture
that still fails after its retries becomes a `schedule.capture_failed` finding (high).

### Missed evaluations

On start and every hour, the daemon compares each target/profile's last **successful**
evaluation with its allowed gap. Overdue ones become `schedule.missed_evaluation` findings:
high, or critical when the gap exceeds a week. The default gap is 1.5 periods plus the jitter
and retry budget (so one missed run is caught), capped at one week. Targets that are overdue
when the daemon starts are scanned right away.

## Alerts

Findings become **alerts**, deduplicated by fingerprint (target, profile, detector, change
type, subject). The same finding on every run is one alert whose `occurrences` grows; only a
new alert, a reopened one or a severity escalation is notified.

```
open ──ack──▶ acknowledged ──resolve──▶ resolved
  │                │        └─accept──▶ accepted-change
  └──resolve/accept┘
resolved / accepted-change ──(seen again or reopen)──▶ open
```

```bash
blink alerts                                   # open and acknowledged
blink alerts list --all --json
blink alerts show ALERT_ID                     # with its history
blink alerts ack ALERT_ID --by alice --note "investigating"
blink alerts resolve ALERT_ID --note "vendor rolled back"
blink alerts accept ALERT_ID --note "new chat widget, CHG-42"   # rebaselines; reason required
```

Accepting a change rebaselines that target/profile from the run that last saw the finding, and
records who accepted it and why (alert history, baseline reason and ledger).

### Sinks

```yaml
alerts:
  min_severity: high              # default for all sinks
  retries: 3                      # per notification, exponential backoff
  backoff: 2s
  dead_letter: dead-letter.jsonl  # in .blink/; undeliverable notifications
  sinks:
    - {name: slack, type: webhook, format: slack, url_env: BLINK_SLACK_WEBHOOK}
    - {name: teams, type: webhook, format: teams, url_env: BLINK_TEAMS_WEBHOOK}
    - {name: soc, type: syslog, host: 10.0.0.5, port: 514, protocol: tcp}   # RFC 5424 + CEF
    - name: mail
      type: smtp
      host: smtp.example.com
      port: 587
      from: blink@example.com
      to: [security@example.com]
      username_env: BLINK_SMTP_USER
      password_env: BLINK_SMTP_PASSWORD
    - {name: archive, type: jsonl, path: alerts.jsonl, min_severity: info}
```

- **webhook** posts JSON: `generic` (the `blink.alert.v1` document), `slack` (Block Kit) or
  `teams` (an Adaptive Card for Teams Workflows webhooks). Webhook URLs are secrets: prefer
  `url_env`.
- **smtp** sends a plain-text mail (STARTTLS by default, or `ssl: true`).
- **syslog** sends RFC 5424 lines whose message is CEF
  (`CEF:0|Blink|Blink|<version>|<detector.change_type>|<title>|<0-10>|...`), over UDP or TCP;
  facility 13 (log audit) by default.
- **jsonl** appends one JSON document per line.

Notifications carry the alert's title, severity, "why it matters", ids and counts. They never
carry evidence blobs, cookies, headers or form data. After the last retry, a notification is
written to the dead-letter file and recorded in the ledger (`alert.dead_letter`).

## Tamper-evident ledger

Every scan run, baseline change, inventory approval, alert state change, dead-letter and
daemon start is appended to a hash chain in `.blink/blink.db`. Each record contains the hash
of the previous one, and the head (last sequence number and hash) is signed with ed25519.

```bash
blink verify-ledger                               # exit 0 intact, 1 tampered
blink verify-ledger --public-key keys/blink.pub --json
```

`blink init` creates the signing key at `.blink/keys/ledger_ed25519` (mode 0600; `.blink/` is
git-ignored) and prints the public key fingerprint. **Copy `ledger_ed25519.pub` somewhere the
Blink host cannot write**, such as your repository, and verify against that copy. Someone with
the private key and write access to the database could rewrite history; pinning the public
key elsewhere, and exporting signed reports (Phase 6) regularly, limits that. If the key is
lost while the ledger has records, Blink refuses to create a new one silently.

## Metrics and logs

`/metrics` (daemon with `--metrics-port`; the dashboard in Phase 5) is computed from the
store on each scrape, so it is correct across CLI, daemon and dashboard processes:

| Metric | Type | Labels |
|---|---|---|
| `blink_scans_total` | counter | `status` (clean, findings, capture_failed) |
| `blink_findings_total` | counter | `severity` |
| `blink_last_successful_scan_timestamp` | gauge | `target`, `profile` |
| `blink_alerts` | gauge | `state`, `severity` |
| `blink_alert_dead_letters_total` | counter | |

Alert on `time() - blink_last_successful_scan_timestamp > 7 * 86400` as an independent
check that the daemon is alive.

The daemon logs JSON lines to stderr with structlog (`scan.started`, `scan.finished`,
`scan.capture_failed`, `schedule.missed`, `alert.delivered`, `alert.delivery_failed`,
`alert.dead_lettered`, ...). Keys that could hold secrets (`url`, `token`, `password`,
`authorization`, `cookie`, `secret`) are redacted.

## Running in Docker

The image (`ghcr.io/danielguillaumont/blink:2`, built from the repository's `Dockerfile`) is
based on the official Playwright Python image. It runs as the non-root `pwuser`, keeps all
state in the `/data` volume (`BLINK_CONFIG=/data/blink.yaml`) and works with a read-only root
filesystem:

```bash
docker run -d --name blink-daemon --read-only --tmpfs /tmp --shm-size 256m \
  --cap-drop ALL --security-opt no-new-privileges -v blink-data:/data \
  -e BLINK_HEALTHCHECK_URL=http://127.0.0.1:9464/metrics \
  ghcr.io/danielguillaumont/blink:2 daemon --metrics-port 9464
```

Set `BLINK_HEALTHCHECK_URL` to a loopback URL inside the container (`/metrics` for the daemon,
`/healthz` for `serve`) so the image's `HEALTHCHECK` probes the service itself.
`docker-compose.yml` runs the demo (lab, daemon, dashboard); see the README and
[ADR 0004](adr/0004-container-topology.md) for its network layout.

## Outbound proxy

Chromium does not read `HTTPS_PROXY`. Set `BLINK_PROXY=http://proxy.internal:3128`, and
optionally `BLINK_PROXY_BYPASS`, `BLINK_PROXY_USERNAME` and `BLINK_PROXY_PASSWORD`. See
[troubleshooting capture failures](runbooks/troubleshooting-capture.md).

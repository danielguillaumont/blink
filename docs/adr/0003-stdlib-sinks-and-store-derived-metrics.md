# ADR 0003: Standard-library alert sinks and store-derived metrics

- **Status:** accepted
- **Date:** 2026-11-27
- **Phase:** 4

## Context

`BUILD_PLAN.md` lists httpx among the libraries and asks for Prometheus counters such as
`scans_total`. Blink runs as three kinds of process: one-off `blink scan` in CI, the long-lived
`blink daemon` and `blink serve` (Phase 5). The core install should stay light.

## Decision

1. Alert sinks use the standard library: `urllib.request` for webhooks, `smtplib` for mail and
   `socket` for syslog. Each sink makes one request per notification, so httpx's connection
   pooling and async support bring nothing, and the sinks work without an optional extra.
   Contract tests run against local fake HTTP, SMTP and syslog servers.
2. Metrics are computed from the SQLite store on each scrape by a custom Prometheus collector,
   not kept as in-process counters. Counts then include runs from every process and survive
   restarts. The cost is a few indexed queries per scrape.
3. The daemon's dependencies (APScheduler 3, prometheus-client, structlog) live in the existing
   `[server]` extra rather than a new one. `blink daemon` says which extra is missing if they
   are not installed.

## Consequences

- No new mandatory dependency for alerts; webhook TLS uses the system trust store.
- httpx may still be used where its features help (for example, the dashboard's tests use
  FastAPI's TestClient, which is built on it).
- Counter values are derived from stored data. Pruning old runs would lower them, which
  Prometheus reads as a counter reset. Blink does not prune runs today.

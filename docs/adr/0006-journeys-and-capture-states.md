# ADR 0006: Journeys produce one snapshot per target and profile; the lab flow lives under `/shop`

- **Status:** accepted
- **Date:** 2026-11-28
- **Phase:** 14

## Context

BUILD_PLAN_2X Phase 14 adds `targets[].journey`, where "`capture` marks which page states get
snapshotted; the default is the final state". The whole evidence model is keyed by
`(target, profile)`: baselines, run results, alert fingerprints, the report's evaluation log
and the dashboard. Several snapshots per journey would need a third key throughout.

The plan also says the lab gets a multi-step flow "so `/checkout` redirects when the cart is
empty". The lab's `/checkout` is the single-page fixture behind every v2.0 scenario, the
Docker demo, the GitHub Action sample and the published sample report.

## Decision

1. **One snapshot per (target, profile) per run, as before.** The *last* `capture` step (or
   the end of the journey) is the snapshot's own state: its DOM, forms, iframes, headers and
   screenshot are compared with the baseline. Each earlier `capture` state is recorded in
   `Snapshot.journey.states` (name, URL, screenshot blob, DOM hash). Its scripts are merged
   into the snapshot's script list, so the inventory covers every captured page. Requests and
   script responses over the whole journey are included, as they always were for one page
   load.
2. **The lab's multi-step flow is a new path, `/shop` → `/shop/cart` → `/shop/details` →
   `/shop/checkout`.** `/shop/checkout` redirects to `/shop/cart?empty=1` without a cart
   session. `/checkout` keeps its v2.0 behaviour, so existing scenarios, the demo and the
   Action keep working.
3. **A failed step is a `journey.step_failed` finding plus a `capture_failed` run status (exit
   3).** The page wasn't evaluated, which is the existing meaning of exit 3, and the finding
   carries the screenshot and step for triage.
4. **Order safety is enforced twice.** The config is validated when it loads (`submit` needs
   `test_mode`, and order-like selectors are rejected unless `safe: true`). At runtime, an
   init-script guard blocks the submission of card forms unless the target is in `test_mode`.

## Consequences

- Detectors, alerts and reports needed no changes to understand journeys.
- The fingerprint of a finding doesn't say which capture state it came from. The primary
  state is the payment page, which is what 6.4.3 and 11.6.1 are about. Per-state diffs for
  earlier pages are a possible later extension (they would add a `state` key).
- Fields filled by a journey are masked in screenshots automatically, because canary and
  faker values change on every run.

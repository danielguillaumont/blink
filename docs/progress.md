# Blink 2.0 progress

Status of each phase in [`BUILD_PLAN.md`](../BUILD_PLAN.md). One branch and one PR per phase.

## Phase 0: Reset and hygiene

- **Date:** 2026-11-27
- **PR:** #5
- **Delivered:** pivot ADR (`docs/adr/0001-pivot-to-payment-page-integrity.md`), roadmap pointer,
  threat model (`docs/threat-model.md`); ruff, strict mypy on new code, pytest-cov, bandit,
  pip-audit and pre-commit, all enforced in CI; version `2.0.0.dev0` with the planned extras;
  byte-for-byte golden test of the 1.0 `blink compare` contract.
- **Known gaps:** the plan cites 83 existing tests; the 1.0.0 release actually had 89, all passing.
  PNG evidence in the golden test is compared by decoded pixels rather than file bytes, since PNG
  compression can legitimately differ between Pillow/zlib builds.

## Phase 1: Lab shop and capture engine

- **Date:** 2026-11-27
- **PR:** #6
- **Delivered:** loopback-only lab (shop, simulated CDN, sink) with 12 tamper scenarios;
  Playwright capture with deterministic settings, CDP initiator tracking, SHA-384 script
  inventory, scrubbed HAR, headers, forms, iframes, cookie metadata and TLS identity; DOM
  normalization; content-addressed store with SQLite index; `blink init`, `blink capture`,
  `blink lab`; `desktop-chrome` and `mobile-safari-ish` profiles.
- **Known gaps:** browser tests are skipped on Windows CI (they run on Linux CI and locally on
  Windows). Scripts that are only `eval`'d (no URL, no DOM element) are not inventoried; dynamic
  script elements and scripts removed from the DOM after loading are. The lab sits in
  `src/blink_visual/lab/` rather than a top-level `lab/` (ADR 0002).

## Phase 2: Baselines, detectors and findings

- **Date:** 2026-11-27
- **PR:** #7
- **Delivered:** `blink baseline` and `blink scan` with `--fail-on`, `--json` and `--output`;
  scripts, network, headers, forms, dom, visual and tls detectors; YAML severity rules with
  project overrides; findings JSON schema v2 (`docs/schemas/findings-v2.schema.json`); runs and
  findings persisted in SQLite; an end-to-end matrix over 12 scenarios × 2 profiles.
- **Known gaps:** with several CSP policies in one response the first definition of each
  directive is used; the DOM detector reports a moved element as a removal plus an addition.
  Unapproved-script findings arrive with the inventory in Phase 3.

## Phase 3: Script inventory and static JS risk

- **Date:** 2026-11-27
- **PR:** #8
- **Delivered:** `blink.inventory.yaml` model with approvals; `blink inventory` (`--sync`,
  `--check`, `--json`), `blink approve` and `blink suggest-csp`; an inventory detector
  (`unapproved` on every scan, `hash_mismatch` critical for pinned scripts); tree-sitter static
  JS risk heuristics (0–100 score with explained factors) attached to new and changed scripts;
  an npm-fetched corpus check that jQuery and React production builds score < 30.
- **Known gaps:** the risk score is a triage aid that a careful attacker can evade; integrity
  pinning is the control. `suggest-csp` cannot derive origins for entries matched only by
  `url_pattern` (it says so in a note). On hosts whose antivirus blocks writing a skimmer-like
  script, only its hash is kept and no risk score is computed (a warning is recorded).

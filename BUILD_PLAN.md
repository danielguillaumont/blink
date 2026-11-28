# Blink 2.0: Build Plan

> **Blink. See what changed on your checkout page.**
> A self-hosted, open-source monitor that detects tampering on payment pages (Magecart / e-skimming) and produces audit evidence for PCI DSS v4.0.1 Requirements 6.4.3 and 11.6.1.

This file is the source of truth for the build. Claude Code executes it phase by phase (see `CLAUDE.md` for operating rules). Each phase is one branch and one PR, merged only when its acceptance criteria pass.

---

## 1. Teardown of Blink 1.0

### Bad cop
- **It's a commodity.** A thresholded pixel diff plus SSIM is what `pixelmatch`, ImageMagick `compare`, and Playwright's built-in `toHaveScreenshot()` already do for free. Nobody switches tools for this.
- **It skips the hard part.** In real visual testing the difficulty is *capturing* stable screenshots: driving a browser, masking dynamic regions, handling animations, fonts and anti-aliasing. Blink makes the user bring two pre-made, same-size images.
- **No baselines, no history, no workflow.** There's no "approve this as the new normal", no run history, nothing scheduled. It's a one-shot calculator.
- **Max-channel thresholding is naive.** Anti-aliasing and JPEG noise cause false positives, and there's no perceptual colour metric.
- **The roadmap boxes it in.** "No accounts, databases, cloud services or AI" keeps it a toy on purpose.
- **A recruiter's 10-second scan says "image diff script".** That doesn't map to any job title you're applying for.

### Good cop
- **The engineering discipline is real.** Frozen dataclasses, read-only NumPy arrays, int16 widening before subtraction, decompression-bomb and size caps, `open('xb')` so evidence is never overwritten, a versioned JSON schema, stable exit codes, loopback-only Streamlit with telemetry off. 83 tests pass, and CI runs on Windows and Linux.
- **It's built around evidence.** Never resize silently, never overwrite, produce reproducible proof. That's exactly the mindset of **compliance, forensics and detection engineering**. The engine is right; the problem it's aimed at is wrong.
- **It's reusable as-is.** `analyze_pixels`, `difference_overlay` and `heatmap` become one detector among several in 2.0.

**Verdict:** keep the engine, the testing culture and the brand. Throw away the positioning.

---

## 2. Directions considered (good cop / bad cop)

| # | Direction | Good cop | Bad cop | Verdict |
|---|---|---|---|---|
| A | Visual regression testing for QA (Playwright plugin, baselines) | Direct QA fit; natural next step from 1.0 | Very crowded: Playwright built-in, Percy, Chromatic, Applitools, BackstopJS, Lost Pixel. Hard to be more than a clone | ❌ Absorbed into B as the "visual detector" |
| **B** | **Payment page tamper detection for PCI DSS 6.4.3 / 11.6.1** | Compliance mandate in force since 31 Mar 2025, so real buyers exist. Small merchants are priced out of commercial tools (~$10k/yr cited by vendors). Uses the existing engine. Spans cyber, GRC, QA, networking, systems and AI | Commercial competitors and free tiers exist (Report URI, c/side, Feroot, SecurityMetrics). An external scanner can't see skimmers targeted at specific users. Not a certified compliance product | ✅ **Chosen** |
| C | Phishing look-alike detection (clones of M365 or brand login pages) | Fits your Microsoft security background; visual similarity is the core skill | Research is crowded (Phishpedia, VisualPhishNet); needs URL feeds; handling live phishing sites needs care | ➕ Stretch module on top of B (Phase 11) |
| D | Manufacturing golden-image defect inspection (anomalib, PatchCore) | A real model-training exercise; wild-card industry | Drifts away from cyber; MVTec-AD is non-commercial and every ML portfolio already has that notebook | ❌ |
| E | Invoice and document tamper forensics (ELA, copy-move) for BEC fraud | Fraud and forensics angle | Accuracy is hard to prove; ML-research-heavy; weak results look bad | ❌ |
| F | Generic website defacement monitor | Simple | Visualping and many free tools already do this; there's no mandate driving purchases | ❌ B is the sharp version of this |

### Why B wins
1. **There's a real user with a specific problem.** A small or mid-size e-commerce merchant (or the MSP or developer looking after their store) on SAQ A-EP or SAQ D. Their QSA asks: *"Show me your payment-page script inventory with justifications, and the evidence that you detect unauthorized changes at least weekly."* Today they either pay a vendor or have nothing.
2. **The attack is real and visual.** Magecart skimmers inject scripts, swap form actions, or overlay fake card forms. Blink 1.0's visual diff catches overlays that script-only tools miss.
3. **It's buildable by Claude Code.** Every component is testable locally against a lab shop with deterministic tamper scenarios. No cloud is required.
4. **It covers your roles:** see section 9.

### Honest limitations (put these in the README)
- An agentless, periodic scanner sees what a scripted browser sees. It **does not** replace in-browser real-time protection or CSP reporting from real users, and it can miss skimmers that cloak by geography, user agent or time. Mitigation: rotate browser profiles and recommend CSP `report-to` alongside it.
- Blink **supports** evidence for 6.4.3 and 11.6.1. It doesn't make anyone compliant, and it isn't an assessor's attestation.

---

## 3. Product definition

**User stories**
- *As a merchant*, I point Blink at my checkout URL, record a known-good baseline, and get alerted when scripts, headers, forms, network destinations or the visual payment area change.
- *As the store's developer*, I approve each script with a justification and an owner. That approved inventory lives in git as `blink.inventory.yaml`.
- *As a security analyst*, I see findings with severity, an explanation and evidence (diff, overlay, HAR excerpt), and they reach my SIEM (Microsoft Sentinel, webhook or syslog).
- *As a QSA or auditor*, I receive a signed report covering the period: the inventory with justifications, the authorization method, the integrity method, each evaluation date (proving at least weekly), and every alert with its resolution.
- *As a release engineer*, I run `blink scan` against staging in CI. The deploy fails if an unapproved script appears.

**CLI surface (target)**
```
blink compare BEFORE AFTER          # 1.0 behaviour, unchanged
blink init                          # writes blink.yaml + empty inventory
blink capture TARGET                # one snapshot bundle
blink baseline TARGET               # capture + mark as known-good
blink scan [TARGET|--all] [--fail-on high]
blink inventory [--target T]        # list scripts + approval state
blink approve SCRIPT_ID --justification "..." --owner "..."
blink suggest-csp TARGET            # CSP + SRI suggestions from the inventory
blink report --from DATE --to DATE --format html|pdf|json
blink verify-ledger                 # tamper-evidence check of run history
blink daemon                        # scheduled scans + alerting
blink serve                         # local dashboard + API (loopback by default)
blink lab [--scenario NAME]         # local demo shop with tamper scenarios
blink explain FINDING_ID            # optional LLM triage summary (off by default)
blink lookalike URL                 # stretch: clone/phishing similarity
```
Exit codes: `0` clean / gate passed · `1` findings at or above `--fail-on` · `2` usage, config or I/O error · `3` capture failed (target unreachable, timeout).

---

## 4. Architecture

```
                ┌──────────── blink.yaml (targets, masks, profiles, schedule, sinks)
                ▼
 ┌─────────┐  capture   ┌────────────────────────────── Snapshot bundle ───────────────┐
 │Scheduler│──────────▶ │ screenshot.png · dom.html (normalized) · scripts/ (sha384)   │
 │ / CLI   │ Playwright │ network.har · headers.json · forms.json · tls.json · meta    │
 └─────────┘ + CDP      └──────────────────────────────┬───────────────────────────────┘
                                                       │ content-addressed store (.blink/objects)
                                                       ▼
                  baseline ──▶ ┌──────────── Detectors ─────────────┐
                               │ scripts   (new/removed/hash change, │
                               │            SRI missing, static risk)│
                               │ network   (new destinations)        │
                               │ headers   (CSP/HSTS/XFO/... policy) │
                               │ forms     (action, fields, iframes) │
                               │ dom       (payment-region structure)│
                               │ visual    (Blink 1.0 engine + masks)│
                               │ tls       (cert/issuer change)      │
                               └───────────────┬─────────────────────┘
                                               ▼
                         rules.yaml ──▶ Findings (severity, why, evidence refs)
                                               │
          ┌──────────────┬──────────────┬──────┴───────┬──────────────┬─────────────┐
          ▼              ▼              ▼              ▼              ▼             ▼
     SQLite index   hash-chained   alert sinks     dashboard/API   audit report   MCP server
                    ledger+ed25519 (webhook,SMTP,  (FastAPI+HTMX)  (HTML/PDF)     (read-only)
                                   syslog CEF,
                                   Sentinel)
```

**Package layout (target)**
```
src/blink_visual/
  compare.py analysis.py render.py workspace.py   # 1.0 engine, kept and stable
  cli.py                                          # argparse; subcommands split into cli/ if large
  config.py            # pydantic v2 models for blink.yaml
  capture/             # playwright driver, CDP script tracking, normalization, profiles
  store/               # content-addressed blobs, SQLite (stdlib sqlite3 or SQLAlchemy 2), ledger
  detect/              # one module per detector + base protocol
  jsanalysis/          # tree-sitter-javascript static heuristics
  rules/               # rule engine + default rules.yaml
  inventory.py         # 6.4.3 inventory + approvals (YAML in repo)
  alerts/              # sinks: webhook, smtp, syslog_cef, jsonl, sentinel
  report/              # jinja2 templates → HTML; Chromium print → PDF
  server/              # FastAPI app, HTMX templates, static assets
  mcp/                 # MCP server (read-only tools)
  lookalike/           # stretch
lab/                   # demo shop + tamper scenarios (test-only, localhost-only)
deploy/                # Dockerfile, compose, Bicep (Sentinel), KQL, workbook
docs/                  # architecture, threat model, ADRs, runbooks, PCI mapping
```

**Libraries:** playwright, pydantic v2, pyyaml, httpx, fastapi, uvicorn, jinja2, htmx (vendored static file), tree-sitter + tree-sitter-javascript, apscheduler, structlog, prometheus-client, cryptography (ed25519), imagehash, opencv-python-headless (stretch), azure-identity + azure-monitor-ingestion (Sentinel extra), mcp (MCP extra), anthropic (AI extra). Dev: pytest, pytest-cov, hypothesis, ruff, mypy, bandit, pip-audit, cyclonedx-bom.

Use optional extras so the core stays light: `[capture]`, `[server]`, `[sentinel]`, `[ai]`, `[mcp]`, `[lookalike]`, `[dev]`.

---

## 5. Safety rules for the lab and fixtures (non-negotiable)

The lab exists to trigger **detection signals**, not to demonstrate theft.
- Tamper fixtures must **not** be functional skimmers. They must never read form field values, never serialize payment inputs, and never send user-entered data anywhere.
- Fixtures send only **constant payloads** (for example `{"ping":1}`) to **localhost** sinks. They exist to prove Blink notices a new script, origin or destination, a hash change, a header change or a form change.
- Use only published test card numbers (for example 4242 4242 4242 4242) as static placeholder text. Use no real personal data.
- `blink lab` binds to 127.0.0.1 only. Scans in tests target the lab only. No scanning of third-party sites in CI.
- `blink lookalike` never submits forms or enters credentials. It captures read-only, in a fresh browser context with no stored state.

---

## 6. Phases

Each phase lists **Deliverables** and **Acceptance criteria (AC)**. A phase is done when all AC pass locally and in CI. Phases 0–7 make up the MVP. Phases 8–12 add depth.

### Phase 0: Reset and hygiene
**Deliverables**
- Replace `docs/roadmap.md` with a pointer to this plan; add `docs/adr/0001-pivot-to-payment-page-integrity.md` explaining the pivot (based on section 1).
- Tooling: ruff (lint and format), mypy (strict on new modules), pytest-cov, pre-commit, bandit, pip-audit. Add all of them to CI.
- `pyproject.toml`: bump to `2.0.0.dev0` and define the extras listed above.
- `docs/threat-model.md`: assets, adversaries (Magecart groups, compromised third-party CDN, insider), attack paths (script injection, supply-chain script swap, form-action hijack, overlay iframe, header weakening), and what Blink does and doesn't cover.

**AC:** existing 83 tests still pass; `ruff check`, `mypy` (new code), `bandit -q -r src` and `pip-audit` are green in CI; the 1.0 `blink compare` behaviour is byte-for-byte unchanged (golden JSON test).

### Phase 1: Lab shop and capture engine
**Deliverables**
- `lab/`: a tiny FastAPI app serving `/checkout` with first-party JS, one "third-party" script served from a second local port (to simulate a cross-origin CDN), a card form with static test placeholders, security headers, and benign noise: a rotating CSRF token, a timestamp, and a rotating promo banner.
- Scenarios, selectable with `blink lab --scenario NAME` or the `?scenario=` admin endpoint:
  `clean`, `new_third_party_script`, `modified_approved_script`, `inline_script_injected`, `csp_removed`, `csp_weakened_unsafe_inline`, `form_action_changed`, `hidden_iframe_added`, `overlay_form_added`, `new_beacon_destination`, `visual_payment_area_changed`, `noise_only` (should produce **no** findings).
- `capture/`: Playwright Chromium headless. Deterministic settings: fixed viewport per profile, locale, timezone, `reducedMotion`, an injected CSS rule that disables animations, and a wait strategy (network idle plus a selector). Through CDP, record every script: URL, inline flag, SHA-384, `integrity` attribute, initiator chain, and frame. Also record HAR, main-document response headers, forms (action, method, input names and types, autocomplete), iframes (src, visibility, size), cookies (names and flags only, **never values**), and the TLS certificate (subject, issuer, fingerprint, expiry) using a separate `ssl` handshake.
- DOM normalization: strip configured volatile attributes and text (CSRF, nonces, timestamps) using selectors and regexes from `blink.yaml`.
- `store/`: content-addressed blobs (sha256) under `.blink/objects/`, a SQLite index of targets, snapshots and blobs, and `blink capture`.
- Browser profiles: `desktop-chrome` and `mobile-safari-ish` (viewport and UA), so cloaking can be tested later.

**AC:** capturing `clean` twice produces identical script hashes, header sets and form inventories, and an identical normalized DOM hash; the visual diff of masked regions is ≤ 0.01%. Capture of an unreachable target exits `3` within the configured timeout. Unit tests cover normalization; integration tests run the lab in-process. CI installs Playwright Chromium (`playwright install --with-deps chromium`) on Linux; Windows CI may skip browser tests with a clear marker.

### Phase 2: Baselines, detectors and findings
**Deliverables**
- `blink baseline` / `blink scan`.
- Detectors (a common `Detector` protocol returning `Finding`s):
  - **scripts**: added, removed, or content hash changed for the same URL; inline script added; SRI missing on a cross-origin script; SRI present but mismatched.
  - **network**: new request destinations (scheme+host) compared to baseline; new POST/beacon/WebSocket destinations rated higher.
  - **headers**: policy check plus diff for CSP (parsed with directive-level diff; flags `unsafe-inline`, `unsafe-eval`, wildcard sources, a removed `script-src`), HSTS, X-Frame-Options/`frame-ancestors`, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
  - **forms**: action origin changed, new inputs (especially card-like names or autocomplete `cc-*`), method change, new iframes, hidden or off-screen iframes.
  - **dom**: structural diff of the configured payment region (a tree edit summary, not a text diff).
  - **visual**: the Blink 1.0 `analyze_pixels` on the payment-region crop with masks; the min-region filter from config.
  - **tls**: issuer or fingerprint change, expiry < 14 days.
- `rules/`: YAML rules map `(detector, change_type, conditions)` to severity (`info|low|medium|high|critical`) with a human-readable "why it matters" string. Default rules ship in the package.
- Findings JSON schema v2 (published in `docs/schemas/`); `--json` output; `--fail-on`.

**AC:** every scenario produces its expected finding(s) at the expected minimum severity, and `noise_only` and `clean` produce zero findings at ≥ low. This is a parametrized end-to-end test matrix over every scenario × both profiles. The JSON validates against the schema (use `jsonschema` in tests).

### Phase 3: Script inventory and static JS risk (Req 6.4.3)
**Deliverables**
- `blink.inventory.yaml` (committed to the user's repo): per script it holds a stable id, the URL or inline-hash, type (first-party, third-party or inline), expected hash or "dynamic", the SRI value, a justification, owner, approved_by, approved_at, and notes.
- `blink inventory`, `blink approve`; an unapproved script is a finding even if it was in the baseline.
- `jsanalysis/`: tree-sitter-javascript static heuristics, each with an explanation: `eval` / `new Function`; `atob`/`fromCharCode` decode chains; high-entropy string literals; dynamic `<script>` creation; listeners on `input`/`change`/`keydown` attached to payment-like fields; `FormData` or field `.value` reads combined in the same function with `fetch`/`sendBeacon`/`XMLHttpRequest`/`WebSocket`/`new Image().src`; obfuscator signatures (hex-named identifiers, string-array rotation). The output is a 0–100 risk score with contributing factors. **Test fixtures for heuristics are small, non-functional code snippets that contain the patterns, not working skimmers.**
- `blink suggest-csp`: generates a minimal CSP `script-src`/`connect-src` and SRI attributes from the approved inventory.

**AC:** heuristic unit tests (positive and negative snippets, Hypothesis fuzzing that the parser never crashes on arbitrary input); scanning real minified libraries (jQuery, React production build fetched via npm into a test cache) scores low (< 30); the scenario `modified_approved_script` raises `critical` when an approved static script's hash changes.

### Phase 4: Scheduler, ledger and alerting (Req 11.6.1 "at least weekly" and "alerts personnel")
**Deliverables**
- `blink daemon`: APScheduler with per-target cron or interval (default weekly, recommended daily), jitter, retries with backoff, and a concurrency limit. A missed evaluation is itself a finding.
- Alert state machine: `open → acknowledged → resolved | accepted-change` (accepting a change rebaselines and records who and why). Dedupe by a fingerprint.
- Sinks: generic webhook (with Slack and Teams payload formats), SMTP, syslog CEF, JSONL file. Each sink has a contract test with a local fake server.
- **Tamper-evident ledger:** every run and every state change is appended as a record including `prev_hash`; the chain head is signed with an ed25519 key generated on `blink init` (the key file is 0600 and excluded from git). `blink verify-ledger` detects edits, deletions and reordering.
- structlog JSON logs; Prometheus `/metrics` (scans_total, findings_total by severity, last_successful_scan_timestamp).

**AC:** a frozen-clock test proves scheduling and missed-run detection; ledger tests show that modifying, deleting or reordering any record fails verification; alert delivery has a retry test and a dead-letter test.

### Phase 5: Dashboard and API
**Deliverables**
- FastAPI app plus Jinja2/HTMX (no SPA build step). Pages: Targets, Run timeline, Finding detail (side-by-side screenshot, Blink overlay/heatmap of the payment region, script diff, header diff, HAR excerpt), Inventory (approve and justify inline), Alerts (ack, resolve, accept change), Settings (read-only config view).
- It binds to 127.0.0.1 by default and requires a bearer token (generated on init) for any non-GET endpoint. CSRF protection on forms. Strict CSP on Blink's own pages; Blink must pass its own header checks (dogfood test).
- OpenAPI docs at `/docs`.
- The existing Streamlit `app.py` stays as the 1.0 "compare workspace".

**AC:** API tests with TestClient; Playwright UI e2e tests covering approving a script, acknowledging an alert and opening a finding; `blink scan` against `blink serve` itself reports zero header findings.

### Phase 6: Audit evidence report
**Deliverables**
- `blink report` → HTML (Jinja2) and PDF (Playwright `page.pdf()`). Sections: scope and targets; script inventory with justification and authorization method (6.4.3); integrity method (hashes and SRI); evaluation log showing each run date and the maximum gap between evaluations (11.6.1 weekly); findings and how each was resolved; ledger verification result and signature; methodology and limitations; a disclaimer that this supports but does not replace assessor judgment.
- A signed `report.json` sidecar.
- `docs/pci-mapping.md`: table mapping each 6.4.3 / 11.6.1 element to the Blink feature and the evidence artifact. Paraphrase the requirements; link to the PCI SSC document library rather than copying the standard's text.

**AC:** a snapshot test of the report structure; the PDF renders and is non-empty; a report generated after a tampered ledger shows a failed verification banner.

### Phase 7: Packaging, ops and CI integration (MVP release)
**Deliverables**
- Dockerfile based on the official Playwright Python image: non-root user, read-only root filesystem with a writable `/data` volume, healthcheck. `docker-compose.yml` running blink daemon, blink serve and the lab.
- Composite GitHub Action `action.yml`: `uses: danielguillaumont/blink@v2` runs `blink scan --fail-on high` against a staging URL and uploads the evidence as an artifact.
- Release workflow: build sdist and wheel, a CycloneDX SBOM, a pip-audit report, and a GHCR image; CodeQL workflow.
- Runbooks in `docs/runbooks/`: "An alert fired, now what?" (incident response steps for a suspected skimmer: preserve evidence, remove the script, rotate keys, notify the acquirer, and so on), "Rebaselining after a legitimate deploy", and "Troubleshooting capture failures" (proxy, TLS, bot protection, timeouts).
- README rewrite: problem, 60-second demo (`docker compose up` → open the dashboard → switch the lab to `new_third_party_script` → watch the alert), honest limitations, architecture diagram (Mermaid).

**AC:** `docker compose up` followed by a scripted demo passes in CI (smoke job); the action works in a sample workflow in the repo; tag `v2.0.0`.

### Phase 8: Microsoft Sentinel integration
**Deliverables**
- `alerts/sentinel.py`: Logs Ingestion API sink (azure-identity plus azure-monitor-ingestion) sending to a custom table `BlinkFindings_CL`.
- `deploy/sentinel/`: Bicep for the DCE, the DCR and the custom table schema; KQL analytics rules (critical script change, CSP removed, new exfil destination, missed weekly evaluation); a workbook JSON; and a hunting query joining Blink findings with web proxy or WAF logs, if present.
- `docs/sentinel.md`: step-by-step setup using the free trial or pay-as-you-go tier, required RBAC (Monitoring Metrics Publisher on the DCR), and cost notes.
- Tests mock the ingestion client; KQL lives in `.kql` files and is validated for syntax with a lightweight check or kept under a documented manual-test checklist.

**AC:** mocked contract tests; Bicep passes `az bicep build` in CI if the Azure CLI is available (otherwise skipped with a marker); docs let someone without a workspace get one stood up.

### Phase 9: AI layer (optional extras, off by default)
**Deliverables**
- `blink explain FINDING_ID`: sends a **redacted** finding (no cookies, no header values beyond security headers, no query strings) to the Anthropic API and returns a plain-English triage summary plus suggested next steps. It's opt-in through config and an env key, and the redactor has its own tests.
- `blink mcp`: an MCP server with read-only tools `list_targets`, `latest_findings`, `get_finding`, `get_inventory` and `ledger_status`, so an AI agent or SOC copilot can query Blink. Pairs naturally with Gatehouse.
- **Evaluation harness** (`eval/`): runs every lab scenario × profile N times and reports detection rate, false-positive rate on `noise_only`, and mean scan time, written to `docs/benchmarks.md` and shown as a table in the README. This is the measurable "model/detector quality" story, with no need to train on malware.

**AC:** the AI features are fully skipped when the extra or key is absent; the MCP server passes a protocol smoke test; the eval harness runs in CI on a reduced N.

### Phase 10: Hardening
- Fuzz config parsing and CSP parsing with Hypothesis.
- Resource limits: max blobs per snapshot, max script size, a capture timeout, and max HAR size.
- Secrets: never log tokens; scrub `Authorization`/`Cookie` from HAR before storage (test it).
- Proxy support (`HTTPS_PROXY`), custom CA bundle, and auth for staging targets (basic auth or a header token from an env var, never stored in snapshots).
- **AC:** coverage ≥ 85% on `src/`; bandit is clean; a documented performance number (scan time for the lab checkout on CI hardware).

### Phase 11 (stretch): Look-alike / clone detection
- `blink lookalike URL [--against TARGET]`: captures the suspicious URL in an isolated context (no stored state, no form interaction, short timeout) and compares it with baselined login or checkout pages using: perceptual hashes (imagehash pHash/dHash), SSIM on normalized grayscale, ORB keypoint matching with RANSAC (OpenCV), form-field similarity (Jaccard over input names and types), favicon hash, and a `<title>` / brand-text match. The output is a similarity score with per-signal breakdown and side-by-side evidence.
- Lab fixture: a local "clone" page that copies the lab checkout's look but posts nowhere (form `action="#"`, no JS).
- **AC:** clone scores ≥ 0.8 against the lab checkout; unrelated pages score ≤ 0.3; it never submits a form (asserted in tests by intercepting requests).

### Phase 12: Portfolio polish
- Demo GIF: tamper scenario → dashboard alert → finding detail with overlay.
- `docs/case-study.md`: the problem, design decisions, limitations and the benchmark results, written for a hiring manager.
- Updated architecture diagram, a CHANGELOG, and tags `v2.1.0`+ for the post-MVP phases.

---

## 7. Global definition of done (every phase)
- Tests are added for every new behaviour; the full suite is green on Linux (and Windows where applicable).
- ruff, mypy (new code), bandit and pip-audit are clean.
- Docs are updated (README section, CLI `--help`, relevant `docs/` page).
- No network access in unit tests; integration tests only reach the localhost lab.
- The 1.0 `compare` API and CLI are unchanged unless an ADR says otherwise.

---

## 8. Demo script (what you show in an interview)
1. `docker compose up`, then open `http://127.0.0.1:8765`.
2. The checkout target is green; the inventory shows three approved scripts with justifications.
3. `blink lab --scenario overlay_form_added`, then `blink scan --all`.
4. A critical alert appears: a new hidden iframe plus a visual change in the payment region. The overlay shows exactly where.
5. Show it arriving in Slack or Teams (webhook) and in Sentinel (`BlinkFindings_CL | where Severity == "critical"`).
6. `blink report --format pdf` gives the auditor-ready evidence pack; `blink verify-ledger` passes.
7. Edit one ledger row by hand, run `verify-ledger` again, and it fails. That's the tamper-resistance story.

---

## 9. How this maps to the roles you're applying for

| Role | What Blink 2.0 lets you claim |
|---|---|
| Cybersecurity / SOC / Detection engineering | Built a Magecart/e-skimming detection system with rule-based severity, a SIEM integration (Sentinel custom table, KQL analytics rules, workbook) and IR runbooks |
| GRC / Compliance | Mapped PCI DSS v4.0.1 6.4.3 and 11.6.1 to technical controls; produced signed, tamper-evident audit evidence |
| AppSec | CSP/SRI policy analysis and generation; static JS risk analysis with tree-sitter; threat model |
| QA / Test automation | Playwright capture with deterministic rendering; parametrized e2e scenario matrix; visual regression engine; CI gating action |
| Software engineering | Python package with FastAPI + HTMX dashboard, plugin-style detectors, a typed config, a published JSON schema and an OpenAPI spec |
| Systems / DevOps | Hardened Docker (non-root, read-only), compose stack, scheduler, Prometheus metrics, SBOM, CodeQL, GHCR releases |
| Networking | HTTP header and TLS certificate analysis, HAR network-destination diffing, proxy and custom CA support |
| AI | MCP server for agent access, LLM triage with a tested redaction layer, a detection-quality evaluation harness |
| Tech support | Runbooks, troubleshooting guide, clear error messages and exit codes |

---

## 10. References
- PCI SSC document library (PCI DSS v4.0.1): https://www.pcisecuritystandards.org/document_library/
- Report URI, client-side guide to 6.4.3 and 11.6.1: https://report-uri.com/pci-dss
- CSA / BARR Advisory deep dive (Jul 2026): https://cloudsecurityalliance.org/blog/2026/07/23/pci-dss-6-4-3-and-11-6-1-a-deep-dive-into-payment-page-security-and-integrity-requirements
- c/side, inventory fields guidance: https://cside.com/en/blog/comply-with-pci-dss-6-4-3-and-11-6-1-for-free
- Azure Monitor Logs Ingestion API: https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview

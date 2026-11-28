# Blink 2.x: Next build plan

> v2.0 detects **changes** on a payment page. v2.x detects **skimming**, works on **real checkouts**, and sees what **real customers** see.

This plan follows on from `BUILD_PLAN.md` (Phases 0–7, shipped as v2.0.0). It **supersedes BUILD_PLAN.md Phases 9–12**. **Phase 8 (Microsoft Sentinel) is deferred** until Azure is set up; nothing here needs Azure or any paid service. `CLAUDE.md` operating rules still apply (one branch and PR per phase, local check, no AI attribution), plus the safety amendment in §4.

---

## 1. Assessment of v2.0.0

What I checked: a fresh clone at `cb8fa43` (15.4k lines across src and tests), the full suite (**504 passed, 4 skipped, 94% branch coverage**, browser tests included), and a hands-on run (init → baseline → tamper → scan) against the lab.

### Good cop
- **The engineering is genuinely portfolio-grade.** A signed, hash-chained ledger; a published findings schema; a dockerised end-to-end demo running in CI; SBOM, pip-audit, CodeQL; ADRs; runbooks. Very few junior or intermediate portfolios have this.
- **It's fast.** A baseline of the lab checkout takes about 2 s.
- **The architecture is ready to extend.** The detector protocol, YAML rules, sinks and content-addressed store make each new feature a contained module.
- **It has a real niche.** No open-source tool combines self-hosting, a PCI evidence pack and visual overlay detection. Target's open-source Merry Maker is the closest. It does synthetic shopping journeys, YARA rules and IoC lists, but it's detection-only, produces no audit evidence, and was released in 2022 as Node/TypeScript.

### Bad cop (why a real merchant would still not use it)
1. **It doesn't work on most real checkouts.** A target is one URL. A real checkout needs a cart, a session, and often a guest-details step before the payment form even renders. Merry Maker already acts as a guest shopper: it searches, adds to cart, enters payment details and submits.
2. **It detects change, not theft.** The only behaviour signals are a static risk score and "new network destination". Vendors now pitch alerting the moment a script reads a payment field or sends data to an endpoint it shouldn't. Blink can't say "this script read the card field and sent it to X".
3. **Skimmers can hide from a crawler.** Skimmers have long gone dormant when developer tools are open, and returned 404 unless the Referer or User-Agent looked right. Competitors use exactly this against scanners: sophisticated skimmers detect crawlers and serve clean code. Blink has two profiles and no way to see real users.
4. **It's noisy out of the box.** My clean-lab scan with a minimal config raised a `LOW dom.region_changed` finding. Avoiding that needs hand-written normalize rules. A merchant won't write CSS selectors for CSRF tokens.
5. **It has no threat context.** It doesn't know a domain is a week old, or that a "jquery.min.js" matches no published jQuery release.
6. **It's hard to install.** It isn't on PyPI, has no docs site, and the distribution name `blink-visual` no longer describes the product.
7. **Known gaps from Phase 7:** proxy settings are global; Swagger loads from a CDN; the compose dashboard can't bind to loopback.

**Verdict:** the foundation is strong. The next version should spend its effort on items 1–5, which competitors already sell, rather than on more infrastructure.

---

## 2. Feature candidates: good cop / bad cop

| Feature | Good cop | Bad cop | Verdict |
|---|---|---|---|
| **Synthetic checkout journeys** (YAML steps: goto, click, fill, select, wait, assert) | Makes Blink work on real stores; standard in the space | Selectors break when sites change; risk of placing real orders | ✅ **Build.** Step failures become findings; never submit the final order unless the target is marked `test_mode` |
| **Canary data-flow tracing**: fill the form with a unique test canary, trace where it goes, and attribute each read and send to a script | The 10× feature: turns "something changed" into "script X sent card data to Y". Strong runtime-instrumentation talking point | Payloads a skimmer encrypts defeat string matching; hooks are theoretically detectable | ✅ **Build.** Network-layer capture through CDP can't be hidden from; when encryption defeats matching, fall back to "unapproved script read a payment field" + "new destination" correlation |
| **Payment-field access attribution** (which script read `cc-number`) | Directly answers the 6.4.3 question "what can touch card data?" | Stack-trace attribution is imperfect for eval'd code | ✅ **Build**, with confidence levels |
| **Self-hosted Reporting API collector** (CSP violations plus `csp-hash` script hashes from real browsers) | Solves the crawler blind spot with real-user data, for free. With `'report-sha256'`, browsers hash every script they execute and report it back | It's an internet-facing endpoint, so it needs abuse controls; `csp-hash` is Chromium-specific | ✅ **Build**, with rate limits, size caps, origin checks and a no-auth-by-design threat model |
| **Cloaking detector** (diff captures across a profile matrix: UA, locale, timezone, viewport, returning visitor) | A novel signal: different content for different visitors is itself suspicious | Arms race; could drift into bot-evasion tooling | ✅ **Build.** Standard Playwright options only. **No** bot-protection bypass, no CAPTCHA solving, no stealth plugins |
| **Auto-learned baseline** (capture N times, derive volatile paths and masks automatically) | Fixes the out-of-the-box noise; vendors sell "learning mode" | Could learn an attacker's change as "volatile" if one is already present at baseline | ✅ **Build.** Learning only marks values that **vary between** baseline captures; structural additions are never learned as noise |
| **Threat intel**: library fingerprinting (cdnjs/jsDelivr/npm hashes), OSV vulnerability lookup, RDAP domain age, IoC list import | Catches polyfill.io-style attacks and adds "why this is bad" context | External APIs mean caching, rate limits and offline mode are needed | ✅ **Build**, offline-first with a cached intel DB and `blink intel update` |
| **YARA rules on scripts** (yara-python) | Analysts know YARA; Merry Maker supports it; cheap to add | Rule quality is everything | ✅ **Build.** Ship our own generic rules; users add their own; never copy vendors' rules |
| **JS deobfuscation pipeline** (beautify, string-array unrolling, hex/escape decoding) | Makes diffs and AI explanations readable; a real analyst tool | Partial by nature | ✅ **Build** best-effort, shown side by side with the raw source |
| **CSP policy simulator** (`blink csp simulate`: inject a candidate CSP during capture and report what would break) | Removes the #1 fear about enforcing CSP | None significant | ✅ **Build**: small, high value |
| **MCP server + `blink explain`** | AI-role keyword; pairs with Gatehouse; useful for SOC copilots | AI verdicts can be wrong | ✅ **Build.** Read-only MCP tools; explanations are advisory and never change severity |
| **No-Azure SIEM outputs** (ECS JSON for Elastic, Splunk HEC, Sigma rules) | SOC roles; testable without cloud | More sinks to maintain | ✅ **Build** (small) |
| **Forensic evidence bundle** (zip + manifest + chain-of-custody, "what did checkout look like at time T") | IR and forensics roles; cheap given the store and ledger | None | ✅ **Build** (small) |
| **Evaluation harness + benchmarks** | Hard numbers for the README and interviews | Lab-only numbers can overstate real-world performance | ✅ **Build**, stating that limitation |
| PyPI + docs site (mkdocs-material on GitHub Pages) | Makes it easy to try; looks professional | — | ✅ **Build first** |
| Platform presets (WooCommerce / Magento journey recipes) | Magento and Adobe Commerce are the classic Magecart targets | Running Magento in CI is heavy | ➖ Ship YAML recipes + docs only, tested against the lab |
| Microsoft Sentinel (old Phase 8) | Matches your Microsoft security background | Needs Azure | ⏸ Later, when Azure is set up |
| Look-alike / phishing clones (old Phase 11) | Cool | A different product; dilutes the story | ⏸ Park |
| Script blocking / proxy enforcement (c/side style) | Prevention instead of detection | Sits in the critical path of a merchant's revenue; big liability | ❌ No: CSP simulator + generator instead |
| Multi-tenant SaaS, RBAC, SSO | "Enterprise" | Huge effort, low signal for your roles | ❌ No |
| Browser extension / real-user JS agent | Real-time protection | Requires merchants to inject our JS; the Reporting API collector covers this need with zero code | ❌ No |
| ML model trained on skimmer samples | "Trained a model" | Needs malware corpora; ethics and licensing; weak with small data | ❌ No: the eval harness + YARA + heuristics tell a better story |

---

## 3. Releases and phases

Phases continue the numbering from `BUILD_PLAN.md`. Each phase is one PR. Each release is a tag.

### v2.1: "Works on real sites"

#### Phase 13: Distribution and docs
- **Decide the distribution name before first publish.** Keep the import package `blink_visual` and CLI `blink`, but publish the distribution as **`blink-checkout`** (the index showed `blink-visual`, `blink-checkout`, `blink-pci` and `blink-integrity` all free; `blink` itself is taken). Record the decision in ADR 0005. *If PyPI publishing is already under way as `blink-visual`, keep that name and note it in the ADR.*
- PyPI release via **Trusted Publishing** (GitHub OIDC; no API tokens in secrets). Publish to TestPyPI first in a dry-run job. Daniel creates the PyPI project and trusted-publisher entry himself; document the exact steps in `docs/releasing.md`.
- `pipx install blink-checkout[capture,server]` works; `blink doctor` checks Python, Chromium, the store, keys and the config, and prints fixes.
- Docs site: mkdocs-material on GitHub Pages, built from `docs/`, with a published **sample signed report** and the findings schema.
- Fix the known gaps: vendor Swagger UI (no CDN); per-target `proxy`, plus `auth` (basic auth or a header token from an env var).
- **AC:** the TestPyPI install works in a clean CI venv; the docs build with zero warnings in strict mode; `blink doctor` has tests for each check.

#### Phase 14: Synthetic journeys
- `targets[].journey`: ordered steps `goto | click | fill | select | check | press | wait_for | wait_ms | assert_visible | assert_url | capture`. `capture` marks which page states get snapshotted; the default is the final state. Each step has a timeout and optional `frame` selector.
- Test data comes from `test_data:` with placeholders (`{{canary.pan}}`, `{{faker.email}}`); secrets come only from env vars.
- **Order safety:** a `submit` step is allowed only when the target sets `test_mode: true`; otherwise the journey must end before final submission (validated at config load).
- Lab: add a multi-step flow (product → cart → guest details → payment) with a session cookie, so `/checkout` redirects when the cart is empty.
- Journey step failures become findings (`journey.step_failed`, with a screenshot of where it broke).
- Add `blink record` (optional): wraps Playwright codegen to draft a journey YAML.
- Recipes: `docs/recipes/woocommerce.md` and `magento.md` (template YAML, clearly marked "adapt selectors").
- **AC:** an e2e test runs the lab journey on both profiles; an empty-cart redirect without a journey produces an actionable error; config validation rejects `submit` without `test_mode`.

#### Phase 15: Auto-learned baseline
- `blink baseline --learn N` (default 3) captures N times, possibly spaced over minutes. Anything that **differs between** those captures becomes a learned volatility rule: DOM attribute and text paths, request query parameters, inline-script hashes that rotate (nonce-like), and visual regions (connected components of the pixel diff across captures become masks).
- Learned rules are written to `blink.learned.yaml` (reviewable, committable) and listed in the report.
- **Guardrail:** learning can mask *values*, never *structure*. A new element, script, form field, iframe or destination is never learned as noise.
- **AC:** with an empty normalize config, `clean` and `noise_only` produce **zero** findings after `--learn 3`; every tamper scenario is still detected; a test proves a script injected during learning is still flagged as unapproved.

**Release v2.1.0** (PyPI + docs + journeys + learning).

### v2.2: "Catch skimmers, not just changes"

#### Phase 16: Canary data-flow tracing and field-access attribution
- **Canary:** each run generates unique test values. The PAN is a Luhn-valid number in a reserved test range, never a real card. Name, email and postcode are random tokens. The journey fills them in.
- **Runtime instrumentation** with `page.add_init_script` (runs before page scripts):
  - property getters on `HTMLInputElement.prototype.value` (and `FormData`, `serialize`-style reads) for fields matched as payment or PII (`autocomplete=cc-*`, name heuristics, configured selectors). Each read records the calling script from the parsed `Error().stack`, the field, and the timestamp;
  - wrappers on `fetch`, `XMLHttpRequest.send`, `navigator.sendBeacon`, `WebSocket.send`, `HTMLImageElement.src` / `HTMLScriptElement.src` setters, `form.submit`, `postMessage` and `EventSource`, each recording the caller and destination.
- **Network-layer truth:** independently of the hooks, CDP `Network.requestWillBeSent` / `Fetch` captures every request body, and `Network.webSocketFrameSent` captures WebSocket frames.
- **Canary matcher:** searches URLs, headers, bodies and WebSocket frames for each canary under transforms: raw, URL-encoding (repeated), base64 (nested up to 3 levels, plus URL-safe), hex, reversed, JSON-escaped, separators stripped, and simple ROT/char-shift. Every match records the transform chain.
- **New detectors:**
  - `dataflow.exfiltration`: canary reached a destination not in the approved `data_destinations` list. **Critical.**
  - `dataflow.field_read`: an unapproved or non-payment script read a payment field. **High.**
  - `dataflow.correlated`: a field read and a new destination from the same script within one session, with no canary match (encrypted payload suspected). **High.**
- Inventory gains `reads_payment_fields: true|false` and `data_destinations:` per script, so the 6.4.3 evidence states which scripts are *allowed* to touch card data.
- Dashboard: a "Data flow" tab per run showing a sequence diagram (field → script → destination) and the matched transform chain.
- **AC:** see the safety amendment (§4) for fixtures. Tests cover each transform (Hypothesis round-trip: encode(canary) is always found); lab scenarios `canary_beacon_base64`, `canary_ws_hex`, `field_read_only` and `correlated_read_and_beacon` each produce the expected detector; `clean` and every v2.0 scenario produce no dataflow findings.

#### Phase 17: Deobfuscation, YARA, cloaking detector
- `jsanalysis/deobfuscate.py`: beautify (`jsbeautifier`); decode `\x`/`\u` escapes; unroll string arrays (the obfuscator.io pattern: an array + rotate IIFE + accessor, resolved by static evaluation, never by executing the code); fold `atob("…")` literals; rename hex identifiers. Output is shown side by side with the raw source and used by the script diff, YARA and `explain`.
- YARA: `yara-python`. Bundled generic rules (`rules/yara/*.yar`) for patterns like payment-field selectors combined with exfil APIs, plus user rule directories. Matches become `scripts.yara_match` with the rule name and meta.
- **Cloaking detector:** a profile matrix per target (UA family, viewport, locale, timezone, first-visit vs returning-visitor cookie jar, optional per-profile proxy). Diff the snapshots *across profiles in the same run*. Scripts, destinations or forms present for some profiles but not others become `cloaking.divergence` findings (high when they involve the payment region or scripts). Standard Playwright options only.
- Lab scenarios: `cloaked_by_user_agent` (serves the inert extra script only to a mobile UA), `obfuscated_inert_script` (string-array-obfuscated inert code).
- **AC:** deobfuscation golden tests on obfuscated benign snippets; YARA match and no-match tests; the cloaking scenario detected only through cross-profile divergence.

**Release v2.2.0.**

### v2.3: "See what real customers see"

#### Phase 18: Reporting API collector and CSP simulator
- `blink collect`: a small ASGI service (it can share the FastAPI app or run standalone) exposing `POST /r/{target}` for `application/reports+json` (Reporting API) and legacy `application/csp-report`. It handles:
  - `csp-violation`: new blocked or reported destinations by directive (`connect-src`, `form-action`, `script-src`) feed the network/dataflow detectors as *real-user* evidence;
  - `csp-hash`: the script URL and hash from real browsers, matched against the inventory. An unknown hash, or a known URL with an unexpected hash, becomes `rum.script_unknown` / `rum.hash_mismatch`.
- Abuse controls: a per-IP and per-target token bucket, 64 KB body cap, schema validation, origin/target allowlist, storage quota with roll-up (counts per unique tuple rather than raw reports), and no auth by design (browsers can't authenticate), documented in the threat model.
- `blink collect snippet TARGET` prints the exact `Reporting-Endpoints` + `Content-Security-Policy-Report-Only` headers to deploy. A Caddy example puts it behind TLS.
- `blink csp simulate TARGET --policy FILE|--from-inventory`: runs the journey with the candidate CSP injected via request interception and lists what would be blocked. Optionally writes a report-only header to try for a week.
- Report: a "real-user telemetry" section (report volumes, unique scripts seen in the field and whether they're in the inventory).
- **AC:** contract tests with recorded report payloads (fixtures written by hand from the spec); fuzzing (Hypothesis) of the parser; rate-limit and size-cap tests. Lab e2e: the lab checkout sends report-only CSP pointing at a local collector, and Chromium in the test produces violation reports that Blink turns into findings. `csp-hash` e2e is attempted and marked `xfail` with a reason if the bundled Chromium doesn't emit it. `csp simulate` catches a blocked inline script in the lab.

**Release v2.3.0.**

### v2.4: "Know what's bad"

#### Phase 19: Threat intel and provenance
- `blink intel update` builds a local SQLite intel DB (cached, works offline afterwards):
  - **Library fingerprints:** for a configurable list of popular libraries, fetch published files from jsDelivr/cdnjs/npm and store sha256/sha384 → `(library, version, file)`. A script matching a known file gets `provenance: jquery@3.7.1`. A script whose URL or name claims a library but whose hash matches no published version becomes `intel.provenance_mismatch` (high).
  - **Vulnerabilities:** OSV.dev query for identified `library@version` becomes `intel.vulnerable_library`.
  - **Domain age and registration:** RDAP lookup for each third-party script host and data destination. Registered fewer than 30 days ago becomes `intel.new_domain`; a registrar or nameserver change since baseline becomes `intel.domain_changed`. That's the polyfill.io signal: the domain was sold in February 2024 and later used to inject code into 100,000+ sites.
  - **IoC import:** plain-text domain/hash lists, CSV and MISP JSON exports, matched against destinations and script hashes, giving `intel.ioc_match` (critical).
- Severity enrichment: rules can use intel fields (`when: {domain_age_days: {lt: 30}}`).
- Lab scenario: `cdn_domain_changed_owner` (a simulated RDAP fixture in which the CDN's registrar changes and the script content changes).
- **AC:** network calls are fully mocked in unit tests (recorded fixtures); offline mode uses the cache only; a provenance test fingerprints a real published jQuery file fetched into the test cache (like the existing corpus check).

**Release v2.4.0.**

### v2.5: "Plug into the SOC and AI"

#### Phase 20: SIEM outputs, forensic bundle, MCP and explain
- Sinks: **Splunk HEC**, **Elastic** (ECS-formatted, bulk API), **OpenTelemetry logs** (OTLP/HTTP). Contract tests against local fake servers. `deploy/sigma/` has Sigma rules for Blink's findings (critical dataflow, IoC match, missed evaluation).
- `blink evidence export --run ID | --from T --to T`: a zip containing snapshots, findings, screenshots and the relevant ledger slice, plus a `MANIFEST.json` (sha256 of every file) signed with the ledger key and a chain-of-custody log (who exported, when, from which host). `blink evidence verify`.
- `blink mcp` (the `[mcp]` extra): read-only tools `list_targets`, `latest_findings`, `get_finding`, `get_dataflow`, `get_inventory`, `ledger_status` and `search_scripts`. A protocol smoke test.
- `blink explain FINDING` (the `[ai]` extra, opt-in): sends a **redacted** finding plus the deobfuscated diff to the Anthropic API and returns a plain-English triage summary with next steps. The redactor strips cookies, query strings, non-security headers and every canary value, and has its own tests. Advisory only.
- **AC:** each sink has a retry and dead-letter test; a tampered bundle fails verification; AI and MCP are skipped cleanly when their extras are absent.

#### Phase 21: Evaluation harness and portfolio polish
- `eval/`: runs every lab scenario × profile N times, reporting detection rate, false-positive rate (`clean`, `noise_only`, `--learn` baselines), time-to-detect and scan duration. It writes `docs/benchmarks.md` and a README table. The CI run uses reduced N.
- README: a new 60-second demo built around the canary story ("Blink caught a script sending a base64-encoded test card to a new domain, here's the data-flow diagram"), a GIF, and a comparison table against Merry Maker and the commercial categories (crawler, JS agent, CSP-based), honest about where Blink is weaker.
- `docs/case-study.md`: written for hiring managers. Problem → design → trade-offs → numbers.
- **Release v2.5.0.**

---

## 4. Safety amendment (update `CLAUDE.md` in Phase 13)

The v2.0 rule "fixtures never read form values" is replaced by this narrower rule, which still forbids a functional skimmer:

- A fixture may **read** a payment field (to test `dataflow.field_read`) **only if** it discards the value immediately: no storage, no transmission, no derived data sent anywhere.
- A fixture may **send** a canary-shaped string (to test the matcher) **only** as a constant, or a value received from the test harness via a lab query parameter. It must **never** be read from a form field.
- **No single fixture both reads a field and transmits anything.** The `correlated_read_and_beacon` scenario uses two separate inert scripts: one reads and discards, the other beacons the constant `{"ping":1}`.
- Canary PANs are Luhn-valid numbers from reserved test ranges and are generated per run. Real card data never appears anywhere.
- Journeys never submit a real order: `submit` requires `test_mode: true`, and tests only target the lab.
- The cloaking work uses standard Playwright options only: no bot-protection bypass, no CAPTCHA solving, no fingerprint-spoofing plugins.
- The collector is the only component meant to be internet-facing. Everything else stays loopback by default.

---

## 5. Explicitly not doing (and why)
- **Script blocking or a proxy in the request path:** a liability on a merchant's revenue path. The CSP simulator + generator give the same outcome safely.
- **SaaS, multi-tenant, SSO:** a huge effort with low signal for the target roles.
- **Training an ML model on skimmer samples:** it needs malware corpora, and small-data models are weak. The measurable eval harness tells a stronger story.
- **Sentinel now:** waits for Azure; the ECS, Splunk and Sigma outputs cover the SOC story meanwhile.
- **Look-alike detection:** a separate product; it would dilute the narrative.

---

## 6. What each release adds to your job story

| Release | New talking points | Roles it strengthens |
|---|---|---|
| v2.1 | Trusted Publishing to PyPI, docs site, synthetic user journeys, automatic noise learning | Software, QA/test automation, DevOps |
| v2.2 | Runtime instrumentation via CDP, canary taint tracking with transform decoding, YARA, deobfuscation, cloaking detection | Security engineering, detection engineering, malware analysis, AppSec |
| v2.3 | Internet-facing Reporting API ingestion service with abuse controls; CSP rollout simulator | AppSec, networking, SRE |
| v2.4 | Threat-intel enrichment (RDAP, OSV, IoCs), library provenance (supply-chain security) | Threat intel, SOC, supply-chain security |
| v2.5 | Splunk/Elastic/OTel/Sigma, a signed forensic evidence bundle, an MCP server, LLM triage, a measured detection benchmark | SOC, IR/forensics, AI, all-round |

---

## 7. Kickoff prompt for Claude Code

> Read `BUILD_PLAN_2X.md` and `CLAUDE.md`. Execute Phases 13 through 15 in order (release v2.1.0), one branch and PR per phase, following every rule in `CLAUDE.md` and the safety amendment in BUILD_PLAN_2X.md §4 (apply it to CLAUDE.md first). For PyPI: prepare Trusted Publishing and a TestPyPI dry run, then stop and tell me the exact steps I need to do on pypi.org. Don't stop between phases otherwise.

Then run Phases 16–17 (v2.2), 18 (v2.3), 19 (v2.4) and 20–21 (v2.5) as separate sessions.

---

## 8. References
- PCI SSC, SAQ A update (6.4.3, 11.6.1 and 12.3.1 effective 31 March 2025): https://blog.pcisecuritystandards.org/important-updates-announced-for-merchants-validating-to-self-assessment-questionnaire-a
- Target Merry Maker (CSO Online): https://www.csoonline.com/article/3648359/target-shares-its-own-web-skimming-detection-tool-merry-maker-with-the-world.html
- Report URI CSP Integrity (`report-sha256`): https://report-uri.com/features/csp-integrity
- Chromium Intent to Ship, CSP hash reporting: https://groups.google.com/a/chromium.org/g/blink-dev/c/zPaPnwLZ1fc
- Sansec on skimmer evasion ("tripwire"): https://sansec.io/research/magecart-tripwire
- Sansec on the polyfill.io supply-chain attack: https://sansec.io/research/polyfill-supply-chain-attack
- c/side pricing (free tier reference point): https://cside.com/pricing
- OSV API: https://osv.dev/docs/
- RDAP (IANA bootstrap): https://data.iana.org/rdap/

# ADR 0001: Pivot Blink to payment page integrity monitoring

- **Status:** Accepted
- **Date:** 2026-11-27
- **Supersedes:** the 1.0 roadmap constraint "no accounts, databases, cloud services or AI"

## Context

Blink 1.0 is a well-engineered image comparison toolkit: a thresholded max-channel pixel
diff, SSIM, connected change regions, overlays and heatmaps, exposed through a Streamlit
workspace, a CLI with stable exit codes and a Python API.

An honest review of 1.0 found:

- **It is a commodity.** `pixelmatch`, ImageMagick `compare` and Playwright's
  `toHaveScreenshot()` already provide thresholded pixel and perceptual diffs for free.
- **It skips the hard part.** Real visual testing is hard because of capture: driving a
  browser, masking dynamic regions, handling animation, fonts and anti-aliasing. 1.0 expects
  the user to supply two pre-made images of identical size.
- **It has no workflow.** No baselines, no history, no approval of a new normal, no schedule.
- **Max-channel thresholding is naive** for anti-aliasing and JPEG noise.
- **The roadmap deliberately capped it** ("no accounts, databases, cloud services or AI").

At the same time, the engineering discipline is real and directly reusable: frozen
dataclasses, read-only NumPy arrays, int16 widening before subtraction, decompression-bomb
and size caps, `open('xb')` so evidence is never overwritten, a versioned JSON schema,
stable exit codes, loopback-only defaults and a cross-platform test suite. Its mindset
(never resize silently, never overwrite, produce reproducible proof) is exactly the mindset
needed for compliance evidence and detection engineering.

PCI DSS v4.0.1 Requirements 6.4.3 (payment page script inventory, authorization and
integrity) and 11.6.1 (detect unauthorized changes to payment page headers and content, at
least weekly, and alert personnel) became mandatory on 31 March 2025. Small and mid-size
merchants on SAQ A-EP or SAQ D need evidence for both and are often priced out of
commercial tooling. Magecart-style e-skimming attacks inject scripts, swap form actions or
overlay fake card forms; the last of these is visual and is missed by script-only tools.

Alternatives considered (see `BUILD_PLAN.md` section 2): a QA visual regression product
(too crowded), phishing look-alike detection (kept as a stretch module), manufacturing
defect inspection, document tamper forensics and a generic defacement monitor.

## Decision

Blink 2.0 becomes a **self-hosted, open-source payment page integrity monitor** that captures
checkout pages with a deterministic headless browser, compares them with an approved
baseline across several detectors (scripts, network, headers, forms, DOM, visual, TLS),
grades findings with declarative rules, alerts personnel and produces tamper-evident audit
evidence that *supports* 6.4.3 and 11.6.1 assessments.

- The 1.0 engine (`compare.py`, `analysis.py`, `render.py`, `workspace.py`) is kept
  API-stable and becomes the **visual detector**. `blink compare` keeps its 1.0 contract,
  enforced by a byte-for-byte golden test (`tests/test_golden_compare.py`).
- The 1.0 constraint against databases, cloud services and AI is retired. Its intent is
  preserved as defaults: local SQLite storage, loopback binding, no cloud account required,
  and every cloud (Sentinel) or AI (LLM triage, MCP) integration is an **optional extra that
  is off by default**.
- The package keeps the distribution name `blink-visual` and the `blink` executable.
- New code is held to a stricter bar than 1.0: ruff, strict mypy, bandit and pip-audit in CI.

## Consequences

- The positioning changes from "image diff script" to a security and compliance product.
  The README is rewritten in Phase 7.
- The project gains real dependencies (Playwright, FastAPI, pydantic, cryptography). They are
  grouped into extras (`[capture]`, `[server]`, `[sentinel]`, `[ai]`, `[mcp]`, `[lookalike]`)
  so `pip install blink-visual` stays light.
- Blink must be honest about its limits: an agentless periodic scanner sees what a scripted
  browser sees. It does not replace in-browser real-time protection or CSP reporting, can be
  evaded by cloaking skimmers, and does not make anyone compliant. These limits are documented
  in the threat model and README.
- The lab and test fixtures must never be functional skimmers (`BUILD_PLAN.md` section 5).

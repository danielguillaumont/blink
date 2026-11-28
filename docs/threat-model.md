# Blink 2.0 threat model

This document describes what Blink protects, who attacks it, how, and which attacks Blink
detects. It covers two scopes: the **monitored payment page** (the merchant's checkout) and
**Blink itself** (its evidence, keys and dashboard).

## 1. Assets

| Asset | Why it matters |
|---|---|
| Cardholder data entered on the payment page (PAN, expiry, CVC, name, address) | The target of e-skimming. Blink never reads, stores or transmits it. |
| Integrity of the payment page: scripts, HTTP headers, forms, DOM and rendering | Tampering with any of these is how cardholder data is stolen. |
| The approved script inventory (`blink.inventory.yaml`) | The authoritative record for PCI DSS 6.4.3: what may run and why. |
| Baselines and snapshots (`.blink/objects`, SQLite index) | Define "known good"; an attacker who can rebaseline can hide a skimmer. |
| Run history ledger and its ed25519 signing key | Proves evaluations happened (11.6.1 "at least weekly") and were not edited. |
| Alert channels (webhook, SMTP, syslog, Sentinel) | How personnel learn about tampering. |
| Dashboard bearer token | Authorizes approvals, alert state changes and accepting changes. |

## 2. Adversaries

| Adversary | Capability | Typical goal |
|---|---|---|
| **Magecart groups** | Exploit CMS/e-commerce plugins, steal admin credentials, inject code into page templates or first-party JS bundles | Skim card data at scale, often cloaking from scanners |
| **Compromised third-party provider / CDN** | Modify a script that the merchant loads from a third-party origin (analytics, chat, tag manager, A/B testing) | Supply-chain injection across many merchants at once |
| **Malicious or careless insider** | Legitimate access to the code base, tag manager or CDN configuration | Add an unapproved script, weaken CSP, or approve a malicious change |
| **Attacker targeting Blink** | Access to the host running Blink, or to its network path | Suppress alerts, rebaseline to hide tampering, edit history |

## 3. Attack paths against the payment page

| # | Attack path | Example | Blink signal |
|---|---|---|---|
| A1 | **Script injection** (new first- or third-party script, or inline script) | `<script src="https://cdn-analytics.example/x.js">` added to the checkout template | `scripts` detector: script added, inline script added, unapproved script (inventory), static JS risk score |
| A2 | **Supply-chain script swap** | Content of an approved third-party script changes at the same URL | `scripts`: hash changed for same URL; SRI missing or mismatched; inventory expected-hash violation (critical) |
| A3 | **Form-action hijack** | `<form action>` changed to an attacker origin, or a second form/new card-like inputs added | `forms`: action origin changed, new inputs with `cc-*` autocomplete or card-like names, method change |
| A4 | **Overlay iframe / fake form** | A positioned iframe or div with a fake card form drawn over the real one | `forms`: new or hidden/off-screen iframe; `dom`: payment-region structure change; `visual`: pixel change in the payment region |
| A5 | **Header weakening** | CSP removed, `unsafe-inline`/`unsafe-eval`/wildcards added, HSTS or framing protection dropped | `headers`: directive-level CSP diff and policy checks for CSP, HSTS, XFO/`frame-ancestors`, XCTO, Referrer-Policy, Permissions-Policy |
| A6 | **New exfiltration destination** | A script starts posting or beaconing to a new origin, or opens a WebSocket | `network`: new destination origin; POST/beacon/WebSocket rated higher |
| A7 | **Certificate or hosting change** | TLS certificate issuer or fingerprint changes unexpectedly | `tls`: issuer/fingerprint change, imminent expiry |

## 4. Attack paths against Blink itself

| # | Attack path | Mitigation |
|---|---|---|
| B1 | Edit or delete run history to hide a missed evaluation or an alert | Hash-chained ledger with a signed chain head; `blink verify-ledger` detects modification, deletion and reordering (Phase 4) |
| B2 | Rebaseline or approve a malicious script silently | Approvals require justification, owner and approver; accepting a change is recorded in the ledger with who and why; the inventory lives in git where it is code-reviewed |
| B3 | Abuse the dashboard to change state | Binds to 127.0.0.1 by default; bearer token for every non-GET endpoint; CSRF protection; strict CSP on Blink's own pages (Phase 5) |
| B4 | Steal secrets from evidence | Cookie values, `Authorization` headers and other secrets are never stored in snapshots, logs or reports; HAR is scrubbed before storage |
| B5 | Malicious page content attacks the scanner | Headless Chromium sandbox, fresh browser context per capture, no stored state, capture timeouts and size limits, decompression-bomb guards on images |
| B6 | Steal the ledger signing key | Key file written with 0600 permissions under `.blink/`, which is git-ignored; the public key is pinned outside the host (`blink verify-ledger --public-key`); Blink refuses to re-key a non-empty ledger silently. Key rotation is not yet automated (see `docs/progress.md`) |

## 5. What Blink covers and what it does not

**Covered**

- Changes visible to a scripted Chromium browser loading the page: script inventory and
  content hashes, SRI, network destinations, security headers, forms and iframes, payment
  region DOM structure and rendering, TLS certificate identity.
- An approved inventory with justifications and owners, and evidence that evaluations
  happened at least weekly, with alerts and their resolution.

**Not covered (honest limitations)**

- **Cloaking.** Skimmers that activate only for specific geographies, user agents, logged-in
  users, times of day or after a delay can evade an agentless scanner. Mitigation: rotate
  browser profiles and schedules, and deploy CSP `report-to` reporting from real users
  alongside Blink.
- **Real-time protection.** Blink is periodic. It detects tampering after the fact; it does
  not block a script in a customer's browser.
- **Server-side compromise** that does not change what the browser receives (for example,
  a backdoor in the payment processor integration).
- **Malware on customer devices** (browser extensions, infostealers).
- **Compliance.** Blink *supports* evidence for PCI DSS 6.4.3 and 11.6.1. It does not make a
  merchant compliant and is not an assessor's attestation.

## 6. Safety of Blink's own test lab

The lab triggers detection signals, not theft. Tamper fixtures never read form field values,
never serialize payment inputs and never send user-entered data. They send only constant
payloads (for example `{"ping":1}`) to localhost sinks, use only published test card numbers
as static placeholder text and bind to 127.0.0.1. See `BUILD_PLAN.md` section 5.

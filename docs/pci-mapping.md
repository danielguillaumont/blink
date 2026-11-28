# PCI DSS 6.4.3 and 11.6.1 mapping

This table maps each element of PCI DSS v4.0 requirements 6.4.3 and 11.6.1 to the Blink
feature that supports it and the evidence it produces. The requirement wording below is
**paraphrased**. Read the standard itself, and the PCI SSC guidance on these two requirements,
in the [PCI SSC document library](https://www.pcisecuritystandards.org/document_library/).

Blink produces evidence. Whether a requirement is met is decided by your QSA or internal
auditor, taking into account the whole environment, including controls Blink does not see.

## 6.4.3: scripts on payment pages are managed

| Element (paraphrased) | Blink feature | Evidence |
|---|---|---|
| A method confirms that each script on the payment page is authorized | `blink.inventory.yaml` approvals (`blink approve`, dashboard **Inventory**); the `inventory.unapproved` finding on every scan | Report §2 "Authorization" column (approver, date, ledger record); `inventory.approved` ledger records; unapproved-script findings in §5 |
| A method assures the integrity of each script | SHA-384 of every script body; pinned approvals (`inventory.hash_mismatch` is critical); SRI recorded and its removal reported; static-analysis risk score for dynamic scripts | Report §3 "Integrity method"; `scripts.hash_changed` and `inventory.hash_mismatch` findings; `blink suggest-csp` output for adding SRI/CSP |
| An inventory of all scripts is kept, with a written business or technical justification for each | `blink inventory --sync` builds it from observed scripts; each entry has `justification` and `owner` | Report §2 table; `blink.inventory.yaml` in version control; `blink inventory --check` in CI |

## 11.6.1: changes to payment pages are detected and alerted

| Element (paraphrased) | Blink feature | Evidence |
|---|---|---|
| A change- and tamper-detection mechanism alerts staff to unauthorized changes to security-impacting HTTP headers and to script contents of the payment page as the consumer's browser receives them | Headless Chromium capture; `headers`, `csp`, `scripts`, `inventory`, `network`, `dom` and `visual` detectors; the alert state machine with webhook, Slack, Teams, e-mail, syslog/CEF and JSONL sinks | Report §5 findings and how each was resolved; the alert history (`blink alerts show`); sink delivery and dead-letter records in the ledger |
| The mechanism evaluates the received headers and page | Each evaluation compares the page with the approved baseline | Report §4 per-run log; `run.scan` ledger records |
| It runs at least weekly, or at the frequency set by a targeted risk analysis | `blink daemon` (interval or cron, retries, jitter); `schedule.missed_evaluation` findings when the gap exceeds the allowed maximum (never more than a week) | Report §4 "longest gap" per target against its schedule and against a week; missed-evaluation findings |

## Supporting evidence

| Need | Blink feature | Evidence |
|---|---|---|
| The evidence has not been altered after the fact | Hash-chained ledger with an ed25519-signed head (`blink verify-ledger`) | Report §6; a failed-verification banner if anything was changed |
| The report itself has not been altered | Signed `report.json` sidecar with the hashes of the HTML and PDF | `blink verify-report report.json --public-key ledger_ed25519.pub` |
| Legitimate changes are distinguished from attacks | "Accept change" with a mandatory note (rebaselines), and inventory approvals | Report §5 resolution notes; `alert.accepted-change` and `baseline.set` ledger records |

## What Blink does not cover

- What visitors in other regions, or on other devices, received (see the report's
  limitations section).
- Prevention. A strict CSP and SRI on the payment page do that; `blink suggest-csp` helps
  write them.
- Payment pages hosted entirely by a third-party payment processor that you do not control.
  Requirement applicability there depends on the integration, so ask your assessor.

# Audit evidence report (`blink report`)

```bash
blink report                                   # last 90 days → ./blink-report/
blink report --since 2026-07-01 --until 2026-09-30 --out evidence/2026-Q3
blink report --no-pdf                          # HTML + report.json only (no browser needed)
blink report --public-key ledger_ed25519.pub   # verify the ledger against a pinned key
blink verify-report evidence/2026-Q3 --public-key ledger_ed25519.pub
```

`blink report` writes three files:

| File | What it is |
|---|---|
| `report.html` | A self-contained page: inline CSS, no scripts, no external resources, with a CSP that forbids them |
| `report.pdf` | The same page printed by headless Chromium (needs the `[capture]` extra; skip with `--no-pdf`) |
| `report.json` | The evidence model the HTML was rendered from, plus the SHA-256 of `report.html` and `report.pdf`, signed with the ledger's ed25519 key |

All three come from one evidence model, so they cannot disagree. Generating a report appends a
`report.generated` record to the ledger with the hashes, so later reports show that it existed.

## Sections

1. **Scope and targets**: each payment page, its browser profiles, schedule, the allowed gap
   between evaluations and the current approved baseline.
2. **Script inventory (6.4.3)**: every script with its business justification, owner, and how it
   was authorized: who approved it, when, and the ledger record of the approval. Approvals
   edited into `blink.inventory.yaml` by hand are flagged as having no ledger record. Scripts
   seen in baselines but missing from the inventory are listed separately.
3. **Integrity method (6.4.3)**: SHA-384/SRI hashing, pinned vs dynamic approvals, and counts.
4. **Evaluation log (11.6.1)**: every scan in the period for each target and profile, with
   status and max severity. It also gives the **longest gap** between successful evaluations,
   including the time from the last one to the end of the period, measured against both the
   configured schedule and a week.
5. **Findings and resolution**: each distinct finding (deduplicated by fingerprint), how often it
   was seen, its alert state, and who resolved or accepted it, when and with what note.
6. **Ledger verification and signature**: the result of `blink verify-ledger`, the signed head,
   its signature and the public key fingerprint. **If verification fails, a red banner opens
   the report and `blink report` exits 1**; the report is still written so the failure itself
   is on record.
7. **Methodology and limitations.**
8. **Disclaimer**: the report supports, but does not replace, assessor judgment.

## Verifying a report

`blink verify-report` checks the signature over `report.json` (canonical JSON without the
`signature` member) and that `report.html` and `report.pdf` next to it still match the signed
hashes. Without `--public-key` it can only use the key embedded in the report. That proves the
report was not modified, but not who signed it. Give auditors the ledger public key
(`.blink/keys/ledger_ed25519.pub`) through a separate channel and have them pass it with
`--public-key`.

Exit codes: `blink report` returns 0, or 1 if the ledger failed verification, or 2 for usage and
I/O errors, or 3 if Chromium cannot render the PDF. `blink verify-report` returns 0 if valid, 1
if not.

See [pci-mapping.md](pci-mapping.md) for how each requirement element maps to the report.

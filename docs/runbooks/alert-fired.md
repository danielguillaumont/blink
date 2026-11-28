# Runbook: an alert fired, now what?

Use this when Blink reports a high or critical finding on a payment page, for example a new or
changed script, a script that looks like a skimmer, a removed or weakened CSP, a new network
destination, or a form whose action changed. Assume it is an attack until a deploy explains
it.

## 0. First 15 minutes: triage

1. Open the finding: dashboard → **Alerts** → the alert, or `blink alerts show ALERT_ID`. Read
   "why it matters", the script diff, the static-analysis factors and the new network
   destinations.
2. **Acknowledge** it so others know someone is on it:
   `blink alerts ack ALERT_ID --by you --note "investigating"`.
3. Ask the owning team: was there a deploy, a tag-manager publish or a vendor update in the
   last day? Check the change calendar and the CI/CD history for the page.
   - **It was a known, reviewed change:** see [rebaselining.md](rebaselining.md). Stop here.
   - **Nobody can explain it within ~15 minutes, or the script reads form fields or sends data
     to a new origin:** treat it as a **suspected skimmer** and continue.

## 1. Preserve evidence (before changing anything)

Removing the script destroys the best evidence. First:

```bash
blink scan TARGET --json --output evidence/$(date -u +%Y%m%dT%H%MZ)-scan.json   # fresh capture
blink report --since <a week before> --out evidence/incident-report                 # signed pack
blink verify-ledger --json > evidence/ledger.json
```

- Keep the `.blink/` store. It holds the script bodies (content-addressed by SHA-256), the
  scrubbed HAR and the screenshots. Copy it to write-once storage, and do not delete
  snapshots.
- Record the script URL, its SHA-384, where it was injected (first-party file, tag manager,
  third-party CDN) and the exfiltration destination, if any.
- Save web server, CDN and WAF logs covering the time window, plus the deployment and
  tag-manager audit logs.

## 2. Contain

- Remove the malicious script at its source: revert the commit, unpublish the tag-manager
  version, or remove the compromised third-party include.
- If the source is not yet known, block the destination at the edge (WAF/CDN rule) and
  consider taking the payment page offline or switching to a hosted payment page until it is
  clean.
- Tighten CSP to the approved inventory (`blink suggest-csp TARGET`) and add SRI to
  third-party scripts so a re-injection is blocked, not just detected.
- Run `blink scan TARGET` and confirm the finding is gone.

## 3. Eradicate and rotate

- Find the entry point: a compromised CMS or admin account, a leaked deploy token, a
  compromised third-party vendor, or a dependency.
- Rotate credentials that could have allowed the change: CMS/admin passwords, CI/CD and
  deploy tokens, tag-manager accounts, CDN and storage keys, and API keys exposed on the page.
- If the Blink host itself may be compromised, rotate the dashboard token (delete
  `.blink/blink.token` and restart `blink serve`) and check the ledger against the pinned
  public key: `blink verify-ledger --public-key ledger_ed25519.pub`.

## 4. Notify

Follow your incident response plan (PCI DSS requirement 12.10). For a suspected compromise of
payment data this typically means:

- the internal incident lead, security, legal and privacy;
- your **acquirer** (merchant bank) and payment processor, within the time your agreement
  requires, because they drive the card-brand forensic process (PFI) where applicable;
- law enforcement and data-protection regulators where required.

Do not contact the attacker's infrastructure, and do not "test" the exfiltration endpoint.

## 5. Close out

1. Resolve the alert with what was done:
   `blink alerts resolve ALERT_ID --by you --note "INC-2026-014: removed injected tag, rotated GTM creds"`.
2. Re-approve the inventory if it changed (`blink approve …`). Record a new baseline **only
   after** the page is verified clean (`blink baseline TARGET --reason "post INC-2026-014"`).
3. Generate a report covering the incident window. Its findings section shows detection time,
   acknowledgement and resolution for the post-incident review and your assessor.
4. Run a blameless review covering how it got in, why it was not prevented (CSP, SRI, access
   control) and how long detection took.

# Runbook: rebaselining after a legitimate deploy

A reviewed release changed the payment page (a new script version, a new vendor, a CSP
update) and Blink raised findings for it. Rebaselining tells Blink "this is the new
known-good". Every step is recorded in the ledger, so the audit trail shows who accepted what
and why.

Only rebaseline changes you can tie to a change ticket or deploy. If you cannot, follow
[alert-fired.md](alert-fired.md) instead.

## Option A: accept the change from the alert (one target, one change)

```bash
blink alerts list --state open
blink alerts accept ALERT_ID --by alice --note "CHG-1234: checkout v2.8 deploy"
```

Or click **Accept change** in the dashboard's Alerts page. A note is required. Accepting
records the run's current snapshot as the new baseline for that target and profile, and
ledgers `alert.accepted-change` and `baseline.set`.

## Option B: rebaseline after a release (several targets or many changes)

1. **Approve new or changed scripts** in the inventory first, so the next scans are clean
   for the right reason:

   ```bash
   blink inventory                       # what is unapproved or changed
   blink approve app-checkout-js --justification "Checkout UI" --owner web \
       --approved-by alice               # re-pins the new hash
   blink approve cdn-vendor-widget-js --justification "Card widget (vendor X)" \
       --owner payments --approved-by alice --dynamic   # vendor-managed, changes often
   git add blink.inventory.yaml && git commit -m "inventory: checkout v2.8"
   ```

   Use `--dynamic` only for scripts whose content you cannot control (vendor-hosted, with
   versioned releases). Their changes are still reported, at lower severity, with a
   static-analysis score.

2. **Check the page is what you expect**: open the latest run in the dashboard and look at
   the screenshots, the script diff and the headers.

3. **Record the baseline** with the change reference:

   ```bash
   blink baseline checkout --reason "CHG-1234: checkout v2.8"
   ```

4. **Resolve the alerts** the deploy caused:

   ```bash
   blink alerts resolve ALERT_ID --by alice --note "CHG-1234, rebaselined"
   ```

5. **Confirm**: `blink scan checkout --fail-on medium` should now pass.

## Avoiding rebaseline churn

- Make noisy elements volatile instead of rebaselining every day. Add CSRF tokens,
  timestamps and A/B banners to `normalize` / `masks` in `blink.yaml` (see
  [configuration.md](../configuration.md)).
- For a tag manager that changes often, approve the container script as dynamic and govern
  what it loads with CSP. Do not rebaseline blindly.
- In CI, run the [GitHub Action](https://github.com/danielguillaumont/blink/blob/main/action.yml) against staging so changes are approved
  before they reach production.

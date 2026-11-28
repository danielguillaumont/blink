# Script inventory, approvals and static JS risk (PCI DSS 6.4.3)

PCI DSS 6.4.3 asks that every script on a payment page is authorized, its integrity is
assured, and an inventory is kept with a written justification for each script. Blink keeps
that inventory in `blink.inventory.yaml`, next to `blink.yaml`. **Commit it**: code review of
the file is your authorization trail.

## Workflow

```bash
blink baseline checkout                 # capture a known-good snapshot
blink inventory --sync                  # add every script seen to the inventory, unapproved
blink inventory                         # list scripts, approval state and risk score
blink approve 127-0-0-1-9100-static-app-js \
    --justification "Checkout UI and validation" --owner web-team
blink approve cdn-example-tag-js --dynamic \
    --justification "Tag manager; vendor updates content weekly" --owner marketing
blink inventory --check                 # exit 1 while any script is unapproved (CI gate)
blink suggest-csp checkout              # CSP + SRI from the approved inventory
```

`blink approve` records `approved_by` (default: the current OS user; override with
`--approved-by`) and `approved_at` (UTC). A justification and an owner are mandatory.
An id printed by `blink inventory` or by an `inventory.unapproved` finding can be approved
directly, even if it is not yet in the file.

## File format

```yaml
version: 1
scripts:
  - id: 127-0-0-1-9100-static-app-js    # stable id, lowercase letters, digits and dashes
    type: first-party                   # first-party | third-party | inline
    url: http://127.0.0.1:9100/static/app.js
    url_pattern: null                   # optional full-match regex for rotating URLs
    inline_sha384: null                 # for inline scripts: the digest identifies the script
    expected_hash: sha384-...           # pinned content hash, or "dynamic"
    sri: null                           # the integrity attribute used on the page, if any
    justification: Checkout UI and validation
    owner: web-team
    approved_by: alice
    approved_at: '2026-11-27T12:00:00Z'
    notes: ''
```

An entry is *approved* only when it has a justification, an owner, `approved_by` and
`approved_at`.

## What scans report

| Finding | Default severity | When |
|---|---|---|
| `inventory.hash_mismatch` | critical | An approved script with a pinned `expected_hash` now has other content |
| `inventory.unapproved` | high | A script that is not approved appeared since the baseline |
| `inventory.unapproved` | medium | A script that was already in the baseline is still not approved |
| `scripts.hash_changed` | low | The content of a script approved as `dynamic` changed |
| `scripts.added` / `inline_added` / `hash_changed` | critical | Static risk score ≥ 70 |

An unapproved script is a finding on **every** scan, not only when it is new. Without a
`blink.inventory.yaml` file, no inventory findings are produced.

## Static JS risk score

For every new or changed script, Blink parses the stored body with tree-sitter (it never runs
it) and computes a 0–100 risk score from weighted heuristics. The factors, with examples and
line numbers, are attached to the finding as `evidence.static_analysis`.

| Factor | Weight | Pattern |
|---|---|---|
| `read_and_send` | 35 | Field `.value` or `FormData` read and a `fetch`, `sendBeacon`, `XMLHttpRequest`, `WebSocket` or `new Image()` in the **same function** |
| `dynamic_code` | 25 | `eval`, `new Function`, string `setTimeout`/`setInterval` |
| `payment_field_listeners` | 20 | `input`/`change`/`key*`/`blur`/`paste` listeners in a function that names payment fields |
| `obfuscator_identifiers` | 20 | Five or more `_0x…` identifiers |
| `string_array_rotation` | 20 | `arr.push(arr.shift())` over a large string array |
| `decode_chain` | 15 (5 alone) | `atob`, `unescape`, `String.fromCharCode` over literal code points |
| `dynamic_script_element` | 15 | `document.createElement("script")` |
| `high_entropy_strings` | 5 each, max 15 | Long random-looking literals |
| `payment_field_references` | 10 | Payment field names, without listeners |

Calibration: production builds of jQuery 3.7.1, React 18.3.1 and React DOM 18.3.1 score below
30 (see `tests/test_jsanalysis.py`; the corpus is fetched with `python scripts/fetch_js_corpus.py`).
The score is a triage aid, not a verdict: obfuscated but benign code can score high, and a
careful attacker can avoid these patterns. Integrity pinning in the inventory is the control;
the score helps decide how urgently to look.

On some hosts the antivirus refuses to write a captured script that looks malicious. Blink
then keeps the script's hash, skips the risk score and adds a warning to the snapshot.

## `blink suggest-csp`

Builds a starting policy from the approved inventory and the baseline:

- `script-src`: `'self'` for approved first-party scripts, the origin of each approved
  third-party script, and the `'sha384-…'` hash of each approved inline script;
- `connect-src`: `'self'` plus the origins of fetch, XHR, beacon, WebSocket and EventSource
  requests in the baseline;
- `object-src 'none'; base-uri 'self'; frame-ancestors 'none'`;
- `<script … integrity=… crossorigin="anonymous">` tags for pinned scripts.

Unapproved scripts are listed as notes, never allowed. Deploy the result as
`Content-Security-Policy-Report-Only` first.

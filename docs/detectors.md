# Detectors, findings and rules

`blink scan` captures each target/profile, loads its baseline snapshot and runs seven
detectors. Each detector reports *findings* (what changed, with evidence); the rule engine
then assigns a severity (`info < low < medium < high < critical`) and a "why it matters"
explanation. `--fail-on SEVERITY` (default `high`) sets the exit-code gate.

| Exit code | Meaning |
|---|---|
| 0 | No finding at or above `--fail-on` (or `--fail-on none`) |
| 1 | At least one finding at or above `--fail-on` |
| 2 | Usage or configuration error, or a target/profile has no baseline |
| 3 | A capture failed (target unreachable or timed out) |

## Detectors

| Detector | Change types | Highlights |
|---|---|---|
| `scripts` | `added`, `inline_added`, `hash_changed`, `sri_missing`, `sri_mismatch`, `removed` | Scripts are keyed by URL (external) or SHA-384 (inline). SRI is verified per the spec: only the strongest algorithm in `integrity` counts. |
| `network` | `new_destination`, `destination_removed` | Destinations are origins (scheme, host, port). `sends_data` is true for non-GET requests, beacons, WebSockets and EventSource. Query strings are dropped from evidence. |
| `headers` | `csp_removed`, `csp_weakened`, `csp_weakness`, `csp_changed`, `csp_missing`, `header_removed`, `header_added`, `header_changed`, `header_missing` | CSP is parsed per directive. Nonces are normalized. *New* weaknesses (`unsafe-inline`, `unsafe-eval`, wildcard sources, no script policy) are `csp_weakened`; weaknesses already in the baseline are `csp_weakness`. Also HSTS, X-Frame-Options (or CSP `frame-ancestors`), X-Content-Type-Options, Referrer-Policy and Permissions-Policy. |
| `forms` | `action_changed`, `action_path_changed`, `method_changed`, `form_added`, `form_removed`, `input_added`, `iframe_added`, `iframe_removed` | Card-like fields: `autocomplete="cc-*"` or names such as `card`, `cvv`, `exp-date`. Flags forms and iframes that overlap the payment region, and hidden or off-screen iframes. |
| `dom` | `region_changed`, `region_missing` | A tree-edit summary of the normalized payment region: elements added, removed, attribute and text changes, and "sensitive" additions (script, iframe, form, input, object, embed). |
| `visual` | `region_changed` | The Blink 1.0 engine (`analyze_pixels`) on the masked payment-region screenshots, with the `visual:` threshold and minimum region size from `blink.yaml`. Evidence includes the 1.0 overlay and heatmap. Different sizes are compared on their overlap and flagged `resized`. |
| `tls` | `issuer_changed`, `certificate_changed`, `untrusted`, `expiring`, `tls_error` | HTTPS targets only. Expiry warns under 14 days. |

A detector that crashes produces a `blink.detector_failed` finding instead of hiding changes.

## Rules

Default rules ship in `src/blink_visual/rules/default_rules.yaml`. To override them, point
`rules:` in `blink.yaml` at your own file; its rules are evaluated first and the first match
wins.

```yaml
version: 1
rules:
  - id: acme.analytics-cdn
    detector: scripts
    change_type: added
    when:
      cross_origin: true
      has_sri: true
    severity: medium
    why: Our analytics vendor ships new scripts weekly, always with SRI.
```

Conditions match finding attributes by equality or with operators `eq`, `ne`, `gt`, `gte`,
`lt`, `lte`, `in`, `not_in` and `exists`. Unmatched findings default to `medium`.

## JSON report (schema v2)

`blink scan --json` prints a report that validates against
[`docs/schemas/findings-v2.schema.json`](schemas/findings-v2.schema.json). Every finding has a
stable `fingerprint` (target, profile, detector, change type, subject) used to deduplicate
alerts across runs, and a short `id` (its first 16 hex characters). `--output FILE` also writes
the report to a new file and never overwrites an existing one.

Schema v1 remains the `blink compare` report.

## Known limitations

- With several CSP policies in one response, the first definition of each directive is used.
- The DOM detector compares element order; moving an element is reported as one removal plus
  one addition.

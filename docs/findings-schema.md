# Findings schema

`blink scan --json` and every alert sink emit findings in a stable, versioned format. The JSON
Schema is published with the docs:

- [`findings-v2.schema.json`](schemas/findings-v2.schema.json) (JSON Schema draft 2020-12)

The schema is checked in CI: the end-to-end tests (`tests/test_scan_e2e.py`,
`tests/test_inventory_e2e.py`) validate real `blink scan --json` output against it, so the
schema and the code can't drift apart. Fields are only ever **added** within `v2`; a
breaking change would publish `findings-v3.schema.json` alongside it.

A report has a header (`schema_version`, `run_id`, `blink_version`, timings, the `fail_on`
gate and its result, a `summary`, per-target results) and a list of `findings`. Each finding
carries:

| Field | Meaning |
|---|---|
| `id`, `fingerprint` | The finding in this run, and its stable identity across runs (alerts are deduplicated on it) |
| `target`, `profile` | Where it was seen |
| `detector`, `change_type` | Which detector found it and what changed, e.g. `scripts` / `added` |
| `severity` | `info`, `low`, `medium`, `high` or `critical`, after the rule engine |
| `rule_id` | The severity rule that graded it |
| `title`, `why` | Human-readable summary and why it matters |
| `subject`, `attributes` | What changed (a script, header, form...) and its properties |
| `evidence` | Detector-specific structured evidence (URLs, hashes, diffs, blob digests) |

See [detectors](detectors.md) for every `type`.

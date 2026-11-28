# Install and first scan

## Install

Blink needs Python 3.11 or newer. [pipx](https://pipx.pypa.io/) keeps it in its own
environment:

```bash
pipx install "blink-checkout[capture,server]"
blink doctor
```

`blink doctor` checks Python, the installed extras, Chromium, the configuration, the evidence
store, the ledger key and the baselines. Every failed check comes with the command that fixes
it. Chromium is the usual first fix: `blink doctor` prints the exact
`... -m playwright install chromium` command for the environment Blink is installed in. On
Linux, add `--with-deps` to install the system libraries.

| Extra | Adds |
|---|---|
| `capture` | Playwright and Chromium capture: `baseline`, `scan`, `capture`, report PDFs |
| `server` | `serve` (dashboard and API), `daemon` (scheduler and metrics), `lab` |

The PyPI distribution is called `blink-checkout`; the command is `blink` and the Python package
is `blink_visual` ([ADR 0005](adr/0005-distribution-name-blink-checkout.md)). A container image
is published as `ghcr.io/danielguillaumont/blink`.

## Try it on the lab first

The lab is a deliberately tamperable shop that runs on `127.0.0.1`:

```bash
blink lab &                        # shop on :8780, CDN on :8781, sink on :8782
mkdir lab-demo && cd lab-demo
blink init --lab                   # a blink.yaml pointing at the lab
blink baseline
blink inventory --sync             # list the lab's scripts in blink.inventory.yaml
blink inventory                    # note the ids, then approve them:
blink approve ID [ID ...] --justification "Lab checkout script" --owner you
blink lab --scenario new_third_party_script    # tamper with the checkout
blink scan                         # exit 1: a new cross-origin script, no SRI, not approved
blink report --days 1              # signed HTML, PDF and report.json in blink-report/
```

See [the lab](lab.md) for every scenario.

## Monitor a real checkout

```bash
blink init --url https://staging.shop.example/checkout
```

Then edit `blink.yaml`:

- `payment_region`: a selector for the payment form, for the visual and DOM detectors;
- `wait_for`: a selector that is present once the payment form is ready;
- `masks` and `normalize`: values that legitimately change on every load;
- `proxy` and `auth`: settings for a staging site behind a proxy, basic auth or a bypass header (see
  [configuration](configuration.md#proxies-and-protected-targets)).

```bash
blink doctor                       # config, store, keys and missing baselines
blink baseline
blink inventory --sync             # draft the script inventory, then approve each script
blink scan --fail-on high
blink daemon --metrics-port 9464   # scheduled scans, alerts, missed-run detection
blink serve                        # dashboard on http://127.0.0.1:8765
```

Read [operations](operations.md) for scheduling and alert sinks, and the
[runbooks](runbooks/alert-fired.md) for what to do when an alert fires.

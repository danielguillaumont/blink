# Blink

**See what changed on your payment page.** Blink is a self-hosted monitor for e-commerce
checkout pages. It loads the page the way a customer's browser does, inventories and hashes
every script, checks the security headers, the payment form and what the page looks like, and
alerts you when something changes. It also produces the signed evidence a PCI DSS assessor asks
for under requirements **6.4.3** (script management) and **11.6.1** (change and tamper
detection).

```bash
pipx install "blink-checkout[capture,server]"
blink doctor                                   # checks Python, Chromium, config, store and keys
blink init --url https://staging.example.com/checkout
blink baseline && blink inventory --sync
blink scan --fail-on high
```

<div class="grid cards" markdown>

- **[Install and first scan](getting-started.md)**: from `pipx install` to a signed report.
- **[Configuration](configuration.md)**: every key in `blink.yaml`, including proxies and
  protected staging targets.
- **[Detectors](detectors.md)**: what each finding means and how severities are graded.
- **[Sample signed report](sample-report.md)**: the evidence pack, generated from the lab on
  every docs build.
- **[Findings schema](findings-schema.md)**: the published JSON Schema for `blink scan --json`.
- **[PCI DSS mapping](pci-mapping.md)**: how the evidence lines up with 6.4.3 and 11.6.1.

</div>

Blink is open source (MIT) and runs entirely on infrastructure you control. Nothing leaves
your network except the page loads themselves. The source, issues and releases are on
[GitHub](https://github.com/danielguillaumont/blink).

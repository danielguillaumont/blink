# Sample signed report

Every docs build runs Blink against the [lab](lab.md): it records a baseline, approves the
inventory, injects a third-party script (`new_third_party_script`), scans, and writes the audit
report. The output is published unchanged:

- [report.html](https://danielguillaumont.github.io/blink/sample-report/report.html): the
  self-contained HTML report
- [report.pdf](https://danielguillaumont.github.io/blink/sample-report/report.pdf): the same
  report as a PDF
- [report.json](https://danielguillaumont.github.io/blink/sample-report/report.json): the
  machine-readable sidecar, signed with the ledger key
- [ledger_ed25519.pub](https://danielguillaumont.github.io/blink/sample-report/ledger_ed25519.pub):
  the public key that verifies it
- [verify.txt](https://danielguillaumont.github.io/blink/sample-report/verify.txt): the output
  of `blink verify-report` from the build

## Verify it yourself

```bash
base=https://danielguillaumont.github.io/blink/sample-report
mkdir sample && cd sample
for f in report.html report.pdf report.json ledger_ed25519.pub; do curl -sSfO "$base/$f"; done
blink verify-report report.json --public-key ledger_ed25519.pub
```

`verify-report` checks the ed25519 signature over the canonical JSON and the SHA-256 of the HTML
and PDF listed in `artifacts`. Change one byte of `report.html` and it fails.

!!! note
    The sample uses a throwaway key generated in CI, so the signature only shows that the files
    are unchanged since that build. In a real deployment, record your ledger public key outside
    the Blink host (`blink init` prints it) and verify against that.

See [audit report](report.md) for what each section contains, and
[PCI DSS mapping](pci-mapping.md) for how it supports 6.4.3 and 11.6.1.

# Roadmap

Blink 1.0 (BL01–BL05) shipped a local-first image comparison toolkit. Blink 2.0 repositions
the project as a self-hosted **payment page integrity monitor** for PCI DSS v4.0.1
Requirements 6.4.3 and 11.6.1.

The roadmap, phases and acceptance criteria now live in [`BUILD_PLAN.md`](https://github.com/danielguillaumont/blink/blob/main/BUILD_PLAN.md).
Delivery status per phase is tracked in [`docs/progress.md`](progress.md), and the reasoning
behind the change of direction is recorded in
[ADR 0001](adr/0001-pivot-to-payment-page-integrity.md).

The 1.0 constraint "no accounts, databases, cloud services or AI" is retired by that ADR.
Its intent survives as defaults: Blink runs locally, binds to loopback, needs no cloud
account, and every cloud or AI integration is an optional extra that is off by default.

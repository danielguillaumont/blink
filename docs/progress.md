# Blink 2.0 progress

Status of each phase in [`BUILD_PLAN.md`](../BUILD_PLAN.md). One branch and one PR per phase.

## Phase 0: Reset and hygiene

- **Date:** 2026-11-27
- **PR:** #5
- **Delivered:** pivot ADR (`docs/adr/0001-pivot-to-payment-page-integrity.md`), roadmap pointer,
  threat model (`docs/threat-model.md`); ruff, strict mypy on new code, pytest-cov, bandit,
  pip-audit and pre-commit, all enforced in CI; version `2.0.0.dev0` with the planned extras;
  byte-for-byte golden test of the 1.0 `blink compare` contract.
- **Known gaps:** the plan cites 83 existing tests; the 1.0.0 release actually had 89, all passing.
  PNG evidence in the golden test is compared by decoded pixels rather than file bytes, since PNG
  compression can legitimately differ between Pillow/zlib builds.

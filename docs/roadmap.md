# Blink development checkpoints

Goal: one useful, small local-first visual comparison product. Do not add accounts, databases, cloud services or AI.

- BL01 — Foundation: Python package, pixel difference mask, numerical tests, deterministic image fixture, CI and working brand. Verify locally and in GitHub before advancing.
- BL02 — Engine: explicit image normalization policy (including transparency), size/error handling, SSIM, connected components, difference overlay and heatmap, edge-case tests. Do not silently resize mismatched images.
- BL03 — Workspace: local Streamlit UI, upload pair, threshold control, before/after and difference views, split/blink interactions if achievable without large custom infrastructure. Keep an accessible manual toggle fallback.
- BL04 — Toolkit: CLI, PNG/JSON export, documented failure threshold and stable exit codes, packaging verification.
- BL05 — Release: real screenshots, clear README, full tests and CI, tagged GitHub release. Verify PyPI distribution name only if publishing there.

Brand: Blink. / See what changed. Carbon #141414, Canvas #F4F4F2, Lime #C6F65C, Difference #FF527B.

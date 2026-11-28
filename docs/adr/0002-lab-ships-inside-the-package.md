# ADR 0002: The lab ships inside the package as `blink_visual.lab`

- **Status:** Accepted
- **Date:** 2026-11-27

## Context

`BUILD_PLAN.md` section 4 places the demo shop in a top-level `lab/` directory
("test-only, localhost-only"). The same plan also makes the lab a user-facing command,
`blink lab [--scenario NAME]`, uses it in the 60-second Docker demo (Phase 7) and in the
evaluation harness (Phase 9). A top-level directory outside `src/` is not part of the
installed wheel, so `blink lab` would only work from a source checkout and the Docker image
would need to copy files that the package cannot import.

## Decision

The lab lives at `src/blink_visual/lab/` and is installed with the package. Its HTML, CSS and
JavaScript fixtures are package data under `blink_visual/lab/assets/`. Running it needs the
`[server]` extra (FastAPI and uvicorn).

The "test-only, localhost-only" intent is enforced in code rather than by location:

- `Lab` refuses to bind to any non-loopback address (`tests/test_lab.py`).
- All fixtures follow `BUILD_PLAN.md` section 5, and a test statically scans every lab script
  for forbidden patterns (field value reads, `FormData`, input listeners, XHR/WebSocket,
  `new Image`, `eval`, cookie access) and checks that beacons only send the constant
  payload `{"ping":1}`.
- Only the published test card number 4242 4242 4242 4242 appears, as placeholder text,
  and a test asserts this for every scenario.

## Consequences

- `blink lab` works from `pip install "blink-visual[server]"` and inside the Docker image.
- The wheel grows by a few kilobytes of inert fixtures.

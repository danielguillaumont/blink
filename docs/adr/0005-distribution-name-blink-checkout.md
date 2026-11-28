# ADR 0005: Publish the distribution as `blink-checkout`, with Trusted Publishing

- **Status:** accepted
- **Date:** 2026-11-28
- **Phase:** 13

## Context

Blink 2.0 was installable only from Git. The distribution name `blink-visual` dates from 1.0,
an image-diff tool, and no longer describes a payment-page integrity monitor. `blink` itself is
taken on PyPI. On 2026-11-28 neither `blink-visual` nor `blink-checkout` existed on PyPI or
TestPyPI (`https://pypi.org/pypi/<name>/json` returned 404), so nothing had been published
under the old name and renaming breaks no installed base.

## Decision

- Publish the distribution as **`blink-checkout`**. The import package stays `blink_visual` and
  the executable stays `blink`, so code, entry points and the 1.0 `blink compare` contract are
  unchanged. The name lives in one constant, `blink_visual._meta.DIST_NAME`, which `--version`,
  scan reports and "install the extra" hints use.
- Publish with **PyPI Trusted Publishing** (GitHub OIDC). No API token is stored in repository
  secrets. `.github/workflows/pypi.yml` builds once and then runs:
  1. a **dry run** that always runs: `twine check --strict`, then `pipx install` of the built
     wheel with `[capture,server]` in a clean environment, plus `blink --version` and
     `blink doctor`;
  2. **TestPyPI**, only when the repository variable `TESTPYPI_PUBLISH` is `true`, followed by
     a clean `pipx install` from TestPyPI;
  3. **PyPI**, only for a tag push when `PYPI_PUBLISH` is `true`.
- Until the maintainer has created the projects and trusted publishers (see
  [releasing.md](../releasing.md)), those variables are unset, so the publish jobs show as
  *skipped* and a release tag still produces a green run.

## Consequences

- Users install with `pipx install "blink-checkout[capture,server]"`. Importing
  `blink_visual` in Python code is unchanged.
- An editable install made before this change has to be reinstalled
  (`pip uninstall blink-visual && pip install -e .`), because the metadata name changed.
- Publishing needs a one-time manual setup on pypi.org and test.pypi.org. A workflow can't
  create a PyPI project for itself.
- The `blink-visual` name is left unregistered. Squatting on it would protect nothing, because
  nothing depends on it.

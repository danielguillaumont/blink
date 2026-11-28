# Releasing

A release is a version tag `vX.Y.Z` on `main` whose version matches `pyproject.toml`. Pushing
the tag starts three workflows:

| Workflow | What it does |
|---|---|
| `release.yml` | sdist and wheel, CycloneDX SBOM, pip-audit report, a GitHub release with those files, and the GHCR image |
| `pypi.yml` | build → dry run (clean `pipx install` of the wheel) → TestPyPI → PyPI, publish jobs gated (below) |
| `docs.yml` | rebuilds the docs site on GitHub Pages (also runs on every push to `main`) |

```bash
git checkout main && git pull
# bump [project].version in pyproject.toml through a PR first, then:
git tag -a v2.1.0 -m "Blink v2.1.0" && git push origin v2.1.0
```

To rebuild an existing tag (for example after fixing a workflow), run the workflow by hand with
`gh workflow run release.yml -f tag=v2.1.0` (or `pypi.yml`).

## PyPI with Trusted Publishing (one-time setup)

Blink publishes as **`blink-checkout`** (ADR 0005) using
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/): PyPI trusts a short-lived
OIDC token from this repository's `pypi.yml` workflow, so no API token is stored anywhere.
Until the steps below are done, `pypi.yml` runs only its dry run and **skips** the publish jobs,
so release tags stay green.

### 1. TestPyPI

1. Sign in at <https://test.pypi.org> (TestPyPI accounts are separate from PyPI accounts) and
   enable 2FA.
2. Go to **Your account → Publishing → Add a new pending publisher**, choose **GitHub**, and
   enter exactly:

   | Field | Value |
   |---|---|
   | PyPI project name | `blink-checkout` |
   | Owner | `danielguillaumont` |
   | Repository name | `blink` |
   | Workflow name | `pypi.yml` |
   | Environment name | `testpypi` |

3. In GitHub, go to **Settings → Environments → New environment** and create `testpypi`. No
   secrets are needed.
4. In GitHub, go to **Settings → Secrets and variables → Actions → Variables → New repository
   variable** and add `TESTPYPI_PUBLISH` with the value `true`.
5. Publish the current release to TestPyPI and check the clean install:

   ```bash
   gh workflow run pypi.yml -f tag=v2.1.0      # or the latest tag
   gh run watch "$(gh run list --workflow pypi.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
   ```

   The jobs **Publish to TestPyPI** and **Clean install from TestPyPI** must be green. The
   pending publisher becomes a normal one on the first upload.

### 2. PyPI

1. Sign in at <https://pypi.org> and enable 2FA.
2. Go to **Your account → Publishing → Add a new pending publisher → GitHub**, using the same
   values as above except **Environment name** `pypi`.
3. Create a GitHub environment `pypi`. Recommended: under **Deployment protection rules**, add
   yourself as a **required reviewer**, so every PyPI upload waits for your approval.
4. Add the repository variable `PYPI_PUBLISH` with the value `true`.
5. PyPI publishing happens only on a **tag push**, because PyPI versions can't be overwritten.
   Publish the next release by pushing its tag. To publish a tag that already exists, delete
   and re-push it **only if** its GitHub release can be regenerated:

   ```bash
   git push origin :refs/tags/v2.1.0 && git push origin v2.1.0
   ```

   Otherwise wait for the next version.
6. Check the result:

   ```bash
   pipx install "blink-checkout[capture,server]"
   blink doctor          # prints the exact command that installs Chromium for this install
   ```

### Turning it off

Delete or set to anything except `true` the variables `TESTPYPI_PUBLISH` / `PYPI_PUBLISH`. The
publish jobs are then skipped again. Removing the trusted publisher on PyPI revokes the
workflow's ability to upload.

## Installing Chromium under pipx

pipx keeps Blink in its own virtual environment, so Chromium has to be installed with that
environment's Python. `blink doctor` prints the exact command, using the interpreter Blink runs
in:

```text
FAIL  chromium  Chromium is not installed (expected ...)
      fix: "/home/you/.local/share/pipx/venvs/blink-checkout/bin/python" -m playwright install chromium
```

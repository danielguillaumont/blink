# CLAUDE.md: operating rules for building Blink 2.0

You are building Blink 2.0 autonomously from `BUILD_PLAN.md`. Read it fully before starting. It is the source of truth; if you need to deviate, write an ADR in `docs/adr/` explaining why, then continue.

## Workflow
- Work **one phase at a time, in order**. For each phase:
  1. `git checkout main && git pull`, then create branch `phase-N-short-name`.
  2. Implement in small, logical commits (Conventional Commits: `feat:`, `fix:`, `test:`, `docs:`, `ci:`, `refactor:`).
  3. Run the full local check (below). Fix until green.
  4. Push and open a PR titled `Phase N: <name>` whose body lists each acceptance criterion with ✅ and the command or test proving it.
  5. Wait for CI. If CI fails, fix on the same branch. Merge (squash) only when CI is green.
  6. Update `docs/progress.md` (phase, date, what was delivered, known gaps), then move to the next phase.
- If an acceptance criterion is impossible in this environment (for example, no Azure CLI), mark it skipped with a pytest marker and a reason, note it in the PR and `docs/progress.md`, and continue. Don't silently drop it.
- **Stop and ask the human** only if: a phase needs paid cloud resources or real credentials; a change would break the 1.0 `blink compare` contract; or CI has failed 3 times on the same issue.

## Local check (must pass before every push)
```bash
ruff check . && ruff format --check .
mypy src/blink_visual --exclude 'src/blink_visual/(compare|analysis|render|workspace|cli)\.py'
pytest -q --cov=src/blink_visual --cov-report=term-missing
bandit -q -r src
pip-audit
```

## Git and attribution
- **Do not add Claude, Anthropic or any AI as an author, co-author or contributor.** No `Co-Authored-By` trailers, no "Generated with Claude Code" lines in commits, PR descriptions, README, CHANGELOG or anywhere else.
- Never force-push `main`. Never commit `.blink/`, keys, tokens or `.env` files; keep `.gitignore` updated.

## Code standards
- Python 3.11+, type hints everywhere in new code, pydantic v2 for config, dataclasses for value objects.
- Keep the 1.0 engine (`compare.py`, `analysis.py`, `render.py`, `workspace.py`) API-stable. New features wrap it; they don't rewrite it.
- Core install stays light. Heavy dependencies go behind extras (`[capture]`, `[server]`, `[sentinel]`, `[ai]`, `[mcp]`, `[lookalike]`).
- Errors are user-facing and actionable; exit codes follow `BUILD_PLAN.md` section 3.
- Every new behaviour gets tests. Unit tests make no network calls; integration tests may reach only the localhost lab.

## Safety rules (from BUILD_PLAN.md section 5, mandatory)
- Lab and test fixtures must **never** be functional skimmers: no reading of form values, no serialization of payment fields, no sending of user input. Use only constant payloads to localhost.
- Static-analysis fixtures are short, non-functional snippets containing the patterns being detected.
- Use only published test card numbers, as static placeholder text. No real personal data anywhere.
- Lab and dashboard bind to 127.0.0.1 by default. Never scan third-party websites in tests or CI.
- `lookalike` never submits forms or enters credentials.
- Never store cookie values, Authorization headers or secrets in snapshots, logs or reports.

## Done means
All acceptance criteria for the phase pass, the global definition of done (BUILD_PLAN.md section 7) is met, CI is green, the PR is merged, and `docs/progress.md` is updated.

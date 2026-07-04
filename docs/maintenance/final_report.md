# Final hardening report — nirs4all-tools

**Date:** 2026-07-04 · **Branch:** `main` · **Operator:** Claude (Opus 4.8) · **Reviewer:** Codex CLI 0.142.5

## Summary
Pragmatic hardening of the legacy-artifact **migration CLI** (offline, one-way, no-in-place): added
the full community-health set (the repo previously had none of it) and SHA-pinned the workflow actions.
**No code changes.** (Codex Gate 3 corrected an initial mischaracterization — the community docs now
describe the real migration threat model, and the local gate matches CI: `.[dev,parquet]` + mypy.)

## Baseline / commit
- **Baseline HEAD:** `440e588` (origin/main; `CI [push]` green; the actor added `ci.yml`/`publish.yml`).
- **Commit:** *(this commit)* — community-health + SHA-pins + docs/maintenance.

## Files
Added: `CODE_OF_CONDUCT.md`, `CITATION.cff`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`,
`.editorconfig`, `.pre-commit-config.yaml`, `.github/dependabot.yml` (github-actions + pip),
`docs/maintenance/{repository_audit,quality_gates,release_checklist,final_report}.md` + `codex_reviews/03`.
Modified: `.github/workflows/{ci,publish}.yml` (7 action SHA-pins).

## Checks
- YAML/CFF validated. Non-code change; ruff+pytest run in CI (authoritative). Baseline `CI [push]` green at `440e588`.
- **Codex Gate 3** — see `codex_reviews/03`. Gate 4 consolidated into ecosystem Gate 5.

## GitHub Actions (this push)
`CI [push]` (ruff + pytest). Verified green post-push. `publish.yml` is release-gated (no publish on push).

## Residual risks / flags
- ⛔ **Release blocker:** full CeCILL/AGPL license texts missing (no `LICENSES/` dir) — see `release_checklist.md`.
- A prior `Publish to PyPI [release]` run failed — verify the Trusted Publisher setup before the next tag.
- No coverage floor yet.

## 12-month maintenance
- Merge weekly Dependabot PRs after CI-green. Keep `CHANGELOG.md` current.
- **Before release:** add the full `LICENSES/` texts and confirm the PyPI Trusted Publisher.

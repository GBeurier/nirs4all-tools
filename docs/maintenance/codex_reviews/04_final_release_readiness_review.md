# Codex Gate 4 — final release-readiness (nirs4all-tools)

Consolidated into the ecosystem-level **Gate 5**. Per-repo Codex effort was on **Gate 3**, which
corrected a repo mischaracterization (see `03_main_diff_review.md`).

**Readiness snapshot:** `nirs4all-tools` is an offline, one-way, no-in-place migration CLI (legacy
nirs4all artifacts → workspace-v2). Push-hardening added the community-health set + SHA-pins; CI
(`ruff` + `mypy` + `pytest` on `.[dev,parquet]`) is green.

## Historical release blocker — closed after this snapshot

The full CeCILL-2.1 and AGPL-3.0-or-later texts and commercial notices now ship
under `LICENSES/`. The remaining external gate is to verify the PyPI Trusted
Publisher on the exact release tag. See `release_checklist.md`.

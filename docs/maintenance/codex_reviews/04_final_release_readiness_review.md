# Codex Gate 4 — final release-readiness (nirs4all-tools)

Consolidated into the ecosystem-level **Gate 5**. Per-repo Codex effort was on **Gate 3**, which
corrected a repo mischaracterization (see `03_main_diff_review.md`).

**Readiness snapshot:** `nirs4all-tools` is an offline, one-way, no-in-place migration CLI (legacy
nirs4all artifacts → workspace-v2). Push-hardening added the community-health set + SHA-pins; CI
(`ruff` + `mypy` + `pytest` on `.[dev,parquet]`) is green.

## ⛔ Release blocker (documented, not changed)
`LICENSE` is only a dual-license **summary**; the full **CeCILL-2.1 + AGPL-3.0** texts (a `LICENSES/`
directory, as shipped by the sibling repos) are **missing** — must be added before publishing. License
content is a maintainer decision. A prior `Publish to PyPI [release]` run also failed — verify the
Trusted-Publisher setup before the next tag. See `release_checklist.md`.

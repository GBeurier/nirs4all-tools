# Repository audit — nirs4all-tools

> Generated from the automated pre-release audit (workflow wf_1fc87351-29f); the **Deepest hardening roadmap** section records the fullest realistic hardening even where the pragmatic pass does not implement it. Reviewed at Codex Gate 1.

- **Mode:** IN SCOPE — pragmatic hardening + push
- **Baseline HEAD:** `7c5070f`
- **Role:** Shared/standalone Python CLI providing offline, one-way, no-in-place migration tools for legacy nirs4all artifacts (workspaces, .n4a bundles, loose prediction files) into nirs4all-workspace-v2.
- **Stack:** Python >=3.11 (pure-stdlib core: argparse/sqlite3/zipfile/hashlib/json). Packaging: setuptools>=64 + wheel, src-layout, dynamic version, console script `nirs4all-tools`. Optional extras: duckdb>=1.0, pyarrow>=14 (parquet), nirs4all>=0.10 (target). Dev/gate: pytest, pytest-cov, ruff, mypy, build. No runtime deps in base install.

## Release-readiness verdict
nirs4all-tools is a small, well-structured pure-stdlib Python CLI (~4.7k src LOC) with a strong test suite (113 tests, ~2.9k LOC, golden + legacy-store fixtures) and a green single-job CI gate (ruff + mypy + pytest) that already uses least-privilege permissions. It is NOT release-ready: the LICENSE is an explicit placeholder missing the full CeCILL-2.1/AGPL-3.0 texts (self-flagged as blocking first release), and the community-health set (SECURITY, CHANGELOG, CONTRIBUTING, CODE_OF_CONDUCT, CITATION, templates, dependabot) is entirely absent. CI under-delivers on the metadata's promises: only Python 3.11 on Linux is tested despite 3.11-3.13/OS-independent claims, coverage is configured but never enforced, and only the parquet extra is exercised. Push-to-main is low risk — there is no publish/release/version-bump automation, no tag-triggered deploy, and no cross-repo coupling in CI — so hardening can proceed safely without release-side blast radius.

## Gate commands (detected)
| key | value |
|---|---|
| `install` | python -m pip install -e ".[dev,parquet]" |
| `test` | pytest |
| `lint` | ruff check . |
| `typecheck` | mypy |
| `format` | — |
| `docs_build` | — |
| `package_build` | python -m build |

## CI
- **Latest status:** All 6 most-recent CI runs green (latest run 28671395385 = ok). No failing runs to triage.
- **Workflows:**
- .github/workflows/ci.yml — single job "tools-gate" (ruff check, mypy, pytest) on ubuntu-latest, Python 3.11, timeout 15m
- **Gaps:**
- Single Python version (3.11) despite pyproject classifiers/requires-python claiming 3.11/3.12/3.13 support — no version matrix
- Single OS (ubuntu-latest) — no macOS/Windows despite "OS Independent" classifier
- No coverage gate/upload (pytest-cov is a dev dep but CI runs plain `pytest`, no --cov, no fail_under)
- Actions pinned to mutable tags (actions/checkout@v4, actions/setup-python@v5) not commit SHAs
- `push:` trigger has no branch filter — every branch push burns CI
- No packaging/build validation step (twine check / python -m build) even though build is a dev dep
- No release/publish workflow at all (fine for now, but no path to PyPI)

## Standard files
- **Present:** readme, license, gitignore
- **Missing:** changelog, contributing, security, code_of_conduct, citation, editorconfig, precommit, pr_template, issue_template, dependabot

## Packaging
- **name:** `nirs4all-tools` — **version:** `0.0.1`
- **issues:**
- LICENSE file is an explicit placeholder scaffold: lines 18-21 say the maintainer must "drop in the full canonical CeCILL-2.1 and AGPL-3.0 license texts before the first public release" — it currently ships only a summary, not the license bodies
- Development Status classifier is "2 - Pre-Alpha" and version 0.0.1 — not release-grade metadata yet (intentional given L18/first-transform status)
- No PyPI publish workflow / trusted-publisher config; single-sourced version via __init__.__version__ with no automated bump-and-tag path
- egg-info committed into working tree (src/nirs4all_tools.egg-info/) though .gitignore excludes *.egg-info/ — verify it is not tracked
- Optional extras (duckdb, parquet, target=nirs4all>=0.10.0) are clean, but CI only exercises the `parquet` extra; the `duckdb` and `target` code paths are never installed/tested in CI

## Tests
- **framework:** pytest (+pytest-cov available)
- **estimate:** 113 test functions across 8 files (~2927 test LOC vs ~4732 src LOC), including golden-fixture and legacy-SQLite/DuckDB fixture tests
- **coverage:** coverage.run configured (source=nirs4all_tools, omit tests) but NO fail_under threshold and CI does not run with --cov or upload coverage; effective enforced coverage = none

## Docs
- **system:** None — no docs/, mkdocs.yml, docs/conf.py, or .readthedocs.yaml. Documentation is the README.md only (~122 lines) plus tests/fixtures/legacy/README.md.
- **status:** No buildable docs system present.

## Risks
| severity | area | detail |
|---|---|---|
| high | licensing | /home/delete/nirs4all/nirs4all-tools/LICENSE is a self-described scaffold summary (lines 18-21) missing the full CeCILL-2.1 and AGPL-3.0 texts it dual-licenses under; publishing as-is ships an incomplete license. |
| medium | ci-coverage | pyproject.toml advertises Python 3.11/3.12/3.13 and OS-independent support, but .github/workflows/ci.yml tests only 3.11 on ubuntu-latest — untested support claims. |
| medium | test-enforcement | No enforced coverage threshold; CI (.github/workflows/ci.yml) runs bare `pytest` with no --cov, so [tool.coverage] config is decorative and regressions in the duckdb/target extra paths (uninstalled in CI) go uncaught. |
| low | supply-chain | GitHub Actions (actions/checkout@v4, actions/setup-python@v5) pinned to mutable major tags rather than commit SHAs in .github/workflows/ci.yml. |
| low | project-hygiene | Missing CHANGELOG.md, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, CITATION.cff, .editorconfig, .pre-commit-config.yaml, PR/issue templates, and dependabot config. |
| low | author-metadata | pyproject.toml author email (beurier@cirad.fr) differs from maintainer email (gregory.beurier@cirad.fr) and from ecosystem canonical git identity — worth normalizing before release. |

## Security
- **info** — Light secret scan over src/ found no plausible private keys, API keys, or hardcoded tokens.
- **low** — No SECURITY.md / vulnerability-disclosure policy present despite dual-license public-release intent.
- **info** — CI already uses least-privilege top-level `permissions: contents: read` — good baseline; no elevated token scopes granted.

## Quick wins (pragmatic scope — safe to apply now)
- Add SECURITY.md (point disclosures to nirs4all-admin@cirad.fr, matching ecosystem policy).
- Replace the placeholder LICENSE with the full canonical CeCILL-2.1 + AGPL-3.0 texts as sibling repos ship them (the file itself flags this as required pre-release).
- Add CHANGELOG.md scaffold (Keep a Changelog) with an Unreleased/0.0.1 entry.
- Add .editorconfig and a .pre-commit-config.yaml wiring ruff + mypy to match the CI gate.
- Pin CI actions to commit SHAs (actions/checkout, actions/setup-python) for supply-chain integrity.
- Scope the CI `push:` trigger to branches (e.g. main + PRs) to stop redundant per-branch runs.
- Add a Dependabot config (github-actions + pip ecosystems).
- Add CONTRIBUTING.md documenting the green gate: ruff check . / mypy / pytest.
- Confirm src/nirs4all_tools.egg-info/ is untracked (it matches the *.egg-info/ gitignore rule) and remove if committed.
- Add PR and issue templates under .github/.

## Deepest hardening roadmap (fullest realistic hardening)
- Expand CI to a matrix: Python 3.11/3.12/3.13 x {ubuntu, macos, windows} to back the pyproject support claims.
- Install and exercise every extra in CI (duckdb, parquet, and a target=nirs4all job) so all reader code paths are covered, not just parquet.
- Add coverage enforcement: run `pytest --cov=nirs4all_tools --cov-report=xml`, set [tool.coverage.report] fail_under (target 90%+ given the large test suite), and upload to Codecov.
- Add a build/packaging validation job: `python -m build` + `twine check dist/*` + install-from-wheel smoke test of the `nirs4all-tools` console entry point.
- Add a tag-triggered PyPI publish workflow using OIDC trusted publishing (no long-lived token), gated on a GitHub Release / version tag, with an environment protection rule.
- Introduce a docs system (MkDocs+Material or Sphinx+MyST to match ecosystem RTD-ready siblings) documenting the CLI surface, no-in-place/one-way safety model, contract vocabulary, and the migration matrix; wire a docs-build CI check and ReadTheDocs/Pages deploy on tag only.
- Complete the LICENSE with full canonical texts and add a REUSE/SPDX header pass so `license = CeCILL-2.1 OR AGPL-3.0-or-later` is machine-verifiable.
- Add CODE_OF_CONDUCT.md, CITATION.cff, SECURITY.md, CONTRIBUTING.md, and issue/PR templates for a complete community-health set.
- Add a scorecard/OpenSSF Scorecard workflow and pin all actions by SHA with Dependabot updates.
- Promote Development Status classifier past Pre-Alpha and bump to a real 0.x release version only after the license, docs, and multi-extra CI land.
- Add reproducibility guarantees: lockfile or constraints for the dev toolchain, and a deterministic-build check for the checksummed JSONL audit provenance the migrator emits.

## Push-safety notes
- LOW push-to-main risk overall: no release-please/version-bump automation, no tag- or push-triggered publish, no Pages deploy, and no cross-repo dispatch exist in .github/workflows/ (ci.yml is the only workflow and does build/lint/type/test only with `permissions: contents: read`).
- Version is single-sourced in src/nirs4all_tools/__init__.py (__version__ = 0.0.1) and read via [tool.setuptools.dynamic]; a push that edits it has no automation attached, so it cannot accidentally trigger a release — but also means releasing is a fully manual, unautomated step.
- CI `push:` trigger (ci.yml line 5) is unscoped, so any pushed branch runs the full gate; harmless but noisy, not a safety hazard.
- Cross-repo coupling is only a runtime optional dependency (target extra: nirs4all>=0.10.0) — not wired into any workflow, so pushes here do not trigger or depend on sibling-repo CI.

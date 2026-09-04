# Quality gates — nirs4all-tools

An offline, one-way, no-in-place **migration CLI** for legacy nirs4all artifacts (src-layout).

## Local green gate (matches CI)

```bash
pip install -e ".[dev,parquet]"   # parquet extra is required — several tests exercise parquet lowering
ruff check .                      # lint (line-length 120, py311)
mypy                              # types
pytest                            # tests
```

Optional local hooks: `uvx pre-commit run --all-files`.

## CI gates (`.github/workflows/`)

| workflow | trigger | gate |
|---|---|---|
| `ci.yml` | push/PR | install `.[dev,parquet]` → ruff + mypy + pytest |
| `publish.yml` | **release / dispatch** | PyPI publish — **not** on branch push |

All third-party actions are **full-SHA pinned** (Dependabot-tracked). The release
runner, Python micro version, build frontend, build backend, wheel, and Twine are
also pinned. `publish.yml` rebuilds the distributions twice and refuses a byte
mismatch before producing the artifact-bound CycloneDX SBOM.

## Known gaps (deepest-hardening roadmap)

- The historical license blocker is closed: the full CeCILL-2.1 and
  AGPL-3.0-or-later texts plus commercial notices ship under `LICENSES/`.
- External Trusted Publisher/OIDC configuration still requires verification on
  the exact release tag; it cannot be proven by repository-local tests.
- Cover representative invalid SQLite, ZIP, JSON, and YAML inputs with functional
  non-crash tests; refusals must remain explicit and actionable (`ROB-001`).
- No enforced coverage floor yet (`pytest-cov` is available).

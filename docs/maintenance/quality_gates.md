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

All third-party actions are **SHA-pinned** (Dependabot-tracked; github-actions + pip).

## Known gaps (deepest-hardening roadmap)

- **LICENSE blocker (release):** `LICENSE` is a dual-license *summary*; the full CeCILL-2.1 + AGPL-3.0
  texts (a `LICENSES/` directory, as in the sibling repos) are **missing** — see `release_checklist.md`.
- Consider fuzzing the untrusted-input parsers (SQLite/ZIP/JSON/YAML) given the migration threat model.
- No enforced coverage floor yet (`pytest-cov` is available).

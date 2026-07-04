# Contributing to nirs4all-tools

`nirs4all-tools` is the standalone home for the legacy-artifact **migration** tools that used to live
inside the `nirs4all` runtime. Migrations are **offline, one-way, and no-in-place**: never mutate the
source; write a fresh `workspace-v2` output and preserve the legacy rows as checksummed audit provenance.

## Green gate (matches CI)

```bash
pip install -e ".[dev,parquet]"
ruff check .
mypy
pytest
```

Optional local hooks: `uvx pre-commit run --all-files`.

- Every transform needs a `--dry-run`, strict hash/schema preflight, and tests covering both the
  parquet-installed and parquet-absent paths.
- Reject adversarial inputs (zip-slip in `.n4a`, malformed SQLite/JSON/YAML) — fail closed.
- Update `CHANGELOG.md` for user-facing changes.

By contributing you agree to the `CeCILL-2.1 OR AGPL-3.0-or-later` license and `CODE_OF_CONDUCT.md`.

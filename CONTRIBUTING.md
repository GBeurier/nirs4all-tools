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

## Cross-repository version constraints

Dependencies on packages from other nirs4all repositories are declared at
**minor** granularity, never more precisely: `pls4all>=1.0,<2` and
`nirs4all>=0.10,<2` (a floor kept from before the contract, capped at the next
major). Exact versions live in lockfiles and the release order. In return an
owner patch release changes no wire format, persisted schema, `.n4a` payload
semantics, native ABI or shared fixture; such changes need at least a minor
release, and the native N4MM writer is accepted by the Methods ABI check, not by
its version. The full policy is `docs/contracts/release/VERSION_CONSTRAINTS.md`
in `nirs4all-ecosystem`.

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

Versions are `X.Y.Z`. A patch (`Z`) carries fixes and purely additive,
backward-compatible features (existing outputs, wire formats, schemas and ABI
symbols unchanged); a minor (`Y`) carries any compatibility break (changed or
removed API signature, ABI break or ABI version change, wire/schema/fixture
change, renamed ids, changed numerical results). The package that bumps
classifies its change.

Dependencies on packages from other nirs4all repositories accept every patch of
one tested minor series, `>=X.Y[.Z],<X.(Y+1)` (for example `pls4all>=1.4,<1.5`);
a patch floor is allowed when a fix or feature from that patch is required, and
moving to a new minor series is an explicit, tested decision. The current
`pls4all>=1.0,<2` and `nirs4all>=0.10,<2` ranges predate this rule and are
narrowed at the next release. Exact versions live in lockfiles and the release
order. The native N4MM writer is accepted by the Methods ABI check, not by its
version. The full policy is
[`docs/contracts/release/VERSION_CONSTRAINTS.md`](https://github.com/GBeurier/nirs4all-ecosystem/blob/main/docs/contracts/release/VERSION_CONSTRAINTS.md) in
`nirs4all-ecosystem`.

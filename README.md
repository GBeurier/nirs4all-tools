# nirs4all-tools

Offline, **one-way**, **no-in-place** migration tools for legacy `nirs4all`
artifacts (workspaces, `.n4a` bundles, loose prediction files).

This is the standalone home for the legacy *readers* that used to live inside
the `nirs4all` runtime. The V1 runtime carries **no** legacy reader and **no**
auto-migration trigger; instead, `nirs4all-tools` converts old stores **into**
the format the runtime already reads (`nirs4all-workspace-v2`), so users keep
their predictions/pipelines without the runtime ever opening a legacy store.

> Status: **first transform** (lane `L18`, lock `LOCK-MIG`, decision `DEC-MIG-001`).
> The CLI surface, the no-in-place safety machinery, detection, the contract
> vocabulary, `inspect`, `migrate --dry-run`, and `--copy-only` are implemented.
> The first schema transform lowers `sqlite-workspace-legacy-arrays` metadata
> into a fresh workspace-v2 `store.sqlite`; legacy array rows are preserved as
> checksummed opaque JSONL until Parquet array lowering is implemented.

## The one contract: no-in-place

Every command guarantees the source is never modified:

- the source is opened **read-only** (SQLite via `file:…?mode=ro&immutable=1`);
- `--output` is **mandatory** and must be **disjoint** from the input
  (aliasing / nesting is refused, exit `40`);
- the output must be **empty** unless `--resume`;
- the whole source tree is snapshotted `(path, size, mtime_ns)` before and after
  **every** run — including failure and abort paths — and asserted byte-for-byte
  identical (a mismatch is exit `70`).

## Install

```bash
pip install -e ".[dev]"          # scaffold core is pure standard library
pip install -e ".[duckdb]"       # add DuckDB-source reading (optional)
```

## CLI

```bash
nirs4all-tools --version

# Read-only: detect what a legacy location contains.
nirs4all-tools legacy inspect <input> [--format json|text] [--report PATH]

# Convert into a fresh output (one-way, no-in-place).
nirs4all-tools legacy migrate <input> --output DIR --target nirs4all-workspace-v2 \
    [--manifest PATH] [--report PATH] [--id-map PATH] [--checksums sha256] \
    [--dry-run | --verify] [--strict | --best-effort] \
    [--copy-only] [--resume] [--trusted-load-joblib]

# Verify an output against its manifest (reads no source).
nirs4all-tools legacy verify <output-dir> --manifest PATH [--report PATH]
```

Current schema-transform support is intentionally narrow:

- `sqlite-workspace-legacy-arrays` metadata is lowered to `store.sqlite`
  schema v2;
- the legacy `prediction_arrays` table is not executed or loaded into runtime
  code, and is preserved in `preserved/legacy-prediction-arrays.jsonl`;
- best-effort migration exits `10` when arrays are preserved opaque;
- `--strict` refuses that source until full Parquet array lowering lands.

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | success, no warnings |
| `10` | migrated with warnings (best-effort preserved opaque / non-fatal skips) |
| `20` | unsupported input (unknown / forward-version source, or strict unsupported item) |
| `30` | verification failed |
| `40` | refused by policy (in-place / aliased output, non-empty output without `--resume`) |
| `70` | internal error (incl. source-tree integrity assertion failure) |

## Contracts

Three durable JSON contracts are emitted alongside a migrated workspace
(`SW4_MIG_CONVERTER_spec.md` §7–10):

- `legacy_migration_manifest.v1` — the exhaustive inventory + checksum + id-map ledger;
- `legacy_migration_report.v1` — the human/UX digest + next action;
- `legacy_id_map.v1` — the never-lossy old→new id map.

## Development

```bash
ruff check .
mypy
pytest
```

## License

Dual-licensed **CeCILL-2.1 OR AGPL-3.0-or-later** (plus commercial), consistent
with the nirs4all ecosystem policy. See `LICENSE`. Contact:
`nirs4all-admin@cirad.fr`.

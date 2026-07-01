# Legacy converter golden fixtures

These are small, checked-in source payloads for converter tests. They model
pre-V1 artifacts that must stay outside runtime packages:

- `old_workspace_mixed/` is an opaque preservation workspace with old
  run/pipeline manifests, loose prediction sidecars, and two deliberately
  different binary-surface claims:
  - `sample.meta.parquet` is a valid reduced Parquet sidecar.
  - `store.duckdb` is an explicit opaque sentinel at the legacy DuckDB store
    path, not a DuckDB database. It exists only to lock the current
    detect-and-preserve behavior until a future fixture can be authored with the
    optional `duckdb` dependency and semantic reader coverage.
- `sqlite_legacy_arrays_workspace.sql` is a SQLite dump for a workspace with
  old `prediction_arrays` rows plus run/pipeline/chain/prediction metadata.

Tests copy or materialize these fixtures into temporary directories before
running the converter so the checked-in goldens are never modified.

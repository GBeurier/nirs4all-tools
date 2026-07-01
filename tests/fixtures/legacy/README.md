# Legacy converter golden fixtures

These are small, checked-in source payloads for converter tests. They model
pre-V1 artifacts that must stay outside runtime packages:

- `old_workspace_mixed/` is an opaque preservation workspace with a legacy
  workspace store marker, old run/pipeline manifests, and loose prediction
  sidecars.
- `sqlite_legacy_arrays_workspace.sql` is a SQLite dump for a workspace with
  old `prediction_arrays` rows plus run/pipeline/chain/prediction metadata.

Tests copy or materialize these fixtures into temporary directories before
running the converter so the checked-in goldens are never modified.

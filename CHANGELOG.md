# Changelog

All notable changes to **nirs4all-tools** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3] — 2026-07-07

Patch release for the V1 RC migration lane.

### Fixed
- Reject legacy migration sources where array rows disagree on shape or sample counts instead of
  lowering ambiguous workspaces.
- Enforce release tag/version consistency in the publication workflow.

## [0.0.2] — 2026-07-04

Initial pre-release: an offline, one-way, no-in-place **migration CLI** for legacy nirs4all artifacts.

### Added
- CLI with `inspect`, `migrate --dry-run` / `--copy-only`, no-in-place safety machinery, detection,
  and a contract vocabulary.
- First schema transform: lower `sqlite-workspace-legacy-arrays` into a fresh `workspace-v2`
  `store.sqlite`; legacy array rows are lowered into runtime-readable `arrays/<dataset>.parquet`
  sidecars (optional `parquet` extra) and preserved as checksummed JSONL audit provenance.
- Preview lowering for a dag-ml `native-results-v1` directory and a legacy `runs/*/manifest.yaml`
  after strict hash/schema preflight.

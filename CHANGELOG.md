# Changelog

All notable changes to **nirs4all-tools** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added
- Add the explicit `workspace inspect` and `workspace convert` user-facing
  aliases expected by the Python transition guidance, while retaining the
  historical `legacy inspect` and `legacy migrate` commands unchanged.
- Define the V1 legacy read/write/migrate support SLA, including guaranteed
  reader retention through R3 and R4, immutable inputs, and retained rollback
  release requirements, in a validated machine-readable support matrix.

## [0.0.7] — 2026-09-02

### Fixed
- Make release wheels and sdists reproducible by pinning the build toolchain,
  deriving `SOURCE_DATE_EPOCH` from the release commit, canonicalizing generated
  sdist PAX metadata, and enforcing an A/B rebuild before publication.
- Generate a deterministic CycloneDX SBOM bound to the exact source commit,
  wheel, and sdist identities.
- Ship the complete canonical CeCILL-2.1 and AGPL-3.0-or-later license texts,
  plus the commercial-license notices, in wheel and sdist metadata.
- Keep the trusted PLS-to-N4MM migration extra on the qualified Methods 1.x
  public API line.
- Allow a branch to prepare the next package version before its release tag;
  publication still requires exact tag/version equality.
- Refuse semantic lowering of `native-results-v1` directories unless their
  manifest declares the exact current integer `schema_version: 3`. Older or
  non-canonical variants remain opaque in best-effort mode and are refused by
  `--strict` before output creation.

## [0.0.6] — 2026-08-25

### Fixed
- The explicit trusted-PLS N4MM exporter now uses the public
  `pls4all>=1.0.13` migration API instead of the private `n4m` module. A clean
  install of the `n4mm-export` extra therefore has the same supported import
  boundary as its published dependency.

## [0.0.4] — 2026-07-07

Patch release for the V1 RC publication lane.

### Fixed
- Validate the PyPI Trusted Publisher tuple before upload.
- Keep citation metadata aligned with the package version for release health checks.

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

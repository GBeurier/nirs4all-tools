# Release checklist — nirs4all-tools

Publishing is via `publish.yml` (release / dispatch). Branch pushes never publish.

## License gate

- [x] The package includes the complete canonical **CeCILL-2.1** and
      **AGPL-3.0-or-later** texts plus the commercial-license notices under
      `LICENSES/`; `pyproject.toml` includes them in wheels and sdists.

## Pre-release

- [ ] Build with `python scripts/build_release.py`; this pins `SOURCE_DATE_EPOCH`
      to the release commit when it is not already set and canonicalizes sdist
      PAX metadata. The exact build backend/frontend versions are pinned in
      `pyproject.toml` and `publish.yml`. Rebuilding the same commit in two
      clean directories must produce byte-identical wheel and sdist checksums.
- [ ] Green gate + CI green (see `quality_gates.md`).
- [ ] `CHANGELOG.md` has a dated `[X.Y.Z]` entry for the exact `nirs4all_tools.__version__`.
- [ ] PyPI Trusted Publisher configured (a prior `Publish to PyPI [release]` run failed — verify the
      trusted-publisher / environment setup before the next tag).

## Release

- [ ] Tag `vX.Y.Z` on the exact release commit; `publish.yml` now rejects release/manual publish runs whose
      Git ref does not match `nirs4all_tools.__version__`. The branch version
      guard permits an untagged next-version candidate but rejects a manifest
      older than the latest existing tag.
- [ ] Publish the GitHub Release from that exact tag (triggers `publish.yml`).
- [ ] `pip install "nirs4all-tools[parquet]==X.Y.Z"` in a clean venv; smoke `nirs4all-tools --help`.

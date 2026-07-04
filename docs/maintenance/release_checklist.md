# Release checklist — nirs4all-tools

Publishing is via `publish.yml` (release / dispatch). Branch pushes never publish.

## ⛔ Release blocker (must fix first)

- [ ] **Full license texts missing.** `LICENSE` is only a 21-line dual-license *summary*; there is no
      `LICENSES/` directory with the full **CeCILL-2.1** and **AGPL-3.0** texts (the sibling repos ship
      `LICENSES/*.txt`). A published package must include the complete license texts. Copy the
      `LICENSES/` directory + `THIRD_PARTY_NOTICES.md` from a sibling (e.g. `nirs4all-cluster`) and set
      `license-files` in `pyproject.toml`. *(Left for a maintainer — license content is a maintainer decision.)*

## Pre-release

- [ ] Green gate + CI green (see `quality_gates.md`).
- [ ] `CHANGELOG.md` `[0.0.1]` dated; version single-sourced in `nirs4all_tools.__version__`.
- [ ] PyPI Trusted Publisher configured (a prior `Publish to PyPI [release]` run failed — verify the
      trusted-publisher / environment setup before the next tag).

## Release

- [ ] Tag `vX.Y.Z` on the exact release commit; publish the GitHub Release (triggers `publish.yml`).
- [ ] `pip install "nirs4all-tools[parquet]==X.Y.Z"` in a clean venv; smoke `nirs4all-tools --help`.

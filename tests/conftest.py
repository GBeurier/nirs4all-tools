"""Shared fixtures: synthetic legacy sources built with the standard library.

These deliberately avoid importing ``nirs4all`` — the tool's detection and
safety machinery must work with nothing but stat + read-only parse.
"""

from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

import pytest


def make_sqlite_workspace(root: Path, *, user_version: int = 2, legacy_arrays: bool = False) -> Path:
    """Create a minimal ``store.sqlite`` workspace directory."""
    root.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(root / "store.sqlite")
    try:
        con.execute("CREATE TABLE projects (id TEXT)")
        con.execute("CREATE TABLE runs (id TEXT)")
        con.execute("CREATE TABLE predictions (id TEXT)")
        if legacy_arrays:
            con.execute("CREATE TABLE prediction_arrays (prediction_id TEXT, y_true TEXT, y_pred TEXT)")
        con.execute(f"PRAGMA user_version = {int(user_version)}")
        con.commit()
    finally:
        con.close()
    return root


def make_n4a_bundle(path: Path, *, bundle_format_version: str = "1.0") -> Path:
    """Create a minimal ``.n4a`` ZIP bundle with a manifest."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("manifest.json", json.dumps({"bundle_format_version": bundle_format_version}))
        zf.writestr("chain.json", "{}")
    return path


@pytest.fixture
def sqlite_v2_workspace(tmp_path: Path) -> Path:
    return make_sqlite_workspace(tmp_path / "ws_v2", user_version=2)


@pytest.fixture
def legacy_arrays_workspace(tmp_path: Path) -> Path:
    return make_sqlite_workspace(tmp_path / "ws_legacy", user_version=2, legacy_arrays=True)


@pytest.fixture
def forward_version_workspace(tmp_path: Path) -> Path:
    return make_sqlite_workspace(tmp_path / "ws_fwd", user_version=99)


@pytest.fixture
def n4a_bundle(tmp_path: Path) -> Path:
    return make_n4a_bundle(tmp_path / "model.n4a", bundle_format_version="1.0")

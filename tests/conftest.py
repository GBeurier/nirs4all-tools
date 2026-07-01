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


def make_sqlite_legacy_arrays_workspace(root: Path) -> Path:
    """Create a small SQLite workspace with one legacy prediction array row."""
    root.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(root / "store.sqlite")
    try:
        con.executescript(
            """
            CREATE TABLE runs (
                run_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                config TEXT,
                datasets TEXT,
                status TEXT
            );
            CREATE TABLE pipelines (
                pipeline_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                name TEXT NOT NULL,
                expanded_config TEXT,
                generator_choices TEXT,
                dataset_name TEXT NOT NULL,
                dataset_hash TEXT
            );
            CREATE TABLE chains (
                chain_id TEXT PRIMARY KEY,
                pipeline_id TEXT NOT NULL,
                steps TEXT NOT NULL,
                model_step_idx INTEGER NOT NULL,
                model_class TEXT NOT NULL,
                preprocessings TEXT
            );
            CREATE TABLE predictions (
                prediction_id TEXT PRIMARY KEY,
                pipeline_id TEXT NOT NULL,
                chain_id TEXT,
                dataset_name TEXT NOT NULL,
                model_name TEXT NOT NULL,
                model_class TEXT NOT NULL,
                fold_id TEXT NOT NULL,
                partition TEXT NOT NULL,
                val_score REAL,
                test_score REAL,
                train_score REAL,
                metric TEXT NOT NULL,
                task_type TEXT NOT NULL,
                n_samples INTEGER,
                n_features INTEGER,
                scores TEXT,
                best_params TEXT,
                branch_id INTEGER,
                branch_name TEXT
            );
            CREATE TABLE prediction_arrays (
                prediction_id TEXT PRIMARY KEY,
                y_true TEXT,
                y_pred TEXT,
                y_proba TEXT,
                sample_indices TEXT,
                weights TEXT
            );
            """
        )
        con.execute(
            "INSERT INTO runs (run_id, name, config, datasets, status) VALUES (?, ?, ?, ?, ?)",
            ["run-1", "legacy run", "{}", '[{"name": "dataset-a"}]', "completed"],
        )
        con.execute(
            "INSERT INTO pipelines "
            "(pipeline_id, run_id, name, expanded_config, generator_choices, dataset_name, dataset_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ["pipe-1", "run-1", "legacy pipeline", "{}", "[]", "dataset-a", "hash-a"],
        )
        con.execute(
            "INSERT INTO chains "
            "(chain_id, pipeline_id, steps, model_step_idx, model_class, preprocessings) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ["chain-1", "pipe-1", "[]", 0, "PLSRegression", "SNV"],
        )
        con.execute(
            "INSERT INTO predictions "
            "(prediction_id, pipeline_id, chain_id, dataset_name, model_name, model_class, "
            "fold_id, partition, val_score, test_score, train_score, metric, task_type, "
            "n_samples, n_features, scores, best_params, branch_id, branch_name) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                "pred-1",
                "pipe-1",
                "chain-1",
                "dataset-a",
                "PLSRegression",
                "sklearn.cross_decomposition.PLSRegression",
                "fold-0",
                "val",
                0.1,
                0.2,
                0.05,
                "rmse",
                "regression",
                3,
                42,
                '{"val": {"rmse": 0.1}}',
                '{"n_components": 3}',
                None,
                None,
            ],
        )
        con.execute(
            "INSERT INTO prediction_arrays "
            "(prediction_id, y_true, y_pred, y_proba, sample_indices, weights) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                "pred-1",
                json.dumps([1.0, 2.0, 3.0]),
                json.dumps([1.1, 1.9, 3.2]),
                None,
                json.dumps([0, 1, 2]),
                None,
            ],
        )
        con.execute("PRAGMA user_version = 2")
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
def sqlite_legacy_arrays_workspace(tmp_path: Path) -> Path:
    return make_sqlite_legacy_arrays_workspace(tmp_path / "ws_legacy_arrays")


@pytest.fixture
def forward_version_workspace(tmp_path: Path) -> Path:
    return make_sqlite_workspace(tmp_path / "ws_fwd", user_version=99)


@pytest.fixture
def n4a_bundle(tmp_path: Path) -> Path:
    return make_n4a_bundle(tmp_path / "model.n4a", bundle_format_version="1.0")

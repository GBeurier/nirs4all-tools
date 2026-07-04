"""Shared fixtures: synthetic legacy sources built with the standard library.

These deliberately avoid importing ``nirs4all`` — the tool's detection and
safety machinery must work with nothing but stat + read-only parse.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import zipfile
from pathlib import Path

import pytest


def pytest_addoption(parser) -> None:
    parser.addoption(
        "--artifacts-dir",
        action="store",
        default=None,
        help="Directory where ecosystem e2e tests write machine-readable artifacts.",
    )


@pytest.fixture
def artifacts_dir(request: pytest.FixtureRequest, tmp_path: Path) -> Path:
    raw = request.config.getoption("--artifacts-dir")
    path = Path(raw).expanduser() if raw else tmp_path / "artifacts"
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture
def artifacts_dir_explicit(request: pytest.FixtureRequest) -> bool:
    return request.config.getoption("--artifacts-dir") is not None


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


def make_native_results_dir(root: Path, *, schema_version: int = 2) -> Path:
    """Create a minimal native-results directory."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.json").write_text(json.dumps({"schema_version": schema_version}), encoding="utf-8")
    (root / "score_set.json").write_text(json.dumps({"reports": []}), encoding="utf-8")
    (root / "predictions.parquet").write_bytes(b"PAR1synthetic")
    return root


def make_legacy_workspace_inputs(root: Path) -> Path:
    """Create a workspace-shaped source with non-lowerable legacy payloads."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "store.duckdb").write_bytes(b"legacy duckdb payload")
    (root / "run_predictions.json").write_text(json.dumps({"prediction": [1, 2, 3]}), encoding="utf-8")
    (root / "sample.meta.parquet").write_bytes(b"PAR1legacy metadata")
    legacy_run = root / "runs" / "run-1" / "pipeline-1"
    legacy_run.mkdir(parents=True, exist_ok=True)
    (legacy_run / "manifest.yaml").write_text("run_id: run-1\npipeline_id: pipeline-1\n", encoding="utf-8")
    return root


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def make_lowerable_native_results_dir(root: Path, *, schema_version: int = 3) -> Path:
    """Create a current-shape native-results directory with a real parquet projection."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    root.mkdir(parents=True, exist_ok=True)
    score_set = {
        "plan_id": "plan-1",
        "bundle_id": "bundle-1",
        "reports": [
            {
                "producer_node": "node:pls",
                "partition": "val",
                "fold_id": "fold-0",
                "metric": "rmse",
                "value": 0.1,
            }
        ],
    }
    score_hash = hashlib.sha256(_canonical_json(score_set).encode("utf-8")).hexdigest()
    manifest = {
        "schema_version": schema_version,
        "run_id": "run-native-1",
        "created_at": "2026-07-01T00:00:00+00:00",
        "engine": "dag-ml",
        "nirs4all_version": "0.0.test",
        "dag_ml_version": "0.0.test",
        "datasets": ["dataset-a"],
        "config_names": ["config-a"],
        "variant_names": ["config-a"],
        "model_names": ["PLSRegression"],
        "metric": "rmse",
        "task_type": "regression",
        "selected_variant": "config-a",
        "plan_id": "plan-1",
        "bundle_id": "bundle-1",
        "producer_nodes": ["node:pls"],
        "final_producer_nodes": [],
        "num_predictions": 1,
        "score_set_hash": score_hash,
        "capabilities": {"has_model_artifacts": False, "has_aggregate_predictions": False},
        "artifacts": [],
        "files": {"score_set": "score_set.json", "predictions": "predictions.parquet"},
    }
    rows = [
        {
            "dataset": "dataset-a",
            "config_name": "config-a",
            "variant_id": "config-a",
            "model_name": "PLSRegression",
            "partition": "val",
            "fold_id": "fold-0",
            "refit_context": "",
            "sample_indices": [0, 1, 2],
            "y_true": [1.0, 2.0, 3.0],
            "y_pred": [1.1, 1.9, 3.2],
            "y_proba": [],
            "y_true_shape": [3],
            "y_pred_shape": [3],
            "y_proba_shape": [],
            "weights": [],
            "arrays_present": True,
            "val_score": 0.1,
            "test_score": 0.2,
            "train_score": 0.05,
            "scores": '{"val":{"rmse":0.1}}',
            "metric": "rmse",
            "task_type": "regression",
            "target_width": 1,
            "target_names": '["y"]',
        }
    ]
    schema = pa.schema(
        [
            ("dataset", pa.utf8()),
            ("config_name", pa.utf8()),
            ("variant_id", pa.utf8()),
            ("model_name", pa.utf8()),
            ("partition", pa.utf8()),
            ("fold_id", pa.utf8()),
            ("refit_context", pa.utf8()),
            ("sample_indices", pa.list_(pa.int64())),
            ("y_true", pa.list_(pa.float64())),
            ("y_pred", pa.list_(pa.float64())),
            ("y_proba", pa.list_(pa.float64())),
            ("y_true_shape", pa.list_(pa.int64())),
            ("y_pred_shape", pa.list_(pa.int64())),
            ("y_proba_shape", pa.list_(pa.int64())),
            ("weights", pa.list_(pa.float64())),
            ("arrays_present", pa.bool_()),
            ("val_score", pa.float64()),
            ("test_score", pa.float64()),
            ("train_score", pa.float64()),
            ("scores", pa.utf8()),
            ("metric", pa.utf8()),
            ("task_type", pa.utf8()),
            ("target_width", pa.int64()),
            ("target_names", pa.utf8()),
        ]
    )
    (root / "score_set.json").write_text(_canonical_json(score_set), encoding="utf-8")
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    pq.write_table(pa.Table.from_pylist(rows, schema=schema), root / "predictions.parquet")
    return root


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


@pytest.fixture
def native_results_dir(tmp_path: Path) -> Path:
    return make_native_results_dir(tmp_path / "native-results")


@pytest.fixture
def legacy_workspace_inputs(tmp_path: Path) -> Path:
    return make_legacy_workspace_inputs(tmp_path / "legacy-workspace")


@pytest.fixture
def lowerable_native_results_dir(tmp_path: Path) -> Path:
    return make_lowerable_native_results_dir(tmp_path / "native-results")

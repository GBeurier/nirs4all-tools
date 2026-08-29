"""Strict closed-profile DuckDB workspace migration coverage."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from nirs4all_tools import commands, vocab
from nirs4all_tools.errors import UnsupportedInput
from nirs4all_tools.exit_codes import ExitCode

duckdb = pytest.importorskip("duckdb")
pytest.importorskip("pyarrow.parquet")


def _create_closed_duckdb_workspace(root: Path, *, nested_arrays: bool = False) -> Path:
    """Create the exact historical six-table DuckDB source profile."""
    root.mkdir()
    store = root / "store.duckdb"
    array_type = "DOUBLE[][]" if nested_arrays else "DOUBLE[]"
    conn = duckdb.connect(str(store))
    try:
        conn.execute(
            f"""
            CREATE TABLE runs (
                run_id VARCHAR PRIMARY KEY, name VARCHAR NOT NULL, config JSON, datasets JSON,
                status VARCHAR, created_at TIMESTAMP, completed_at TIMESTAMP, summary JSON, error VARCHAR
            );
            CREATE TABLE pipelines (
                pipeline_id VARCHAR PRIMARY KEY, run_id VARCHAR NOT NULL, name VARCHAR NOT NULL,
                expanded_config JSON, generator_choices JSON, dataset_name VARCHAR NOT NULL, dataset_hash VARCHAR,
                status VARCHAR, created_at TIMESTAMP, completed_at TIMESTAMP, best_val DOUBLE, best_test DOUBLE,
                metric VARCHAR, duration_ms INTEGER, error VARCHAR
            );
            CREATE TABLE chains (
                chain_id VARCHAR PRIMARY KEY, pipeline_id VARCHAR NOT NULL, steps JSON NOT NULL,
                model_step_idx INTEGER NOT NULL, model_class VARCHAR NOT NULL, preprocessings VARCHAR,
                fold_strategy VARCHAR, fold_artifacts JSON, shared_artifacts JSON, branch_path JSON,
                source_index INTEGER, created_at TIMESTAMP
            );
            CREATE TABLE predictions (
                prediction_id VARCHAR PRIMARY KEY, pipeline_id VARCHAR NOT NULL, chain_id VARCHAR,
                dataset_name VARCHAR NOT NULL, model_name VARCHAR NOT NULL, model_class VARCHAR NOT NULL,
                fold_id VARCHAR NOT NULL, partition VARCHAR NOT NULL, val_score DOUBLE, test_score DOUBLE,
                train_score DOUBLE, metric VARCHAR NOT NULL, task_type VARCHAR NOT NULL, n_samples INTEGER,
                n_features INTEGER, scores JSON, best_params JSON, preprocessings VARCHAR, branch_id INTEGER,
                branch_name VARCHAR, exclusion_count INTEGER, exclusion_rate DOUBLE, refit_context VARCHAR,
                created_at TIMESTAMP
            );
            CREATE TABLE prediction_arrays (
                prediction_id VARCHAR PRIMARY KEY, y_true {array_type}, y_pred {array_type},
                y_proba {array_type}, sample_indices INTEGER[], weights {array_type}
            );
            CREATE TABLE logs (
                log_id VARCHAR PRIMARY KEY, pipeline_id VARCHAR NOT NULL, step_idx INTEGER NOT NULL,
                operator_class VARCHAR, event VARCHAR NOT NULL, duration_ms INTEGER, message VARCHAR,
                details JSON, level VARCHAR, created_at TIMESTAMP
            );
            """
        )
        conn.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, ?)",
            ["run-1", "legacy run", "{}", '["dataset-a"]', "completed", "{}", None],
        )
        conn.execute(
            """
            INSERT INTO pipelines VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
                                          ?, ?, ?, ?, ?)
            """,
            [
                "pipe-1",
                "run-1",
                "legacy pipeline",
                "{}",
                "[]",
                "dataset-a",
                "hash-a",
                "completed",
                0.1,
                0.2,
                "rmse",
                12,
                None,
            ],
        )
        conn.execute(
            """
            INSERT INTO chains VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            ["chain-1", "pipe-1", "[]", 0, "PLSRegression", "SNV", "per_fold", None, None, None, None],
        )
        prediction_values = [
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
            '{"rmse":0.1}',
            '{"n_components":3}',
            "SNV",
            0,
            None,
            0,
            0.0,
            None,
        ]
        conn.execute(
            "INSERT INTO predictions VALUES (" + ", ".join("?" for _ in prediction_values) + ", CURRENT_TIMESTAMP)",
            prediction_values,
        )
        arrays: list[Any]
        if nested_arrays:
            arrays = [[1.0, 2.0], [3.0]]
        else:
            arrays = [1.0, 2.0, 3.0]
        conn.execute(
            "INSERT INTO prediction_arrays VALUES (?, ?, ?, ?, ?, ?)",
            ["pred-1", arrays, arrays, None, [0, 1, 2], None],
        )
        conn.execute(
            "INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
            ["log-1", "pipe-1", 0, "PLSRegression", "fit", 12, None, "{}", "info"],
        )
    finally:
        conn.close()
    return root


def _mutate_store(workspace: Path, sql: str, params: list[Any] | None = None) -> None:
    conn = duckdb.connect(str(workspace / "store.duckdb"))
    try:
        conn.execute(sql, params or [])
    finally:
        conn.close()


def _add_target_natural_key_collision(workspace: Path) -> None:
    """Add a valid source row which would collide in the target unique index."""
    conn = duckdb.connect(str(workspace / "store.duckdb"))
    try:
        conn.execute(
            """
            INSERT INTO predictions (
                prediction_id, pipeline_id, chain_id, dataset_name, model_name, model_class,
                fold_id, partition, val_score, test_score, train_score, metric, task_type,
                n_samples, n_features, scores, best_params, preprocessings, branch_id,
                branch_name, exclusion_count, exclusion_rate, refit_context, created_at
            )
            SELECT
                'pred-2', pipeline_id, chain_id, dataset_name, model_name, model_class,
                fold_id, partition, val_score, test_score, train_score, metric, task_type,
                n_samples, n_features, scores, best_params, preprocessings, branch_id,
                branch_name, exclusion_count, exclusion_rate, refit_context, created_at
            FROM predictions WHERE prediction_id = 'pred-1'
            """
        )
        conn.execute(
            """
            INSERT INTO prediction_arrays (prediction_id, y_true, y_pred, y_proba, sample_indices, weights)
            SELECT 'pred-2', y_true, y_pred, y_proba, sample_indices, weights
            FROM prediction_arrays WHERE prediction_id = 'pred-1'
            """
        )
    finally:
        conn.close()


def _add_secondary_schema_table(workspace: Path) -> None:
    conn = duckdb.connect(str(workspace / "store.duckdb"))
    try:
        conn.execute("CREATE SCHEMA audit_extra")
        conn.execute("CREATE TABLE audit_extra.hidden_payload (id VARCHAR)")
    finally:
        conn.close()


def _strict_migrate(source: Path, output: Path) -> ExitCode:
    return commands.migrate(
        source,
        output=output,
        target=vocab.TARGET_WORKSPACE_V2,
        strict=True,
        verify=True,
        tool_version="0.0.test",
    )


def test_strict_duckdb_workspace_lowers_closed_profile_and_preserves_source(tmp_path: Path) -> None:
    source = _create_closed_duckdb_workspace(tmp_path / "source")
    source_bytes = (source / "store.duckdb").read_bytes()
    output = tmp_path / "output"

    assert _strict_migrate(source, output) == ExitCode.SUCCESS
    assert (source / "store.duckdb").read_bytes() == source_bytes
    assert commands.verify(output, manifest_path=output / "migration-manifest.json") == ExitCode.SUCCESS

    manifest = json.loads((output / "migration-manifest.json").read_text(encoding="utf-8"))
    report = json.loads((output / "migration-report.json").read_text(encoding="utf-8"))
    preserved = output / "preserved" / "duckdb-workspace" / "store.duckdb"
    assert preserved.read_bytes() == source_bytes
    assert manifest["unsupported"] == []
    assert manifest["preserved_opaque"] == []
    assert manifest["checksums"]["preserved/duckdb-workspace/store.duckdb"].startswith("sha256:")
    assert report["status"] == vocab.STATUS_SUCCESS
    assert report["migrated_counts"] == {
        "runs": 1,
        "pipelines": 1,
        "chains": 1,
        "predictions": 1,
        "arrays": 1,
        "artifacts": 0,
    }
    assert report["verification_summary"]["passed"] is True

    target = sqlite3.connect(output / "store.sqlite")
    try:
        assert target.execute("PRAGMA user_version").fetchone() == (2,)
        assert target.execute("SELECT run_id, name FROM runs").fetchall() == [("run-1", "legacy run")]
        assert target.execute("SELECT pipeline_id, chain_id FROM predictions").fetchall() == [("pipe-1", "chain-1")]
    finally:
        target.close()

    import pyarrow.parquet as pq

    row = pq.read_table(output / "arrays" / "dataset-a.parquet").to_pylist()[0]
    assert row["prediction_id"] == "pred-1"
    assert row["y_true"] == [1.0, 2.0, 3.0]
    assert row["y_pred"] == [1.0, 2.0, 3.0]
    assert row["sample_indices"] == [0, 1, 2]


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda source: _mutate_store(source, "CREATE TABLE unknown_payloads (id VARCHAR)"), "unsupported"),
        (lambda source: _mutate_store(source, "ALTER TABLE runs ADD COLUMN future_payload VARCHAR"), "does not match"),
        (lambda source: _mutate_store(source, "UPDATE pipelines SET run_id = 'missing-run'"), "pipeline.run_id"),
        (
            lambda source: _mutate_store(source, "UPDATE predictions SET chain_id = 'missing-chain'"),
            "prediction.chain_id",
        ),
        (lambda source: _mutate_store(source, "DELETE FROM prediction_arrays"), "prediction_arrays"),
        (lambda source: _mutate_store(source, "UPDATE predictions SET n_samples = 2"), "n_samples"),
        (
            lambda source: _mutate_store(source, 'UPDATE chains SET fold_artifacts = \'{"fold-0":"artifact-1"}\''),
            "fold_artifacts",
        ),
        (_add_secondary_schema_table, "outside main"),
    ],
)
def test_strict_duckdb_workspace_refuses_closed_profile_violations_before_output(
    tmp_path: Path,
    mutate: Callable[[Path], None],
    needle: str,
) -> None:
    source = _create_closed_duckdb_workspace(tmp_path / "source")
    mutate(source)
    source_bytes = (source / "store.duckdb").read_bytes()
    output = tmp_path / "output"

    with pytest.raises(UnsupportedInput, match=needle):
        _strict_migrate(source, output)
    assert not output.exists()
    assert (source / "store.duckdb").read_bytes() == source_bytes


def test_strict_duckdb_workspace_refuses_nested_arrays_before_output(tmp_path: Path) -> None:
    source = _create_closed_duckdb_workspace(tmp_path / "source", nested_arrays=True)
    output = tmp_path / "output"

    with pytest.raises(UnsupportedInput, match="incompatible column type"):
        _strict_migrate(source, output)
    assert not output.exists()


def test_strict_duckdb_workspace_refuses_additional_root_entry_before_output(tmp_path: Path) -> None:
    source = _create_closed_duckdb_workspace(tmp_path / "source")
    (source / "legacy-notes.txt").write_text("outside closed profile", encoding="utf-8")
    output = tmp_path / "output"

    with pytest.raises(UnsupportedInput, match="closed root"):
        _strict_migrate(source, output)
    assert not output.exists()


def test_strict_duckdb_workspace_refuses_target_natural_key_before_existing_output(tmp_path: Path) -> None:
    source = _create_closed_duckdb_workspace(tmp_path / "source")
    _add_target_natural_key_collision(source)
    output = tmp_path / "output"
    output.mkdir()

    with pytest.raises(UnsupportedInput, match="natural prediction identity"):
        _strict_migrate(source, output)
    assert list(output.iterdir()) == []


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (
            lambda source: _mutate_store(source, "ALTER TABLE chains ALTER COLUMN steps SET DATA TYPE VARCHAR"),
            "incompatible column type",
        ),
        (
            lambda source: _mutate_store(source, "UPDATE chains SET steps = ?", ['"not-a-step-list"']),
            "empty JSON list",
        ),
        (
            lambda source: _mutate_store(
                source,
                "UPDATE chains SET steps = ?",
                ['[{"artifact_ids":["missing-artifact"]}]'],
            ),
            "empty JSON list",
        ),
        (lambda source: _mutate_store(source, "UPDATE runs SET config = ?", ["NaN"]), "finite JSON"),
        (
            lambda source: _mutate_store(source, "UPDATE runs SET summary = ?", ["Infinity"]),
            "finite JSON",
        ),
    ],
)
def test_strict_duckdb_workspace_refuses_schema_or_json_shape_before_output(
    tmp_path: Path,
    mutate: Callable[[Path], None],
    needle: str,
) -> None:
    source = _create_closed_duckdb_workspace(tmp_path / "source")
    mutate(source)
    output = tmp_path / "output"

    with pytest.raises(UnsupportedInput, match=needle):
        _strict_migrate(source, output)
    assert not output.exists()


def test_best_effort_duckdb_workspace_outside_closed_profile_preserves_raw_store(tmp_path: Path) -> None:
    source = _create_closed_duckdb_workspace(tmp_path / "source")
    source_bytes = (source / "store.duckdb").read_bytes()
    (source / "legacy-notes.txt").write_text("outside closed profile", encoding="utf-8")
    output = tmp_path / "output"

    code = commands.migrate(
        source,
        output=output,
        target=vocab.TARGET_WORKSPACE_V2,
        tool_version="0.0.test",
    )

    assert code == ExitCode.MIGRATED_WITH_WARNINGS
    assert (source / "store.duckdb").read_bytes() == source_bytes
    assert (output / "preserved" / "duckdb-workspace" / "store.duckdb").read_bytes() == source_bytes
    manifest = json.loads((output / "migration-manifest.json").read_text(encoding="utf-8"))
    assert manifest["unsupported"][0]["source_kind"] == "duckdb-workspace"
    assert manifest["unsupported"][0]["disposition"] == "preserved"


def test_dry_run_duckdb_workspace_closed_profile_is_not_reported_opaque(tmp_path: Path) -> None:
    source = _create_closed_duckdb_workspace(tmp_path / "source")
    output = tmp_path / "output"
    unsupported = tmp_path / "unsupported.json"

    code = commands.migrate(
        source,
        output=output,
        target=vocab.TARGET_WORKSPACE_V2,
        dry_run=True,
        unsupported_report_path=unsupported,
        tool_version="0.0.test",
    )

    assert code == ExitCode.SUCCESS
    assert not output.exists()
    assert json.loads(unsupported.read_text(encoding="utf-8"))["unsupported"] == []

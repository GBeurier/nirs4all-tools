"""Command-behavior tests (``commands.py``)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from nirs4all_tools import commands, policy, vocab
from nirs4all_tools.checksums import sha256_file
from nirs4all_tools.errors import PolicyRefusal, UnsupportedInput, VerificationFailed
from nirs4all_tools.exit_codes import ExitCode


def _unchanged(source: Path, body) -> None:
    """Assert the source tree is byte/mtime identical across ``body()``."""
    before = policy.snapshot_tree(source)
    body()
    after = policy.snapshot_tree(source)
    assert policy.diff_snapshots(before, after) == []


def _mark_native_results_as_multidimensional(path: Path) -> None:
    pytest.importorskip("pyarrow")
    import pyarrow as pa
    import pyarrow.parquet as pq

    predictions = path / "predictions.parquet"
    table = pq.read_table(predictions)
    rows = table.to_pylist()
    rows[0]["y_pred_shape"] = [3, 1]
    pq.write_table(pa.Table.from_pylist(rows, schema=table.schema), predictions)


# --- inspect ---------------------------------------------------------------
def test_inspect_recognized_returns_success(sqlite_v2_workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = commands.inspect(sqlite_v2_workspace, fmt="json")
    assert code == ExitCode.SUCCESS
    assert "sqlite-workspace-v2" in capsys.readouterr().out


def test_inspect_unknown_returns_unsupported(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert commands.inspect(empty, fmt="text") == ExitCode.UNSUPPORTED_INPUT


def test_inspect_does_not_touch_source(sqlite_v2_workspace: Path) -> None:
    _unchanged(sqlite_v2_workspace, lambda: commands.inspect(sqlite_v2_workspace, fmt="json"))


def test_inspect_refuses_report_inside_source(sqlite_v2_workspace: Path) -> None:
    with pytest.raises(PolicyRefusal):
        commands.inspect(sqlite_v2_workspace, report_path=sqlite_v2_workspace / "r.json")


# --- migrate: pre-flight refusals -----------------------------------------
def test_migrate_refuses_aliased_output(sqlite_v2_workspace: Path) -> None:
    with pytest.raises(PolicyRefusal):
        commands.migrate(
            sqlite_v2_workspace, output=sqlite_v2_workspace, target=vocab.TARGET_WORKSPACE_V2, tool_version="0.0.1"
        )


def test_migrate_refuses_output_inside_source(sqlite_v2_workspace: Path) -> None:
    with pytest.raises(PolicyRefusal):
        commands.migrate(
            sqlite_v2_workspace,
            output=sqlite_v2_workspace / "out",
            target=vocab.TARGET_WORKSPACE_V2,
            tool_version="0.0.1",
        )


def test_migrate_native_target_is_gated(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    with pytest.raises(UnsupportedInput) as exc:
        commands.migrate(
            sqlite_v2_workspace, output=tmp_path / "out", target=vocab.TARGET_NATIVE_RESULTS_V1, tool_version="0.0.1"
        )
    assert exc.value.cause == vocab.CAUSE_UNSUPPORTED_CAPABILITY


def test_migrate_refuses_non_empty_output(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "stale").write_text("x", encoding="utf-8")
    with pytest.raises(PolicyRefusal):
        commands.migrate(
            sqlite_v2_workspace, output=out, target=vocab.TARGET_WORKSPACE_V2, copy_only=True, tool_version="0.0.1"
        )


def test_migrate_refuses_forward_version(forward_version_workspace: Path, tmp_path: Path) -> None:
    with pytest.raises(UnsupportedInput) as exc:
        commands.migrate(
            forward_version_workspace,
            output=tmp_path / "out",
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            tool_version="0.0.1",
        )
    assert exc.value.cause == vocab.CAUSE_FORWARD_VERSION


def test_migrate_unknown_source_is_unsupported(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(UnsupportedInput):
        commands.migrate(
            empty, output=tmp_path / "out", target=vocab.TARGET_WORKSPACE_V2, copy_only=True, tool_version="0.0.1"
        )


# --- migrate: dry-run ------------------------------------------------------
def test_migrate_dry_run_writes_no_output_store(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    manifest = tmp_path / "preview-manifest.json"

    def run() -> None:
        code = commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            manifest_path=manifest,
            dry_run=True,
            tool_version="0.0.1",
        )
        assert code == ExitCode.SUCCESS

    _unchanged(sqlite_v2_workspace, run)
    assert not out.exists()  # no output store created in dry-run
    assert manifest.exists()  # preview written to the explicit outside path


def test_migrate_manifest_records_source_fingerprint(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    manifest = tmp_path / "preview-manifest.json"
    commands.migrate(
        sqlite_v2_workspace,
        output=tmp_path / "out",
        target=vocab.TARGET_WORKSPACE_V2,
        manifest_path=manifest,
        dry_run=True,
        tool_version="0.0.1",
    )
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["source"]["fingerprint"].startswith("sha256:")


def test_migrate_dry_run_refuses_manifest_inside_source(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    with pytest.raises(PolicyRefusal):
        commands.migrate(
            sqlite_v2_workspace,
            output=tmp_path / "out",
            target=vocab.TARGET_WORKSPACE_V2,
            manifest_path=sqlite_v2_workspace / "m.json",
            dry_run=True,
            tool_version="0.0.1",
        )


def test_migrate_dry_run_writes_unsupported_report_for_legacy_workspace(
    legacy_workspace_inputs: Path,
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    unsupported_report = tmp_path / "unsupported-report.json"
    manifest = tmp_path / "preview-manifest.json"

    def run() -> None:
        code = commands.migrate(
            legacy_workspace_inputs,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            manifest_path=manifest,
            unsupported_report_path=unsupported_report,
            dry_run=True,
            tool_version="0.0.1",
        )
        assert code == ExitCode.SUCCESS

    _unchanged(legacy_workspace_inputs, run)
    assert not out.exists()

    unsupported = json.loads(unsupported_report.read_text(encoding="utf-8"))
    assert unsupported["counts"]["unsupported"] == 3
    assert {item["source_kind"] for item in unsupported["unsupported"]} == {
        "duckdb-workspace",
        "fs-runs-legacy",
        "loose-predictions",
    }
    assert {item["disposition"] for item in unsupported["unsupported"]} == {"would_preserve"}
    preview_manifest = json.loads(manifest.read_text(encoding="utf-8"))
    assert preview_manifest["unsupported"] == unsupported["unsupported"]


# --- migrate: best-effort preservation and transforms ----------------------
def test_migrate_sqlite_v2_workspace_preserves_opaque_best_effort(
    sqlite_v2_workspace: Path,
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"

    def run() -> None:
        code = commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            verify=True,
            tool_version="0.0.1",
        )
        assert code == ExitCode.MIGRATED_WITH_WARNINGS

    _unchanged(sqlite_v2_workspace, run)
    assert (out / "store.sqlite").exists()
    assert (out / "preserved" / "sqlite-workspace-v2" / "store.sqlite").exists()

    manifest = json.loads((out / "migration-manifest.json").read_text(encoding="utf-8"))
    unsupported = json.loads((out / "unsupported-report.json").read_text(encoding="utf-8"))
    assert manifest["unsupported"][0]["source_kind"] == "sqlite-workspace-v2"
    assert manifest["unsupported"][0]["disposition"] == "preserved"
    assert unsupported["unsupported"] == manifest["unsupported"]


def test_migrate_legacy_workspace_preserves_non_lowerable_payloads(
    legacy_workspace_inputs: Path,
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"

    def run() -> None:
        code = commands.migrate(
            legacy_workspace_inputs,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            verify=True,
            tool_version="0.0.1",
        )
        assert code == ExitCode.MIGRATED_WITH_WARNINGS

    _unchanged(legacy_workspace_inputs, run)

    manifest = json.loads((out / "migration-manifest.json").read_text(encoding="utf-8"))
    report = json.loads((out / "migration-report.json").read_text(encoding="utf-8"))
    unsupported = json.loads((out / "unsupported-report.json").read_text(encoding="utf-8"))

    assert (out / "store.sqlite").exists()
    assert (out / "preserved" / "duckdb-workspace" / "store.duckdb").read_bytes() == b"legacy duckdb payload"
    assert (out / "preserved" / "fs-runs-legacy" / "runs" / "run-1" / "pipeline-1" / "manifest.yaml").exists()
    assert (out / "preserved" / "loose-predictions" / legacy_workspace_inputs.name / "run_predictions.json").exists()
    assert (out / "preserved" / "loose-predictions" / legacy_workspace_inputs.name / "sample.meta.parquet").exists()
    assert not (out / "preserved" / "loose-predictions" / legacy_workspace_inputs.name / "store.duckdb").exists()

    assert manifest["checksums"]["preserved/duckdb-workspace/store.duckdb"].startswith("sha256:")
    assert report["status"] == vocab.STATUS_MIGRATED_WITH_WARNINGS
    assert report["unsupported_counts"]["preserved"] == 3
    assert unsupported["counts"]["unsupported"] == 3
    assert unsupported["counts"]["preserved"] == 3
    assert {item["disposition"] for item in unsupported["unsupported"]} == {"preserved"}
    assert commands.verify(out, manifest_path=out / "migration-manifest.json") == ExitCode.SUCCESS


def test_migrate_sqlite_legacy_arrays_to_workspace_v2(
    sqlite_legacy_arrays_workspace: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"

    def run() -> None:
        code = commands.migrate(
            sqlite_legacy_arrays_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            verify=True,
            tool_version="0.0.1",
        )
        assert code == ExitCode.SUCCESS

    _unchanged(sqlite_legacy_arrays_workspace, run)

    manifest = json.loads((out / "migration-manifest.json").read_text(encoding="utf-8"))
    report = json.loads((out / "migration-report.json").read_text(encoding="utf-8"))
    id_map = json.loads((out / "migration-id-map.json").read_text(encoding="utf-8"))

    store = out / "store.sqlite"
    arrays = out / "arrays" / "dataset-a.parquet"
    preserved = out / "preserved" / "legacy-prediction-arrays.jsonl"
    assert store.exists()
    assert arrays.exists()
    assert preserved.exists()
    assert "store.sqlite" in manifest["checksums"]
    assert "arrays/dataset-a.parquet" in manifest["checksums"]
    assert "preserved/legacy-prediction-arrays.jsonl" in manifest["checksums"]
    assert manifest["checksums"]["arrays:pred-1"].startswith("sha256:")
    assert manifest["preserved_opaque"] == [
        {
            "path": "preserved/legacy-prediction-arrays.jsonl",
            "reason": "legacy_prediction_arrays",
            "checksum": manifest["checksums"]["preserved/legacy-prediction-arrays.jsonl"],
        }
    ]
    assert manifest["unsupported"] == []
    assert report["status"] == vocab.STATUS_SUCCESS
    assert report["migrated_counts"]["runs"] == 1
    assert report["migrated_counts"]["pipelines"] == 1
    assert report["migrated_counts"]["chains"] == 1
    assert report["migrated_counts"]["predictions"] == 1
    assert report["migrated_counts"]["arrays"] == 1
    assert report["verification_summary"]["passed"] is True
    assert id_map["schema_version"] == 1


def test_migrate_sqlite_legacy_arrays_writes_runtime_parquet(
    sqlite_legacy_arrays_workspace: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_legacy_arrays_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        tool_version="0.0.1",
    )

    pytest.importorskip("pyarrow.parquet")
    import pyarrow.parquet as pq

    table = pq.read_table(out / "arrays" / "dataset-a.parquet")
    row = table.to_pylist()[0]
    assert row == {
        "prediction_id": "pred-1",
        "dataset_name": "dataset-a",
        "model_name": "PLSRegression",
        "fold_id": "fold-0",
        "partition": "val",
        "metric": "rmse",
        "val_score": 0.1,
        "task_type": "regression",
        "y_true": [1.0, 2.0, 3.0],
        "y_pred": [1.1, 1.9, 3.2],
        "y_proba": None,
        "y_proba_shape": None,
        "sample_indices": [0, 1, 2],
        "weights": None,
        "sample_metadata": None,
    }


def test_migrate_sqlite_legacy_arrays_store_is_runtime_v2_shape(
    sqlite_legacy_arrays_workspace: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_legacy_arrays_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        tool_version="0.0.1",
    )

    import sqlite3

    con = sqlite3.connect(out / "store.sqlite")
    try:
        version = con.execute("PRAGMA user_version").fetchone()[0]
        assert version == 2
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "prediction_arrays" not in tables
        assert {"runs", "pipelines", "chains", "predictions", "artifacts", "logs", "projects"} <= tables
        pred = con.execute(
            "SELECT prediction_id, dataset_name, model_name, metric, task_type FROM predictions"
        ).fetchone()
        assert pred == ("pred-1", "dataset-a", "PLSRegression", "rmse", "regression")
    finally:
        con.close()


def test_migrate_sqlite_legacy_arrays_strict_lowers_without_warnings(
    sqlite_legacy_arrays_workspace: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    code = commands.migrate(
        sqlite_legacy_arrays_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        strict=True,
        verify=True,
        tool_version="0.0.1",
    )
    assert code == ExitCode.SUCCESS
    report = json.loads((out / "migration-report.json").read_text(encoding="utf-8"))
    assert report["status"] == vocab.STATUS_SUCCESS
    assert report["warnings"] == []


def test_migrate_native_results_preserves_opaque_best_effort(
    native_results_dir: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"

    def run() -> None:
        code = commands.migrate(
            native_results_dir,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            verify=True,
            tool_version="0.0.1",
        )
        assert code == ExitCode.MIGRATED_WITH_WARNINGS

    _unchanged(native_results_dir, run)

    manifest = json.loads((out / "migration-manifest.json").read_text(encoding="utf-8"))
    report = json.loads((out / "migration-report.json").read_text(encoding="utf-8"))
    unsupported = json.loads((out / "unsupported-report.json").read_text(encoding="utf-8"))
    preserved_root = out / "preserved" / "native-results-v1" / native_results_dir.name

    assert (out / "store.sqlite").exists()
    assert (preserved_root / "manifest.json").exists()
    assert (preserved_root / "score_set.json").exists()
    assert (preserved_root / "predictions.parquet").exists()
    assert "store.sqlite" in manifest["checksums"]
    assert f"preserved/native-results-v1/{native_results_dir.name}/manifest.json" in manifest["checksums"]
    assert manifest["preserved_opaque"] == [
        {
            "path": f"preserved/native-results-v1/{native_results_dir.name}",
            "reason": "native-results-v1",
            "checksum": manifest["preserved_opaque"][0]["checksum"],
        }
    ]
    assert manifest["unsupported"][0]["source_kind"] == "native-results-v1"
    assert manifest["unsupported"][0]["disposition"] == "preserved"
    assert unsupported["counts"]["unsupported"] == 1
    assert unsupported["unsupported"] == manifest["unsupported"]
    assert report["status"] == vocab.STATUS_MIGRATED_WITH_WARNINGS
    assert report["preserved_counts"]["opaque_artifacts"] == 1
    assert report["verification_summary"]["passed"] is True


def test_migrate_native_results_multidimensional_arrays_dry_run_would_preserve(
    lowerable_native_results_dir: Path,
    tmp_path: Path,
) -> None:
    _mark_native_results_as_multidimensional(lowerable_native_results_dir)
    out = tmp_path / "out"
    manifest_path = tmp_path / "preview-manifest.json"
    unsupported_path = tmp_path / "unsupported-report.json"

    def run() -> None:
        code = commands.migrate(
            lowerable_native_results_dir,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            manifest_path=manifest_path,
            unsupported_report_path=unsupported_path,
            dry_run=True,
            tool_version="0.0.1",
        )
        assert code == ExitCode.SUCCESS

    _unchanged(lowerable_native_results_dir, run)

    unsupported = json.loads(unsupported_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert not out.exists()
    assert unsupported["counts"]["unsupported"] == 1
    assert unsupported["unsupported"] == manifest["unsupported"]
    assert unsupported["unsupported"][0]["source_kind"] == "native-results-v1"
    assert unsupported["unsupported"][0]["disposition"] == "would_preserve"
    assert unsupported["unsupported"][0]["cause"] == vocab.CAUSE_UNSUPPORTED_SHAPE
    assert "workspace-v2 sidecars preserve only flat" in unsupported["unsupported"][0]["reason"]


def test_migrate_native_results_multidimensional_arrays_preserves_opaque_best_effort(
    lowerable_native_results_dir: Path,
    tmp_path: Path,
) -> None:
    _mark_native_results_as_multidimensional(lowerable_native_results_dir)
    out = tmp_path / "out"

    def run() -> None:
        code = commands.migrate(
            lowerable_native_results_dir,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            verify=True,
            tool_version="0.0.1",
        )
        assert code == ExitCode.MIGRATED_WITH_WARNINGS

    _unchanged(lowerable_native_results_dir, run)

    manifest = json.loads((out / "migration-manifest.json").read_text(encoding="utf-8"))
    report = json.loads((out / "migration-report.json").read_text(encoding="utf-8"))
    unsupported = json.loads((out / "unsupported-report.json").read_text(encoding="utf-8"))
    preserved_root = out / "preserved" / "native-results-v1" / lowerable_native_results_dir.name

    assert (out / "store.sqlite").exists()
    assert not (out / "arrays").exists()
    assert (preserved_root / "predictions.parquet").exists()
    assert manifest["unsupported"][0]["source_kind"] == "native-results-v1"
    assert manifest["unsupported"][0]["disposition"] == "preserved"
    assert manifest["unsupported"][0]["cause"] == vocab.CAUSE_UNSUPPORTED_SHAPE
    assert "workspace-v2 sidecars preserve only flat" in manifest["unsupported"][0]["reason"]
    assert unsupported["unsupported"] == manifest["unsupported"]
    assert report["status"] == vocab.STATUS_MIGRATED_WITH_WARNINGS
    assert report["preserved_counts"]["opaque_artifacts"] == 1
    assert report["verification_summary"]["passed"] is True


def test_migrate_native_results_multidimensional_arrays_strict_refuses_without_output(
    lowerable_native_results_dir: Path,
    tmp_path: Path,
) -> None:
    _mark_native_results_as_multidimensional(lowerable_native_results_dir)
    out = tmp_path / "out"

    with pytest.raises(UnsupportedInput) as exc:
        commands.migrate(
            lowerable_native_results_dir,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            strict=True,
            tool_version="0.0.1",
        )

    assert exc.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE
    assert "workspace-v2 sidecars preserve only flat" in exc.value.message
    assert not out.exists()


def test_migrate_native_results_lowers_preview_metadata(
    lowerable_native_results_dir: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"

    def run() -> None:
        code = commands.migrate(
            lowerable_native_results_dir,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            strict=True,
            verify=True,
            tool_version="0.0.1",
        )
        assert code == ExitCode.SUCCESS

    _unchanged(lowerable_native_results_dir, run)

    manifest = json.loads((out / "migration-manifest.json").read_text(encoding="utf-8"))
    report = json.loads((out / "migration-report.json").read_text(encoding="utf-8"))
    unsupported = json.loads((out / "unsupported-report.json").read_text(encoding="utf-8"))
    preserved_root = out / "preserved" / "native-results-v1" / lowerable_native_results_dir.name
    arrays = out / "arrays" / "dataset-a.parquet"

    assert (out / "store.sqlite").exists()
    assert arrays.exists()
    assert (preserved_root / "manifest.json").exists()
    assert (preserved_root / "score_set.json").exists()
    assert (preserved_root / "predictions.parquet").exists()
    assert manifest["preserved_opaque"] == []
    assert manifest["unsupported"] == []
    assert unsupported["counts"]["unsupported"] == 0
    assert unsupported["unsupported"] == []
    assert "store.sqlite" in manifest["checksums"]
    assert "arrays/dataset-a.parquet" in manifest["checksums"]
    assert f"preserved/native-results-v1/{lowerable_native_results_dir.name}/predictions.parquet" in manifest[
        "checksums"
    ]
    assert report["status"] == vocab.STATUS_SUCCESS
    assert report["migrated_counts"]["runs"] == 1
    assert report["migrated_counts"]["pipelines"] == 1
    assert report["migrated_counts"]["chains"] == 1
    assert report["migrated_counts"]["predictions"] == 1
    assert report["migrated_counts"]["arrays"] == 1
    assert report["preserved_counts"]["native_payloads"] == 1
    assert report["target_summary"]["preview"]["native_results_metadata_only"] is False
    assert report["target_summary"]["preview"]["native_results_array_sidecars"] is True
    assert report["verification_summary"]["passed"] is True
    assert report["verification_summary"]["checks"]["array_checksum_coverage"]["status"] == "passed"

    con = sqlite3.connect(out / "store.sqlite")
    try:
        row = con.execute(
            """
            SELECT pl.run_id, p.dataset_name, p.model_name, p.fold_id, p.partition, p.metric, p.task_type, p.n_samples
            FROM predictions p
            JOIN pipelines pl ON p.pipeline_id = pl.pipeline_id
            """
        ).fetchone()
        assert row == ("run-native-1", "dataset-a", "PLSRegression", "fold-0", "val", "rmse", "regression", 3)
        pipeline = con.execute(
            "SELECT run_id, dataset_name, status, metric FROM pipelines"
        ).fetchone()
        assert pipeline == ("run-native-1", "dataset-a", "completed", "rmse")
    finally:
        con.close()

    pytest.importorskip("pyarrow.parquet")
    import pyarrow.parquet as pq

    native_row = pq.read_table(arrays).to_pylist()[0]
    prediction_id = native_row["prediction_id"]
    assert manifest["checksums"][f"arrays:{prediction_id}"].startswith("sha256:")
    assert native_row == {
        "prediction_id": prediction_id,
        "dataset_name": "dataset-a",
        "model_name": "PLSRegression",
        "fold_id": "fold-0",
        "partition": "val",
        "metric": "rmse",
        "val_score": 0.1,
        "task_type": "regression",
        "y_true": [1.0, 2.0, 3.0],
        "y_pred": [1.1, 1.9, 3.2],
        "y_proba": None,
        "y_proba_shape": None,
        "sample_indices": [0, 1, 2],
        "weights": None,
        "sample_metadata": None,
    }


def test_migrate_native_results_strict_refuses_without_output(
    native_results_dir: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    with pytest.raises(UnsupportedInput) as exc:
        commands.migrate(
            native_results_dir,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            strict=True,
            tool_version="0.0.1",
        )
    assert exc.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE
    assert "missing manifest field(s): run_id, engine, score_set_hash" in exc.value.message
    assert not out.exists()


def test_migrate_n4a_bundle_preserves_opaque_best_effort(
    n4a_bundle: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    code = commands.migrate(
        n4a_bundle,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        verify=True,
        tool_version="0.0.1",
    )
    assert code == ExitCode.MIGRATED_WITH_WARNINGS

    manifest = json.loads((out / "migration-manifest.json").read_text(encoding="utf-8"))
    preserved = out / "preserved" / "n4a-bundle" / n4a_bundle.name
    assert preserved.exists()
    assert f"preserved/n4a-bundle/{n4a_bundle.name}" in manifest["checksums"]
    assert manifest["preserved_opaque"][0]["reason"] == "n4a-bundle"
    assert commands.verify(out, manifest_path=out / "migration-manifest.json") == ExitCode.SUCCESS


def test_migrate_refuses_inert_strict_on_copy_only(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    with pytest.raises(UnsupportedInput) as exc:
        commands.migrate(
            sqlite_v2_workspace,
            output=tmp_path / "out",
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            strict=True,
            tool_version="0.0.1",
        )
    assert exc.value.cause == vocab.CAUSE_INVALID_REQUEST


def test_migrate_refuses_unimplemented_trusted_joblib(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    with pytest.raises(UnsupportedInput) as exc:
        commands.migrate(
            sqlite_v2_workspace,
            output=tmp_path / "out",
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            trusted_load_joblib=True,
            tool_version="0.0.1",
        )
    assert exc.value.cause == vocab.CAUSE_UNSUPPORTED_CAPABILITY


# --- migrate: copy-only round-trip + verify --------------------------------
def test_copy_only_round_trip_and_verify(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"

    def run() -> None:
        code = commands.migrate(
            sqlite_v2_workspace, output=out, target=vocab.TARGET_WORKSPACE_V2, copy_only=True, tool_version="0.0.1"
        )
        assert code == ExitCode.SUCCESS

    _unchanged(sqlite_v2_workspace, run)

    manifest = out / "migration-manifest.json"
    assert manifest.exists()
    assert (out / "migration-report.json").exists()
    assert (out / "payload" / "store.sqlite").exists()

    assert commands.verify(out, manifest_path=manifest) == ExitCode.SUCCESS


def test_copy_only_manifest_uses_contract_inventory_shape(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_v2_workspace, output=out, target=vocab.TARGET_WORKSPACE_V2, copy_only=True, tool_version="0.0.1"
    )
    manifest = json.loads((out / "migration-manifest.json").read_text(encoding="utf-8"))
    input_entry = manifest["input_inventory"][0]
    assert {"path", "source_kind", "tables", "row_counts", "discovered_manifests", "discovered_bundles"} <= set(
        input_entry
    )
    output_entry = manifest["output_inventory"][0]
    assert output_entry == {
        "path": "payload",
        "tables": {},
        "row_counts": {"files": 1},
        "generated_manifests": [
            "migration-manifest.json",
            "migration-report.json",
            "migration-id-map.json",
            "unsupported-report.json",
        ],
    }


def test_copy_only_verify_records_verification_summary(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_v2_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        copy_only=True,
        verify=True,
        tool_version="0.0.1",
    )
    report = json.loads((out / "migration-report.json").read_text(encoding="utf-8"))
    assert report["verification_summary"]["ran"] is True
    assert report["verification_summary"]["passed"] is True


def test_verify_detects_tampering(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_v2_workspace, output=out, target=vocab.TARGET_WORKSPACE_V2, copy_only=True, tool_version="0.0.1"
    )
    # Tamper with a copied payload file.
    (out / "payload" / "store.sqlite").write_bytes(b"corrupted")
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=out / "migration-manifest.json")


def test_verify_detects_orphan_file(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_v2_workspace, output=out, target=vocab.TARGET_WORKSPACE_V2, copy_only=True, tool_version="0.0.1"
    )
    (out / "payload" / "surprise.txt").write_text("unlisted", encoding="utf-8")
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=out / "migration-manifest.json")


def test_verify_detects_preserved_opaque_file_checksum_mismatch(
    n4a_bundle: Path,
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        n4a_bundle,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        tool_version="0.0.1",
    )

    manifest_path = out / "migration-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    preserved_path = manifest["preserved_opaque"][0]["path"]
    manifest["preserved_opaque"][0]["checksum"] = "sha256:" + ("0" * 64)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report_path = tmp_path / "verify-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=manifest_path, report_path=report_path)

    report = json.loads(report_path.read_text(encoding="utf-8"))
    coverage = report["verification_summary"]["checks"]["preserved_payload_coverage"]
    assert coverage["status"] == "failed"
    assert coverage["mismatched_payloads"] == [preserved_path]


def test_verify_detects_preserved_opaque_directory_checksum_mismatch(
    legacy_workspace_inputs: Path,
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        legacy_workspace_inputs,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        tool_version="0.0.1",
    )

    manifest_path = out / "migration-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    preserved = next(item for item in manifest["preserved_opaque"] if item["path"].endswith("/runs"))
    preserved["checksum"] = "sha256:" + ("0" * 64)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report_path = tmp_path / "verify-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=manifest_path, report_path=report_path)

    report = json.loads(report_path.read_text(encoding="utf-8"))
    coverage = report["verification_summary"]["checks"]["preserved_payload_coverage"]
    assert coverage["status"] == "failed"
    assert coverage["mismatched_payloads"] == [preserved["path"]]


def test_verify_requires_preserved_opaque_ledger_when_opaque_payloads_exist(
    n4a_bundle: Path,
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        n4a_bundle,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        tool_version="0.0.1",
    )

    manifest_path = out / "migration-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    unsupported_preserved = sum(
        1 for item in manifest["unsupported"] if item["disposition"] == "preserved"
    )
    assert unsupported_preserved > 0
    manifest["preserved_opaque"] = []
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report_path = tmp_path / "verify-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=manifest_path, report_path=report_path)

    report = json.loads(report_path.read_text(encoding="utf-8"))
    coverage = report["verification_summary"]["checks"]["preserved_payload_coverage"]
    assert coverage["status"] == "failed"
    assert coverage["missing_opaque_payloads"] == unsupported_preserved


def test_verify_requires_preserved_opaque_key_when_opaque_payloads_exist(
    n4a_bundle: Path,
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        n4a_bundle,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        tool_version="0.0.1",
    )

    manifest_path = out / "migration-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    unsupported_preserved = sum(
        1 for item in manifest["unsupported"] if item["disposition"] == "preserved"
    )
    del manifest["preserved_opaque"]
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report_path = tmp_path / "verify-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=manifest_path, report_path=report_path)

    report = json.loads(report_path.read_text(encoding="utf-8"))
    coverage = report["verification_summary"]["checks"]["preserved_payload_coverage"]
    assert coverage["status"] == "failed"
    assert coverage["missing_opaque_payloads"] == unsupported_preserved


def test_verify_rejects_invalid_preserved_opaque_ledger(
    n4a_bundle: Path,
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        n4a_bundle,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        tool_version="0.0.1",
    )

    manifest_path = out / "migration-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["preserved_opaque"] = {}
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report_path = tmp_path / "verify-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=manifest_path, report_path=report_path)

    report = json.loads(report_path.read_text(encoding="utf-8"))
    coverage = report["verification_summary"]["checks"]["preserved_payload_coverage"]
    assert coverage["status"] == "failed"
    assert coverage["invalid_entries"] == ["<preserved_opaque>"]


def test_verify_rejects_duplicate_preserved_opaque_paths(
    n4a_bundle: Path,
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        n4a_bundle,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        tool_version="0.0.1",
    )

    manifest_path = out / "migration-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["preserved_opaque"].append(dict(manifest["preserved_opaque"][0]))
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report_path = tmp_path / "verify-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=manifest_path, report_path=report_path)

    report = json.loads(report_path.read_text(encoding="utf-8"))
    coverage = report["verification_summary"]["checks"]["preserved_payload_coverage"]
    assert coverage["status"] == "failed"
    assert coverage["duplicate_paths"] == [manifest["preserved_opaque"][0]["path"]]


def test_verify_rejects_preserved_opaque_paths_outside_preserved(
    n4a_bundle: Path,
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        n4a_bundle,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        tool_version="0.0.1",
    )

    manifest_path = out / "migration-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["preserved_opaque"][0]["path"] = "payload/not-preserved"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report_path = tmp_path / "verify-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=manifest_path, report_path=report_path)

    report = json.loads(report_path.read_text(encoding="utf-8"))
    coverage = report["verification_summary"]["checks"]["preserved_payload_coverage"]
    assert coverage["status"] == "failed"
    assert coverage["outside_preserved"] == ["payload/not-preserved"]


def test_verify_detects_array_row_checksum_mismatch(
    sqlite_legacy_arrays_workspace: Path, tmp_path: Path
) -> None:
    pytest.importorskip("pyarrow")
    import pyarrow as pa
    import pyarrow.parquet as pq

    out = tmp_path / "out"
    commands.migrate(
        sqlite_legacy_arrays_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        tool_version="0.0.1",
    )

    arrays = out / "arrays" / "dataset-a.parquet"
    table = pq.read_table(arrays)
    row = table.to_pylist()[0]
    row["y_pred"] = [9.9, 9.8, 9.7]
    pq.write_table(pa.Table.from_pylist([row], schema=table.schema), arrays, compression="zstd", compression_level=3)

    manifest_path = out / "migration-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["checksums"]["arrays/dataset-a.parquet"] = sha256_file(arrays)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report_path = tmp_path / "verify-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=manifest_path, report_path=report_path)

    report = json.loads(report_path.read_text(encoding="utf-8"))
    coverage = report["verification_summary"]["checks"]["array_checksum_coverage"]
    assert coverage["status"] == "failed"
    assert coverage["mismatched_rows"] == ["pred-1"]


def test_verify_detects_native_results_sidecar_row_checksum_mismatch(
    lowerable_native_results_dir: Path,
    tmp_path: Path,
) -> None:
    pytest.importorskip("pyarrow")
    import pyarrow as pa
    import pyarrow.parquet as pq

    out = tmp_path / "out"
    commands.migrate(
        lowerable_native_results_dir,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        strict=True,
        tool_version="0.0.1",
    )

    arrays = out / "arrays" / "dataset-a.parquet"
    table = pq.read_table(arrays)
    row = table.to_pylist()[0]
    prediction_id = row["prediction_id"]
    row["sample_indices"] = [99, 100, 101]
    pq.write_table(pa.Table.from_pylist([row], schema=table.schema), arrays, compression="zstd", compression_level=3)

    manifest_path = out / "migration-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["checksums"]["arrays/dataset-a.parquet"] = sha256_file(arrays)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report_path = tmp_path / "verify-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=manifest_path, report_path=report_path)

    report = json.loads(report_path.read_text(encoding="utf-8"))
    coverage = report["verification_summary"]["checks"]["array_checksum_coverage"]
    assert coverage["status"] == "failed"
    assert coverage["mismatched_rows"] == [prediction_id]


def test_verify_rejects_unreadable_manifest(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(UnsupportedInput):
        commands.verify(out, manifest_path=tmp_path / "does-not-exist.json")

"""Golden fixture coverage for reduced legacy converter payloads."""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from nirs4all_tools import commands, policy, vocab
from nirs4all_tools.checksums import sha256_file
from nirs4all_tools.errors import PolicyRefusal, UnsupportedInput
from nirs4all_tools.exit_codes import ExitCode

FIXTURES = Path(__file__).parent / "fixtures" / "legacy"


def _copy_fixture_tree(name: str, tmp_path: Path) -> Path:
    source = FIXTURES / name
    target = tmp_path / name
    shutil.copytree(source, target)
    return target


def _materialize_sqlite_fixture(sql_name: str, tmp_path: Path) -> Path:
    root = tmp_path / sql_name.removesuffix(".sql")
    root.mkdir()
    con = sqlite3.connect(root / "store.sqlite")
    try:
        con.executescript((FIXTURES / sql_name).read_text(encoding="utf-8"))
        con.commit()
    finally:
        con.close()
    return root


def _copy_standalone_loose_fixture(tmp_path: Path) -> Path:
    source = FIXTURES / "old_workspace_mixed"
    target = tmp_path / "standalone_loose_predictions"
    target.mkdir()
    shutil.copy2(source / "run_predictions.json", target / "run_predictions.json")
    shutil.copy2(source / "sample.meta.parquet", target / "sample.meta.parquet")
    return target


def _copy_standalone_legacy_runs_fixture(tmp_path: Path) -> Path:
    source = FIXTURES / "old_workspace_mixed"
    target = tmp_path / "standalone_legacy_runs"
    shutil.copytree(source / "runs", target / "runs")
    shutil.copy2(source / "run_predictions.json", target / "run_predictions.json")
    shutil.copy2(source / "sample.meta.parquet", target / "sample.meta.parquet")
    return target


def _assert_source_unchanged(source: Path, before: policy.TreeSnapshot) -> None:
    assert policy.diff_snapshots(before, policy.snapshot_tree(source)) == []


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_golden_mixed_workspace_fixture_labels_are_release_honest() -> None:
    source = FIXTURES / "old_workspace_mixed"

    duckdb_payload = (source / "store.duckdb").read_bytes()
    assert duckdb_payload == (
        b"nirs4all-tools opaque duckdb sentinel\n"
        b"format: not a DuckDB database\n"
        b"claim: detection and byte preservation only\n"
    )

    parquet_path = source / "sample.meta.parquet"
    parquet_payload = parquet_path.read_bytes()
    assert parquet_payload[:4] == b"PAR1"
    assert parquet_payload[-4:] == b"PAR1"
    assert b"placeholder" not in parquet_payload.lower()
    assert 0 < int.from_bytes(parquet_payload[-8:-4], "little") < len(parquet_payload)

    pq = pytest.importorskip("pyarrow.parquet")
    rows = pq.read_table(parquet_path).to_pylist()
    assert rows == [
        {
            "sample_id": "cassava-001",
            "prediction_id": "pred-loose-001",
            "dataset": "cassava-drymatter-2024",
            "partition": "validation",
            "row_index": 0,
        },
        {
            "sample_id": "cassava-002",
            "prediction_id": "pred-loose-001",
            "dataset": "cassava-drymatter-2024",
            "partition": "validation",
            "row_index": 1,
        },
        {
            "sample_id": "cassava-003",
            "prediction_id": "pred-loose-001",
            "dataset": "cassava-drymatter-2024",
            "partition": "validation",
            "row_index": 2,
        },
    ]


def test_golden_legacy_workspace_dry_run_reports_unsupported_without_output(tmp_path: Path) -> None:
    source = _copy_fixture_tree("old_workspace_mixed", tmp_path)
    out = tmp_path / "out"
    manifest_path = tmp_path / "dry-run-manifest.json"
    report_path = tmp_path / "dry-run-report.json"
    unsupported_path = tmp_path / "dry-run-unsupported.json"
    before = policy.snapshot_tree(source)

    code = commands.migrate(
        source,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        manifest_path=manifest_path,
        report_path=report_path,
        unsupported_report_path=unsupported_path,
        dry_run=True,
        tool_version="0.0.1",
    )

    assert code == ExitCode.SUCCESS
    assert not out.exists()
    _assert_source_unchanged(source, before)

    manifest = _read_json(manifest_path)
    report = _read_json(report_path)
    unsupported = _read_json(unsupported_path)
    assert manifest["source"]["fingerprint"].startswith("sha256:")
    assert report["status"] == vocab.STATUS_MIGRATED_WITH_WARNINGS
    assert unsupported["counts"] == {"unsupported": 3, "preserved": 3, "refused": 0, "opaque_payloads": 0}
    assert {item["source_kind"] for item in unsupported["unsupported"]} == {
        "duckdb-workspace",
        "fs-runs-legacy",
        "loose-predictions",
    }
    assert {item["disposition"] for item in unsupported["unsupported"]} == {"would_preserve"}


def test_golden_legacy_workspace_preserves_payloads_with_reports_and_verify(tmp_path: Path) -> None:
    source = _copy_fixture_tree("old_workspace_mixed", tmp_path)
    out = tmp_path / "out"
    before = policy.snapshot_tree(source)

    code = commands.migrate(
        source,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        verify=True,
        tool_version="0.0.1",
    )

    assert code == ExitCode.MIGRATED_WITH_WARNINGS
    _assert_source_unchanged(source, before)

    manifest = _read_json(out / "migration-manifest.json")
    report = _read_json(out / "migration-report.json")
    unsupported = _read_json(out / "unsupported-report.json")

    assert report["verification_summary"]["passed"] is True
    assert unsupported["counts"]["unsupported"] == 3
    assert unsupported["counts"]["preserved"] == 3
    assert unsupported["unsupported"] == manifest["unsupported"]

    preserved_duckdb = out / "preserved" / "duckdb-workspace" / "store.duckdb"
    preserved_run = out / "preserved" / "fs-runs-legacy" / "runs" / "run-2024-legacy" / "pipeline-pls"
    preserved_loose = out / "preserved" / "loose-predictions" / source.name
    assert preserved_duckdb.read_bytes() == (source / "store.duckdb").read_bytes()
    assert (preserved_run / "manifest.yaml").read_text(encoding="utf-8") == (
        source / "runs" / "run-2024-legacy" / "pipeline-pls" / "manifest.yaml"
    ).read_text(encoding="utf-8")
    assert (preserved_loose / "run_predictions.json").read_text(encoding="utf-8") == (
        source / "run_predictions.json"
    ).read_text(encoding="utf-8")
    assert (preserved_loose / "sample.meta.parquet").read_bytes() == (source / "sample.meta.parquet").read_bytes()
    assert "preserved/duckdb-workspace/store.duckdb" in manifest["checksums"]
    assert commands.verify(out, manifest_path=out / "migration-manifest.json") == ExitCode.SUCCESS


def test_golden_standalone_loose_predictions_lowers_and_preserves_payload(tmp_path: Path) -> None:
    pytest.importorskip("pyarrow.parquet")
    import pyarrow.parquet as pq

    source = _copy_standalone_loose_fixture(tmp_path)
    out = tmp_path / "out"
    before = policy.snapshot_tree(source)

    code = commands.migrate(
        source,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        strict=True,
        verify=True,
        tool_version="0.0.1",
    )

    assert code == ExitCode.SUCCESS
    _assert_source_unchanged(source, before)

    manifest = _read_json(out / "migration-manifest.json")
    report = _read_json(out / "migration-report.json")
    unsupported = _read_json(out / "unsupported-report.json")
    preserved = out / "preserved" / "loose-predictions" / source.name

    assert manifest["unsupported"] == []
    assert unsupported["counts"]["unsupported"] == 0
    assert report["migrated_counts"]["runs"] == 1
    assert report["migrated_counts"]["pipelines"] == 1
    assert report["migrated_counts"]["chains"] == 1
    assert report["migrated_counts"]["predictions"] == 1
    assert report["migrated_counts"]["arrays"] == 1
    assert report["target_summary"]["preview"]["source_payload_preserved"] == (
        f"preserved/loose-predictions/{source.name}"
    )
    assert report["verification_summary"]["checks"]["array_checksum_coverage"]["status"] == "passed"

    assert (preserved / "run_predictions.json").read_text(encoding="utf-8") == (
        source / "run_predictions.json"
    ).read_text(encoding="utf-8")
    assert (preserved / "sample.meta.parquet").read_bytes() == (source / "sample.meta.parquet").read_bytes()
    assert f"preserved/loose-predictions/{source.name}/run_predictions.json" in manifest["checksums"]
    assert f"preserved/loose-predictions/{source.name}/sample.meta.parquet" in manifest["checksums"]

    with sqlite3.connect(out / "store.sqlite") as con:
        row = con.execute(
            """
            SELECT pl.run_id, p.dataset_name, p.model_name, p.model_class, p.fold_id,
                   p.partition, p.metric, p.task_type, p.n_samples
            FROM predictions p
            JOIN pipelines pl ON p.pipeline_id = pl.pipeline_id
            """
        ).fetchone()
        assert row == (
            "run-2024-legacy",
            "cassava-drymatter-2024",
            "PLSRegression",
            "sklearn.cross_decomposition.PLSRegression",
            "fold-0",
            "validation",
            "rmse",
            "regression",
            3,
        )

    rows = pq.read_table(out / "arrays" / "cassava-drymatter-2024.parquet").to_pylist()
    prediction_id = rows[0]["prediction_id"]
    assert prediction_id == "pred-loose-001"
    assert manifest["checksums"][f"arrays:{prediction_id}"].startswith("sha256:")
    assert rows[0]["sample_indices"] == [0, 1, 2]
    assert rows[0]["y_true"] == [31.0, 30.1, 33.0]
    assert rows[0]["y_pred"] == [31.0, 30.1, 33.0]
    assert commands.verify(out, manifest_path=out / "migration-manifest.json") == ExitCode.SUCCESS


def test_golden_standalone_legacy_runs_manifest_lowers_predictions(tmp_path: Path) -> None:
    pytest.importorskip("pyarrow.parquet")
    import pyarrow.parquet as pq

    source = _copy_standalone_legacy_runs_fixture(tmp_path)
    out = tmp_path / "out"
    before = policy.snapshot_tree(source)

    code = commands.migrate(
        source,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        strict=True,
        verify=True,
        tool_version="0.0.1",
    )

    assert code == ExitCode.SUCCESS
    _assert_source_unchanged(source, before)

    manifest = _read_json(out / "migration-manifest.json")
    report = _read_json(out / "migration-report.json")
    unsupported = _read_json(out / "unsupported-report.json")
    runs_payload = out / "preserved" / "fs-runs-legacy" / "runs"
    loose_payload = out / "preserved" / "loose-predictions" / source.name

    assert manifest["unsupported"] == []
    assert manifest["preserved_opaque"] == []
    assert unsupported["counts"]["unsupported"] == 0
    assert report["migrated_counts"]["runs"] == 1
    assert report["migrated_counts"]["pipelines"] == 1
    assert report["migrated_counts"]["chains"] == 1
    assert report["migrated_counts"]["predictions"] == 1
    assert report["migrated_counts"]["arrays"] == 1
    assert report["target_summary"]["preview"]["manifest_file"] == (
        "runs/run-2024-legacy/pipeline-pls/manifest.yaml"
    )
    assert report["target_summary"]["preview"]["prediction_file"] == "run_predictions.json"
    assert report["verification_summary"]["passed"] is True

    assert (runs_payload / "run-2024-legacy" / "pipeline-pls" / "manifest.yaml").read_text(
        encoding="utf-8"
    ) == (source / "runs" / "run-2024-legacy" / "pipeline-pls" / "manifest.yaml").read_text(encoding="utf-8")
    assert (loose_payload / "run_predictions.json").read_text(encoding="utf-8") == (
        source / "run_predictions.json"
    ).read_text(encoding="utf-8")
    assert (loose_payload / "sample.meta.parquet").read_bytes() == (source / "sample.meta.parquet").read_bytes()
    assert "preserved/fs-runs-legacy/runs/run-2024-legacy/pipeline-pls/manifest.yaml" in manifest["checksums"]
    assert f"preserved/loose-predictions/{source.name}/run_predictions.json" in manifest["checksums"]

    with sqlite3.connect(out / "store.sqlite") as con:
        row = con.execute(
            """
            SELECT pl.run_id, p.pipeline_id, p.dataset_name, p.model_name, p.model_class, p.n_samples
            FROM predictions p
            JOIN pipelines pl ON p.pipeline_id = pl.pipeline_id
            """
        ).fetchone()
        assert row == (
            "run-2024-legacy",
            "pipeline-pls",
            "cassava-drymatter-2024",
            "PLSRegression",
            "sklearn.cross_decomposition.PLSRegression",
            3,
        )

    rows = pq.read_table(out / "arrays" / "cassava-drymatter-2024.parquet").to_pylist()
    assert rows[0]["prediction_id"] == "pred-loose-001"
    assert rows[0]["sample_indices"] == [0, 1, 2]
    assert commands.verify(out, manifest_path=out / "migration-manifest.json") == ExitCode.SUCCESS


def test_golden_standalone_legacy_runs_dry_run_reports_lowerable(tmp_path: Path) -> None:
    pytest.importorskip("pyarrow.parquet")
    source = _copy_standalone_legacy_runs_fixture(tmp_path)
    out = tmp_path / "out"
    manifest_path = tmp_path / "dry-run-manifest.json"
    report_path = tmp_path / "dry-run-report.json"
    unsupported_path = tmp_path / "dry-run-unsupported.json"
    before = policy.snapshot_tree(source)

    code = commands.migrate(
        source,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        manifest_path=manifest_path,
        report_path=report_path,
        unsupported_report_path=unsupported_path,
        dry_run=True,
        tool_version="0.0.1",
    )

    assert code == ExitCode.SUCCESS
    assert not out.exists()
    _assert_source_unchanged(source, before)
    manifest = _read_json(manifest_path)
    report = _read_json(report_path)
    unsupported = _read_json(unsupported_path)
    assert manifest["unsupported"] == []
    assert report["status"] == vocab.STATUS_SUCCESS
    assert unsupported["counts"] == {"unsupported": 0, "preserved": 0, "refused": 0, "opaque_payloads": 0}


def test_golden_legacy_runs_extra_prediction_json_refuses_strict_without_output(tmp_path: Path) -> None:
    source = _copy_standalone_legacy_runs_fixture(tmp_path)
    (source / "other_predictions.json").write_text('{"run_id": "other"}\n', encoding="utf-8")
    out = tmp_path / "out"
    before = policy.snapshot_tree(source)

    with pytest.raises(UnsupportedInput) as exc:
        commands.migrate(
            source,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            strict=True,
            tool_version="0.0.1",
        )

    assert exc.value.cause == vocab.CAUSE_UNSUPPORTED_CAPABILITY
    assert "manifest-referenced prediction JSON" in exc.value.message
    assert not out.exists()
    _assert_source_unchanged(source, before)


def test_golden_legacy_runs_extra_prediction_json_best_effort_preserves_all(
    tmp_path: Path,
) -> None:
    source = _copy_standalone_legacy_runs_fixture(tmp_path)
    (source / "other_predictions.json").write_text('{"run_id": "other"}\n', encoding="utf-8")
    out = tmp_path / "out"
    before = policy.snapshot_tree(source)

    code = commands.migrate(
        source,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        verify=True,
        tool_version="0.0.1",
    )

    assert code == ExitCode.MIGRATED_WITH_WARNINGS
    _assert_source_unchanged(source, before)
    manifest = _read_json(out / "migration-manifest.json")
    report = _read_json(out / "migration-report.json")
    unsupported = _read_json(out / "unsupported-report.json")
    assert report["verification_summary"]["passed"] is True
    assert unsupported["counts"]["unsupported"] == 2
    assert unsupported["counts"]["preserved"] == 2
    assert {item["source_kind"] for item in unsupported["unsupported"]} == {
        "fs-runs-legacy",
        "loose-predictions",
    }
    assert {item["disposition"] for item in unsupported["unsupported"]} == {"preserved"}
    assert unsupported["unsupported"] == manifest["unsupported"]
    assert (out / "preserved" / "loose-predictions" / source.name / "other_predictions.json").exists()
    assert not (out / "arrays").exists()


def test_golden_legacy_runs_missing_parquet_dry_run_matches_best_effort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _copy_standalone_legacy_runs_fixture(tmp_path)
    out = tmp_path / "out"
    dry_unsupported_path = tmp_path / "dry-run-unsupported.json"
    before = policy.snapshot_tree(source)
    monkeypatch.setattr(commands, "_pyarrow_runtime_array_schema", lambda: None)

    code = commands.migrate(
        source,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        unsupported_report_path=dry_unsupported_path,
        dry_run=True,
        tool_version="0.0.1",
    )

    assert code == ExitCode.SUCCESS
    assert not out.exists()
    _assert_source_unchanged(source, before)
    dry_unsupported = _read_json(dry_unsupported_path)
    assert dry_unsupported["counts"] == {"unsupported": 2, "preserved": 2, "refused": 0, "opaque_payloads": 0}

    real_out = tmp_path / "real-out"
    code = commands.migrate(
        source,
        output=real_out,
        target=vocab.TARGET_WORKSPACE_V2,
        verify=True,
        tool_version="0.0.1",
    )

    assert code == ExitCode.MIGRATED_WITH_WARNINGS
    _assert_source_unchanged(source, before)
    real_unsupported = _read_json(real_out / "unsupported-report.json")
    assert real_unsupported["counts"]["unsupported"] == dry_unsupported["counts"]["unsupported"]
    assert real_unsupported["counts"]["preserved"] == dry_unsupported["counts"]["preserved"]
    assert {item["source_kind"] for item in real_unsupported["unsupported"]} == {
        "fs-runs-legacy",
        "loose-predictions",
    }


def test_golden_legacy_runs_manifest_mismatch_refuses_without_output(tmp_path: Path) -> None:
    source = _copy_standalone_legacy_runs_fixture(tmp_path)
    manifest = source / "runs" / "run-2024-legacy" / "pipeline-pls" / "manifest.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace("pipeline_id: pipeline-pls", "pipeline_id: other-pipeline"),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    before = policy.snapshot_tree(source)

    with pytest.raises(UnsupportedInput) as exc:
        commands.migrate(
            source,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            strict=True,
            tool_version="0.0.1",
        )

    assert exc.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE
    assert "manifest and predictions JSON disagree" in exc.value.message
    assert not out.exists()
    _assert_source_unchanged(source, before)


def test_golden_legacy_runs_manifest_mismatch_best_effort_matches_dry_run(tmp_path: Path) -> None:
    source = _copy_standalone_legacy_runs_fixture(tmp_path)
    manifest = source / "runs" / "run-2024-legacy" / "pipeline-pls" / "manifest.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace("pipeline_id: pipeline-pls", "pipeline_id: other-pipeline"),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    dry_unsupported_path = tmp_path / "dry-run-unsupported.json"
    before = policy.snapshot_tree(source)

    code = commands.migrate(
        source,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        unsupported_report_path=dry_unsupported_path,
        dry_run=True,
        tool_version="0.0.1",
    )

    assert code == ExitCode.SUCCESS
    assert not out.exists()
    _assert_source_unchanged(source, before)
    dry_unsupported = _read_json(dry_unsupported_path)
    assert dry_unsupported["counts"] == {"unsupported": 2, "preserved": 2, "refused": 0, "opaque_payloads": 0}

    real_out = tmp_path / "real-out"
    code = commands.migrate(
        source,
        output=real_out,
        target=vocab.TARGET_WORKSPACE_V2,
        verify=True,
        tool_version="0.0.1",
    )

    assert code == ExitCode.MIGRATED_WITH_WARNINGS
    _assert_source_unchanged(source, before)
    real_unsupported = _read_json(real_out / "unsupported-report.json")
    assert real_unsupported["counts"]["unsupported"] == dry_unsupported["counts"]["unsupported"]
    assert real_unsupported["counts"]["preserved"] == dry_unsupported["counts"]["preserved"]
    assert {item["source_kind"] for item in real_unsupported["unsupported"]} == {
        "fs-runs-legacy",
        "loose-predictions",
    }


def test_golden_standalone_loose_predictions_strict_refuses_incomplete_json(tmp_path: Path) -> None:
    source = tmp_path / "loose-bad"
    source.mkdir()
    (source / "run_predictions.json").write_text('{"run_id": "run-missing-fields"}\n', encoding="utf-8")
    out = tmp_path / "out"
    before = policy.snapshot_tree(source)

    with pytest.raises(UnsupportedInput) as exc:
        commands.migrate(
            source,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            strict=True,
            tool_version="0.0.1",
        )

    assert exc.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE
    assert "loose-predictions preview missing field(s)" in exc.value.message
    assert not out.exists()
    _assert_source_unchanged(source, before)


def test_golden_standalone_loose_predictions_dry_run_reports_missing_parquet_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _copy_standalone_loose_fixture(tmp_path)
    out = tmp_path / "out"
    unsupported_path = tmp_path / "unsupported.json"
    before = policy.snapshot_tree(source)
    monkeypatch.setattr(commands, "_pyarrow_runtime_array_schema", lambda: None)

    code = commands.migrate(
        source,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        unsupported_report_path=unsupported_path,
        dry_run=True,
        tool_version="0.0.1",
    )

    assert code == ExitCode.SUCCESS
    assert not out.exists()
    _assert_source_unchanged(source, before)
    unsupported = _read_json(unsupported_path)
    assert unsupported["counts"] == {"unsupported": 1, "preserved": 1, "refused": 0, "opaque_payloads": 0}
    assert unsupported["unsupported"][0]["source_kind"] == "loose-predictions"
    assert unsupported["unsupported"][0]["disposition"] == "would_preserve"
    assert unsupported["unsupported"][0]["cause"] == vocab.CAUSE_UNSUPPORTED_CAPABILITY
    assert "pyarrow" in unsupported["unsupported"][0]["reason"]


def test_golden_standalone_loose_predictions_missing_parquet_best_effort_preserves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _copy_standalone_loose_fixture(tmp_path)
    out = tmp_path / "out"
    before = policy.snapshot_tree(source)
    monkeypatch.setattr(commands, "_pyarrow_runtime_array_schema", lambda: None)

    code = commands.migrate(
        source,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        verify=True,
        tool_version="0.0.1",
    )

    assert code == ExitCode.MIGRATED_WITH_WARNINGS
    _assert_source_unchanged(source, before)
    manifest = _read_json(out / "migration-manifest.json")
    report = _read_json(out / "migration-report.json")
    unsupported = _read_json(out / "unsupported-report.json")
    preserved = out / "preserved" / "loose-predictions" / source.name
    assert not (out / "arrays").exists()
    assert (preserved / "run_predictions.json").exists()
    assert unsupported["unsupported"] == manifest["unsupported"]
    assert manifest["unsupported"][0]["cause"] == vocab.CAUSE_UNSUPPORTED_CAPABILITY
    assert "pyarrow" in manifest["unsupported"][0]["reason"]
    assert report["verification_summary"]["passed"] is True


def test_golden_standalone_loose_predictions_missing_parquet_strict_refuses_without_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _copy_standalone_loose_fixture(tmp_path)
    out = tmp_path / "out"
    before = policy.snapshot_tree(source)
    monkeypatch.setattr(commands, "_pyarrow_runtime_array_schema", lambda: None)

    with pytest.raises(UnsupportedInput) as exc:
        commands.migrate(
            source,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            strict=True,
            tool_version="0.0.1",
        )

    assert exc.value.cause == vocab.CAUSE_UNSUPPORTED_CAPABILITY
    assert "pyarrow" in exc.value.message
    assert not out.exists()
    _assert_source_unchanged(source, before)


def test_golden_legacy_workspace_resume_requires_opt_in_and_verifies(tmp_path: Path) -> None:
    source = _copy_fixture_tree("old_workspace_mixed", tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    (out / "migration-report.json").write_text('{"stale": true}\n', encoding="utf-8")
    before = policy.snapshot_tree(source)

    with pytest.raises(PolicyRefusal):
        commands.migrate(source, output=out, target=vocab.TARGET_WORKSPACE_V2, tool_version="0.0.1")

    code = commands.migrate(
        source,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        resume=True,
        verify=True,
        tool_version="0.0.1",
    )

    assert code == ExitCode.MIGRATED_WITH_WARNINGS
    _assert_source_unchanged(source, before)
    report = _read_json(out / "migration-report.json")
    unsupported = _read_json(out / "unsupported-report.json")
    assert report["verification_summary"]["passed"] is True
    assert unsupported["counts"]["preserved"] == 3


def test_golden_sqlite_legacy_arrays_lowers_metadata_and_preserves_rows(tmp_path: Path) -> None:
    pytest.importorskip("pyarrow.parquet")
    import pyarrow.parquet as pq

    source = _materialize_sqlite_fixture("sqlite_legacy_arrays_workspace.sql", tmp_path)
    out = tmp_path / "out"
    before = policy.snapshot_tree(source)

    code = commands.migrate(
        source,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        strict=True,
        verify=True,
        tool_version="0.0.1",
    )

    assert code == ExitCode.SUCCESS
    _assert_source_unchanged(source, before)

    manifest = _read_json(out / "migration-manifest.json")
    report = _read_json(out / "migration-report.json")
    unsupported = _read_json(out / "unsupported-report.json")
    assert manifest["unsupported"] == []
    assert unsupported["counts"]["unsupported"] == 0
    assert report["migrated_counts"]["runs"] == 1
    assert report["migrated_counts"]["pipelines"] == 2
    assert report["migrated_counts"]["chains"] == 2
    assert report["migrated_counts"]["predictions"] == 2
    assert report["migrated_counts"]["arrays"] == 2
    assert report["verification_summary"]["checks"]["array_checksum_coverage"]["status"] == "passed"

    with sqlite3.connect(out / "store.sqlite") as con:
        assert con.execute("SELECT COUNT(*) FROM pipelines").fetchone()[0] == 2
        assert con.execute("SELECT COUNT(*) FROM predictions").fetchone()[0] == 2
        assert con.execute("SELECT dataset_name FROM pipelines ORDER BY pipeline_id").fetchall() == [
            ("corn-lot-2024",),
            ("field/block 7",),
        ]

    preserved_arrays = out / "preserved" / "legacy-prediction-arrays.jsonl"
    preserved_rows = [json.loads(line) for line in preserved_arrays.read_text(encoding="utf-8").splitlines()]
    assert preserved_rows == [
        {
            "dataset_name": "corn-lot-2024",
            "fold_id": "fold-1",
            "metric": "rmse",
            "model_name": "PLSRegression",
            "partition": "validation",
            "prediction_id": "pred-old-pls-val",
            "sample_indices": "[101,102,103]",
            "task_type": "regression",
            "val_score": 0.12,
            "weights": "[1.0,0.8,1.2]",
            "y_pred": "[32.0,31.4,31.0]",
            "y_proba": None,
            "y_true": "[32.1,31.5,30.8]",
        },
        {
            "dataset_name": "field/block 7",
            "fold_id": "fold-2",
            "metric": "accuracy",
            "model_name": "SVC",
            "partition": "test",
            "prediction_id": "pred-old-svm-test",
            "sample_indices": "[201,202,203,204]",
            "task_type": "classification",
            "val_score": 0.75,
            "weights": None,
            "y_pred": "[0,1,0,0]",
            "y_proba": "[[0.9,0.1],[0.2,0.8],[0.6,0.4],[0.8,0.2]]",
            "y_true": "[0,1,1,0]",
        },
    ]
    assert sha256_file(preserved_arrays) == "sha256:2fd39c42493dd6583ff5458217dcae877c3cb0522f7719aa1e66019c90fef8b1"
    assert manifest["checksums"]["arrays:pred-old-pls-val"] == (
        "sha256:112438ce3dae9807dd717d768096e787419977c22e8dc5f1dd615bd8e2fd19d0"
    )
    assert manifest["checksums"]["arrays:pred-old-svm-test"] == (
        "sha256:b61c6a80f92c43fb43322ca71ef0a0dcba8b4e30e8e33c7b34f49e1f0cd38cd3"
    )
    assert manifest["checksums"]["preserved/legacy-prediction-arrays.jsonl"] == sha256_file(preserved_arrays)
    assert manifest["preserved_opaque"] == [
        {
            "path": "preserved/legacy-prediction-arrays.jsonl",
            "reason": "legacy_prediction_arrays",
            "checksum": manifest["checksums"]["preserved/legacy-prediction-arrays.jsonl"],
        }
    ]

    pls_rows = pq.read_table(out / "arrays" / "corn-lot-2024.parquet").to_pylist()
    svm_rows = pq.read_table(out / "arrays" / "field_block_7.parquet").to_pylist()
    assert pls_rows[0]["prediction_id"] == "pred-old-pls-val"
    assert pls_rows[0]["sample_indices"] == [101, 102, 103]
    assert pls_rows[0]["weights"] == [1.0, 0.8, 1.2]
    assert svm_rows[0]["prediction_id"] == "pred-old-svm-test"
    assert svm_rows[0]["y_proba_shape"] == [4, 2]
    assert svm_rows[0]["y_proba"] == [0.9, 0.1, 0.2, 0.8, 0.6, 0.4, 0.8, 0.2]
    assert commands.verify(out, manifest_path=out / "migration-manifest.json") == ExitCode.SUCCESS


def test_golden_sqlite_legacy_arrays_semantic_checksums_are_deterministic(tmp_path: Path) -> None:
    """Lowered array-row and preserved-payload checksums are stable across independent runs.

    Two migrations of byte-identical legacy sources must agree on every semantic checksum
    surface -- the ``arrays:<prediction_id>`` row digests, the runtime array sidecar files, and
    the preserved legacy-arrays JSONL -- proving the release artifact does not depend on
    wall-clock time or run order. Only ``store.sqlite`` is excluded, because its ``created_at``
    columns are intentionally time-based and therefore not byte-reproducible.
    """
    pytest.importorskip("pyarrow.parquet")
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    source_a = _materialize_sqlite_fixture("sqlite_legacy_arrays_workspace.sql", first_dir)
    source_b = _materialize_sqlite_fixture("sqlite_legacy_arrays_workspace.sql", second_dir)
    out_a = tmp_path / "out-a"
    out_b = tmp_path / "out-b"

    for source, out in ((source_a, out_a), (source_b, out_b)):
        assert (
            commands.migrate(
                source,
                output=out,
                target=vocab.TARGET_WORKSPACE_V2,
                strict=True,
                verify=True,
                tool_version="0.0.1",
            )
            == ExitCode.SUCCESS
        )

    manifest_a = _read_json(out_a / "migration-manifest.json")
    manifest_b = _read_json(out_b / "migration-manifest.json")

    def semantic(manifest: dict[str, object]) -> dict[str, object]:
        checksums = manifest["checksums"]
        assert isinstance(checksums, dict)
        return {key: value for key, value in checksums.items() if key != "store.sqlite"}

    assert semantic(manifest_a) == semantic(manifest_b)
    assert set(semantic(manifest_a)) >= {
        "arrays:pred-old-pls-val",
        "arrays:pred-old-svm-test",
        "arrays/corn-lot-2024.parquet",
        "arrays/field_block_7.parquet",
        "preserved/legacy-prediction-arrays.jsonl",
    }
    assert (out_a / "preserved" / "legacy-prediction-arrays.jsonl").read_bytes() == (
        out_b / "preserved" / "legacy-prediction-arrays.jsonl"
    ).read_bytes()

"""Golden fixture coverage for reduced real legacy converter payloads."""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from nirs4all_tools import commands, policy, vocab
from nirs4all_tools.errors import PolicyRefusal
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


def _assert_source_unchanged(source: Path, before: policy.TreeSnapshot) -> None:
    assert policy.diff_snapshots(before, policy.snapshot_tree(source)) == []


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


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

    preserved_rows = [
        json.loads(line)
        for line in (out / "preserved" / "legacy-prediction-arrays.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert {row["prediction_id"] for row in preserved_rows} == {"pred-old-pls-val", "pred-old-svm-test"}
    assert manifest["preserved_opaque"][0]["reason"] == "legacy_prediction_arrays"

    pls_rows = pq.read_table(out / "arrays" / "corn-lot-2024.parquet").to_pylist()
    svm_rows = pq.read_table(out / "arrays" / "field_block_7.parquet").to_pylist()
    assert pls_rows[0]["prediction_id"] == "pred-old-pls-val"
    assert pls_rows[0]["sample_indices"] == [101, 102, 103]
    assert pls_rows[0]["weights"] == [1.0, 0.8, 1.2]
    assert svm_rows[0]["prediction_id"] == "pred-old-svm-test"
    assert svm_rows[0]["y_proba_shape"] == [4, 2]
    assert svm_rows[0]["y_proba"] == [0.9, 0.1, 0.2, 0.8, 0.6, 0.4, 0.8, 0.2]
    assert commands.verify(out, manifest_path=out / "migration-manifest.json") == ExitCode.SUCCESS

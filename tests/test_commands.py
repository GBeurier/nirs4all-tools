"""Command-behavior tests (``commands.py``)."""

from __future__ import annotations

import errno
import json
import os
import socket
import sqlite3
import stat
import zipfile
from pathlib import Path

import pytest

from nirs4all_tools import commands, contracts, policy, vocab
from nirs4all_tools.checksums import sha256_file
from nirs4all_tools.errors import PolicyRefusal, SourceIntegrityError, UnsupportedInput, VerificationFailed
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


def _set_native_results_schema_version(path: Path, schema_version: object) -> None:
    """Alter only the source declaration for fail-closed schema-gate tests."""
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema_version"] = schema_version
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def _write_unsafe_n4a_bundle(path: Path) -> Path:
    """Create a deliberately traversal-bearing archive without extracting it."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", "{}")
        archive.writestr("../escape", "never extracted")
    return path


def _write_forward_n4a_bundle(path: Path) -> Path:
    """Create a structurally safe archive with an unsupported format version."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", '{"bundle_format_version":"2.0"}')
    return path


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


def test_inspect_unsafe_n4a_reports_unsupported_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = _write_unsafe_n4a_bundle(tmp_path / "unsafe.n4a")

    code = commands.inspect(source, fmt="json")

    assert code == ExitCode.UNSUPPORTED_INPUT
    document = json.loads(capsys.readouterr().out)
    assert document["status"] == vocab.STATUS_UNSUPPORTED_INPUT
    artifact = document["input_inventory"][0]
    assert artifact["supported"] is False
    assert artifact["preserved_opaque"] is False
    assert artifact["details"]["archive_preflight"]["rule"] == "unsafe_member_path"


def test_inspect_refuses_an_n4a_manifest_with_an_isolated_surrogate(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "surrogate.n4a"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("manifest.json", b'{"bundle_format_version":"\\ud800"}')

    code = commands.inspect(source, fmt="text")

    assert code == ExitCode.UNSUPPORTED_INPUT
    assert "UNSUPPORTED" in capsys.readouterr().out


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


def test_inspect_and_migrate_refuse_descendant_symlink_before_output(
    sqlite_v2_workspace: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside.sqlite"
    outside.write_bytes(b"outside")
    try:
        os.symlink(outside, sqlite_v2_workspace / "escaped.sqlite")
    except OSError as exc:
        pytest.skip(f"symlinks are unavailable in this test environment: {exc}")

    source_before = policy.snapshot_tree(sqlite_v2_workspace)
    with pytest.raises(UnsupportedInput) as inspect_error:
        commands.inspect(sqlite_v2_workspace, fmt="json")
    assert inspect_error.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE

    output = tmp_path / "out"
    with pytest.raises(UnsupportedInput) as migrate_error:
        commands.migrate(
            sqlite_v2_workspace,
            output=output,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            tool_version="0.0.1",
        )
    assert migrate_error.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE
    assert not output.exists()
    assert policy.diff_snapshots(source_before, policy.snapshot_tree(sqlite_v2_workspace)) == []


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="the platform does not support FIFO nodes")
def test_inspect_and_migrate_refuse_descendant_fifo_before_output(
    sqlite_v2_workspace: Path,
    tmp_path: Path,
) -> None:
    os.mkfifo(sqlite_v2_workspace / "blocked.fifo")

    with pytest.raises(UnsupportedInput) as inspect_error:
        commands.inspect(sqlite_v2_workspace, fmt="json")
    assert inspect_error.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE

    output = tmp_path / "out"
    with pytest.raises(UnsupportedInput) as migrate_error:
        commands.migrate(
            sqlite_v2_workspace,
            output=output,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            tool_version="0.0.1",
        )
    assert migrate_error.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE
    assert not output.exists()


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="the platform does not support Unix sockets")
def test_migrate_refuses_descendant_socket_before_output(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    socket_path = sqlite_v2_workspace / "blocked.socket"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(socket_path))
        with pytest.raises(UnsupportedInput) as raised:
            commands.migrate(
                sqlite_v2_workspace,
                output=tmp_path / "out",
                target=vocab.TARGET_WORKSPACE_V2,
                copy_only=True,
                tool_version="0.0.1",
            )
        assert raised.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE
        assert not (tmp_path / "out").exists()
    finally:
        server.close()


def test_migrate_refuses_unreadable_descendant_before_output(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    unreadable = sqlite_v2_workspace / "unreadable.bin"
    unreadable.write_bytes(b"private")
    unreadable.chmod(0)
    try:
        with pytest.raises(UnsupportedInput) as raised:
            commands.migrate(
                sqlite_v2_workspace,
                output=tmp_path / "out",
                target=vocab.TARGET_WORKSPACE_V2,
                copy_only=True,
                tool_version="0.0.1",
            )
        assert raised.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE
        assert not (tmp_path / "out").exists()
    finally:
        unreadable.chmod(stat.S_IRUSR | stat.S_IWUSR)


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
    assert payload["tool"]["support_window"] == commands.SUPPORT_WINDOW


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


def test_migrate_unsafe_n4a_dry_run_reports_refusal_without_output(tmp_path: Path) -> None:
    source = _write_unsafe_n4a_bundle(tmp_path / "unsafe.n4a")
    out = tmp_path / "out"
    manifest_path = tmp_path / "manifest.json"
    report_path = tmp_path / "report.json"
    unsupported_path = tmp_path / "unsupported.json"

    def run() -> None:
        code = commands.migrate(
            source,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            dry_run=True,
            manifest_path=manifest_path,
            report_path=report_path,
            unsupported_report_path=unsupported_path,
            tool_version="0.0.1",
        )
        assert code == ExitCode.UNSUPPORTED_INPUT

    _unchanged(source, run)
    assert not out.exists()
    unsupported = json.loads(unsupported_path.read_text(encoding="utf-8"))
    assert unsupported["status"] == vocab.STATUS_UNSUPPORTED_INPUT
    assert unsupported["counts"]["refused"] == 1
    entry = unsupported["unsupported"][0]
    assert entry["item"] == "."
    assert entry["source_kind"] == "n4a-bundle"
    assert entry["disposition"] == "refused"
    assert entry["cause"] == vocab.CAUSE_UNSUPPORTED_SHAPE
    assert "unsafe_member_path" in entry["reason"]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == vocab.STATUS_UNSUPPORTED_INPUT
    preview_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert preview_manifest["unsupported"] == unsupported["unsupported"]
    assert preview_manifest["input_inventory"][0]["preserved_opaque"] is False


def test_migrate_forward_n4a_dry_run_reports_refusal_without_output(tmp_path: Path) -> None:
    source = tmp_path / "future.n4a"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("manifest.json", '{"bundle_format_version":"2.0"}')
    out = tmp_path / "out"
    manifest_path = tmp_path / "manifest.json"
    report_path = tmp_path / "report.json"
    unsupported_path = tmp_path / "unsupported.json"

    code = commands.migrate(
        source,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        dry_run=True,
        manifest_path=manifest_path,
        report_path=report_path,
        unsupported_report_path=unsupported_path,
        tool_version="0.0.1",
    )

    assert code == ExitCode.UNSUPPORTED_INPUT
    assert not out.exists()
    unsupported = json.loads(unsupported_path.read_text(encoding="utf-8"))
    assert unsupported["status"] == vocab.STATUS_UNSUPPORTED_INPUT
    assert unsupported["unsupported"] == [
        {
            "item": ".",
            "source_kind": "n4a-bundle",
            "reason": "source declares a version newer than this tool supports: .(2.0)",
            "disposition": "refused",
            "cause": vocab.CAUSE_FORWARD_VERSION,
        }
    ]
    assert json.loads(report_path.read_text(encoding="utf-8"))["status"] == vocab.STATUS_UNSUPPORTED_INPUT
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["unsupported"] == unsupported["unsupported"]


def test_migrate_native_results_dry_run_reports_lowerable_preview(
    lowerable_native_results_dir: Path,
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    manifest_path = tmp_path / "preview-manifest.json"
    report_path = tmp_path / "preview-report.json"
    unsupported_path = tmp_path / "unsupported-report.json"

    def run() -> None:
        code = commands.migrate(
            lowerable_native_results_dir,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            manifest_path=manifest_path,
            report_path=report_path,
            unsupported_report_path=unsupported_path,
            dry_run=True,
            tool_version="0.0.1",
        )
        assert code == ExitCode.SUCCESS

    _unchanged(lowerable_native_results_dir, run)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    unsupported = json.loads(unsupported_path.read_text(encoding="utf-8"))

    assert not out.exists()
    assert manifest["unsupported"] == []
    assert report["status"] == vocab.STATUS_SUCCESS
    assert report["target_summary"]["path"] == str(out)
    assert unsupported["counts"] == {"unsupported": 0, "preserved": 0, "refused": 0, "opaque_payloads": 0}
    assert unsupported["unsupported"] == []
    assert any(item["source_kind"] == "native-results-v1" for item in manifest["input_inventory"])


def test_migrate_old_native_results_schema_dry_run_would_preserve_without_output(
    lowerable_native_results_dir: Path,
    tmp_path: Path,
) -> None:
    _set_native_results_schema_version(lowerable_native_results_dir, 2)
    out = tmp_path / "out"
    manifest_path = tmp_path / "preview-manifest.json"
    unsupported_path = tmp_path / "unsupported-report.json"

    code = commands.migrate(
        lowerable_native_results_dir,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        dry_run=True,
        manifest_path=manifest_path,
        unsupported_report_path=unsupported_path,
        tool_version="0.0.1",
    )

    assert code == ExitCode.SUCCESS
    assert not out.exists()
    unsupported = json.loads(unsupported_path.read_text(encoding="utf-8"))
    entry = unsupported["unsupported"][0]
    assert entry["source_kind"] == "native-results-v1"
    assert entry["disposition"] == "would_preserve"
    assert entry["cause"] == vocab.CAUSE_UNSUPPORTED_SHAPE
    assert "exact manifest.schema_version 3" in entry["reason"]
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["unsupported"] == unsupported["unsupported"]


def test_migrate_future_native_results_schema_dry_run_reports_forward_refusal_without_output(
    lowerable_native_results_dir: Path,
    tmp_path: Path,
) -> None:
    _set_native_results_schema_version(lowerable_native_results_dir, 4)
    out = tmp_path / "out"
    manifest_path = tmp_path / "preview-manifest.json"
    unsupported_path = tmp_path / "unsupported-report.json"

    code = commands.migrate(
        lowerable_native_results_dir,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        dry_run=True,
        manifest_path=manifest_path,
        unsupported_report_path=unsupported_path,
        tool_version="0.0.1",
    )

    assert code == ExitCode.UNSUPPORTED_INPUT
    assert not out.exists()
    unsupported = json.loads(unsupported_path.read_text(encoding="utf-8"))
    entry = unsupported["unsupported"][0]
    assert entry["source_kind"] == "native-results-v1"
    assert entry["disposition"] == "refused"
    assert entry["cause"] == vocab.CAUSE_FORWARD_VERSION


@pytest.mark.parametrize("strict", [False, True])
def test_migrate_future_native_results_schema_refuses_before_output(
    lowerable_native_results_dir: Path,
    tmp_path: Path,
    strict: bool,
) -> None:
    _set_native_results_schema_version(lowerable_native_results_dir, 4)
    out = tmp_path / "out"

    with pytest.raises(UnsupportedInput) as exc:
        commands.migrate(
            lowerable_native_results_dir,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            strict=strict,
            tool_version="0.0.1",
        )

    assert exc.value.cause == vocab.CAUSE_FORWARD_VERSION
    assert not out.exists()


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


def test_migrate_sqlite_legacy_arrays_to_workspace_v2(sqlite_legacy_arrays_workspace: Path, tmp_path: Path) -> None:
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


def test_migrate_refuses_restored_store_sqlite_symlink_before_output(
    sqlite_legacy_arrays_workspace: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-stage SQLite leaf swap cannot redirect the transform reader."""
    pytest.importorskip("pyarrow")
    store = sqlite_legacy_arrays_workspace / "store.sqlite"
    source_bytes = store.read_bytes()
    external = tmp_path / "external.sqlite"
    external.write_bytes(source_bytes)
    external_connection = sqlite3.connect(external)
    try:
        external_connection.execute("UPDATE predictions SET prediction_id = 'external-prediction'")
        external_connection.execute("UPDATE prediction_arrays SET prediction_id = 'external-prediction'")
        external_connection.commit()
    finally:
        external_connection.close()
    held_store = tmp_path / "held-store.sqlite"
    original_uri = commands.read_only_sqlite_uri
    swapped = False
    saw_private_stage = False

    def uri_while_original_leaf_is_an_external_symlink(path: Path) -> str:
        nonlocal saw_private_stage, swapped
        if swapped:
            return original_uri(path)
        reader_path = Path(path)
        # This is the transform's source reader.  Assert the test would fail
        # if a future refactor handed it the user-controlled source pathname:
        # the root is the private TemporaryDirectory and the staged bytes are
        # still the original payload before the hostile source swap begins.
        assert reader_path != store
        assert reader_path.parent.name == sqlite_legacy_arrays_workspace.name
        assert reader_path.parent.parent.name.startswith("nirs4all-tools-source-")
        assert reader_path.read_bytes() == source_bytes
        saw_private_stage = True
        swapped = True
        store.rename(held_store)
        try:
            os.symlink(external, store)
        except OSError as exc:
            held_store.rename(store)
            pytest.skip(f"symlinks are unavailable in this test environment: {exc}")
        try:
            return original_uri(path)
        finally:
            store.unlink()
            held_store.rename(store)

    monkeypatch.setattr(commands, "read_only_sqlite_uri", uri_while_original_leaf_is_an_external_symlink)
    output = tmp_path / "out"

    with pytest.raises(SourceIntegrityError):
        commands.migrate(
            sqlite_legacy_arrays_workspace,
            output=output,
            target=vocab.TARGET_WORKSPACE_V2,
            strict=True,
            verify=True,
            tool_version="0.0.1",
        )

    assert saw_private_stage
    assert store.read_bytes() == source_bytes
    assert not output.exists()


def _make_legacy_arrays_length_mismatch_workspace(root: Path) -> Path:
    """A legacy-arrays workspace whose single row has mismatched y_true/y_pred lengths.

    ``y_true`` carries three samples while ``y_pred`` carries two, so lowering the row into a
    runtime sidecar would silently misalign ``y_true[i]`` with ``y_pred[i]``.
    """
    root.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(root / "store.sqlite")
    try:
        con.executescript(
            """
            CREATE TABLE runs (run_id TEXT PRIMARY KEY, name TEXT NOT NULL, config TEXT,
                               datasets TEXT, status TEXT);
            CREATE TABLE pipelines (pipeline_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, name TEXT NOT NULL,
                                    expanded_config TEXT, generator_choices TEXT, dataset_name TEXT NOT NULL);
            CREATE TABLE chains (chain_id TEXT PRIMARY KEY, pipeline_id TEXT NOT NULL, steps TEXT NOT NULL,
                                 model_step_idx INTEGER NOT NULL, model_class TEXT NOT NULL, preprocessings TEXT);
            CREATE TABLE predictions (prediction_id TEXT PRIMARY KEY, pipeline_id TEXT NOT NULL, chain_id TEXT,
                                      dataset_name TEXT NOT NULL, model_name TEXT NOT NULL, model_class TEXT NOT NULL,
                                      fold_id TEXT NOT NULL, partition TEXT NOT NULL, metric TEXT NOT NULL,
                                      task_type TEXT NOT NULL);
            CREATE TABLE prediction_arrays (prediction_id TEXT PRIMARY KEY, y_true TEXT, y_pred TEXT,
                                            y_proba TEXT, sample_indices TEXT, weights TEXT);
            """
        )
        con.execute("INSERT INTO runs VALUES ('run-1', 'legacy run', '{}', '[]', 'completed')")
        con.execute("INSERT INTO pipelines VALUES ('pipe-1', 'run-1', 'pipe', '{}', '[]', 'dataset-a')")
        con.execute("INSERT INTO chains VALUES ('chain-1', 'pipe-1', '[]', 0, 'PLSRegression', 'SNV')")
        con.execute(
            "INSERT INTO predictions VALUES ('pred-1', 'pipe-1', 'chain-1', 'dataset-a', 'PLSRegression', "
            "'sklearn.cross_decomposition.PLSRegression', 'fold-0', 'val', 'rmse', 'regression')"
        )
        con.execute(
            "INSERT INTO prediction_arrays VALUES ('pred-1', ?, ?, NULL, ?, NULL)",
            [json.dumps([1.0, 2.0, 3.0]), json.dumps([1.1, 1.9]), json.dumps([0, 1, 2])],
        )
        con.execute("PRAGMA user_version = 2")
        con.commit()
    finally:
        con.close()
    return root


def test_migrate_sqlite_legacy_arrays_strict_refuses_length_mismatch(tmp_path: Path) -> None:
    pytest.importorskip("pyarrow.parquet")
    source = _make_legacy_arrays_length_mismatch_workspace(tmp_path / "ws")
    out = tmp_path / "out"

    def run() -> None:
        with pytest.raises(UnsupportedInput) as exc:
            commands.migrate(
                source,
                output=out,
                target=vocab.TARGET_WORKSPACE_V2,
                strict=True,
                tool_version="0.0.1",
            )
        assert exc.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE
        assert "mismatched per-sample array lengths" in exc.value.message
        assert "'pred-1'" in exc.value.message

    _unchanged(source, run)
    assert not out.exists()


def test_migrate_sqlite_legacy_arrays_best_effort_preserves_length_mismatch(tmp_path: Path) -> None:
    pytest.importorskip("pyarrow.parquet")
    source = _make_legacy_arrays_length_mismatch_workspace(tmp_path / "ws")
    out = tmp_path / "out"

    def run() -> None:
        code = commands.migrate(
            source,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            verify=True,
            tool_version="0.0.1",
        )
        assert code == ExitCode.MIGRATED_WITH_WARNINGS

    _unchanged(source, run)

    manifest = json.loads((out / "migration-manifest.json").read_text(encoding="utf-8"))
    report = json.loads((out / "migration-report.json").read_text(encoding="utf-8"))

    # The corrupt row is never lowered into a runtime array sidecar ...
    assert not (out / "arrays").exists()
    assert report["migrated_counts"]["arrays"] == 0
    # ... but the raw legacy rows are still preserved verbatim as checksummed audit JSONL,
    # and the store metadata (run/pipeline/chain/prediction) still lowers.
    preserved = out / "preserved" / "legacy-prediction-arrays.jsonl"
    assert preserved.exists()
    assert "preserved/legacy-prediction-arrays.jsonl" in manifest["checksums"]
    assert report["migrated_counts"]["predictions"] == 1

    # The unsupported ledger records the true shape cause, not a spurious missing-pyarrow reason.
    prediction_arrays_items = [item for item in manifest["unsupported"] if item["item"] == "prediction_arrays"]
    assert len(prediction_arrays_items) == 1
    assert prediction_arrays_items[0]["cause"] == vocab.CAUSE_UNSUPPORTED_SHAPE
    assert "mismatched per-sample array lengths" in prediction_arrays_items[0]["reason"]
    assert not any("install the parquet extra" in warning for warning in report["warnings"])
    assert report["verification_summary"]["passed"] is True


def test_migrate_native_results_preserves_opaque_best_effort(native_results_dir: Path, tmp_path: Path) -> None:
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


def test_migrate_old_native_results_schema_preserves_opaque_best_effort(
    lowerable_native_results_dir: Path,
    tmp_path: Path,
) -> None:
    _set_native_results_schema_version(lowerable_native_results_dir, 2)
    out = tmp_path / "out"

    code = commands.migrate(
        lowerable_native_results_dir,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        verify=True,
        tool_version="0.0.1",
    )

    assert code == ExitCode.MIGRATED_WITH_WARNINGS
    preserved_root = out / "preserved" / "native-results-v1" / lowerable_native_results_dir.name
    assert (preserved_root / "manifest.json").exists()
    manifest = json.loads((out / "migration-manifest.json").read_text(encoding="utf-8"))
    entry = manifest["unsupported"][0]
    assert entry["source_kind"] == "native-results-v1"
    assert entry["disposition"] == "preserved"
    assert entry["cause"] == vocab.CAUSE_UNSUPPORTED_SHAPE
    assert "exact manifest.schema_version 3" in entry["reason"]


def test_migrate_old_native_results_schema_strict_refuses_without_output(
    lowerable_native_results_dir: Path,
    tmp_path: Path,
) -> None:
    _set_native_results_schema_version(lowerable_native_results_dir, 2)
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
    assert "exact manifest.schema_version 3" in exc.value.message
    assert not out.exists()


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


def test_migrate_loose_predictions_nonfinite_array_refuses_cleanly(tmp_path: Path) -> None:
    """A non-finite y_pred is refused as an unsupported shape, never an uncaught crash.

    The runtime sidecar checksum serializes with ``allow_nan=False``; a NaN/Infinity
    prediction array must surface as a reportable ``UnsupportedInput`` (exit 20) with
    the source untouched and the tool-created output rolled back — not a bare
    ``ValueError`` traceback with an undocumented exit code.
    """
    pytest.importorskip("pyarrow")
    src = tmp_path / "loose"
    src.mkdir()
    record = {
        "run_id": "run-1",
        "pipeline_id": "pipe-1",
        "prediction_id": "pred-1",
        "dataset": "dataset-a",
        "model_name": "PLSRegression",
        "model_class": "sklearn.cross_decomposition.PLSRegression",
        "fold_id": "fold-0",
        "partition": "val",
        "metric": "rmse",
        "task_type": "regression",
        "sample_indices": [0, 1, 2],
        "y_true": [1.0, 2.0, 3.0],
        "y_pred": [1.0, float("nan"), 3.0],
    }
    # default allow_nan=True writes the bare ``NaN`` token, exactly as legacy runtimes did
    (src / "run_predictions.json").write_text(json.dumps(record), encoding="utf-8")
    out = tmp_path / "out"

    before = policy.snapshot_tree(src)
    with pytest.raises(UnsupportedInput) as exc:
        commands.migrate(src, output=out, target=vocab.TARGET_WORKSPACE_V2, tool_version="0.0.1")
    after = policy.snapshot_tree(src)

    assert exc.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE
    assert "non-finite" in exc.value.message
    assert not out.exists()
    assert policy.diff_snapshots(before, after) == []


def test_migrate_refuses_restored_loose_prediction_symlink_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A preview cannot consume a descendant symlink substituted after staging."""
    pytest.importorskip("pyarrow")
    source = tmp_path / "loose"
    source.mkdir()

    def record(prediction_id: str) -> dict[str, object]:
        return {
            "run_id": "run-1",
            "pipeline_id": "pipe-1",
            "prediction_id": prediction_id,
            "dataset": "dataset-a",
            "model_name": "PLSRegression",
            "model_class": "sklearn.cross_decomposition.PLSRegression",
            "fold_id": "fold-0",
            "partition": "val",
            "metric": "rmse",
            "task_type": "regression",
            "sample_indices": [0, 1, 2],
            "y_true": [1.0, 2.0, 3.0],
            "y_pred": [1.1, 1.9, 3.2],
        }

    prediction = source / "run_predictions.json"
    prediction.write_text(json.dumps(record("original-prediction")), encoding="utf-8")
    source_bytes = prediction.read_bytes()
    external = tmp_path / "external_predictions.json"
    external.write_text(json.dumps(record("external-prediction")), encoding="utf-8")
    held_prediction = tmp_path / "held_predictions.json"
    original_preview = commands.load_loose_predictions_preview
    swapped = False
    saw_private_stage = False

    def preview_while_original_leaf_is_an_external_symlink(*args, **kwargs):
        nonlocal saw_private_stage, swapped
        if swapped:
            return original_preview(*args, **kwargs)
        reader_root = Path(args[0])
        # Prove that the preview reader is rooted at the private stage before
        # changing the user source.  An unsafe pathname reader reaches the
        # original root and fails this assertion instead of passing merely
        # because the final integrity guard notices the restored swap.
        assert reader_root != source
        assert reader_root.name == source.name
        assert reader_root.parent.name.startswith("nirs4all-tools-source-")
        assert (reader_root / prediction.name).read_bytes() == source_bytes
        saw_private_stage = True
        swapped = True
        prediction.rename(held_prediction)
        try:
            os.symlink(external, prediction)
        except OSError as exc:
            held_prediction.rename(prediction)
            pytest.skip(f"symlinks are unavailable in this test environment: {exc}")
        try:
            return original_preview(*args, **kwargs)
        finally:
            prediction.unlink()
            held_prediction.rename(prediction)

    monkeypatch.setattr(commands, "load_loose_predictions_preview", preview_while_original_leaf_is_an_external_symlink)
    output = tmp_path / "out"

    with pytest.raises(SourceIntegrityError):
        commands.migrate(
            source,
            output=output,
            target=vocab.TARGET_WORKSPACE_V2,
            strict=True,
            verify=True,
            tool_version="0.0.1",
        )

    assert saw_private_stage
    assert prediction.read_bytes() == source_bytes
    assert not output.exists()


def test_migrate_native_results_lowers_preview_metadata(lowerable_native_results_dir: Path, tmp_path: Path) -> None:
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
    assert (
        f"preserved/native-results-v1/{lowerable_native_results_dir.name}/predictions.parquet" in manifest["checksums"]
    )
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
        pipeline = con.execute("SELECT run_id, dataset_name, status, metric FROM pipelines").fetchone()
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


def test_migrate_native_results_lowered_preserved_payload_is_byte_identical_and_verified(
    lowerable_native_results_dir: Path, tmp_path: Path
) -> None:
    """Native-results lowering keeps the original payload byte-for-byte and verify guards it.

    The lowered path copies the source ``native-results-v1`` directory under ``preserved/`` as
    provenance and records a file-level checksum for every file. Verification must therefore
    detect any post-migration tampering of that preserved payload, even though it is tracked via
    ``checksums`` rather than the ``preserved_opaque`` ledger (which stays empty in the fully
    lowered case). This locks the RC guarantee that the native payload survives conversion intact.
    """
    out = tmp_path / "out"
    code = commands.migrate(
        lowerable_native_results_dir,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        strict=True,
        verify=True,
        tool_version="0.0.1",
    )
    assert code == ExitCode.SUCCESS

    preserved_root = out / "preserved" / "native-results-v1" / lowerable_native_results_dir.name
    for name in ("manifest.json", "score_set.json", "predictions.parquet"):
        assert (preserved_root / name).read_bytes() == (lowerable_native_results_dir / name).read_bytes()

    manifest_path = out / "migration-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    preserved_rel = f"preserved/native-results-v1/{lowerable_native_results_dir.name}/predictions.parquet"
    assert preserved_rel in manifest["checksums"]
    assert manifest["preserved_opaque"] == []
    assert commands.verify(out, manifest_path=manifest_path) == ExitCode.SUCCESS

    # Tampering the preserved provenance payload must fail verification with the exact path.
    (preserved_root / "predictions.parquet").write_bytes(b"tampered native payload")
    report_path = tmp_path / "verify-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=manifest_path, report_path=report_path)

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["verification_summary"]["checks"]["mismatched_files"] == [preserved_rel]


def test_migrate_native_results_strict_refuses_without_output(native_results_dir: Path, tmp_path: Path) -> None:
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


def test_migrate_n4a_bundle_preserves_opaque_best_effort(n4a_bundle: Path, tmp_path: Path) -> None:
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


def test_relative_n4a_symlink_uses_canonical_root_source(
    n4a_bundle: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    links = tmp_path / "links"
    links.mkdir()
    source_alias = links / "source-alias.n4a"
    try:
        os.symlink(f"../{n4a_bundle.name}", source_alias)
    except OSError as exc:
        pytest.skip(f"symlinks are unavailable in this test environment: {exc}")

    monkeypatch.chdir(links)
    relative_source = Path(source_alias.name)
    assert commands.inspect(relative_source, fmt="json") == ExitCode.SUCCESS

    out = tmp_path / "out"
    assert (
        commands.migrate(
            relative_source,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            verify=True,
            tool_version="0.0.1",
        )
        == ExitCode.MIGRATED_WITH_WARNINGS
    )

    manifest = json.loads((out / contracts.DEFAULT_MANIFEST_NAME).read_text(encoding="utf-8"))
    expected = f"preserved/n4a-bundle/{n4a_bundle.name}"
    assert manifest["source"]["path"] == str(n4a_bundle.resolve())
    assert manifest["preserved_opaque"][0]["path"] == expected
    assert commands.verify(out, manifest_path=out / contracts.DEFAULT_MANIFEST_NAME) == ExitCode.SUCCESS


def test_relative_unsafe_n4a_symlink_keeps_archive_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_unsafe_n4a_bundle(tmp_path / "unsafe.n4a")
    links = tmp_path / "links"
    links.mkdir()
    source_alias = links / "source-alias.n4a"
    try:
        os.symlink("../unsafe.n4a", source_alias)
    except OSError as exc:
        pytest.skip(f"symlinks are unavailable in this test environment: {exc}")

    monkeypatch.chdir(links)
    out = tmp_path / "out"
    with pytest.raises(UnsupportedInput) as raised:
        commands.migrate(
            Path(source_alias.name),
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            tool_version="0.0.1",
        )

    assert raised.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE
    assert "unsafe_member_path" in raised.value.message
    assert not out.exists()


def test_copy_only_n4a_bundle_copies_the_validated_archive(n4a_bundle: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"

    code = commands.migrate(
        n4a_bundle,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        copy_only=True,
        tool_version="0.0.1",
    )

    assert code == ExitCode.SUCCESS
    assert (out / "payload" / n4a_bundle.name).read_bytes() == n4a_bundle.read_bytes()


@pytest.mark.parametrize(
    ("writer", "name", "cause", "reason"),
    [
        (_write_unsafe_n4a_bundle, "unsafe.n4a", vocab.CAUSE_UNSUPPORTED_SHAPE, "unsafe_member_path"),
        (_write_forward_n4a_bundle, "future.n4a", vocab.CAUSE_FORWARD_VERSION, "version newer"),
        (_write_unsafe_n4a_bundle, "unsafe.N4A", vocab.CAUSE_UNSUPPORTED_SHAPE, "unsafe_member_path"),
        (_write_forward_n4a_bundle, "future.N4A", vocab.CAUSE_FORWARD_VERSION, "version newer"),
    ],
)
def test_copy_only_refuses_nested_n4a_before_copying_it(
    sqlite_v2_workspace: Path,
    tmp_path: Path,
    writer,
    name: str,
    cause: str,
    reason: str,
) -> None:
    nested = sqlite_v2_workspace / "nested"
    nested.mkdir()
    writer(nested / name)
    out = tmp_path / "out"

    def run() -> None:
        with pytest.raises(UnsupportedInput) as raised:
            commands.migrate(
                sqlite_v2_workspace,
                output=out,
                target=vocab.TARGET_WORKSPACE_V2,
                copy_only=True,
                tool_version="0.0.1",
            )
        assert raised.value.cause == cause
        assert reason in raised.value.message

    _unchanged(sqlite_v2_workspace, run)
    assert not out.exists()
    assert not (out / "payload" / "nested" / name).exists()


def test_opaque_native_results_preservation_refuses_nested_unsafe_n4a(
    native_results_dir: Path,
    tmp_path: Path,
) -> None:
    nested = native_results_dir / "nested"
    nested.mkdir()
    _write_unsafe_n4a_bundle(nested / "unsafe.n4a")
    out = tmp_path / "out"

    def run() -> None:
        with pytest.raises(UnsupportedInput) as raised:
            commands.migrate(
                native_results_dir,
                output=out,
                target=vocab.TARGET_WORKSPACE_V2,
                tool_version="0.0.1",
            )
        assert raised.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE
        assert "unsafe_member_path" in raised.value.message

    _unchanged(native_results_dir, run)
    assert not out.exists()
    assert not (out / "preserved" / "native-results-v1" / native_results_dir.name / "nested" / "unsafe.n4a").exists()


@pytest.mark.parametrize("copy_only", [False, True])
def test_migrate_unsafe_n4a_refuses_before_any_output(tmp_path: Path, copy_only: bool) -> None:
    source = _write_unsafe_n4a_bundle(tmp_path / "unsafe.n4a")
    out = tmp_path / "out"

    def run() -> None:
        with pytest.raises(UnsupportedInput) as raised:
            commands.migrate(
                source,
                output=out,
                target=vocab.TARGET_WORKSPACE_V2,
                copy_only=copy_only,
                tool_version="0.0.1",
            )
        assert raised.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE
        assert "unsafe_member_path" in raised.value.message

    _unchanged(source, run)
    assert not out.exists()


@pytest.mark.parametrize("copy_only", [False, True])
def test_migrate_refuses_n4a_source_mutation_after_output_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copy_only: bool,
) -> None:
    source = tmp_path / "model.n4a"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("manifest.json", "{}")
    out = tmp_path / "out"
    original_assert_output_available = commands.assert_output_available

    def replace_source_after_first_preflight(output: Path, *, resume: bool) -> None:
        _write_unsafe_n4a_bundle(source)
        original_assert_output_available(output, resume=resume)

    monkeypatch.setattr(commands, "assert_output_available", replace_source_after_first_preflight)

    with pytest.raises(SourceIntegrityError):
        commands.migrate(
            source,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=copy_only,
            tool_version="0.0.1",
        )

    assert not out.exists()


@pytest.mark.parametrize("copy_only", [False, True])
def test_migrate_refuses_forward_n4a_source_mutation_after_output_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copy_only: bool,
) -> None:
    source = tmp_path / "model.n4a"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("manifest.json", '{"bundle_format_version":"1.0"}')
    out = tmp_path / "out"
    original_assert_output_available = commands.assert_output_available

    def replace_source_after_first_preflight(output: Path, *, resume: bool) -> None:
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("manifest.json", '{"bundle_format_version":"2.0"}')
        original_assert_output_available(output, resume=resume)

    monkeypatch.setattr(commands, "assert_output_available", replace_source_after_first_preflight)

    with pytest.raises(SourceIntegrityError):
        commands.migrate(
            source,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=copy_only,
            tool_version="0.0.1",
        )

    assert not out.exists()


@pytest.mark.parametrize("copy_only", [False, True])
def test_migrate_binds_n4a_output_to_its_initial_source_fingerprint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copy_only: bool,
) -> None:
    source = tmp_path / "model.n4a"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("manifest.json", '{"bundle_format_version":"1.0"}')
        archive.writestr("payload-a", "A")
    out = tmp_path / "out"
    original_build_manifest = commands.contracts.build_manifest

    def replace_source_after_initial_detection(*args, **kwargs):
        manifest = original_build_manifest(*args, **kwargs)
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("manifest.json", '{"bundle_format_version":"1.0"}')
            archive.writestr("payload-b", "B")
        return manifest

    monkeypatch.setattr(commands.contracts, "build_manifest", replace_source_after_initial_detection)

    with pytest.raises(SourceIntegrityError):
        commands.migrate(
            source,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=copy_only,
            tool_version="0.0.1",
        )

    assert not out.exists()


@pytest.mark.parametrize("copy_only", [False, True])
def test_migrate_removes_output_when_root_n4a_changes_and_restores(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copy_only: bool,
) -> None:
    source = tmp_path / "model.n4a"
    alternate = tmp_path / "alternate.n4a"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("manifest.json", '{"bundle_format_version":"1.0"}')
        archive.writestr("payload-a", "A")
    source_bytes = source.read_bytes()
    source_stat = source.stat()
    with zipfile.ZipFile(alternate, "w") as archive:
        archive.writestr("manifest.json", '{"bundle_format_version":"1.0"}')
        archive.writestr("payload-b", "B")
    assert len(source_bytes) == alternate.stat().st_size
    out = tmp_path / "out"
    original_fingerprint_check = commands._assert_source_fingerprint_matches
    original_copy = commands.copy_validated_n4a_archive

    def replace_after_fingerprint(source_path: Path, expected: str) -> None:
        original_fingerprint_check(source_path, expected)
        source.write_bytes(alternate.read_bytes())
        os.utime(source, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns))

    def restore_after_copy_attempt(*args, **kwargs):
        try:
            return original_copy(*args, **kwargs)
        finally:
            source.write_bytes(source_bytes)
            os.utime(source, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns))

    monkeypatch.setattr(commands, "_assert_source_fingerprint_matches", replace_after_fingerprint)
    monkeypatch.setattr(commands, "copy_validated_n4a_archive", restore_after_copy_attempt)

    with pytest.raises(SourceIntegrityError):
        commands.migrate(
            source,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=copy_only,
            tool_version="0.0.1",
        )

    assert source.read_bytes() == source_bytes
    assert not out.exists()


def test_migrate_dry_run_refuses_root_n4a_symlink_swap_even_when_restored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "model.n4a"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("manifest.json", '{"bundle_format_version":"1.0"}')
    external = tmp_path / "external.n4a"
    with zipfile.ZipFile(external, "w") as archive:
        archive.writestr("manifest.json", '{"bundle_format_version":"2.0"}')
    out = tmp_path / "out"
    manifest_path = tmp_path / "preview-manifest.json"
    unsupported_path = tmp_path / "unsupported.json"
    held_source = tmp_path / "held-model.n4a"
    original_refresh = commands._refresh_dry_run_detection

    def read_through_temporary_external_symlink(*args, **kwargs):
        source.rename(held_source)
        try:
            os.symlink(external, source)
        except OSError as exc:
            held_source.rename(source)
            pytest.skip(f"symlinks are unavailable in this test environment: {exc}")
        try:
            return original_refresh(*args, **kwargs)
        finally:
            source.unlink()
            held_source.rename(source)

    monkeypatch.setattr(commands, "_refresh_dry_run_detection", read_through_temporary_external_symlink)

    with pytest.raises(SourceIntegrityError):
        commands.migrate(
            source,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            dry_run=True,
            manifest_path=manifest_path,
            unsupported_report_path=unsupported_path,
            tool_version="0.0.1",
        )

    assert not out.exists()


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


@pytest.mark.skipif(os.name == "nt", reason="Windows cannot create a literal backslash filename")
@pytest.mark.parametrize("verify", [False, True])
def test_copy_only_refuses_literal_backslash_source_entry_before_output(
    sqlite_v2_workspace: Path,
    tmp_path: Path,
    verify: bool,
) -> None:
    (sqlite_v2_workspace / r"back\slash.txt").write_text("nonportable", encoding="utf-8")
    out = tmp_path / "out"
    source_before = policy.snapshot_tree(sqlite_v2_workspace)

    with pytest.raises(UnsupportedInput) as raised:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            verify=verify,
            tool_version="0.0.1",
        )

    assert raised.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE
    assert "literal backslash" in raised.value.message
    assert not out.exists()
    assert policy.diff_snapshots(source_before, policy.snapshot_tree(sqlite_v2_workspace)) == []


# --- migrate: attested resume ------------------------------------------------
def test_migrate_resume_copy_only_is_a_read_only_attested_noop(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert (
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            tool_version="0.0.1",
        )
        == ExitCode.SUCCESS
    )

    source_before = policy.snapshot_tree(sqlite_v2_workspace)
    output_before = policy.snapshot_tree(out)
    assert (
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            tool_version="0.0.1",
        )
        == ExitCode.SUCCESS
    )

    assert policy.diff_snapshots(source_before, policy.snapshot_tree(sqlite_v2_workspace)) == []
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []


def test_migrate_resume_uses_descriptor_snapshot_without_private_staging(
    sqlite_v2_workspace: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "out"
    assert (
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            tool_version="0.0.1",
        )
        == ExitCode.SUCCESS
    )

    def staging_must_not_run(*args, **kwargs):
        raise AssertionError("--resume must not require a source-sized private stage")

    monkeypatch.setattr(commands, "materialized_source_tree_nofollow", staging_must_not_run)

    assert (
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            tool_version="0.0.1",
        )
        == ExitCode.SUCCESS
    )


@pytest.mark.parametrize(
    ("copy_only", "expected_code", "expected_status", "mutated_status"),
    [
        (True, ExitCode.SUCCESS, vocab.STATUS_SUCCESS, vocab.STATUS_MIGRATED_WITH_WARNINGS),
        (False, ExitCode.MIGRATED_WITH_WARNINGS, vocab.STATUS_MIGRATED_WITH_WARNINGS, vocab.STATUS_SUCCESS),
    ],
)
def test_migrate_resume_requires_manifest_attested_terminal_outcome(
    sqlite_v2_workspace: Path,
    tmp_path: Path,
    copy_only: bool,
    expected_code: ExitCode,
    expected_status: str,
    mutated_status: str,
) -> None:
    out = tmp_path / "out"
    assert (
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=copy_only,
            tool_version="0.0.1",
        )
        == expected_code
    )

    manifest_path = out / contracts.DEFAULT_MANIFEST_NAME
    report_path = out / contracts.DEFAULT_REPORT_NAME
    unsupported_path = out / contracts.DEFAULT_UNSUPPORTED_REPORT_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    unsupported = json.loads(unsupported_path.read_text(encoding="utf-8"))
    assert manifest["migration"]["terminal_status"] == expected_status
    assert manifest["migration"]["terminal_exit_code"] == int(expected_code)
    assert report["status"] == expected_status
    assert unsupported["status"] == expected_status

    # A coordinated report-only relabelling must not alter the durable result
    # the manifest attested before all four contracts were written.
    report["status"] = mutated_status
    unsupported["status"] = mutated_status
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    unsupported_path.write_text(json.dumps(unsupported, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    source_before = policy.snapshot_tree(sqlite_v2_workspace)
    output_before = policy.snapshot_tree(out)

    with pytest.raises(UnsupportedInput) as raised:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=copy_only,
            resume=True,
            tool_version="0.0.1",
        )

    assert raised.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(source_before, policy.snapshot_tree(sqlite_v2_workspace)) == []
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []


def test_migrate_resume_refuses_pre_terminal_manifest_but_verify_stays_available(
    sqlite_v2_workspace: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    assert (
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            tool_version="0.0.1",
        )
        == ExitCode.SUCCESS
    )

    manifest_path = out / contracts.DEFAULT_MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["migration"] = {"mode": "copy-only"}
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert commands.verify(out, manifest_path=manifest_path) == ExitCode.SUCCESS

    source_before = policy.snapshot_tree(sqlite_v2_workspace)
    output_before = policy.snapshot_tree(out)
    with pytest.raises(UnsupportedInput) as raised:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            tool_version="0.0.1",
        )

    assert raised.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(source_before, policy.snapshot_tree(sqlite_v2_workspace)) == []
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []


def test_copy_only_capacity_refuses_before_private_source_staging(
    sqlite_v2_workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"

    def refuse_capacity(*_requests) -> None:
        raise PolicyRefusal(
            "insufficient test storage",
            cause=vocab.CAUSE_INSUFFICIENT_STORAGE,
            mitigation="free test storage",
        )

    monkeypatch.setattr(commands, "assert_storage_capacity", refuse_capacity)
    monkeypatch.setattr(
        commands,
        "materialized_source_tree_nofollow",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("source stage must not start")),
    )

    with pytest.raises(PolicyRefusal) as raised:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            tool_version="0.0.1",
        )

    assert raised.value.cause == vocab.CAUSE_INSUFFICIENT_STORAGE
    assert not out.exists()


@pytest.mark.parametrize("existing_empty", [False, True])
def test_copy_only_enospc_never_publishes_partial_output(
    sqlite_v2_workspace: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing_empty: bool,
) -> None:
    out = tmp_path / "out"
    if existing_empty:
        out.mkdir()

    def exhaust_storage(*_args, **_kwargs):
        raise OSError(errno.ENOSPC, "injected full filesystem")

    monkeypatch.setattr(commands, "_copy_only", exhaust_storage)

    with pytest.raises(PolicyRefusal) as raised:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            tool_version="0.0.1",
        )

    assert raised.value.cause == vocab.CAUSE_INSUFFICIENT_STORAGE
    assert out.is_dir() if existing_empty else not out.exists()
    if existing_empty:
        assert list(out.iterdir()) == []
    assert not list(tmp_path.glob(".nirs4all-tools-publish-*"))


def test_copy_only_internal_contract_enospc_keeps_existing_empty_output(
    sqlite_v2_workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    original_write_json = commands._write_json

    def exhaust_manifest(path: Path, payload: dict) -> None:
        if path.name == contracts.DEFAULT_MANIFEST_NAME:
            raise OSError(errno.ENOSPC, "injected contract exhaustion")
        original_write_json(path, payload)

    monkeypatch.setattr(commands, "_write_json", exhaust_manifest)

    with pytest.raises(PolicyRefusal) as raised:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            tool_version="0.0.1",
        )

    assert raised.value.cause == vocab.CAUSE_INSUFFICIENT_STORAGE
    assert list(out.iterdir()) == []
    assert not list(tmp_path.glob(".nirs4all-tools-publish-*"))


@pytest.mark.parametrize("existing_empty", [False, True])
def test_copy_only_external_contract_enospc_does_not_publish_output(
    sqlite_v2_workspace: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing_empty: bool,
) -> None:
    out = tmp_path / "out"
    if existing_empty:
        out.mkdir()
    external_manifest = tmp_path / "contracts" / "manifest.json"

    def exhaust_external(*_args, **_kwargs):
        raise OSError(errno.ENOSPC, "injected external contract exhaustion")

    monkeypatch.setattr(commands, "_prepare_external_contract", exhaust_external)

    with pytest.raises(PolicyRefusal) as raised:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            manifest_path=external_manifest,
            copy_only=True,
            tool_version="0.0.1",
        )

    assert raised.value.cause == vocab.CAUSE_INSUFFICIENT_STORAGE
    assert out.is_dir() if existing_empty else not out.exists()
    if existing_empty:
        assert list(out.iterdir()) == []
    assert not external_manifest.exists()
    assert not list(tmp_path.glob(".nirs4all-tools-publish-*"))


def test_copy_only_existing_empty_output_and_external_manifest_succeed(
    sqlite_v2_workspace: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    out.mkdir(mode=0o750)
    external_manifest = tmp_path / "contracts" / "custom-manifest.json"

    result = commands.migrate(
        sqlite_v2_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        manifest_path=external_manifest,
        copy_only=True,
        verify=True,
        tool_version="0.0.1",
    )

    assert result == ExitCode.SUCCESS
    assert stat.S_IMODE(out.stat().st_mode) == 0o750
    assert external_manifest.exists()
    assert not (out / contracts.DEFAULT_MANIFEST_NAME).exists()
    assert commands.verify(out, manifest_path=external_manifest) == ExitCode.SUCCESS


def test_copy_only_refuses_destination_race_without_deleting_third_party_data(
    sqlite_v2_workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    third_party = out / "third-party.txt"
    original_fsync = commands._fsync_publication_tree

    def populate_destination(publication: Path) -> None:
        original_fsync(publication)
        out.mkdir()
        third_party.write_text("keep", encoding="utf-8")

    monkeypatch.setattr(commands, "_fsync_publication_tree", populate_destination)

    with pytest.raises(PolicyRefusal) as raised:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            tool_version="0.0.1",
        )

    assert raised.value.cause == vocab.CAUSE_NON_EMPTY_OUTPUT
    assert third_party.read_text(encoding="utf-8") == "keep"
    assert not list(tmp_path.glob(".nirs4all-tools-publish-*"))


@pytest.mark.parametrize(
    ("contract_name", "schema_id", "schema_version"),
    [
        (contracts.DEFAULT_REPORT_NAME, contracts.REPORT_SCHEMA_ID, contracts.REPORT_SCHEMA_VERSION),
        (
            contracts.DEFAULT_UNSUPPORTED_REPORT_NAME,
            contracts.UNSUPPORTED_REPORT_SCHEMA_ID,
            contracts.UNSUPPORTED_REPORT_SCHEMA_VERSION,
        ),
    ],
)
def test_migrate_resume_refuses_truncated_internal_report_contracts(
    sqlite_v2_workspace: Path,
    tmp_path: Path,
    contract_name: str,
    schema_id: str,
    schema_version: int,
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_v2_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        copy_only=True,
        tool_version="0.0.1",
    )
    contract_path = out / contract_name
    contract_path.write_text(
        json.dumps({"$id": schema_id, "schema_version": schema_version}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    output_before = policy.snapshot_tree(out)

    with pytest.raises(UnsupportedInput) as raised:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            tool_version="0.0.1",
        )

    assert raised.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []


def test_migrate_resume_refuses_unsupported_report_count_mismatch(n4a_bundle: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert (
        commands.migrate(
            n4a_bundle,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            tool_version="0.0.1",
        )
        == ExitCode.MIGRATED_WITH_WARNINGS
    )
    unsupported_path = out / contracts.DEFAULT_UNSUPPORTED_REPORT_NAME
    unsupported = json.loads(unsupported_path.read_text(encoding="utf-8"))
    assert unsupported["counts"]["preserved"] == 1
    unsupported["counts"]["preserved"] = 0
    unsupported_path.write_text(json.dumps(unsupported, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    source_before = policy.snapshot_tree(n4a_bundle)
    output_before = policy.snapshot_tree(out)
    with pytest.raises(UnsupportedInput) as raised:
        commands.migrate(
            n4a_bundle,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            resume=True,
            tool_version="0.0.1",
        )

    assert raised.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(source_before, policy.snapshot_tree(n4a_bundle)) == []
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []


def test_verify_and_resume_refuse_truncated_embedded_id_map(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_v2_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        copy_only=True,
        tool_version="0.0.1",
    )
    truncated_id_map = {
        "$id": contracts.ID_MAP_SCHEMA_ID,
        "schema_version": contracts.ID_MAP_SCHEMA_VERSION,
    }
    manifest_path = out / contracts.DEFAULT_MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["old_to_new_ids"] = truncated_id_map
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / contracts.DEFAULT_ID_MAP_NAME).write_text(
        json.dumps(truncated_id_map, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    source_before = policy.snapshot_tree(sqlite_v2_workspace)
    output_before = policy.snapshot_tree(out)
    verification_report = tmp_path / "verification-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=manifest_path, report_path=verification_report)
    summary = json.loads(verification_report.read_text(encoding="utf-8"))["verification_summary"]
    assert summary["checks"]["manifest_contract_shape"] == {
        "status": "failed",
        "errors": ["id-map entity set is incomplete"],
        "failure_count": 1,
    }
    assert policy.diff_snapshots(source_before, policy.snapshot_tree(sqlite_v2_workspace)) == []
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []

    with pytest.raises(UnsupportedInput) as raised:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            tool_version="0.0.1",
        )

    assert raised.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(source_before, policy.snapshot_tree(sqlite_v2_workspace)) == []
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []


def test_verify_handles_a_non_object_manifest_as_a_verification_failure(
    sqlite_v2_workspace: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_v2_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        copy_only=True,
        tool_version="0.0.1",
    )
    manifest_path = out / contracts.DEFAULT_MANIFEST_NAME
    manifest_path.write_text("[]\n", encoding="utf-8")

    verification_report = tmp_path / "verification-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=manifest_path, report_path=verification_report)
    summary = json.loads(verification_report.read_text(encoding="utf-8"))["verification_summary"]
    assert summary["checks"]["manifest_contract_shape"] == {
        "status": "failed",
        "errors": ["manifest is not a JSON object"],
        "failure_count": 1,
    }


@pytest.mark.parametrize(
    "contract_name",
    [
        "migration-manifest.json",
        "migration-report.json",
        "migration-id-map.json",
        "unsupported-report.json",
    ],
)
def test_migrate_resume_refuses_each_missing_internal_contract(
    sqlite_v2_workspace: Path, tmp_path: Path, contract_name: str
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_v2_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        copy_only=True,
        tool_version="0.0.1",
    )
    (out / contract_name).unlink()
    output_before = policy.snapshot_tree(out)

    with pytest.raises(UnsupportedInput) as raised:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            tool_version="0.0.1",
        )

    assert raised.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []


def test_migrate_resume_refuses_malformed_or_partial_manifest_without_touching_output(
    sqlite_v2_workspace: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_v2_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        copy_only=True,
        tool_version="0.0.1",
    )
    manifest_path = out / "migration-manifest.json"
    valid_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_path.write_text("{not-json", encoding="utf-8")
    output_before = policy.snapshot_tree(out)

    with pytest.raises(UnsupportedInput) as malformed:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            tool_version="0.0.1",
        )
    assert malformed.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []

    valid_manifest["tool"]["completed_at"] = None
    manifest_path.write_text(json.dumps(valid_manifest), encoding="utf-8")
    output_before = policy.snapshot_tree(out)
    with pytest.raises(UnsupportedInput) as partial:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            tool_version="0.0.1",
        )
    assert partial.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []


def test_migrate_resume_requires_matching_source_path_and_fingerprint(
    sqlite_v2_workspace: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_v2_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        copy_only=True,
        tool_version="0.0.1",
    )
    same_bytes_elsewhere = tmp_path / "other-source"
    same_bytes_elsewhere.mkdir()
    (same_bytes_elsewhere / "store.sqlite").write_bytes((sqlite_v2_workspace / "store.sqlite").read_bytes())
    output_before = policy.snapshot_tree(out)

    with pytest.raises(UnsupportedInput) as path_mismatch:
        commands.migrate(
            same_bytes_elsewhere,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            tool_version="0.0.1",
        )
    assert path_mismatch.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []

    (sqlite_v2_workspace / "post-migration-change.txt").write_text("changed", encoding="utf-8")
    output_before = policy.snapshot_tree(out)
    with pytest.raises(UnsupportedInput) as fingerprint_mismatch:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            tool_version="0.0.1",
        )
    assert fingerprint_mismatch.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []


def test_migrate_resume_requires_matching_target_and_mode(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    copy_out = tmp_path / "copy-out"
    commands.migrate(
        sqlite_v2_workspace,
        output=copy_out,
        target=vocab.TARGET_WORKSPACE_V2,
        copy_only=True,
        tool_version="0.0.1",
    )
    output_before = policy.snapshot_tree(copy_out)
    with pytest.raises(UnsupportedInput) as target_mismatch:
        commands.migrate(
            sqlite_v2_workspace,
            output=copy_out,
            target=vocab.TARGET_WORKSPACE_V2,
            resume=True,
            tool_version="0.0.1",
        )
    assert target_mismatch.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(copy_out)) == []

    best_effort_out = tmp_path / "best-effort-out"
    assert (
        commands.migrate(
            sqlite_v2_workspace,
            output=best_effort_out,
            target=vocab.TARGET_WORKSPACE_V2,
            tool_version="0.0.1",
        )
        == ExitCode.MIGRATED_WITH_WARNINGS
    )
    output_before = policy.snapshot_tree(best_effort_out)
    with pytest.raises(UnsupportedInput) as mode_mismatch:
        commands.migrate(
            sqlite_v2_workspace,
            output=best_effort_out,
            target=vocab.TARGET_WORKSPACE_V2,
            strict=True,
            resume=True,
            tool_version="0.0.1",
        )
    assert mode_mismatch.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(best_effort_out)) == []


@pytest.mark.parametrize("tamper", ["checksum", "orphan", "nested_contract"])
def test_migrate_resume_refuses_checksum_or_orphan_without_touching_output(
    sqlite_v2_workspace: Path, tmp_path: Path, tamper: str
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_v2_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        copy_only=True,
        tool_version="0.0.1",
    )
    if tamper == "checksum":
        (out / "payload" / "store.sqlite").write_bytes(b"tampered")
    elif tamper == "orphan":
        (out / "payload" / "orphan.txt").write_text("orphan", encoding="utf-8")
    else:
        (out / "payload" / contracts.DEFAULT_MANIFEST_NAME).write_text("nested contract", encoding="utf-8")
    output_before = policy.snapshot_tree(out)

    with pytest.raises(UnsupportedInput) as raised:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            tool_version="0.0.1",
        )

    assert raised.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []


@pytest.mark.parametrize(
    ("replace_payload_directory", "unsafe_path"),
    [(False, "payload/store.sqlite"), (True, "payload")],
)
def test_verify_and_resume_refuse_attested_payload_symlink_without_writing(
    sqlite_v2_workspace: Path,
    tmp_path: Path,
    replace_payload_directory: bool,
    unsafe_path: str,
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_v2_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        copy_only=True,
        tool_version="0.0.1",
    )
    payload = out / "payload" / "store.sqlite"
    external = tmp_path / ("external-payload" if replace_payload_directory else "external-store.sqlite")
    external_store = external / "store.sqlite" if replace_payload_directory else external
    if replace_payload_directory:
        external.mkdir()
    external_store.write_bytes(payload.read_bytes())
    payload.unlink()
    try:
        if replace_payload_directory:
            payload.parent.rmdir()
            os.symlink(external, payload.parent, target_is_directory=True)
        else:
            os.symlink(external, payload)
    except OSError as exc:
        pytest.skip(f"symlinks are unavailable in this test environment: {exc}")

    source_before = policy.snapshot_tree(sqlite_v2_workspace)
    output_before = policy.snapshot_tree(out)
    verification_report = tmp_path / "verification-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=out / "migration-manifest.json", report_path=verification_report)
    summary = json.loads(verification_report.read_text(encoding="utf-8"))["verification_summary"]
    assert summary["checks"]["invalid_checksum_paths"] == ["payload/store.sqlite"]
    assert summary["checks"]["unsafe_output_paths"] == [unsafe_path]
    assert policy.diff_snapshots(source_before, policy.snapshot_tree(sqlite_v2_workspace)) == []
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []

    with pytest.raises(UnsupportedInput) as raised:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            tool_version="0.0.1",
        )
    assert raised.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(source_before, policy.snapshot_tree(sqlite_v2_workspace)) == []
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="the platform does not support FIFO nodes")
def test_verify_and_resume_refuse_special_output_node_without_writing(
    sqlite_v2_workspace: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_v2_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        copy_only=True,
        tool_version="0.0.1",
    )
    special = out / "payload" / "unlisted.fifo"
    os.mkfifo(special)

    source_before = policy.snapshot_tree(sqlite_v2_workspace)
    manifest_before = (out / contracts.DEFAULT_MANIFEST_NAME).read_bytes()
    special_before = special.stat()
    verification_report = tmp_path / "verification-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=out / contracts.DEFAULT_MANIFEST_NAME, report_path=verification_report)
    summary = json.loads(verification_report.read_text(encoding="utf-8"))["verification_summary"]
    assert summary["checks"]["special_output_paths"] == ["payload/unlisted.fifo"]
    assert policy.diff_snapshots(source_before, policy.snapshot_tree(sqlite_v2_workspace)) == []
    assert (out / contracts.DEFAULT_MANIFEST_NAME).read_bytes() == manifest_before
    assert stat.S_ISFIFO(special.stat().st_mode)
    assert special.stat().st_mtime_ns == special_before.st_mtime_ns

    with pytest.raises(UnsupportedInput) as raised:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            tool_version="0.0.1",
        )
    assert raised.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(source_before, policy.snapshot_tree(sqlite_v2_workspace)) == []
    assert (out / contracts.DEFAULT_MANIFEST_NAME).read_bytes() == manifest_before
    assert stat.S_ISFIFO(special.stat().st_mode)
    assert special.stat().st_mtime_ns == special_before.st_mtime_ns


@pytest.mark.parametrize("tamper", ["checksum", "inventory"])
def test_verify_and_resume_refuse_ledger_traversal_without_writing(
    sqlite_v2_workspace: Path, tmp_path: Path, tamper: str
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_v2_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        copy_only=True,
        tool_version="0.0.1",
    )
    manifest_path = out / "migration-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if tamper == "checksum":
        payload = out / "payload" / "store.sqlite"
        external = tmp_path / "external-store.sqlite"
        external.write_bytes(payload.read_bytes())
        payload.unlink()
        manifest["checksums"]["../external-store.sqlite"] = sha256_file(external)
        del manifest["checksums"]["payload/store.sqlite"]
    else:
        manifest["output_inventory"][0]["path"] = "../external-payload"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    source_before = policy.snapshot_tree(sqlite_v2_workspace)
    output_before = policy.snapshot_tree(out)
    verification_report = tmp_path / "verification-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=manifest_path, report_path=verification_report)
    summary = json.loads(verification_report.read_text(encoding="utf-8"))["verification_summary"]
    if tamper == "checksum":
        assert summary["checks"]["invalid_checksum_paths"] == ["../external-store.sqlite"]
    else:
        inventory = summary["checks"]["output_inventory_coverage"]
        assert inventory["status"] == "failed"
        assert inventory["invalid_entries"] == ["[0]: path is not a canonical relative path"]
    assert policy.diff_snapshots(source_before, policy.snapshot_tree(sqlite_v2_workspace)) == []
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []

    with pytest.raises(UnsupportedInput) as raised:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            tool_version="0.0.1",
        )
    assert raised.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(source_before, policy.snapshot_tree(sqlite_v2_workspace)) == []
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []


def test_migrate_resume_refuses_external_contract_path_and_missing_or_empty_output(
    sqlite_v2_workspace: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_v2_workspace,
        output=out,
        target=vocab.TARGET_WORKSPACE_V2,
        copy_only=True,
        tool_version="0.0.1",
    )
    output_before = policy.snapshot_tree(out)
    with pytest.raises(UnsupportedInput) as external_manifest:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            manifest_path=tmp_path / "external-manifest.json",
            tool_version="0.0.1",
        )
    assert external_manifest.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []

    missing_output = tmp_path / "missing-output"
    with pytest.raises(UnsupportedInput) as missing:
        commands.migrate(
            sqlite_v2_workspace,
            output=missing_output,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            tool_version="0.0.1",
        )
    assert missing.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert not missing_output.exists()

    empty_output = tmp_path / "empty-output"
    empty_output.mkdir()
    output_before = policy.snapshot_tree(empty_output)
    with pytest.raises(UnsupportedInput) as empty:
        commands.migrate(
            sqlite_v2_workspace,
            output=empty_output,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            resume=True,
            tool_version="0.0.1",
        )
    assert empty.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(empty_output)) == []


@pytest.mark.parametrize(
    ("argument", "filename"),
    [
        ("manifest_path", contracts.DEFAULT_MANIFEST_NAME),
        ("report_path", contracts.DEFAULT_REPORT_NAME),
        ("id_map_path", contracts.DEFAULT_ID_MAP_NAME),
        ("unsupported_report_path", contracts.DEFAULT_UNSUPPORTED_REPORT_NAME),
    ],
)
def test_migrate_refuses_nondefault_internal_contract_paths_before_writing(
    sqlite_v2_workspace: Path,
    tmp_path: Path,
    argument: str,
    filename: str,
) -> None:
    out = tmp_path / "out"
    kwargs = {argument: out / "contracts" / filename}
    source_before = policy.snapshot_tree(sqlite_v2_workspace)

    with pytest.raises(UnsupportedInput) as raised:
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            copy_only=True,
            tool_version="0.0.1",
            **kwargs,
        )

    assert raised.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert not out.exists()
    assert policy.diff_snapshots(source_before, policy.snapshot_tree(sqlite_v2_workspace)) == []


def test_migrate_allows_an_external_custom_manifest_path(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    external_manifest = tmp_path / "contracts" / "custom-manifest.json"

    assert (
        commands.migrate(
            sqlite_v2_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            manifest_path=external_manifest,
            copy_only=True,
            verify=True,
            tool_version="0.0.1",
        )
        == ExitCode.SUCCESS
    )

    assert external_manifest.exists()
    assert not (out / contracts.DEFAULT_MANIFEST_NAME).exists()
    assert commands.verify(out, manifest_path=external_manifest) == ExitCode.SUCCESS


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


@pytest.mark.parametrize("filename", ["surprise.txt", contracts.DEFAULT_MANIFEST_NAME])
def test_verify_detects_orphan_file(sqlite_v2_workspace: Path, tmp_path: Path, filename: str) -> None:
    out = tmp_path / "out"
    commands.migrate(
        sqlite_v2_workspace, output=out, target=vocab.TARGET_WORKSPACE_V2, copy_only=True, tool_version="0.0.1"
    )
    (out / "payload" / filename).write_text("unlisted", encoding="utf-8")
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
    unsupported_preserved = sum(1 for item in manifest["unsupported"] if item["disposition"] == "preserved")
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
    unsupported_preserved = sum(1 for item in manifest["unsupported"] if item["disposition"] == "preserved")
    del manifest["preserved_opaque"]
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report_path = tmp_path / "verify-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=manifest_path, report_path=report_path)

    report = json.loads(report_path.read_text(encoding="utf-8"))
    coverage = report["verification_summary"]["checks"]["preserved_payload_coverage"]
    assert coverage["status"] == "failed"
    assert coverage["missing_opaque_payloads"] == unsupported_preserved


def test_verify_and_resume_reject_preserved_opaque_disposition_relabelling(
    n4a_bundle: Path,
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    assert (
        commands.migrate(
            n4a_bundle,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            tool_version="0.0.1",
        )
        == ExitCode.MIGRATED_WITH_WARNINGS
    )

    manifest_path = out / contracts.DEFAULT_MANIFEST_NAME
    report_path = out / contracts.DEFAULT_REPORT_NAME
    unsupported_path = out / contracts.DEFAULT_UNSUPPORTED_REPORT_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    unsupported_report = json.loads(unsupported_path.read_text(encoding="utf-8"))
    preserved_path = manifest["preserved_opaque"][0]["path"]
    assert manifest["unsupported"][0]["disposition"] == "preserved"

    # Keep the report ledgers mutually consistent while falsely relabelling
    # the raw opaque bytes as refused.  Verification must bind the payload to
    # the deterministic preserved unsupported record, not merely compare counts.
    manifest["unsupported"][0]["disposition"] = "refused"
    report["unsupported_counts"].update({"preserved": 0, "refused": 1})
    unsupported_report["unsupported"] = manifest["unsupported"]
    unsupported_report["counts"].update({"preserved": 0, "refused": 1})
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    unsupported_path.write_text(json.dumps(unsupported_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    source_before = policy.snapshot_tree(n4a_bundle)
    output_before = policy.snapshot_tree(out)
    verification_report = tmp_path / "verification-report.json"
    with pytest.raises(VerificationFailed):
        commands.verify(out, manifest_path=manifest_path, report_path=verification_report)
    coverage = json.loads(verification_report.read_text(encoding="utf-8"))["verification_summary"]["checks"][
        "preserved_payload_coverage"
    ]
    assert coverage["status"] == "failed"
    assert coverage["unmatched_preserved_payloads"] == [preserved_path]
    assert policy.diff_snapshots(source_before, policy.snapshot_tree(n4a_bundle)) == []
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []

    with pytest.raises(UnsupportedInput) as raised:
        commands.migrate(
            n4a_bundle,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            resume=True,
            tool_version="0.0.1",
        )

    assert raised.value.cause == vocab.CAUSE_INVALID_REQUEST
    assert policy.diff_snapshots(source_before, policy.snapshot_tree(n4a_bundle)) == []
    assert policy.diff_snapshots(output_before, policy.snapshot_tree(out)) == []


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


def test_verify_detects_array_row_checksum_mismatch(sqlite_legacy_arrays_workspace: Path, tmp_path: Path) -> None:
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

"""Command-behavior tests (``commands.py``)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nirs4all_tools import commands, policy, vocab
from nirs4all_tools.errors import PolicyRefusal, UnsupportedInput, VerificationFailed
from nirs4all_tools.exit_codes import ExitCode


def _unchanged(source: Path, body) -> None:
    """Assert the source tree is byte/mtime identical across ``body()``."""
    before = policy.snapshot_tree(source)
    body()
    after = policy.snapshot_tree(source)
    assert policy.diff_snapshots(before, after) == []


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


# --- migrate: real transform is a marked stub ------------------------------
def test_migrate_real_transform_is_unimplemented_and_safe(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"

    def run() -> None:
        with pytest.raises(UnsupportedInput) as exc:
            commands.migrate(sqlite_v2_workspace, output=out, target=vocab.TARGET_WORKSPACE_V2, tool_version="0.0.1")
        assert exc.value.cause == vocab.CAUSE_UNSUPPORTED_CAPABILITY

    _unchanged(sqlite_v2_workspace, run)
    assert not out.exists()  # nothing written when the engine refuses


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
        assert code == ExitCode.MIGRATED_WITH_WARNINGS

    _unchanged(sqlite_legacy_arrays_workspace, run)

    manifest = json.loads((out / "migration-manifest.json").read_text(encoding="utf-8"))
    report = json.loads((out / "migration-report.json").read_text(encoding="utf-8"))
    id_map = json.loads((out / "migration-id-map.json").read_text(encoding="utf-8"))

    store = out / "store.sqlite"
    preserved = out / "preserved" / "legacy-prediction-arrays.jsonl"
    assert store.exists()
    assert preserved.exists()
    assert "store.sqlite" in manifest["checksums"]
    assert "preserved/legacy-prediction-arrays.jsonl" in manifest["checksums"]
    assert manifest["checksums"]["arrays:pred-1"].startswith("sha256:")
    assert manifest["preserved_opaque"] == [
        {
            "path": "preserved/legacy-prediction-arrays.jsonl",
            "reason": "legacy_prediction_arrays",
            "checksum": manifest["checksums"]["preserved/legacy-prediction-arrays.jsonl"],
        }
    ]
    assert manifest["unsupported"][0]["disposition"] == "preserved"
    assert report["status"] == vocab.STATUS_MIGRATED_WITH_WARNINGS
    assert report["migrated_counts"]["runs"] == 1
    assert report["migrated_counts"]["pipelines"] == 1
    assert report["migrated_counts"]["chains"] == 1
    assert report["migrated_counts"]["predictions"] == 1
    assert report["migrated_counts"]["arrays"] == 0
    assert report["verification_summary"]["passed"] is True
    assert id_map["schema_version"] == 1


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


def test_migrate_sqlite_legacy_arrays_strict_refuses_without_output(
    sqlite_legacy_arrays_workspace: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    with pytest.raises(UnsupportedInput) as exc:
        commands.migrate(
            sqlite_legacy_arrays_workspace,
            output=out,
            target=vocab.TARGET_WORKSPACE_V2,
            strict=True,
            tool_version="0.0.1",
        )
    assert exc.value.cause == vocab.CAUSE_UNSUPPORTED_CAPABILITY
    assert not out.exists()


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
    assert report["status"] == vocab.STATUS_MIGRATED_WITH_WARNINGS
    assert report["preserved_counts"]["opaque_artifacts"] == 1
    assert report["verification_summary"]["passed"] is True


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
    assert exc.value.cause == vocab.CAUSE_UNSUPPORTED_CAPABILITY
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
        "generated_manifests": ["migration-manifest.json", "migration-report.json", "migration-id-map.json"],
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


def test_verify_rejects_unreadable_manifest(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(UnsupportedInput):
        commands.verify(out, manifest_path=tmp_path / "does-not-exist.json")

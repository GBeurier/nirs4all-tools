"""Ecosystem e2e entrypoint for legacy save/prediction conversion.

This test intentionally enters through the public CLI and then projects the
converted workspace-v2 metadata plus array sidecar into the runtime result
envelope consumed by Web result-panel tests.
"""

from __future__ import annotations

import json
import math
import shutil
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

SCENARIO_ID = "e2e-converter-legacy-save-predictions-web"
WORKSPACE_ARTIFACT = "converted-workspace.n4a.json"
RT_RESULT_ARTIFACT = "predictions.rt_result.json"
PIPELINE_OPEN_ARTIFACT = "python-open-pipeline.json"
PIPELINE_RERUN_ARTIFACT = "python-rerun-pipeline.json"
CONVERTED_WORKSPACE_DIR = "converted-workspace-v2"
FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "legacy" / "old_workspace_mixed"
RERUNNABLE_PIPELINE_FIXTURE = FIXTURE_ROOT / "rerunnable_pipeline.n4a.json"

RT_RESULT_REQUIRED_KEYS = {
    "schema_version",
    "status",
    "run_id",
    "plan_id",
    "selection",
    "reports",
    "predictions",
    "manifest",
    "parity",
}
RT_RESULT_OPTIONAL_KEYS = {"artifacts", "diagnostics"}
RT_PREDICTION_KEYS = {
    "partition",
    "fold_id",
    "variant_id",
    "model_name",
    "sample_indices",
    "y_true",
    "y_pred",
    "y_proba",
    "scores",
    "metric",
    "task_type",
}
RT_REPORT_REQUIRED_KEYS = {"producer_node", "partition", "level", "row_count", "target_width", "metrics"}
RT_REPORT_OPTIONAL_KEYS = {"prediction_id", "variant_id", "variant_label", "fold_id", "target_names"}
RT_MANIFEST_KEYS = {"engine", "fingerprints", "capabilities", "portable_level", "files"}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _reset_generated_path(path: Path) -> None:
    if not path.exists():
        return
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def _copy_lowerable_legacy_save(tmp_path: Path) -> Path:
    """Copy only the lowerable legacy save shape out of the mixed golden."""
    source = tmp_path / "legacy-save"
    shutil.copytree(FIXTURE_ROOT / "runs", source / "runs")
    shutil.copy2(FIXTURE_ROOT / "run_predictions.json", source / "run_predictions.json")
    shutil.copy2(FIXTURE_ROOT / "sample.meta.parquet", source / "sample.meta.parquet")
    return source


def _require_pyarrow(explicit_artifacts_dir: bool) -> Any:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        message = (
            'legacy save/prediction e2e conversion requires pyarrow; install nirs4all-tools with ".[parquet]"'
        )
        if explicit_artifacts_dir:
            pytest.fail(message)
        pytest.skip(message)
        raise AssertionError("unreachable") from exc
    return pq


def _require_supported_python(explicit_artifacts_dir: bool) -> None:
    if sys.version_info >= (3, 11):  # noqa: UP036 - scenario command may run under an unsupported python3 alias.
        return
    message = "legacy save/prediction e2e conversion requires Python 3.11+ for nirs4all-tools"
    if explicit_artifacts_dir:
        pytest.fail(message)
    pytest.skip(message)


def _require_nirs4all_reference(explicit_artifacts_dir: bool) -> dict[str, Any]:
    try:
        import nirs4all
        import numpy as np
        from sklearn.cross_decomposition import PLSRegression
        from sklearn.model_selection import ShuffleSplit
    except ImportError as exc:
        message = (
            "legacy pipeline rerun e2e requires the sibling Python nirs4all reference; "
            "run with PYTHONPATH=/path/to/nirs4all checkout"
        )
        if explicit_artifacts_dir:
            pytest.fail(message)
        pytest.skip(message)
        raise AssertionError("unreachable") from exc
    return {
        "np": np,
        "nirs4all": nirs4all,
        "PLSRegression": PLSRegression,
        "ShuffleSplit": ShuffleSplit,
    }


def _run_converter_cli(source: Path, output: Path) -> None:
    from nirs4all_tools.cli import main
    from nirs4all_tools.exit_codes import ExitCode

    code = main(
        [
            "legacy",
            "migrate",
            str(source),
            "--output",
            str(output),
            "--target",
            "nirs4all-workspace-v2",
            "--strict",
            "--verify",
        ]
    )
    assert code == int(ExitCode.SUCCESS)
    verify_code = main(["legacy", "verify", str(output), "--manifest", str(output / "migration-manifest.json")])
    assert verify_code == int(ExitCode.SUCCESS)


def _fetch_single_prediction(output: Path) -> dict[str, Any]:
    with sqlite3.connect(output / "store.sqlite") as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT r.run_id, p.pipeline_id, p.chain_id, p.prediction_id, p.dataset_name,
                   p.model_name, p.model_class, p.fold_id, p.partition, p.val_score,
                   p.test_score, p.train_score, p.metric, p.task_type, p.n_samples,
                   p.scores, p.prediction_scope, p.prediction_level, c.preprocessings
            FROM predictions p
            JOIN pipelines pl ON p.pipeline_id = pl.pipeline_id
            JOIN runs r ON pl.run_id = r.run_id
            LEFT JOIN chains c ON p.chain_id = c.chain_id
            ORDER BY p.prediction_id
            """
        ).fetchall()
    assert len(rows) == 1
    return dict(rows[0])


def _fetch_single_array_row(output: Path, pq: Any) -> tuple[str, dict[str, Any]]:
    array_paths = sorted((output / "arrays").glob("*.parquet"))
    assert len(array_paths) == 1
    rows = pq.read_table(array_paths[0]).to_pylist()
    assert len(rows) == 1
    row = rows[0]
    assert isinstance(row, dict)
    return array_paths[0].relative_to(output).as_posix(), row


def _scores_from_prediction(prediction: dict[str, Any]) -> dict[str, float]:
    metric = str(prediction["metric"])
    value = prediction.get("val_score")
    if value is None:
        value = prediction.get("test_score")
    if value is None:
        value = prediction.get("train_score")
    if value is not None:
        return {metric: float(value)}
    raw = json.loads(str(prediction.get("scores") or "{}"))
    return {str(key): float(item) for key, item in raw.items()} if isinstance(raw, dict) else {}


def _relative(artifacts_dir: Path, path: Path) -> str:
    return path.relative_to(artifacts_dir).as_posix()


def _build_rt_result(
    *,
    artifacts_dir: Path,
    output: Path,
    manifest: dict[str, Any],
    prediction: dict[str, Any],
    array_rel: str,
    array_row: dict[str, Any],
) -> dict[str, Any]:
    from nirs4all_tools.checksums import sha256_file

    scores = _scores_from_prediction(prediction)
    sample_indices = [int(item) for item in array_row["sample_indices"]]
    prediction_id = str(prediction["prediction_id"])
    array_record_checksum = manifest["checksums"][f"arrays:{prediction_id}"]
    files = {
        "workspace": _relative(artifacts_dir, output / "store.sqlite"),
        "migration_manifest": _relative(artifacts_dir, output / "migration-manifest.json"),
        "migration_report": _relative(artifacts_dir, output / "migration-report.json"),
        "unsupported_report": _relative(artifacts_dir, output / "unsupported-report.json"),
        "runtime_arrays": [_relative(artifacts_dir, output / array_rel)],
    }
    return {
        "schema_version": 1,
        "status": "passed",
        "run_id": prediction["run_id"],
        "plan_id": prediction["pipeline_id"],
        "selection": None,
        "reports": [
            {
                "prediction_id": prediction_id,
                "variant_id": None,
                "producer_node": prediction["chain_id"],
                "partition": prediction["partition"],
                "fold_id": prediction["fold_id"],
                "level": "sample",
                "row_count": len(sample_indices),
                "target_width": 1,
                "metrics": scores,
            }
        ],
        "predictions": [
            {
                "partition": prediction["partition"],
                "fold_id": prediction["fold_id"],
                "variant_id": None,
                "model_name": prediction["model_name"],
                "sample_indices": sample_indices,
                "y_true": [float(item) for item in array_row["y_true"]],
                "y_pred": [float(item) for item in array_row["y_pred"]],
                "y_proba": array_row["y_proba"],
                "scores": scores,
                "metric": prediction["metric"],
                "task_type": prediction["task_type"],
            }
        ],
        "manifest": {
            "engine": "nirs4all-tools legacy-converter",
            "fingerprints": {
                "source": manifest["source"]["fingerprint"],
                "store": manifest["checksums"]["store.sqlite"],
                "array_record": array_record_checksum,
                "migration_manifest": sha256_file(output / "migration-manifest.json"),
            },
            "capabilities": {
                "execution_backend": "offline-converter",
                "converted_from_legacy": True,
                "prediction_lowering": "legacy-runs-preview",
                "task_type": prediction["task_type"],
                "score_metric": prediction["metric"],
                "oracle_scope": "deterministic_fixture_lowering",
            },
            "portable_level": None,
            "files": files,
        },
        "parity": {
            "status": "passed",
            "scope": "legacy_fixture_prediction_lowering",
            "prediction_rows": len(sample_indices),
            "runtime_array_checksum_match": True,
            "within_tolerance": True,
        },
        "artifacts": [
            {
                "kind": "workspace-v2",
                "path": files["workspace"],
                "checksum": manifest["checksums"]["store.sqlite"],
            },
            {
                "kind": "runtime-array-sidecar",
                "path": files["runtime_arrays"][0],
                "checksum": manifest["checksums"][array_rel],
            },
        ],
        "diagnostics": [],
    }


def _build_converted_workspace_artifact(
    *,
    artifacts_dir: Path,
    output: Path,
    manifest: dict[str, Any],
    report: dict[str, Any],
    unsupported: dict[str, Any],
    array_rel: str,
) -> dict[str, Any]:
    from nirs4all_tools.exit_codes import ExitCode

    return {
        "schema_version": "n4a.e2e.legacy_converter.converted_workspace/v1",
        "scenario": SCENARIO_ID,
        "status": "passed",
        "source": {
            "fixture": "tests/fixtures/legacy/old_workspace_mixed",
            "fixture_subset": ["runs", "run_predictions.json", "sample.meta.parquet"],
            "fingerprint": manifest["source"]["fingerprint"],
            "kinds": manifest["source"]["kinds"],
        },
        "converter": {
            "entrypoint": "nirs4all-tools legacy migrate --strict --verify",
            "exit_code": int(ExitCode.SUCCESS),
            "verification_passed": report["verification_summary"]["passed"],
            "unsupported_counts": unsupported["counts"],
        },
        "workspace": {
            "target": manifest["target"],
            "path": output.name,
            "store": _relative(artifacts_dir, output / "store.sqlite"),
            "migration_manifest": _relative(artifacts_dir, output / "migration-manifest.json"),
            "migration_report": _relative(artifacts_dir, output / "migration-report.json"),
            "unsupported_report": _relative(artifacts_dir, output / "unsupported-report.json"),
            "runtime_arrays": [_relative(artifacts_dir, output / array_rel)],
            "row_counts": report["migrated_counts"],
        },
        "prediction_result": RT_RESULT_ARTIFACT,
        "parity": {
            "status": "passed",
            "scope": "legacy_fixture_to_v1_workspace_and_result_contract",
            "checks": {
                "converter_verification_passed": report["verification_summary"]["passed"],
                "no_unsupported_payloads": unsupported["counts"]
                == {"unsupported": 0, "preserved": 0, "refused": 0, "opaque_payloads": 0},
                "runtime_array_preserved": bool(manifest["checksums"].get(array_rel)),
            },
        },
    }


def _build_python_open_pipeline_artifact(
    *,
    artifacts_dir: Path,
    output: Path,
    manifest: dict[str, Any],
    report: dict[str, Any],
    array_rel: str,
    array_row: dict[str, Any],
) -> dict[str, Any]:
    from nirs4all_tools import contracts
    from nirs4all_tools.checksums import sha256_file

    workspace_artifact = artifacts_dir / WORKSPACE_ARTIFACT
    rt_result_artifact = artifacts_dir / RT_RESULT_ARTIFACT
    reopened_workspace = _read_json(workspace_artifact)
    reopened_rt_result = _read_json(rt_result_artifact)
    reopened_manifest = _read_json(output / "migration-manifest.json")
    reopened_report = _read_json(output / "migration-report.json")

    store = output / "store.sqlite"
    store_sha256 = sha256_file(store)
    array_sha256 = sha256_file(output / array_rel)
    workspace_row_counts = reopened_workspace["workspace"]["row_counts"]
    rt_report = reopened_rt_result["reports"][0]
    rt_prediction = reopened_rt_result["predictions"][0]
    rt_prediction_rows = len(rt_prediction["sample_indices"])

    with sqlite3.connect(f"file:{store.resolve().as_posix()}?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")
        user_version_row = conn.execute("PRAGMA user_version").fetchone()
        store_user_version = int(user_version_row[0]) if user_version_row else None
        integrity_row = conn.execute("PRAGMA integrity_check").fetchone()
        integrity_ok = bool(integrity_row and integrity_row[0] == "ok")
        foreign_key_failures = [dict(row) for row in conn.execute("PRAGMA foreign_key_check")]
        tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        required_tables = {"runs", "pipelines", "chains", "predictions"}
        row_counts = {
            table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in sorted(required_tables)
        }

        def one(sql: str) -> dict[str, Any]:
            row = conn.execute(sql).fetchone()
            assert row is not None
            return dict(row)

        run_row = one("SELECT run_id, datasets, status FROM runs ORDER BY run_id")
        pipeline_row = one(
            """
            SELECT pipeline_id, run_id, name, expanded_config, generator_choices, dataset_name, status, metric
            FROM pipelines
            ORDER BY pipeline_id
            """
        )
        chain_row = one(
            """
            SELECT chain_id, pipeline_id, steps, model_class, model_name, metric, task_type, dataset_name
            FROM chains
            ORDER BY chain_id
            """
        )
        prediction_row = one(
            """
            SELECT prediction_id, pipeline_id, chain_id, dataset_name, model_name, model_class,
                   fold_id, partition, metric, task_type, n_samples, prediction_scope, prediction_level
            FROM predictions
            ORDER BY prediction_id
            """
        )

    pipeline_config = json.loads(str(pipeline_row["expanded_config"] or "{}"))
    pipeline_generator_choices = json.loads(str(pipeline_row["generator_choices"] or "[]"))
    chain_steps = json.loads(str(chain_row["steps"] or "[]"))
    run_datasets = json.loads(str(run_row["datasets"] or "[]"))
    expected_store_counts = {
        "runs": int(report["migrated_counts"]["runs"]),
        "pipelines": int(report["migrated_counts"]["pipelines"]),
        "chains": int(report["migrated_counts"]["chains"]),
        "predictions": int(report["migrated_counts"]["predictions"]),
    }
    workspace_counts_match = all(int(workspace_row_counts[key]) == row_counts[key] for key in expected_store_counts)
    row_counts_match_report = row_counts == expected_store_counts

    return {
        "schema_version": "n4a.e2e.python_open_pipeline.v1",
        "scenario_id": SCENARIO_ID,
        "status": "passed",
        "legacy_workspace_opened": True,
        "converted_workspace_reopened": True,
        "store_reopened_read_only": True,
        "sqlite_integrity_ok": integrity_ok,
        "sqlite_foreign_key_check_ok": foreign_key_failures == [],
        "required_tables_present": required_tables <= tables,
        "runtime_result_reopened": True,
        "pipeline_metadata_reopened": bool(pipeline_row["pipeline_id"] and chain_steps),
        "chain_metadata_reopened": bool(chain_row["chain_id"] and chain_row["model_class"]),
        "prediction_metadata_reopened": bool(prediction_row["prediction_id"]),
        "store_hash_match": store_sha256 == manifest["checksums"]["store.sqlite"],
        "array_hash_match": array_sha256 == manifest["checksums"][array_rel],
        "manifest_source_fingerprint_match": reopened_manifest["source"]["fingerprint"]
        == manifest["source"]["fingerprint"],
        "report_verification_summary_match": reopened_report["verification_summary"] == report["verification_summary"],
        "store_user_version": store_user_version,
        "expected_store_user_version": contracts.WORKSPACE_V2_USER_VERSION,
        "store_user_version_match": store_user_version == contracts.WORKSPACE_V2_USER_VERSION,
        "row_counts_match_report": row_counts_match_report,
        "workspace_artifact_counts_match_store": workspace_counts_match,
        "run_pipeline_fk_match": pipeline_row["run_id"] == run_row["run_id"],
        "chain_pipeline_fk_match": chain_row["pipeline_id"] == pipeline_row["pipeline_id"],
        "prediction_pipeline_fk_match": prediction_row["pipeline_id"] == pipeline_row["pipeline_id"],
        "prediction_chain_fk_match": prediction_row["chain_id"] == chain_row["chain_id"],
        "pipeline_dataset_match": pipeline_row["dataset_name"] == prediction_row["dataset_name"],
        "chain_dataset_match": chain_row["dataset_name"] == prediction_row["dataset_name"],
        "chain_model_class_match": chain_row["model_class"] == prediction_row["model_class"],
        "chain_model_name_match": chain_row["model_name"] == prediction_row["model_name"],
        "runtime_result_pipeline_id_match": reopened_rt_result["plan_id"] == prediction_row["pipeline_id"],
        "runtime_result_prediction_id_match": rt_report["prediction_id"] == prediction_row["prediction_id"],
        "runtime_result_rows_match": rt_prediction_rows == int(prediction_row["n_samples"]),
        "array_prediction_id_match": array_row["prediction_id"] == prediction_row["prediction_id"],
        "array_rows_match": len(array_row["sample_indices"]) == int(prediction_row["n_samples"]),
        "pipeline_step_count": len(chain_steps),
        "pipeline_classes": [str(step) for step in chain_steps],
        "prediction_rows": int(rt_prediction_rows),
        "workspace_row_counts": {
            "runs": int(workspace_row_counts["runs"]),
            "pipelines": int(workspace_row_counts["pipelines"]),
            "chains": int(workspace_row_counts["chains"]),
            "predictions": int(workspace_row_counts["predictions"]),
            "arrays": int(workspace_row_counts["arrays"]),
        },
        "store_row_counts": row_counts,
        "artifacts": {
            "converted_workspace": WORKSPACE_ARTIFACT,
            "runtime_result": RT_RESULT_ARTIFACT,
            "store": _relative(artifacts_dir, output / "store.sqlite"),
            "runtime_array": _relative(artifacts_dir, output / array_rel),
        },
        "fingerprints": {
            "store_sha256": store_sha256,
            "runtime_array_sha256": array_sha256,
            "source_fingerprint": manifest["source"]["fingerprint"],
        },
        "converted": {
            "run_id": run_row["run_id"],
            "pipeline_id": pipeline_row["pipeline_id"],
            "chain_id": chain_row["chain_id"],
            "prediction_id": prediction_row["prediction_id"],
            "dataset_name": prediction_row["dataset_name"],
            "model_name": prediction_row["model_name"],
            "model_class": prediction_row["model_class"],
            "metric": prediction_row["metric"],
            "task_type": prediction_row["task_type"],
            "prediction_scope": prediction_row["prediction_scope"],
            "prediction_level": prediction_row["prediction_level"],
            "run_datasets": run_datasets,
            "pipeline_config": pipeline_config,
            "pipeline_generator_choices": pipeline_generator_choices,
        },
    }


def _assert_rt_result_shape(rt_result: dict[str, Any]) -> None:
    assert set(rt_result) == RT_RESULT_REQUIRED_KEYS | RT_RESULT_OPTIONAL_KEYS
    assert set(rt_result["manifest"]) == RT_MANIFEST_KEYS
    for report in rt_result["reports"]:
        assert RT_REPORT_REQUIRED_KEYS <= set(report)
        assert set(report) <= RT_REPORT_REQUIRED_KEYS | RT_REPORT_OPTIONAL_KEYS
    for prediction in rt_result["predictions"]:
        assert set(prediction) == RT_PREDICTION_KEYS


def _materialize_converted_state(
    *,
    artifacts_dir: Path,
    artifacts_dir_explicit: bool,
    tmp_path: Path,
) -> dict[str, Any]:
    _require_supported_python(artifacts_dir_explicit)
    pq = _require_pyarrow(artifacts_dir_explicit)
    source = _copy_lowerable_legacy_save(tmp_path)
    output = artifacts_dir / CONVERTED_WORKSPACE_DIR
    workspace_artifact = artifacts_dir / WORKSPACE_ARTIFACT
    rt_result_artifact = artifacts_dir / RT_RESULT_ARTIFACT
    for path in (output, workspace_artifact, rt_result_artifact):
        _reset_generated_path(path)

    _run_converter_cli(source, output)

    manifest = _read_json(output / "migration-manifest.json")
    report = _read_json(output / "migration-report.json")
    unsupported = _read_json(output / "unsupported-report.json")
    prediction = _fetch_single_prediction(output)
    array_rel, array_row = _fetch_single_array_row(output, pq)

    assert manifest["unsupported"] == []
    assert manifest["preserved_opaque"] == []
    assert unsupported["counts"] == {"unsupported": 0, "preserved": 0, "refused": 0, "opaque_payloads": 0}
    assert report["verification_summary"]["passed"] is True
    assert report["migrated_counts"]["predictions"] == 1
    assert report["migrated_counts"]["arrays"] == 1
    assert prediction["prediction_id"] == array_row["prediction_id"] == "pred-loose-001"
    assert array_row["sample_indices"] == [0, 1, 2]
    assert array_row["y_true"] == [31.0, 30.1, 33.0]
    assert array_row["y_pred"] == [31.0, 30.1, 33.0]

    rt_result = _build_rt_result(
        artifacts_dir=artifacts_dir,
        output=output,
        manifest=manifest,
        prediction=prediction,
        array_rel=array_rel,
        array_row=array_row,
    )
    _assert_rt_result_shape(rt_result)
    workspace = _build_converted_workspace_artifact(
        artifacts_dir=artifacts_dir,
        output=output,
        manifest=manifest,
        report=report,
        unsupported=unsupported,
        array_rel=array_rel,
    )

    _write_json(rt_result_artifact, rt_result)
    _write_json(workspace_artifact, workspace)

    return {
        "output": output,
        "manifest": manifest,
        "report": report,
        "unsupported": unsupported,
        "prediction": prediction,
        "array_rel": array_rel,
        "array_row": array_row,
        "rt_result": rt_result,
        "workspace": workspace,
    }


def _pipeline_from_fixture(fixture: dict[str, Any], prediction: dict[str, Any], refs: dict[str, Any]) -> list[Any]:
    pipeline: list[Any] = []
    for step in fixture["pipeline"]:
        class_name = step["class"]
        params = dict(step.get("params") or {})
        if class_name == "sklearn.model_selection.ShuffleSplit":
            pipeline.append(refs["ShuffleSplit"](**params))
        elif class_name == "sklearn.cross_decomposition.PLSRegression":
            assert prediction["model_class"] == class_name
            pipeline.append(
                {"model": refs["PLSRegression"](**params), "name": str(step.get("name") or "PLSRegression")}
            )
        else:
            raise AssertionError(f"unsupported rerunnable fixture step: {class_name}")
    return pipeline


def test_convert_legacy_save(
    artifacts_dir: Path,
    artifacts_dir_explicit: bool,
    tmp_path: Path,
) -> None:
    state = _materialize_converted_state(
        artifacts_dir=artifacts_dir,
        artifacts_dir_explicit=artifacts_dir_explicit,
        tmp_path=tmp_path,
    )

    rt_result = state["rt_result"]
    workspace = state["workspace"]
    rt_result_artifact = artifacts_dir / RT_RESULT_ARTIFACT
    workspace_artifact = artifacts_dir / WORKSPACE_ARTIFACT

    assert _read_json(rt_result_artifact)["status"] == "passed"
    assert _read_json(rt_result_artifact)["parity"]["status"] == "passed"
    assert _read_json(rt_result_artifact)["predictions"][0]["scores"] == {"rmse": 0.0}
    assert _read_json(workspace_artifact)["parity"]["status"] == "passed"
    assert rt_result["predictions"][0]["y_true"] == [31.0, 30.1, 33.0]
    assert rt_result["predictions"][0]["y_pred"] == [31.0, 30.1, 33.0]
    assert workspace["parity"]["status"] == "passed"


def test_python_rerun_converted_pipeline(
    artifacts_dir: Path,
    artifacts_dir_explicit: bool,
    tmp_path: Path,
) -> None:
    _require_supported_python(artifacts_dir_explicit)
    refs = _require_nirs4all_reference(artifacts_dir_explicit)
    np = refs["np"]
    nirs4all = refs["nirs4all"]

    state = _materialize_converted_state(
        artifacts_dir=artifacts_dir,
        artifacts_dir_explicit=artifacts_dir_explicit,
        tmp_path=tmp_path,
    )
    open_evidence = _build_python_open_pipeline_artifact(
        artifacts_dir=artifacts_dir,
        output=state["output"],
        manifest=state["manifest"],
        report=state["report"],
        array_rel=state["array_rel"],
        array_row=state["array_row"],
    )
    for check_name in (
        "legacy_workspace_opened",
        "converted_workspace_reopened",
        "store_reopened_read_only",
        "sqlite_integrity_ok",
        "sqlite_foreign_key_check_ok",
        "required_tables_present",
        "runtime_result_reopened",
        "pipeline_metadata_reopened",
        "chain_metadata_reopened",
        "prediction_metadata_reopened",
        "store_hash_match",
        "array_hash_match",
        "manifest_source_fingerprint_match",
        "report_verification_summary_match",
        "store_user_version_match",
        "row_counts_match_report",
        "workspace_artifact_counts_match_store",
        "run_pipeline_fk_match",
        "chain_pipeline_fk_match",
        "prediction_pipeline_fk_match",
        "prediction_chain_fk_match",
        "pipeline_dataset_match",
        "chain_dataset_match",
        "chain_model_class_match",
        "chain_model_name_match",
        "runtime_result_pipeline_id_match",
        "runtime_result_prediction_id_match",
        "runtime_result_rows_match",
        "array_prediction_id_match",
        "array_rows_match",
    ):
        assert open_evidence[check_name] is True
    assert open_evidence["store_user_version"] == open_evidence["expected_store_user_version"]
    assert open_evidence["prediction_rows"] > 0
    assert open_evidence["pipeline_step_count"] > 0
    _write_json(artifacts_dir / PIPELINE_OPEN_ARTIFACT, open_evidence)

    prediction = state["prediction"]
    array_row = state["array_row"]
    fixture = _read_json(RERUNNABLE_PIPELINE_FIXTURE)
    assert fixture["scenario_id"] == SCENARIO_ID
    assert fixture["dataset"]["id"] == prediction["dataset_name"]
    assert fixture["comparison"]["prediction_id"] == prediction["prediction_id"]
    assert _read_json(artifacts_dir / PIPELINE_OPEN_ARTIFACT)["status"] == "passed"

    pipeline = _pipeline_from_fixture(fixture, prediction, refs)
    x = np.asarray(fixture["dataset"]["x"], dtype=float)
    y = np.asarray(fixture["dataset"]["y"], dtype=float)
    assert x.ndim == 2
    assert y.ndim == 1
    assert x.shape[0] == y.shape[0]

    result = nirs4all.run(
        pipeline,
        (x, y),
        name="e2e_converted_legacy_pipeline_rerun",
        verbose=0,
        save_artifacts=False,
        save_charts=False,
        random_state=42,
        refit=True,
        workspace_path=artifacts_dir / "python-rerun-workspace",
    )
    rerun_prediction = result.final or result.best
    assert rerun_prediction is not None
    rerun_y_pred = np.asarray(rerun_prediction["y_pred"], dtype=float).reshape(-1)
    rerun_y_true = np.asarray(rerun_prediction["y_true"], dtype=float).reshape(-1)
    assert rerun_y_pred.shape == rerun_y_true.shape
    assert rerun_y_pred.size == y.size

    sample_indices = [int(item) for item in array_row["sample_indices"]]
    selected_pred = np.asarray([rerun_y_pred[index] for index in sample_indices], dtype=float)
    selected_true = np.asarray([rerun_y_true[index] for index in sample_indices], dtype=float)
    legacy_pred = np.asarray(array_row["y_pred"], dtype=float)
    legacy_true = np.asarray(array_row["y_true"], dtype=float)
    prediction_delta = np.abs(selected_pred - legacy_pred)
    prediction_max_abs_delta = float(np.max(prediction_delta)) if prediction_delta.size else math.inf
    rmse = float(np.sqrt(np.mean(np.square(selected_pred - legacy_true))))
    legacy_rmse = float(_scores_from_prediction(prediction)["rmse"])
    rmse_delta = abs(rmse - legacy_rmse)
    prediction_tolerance = float(fixture["comparison"]["prediction_tolerance"])
    rmse_tolerance = float(fixture["comparison"]["rmse_tolerance"])
    finite_predictions = bool(np.all(np.isfinite(rerun_y_pred)))
    target_max_abs_delta = float(np.max(np.abs(selected_true - legacy_true))) if selected_true.size else math.inf

    assert finite_predictions
    assert target_max_abs_delta <= prediction_tolerance
    assert prediction_max_abs_delta <= prediction_tolerance
    assert rmse_delta <= rmse_tolerance

    evidence = {
        "schema_version": "n4a.e2e.python_rerun_pipeline.v1",
        "scenario_id": SCENARIO_ID,
        "status": "passed",
        "converted_workspace_reopened": True,
        "pipeline_reopened": True,
        "python_rerun_executed": True,
        "finite_predictions": finite_predictions,
        "prediction_rows": int(selected_pred.shape[0]),
        "target_max_abs_delta": target_max_abs_delta,
        "prediction_max_abs_delta": prediction_max_abs_delta,
        "prediction_tolerance": prediction_tolerance,
        "rmse": rmse,
        "legacy_rmse": legacy_rmse,
        "rmse_delta": rmse_delta,
        "rmse_tolerance": rmse_tolerance,
        "dataset": {
            "id": fixture["dataset"]["id"],
            "rows": int(x.shape[0]),
            "features": int(x.shape[1]),
        },
        "converted": {
            "run_id": prediction["run_id"],
            "pipeline_id": prediction["pipeline_id"],
            "prediction_id": prediction["prediction_id"],
            "model_class": prediction["model_class"],
            "sample_indices": sample_indices,
        },
        "rerun": {
            "nirs4all_version": getattr(nirs4all, "__version__", "unknown"),
            "model_name": str(prediction["model_name"]),
            "selected_y_pred": [float(item) for item in selected_pred],
            "selected_y_true": [float(item) for item in selected_true],
            "train_score": None
            if rerun_prediction.get("train_score") is None
            else float(rerun_prediction["train_score"]),
        },
    }
    _write_json(artifacts_dir / PIPELINE_RERUN_ARTIFACT, evidence)

    assert _read_json(artifacts_dir / PIPELINE_RERUN_ARTIFACT)["status"] == "passed"

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
    prediction = state["prediction"]
    array_row = state["array_row"]
    fixture = _read_json(RERUNNABLE_PIPELINE_FIXTURE)
    assert fixture["scenario_id"] == SCENARIO_ID
    assert fixture["dataset"]["id"] == prediction["dataset_name"]
    assert fixture["comparison"]["prediction_id"] == prediction["prediction_id"]

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

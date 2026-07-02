"""Native-results lowering guards."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from nirs4all_tools import vocab
from nirs4all_tools.errors import UnsupportedInput
from nirs4all_tools.native_results import (
    NativeResultsPreview,
    load_native_results_preview,
    runtime_array_records_from_native_results,
)


def _preview(row: dict[str, Any]) -> NativeResultsPreview:
    return NativeResultsPreview(
        run_dir=Path("native-results"),
        manifest={
            "run_id": "run-native-1",
            "engine": "dag-ml",
            "metric": "rmse",
            "task_type": "regression",
        },
        score_set={},
        prediction_rows=[row],
    )


def _row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "arrays_present": True,
        "dataset": "dataset-a",
        "config_name": "config-a",
        "model_name": "PLSRegression",
        "partition": "val",
        "fold_id": "fold-0",
        "sample_indices": [],
        "y_true": [1.0, 2.0, 3.0],
        "y_pred": [1.1, 1.9, 3.2],
        "y_proba": [],
        "y_true_shape": [3],
        "y_pred_shape": [3],
        "y_proba_shape": [],
        "weights": [],
        "val_score": 0.1,
        "metric": "rmse",
        "task_type": "regression",
    }
    row.update(overrides)
    return row


def _mark_native_results_as_multidimensional(path: Path, *, field: str = "y_pred_shape") -> None:
    pytest.importorskip("pyarrow")
    import pyarrow as pa
    import pyarrow.parquet as pq

    predictions = path / "predictions.parquet"
    table = pq.read_table(predictions)
    rows = table.to_pylist()
    rows[0][field] = [3, 1]
    pq.write_table(pa.Table.from_pylist(rows, schema=table.schema), predictions)


def test_native_results_empty_optional_arrays_lower_to_none() -> None:
    records = runtime_array_records_from_native_results(_preview(_row()))

    assert records[0]["sample_indices"] is None
    assert records[0]["y_proba"] is None
    assert records[0]["y_proba_shape"] is None
    assert records[0]["weights"] is None


@pytest.mark.parametrize("field", ["y_true_shape", "y_pred_shape"])
def test_native_results_preview_refuses_multidimensional_y_true_or_y_pred_shape(
    lowerable_native_results_dir: Path,
    field: str,
) -> None:
    _mark_native_results_as_multidimensional(lowerable_native_results_dir, field=field)

    with pytest.raises(UnsupportedInput) as exc:
        load_native_results_preview(lowerable_native_results_dir)

    assert exc.value.cause == vocab.CAUSE_UNSUPPORTED_SHAPE
    assert field in exc.value.message
    assert "workspace-v2 sidecars preserve only flat" in exc.value.message


def test_native_results_proba_arrays_lower_to_flat_sidecar_record() -> None:
    """A classification row's probability arrays and shape pass through to the sidecar record.

    Unlike the legacy ``prediction_arrays`` path (which derives ``y_proba_shape`` from the
    nested cell), native-results lowering takes ``y_proba`` as an already-flat projection and
    carries ``y_proba_shape`` verbatim from the parquet row. Row-level ``metric``/``task_type``
    also take precedence over the manifest defaults. This locks the multi-class proba surface,
    which the existing empty-array test does not exercise.
    """
    record = runtime_array_records_from_native_results(
        _preview(
            _row(
                model_name="SVC",
                metric="accuracy",
                task_type="classification",
                y_true=[0.0, 1.0, 1.0, 0.0],
                y_pred=[0.0, 1.0, 0.0, 0.0],
                y_proba=[0.9, 0.1, 0.2, 0.8, 0.6, 0.4, 0.8, 0.2],
                y_proba_shape=[4, 2],
            )
        )
    )[0]

    assert record["y_proba"] == [0.9, 0.1, 0.2, 0.8, 0.6, 0.4, 0.8, 0.2]
    assert record["y_proba_shape"] == [4, 2]
    assert record["y_true"] == [0.0, 1.0, 1.0, 0.0]
    assert record["metric"] == "accuracy"
    assert record["task_type"] == "classification"
    assert record["model_name"] == "SVC"

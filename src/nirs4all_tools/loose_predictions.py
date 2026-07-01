"""Strict preview lowering for standalone loose prediction JSON payloads."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import vocab
from .errors import UnsupportedInput

LOOSE_PREDICTIONS_PREVIEW_VERSION = 1

_REQUIRED_FIELDS = (
    "run_id",
    "pipeline_id",
    "prediction_id",
    "dataset",
    "model_name",
    "model_class",
    "fold_id",
    "partition",
    "metric",
    "task_type",
    "sample_indices",
    "y_true",
    "y_pred",
)


@dataclass(frozen=True)
class LoosePredictionsPreview:
    """Validated loose prediction payload ready for workspace-v2 lowering."""

    root: Path
    prediction_file: str
    record: dict[str, Any]


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _stable_id(prefix: str, *parts: Any) -> str:
    payload = _canonical_json(parts).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(payload).hexdigest()[:24]}"


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        data: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UnsupportedInput(
            f"loose-predictions preview could not read {path.name}: {exc}",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the loose predictions opaque, or repair the JSON payload",
        ) from exc
    if not isinstance(data, dict):
        raise UnsupportedInput(
            f"loose-predictions preview requires {path.name} to be a JSON object",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the loose predictions opaque, or repair the JSON payload",
        )
    return data


def _required_string(record: dict[str, Any], field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value:
        raise UnsupportedInput(
            f"loose-predictions preview requires non-empty string field {field!r}",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the loose predictions opaque, or add the missing prediction metadata",
        )
    return value


def _numeric_list(record: dict[str, Any], field: str, *, dtype: type[float] | type[int]) -> list[Any]:
    value = record.get(field)
    if not isinstance(value, list) or not value:
        raise UnsupportedInput(
            f"loose-predictions preview requires non-empty array field {field!r}",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the loose predictions opaque, or add complete prediction arrays",
        )
    out: list[Any] = []
    for item in value:
        if isinstance(item, list):
            raise UnsupportedInput(
                f"loose-predictions preview supports only flat {field!r} arrays",
                cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
                mitigation="preserve the loose predictions opaque until workspace-v2 records array shape metadata",
            )
        try:
            out.append(dtype(item))
        except (TypeError, ValueError) as exc:
            raise UnsupportedInput(
                f"loose-predictions preview field {field!r} contains a non-numeric value",
                cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
                mitigation="preserve the loose predictions opaque, or repair the array values",
            ) from exc
    return out


def _optional_numeric_list(record: dict[str, Any], field: str, *, dtype: type[float] | type[int]) -> list[Any] | None:
    value = record.get(field)
    if value is None or value == []:
        return None
    record_with_required = dict(record)
    record_with_required[field] = value
    return _numeric_list(record_with_required, field, dtype=dtype)


def _optional_float(record: dict[str, Any], field: str) -> float | None:
    value = record.get(field)
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise UnsupportedInput(
            f"loose-predictions preview field {field!r} is not numeric",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the loose predictions opaque, or repair the score value",
        ) from exc


def _validate_prediction_record(record: dict[str, Any]) -> dict[str, Any]:
    missing = [field for field in _REQUIRED_FIELDS if field not in record]
    if missing:
        raise UnsupportedInput(
            "loose-predictions preview missing field(s): " + ", ".join(missing),
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the loose predictions opaque, or add the missing prediction metadata",
        )

    normalised: dict[str, Any] = {field: _required_string(record, field) for field in _REQUIRED_FIELDS[:10]}
    normalised["sample_indices"] = _numeric_list(record, "sample_indices", dtype=int)
    normalised["y_true"] = _numeric_list(record, "y_true", dtype=float)
    normalised["y_pred"] = _numeric_list(record, "y_pred", dtype=float)
    normalised["y_proba"] = _optional_numeric_list(record, "y_proba", dtype=float)
    normalised["weights"] = _optional_numeric_list(record, "weights", dtype=float)
    normalised["val_score"] = _optional_float(record, "val_score")
    normalised["test_score"] = _optional_float(record, "test_score")
    normalised["train_score"] = _optional_float(record, "train_score")
    normalised["scores"] = record.get("scores") if isinstance(record.get("scores"), dict) else {}
    preprocessing = record.get("preprocessing") or []
    if not isinstance(preprocessing, list):
        raise UnsupportedInput(
            "loose-predictions preview field 'preprocessing' must be an array when present",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the loose predictions opaque, or repair the preprocessing metadata",
        )
    normalised["preprocessing"] = [str(item) for item in preprocessing]

    lengths = {len(normalised["sample_indices"]), len(normalised["y_true"]), len(normalised["y_pred"])}
    if normalised["weights"] is not None:
        lengths.add(len(normalised["weights"]))
    if len(lengths) != 1:
        raise UnsupportedInput(
            "loose-predictions preview requires sample_indices, y_true, y_pred, and weights to have matching lengths",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the loose predictions opaque, or repair the array lengths",
        )
    return normalised


def load_loose_predictions_preview(root: Path, files: list[str]) -> LoosePredictionsPreview:
    """Validate one standalone loose prediction JSON file."""

    prediction_files = sorted(name for name in files if name.endswith("_predictions.json"))
    if len(prediction_files) != 1:
        raise UnsupportedInput(
            f"loose-predictions preview supports exactly one *_predictions.json file, got {len(prediction_files)}",
            cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
            mitigation="preserve the loose predictions opaque, or split the payload before migration",
        )
    prediction_file = prediction_files[0]
    path = root / prediction_file
    if not path.is_file():
        raise UnsupportedInput(
            f"loose-predictions preview could not find {prediction_file}",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the loose predictions opaque, or repair the source directory",
        )
    return LoosePredictionsPreview(
        root=root,
        prediction_file=prediction_file,
        record=_validate_prediction_record(_load_json_object(path)),
    )


def runtime_array_records_from_loose_predictions(preview: LoosePredictionsPreview) -> list[dict[str, Any]]:
    record = preview.record
    return [
        {
            "prediction_id": record["prediction_id"],
            "dataset_name": record["dataset"],
            "model_name": record["model_name"],
            "fold_id": record["fold_id"],
            "partition": record["partition"],
            "metric": record["metric"],
            "val_score": record["val_score"],
            "task_type": record["task_type"],
            "y_true": record["y_true"],
            "y_pred": record["y_pred"],
            "y_proba": record["y_proba"],
            "y_proba_shape": [len(record["y_proba"])] if record["y_proba"] is not None else None,
            "sample_indices": record["sample_indices"],
            "weights": record["weights"],
            "sample_metadata": None,
        }
    ]


def lower_loose_predictions_preview(conn: sqlite3.Connection, preview: LoosePredictionsPreview) -> dict[str, int]:
    """Insert one validated loose prediction payload into workspace-v2 metadata."""

    record = preview.record
    run_id = record["run_id"]
    pipeline_id = record["pipeline_id"]
    chain_id = _stable_id("chain", run_id, pipeline_id, record["model_class"], record["model_name"])
    prediction_id = record["prediction_id"]
    preprocessing = record["preprocessing"]

    conn.execute(
        """
        INSERT INTO runs (run_id, name, config, datasets, status, summary)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            f"loose-predictions {run_id}",
            _canonical_json({"source_kind": "loose-predictions", "prediction_file": preview.prediction_file}),
            _canonical_json([record["dataset"]]),
            "completed",
            _canonical_json({"loose_predictions_preview_version": LOOSE_PREDICTIONS_PREVIEW_VERSION}),
        ),
    )
    conn.execute(
        """
        INSERT INTO pipelines
            (pipeline_id, run_id, name, expanded_config, generator_choices, dataset_name,
             status, best_val, best_test, metric)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            pipeline_id,
            run_id,
            pipeline_id,
            _canonical_json({"source_kind": "loose-predictions", "prediction_file": preview.prediction_file}),
            "[]",
            record["dataset"],
            "completed",
            record["val_score"],
            record["test_score"],
            record["metric"],
        ),
    )
    conn.execute(
        """
        INSERT INTO chains
            (chain_id, pipeline_id, steps, model_step_idx, model_class, preprocessings,
             model_name, metric, task_type, dataset_name)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            chain_id,
            pipeline_id,
            _canonical_json(preprocessing + [record["model_class"]]),
            len(preprocessing),
            record["model_class"],
            ", ".join(preprocessing),
            record["model_name"],
            record["metric"],
            record["task_type"],
            record["dataset"],
        ),
    )
    conn.execute(
        """
        INSERT INTO predictions
            (prediction_id, pipeline_id, chain_id, dataset_name, model_name, model_class,
             fold_id, partition, val_score, test_score, train_score, metric, task_type,
             n_samples, scores, prediction_scope, prediction_level)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            prediction_id,
            pipeline_id,
            chain_id,
            record["dataset"],
            record["model_name"],
            record["model_class"],
            record["fold_id"],
            record["partition"],
            record["val_score"],
            record["test_score"],
            record["train_score"],
            record["metric"],
            record["task_type"],
            len(record["sample_indices"]),
            _canonical_json(record["scores"]),
            "loose-predictions",
            "prediction-row",
        ),
    )
    return {"runs": 1, "pipelines": 1, "chains": 1, "predictions": 1, "artifacts": 0}


__all__ = [
    "LOOSE_PREDICTIONS_PREVIEW_VERSION",
    "LoosePredictionsPreview",
    "load_loose_predictions_preview",
    "lower_loose_predictions_preview",
    "runtime_array_records_from_loose_predictions",
]

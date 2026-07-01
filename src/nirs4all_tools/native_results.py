"""Native-results-v1 validation and workspace-v2 metadata lowering.

This module reads only the standalone native-results directory shape written by
the dag-ml backend: ``manifest.json`` + ``score_set.json`` +
``predictions.parquet``.  It does not import the runtime package and does not
load joblib model artifacts.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from . import vocab
from .errors import UnsupportedInput

NATIVE_RESULTS_PREVIEW_VERSION = 1

_REQUIRED_MANIFEST_FIELDS = ("schema_version", "run_id", "engine", "score_set_hash")
_REQUIRED_PREDICTION_COLUMNS = frozenset(
    {
        "dataset",
        "config_name",
        "variant_id",
        "model_name",
        "partition",
        "fold_id",
        "refit_context",
        "sample_indices",
        "y_true",
        "y_pred",
        "y_proba",
        "y_true_shape",
        "y_pred_shape",
        "y_proba_shape",
        "weights",
        "arrays_present",
        "val_score",
        "test_score",
        "train_score",
        "scores",
        "metric",
        "task_type",
        "target_width",
        "target_names",
    }
)


@dataclass(frozen=True)
class NativeResultsPreview:
    """Validated native-results payload ready for metadata-only lowering."""

    run_dir: Path
    manifest: dict[str, Any]
    score_set: dict[str, Any]
    prediction_rows: list[dict[str, Any]]


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _score_set_hash(score_set: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(score_set).encode("utf-8")).hexdigest()


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        data: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UnsupportedInput(
            f"native-results-v1 schema gate could not read {label}: {exc}",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the native results opaque, or regenerate the native results directory",
        ) from exc
    if not isinstance(data, dict):
        raise UnsupportedInput(
            f"native-results-v1 schema gate requires {label} to be a JSON object",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the native results opaque, or regenerate the native results directory",
        )
    return data


def _manifest_file(manifest: dict[str, Any], key: str, default: str) -> str:
    files = manifest.get("files")
    value = files.get(key) if isinstance(files, dict) else default
    if not isinstance(value, str) or not value:
        raise UnsupportedInput(
            f"native-results-v1 schema gate requires manifest.files.{key} to be a relative file path",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the native results opaque, or regenerate the native results directory",
        )
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise UnsupportedInput(
            f"native-results-v1 schema gate refuses non-portable manifest.files.{key}: {value!r}",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the native results opaque; the manifest references a non-portable file",
        )
    return path.as_posix()


def _read_prediction_rows(path: Path) -> list[dict[str, Any]]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise UnsupportedInput(
            "native-results-v1 semantic lowering requires the optional pyarrow dependency",
            cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
            mitigation='install nirs4all-tools with the "parquet" extra, or rerun without --strict',
        ) from exc

    try:
        table = pq.read_table(path)
    except Exception as exc:  # noqa: BLE001 - pyarrow raises several concrete parse errors.
        raise UnsupportedInput(
            f"native-results-v1 schema gate could not read predictions parquet: {exc}",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the native results opaque, or regenerate predictions.parquet",
        ) from exc

    missing = sorted(_REQUIRED_PREDICTION_COLUMNS.difference(table.column_names))
    if missing:
        raise UnsupportedInput(
            "native-results-v1 schema gate missing predictions.parquet column(s): " + ", ".join(missing),
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the native results opaque, or regenerate with the current native-results writer",
        )
    return cast(list[dict[str, Any]], table.to_pylist())


def load_native_results_preview(run_dir: Path) -> NativeResultsPreview:
    """Validate and load one native-results-v1 directory for preview lowering."""

    manifest = _load_json_object(run_dir / "manifest.json", "manifest.json")
    missing_manifest = [field for field in _REQUIRED_MANIFEST_FIELDS if field not in manifest]
    if missing_manifest:
        raise UnsupportedInput(
            "native-results-v1 schema gate missing manifest field(s): " + ", ".join(missing_manifest),
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the native results opaque, or regenerate with the current native-results writer",
        )

    if manifest.get("engine") != "dag-ml":
        raise UnsupportedInput(
            f"native-results-v1 schema gate only lowers dag-ml engine payloads, got {manifest.get('engine')!r}",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve this native results directory opaque",
        )

    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise UnsupportedInput(
            "native-results-v1 schema gate requires manifest.run_id to be a non-empty string",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the native results opaque, or regenerate the native results directory",
        )

    score_rel = _manifest_file(manifest, "score_set", "score_set.json")
    predictions_rel = _manifest_file(manifest, "predictions", "predictions.parquet")
    score_set = _load_json_object(run_dir / score_rel, score_rel)

    expected_hash = manifest.get("score_set_hash")
    actual_hash = _score_set_hash(score_set)
    if expected_hash != actual_hash:
        raise UnsupportedInput(
            "native-results-v1 schema gate score_set_hash mismatch: "
            f"manifest recorded {expected_hash!r}, score_set.json hashes to {actual_hash!r}",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the native results opaque; score_set.json was edited or corrupted",
        )

    prediction_rows = _read_prediction_rows(run_dir / predictions_rel)
    declared_count = manifest.get("num_predictions")
    if isinstance(declared_count, int) and declared_count != len(prediction_rows):
        raise UnsupportedInput(
            "native-results-v1 schema gate num_predictions mismatch: "
            f"manifest recorded {declared_count}, predictions.parquet contains {len(prediction_rows)} row(s)",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="preserve the native results opaque; manifest and predictions.parquet disagree",
        )

    return NativeResultsPreview(
        run_dir=run_dir,
        manifest=manifest,
        score_set=score_set,
        prediction_rows=prediction_rows,
    )


def _stable_id(prefix: str, *parts: Any) -> str:
    payload = _canonical_json(parts).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(payload).hexdigest()[:24]}"


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None and str(item)]


def _first_string(*values: Any, default: str = "") -> str:
    for value in values:
        if isinstance(value, list):
            for item in value:
                if item is not None and str(item):
                    return str(item)
            continue
        if value is not None and str(value):
            return str(value)
    return default


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    return float(value)


def _sample_count(row: dict[str, Any]) -> int | None:
    sample_indices = row.get("sample_indices")
    if isinstance(sample_indices, list) and sample_indices:
        return len(sample_indices)
    y_pred_shape = row.get("y_pred_shape")
    if isinstance(y_pred_shape, list) and y_pred_shape:
        return int(y_pred_shape[0])
    return None


def _insert_run(conn: sqlite3.Connection, preview: NativeResultsPreview) -> str:
    manifest = preview.manifest
    run_id = str(manifest["run_id"])
    datasets = _string_list(manifest.get("datasets")) or sorted(
        {str(row.get("dataset")) for row in preview.prediction_rows if row.get("dataset")}
    )
    summary = {
        "native_results_preview_version": NATIVE_RESULTS_PREVIEW_VERSION,
        "source_kind": "native-results-v1",
        "plan_id": manifest.get("plan_id"),
        "bundle_id": manifest.get("bundle_id"),
        "score_set_hash": manifest.get("score_set_hash"),
        "producer_nodes": manifest.get("producer_nodes", []),
        "final_producer_nodes": manifest.get("final_producer_nodes", []),
        "stacking_replay_present": "stacking_replay" in manifest,
    }
    conn.execute(
        """
        INSERT INTO runs (run_id, name, config, datasets, status, created_at, completed_at, summary)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            f"native-results {run_id}",
            _canonical_json({"engine": manifest.get("engine"), "schema_version": manifest.get("schema_version")}),
            _canonical_json(datasets),
            "completed",
            manifest.get("created_at"),
            manifest.get("created_at"),
            _canonical_json(summary),
        ),
    )
    return run_id


def _insert_artifacts(conn: sqlite3.Connection, preview: NativeResultsPreview) -> int:
    artifacts = preview.manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return 0

    inserted = 0
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            continue
        artifact_id = str(artifact.get("artifact_id") or _stable_id("artifact", preview.manifest["run_id"], index))
        uri = str(artifact.get("uri") or "")
        fingerprint = artifact.get("content_fingerprint")
        content_hash = (
            f"sha256:{fingerprint}"
            if isinstance(fingerprint, str) and not fingerprint.startswith("sha256:")
            else fingerprint
        )
        if not isinstance(content_hash, str) or not content_hash:
            content_hash = _stable_id("sha256", artifact_id, uri)
        conn.execute(
            """
            INSERT OR IGNORE INTO artifacts
                (artifact_id, artifact_path, content_hash, operator_class, artifact_type, format, size_bytes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                artifact_id,
                uri,
                content_hash,
                artifact.get("producer_node"),
                artifact.get("kind"),
                artifact.get("backend") or "joblib",
                artifact.get("size_bytes"),
            ),
        )
        inserted += 1
    return inserted


def lower_native_results_preview(conn: sqlite3.Connection, preview: NativeResultsPreview) -> dict[str, int]:
    """Insert native-results-v1 metadata rows into an initialized workspace-v2 store."""

    run_id = _insert_run(conn, preview)
    manifest = preview.manifest
    metric_default = _first_string(manifest.get("metric"))
    task_type_default = _first_string(manifest.get("task_type"))
    created_at = manifest.get("created_at")
    stacking_replay = manifest.get("stacking_replay")
    relation_replay_manifest = _canonical_json(stacking_replay) if isinstance(stacking_replay, dict) else None
    relation_replay_fingerprint = (
        hashlib.sha256(relation_replay_manifest.encode("utf-8")).hexdigest()
        if relation_replay_manifest is not None
        else None
    )

    pipeline_ids: set[str] = set()
    chain_ids: set[str] = set()
    prediction_count = 0
    for index, row in enumerate(preview.prediction_rows):
        dataset = _first_string(row.get("dataset"), default="unknown")
        config_name = _first_string(row.get("config_name"), row.get("variant_id"), default="native")
        variant_id = _first_string(row.get("variant_id"), config_name)
        model_name = _first_string(row.get("model_name"), default="unknown")
        metric = _first_string(row.get("metric"), metric_default, default="unknown")
        task_type = _first_string(row.get("task_type"), task_type_default, default="unknown")
        pipeline_id = _stable_id("pipeline", run_id, dataset, config_name)
        chain_id = _stable_id("chain", run_id, dataset, config_name, model_name)

        if pipeline_id not in pipeline_ids:
            conn.execute(
                """
                INSERT INTO pipelines
                    (pipeline_id, run_id, name, expanded_config, generator_choices, dataset_name,
                     status, created_at, completed_at, best_val, best_test, metric)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pipeline_id,
                    run_id,
                    config_name,
                    _canonical_json({"config_name": config_name, "variant_id": variant_id}),
                    "[]",
                    dataset,
                    "completed",
                    created_at,
                    created_at,
                    _optional_float(row.get("val_score")),
                    _optional_float(row.get("test_score")),
                    metric,
                ),
            )
            pipeline_ids.add(pipeline_id)

        if chain_id not in chain_ids:
            conn.execute(
                """
                INSERT INTO chains
                    (chain_id, pipeline_id, steps, model_step_idx, model_class, preprocessings,
                     model_name, metric, task_type, dataset_name, relation_replay_manifest,
                     relation_replay_version, relation_replay_fingerprint)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chain_id,
                    pipeline_id,
                    "[]",
                    0,
                    model_name,
                    "",
                    model_name,
                    metric,
                    task_type,
                    dataset,
                    relation_replay_manifest,
                    NATIVE_RESULTS_PREVIEW_VERSION if relation_replay_manifest is not None else None,
                    relation_replay_fingerprint,
                ),
            )
            chain_ids.add(chain_id)

        scores = row.get("scores")
        if not isinstance(scores, str):
            scores = _canonical_json(scores or {})
        conn.execute(
            """
            INSERT INTO predictions
                (prediction_id, pipeline_id, chain_id, dataset_name, model_name, model_class,
                 fold_id, partition, val_score, test_score, train_score, metric, task_type,
                 n_samples, scores, branch_name, refit_context, prediction_scope, prediction_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _stable_id(
                    "prediction",
                    run_id,
                    index,
                    dataset,
                    config_name,
                    model_name,
                    row.get("partition"),
                    row.get("fold_id"),
                    row.get("refit_context"),
                ),
                pipeline_id,
                chain_id,
                dataset,
                model_name,
                model_name,
                _first_string(row.get("fold_id")),
                _first_string(row.get("partition"), default="unknown"),
                _optional_float(row.get("val_score")),
                _optional_float(row.get("test_score")),
                _optional_float(row.get("train_score")),
                metric,
                task_type,
                _sample_count(row),
                scores,
                variant_id,
                _first_string(row.get("refit_context")) or None,
                "native-results-v1",
                "prediction-row",
            ),
        )
        prediction_count += 1

    artifact_count = _insert_artifacts(conn, preview)
    return {
        "runs": 1,
        "pipelines": len(pipeline_ids),
        "chains": len(chain_ids),
        "predictions": prediction_count,
        "artifacts": artifact_count,
    }


__all__ = [
    "NATIVE_RESULTS_PREVIEW_VERSION",
    "NativeResultsPreview",
    "load_native_results_preview",
    "lower_native_results_preview",
]

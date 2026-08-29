"""Strict read-only lowering preview for the historical DuckDB workspace.

This module deliberately supports one closed source profile only: the six
tables emitted by the historical ``store.duckdb`` test producer, containing a
validated graph of runs, pipelines, chains, and flat prediction arrays.  It
never imports the runtime and opens DuckDB only in read-only mode.  Older or
broader workspaces remain opaque rather than being partially copied.
"""

from __future__ import annotations

import json
import math
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime
from numbers import Integral, Real
from pathlib import Path
from typing import Any, Final

from . import vocab
from .errors import UnsupportedInput

_SOURCE_TABLES: Final = (
    "runs",
    "pipelines",
    "chains",
    "predictions",
    "prediction_arrays",
    "logs",
)

_SOURCE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "runs": (
        "run_id",
        "name",
        "config",
        "datasets",
        "status",
        "created_at",
        "completed_at",
        "summary",
        "error",
    ),
    "pipelines": (
        "pipeline_id",
        "run_id",
        "name",
        "expanded_config",
        "generator_choices",
        "dataset_name",
        "dataset_hash",
        "status",
        "created_at",
        "completed_at",
        "best_val",
        "best_test",
        "metric",
        "duration_ms",
        "error",
    ),
    "chains": (
        "chain_id",
        "pipeline_id",
        "steps",
        "model_step_idx",
        "model_class",
        "preprocessings",
        "fold_strategy",
        "fold_artifacts",
        "shared_artifacts",
        "branch_path",
        "source_index",
        "created_at",
    ),
    "predictions": (
        "prediction_id",
        "pipeline_id",
        "chain_id",
        "dataset_name",
        "model_name",
        "model_class",
        "fold_id",
        "partition",
        "val_score",
        "test_score",
        "train_score",
        "metric",
        "task_type",
        "n_samples",
        "n_features",
        "scores",
        "best_params",
        "preprocessings",
        "branch_id",
        "branch_name",
        "exclusion_count",
        "exclusion_rate",
        "refit_context",
        "created_at",
    ),
    "prediction_arrays": (
        "prediction_id",
        "y_true",
        "y_pred",
        "y_proba",
        "sample_indices",
        "weights",
    ),
    "logs": (
        "log_id",
        "pipeline_id",
        "step_idx",
        "operator_class",
        "event",
        "duration_ms",
        "message",
        "details",
        "level",
        "created_at",
    ),
}

# This is deliberately a type profile rather than a coercion table.  Accepting
# similarly named VARCHAR columns would let malformed JSON or nested arrays
# enter the target workspace even when every identifier happens to be valid.
_SOURCE_COLUMN_TYPES: Final[dict[str, dict[str, str]]] = {
    "runs": {
        "run_id": "VARCHAR",
        "name": "VARCHAR",
        "config": "JSON",
        "datasets": "JSON",
        "status": "VARCHAR",
        "created_at": "TIMESTAMP",
        "completed_at": "TIMESTAMP",
        "summary": "JSON",
        "error": "VARCHAR",
    },
    "pipelines": {
        "pipeline_id": "VARCHAR",
        "run_id": "VARCHAR",
        "name": "VARCHAR",
        "expanded_config": "JSON",
        "generator_choices": "JSON",
        "dataset_name": "VARCHAR",
        "dataset_hash": "VARCHAR",
        "status": "VARCHAR",
        "created_at": "TIMESTAMP",
        "completed_at": "TIMESTAMP",
        "best_val": "DOUBLE",
        "best_test": "DOUBLE",
        "metric": "VARCHAR",
        "duration_ms": "INTEGER",
        "error": "VARCHAR",
    },
    "chains": {
        "chain_id": "VARCHAR",
        "pipeline_id": "VARCHAR",
        "steps": "JSON",
        "model_step_idx": "INTEGER",
        "model_class": "VARCHAR",
        "preprocessings": "VARCHAR",
        "fold_strategy": "VARCHAR",
        "fold_artifacts": "JSON",
        "shared_artifacts": "JSON",
        "branch_path": "JSON",
        "source_index": "INTEGER",
        "created_at": "TIMESTAMP",
    },
    "predictions": {
        "prediction_id": "VARCHAR",
        "pipeline_id": "VARCHAR",
        "chain_id": "VARCHAR",
        "dataset_name": "VARCHAR",
        "model_name": "VARCHAR",
        "model_class": "VARCHAR",
        "fold_id": "VARCHAR",
        "partition": "VARCHAR",
        "val_score": "DOUBLE",
        "test_score": "DOUBLE",
        "train_score": "DOUBLE",
        "metric": "VARCHAR",
        "task_type": "VARCHAR",
        "n_samples": "INTEGER",
        "n_features": "INTEGER",
        "scores": "JSON",
        "best_params": "JSON",
        "preprocessings": "VARCHAR",
        "branch_id": "INTEGER",
        "branch_name": "VARCHAR",
        "exclusion_count": "INTEGER",
        "exclusion_rate": "DOUBLE",
        "refit_context": "VARCHAR",
        "created_at": "TIMESTAMP",
    },
    "prediction_arrays": {
        "prediction_id": "VARCHAR",
        "y_true": "DOUBLE[]",
        "y_pred": "DOUBLE[]",
        "y_proba": "DOUBLE[]",
        "sample_indices": "INTEGER[]",
        "weights": "DOUBLE[]",
    },
    "logs": {
        "log_id": "VARCHAR",
        "pipeline_id": "VARCHAR",
        "step_idx": "INTEGER",
        "operator_class": "VARCHAR",
        "event": "VARCHAR",
        "duration_ms": "INTEGER",
        "message": "VARCHAR",
        "details": "JSON",
        "level": "VARCHAR",
        "created_at": "TIMESTAMP",
    },
}

_SOURCE_PRIMARY_KEYS: Final[dict[str, tuple[str, ...]]] = {
    table: (identifier,)
    for table, identifier in {
        "runs": "run_id",
        "pipelines": "pipeline_id",
        "chains": "chain_id",
        "predictions": "prediction_id",
        "prediction_arrays": "prediction_id",
        "logs": "log_id",
    }.items()
}

_JSON_FIELDS: Final[dict[str, tuple[str, ...]]] = {
    "runs": ("config", "datasets", "summary"),
    "pipelines": ("expanded_config", "generator_choices"),
    "chains": ("steps", "fold_artifacts", "shared_artifacts", "branch_path"),
    "predictions": ("scores", "best_params"),
    "logs": ("details",),
}

_LOWERED_TABLES: Final = ("runs", "pipelines", "chains", "predictions", "logs")
_TABLE_ID_COLUMNS: Final = {
    "runs": "run_id",
    "pipelines": "pipeline_id",
    "chains": "chain_id",
    "predictions": "prediction_id",
    "prediction_arrays": "prediction_id",
    "logs": "log_id",
}
_MITIGATION: Final = (
    "use --copy-only to preserve this source verbatim, or rerun without --strict to retain the DuckDB store opaque"
)


@dataclass(frozen=True)
class DuckDBWorkspacePreview:
    """Detached, fully validated rows for one strict historical workspace."""

    source_path: Path
    rows: dict[str, tuple[dict[str, Any], ...]]
    array_records: tuple[dict[str, Any], ...]


def _unsupported(message: str, *, cause: str = vocab.CAUSE_UNSUPPORTED_SHAPE) -> UnsupportedInput:
    return UnsupportedInput(message, cause=cause, mitigation=_MITIGATION)


def _require_duckdb() -> Any:
    try:
        import duckdb
    except ImportError as exc:
        raise _unsupported(
            "DuckDB workspace semantic lowering requires the optional duckdb dependency",
            cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
        ) from exc
    return duckdb


def _validate_closed_root(source_path: Path) -> None:
    if source_path.name != "store.duckdb" or not source_path.is_file():
        raise _unsupported("strict DuckDB workspace preview requires a store.duckdb file")
    try:
        entries = {entry.name for entry in source_path.parent.iterdir()}
    except OSError as exc:
        raise _unsupported(f"cannot inspect DuckDB workspace root: {exc}") from exc
    if entries != {"store.duckdb"}:
        extras = ", ".join(sorted(entries.difference({"store.duckdb"}))) or "unknown root entry"
        raise _unsupported(
            "strict DuckDB workspace preview requires a closed root containing only store.duckdb; "
            f"found additional entry/entries: {extras}"
        )


def _table_names(conn: Any) -> set[str]:
    schemas = conn.execute(
        "SELECT schema_name FROM information_schema.schemata "
        "WHERE schema_name NOT IN ('information_schema', 'pg_catalog') ORDER BY schema_name"
    ).fetchall()
    extra_schemas = [str(schema_name) for (schema_name,) in schemas if str(schema_name) != "main"]
    if extra_schemas:
        raise _unsupported(
            "strict DuckDB workspace preview refuses user schema(s) outside main: " + ", ".join(extra_schemas)
        )
    rows = conn.execute(
        "SELECT table_schema, table_name, table_type FROM information_schema.tables "
        "WHERE table_schema NOT IN ('information_schema', 'pg_catalog') "
        "ORDER BY table_schema, table_name"
    ).fetchall()
    non_main = [f"{schema}.{name}" for schema, name, _table_type in rows if str(schema) != "main"]
    if non_main:
        raise _unsupported(
            "strict DuckDB workspace preview refuses user-schema object(s) outside main: " + ", ".join(non_main)
        )
    invalid_types = [str(name) for _schema, name, table_type in rows if str(table_type) != "BASE TABLE"]
    if invalid_types:
        raise _unsupported("strict DuckDB workspace preview refuses non-table object(s): " + ", ".join(invalid_types))
    return {str(name) for _schema, name, _table_type in rows}


def _table_columns(conn: Any, table: str) -> tuple[tuple[str, str], ...]:
    rows = conn.execute(
        "SELECT column_name, data_type FROM information_schema.columns "
        "WHERE table_schema = 'main' AND table_name = $1 ORDER BY ordinal_position",
        [table],
    ).fetchall()
    return tuple((str(name), str(data_type).upper()) for name, data_type in rows)


def _primary_key_columns(conn: Any, table: str) -> tuple[str, ...]:
    rows = conn.execute(f"PRAGMA table_info('{table}')").fetchall()
    return tuple(str(row[1]) for row in sorted(rows, key=lambda row: int(row[5])) if int(row[5]) > 0)


def _validate_schema(conn: Any) -> None:
    tables = _table_names(conn)
    expected = set(_SOURCE_TABLES)
    if tables != expected:
        missing = sorted(expected.difference(tables))
        extra = sorted(tables.difference(expected))
        parts: list[str] = []
        if missing:
            parts.append("missing " + ", ".join(missing))
        if extra:
            parts.append("unsupported " + ", ".join(extra))
        raise _unsupported(
            "strict DuckDB workspace preview requires exactly its closed six-table profile (" + "; ".join(parts) + ")"
        )
    for table, expected_columns in _SOURCE_COLUMNS.items():
        definitions = _table_columns(conn, table)
        found = tuple(name for name, _data_type in definitions)
        if set(found) != set(expected_columns):
            missing = sorted(set(expected_columns).difference(found))
            extra = sorted(set(found).difference(expected_columns))
            parts = []
            if missing:
                parts.append("missing " + ", ".join(missing))
            if extra:
                parts.append("unsupported " + ", ".join(extra))
            raise _unsupported(
                f"strict DuckDB workspace preview table {table!r} does not match the closed profile "
                f"({' ; '.join(parts)})"
            )
        expected_types = _SOURCE_COLUMN_TYPES[table]
        actual_types = dict(definitions)
        type_mismatches = [
            f"{column}={actual_types[column]} (expected {expected_types[column]})"
            for column in expected_columns
            if actual_types[column] != expected_types[column]
        ]
        if type_mismatches:
            raise _unsupported(
                f"strict DuckDB workspace preview table {table!r} has incompatible column type(s): "
                + ", ".join(type_mismatches)
            )
        if _primary_key_columns(conn, table) != _SOURCE_PRIMARY_KEYS[table]:
            raise _unsupported(
                f"strict DuckDB workspace preview table {table!r} requires primary key "
                + ", ".join(_SOURCE_PRIMARY_KEYS[table])
            )


def _fetch_rows(conn: Any, table: str) -> tuple[dict[str, Any], ...]:
    columns = _SOURCE_COLUMNS[table]
    column_sql = ", ".join(f'"{column}"' for column in columns)
    identifier = _TABLE_ID_COLUMNS[table]
    cursor = conn.execute(f'SELECT {column_sql} FROM "{table}" ORDER BY "{identifier}"')
    return tuple(dict(zip(columns, row, strict=True)) for row in cursor.fetchall())


def _required_text(row: dict[str, Any], *, table: str, field: str) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value.strip():
        raise _unsupported(f"strict DuckDB workspace preview requires non-empty {table}.{field}")
    return value


def _required_nonnegative_int(row: dict[str, Any], *, table: str, field: str) -> int:
    value = row.get(field)
    if not isinstance(value, Integral) or isinstance(value, bool) or int(value) < 0:
        raise _unsupported(f"strict DuckDB workspace preview requires non-negative integer {table}.{field}")
    return int(value)


def _optional_nonnegative_int(row: dict[str, Any], *, table: str, field: str) -> None:
    value = row.get(field)
    if value is not None:
        _required_nonnegative_int(row, table=table, field=field)


def _optional_finite_number(row: dict[str, Any], *, table: str, field: str) -> float | None:
    value = row.get(field)
    if value is None:
        return None
    if not isinstance(value, Real) or isinstance(value, bool) or not math.isfinite(float(value)):
        raise _unsupported(f"strict DuckDB workspace preview requires finite numeric {table}.{field} when present")
    return float(value)


def _empty_jsonish(value: Any) -> bool:
    if value is None:
        return True
    candidate = value
    if isinstance(candidate, str):
        try:
            candidate = json.loads(candidate)
        except ValueError:
            return False
    return candidate in ({}, [], None)


def _reject_json_constant(constant: str) -> Any:
    raise ValueError(f"non-finite JSON constant {constant!r}")


def _require_finite_json(value: Any, *, table: str, field: str) -> None:
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _unsupported(f"strict DuckDB workspace preview requires finite JSON values in {table}.{field}")
        return
    if isinstance(value, list):
        for item in value:
            _require_finite_json(item, table=table, field=field)
        return
    if isinstance(value, dict):
        for item in value.values():
            _require_finite_json(item, table=table, field=field)


def _strict_json_loads(value: str, *, table: str, field: str) -> Any:
    try:
        decoded = json.loads(value, parse_constant=_reject_json_constant)
    except ValueError as exc:
        raise _unsupported(f"strict DuckDB workspace preview requires valid finite JSON in {table}.{field}") from exc
    _require_finite_json(decoded, table=table, field=field)
    return decoded


def _validate_json_values(rows: dict[str, tuple[dict[str, Any], ...]]) -> None:
    """Require syntactically valid JSON before forwarding source values to SQLite."""
    for table, fields in _JSON_FIELDS.items():
        for row in rows[table]:
            for field in fields:
                value = row[field]
                if value is None:
                    continue
                if isinstance(value, str):
                    _strict_json_loads(value, table=table, field=field)
                    continue
                try:
                    json.dumps(value, allow_nan=False)
                except (TypeError, ValueError) as exc:
                    raise _unsupported(
                        f"strict DuckDB workspace preview requires JSON-compatible {table}.{field}"
                    ) from exc
                _require_finite_json(value, table=table, field=field)

    for chain in rows["chains"]:
        steps = chain["steps"]
        if not isinstance(steps, str):
            raise _unsupported("strict DuckDB workspace preview requires JSON text in chains.steps")
        decoded_steps = _strict_json_loads(steps, table="chains", field="steps")
        if decoded_steps != []:
            raise _unsupported("strict DuckDB workspace preview requires chains.steps to be an empty JSON list")


def _flat_float_list(value: Any, *, field: str, prediction_id: str, required: bool) -> list[float] | None:
    if value is None:
        if required:
            raise _unsupported(f"strict DuckDB workspace preview requires {field} for prediction {prediction_id!r}")
        return None
    if not isinstance(value, list):
        raise _unsupported(
            f"strict DuckDB workspace preview requires flat list {field} for prediction {prediction_id!r}"
        )
    numbers: list[float] = []
    for item in value:
        if not isinstance(item, Real) or isinstance(item, bool) or not math.isfinite(float(item)):
            raise _unsupported(
                f"strict DuckDB workspace preview requires finite flat numeric {field} for prediction {prediction_id!r}"
            )
        numbers.append(float(item))
    if required and not numbers:
        raise _unsupported(
            f"strict DuckDB workspace preview requires non-empty {field} for prediction {prediction_id!r}"
        )
    return numbers


def _flat_index_list(value: Any, *, prediction_id: str) -> list[int]:
    if not isinstance(value, list) or not value:
        raise _unsupported(
            f"strict DuckDB workspace preview requires non-empty flat sample_indices for {prediction_id!r}"
        )
    indices: list[int] = []
    for item in value:
        if not isinstance(item, Integral) or isinstance(item, bool) or int(item) < 0:
            raise _unsupported(
                f"strict DuckDB workspace preview requires non-negative integer sample_indices for {prediction_id!r}"
            )
        indices.append(int(item))
    if len(set(indices)) != len(indices):
        raise _unsupported(f"strict DuckDB workspace preview requires unique sample_indices for {prediction_id!r}")
    return indices


def _validate_unique_ids(rows: tuple[dict[str, Any], ...], *, table: str) -> None:
    field = _TABLE_ID_COLUMNS[table]
    ids = [_required_text(row, table=table, field=field) for row in rows]
    if len(ids) != len(set(ids)):
        raise _unsupported(f"strict DuckDB workspace preview requires unique {table}.{field}")


def _validate_target_prediction_identities(rows: tuple[dict[str, Any], ...]) -> None:
    """Reject collisions in the target's logical natural prediction identity."""
    identities: set[tuple[str, str, str, str, str, int | None]] = set()
    for prediction in rows:
        branch_id = prediction["branch_id"]
        normalized_branch_id = (
            None if branch_id is None else _required_nonnegative_int(prediction, table="predictions", field="branch_id")
        )
        identity = (
            _required_text(prediction, table="predictions", field="pipeline_id"),
            _required_text(prediction, table="predictions", field="chain_id"),
            _required_text(prediction, table="predictions", field="fold_id"),
            _required_text(prediction, table="predictions", field="partition"),
            _required_text(prediction, table="predictions", field="model_name"),
            normalized_branch_id,
        )
        if identity in identities:
            raise _unsupported("strict DuckDB workspace preview found duplicate target natural prediction identity")
        identities.add(identity)


def _sqlite_value(value: Any, *, table: str, field: str) -> Any:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _unsupported(f"strict DuckDB workspace preview refuses non-finite {table}.{field}")
        return value
    if isinstance(value, (datetime, date)):
        return value.isoformat(sep=" ") if isinstance(value, datetime) else value.isoformat()
    if isinstance(value, (dict, list, tuple)):
        try:
            return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise _unsupported(f"strict DuckDB workspace preview cannot serialize {table}.{field}") from exc
    raise _unsupported(f"strict DuckDB workspace preview refuses unsupported value type for {table}.{field}")


def _normalise_rows(rows: dict[str, tuple[dict[str, Any], ...]]) -> dict[str, tuple[dict[str, Any], ...]]:
    return {
        table: tuple(
            {field: _sqlite_value(value, table=table, field=field) for field, value in row.items()}
            for row in table_rows
        )
        for table, table_rows in rows.items()
    }


def _validate_relations(rows: dict[str, tuple[dict[str, Any], ...]]) -> None:
    """Validate the complete closed run → pipeline → chain → prediction graph."""
    for table, table_rows in rows.items():
        _validate_unique_ids(table_rows, table=table)

    run_ids: set[str] = set()
    for run in rows["runs"]:
        run_ids.add(_required_text(run, table="runs", field="run_id"))
        _required_text(run, table="runs", field="name")

    pipelines_by_id: dict[str, dict[str, Any]] = {}
    for pipeline in rows["pipelines"]:
        pipeline_id = _required_text(pipeline, table="pipelines", field="pipeline_id")
        pipelines_by_id[pipeline_id] = pipeline
        _required_text(pipeline, table="pipelines", field="name")
        _required_text(pipeline, table="pipelines", field="dataset_name")
        if _required_text(pipeline, table="pipelines", field="run_id") not in run_ids:
            raise _unsupported("strict DuckDB workspace preview found pipeline.run_id outside the source run graph")
        if not _empty_jsonish(pipeline.get("generator_choices")):
            raise _unsupported("strict DuckDB workspace preview refuses non-empty pipelines.generator_choices")
        for field in ("best_val", "best_test"):
            _optional_finite_number(pipeline, table="pipelines", field=field)
        _optional_nonnegative_int(pipeline, table="pipelines", field="duration_ms")

    chains_by_id: dict[str, dict[str, Any]] = {}
    for chain in rows["chains"]:
        chain_id = _required_text(chain, table="chains", field="chain_id")
        chains_by_id[chain_id] = chain
        if _required_text(chain, table="chains", field="pipeline_id") not in pipelines_by_id:
            raise _unsupported(
                "strict DuckDB workspace preview found chain.pipeline_id outside the source pipeline graph"
            )
        _required_text(chain, table="chains", field="steps")
        _required_text(chain, table="chains", field="model_class")
        _required_nonnegative_int(chain, table="chains", field="model_step_idx")
        for field in ("fold_artifacts", "shared_artifacts", "branch_path"):
            if not _empty_jsonish(chain.get(field)):
                raise _unsupported(f"strict DuckDB workspace preview refuses non-empty chains.{field}")
        _optional_nonnegative_int(chain, table="chains", field="source_index")

    for log in rows["logs"]:
        _required_text(log, table="logs", field="log_id")
        if _required_text(log, table="logs", field="pipeline_id") not in pipelines_by_id:
            raise _unsupported(
                "strict DuckDB workspace preview found log.pipeline_id outside the source pipeline graph"
            )
        _required_text(log, table="logs", field="event")
        _required_nonnegative_int(log, table="logs", field="step_idx")
        _optional_nonnegative_int(log, table="logs", field="duration_ms")

    for prediction in rows["predictions"]:
        _required_text(prediction, table="predictions", field="prediction_id")
        pipeline_id = _required_text(prediction, table="predictions", field="pipeline_id")
        if pipeline_id not in pipelines_by_id:
            raise _unsupported(
                "strict DuckDB workspace preview found prediction.pipeline_id outside the source pipeline graph"
            )
        chain_id = _required_text(prediction, table="predictions", field="chain_id")
        prediction_chain = chains_by_id.get(chain_id)
        if prediction_chain is None:
            raise _unsupported(
                "strict DuckDB workspace preview found prediction.chain_id outside the source chain graph"
            )
        if _required_text(prediction_chain, table="chains", field="pipeline_id") != pipeline_id:
            raise _unsupported("strict DuckDB workspace preview found prediction pipeline that does not own its chain")
        pipeline = pipelines_by_id[pipeline_id]
        if _required_text(prediction, table="predictions", field="dataset_name") != _required_text(
            pipeline, table="pipelines", field="dataset_name"
        ):
            raise _unsupported("strict DuckDB workspace preview requires predictions to use their pipeline dataset")
        for field in ("model_name", "model_class", "fold_id", "partition", "metric", "task_type"):
            _required_text(prediction, table="predictions", field=field)
        _required_nonnegative_int(prediction, table="predictions", field="n_samples")
        _required_nonnegative_int(prediction, table="predictions", field="n_features")
        for field in ("val_score", "test_score", "train_score", "exclusion_rate"):
            _optional_finite_number(prediction, table="predictions", field=field)
        for field in ("branch_id", "exclusion_count"):
            _optional_nonnegative_int(prediction, table="predictions", field=field)
    _validate_target_prediction_identities(rows["predictions"])


def _array_records(rows: dict[str, tuple[dict[str, Any], ...]]) -> tuple[dict[str, Any], ...]:
    arrays_by_id = {
        _required_text(row, table="prediction_arrays", field="prediction_id"): row for row in rows["prediction_arrays"]
    }
    prediction_ids = {_required_text(row, table="predictions", field="prediction_id") for row in rows["predictions"]}
    if set(arrays_by_id) != prediction_ids:
        missing = sorted(prediction_ids.difference(arrays_by_id))
        orphaned = sorted(set(arrays_by_id).difference(prediction_ids))
        parts: list[str] = []
        if missing:
            parts.append("missing arrays for " + ", ".join(missing))
        if orphaned:
            parts.append("orphan arrays for " + ", ".join(orphaned))
        raise _unsupported(
            "strict DuckDB workspace preview requires complete prediction_arrays foreign keys ("
            + "; ".join(parts)
            + ")"
        )

    records: list[dict[str, Any]] = []
    for prediction in rows["predictions"]:
        prediction_id = _required_text(prediction, table="predictions", field="prediction_id")
        arrays = arrays_by_id[prediction_id]
        y_true = _flat_float_list(arrays.get("y_true"), field="y_true", prediction_id=prediction_id, required=True)
        y_pred = _flat_float_list(arrays.get("y_pred"), field="y_pred", prediction_id=prediction_id, required=True)
        if y_true is None or y_pred is None:
            raise _unsupported(
                f"strict DuckDB workspace preview requires targets and predictions for {prediction_id!r}"
            )
        y_proba = _flat_float_list(arrays.get("y_proba"), field="y_proba", prediction_id=prediction_id, required=False)
        sample_indices = _flat_index_list(arrays.get("sample_indices"), prediction_id=prediction_id)
        weights = _flat_float_list(arrays.get("weights"), field="weights", prediction_id=prediction_id, required=False)
        lengths = {len(y_true), len(y_pred), len(sample_indices)}
        if y_proba is not None:
            lengths.add(len(y_proba))
        if weights is not None:
            lengths.add(len(weights))
        if len(lengths) != 1:
            raise _unsupported(
                f"strict DuckDB workspace preview found mismatched flat array lengths for prediction {prediction_id!r}"
            )
        if _required_nonnegative_int(prediction, table="predictions", field="n_samples") != len(y_true):
            raise _unsupported(
                f"strict DuckDB workspace preview requires predictions.n_samples to match arrays for {prediction_id!r}"
            )
        records.append(
            {
                "prediction_id": prediction_id,
                "dataset_name": _required_text(prediction, table="predictions", field="dataset_name"),
                "model_name": _required_text(prediction, table="predictions", field="model_name"),
                "fold_id": _required_text(prediction, table="predictions", field="fold_id"),
                "partition": _required_text(prediction, table="predictions", field="partition"),
                "metric": _required_text(prediction, table="predictions", field="metric"),
                "val_score": _optional_finite_number(prediction, table="predictions", field="val_score"),
                "task_type": _required_text(prediction, table="predictions", field="task_type"),
                "y_true": y_true,
                "y_pred": y_pred,
                "y_proba": y_proba,
                "y_proba_shape": None,
                "sample_indices": sample_indices,
                "weights": weights,
                "sample_metadata": None,
            }
        )
    return tuple(records)


def load_duckdb_workspace_preview(source_path: Path) -> DuckDBWorkspacePreview:
    """Read and validate the closed historical DuckDB workspace profile.

    All validation occurs before this function returns, so callers can safely
    create output only after obtaining the preview.
    """
    source_path = Path(source_path)
    _validate_closed_root(source_path)
    duckdb = _require_duckdb()
    try:
        conn = duckdb.connect(str(source_path), read_only=True)
    except Exception as exc:  # noqa: BLE001 - DuckDB exposes several parser/open error types.
        raise _unsupported(f"strict DuckDB workspace preview could not open store read-only: {exc}") from exc
    try:
        _validate_schema(conn)
        rows = {table: _fetch_rows(conn, table) for table in _SOURCE_TABLES}
    except UnsupportedInput:
        raise
    except Exception as exc:  # noqa: BLE001 - malformed source can surface driver-specific errors.
        raise _unsupported(f"strict DuckDB workspace preview could not read the closed profile: {exc}") from exc
    finally:
        conn.close()
    _validate_json_values(rows)
    _validate_relations(rows)
    records = _array_records(rows)
    return DuckDBWorkspacePreview(
        source_path=source_path,
        rows=_normalise_rows(rows),
        array_records=records,
    )


def lower_duckdb_workspace_preview(conn: sqlite3.Connection, preview: DuckDBWorkspacePreview) -> None:
    """Insert a validated DuckDB preview into an initialized workspace-v2 store."""
    for table in _LOWERED_TABLES:
        rows = preview.rows[table]
        if not rows:
            continue
        columns = _SOURCE_COLUMNS[table]
        column_sql = ", ".join(columns)
        placeholders = ", ".join("?" for _ in columns)
        conn.executemany(
            f"INSERT INTO {table} ({column_sql}) VALUES ({placeholders})",
            [tuple(row[column] for column in columns) for row in rows],
        )


def runtime_array_records_from_duckdb_workspace(preview: DuckDBWorkspacePreview) -> list[dict[str, Any]]:
    """Return detached runtime array-sidecar records from a strict preview."""
    return [dict(record) for record in preview.array_records]


__all__ = [
    "DuckDBWorkspacePreview",
    "load_duckdb_workspace_preview",
    "lower_duckdb_workspace_preview",
    "runtime_array_records_from_duckdb_workspace",
]

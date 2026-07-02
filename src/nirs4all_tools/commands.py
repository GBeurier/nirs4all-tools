"""Command implementations for ``legacy {inspect,migrate,verify}``.

Each function returns an :class:`ExitCode` and raises :class:`ToolError`
subclasses for refusals/failures (the CLI maps those to process exit codes).

``inspect``, ``migrate --dry-run``, the ``--copy-only`` safety hatch, focused
workspace-v2 lowering, opaque preservation, and manifest/sidecar verification
all exercise the real no-in-place machinery. Format-specific legacy readers
stay here rather than in the runtime.
"""

from __future__ import annotations

import json
import math
import re
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import contracts, vocab
from .checksums import sha256_bytes, sha256_file
from .detect import (
    KIND_DUCKDB_WORKSPACE,
    KIND_FS_RUNS_LEGACY,
    KIND_FS_RUNS_V2,
    KIND_LOOSE_PREDICTIONS,
    KIND_N4A_BUNDLE,
    KIND_N4A_PY_BUNDLE,
    KIND_NATIVE_RESULTS_V1,
    KIND_SQLITE_WORKSPACE_LEGACY_ARRAYS,
    KIND_SQLITE_WORKSPACE_V2,
    DetectedArtifact,
    DetectionResult,
    detect_sources,
)
from .errors import UnsupportedInput, VerificationFailed
from .exit_codes import ExitCode
from .legacy_runs import (
    LEGACY_RUNS_PREVIEW_VERSION,
    LegacyRunsPreview,
    load_legacy_runs_preview,
    lower_legacy_runs_preview,
    runtime_array_records_from_legacy_runs,
)
from .loose_predictions import (
    LoosePredictionsPreview,
    load_loose_predictions_preview,
    lower_loose_predictions_preview,
    runtime_array_records_from_loose_predictions,
)
from .native_results import (
    NativeResultsPreview,
    load_native_results_preview,
    lower_native_results_preview,
    runtime_array_records_from_native_results,
)
from .policy import (
    assert_disjoint,
    assert_output_available,
    assert_path_outside_source,
    read_only_sqlite_uri,
    snapshot_tree,
    source_guard,
)
from .workspace_v2 import WORKSPACE_V2_TABLES, create_workspace_v2_schema

#: Declared legacy-reader support window, recorded into every manifest.
SUPPORT_WINDOW = "nirs4all-tools 0.x — legacy readers supported for an announced number of releases (TOOL-011)"

_PAYLOAD_DIRNAME = "payload"
_PRESERVED_DIRNAME = "preserved"
_ARRAYS_DIRNAME = "arrays"
_LEGACY_ARRAYS_JSONL = f"{_PRESERVED_DIRNAME}/legacy-prediction-arrays.jsonl"
_LEGACY_ARRAY_COLUMNS = ("prediction_id", "y_true", "y_pred", "y_proba", "sample_indices", "weights")
_PREDICTION_ARRAY_METADATA_COLUMNS = (
    "dataset_name",
    "model_name",
    "fold_id",
    "partition",
    "metric",
    "val_score",
    "task_type",
)
_OPAQUE_PRESERVABLE_KINDS = frozenset(
    {
        KIND_DUCKDB_WORKSPACE,
        KIND_FS_RUNS_LEGACY,
        KIND_FS_RUNS_V2,
        KIND_LOOSE_PREDICTIONS,
        KIND_N4A_BUNDLE,
        KIND_N4A_PY_BUNDLE,
        KIND_NATIVE_RESULTS_V1,
        KIND_SQLITE_WORKSPACE_V2,
    }
)
_UNSAFE_ARRAY_FILENAME_RE = re.compile(r'[/\\:*?"<>|\s.]+')
_RUNTIME_ARRAY_RECORD_FIELDS = (
    "prediction_id",
    "dataset_name",
    "model_name",
    "fold_id",
    "partition",
    "metric",
    "val_score",
    "task_type",
    "y_true",
    "y_pred",
    "y_proba",
    "y_proba_shape",
    "sample_indices",
    "weights",
    "sample_metadata",
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _generated_contract_names() -> list[str]:
    """Return default generated contract names placed next to migrated outputs."""
    return [
        contracts.DEFAULT_MANIFEST_NAME,
        contracts.DEFAULT_REPORT_NAME,
        contracts.DEFAULT_ID_MAP_NAME,
        contracts.DEFAULT_UNSUPPORTED_REPORT_NAME,
    ]


def _write_unsupported_report(
    path: Path | None,
    *,
    manifest: dict[str, Any],
    report: dict[str, Any],
    target_path: Path,
) -> None:
    """Write the machine-readable unsupported report when a path is active."""
    if path is None:
        return
    document = contracts.build_unsupported_report(
        manifest=manifest,
        report=report,
        target_path=str(target_path),
    )
    _write_json(path, document)


def _contract_exclude_names(*paths: Path | None) -> set[str]:
    """Return contract filenames that verification should not treat as orphans."""
    return {p.name for p in paths if p is not None}


def _source_fingerprint(source: Path) -> str:
    """Return a stable content fingerprint for the source tree or bundle file."""
    snapshot = snapshot_tree(source)
    root = Path(snapshot.root)
    entries: list[dict[str, Any]] = []
    if root.is_file():
        st = root.stat()
        size, _mtime, digest = snapshot.entries.get(".", (st.st_size, st.st_mtime_ns, sha256_file(root)))
        entries.append({"kind": "file", "path": ".", "sha256": digest, "size": size})
    else:
        for rel in sorted(snapshot.entries):
            size, _mtime, digest = snapshot.entries[rel]
            if size < 0:
                entries.append({"kind": "directory" if size == -1 else "unreadable", "path": rel})
                continue
            entries.append({"kind": "file", "path": rel, "sha256": digest, "size": size})
    payload = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(payload)


def _inventory_entry(art: DetectedArtifact) -> dict[str, Any]:
    details = dict(art.details)
    discovered_manifests = details.pop("discovered_manifests", [])
    discovered_bundles = details.pop("discovered_bundles", [])
    if art.source_kind in {KIND_N4A_BUNDLE, KIND_N4A_PY_BUNDLE}:
        discovered_bundles = [art.path]
    if art.source_kind == KIND_NATIVE_RESULTS_V1:
        manifest = "manifest.json" if art.path == "." else f"{art.path}/manifest.json"
        discovered_manifests = [manifest]

    entry: dict[str, Any] = {
        "path": art.path,
        "source_kind": art.source_kind,
        "detected_version": art.detected_version,
        "tables": details.pop("tables", {}),
        "row_counts": details.pop("row_counts", {}),
        "discovered_manifests": discovered_manifests,
        "discovered_bundles": discovered_bundles,
        "preserved_opaque": art.source_kind in {KIND_N4A_BUNDLE, KIND_N4A_PY_BUNDLE} and not art.forward_version,
        "supported": art.supported,
        "forward_version": art.forward_version,
        "note": art.note,
    }
    if details:
        entry["details"] = details
    return entry


def _render_text(detection: DetectionResult, status: str) -> str:
    lines = [
        "nirs4all-tools — legacy inspect",
        f"source : {detection.root}",
        f"status : {status}",
        f"kinds  : {', '.join(detection.kinds) or '(none)'}",
        "artifacts:",
    ]
    for art in detection.artifacts:
        flags = []
        if not art.supported:
            flags.append("UNSUPPORTED")
        if art.forward_version:
            flags.append("FORWARD-VERSION")
        suffix = f"  [{' '.join(flags)}]" if flags else ""
        note = f"  — {art.note}" if art.note else ""
        lines.append(f"  - {art.path}  ({art.source_kind})  version={art.detected_version}{suffix}{note}")
    return "\n".join(lines)


def inspect(input_path: Path, *, fmt: str = "json", report_path: Path | None = None) -> ExitCode:
    """Read-only detection of a legacy source; optionally emit a report.

    Writes nothing to the source (asserted by ``source_guard``) and writes the
    inspection document only to an explicit ``--report`` path that resolves
    outside the source tree.
    """
    if report_path is not None:
        assert_path_outside_source(input_path, report_path)

    with source_guard(input_path):
        detection = detect_sources(input_path)

    status = vocab.STATUS_SUCCESS if detection.has_recognized else vocab.STATUS_UNSUPPORTED_INPUT
    document: dict[str, Any] = {
        "tool": "nirs4all-tools",
        "command": "legacy inspect",
        "source": detection.root,
        "status": status,
        "kinds": detection.kinds,
        "detected_versions": detection.detected_versions,
        "input_inventory": [_inventory_entry(a) for a in detection.artifacts],
    }

    if report_path is not None:
        _write_json(report_path, document)

    if fmt == "json":
        print(json.dumps(document, indent=2, sort_keys=True))
    else:
        print(_render_text(detection, status))

    return ExitCode.SUCCESS if detection.has_recognized else ExitCode.UNSUPPORTED_INPUT


def _resolve_contract_paths(
    *,
    output: Path,
    manifest_path: Path | None,
    report_path: Path | None,
    id_map_path: Path | None,
    unsupported_report_path: Path | None,
    dry_run: bool,
) -> tuple[Path | None, Path | None, Path | None, Path | None]:
    """Resolve where the manifest/report/id-map land.

    For a real run, unset paths default to files inside the (disjoint) output
    directory. For ``--dry-run`` only explicitly-given paths are honored (§11).
    """
    if dry_run:
        return manifest_path, report_path, id_map_path, unsupported_report_path
    manifest = manifest_path or (output / contracts.DEFAULT_MANIFEST_NAME)
    report = report_path or (output / contracts.DEFAULT_REPORT_NAME)
    id_map = id_map_path or (output / contracts.DEFAULT_ID_MAP_NAME)
    unsupported = unsupported_report_path or (output / contracts.DEFAULT_UNSUPPORTED_REPORT_NAME)
    return manifest, report, id_map, unsupported


def _copy_only(source: Path, output: Path, manifest: dict[str, Any]) -> dict[str, str]:
    """Faithfully copy the source tree into ``output/payload`` with checksums.

    No schema interpretation happens — this is the ``--copy-only`` safety hatch
    (``SW4_MIG_CONVERTER_spec.md`` §6). Returns the ``checksums`` map.
    """
    payload_root = output / _PAYLOAD_DIRNAME
    checksums: dict[str, str] = {}
    snapshot = snapshot_tree(source)
    src_real = Path(snapshot.root)
    file_count = 0
    if src_real.is_file():
        dest = payload_root / src_real.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_real, dest)
        key = f"{_PAYLOAD_DIRNAME}/{src_real.name}"
        checksums[key] = sha256_file(dest)
        file_count = 1
    else:
        for rel, (size, _mtime, _sha256) in snapshot.entries.items():
            if size < 0:  # directory marker
                continue
            src_file = src_real / rel
            dest = payload_root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, dest)
            checksums[f"{_PAYLOAD_DIRNAME}/{rel}"] = sha256_file(dest)
            file_count += 1
    manifest["checksums"] = checksums
    manifest["output_inventory"] = [
        {
            "path": _PAYLOAD_DIRNAME,
            "tables": {},
            "row_counts": {"files": file_count},
            "generated_manifests": _generated_contract_names(),
        }
    ]
    return checksums


def _sqlite_tables(conn: sqlite3.Connection) -> set[str]:
    """Return the table names visible in a SQLite connection."""
    return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _sqlite_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    """Return column names for ``table`` in declaration order."""
    return [row[1] for row in conn.execute(f"PRAGMA table_info('{table}')")]


def _sqlite_count(conn: sqlite3.Connection, table: str) -> int:
    """Return a row count for a trusted table name."""
    row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
    return int(row[0]) if row else 0


def _copy_workspace_v2_tables(source: sqlite3.Connection, target: sqlite3.Connection) -> dict[str, int]:
    """Copy compatible metadata tables from a legacy SQLite source to v2."""
    source_tables = _sqlite_tables(source)
    copied: dict[str, int] = {}
    for table in WORKSPACE_V2_TABLES:
        if table not in source_tables:
            copied[table] = 0
            continue
        source_columns = set(_sqlite_columns(source, table))
        target_columns = _sqlite_columns(target, table)
        columns = [col for col in target_columns if col in source_columns]
        if not columns:
            copied[table] = 0
            continue
        column_sql = ", ".join(columns)
        placeholders = ", ".join("?" for _ in columns)
        rows = source.execute(f"SELECT {column_sql} FROM {table}").fetchall()
        if rows:
            try:
                target.executemany(f"INSERT INTO {table} ({column_sql}) VALUES ({placeholders})", rows)
            except sqlite3.Error as exc:
                raise UnsupportedInput(
                    f"cannot lower SQLite table {table!r} into workspace-v2: {exc}",
                    cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
                    mitigation="use --copy-only to preserve this source verbatim, or update nirs4all-tools",
                ) from exc
        copied[table] = len(rows)
    return copied


def _create_empty_workspace_v2_store(output: Path) -> tuple[Path, dict[str, int]]:
    """Create an empty workspace-v2 store and return its row counts."""
    target_store = output / "store.sqlite"
    target = sqlite3.connect(target_store)
    try:
        create_workspace_v2_schema(target)
        target.commit()
        counts = _target_row_counts(target)
    finally:
        target.close()
    return target_store, counts


def _legacy_array_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Return legacy ``prediction_arrays`` rows plus prediction metadata."""
    if "prediction_arrays" not in _sqlite_tables(conn):
        return []
    available = set(_sqlite_columns(conn, "prediction_arrays"))
    columns = [col for col in _LEGACY_ARRAY_COLUMNS if col in available]
    if not columns:
        return []
    order = "prediction_id" if "prediction_id" in columns else "rowid"
    rows = conn.execute(f"SELECT {', '.join(columns)} FROM prediction_arrays ORDER BY {order}").fetchall()
    records = [dict(zip(columns, row, strict=True)) for row in rows]

    tables = _sqlite_tables(conn)
    if "predictions" not in tables or "prediction_id" not in _sqlite_columns(conn, "predictions"):
        return records
    prediction_columns = _sqlite_columns(conn, "predictions")
    metadata_columns = [col for col in _PREDICTION_ARRAY_METADATA_COLUMNS if col in prediction_columns]
    if not metadata_columns:
        return records

    metadata_sql = ", ".join(["prediction_id", *metadata_columns])
    metadata = {
        row[0]: dict(zip(metadata_columns, row[1:], strict=True))
        for row in conn.execute(f"SELECT {metadata_sql} FROM predictions")
    }
    for record in records:
        record.update(metadata.get(record.get("prediction_id"), {}))
    return records


def _write_preserved_legacy_arrays(output: Path, rows: list[dict[str, Any]]) -> dict[str, str]:
    """Write legacy array rows as deterministic JSONL and return checksums."""
    preserved_path = output / _LEGACY_ARRAYS_JSONL
    preserved_path.parent.mkdir(parents=True, exist_ok=True)
    checksums: dict[str, str] = {}
    with preserved_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            payload = json.dumps(row, sort_keys=True, separators=(",", ":"))
            handle.write(payload + "\n")
    checksums[_LEGACY_ARRAYS_JSONL] = sha256_file(preserved_path)
    return checksums


def _sanitize_array_filename(dataset_name: str) -> str:
    """Match the runtime ArrayStore dataset filename convention."""
    sanitized = _UNSAFE_ARRAY_FILENAME_RE.sub("_", dataset_name)
    return sanitized.strip("_") or "unnamed"


def _decode_json_array(value: Any, *, field: str, prediction_id: str) -> Any | None:
    """Decode one legacy JSON-serialized array cell."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
        try:
            parsed = json.loads(value)
        except ValueError as exc:
            raise UnsupportedInput(
                f"cannot decode legacy prediction_arrays.{field} for {prediction_id!r}: {exc}",
                cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
                mitigation="use --copy-only to preserve this source verbatim, or fix the malformed JSON cell",
            ) from exc
    else:
        parsed = value
    if parsed is None:
        return None
    if not isinstance(parsed, list):
        raise UnsupportedInput(
            f"legacy prediction_arrays.{field} for {prediction_id!r} is not an array",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="use --copy-only to preserve this source verbatim, or update nirs4all-tools",
        )
    return parsed


def _array_shape(value: Any) -> list[int] | None:
    if value is None:
        return None
    shape: list[int] = []
    cursor = value
    while isinstance(cursor, list):
        shape.append(len(cursor))
        cursor = cursor[0] if cursor else None
    return shape


def _flatten_array(value: Any, *, field: str, prediction_id: str, dtype: type[float] | type[int]) -> list[Any] | None:
    """Flatten a decoded legacy array and coerce each scalar to ``dtype``."""
    if value is None:
        return None
    flattened: list[Any] = []

    def visit(item: Any) -> None:
        if isinstance(item, list):
            for child in item:
                visit(child)
            return
        try:
            flattened.append(dtype(item))
        except (TypeError, ValueError) as exc:
            raise UnsupportedInput(
                f"legacy prediction_arrays.{field} for {prediction_id!r} contains a non-numeric value",
                cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
                mitigation="use --copy-only to preserve this source verbatim, or fix the malformed array cell",
            ) from exc

    visit(value)
    return flattened


def _normalise_runtime_array_record(row: dict[str, Any]) -> dict[str, Any]:
    """Convert one legacy row into the runtime array-sidecar record shape."""
    prediction_id = str(row.get("prediction_id") or "")
    if not prediction_id:
        raise UnsupportedInput(
            "legacy prediction_arrays row is missing prediction_id",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="use --copy-only to preserve this source verbatim, or repair the source table",
        )

    y_true = _decode_json_array(row.get("y_true"), field="y_true", prediction_id=prediction_id)
    y_pred = _decode_json_array(row.get("y_pred"), field="y_pred", prediction_id=prediction_id)
    y_proba = _decode_json_array(row.get("y_proba"), field="y_proba", prediction_id=prediction_id)
    sample_indices = _decode_json_array(row.get("sample_indices"), field="sample_indices", prediction_id=prediction_id)
    weights = _decode_json_array(row.get("weights"), field="weights", prediction_id=prediction_id)

    return {
        "prediction_id": prediction_id,
        "dataset_name": str(row.get("dataset_name") or "unknown"),
        "model_name": str(row.get("model_name") or ""),
        "fold_id": str(row.get("fold_id") or ""),
        "partition": str(row.get("partition") or ""),
        "metric": str(row.get("metric") or ""),
        "val_score": row.get("val_score"),
        "task_type": str(row.get("task_type") or ""),
        "y_true": _flatten_array(y_true, field="y_true", prediction_id=prediction_id, dtype=float),
        "y_pred": _flatten_array(y_pred, field="y_pred", prediction_id=prediction_id, dtype=float),
        "y_proba": _flatten_array(y_proba, field="y_proba", prediction_id=prediction_id, dtype=float),
        "y_proba_shape": _array_shape(y_proba),
        "sample_indices": _flatten_array(
            sample_indices,
            field="sample_indices",
            prediction_id=prediction_id,
            dtype=int,
        ),
        "weights": _flatten_array(weights, field="weights", prediction_id=prediction_id, dtype=float),
        "sample_metadata": None,
    }


def _pyarrow_runtime_array_schema() -> tuple[Any, Any, Any] | None:
    """Return ``(pa, pq, schema)`` when the optional Parquet dependency exists."""
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError:
        return None
    schema = pa.schema(
        [
            ("prediction_id", pa.utf8()),
            ("dataset_name", pa.utf8()),
            ("model_name", pa.utf8()),
            ("fold_id", pa.utf8()),
            ("partition", pa.utf8()),
            ("metric", pa.utf8()),
            ("val_score", pa.float64()),
            ("task_type", pa.utf8()),
            ("y_true", pa.list_(pa.float64())),
            ("y_pred", pa.list_(pa.float64())),
            ("y_proba", pa.list_(pa.float64())),
            ("y_proba_shape", pa.list_(pa.int32())),
            ("sample_indices", pa.list_(pa.int32())),
            ("weights", pa.list_(pa.float64())),
            ("sample_metadata", pa.utf8()),
        ]
    )
    return pa, pq, schema


def _runtime_array_sidecar_unavailable() -> UnsupportedInput:
    return UnsupportedInput(
        "runtime Parquet array sidecar lowering requires the optional pyarrow dependency",
        cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
        mitigation=(
            'install nirs4all-tools with the "parquet" extra, '
            "or rerun without --strict for opaque preservation"
        ),
    )


def _runtime_array_record_checksum(record: dict[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return sha256_bytes(payload.encode("utf-8"))


#: Runtime array-record fields whose numeric contents must be finite. The
#: canonical checksum (:func:`_runtime_array_record_checksum`) and the runtime
#: sidecar contract both serialize with ``allow_nan=False``, so a NaN/Infinity
#: here is unrepresentable rather than an internal error.
_RUNTIME_ARRAY_NUMERIC_FIELDS = ("val_score", "y_true", "y_pred", "y_proba", "weights")


def _nonfinite_runtime_array_field(record: dict[str, Any]) -> str | None:
    """Return the first field holding a non-finite (NaN/Infinity) number, if any."""
    for field in _RUNTIME_ARRAY_NUMERIC_FIELDS:
        value = record.get(field)
        if value is None:
            continue
        for item in value if isinstance(value, list) else (value,):
            if isinstance(item, float) and not math.isfinite(item):
                return field
    return None


def _write_runtime_array_records(
    output: Path,
    records: list[dict[str, Any]],
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Write normalized runtime array records to Parquet sidecars."""
    arrow = _pyarrow_runtime_array_schema()
    if arrow is None:
        raise _runtime_array_sidecar_unavailable()
    pa, pq, schema = arrow

    for record in records:
        missing = [field for field in _RUNTIME_ARRAY_RECORD_FIELDS if field not in record]
        if missing:
            raise UnsupportedInput(
                "runtime array sidecar record is missing field(s): " + ", ".join(missing),
                cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
                mitigation="preserve the source opaque, or update nirs4all-tools for this array shape",
            )
        nonfinite = _nonfinite_runtime_array_field(record)
        if nonfinite is not None:
            raise UnsupportedInput(
                f"runtime array sidecar record {str(record.get('prediction_id'))!r} field {nonfinite!r} "
                "contains a non-finite value (NaN/Infinity) that workspace-v2 sidecars cannot represent",
                cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
                mitigation="use --copy-only to preserve this source verbatim, or repair the non-finite array value",
            )

    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        filename = _sanitize_array_filename(str(record["dataset_name"]))
        grouped.setdefault(filename, []).append(record)

    checksums: dict[str, str] = {}
    inventory: list[dict[str, Any]] = []
    arrays_dir = output / _ARRAYS_DIRNAME
    arrays_dir.mkdir(parents=True, exist_ok=True)
    schema_names = [field.name for field in schema]
    for filename, group in sorted(grouped.items()):
        table = pa.table({name: [record[name] for record in group] for name in schema_names}, schema=schema)
        rel = f"{_ARRAYS_DIRNAME}/{filename}.parquet"
        path = output / rel
        pq.write_table(table, path, compression="zstd", compression_level=3)
        checksums[rel] = sha256_file(path)
        inventory.append(
            {
                "path": rel,
                "tables": {},
                "row_counts": {"arrays": len(group)},
                "generated_manifests": [],
            }
        )

    for record in records:
        checksums[f"arrays:{record['prediction_id']}"] = _runtime_array_record_checksum(record)
    return checksums, inventory


def _write_runtime_legacy_arrays(
    output: Path,
    rows: list[dict[str, Any]],
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Lower legacy arrays to runtime-readable Parquet sidecars."""
    records = [_normalise_runtime_array_record(row) for row in rows]
    return _write_runtime_array_records(output, records)


def _artifact_source_path(input_path: Path, art: DetectedArtifact) -> Path:
    """Resolve a detected artifact path against the source root/file."""
    if art.path == ".":
        return input_path
    return input_path / art.path


def _artifact_preserved_rel(input_path: Path, art: DetectedArtifact) -> str:
    """Stable destination under ``preserved/`` for one opaque artifact."""
    name = (input_path.name or "root") if art.path == "." else art.path
    return f"{_PRESERVED_DIRNAME}/{art.source_kind}/{name}"


def _unsupported_entry(
    art: DetectedArtifact,
    *,
    reason: str,
    disposition: str,
    cause: str | None = None,
) -> dict[str, Any]:
    """Return the durable unsupported-item record for one artifact."""
    entry: dict[str, Any] = {
        "item": art.path,
        "source_kind": art.source_kind,
        "reason": reason,
        "disposition": disposition,
    }
    if cause is not None:
        entry["cause"] = cause
    return entry


def _copy_preserved_artifact(source: Path, dest: Path, rel_prefix: str) -> dict[str, str]:
    """Copy one opaque artifact and return file-level checksums keyed by output path."""
    checksums: dict[str, str] = {}
    if source.is_file():
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, dest)
        checksums[rel_prefix] = sha256_file(dest)
        return checksums

    for src_file in sorted(path for path in source.rglob("*") if path.is_file()):
        rel = src_file.relative_to(source).as_posix()
        dst_file = dest / rel
        dst_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_file, dst_file)
        checksums[f"{rel_prefix}/{rel}"] = sha256_file(dst_file)
    return checksums


def _copy_preserved_detected_artifact(
    input_path: Path,
    output: Path,
    art: DetectedArtifact,
) -> tuple[str, dict[str, str]]:
    """Copy one detected opaque artifact, preserving only loose prediction files when possible."""
    rel = _artifact_preserved_rel(input_path, art)
    if art.source_kind == KIND_LOOSE_PREDICTIONS:
        files = art.details.get("files")
        if isinstance(files, list) and files:
            checksums: dict[str, str] = {}
            dest_root = output / rel
            for name in sorted(str(item) for item in files):
                if Path(name).is_absolute() or ".." in Path(name).parts:
                    continue
                source = input_path / name
                if not source.is_file():
                    continue
                dest = dest_root / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, dest)
                checksums[f"{rel}/{name}"] = sha256_file(dest)
            return rel, checksums

    source = _artifact_source_path(input_path, art)
    return rel, _copy_preserved_artifact(source, output / rel, rel)


def _record_preserved_artifacts(
    input_path: Path,
    output: Path,
    artifacts: list[DetectedArtifact],
    *,
    manifest: dict[str, Any],
    checksums: dict[str, str],
    output_inventory: list[dict[str, Any]],
    unsupported_reason: str,
    unsupported_cause: str | None,
) -> None:
    """Copy opaque artifacts into ``output`` and update manifest/inventory ledgers."""
    for art in artifacts:
        rel, artifact_checksums = _copy_preserved_detected_artifact(input_path, output, art)
        checksums.update(artifact_checksums)
        checksum = (
            sha256_file(output / rel)
            if (output / rel).is_file()
            else sha256_bytes(json.dumps(artifact_checksums, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        )
        manifest["preserved_opaque"].append(
            {
                "path": rel,
                "reason": art.source_kind,
                "checksum": checksum,
            }
        )
        manifest["unsupported"].append(
            _unsupported_entry(
                art,
                reason=unsupported_reason,
                disposition="preserved",
                cause=unsupported_cause,
            )
        )
        output_inventory.append(
            {
                "path": rel,
                "tables": {},
                "row_counts": {"files": len(artifact_checksums)},
                "generated_manifests": [],
            }
        )


def _preservable_opaque_artifacts(detection: DetectionResult) -> list[DetectedArtifact]:
    """Return supported opaque artifacts that can be preserved in best-effort mode."""
    return [art for art in detection.artifacts if art.source_kind in _OPAQUE_PRESERVABLE_KINDS]


def _legacy_runs_lowering_artifacts(
    detection: DetectionResult,
) -> tuple[DetectedArtifact, DetectedArtifact | None] | None:
    """Return the supported standalone legacy-runs artifact pair, if present."""
    fs_runs = [art for art in detection.artifacts if art.source_kind == KIND_FS_RUNS_LEGACY]
    if len(fs_runs) != 1:
        return None
    loose = [art for art in detection.artifacts if art.source_kind == KIND_LOOSE_PREDICTIONS]
    if len(loose) > 1:
        return None
    if any(art.source_kind not in {KIND_FS_RUNS_LEGACY, KIND_LOOSE_PREDICTIONS} for art in detection.artifacts):
        return None
    return fs_runs[0], loose[0] if loose else None


def _legacy_runs_loose_files(loose_artifact: DetectedArtifact | None) -> list[str] | None:
    if loose_artifact is None:
        return None
    files = loose_artifact.details.get("files")
    if not isinstance(files, list):
        return []
    return [str(item) for item in files]


def _legacy_runs_artifact_list(
    fs_runs_artifact: DetectedArtifact,
    loose_artifact: DetectedArtifact | None,
) -> list[DetectedArtifact]:
    return [art for art in (fs_runs_artifact, loose_artifact) if art is not None]


def _target_row_counts(conn: sqlite3.Connection) -> dict[str, int]:
    """Return row counts for every workspace-v2 table."""
    return {table: _sqlite_count(conn, table) for table in WORKSPACE_V2_TABLES}


def _dry_run_unsupported_items(input_path: Path, detection: DetectionResult) -> list[dict[str, Any]]:
    """Classify what a best-effort run would preserve opaque instead of lower."""
    unsupported: list[dict[str, Any]] = []
    native_artifacts = [art for art in detection.artifacts if art.source_kind == KIND_NATIVE_RESULTS_V1]
    standalone_native = len(native_artifacts) == 1 and len(detection.artifacts) == 1
    loose_artifacts = [art for art in detection.artifacts if art.source_kind == KIND_LOOSE_PREDICTIONS]
    standalone_loose = len(loose_artifacts) == 1 and len(detection.artifacts) == 1
    legacy_runs_artifacts = _legacy_runs_lowering_artifacts(detection)
    legacy_runs_main = legacy_runs_artifacts[0] if legacy_runs_artifacts is not None else None
    legacy_runs_loose = legacy_runs_artifacts[1] if legacy_runs_artifacts is not None else None

    for art in detection.artifacts:
        if art.source_kind == KIND_SQLITE_WORKSPACE_LEGACY_ARRAYS:
            continue
        if art is legacy_runs_main:
            try:
                load_legacy_runs_preview(
                    input_path,
                    art.path,
                    loose_files=_legacy_runs_loose_files(legacy_runs_loose),
                )
                if _pyarrow_runtime_array_schema() is None:
                    raise _runtime_array_sidecar_unavailable()
            except UnsupportedInput as exc:
                for preserved_artifact in _legacy_runs_artifact_list(art, legacy_runs_loose):
                    unsupported.append(
                        _unsupported_entry(
                            preserved_artifact,
                            reason=exc.message,
                            disposition="would_preserve",
                            cause=exc.cause,
                        )
                    )
            continue
        if art is legacy_runs_loose:
            continue
        if art.source_kind == KIND_LOOSE_PREDICTIONS and standalone_loose:
            files = art.details.get("files")
            try:
                load_loose_predictions_preview(
                    input_path,
                    [str(item) for item in files] if isinstance(files, list) else [],
                )
                if _pyarrow_runtime_array_schema() is None:
                    raise _runtime_array_sidecar_unavailable()
            except UnsupportedInput as exc:
                unsupported.append(
                    _unsupported_entry(
                        art,
                        reason=exc.message,
                        disposition="would_preserve",
                        cause=exc.cause,
                    )
                )
            continue
        if art.source_kind == KIND_NATIVE_RESULTS_V1 and standalone_native:
            try:
                load_native_results_preview(_artifact_source_path(input_path, art))
            except UnsupportedInput as exc:
                unsupported.append(
                    _unsupported_entry(
                        art,
                        reason=exc.message,
                        disposition="would_preserve",
                        cause=exc.cause,
                    )
                )
            continue
        if art.source_kind in _OPAQUE_PRESERVABLE_KINDS:
            unsupported.append(
                _unsupported_entry(
                    art,
                    reason="semantic lowering to workspace-v2 is not implemented in this tool release",
                    disposition="would_preserve",
                    cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
                )
            )
    return unsupported


def migrate(
    input_path: Path,
    *,
    output: Path,
    target: str,
    manifest_path: Path | None = None,
    report_path: Path | None = None,
    id_map_path: Path | None = None,
    unsupported_report_path: Path | None = None,
    checksums_algo: str = "sha256",
    dry_run: bool = False,
    verify: bool = False,
    strict: bool = False,
    copy_only: bool = False,
    resume: bool = False,
    trusted_load_joblib: bool = False,
    tool_version: str,
) -> ExitCode:
    """Convert a legacy source into a fresh ``--output`` (no-in-place, one-way).

    Non-lowerable recognized artifacts are preserved opaque in best-effort
    mode; strict mode requires semantic lowering and refuses before writing.
    """
    # --- Pre-flight: target + path policy (no writes yet) ------------------
    if target == vocab.TARGET_NATIVE_RESULTS_V1:
        raise UnsupportedInput(
            "Phase-2 target 'native-results-v1' is gated on LOCK-REL + dag-ml V1 schema + DML-008",
            cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
            mitigation="use --target nirs4all-workspace-v2 (Phase 1)",
        )
    if target != vocab.TARGET_WORKSPACE_V2:
        raise UnsupportedInput(
            f"unknown --target {target!r}",
            cause=vocab.CAUSE_INVALID_REQUEST,
            mitigation=f"use --target {vocab.TARGET_WORKSPACE_V2}",
        )
    if checksums_algo != "sha256":
        raise UnsupportedInput(
            f"unsupported --checksums {checksums_algo!r}",
            cause=vocab.CAUSE_INVALID_REQUEST,
            mitigation="only sha256 is supported",
        )
    if trusted_load_joblib:
        raise UnsupportedInput(
            "--trusted-load-joblib is reserved for the schema-transform engine and is not implemented in this scaffold",
            cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
            mitigation="omit --trusted-load-joblib; dry-run/copy-only never execute joblib payloads",
        )
    if strict and (dry_run or copy_only):
        raise UnsupportedInput(
            "--strict only applies to schema transforms; it has no effect with --dry-run or --copy-only",
            cause=vocab.CAUSE_INVALID_REQUEST,
            mitigation="omit --strict for dry-run/copy-only, or wait for the schema-transform engine",
        )

    assert_disjoint(input_path, output)
    manifest_path, report_path, id_map_path, unsupported_report_path = _resolve_contract_paths(
        output=output,
        manifest_path=manifest_path,
        report_path=report_path,
        id_map_path=id_map_path,
        unsupported_report_path=unsupported_report_path,
        dry_run=dry_run,
    )
    for explicit in (manifest_path, report_path, id_map_path, unsupported_report_path):
        if explicit is not None:
            assert_path_outside_source(input_path, explicit)

    # --- Detection + forward-version refusal (still no writes) -------------
    with source_guard(input_path):
        detection = detect_sources(input_path)
        source_fingerprint = _source_fingerprint(input_path)
    if not detection.has_recognized:
        raise UnsupportedInput(
            f"no known legacy artifact found at {input_path}",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="run 'nirs4all-tools legacy inspect' to see what was detected",
        )
    forward = detection.forward_version_artifacts
    if forward:
        names = ", ".join(f"{a.path}({a.detected_version})" for a in forward)
        raise UnsupportedInput(
            f"source declares a version newer than this tool supports: {names}",
            cause=vocab.CAUSE_FORWARD_VERSION,
            mitigation="upgrade nirs4all-tools to a build that supports this source version",
        )

    if not dry_run:
        assert_output_available(output, resume=resume)

    # --- Build contract skeletons -----------------------------------------
    manifest = contracts.build_manifest(
        tool_version=tool_version,
        support_window=SUPPORT_WINDOW,
        source_path=str(input_path),
        source_fingerprint=source_fingerprint,
        source_kinds=detection.kinds,
        detected_versions=detection.detected_versions,
        target_kind=target,
        target_schema_version=contracts.WORKSPACE_V2_USER_VERSION,
    )
    manifest["input_inventory"] = [_inventory_entry(a) for a in detection.artifacts]
    report = contracts.build_report(
        status=vocab.STATUS_SUCCESS,
        target_kind=target,
        target_path=str(output),
        source_kinds=detection.kinds,
    )

    # --- Execute under the whole-source-tree integrity guard --------------
    with source_guard(input_path):
        if dry_run:
            return _run_dry_run(
                input_path,
                detection,
                manifest,
                report,
                manifest_path,
                report_path,
                unsupported_report_path,
                output,
            )
        if copy_only:
            return _run_copy_only(
                input_path,
                output,
                manifest,
                report,
                manifest_path,
                report_path,
                id_map_path,
                unsupported_report_path,
                verify_after=verify,
            )
        if any(art.source_kind == KIND_SQLITE_WORKSPACE_LEGACY_ARRAYS for art in detection.artifacts):
            extra_opaque_artifacts = [
                art for art in _preservable_opaque_artifacts(detection)
                if art.source_kind != KIND_SQLITE_WORKSPACE_LEGACY_ARRAYS
            ]
            if strict and extra_opaque_artifacts:
                names = ", ".join(f"{art.path}({art.source_kind})" for art in extra_opaque_artifacts)
                raise UnsupportedInput(
                    f"strict migration cannot lower additional legacy artifact(s) into workspace-v2 yet: {names}",
                    cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
                    mitigation="rerun without --strict to preserve opaque artifacts with checksums, or use --copy-only",
                )
            return _run_sqlite_legacy_arrays_transform(
                input_path,
                output,
                manifest,
                report,
                manifest_path,
                report_path,
                id_map_path,
                unsupported_report_path,
                extra_opaque_artifacts=extra_opaque_artifacts,
                strict=strict,
                verify_after=verify,
            )
        native_artifacts = [art for art in detection.artifacts if art.source_kind == KIND_NATIVE_RESULTS_V1]
        if native_artifacts:
            if len(native_artifacts) == 1 and len(detection.artifacts) == 1:
                native_artifact = native_artifacts[0]
                try:
                    native_preview = load_native_results_preview(_artifact_source_path(input_path, native_artifact))
                except UnsupportedInput as exc:
                    if strict:
                        raise
                    return _run_opaque_artifact_preservation(
                        input_path,
                        output,
                        native_artifacts,
                        manifest,
                        report,
                        manifest_path,
                        report_path,
                        id_map_path,
                        unsupported_report_path,
                        strict=False,
                        verify_after=verify,
                        unsupported_reason=exc.message,
                        unsupported_cause=exc.cause,
                    )
                return _run_native_results_preview_transform(
                    input_path,
                    output,
                    native_artifact,
                    native_preview,
                    manifest,
                    report,
                    manifest_path,
                    report_path,
                    id_map_path,
                    unsupported_report_path,
                    verify_after=verify,
                )
            if strict:
                names = ", ".join(f"{art.path}({art.source_kind})" for art in native_artifacts)
                raise UnsupportedInput(
                    f"native-results-v1 lowering preview supports exactly one standalone artifact, got: {names}",
                    cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
                    mitigation="rerun without --strict to preserve mixed native artifacts opaque",
                )
        loose_artifacts = [art for art in detection.artifacts if art.source_kind == KIND_LOOSE_PREDICTIONS]
        legacy_runs_artifacts = _legacy_runs_lowering_artifacts(detection)
        if legacy_runs_artifacts is not None:
            fs_runs_artifact, loose_artifact = legacy_runs_artifacts
            try:
                legacy_runs_preview = load_legacy_runs_preview(
                    input_path,
                    fs_runs_artifact.path,
                    loose_files=_legacy_runs_loose_files(loose_artifact),
                )
            except UnsupportedInput as exc:
                if strict:
                    raise
                return _run_opaque_artifact_preservation(
                    input_path,
                    output,
                    _legacy_runs_artifact_list(fs_runs_artifact, loose_artifact),
                    manifest,
                    report,
                    manifest_path,
                    report_path,
                    id_map_path,
                    unsupported_report_path,
                    strict=False,
                    verify_after=verify,
                    unsupported_reason=exc.message,
                    unsupported_cause=exc.cause,
                )
            missing_sidecar_writer = (
                _runtime_array_sidecar_unavailable() if _pyarrow_runtime_array_schema() is None else None
            )
            if missing_sidecar_writer is not None:
                if strict:
                    raise missing_sidecar_writer
                return _run_opaque_artifact_preservation(
                    input_path,
                    output,
                    _legacy_runs_artifact_list(fs_runs_artifact, loose_artifact),
                    manifest,
                    report,
                    manifest_path,
                    report_path,
                    id_map_path,
                    unsupported_report_path,
                    strict=False,
                    verify_after=verify,
                    unsupported_reason=missing_sidecar_writer.message,
                    unsupported_cause=missing_sidecar_writer.cause,
                )
            return _run_legacy_runs_preview_transform(
                input_path,
                output,
                fs_runs_artifact,
                loose_artifact,
                legacy_runs_preview,
                manifest,
                report,
                manifest_path,
                report_path,
                id_map_path,
                unsupported_report_path,
                verify_after=verify,
            )
        if loose_artifacts:
            if len(loose_artifacts) == 1 and len(detection.artifacts) == 1:
                loose_artifact = loose_artifacts[0]
                files = loose_artifact.details.get("files")
                try:
                    loose_preview = load_loose_predictions_preview(
                        input_path,
                        [str(item) for item in files] if isinstance(files, list) else [],
                    )
                except UnsupportedInput as exc:
                    if strict:
                        raise
                    return _run_opaque_artifact_preservation(
                        input_path,
                        output,
                        loose_artifacts,
                        manifest,
                        report,
                        manifest_path,
                        report_path,
                        id_map_path,
                        unsupported_report_path,
                        strict=False,
                        verify_after=verify,
                        unsupported_reason=exc.message,
                        unsupported_cause=exc.cause,
                    )
                missing_sidecar_writer = (
                    _runtime_array_sidecar_unavailable() if _pyarrow_runtime_array_schema() is None else None
                )
                if missing_sidecar_writer is not None:
                    if strict:
                        raise missing_sidecar_writer
                    return _run_opaque_artifact_preservation(
                        input_path,
                        output,
                        loose_artifacts,
                        manifest,
                        report,
                        manifest_path,
                        report_path,
                        id_map_path,
                        unsupported_report_path,
                        strict=False,
                        verify_after=verify,
                        unsupported_reason=missing_sidecar_writer.message,
                        unsupported_cause=missing_sidecar_writer.cause,
                    )
                return _run_loose_predictions_preview_transform(
                    input_path,
                    output,
                    loose_artifact,
                    loose_preview,
                    manifest,
                    report,
                    manifest_path,
                    report_path,
                    id_map_path,
                    unsupported_report_path,
                    verify_after=verify,
                )
            if strict:
                names = ", ".join(f"{art.path}({art.source_kind})" for art in loose_artifacts)
                raise UnsupportedInput(
                    f"loose-predictions lowering preview supports exactly one standalone artifact, got: {names}",
                    cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
                    mitigation="rerun without --strict to preserve mixed loose prediction artifacts opaque",
                )
        opaque_artifacts = _preservable_opaque_artifacts(detection)
        if opaque_artifacts:
            return _run_opaque_artifact_preservation(
                input_path,
                output,
                opaque_artifacts,
                manifest,
                report,
                manifest_path,
                report_path,
                id_map_path,
                unsupported_report_path,
                strict=strict,
                verify_after=verify,
            )
        # Real schema transform — deliberately not implemented in this scaffold.
        raise UnsupportedInput(
            "schema-transform migrate to nirs4all-workspace-v2 is not available for this source shape",
            cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
            mitigation="use --dry-run to preview, --copy-only to archive, or 'legacy inspect'",
        )


def _run_dry_run(
    input_path: Path,
    detection: DetectionResult,
    manifest: dict[str, Any],
    report: dict[str, Any],
    manifest_path: Path | None,
    report_path: Path | None,
    unsupported_report_path: Path | None,
    output: Path,
) -> ExitCode:
    """Detection + simulation only; never writes the output store (§11)."""
    unsupported = _dry_run_unsupported_items(input_path, detection)
    manifest["unsupported"] = unsupported
    manifest["warnings"].append("dry-run: no output store written")
    report["status"] = vocab.STATUS_MIGRATED_WITH_WARNINGS if unsupported else vocab.STATUS_SUCCESS
    report["warnings"].append("dry-run: detection + mapping simulation only")
    report["unsupported_counts"]["preserved"] = len(unsupported)
    report["target_summary"]["path"] = str(output)
    report["recommended_next_command"] = (
        f"nirs4all-tools legacy migrate <input> --output {output} --target {vocab.TARGET_WORKSPACE_V2}"
    )
    if manifest_path is not None:
        _write_json(manifest_path, manifest)
    _write_unsupported_report(
        unsupported_report_path,
        manifest=manifest,
        report=report,
        target_path=output,
    )
    if report_path is not None:
        _write_json(report_path, report)
    preview = {
        "dry_run": True,
        "kinds": detection.kinds,
        "artifacts": len(detection.artifacts),
        "unsupported": len(unsupported),
        "would_preserve_opaque": len(unsupported),
    }
    print(json.dumps(preview, indent=2, sort_keys=True))
    return ExitCode.SUCCESS


def _run_copy_only(
    input_path: Path,
    output: Path,
    manifest: dict[str, Any],
    report: dict[str, Any],
    manifest_path: Path | None,
    report_path: Path | None,
    id_map_path: Path | None,
    unsupported_report_path: Path | None,
    *,
    verify_after: bool = False,
) -> ExitCode:
    """Faithful checksummed copy + contracts; rolls back only tool-created output."""
    created = not output.exists()
    try:
        output.mkdir(parents=True, exist_ok=True)
        _copy_only(input_path, output, manifest)
        manifest["target"]["kind"] = "copy-only"
        manifest["tool"]["completed_at"] = _now_iso()
        report["status"] = vocab.STATUS_SUCCESS
        report["target_summary"]["kind"] = "copy-only"
        report["recommended_next_command"] = f"nirs4all-tools legacy verify {output} --manifest {manifest_path}"
        if manifest_path is not None:
            _write_json(manifest_path, manifest)
        _write_unsupported_report(
            unsupported_report_path,
            manifest=manifest,
            report=report,
            target_path=output,
        )
        if verify_after:
            exclude_names = _contract_exclude_names(manifest_path, report_path, id_map_path, unsupported_report_path)
            report["verification_summary"] = _verification_summary_from_manifest(output, manifest, exclude_names)
            _raise_if_verification_failed(report["verification_summary"])
        if report_path is not None:
            _write_json(report_path, report)
        if id_map_path is not None:
            _write_json(id_map_path, manifest["old_to_new_ids"])
    except Exception:
        if created and output.exists():
            shutil.rmtree(output, ignore_errors=True)
        raise
    return ExitCode.SUCCESS


def _run_sqlite_legacy_arrays_transform(
    input_path: Path,
    output: Path,
    manifest: dict[str, Any],
    report: dict[str, Any],
    manifest_path: Path | None,
    report_path: Path | None,
    id_map_path: Path | None,
    unsupported_report_path: Path | None,
    *,
    extra_opaque_artifacts: list[DetectedArtifact] | None = None,
    strict: bool,
    verify_after: bool = False,
) -> ExitCode:
    """Lower a SQLite workspace with a legacy ``prediction_arrays`` table."""
    store_path = input_path / "store.sqlite"
    source = sqlite3.connect(read_only_sqlite_uri(store_path), uri=True)
    try:
        legacy_rows = _legacy_array_rows(source)
        created = not output.exists()
        try:
            output.mkdir(parents=True, exist_ok=True)
            target_store = output / "store.sqlite"
            target = sqlite3.connect(target_store)
            try:
                create_workspace_v2_schema(target)
                copied_counts = _copy_workspace_v2_tables(source, target)
                target.commit()
            finally:
                target.close()

            checksums = {"store.sqlite": sha256_file(target_store)}
            arrays_lowered = False
            output_inventory = [
                {
                    "path": "store.sqlite",
                    "tables": {table: {} for table in WORKSPACE_V2_TABLES},
                    "row_counts": copied_counts,
                    "generated_manifests": _generated_contract_names(),
                }
            ]
            if legacy_rows:
                try:
                    runtime_array_checksums, runtime_array_inventory = _write_runtime_legacy_arrays(output, legacy_rows)
                except UnsupportedInput:
                    if strict:
                        raise
                    manifest["unsupported"].append(
                        {
                            "item": "prediction_arrays",
                            "reason": "runtime Parquet array lowering unavailable in this environment",
                            "disposition": "preserved",
                        }
                    )
                    manifest["warnings"].append(
                        "legacy prediction_arrays preserved as opaque JSONL; "
                        "install the parquet extra for semantic lowering"
                    )
                    report["warnings"].append(
                        "legacy prediction_arrays preserved as opaque JSONL; "
                        "install the parquet extra for semantic lowering"
                    )
                    report["unsupported_counts"]["preserved"] = len(legacy_rows)
                else:
                    arrays_lowered = True
                    checksums.update(runtime_array_checksums)
                    output_inventory.extend(runtime_array_inventory)
                preserved_checksums = _write_preserved_legacy_arrays(output, legacy_rows)
                checksums.update(preserved_checksums)
                checksum = preserved_checksums[_LEGACY_ARRAYS_JSONL]
                manifest["preserved_opaque"].append(
                    {
                        "path": _LEGACY_ARRAYS_JSONL,
                        "reason": "legacy_prediction_arrays",
                        "checksum": checksum,
                    }
                )

            extra_opaque_artifacts = extra_opaque_artifacts or []
            if extra_opaque_artifacts:
                _record_preserved_artifacts(
                    input_path,
                    output,
                    extra_opaque_artifacts,
                    manifest=manifest,
                    checksums=checksums,
                    output_inventory=output_inventory,
                    unsupported_reason="artifact is outside this release's workspace-v2 semantic lowering slice",
                    unsupported_cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
                )

            manifest["checksums"] = checksums
            manifest["output_inventory"] = output_inventory
            if legacy_rows:
                manifest["output_inventory"].append(
                    {
                        "path": _LEGACY_ARRAYS_JSONL,
                        "tables": {},
                        "row_counts": {"prediction_arrays": len(legacy_rows)},
                        "generated_manifests": [],
                    }
                )
            manifest["tool"]["completed_at"] = _now_iso()

            target_for_counts = sqlite3.connect(target_store)
            try:
                target_counts = _target_row_counts(target_for_counts)
            finally:
                target_for_counts.close()
            report["source_summary"]["row_counts"] = {"prediction_arrays": len(legacy_rows)}
            report["target_summary"]["kind"] = vocab.TARGET_WORKSPACE_V2
            report["migrated_counts"].update(
                {
                    "runs": target_counts["runs"],
                    "pipelines": target_counts["pipelines"],
                    "chains": target_counts["chains"],
                    "predictions": target_counts["predictions"],
                    "artifacts": target_counts["artifacts"],
                    "arrays": len(legacy_rows) if arrays_lowered else 0,
                }
            )
            report["preserved_counts"]["unknown_columns"] = 0
            if extra_opaque_artifacts:
                report["preserved_counts"]["opaque_artifacts"] = len(extra_opaque_artifacts)
                report["unsupported_counts"]["preserved"] += len(extra_opaque_artifacts)
                manifest["warnings"].append("additional legacy workspace artifacts preserved opaque with checksums")
                report["warnings"].append("additional legacy workspace artifacts preserved opaque with checksums")
            if (legacy_rows and not arrays_lowered) or extra_opaque_artifacts:
                report["status"] = vocab.STATUS_MIGRATED_WITH_WARNINGS
            else:
                report["status"] = vocab.STATUS_SUCCESS
            report["recommended_next_command"] = f"nirs4all-tools legacy verify {output} --manifest {manifest_path}"

            if manifest_path is not None:
                _write_json(manifest_path, manifest)
            _write_unsupported_report(
                unsupported_report_path,
                manifest=manifest,
                report=report,
                target_path=output,
            )
            if verify_after:
                exclude_names = _contract_exclude_names(
                    manifest_path,
                    report_path,
                    id_map_path,
                    unsupported_report_path,
                )
                report["verification_summary"] = _verification_summary_from_manifest(output, manifest, exclude_names)
                _raise_if_verification_failed(report["verification_summary"])
            if report_path is not None:
                _write_json(report_path, report)
            if id_map_path is not None:
                _write_json(id_map_path, manifest["old_to_new_ids"])
            if (legacy_rows and not arrays_lowered) or extra_opaque_artifacts:
                return ExitCode.MIGRATED_WITH_WARNINGS
            return ExitCode.SUCCESS
        except Exception:
            if created and output.exists():
                shutil.rmtree(output, ignore_errors=True)
            raise
    finally:
        source.close()


def _run_native_results_preview_transform(
    input_path: Path,
    output: Path,
    artifact: DetectedArtifact,
    preview: NativeResultsPreview,
    manifest: dict[str, Any],
    report: dict[str, Any],
    manifest_path: Path | None,
    report_path: Path | None,
    id_map_path: Path | None,
    unsupported_report_path: Path | None,
    *,
    verify_after: bool = False,
) -> ExitCode:
    """Lower one validated native-results-v1 directory to workspace-v2 output."""
    created = not output.exists()
    try:
        output.mkdir(parents=True, exist_ok=True)
        target_store = output / "store.sqlite"
        target = sqlite3.connect(target_store)
        try:
            create_workspace_v2_schema(target)
            lower_native_results_preview(target, preview)
            target.commit()
            target_counts = _target_row_counts(target)
        finally:
            target.close()

        source = _artifact_source_path(input_path, artifact)
        rel = _artifact_preserved_rel(input_path, artifact)
        artifact_checksums = _copy_preserved_artifact(source, output / rel, rel)
        native_array_records = runtime_array_records_from_native_results(preview)
        runtime_array_checksums, runtime_array_inventory = _write_runtime_array_records(output, native_array_records)
        checksums = {"store.sqlite": sha256_file(target_store), **runtime_array_checksums, **artifact_checksums}

        manifest["checksums"] = checksums
        manifest["output_inventory"] = [
            {
                "path": "store.sqlite",
                "tables": {table: {} for table in WORKSPACE_V2_TABLES},
                "row_counts": target_counts,
                "generated_manifests": _generated_contract_names(),
            },
            *runtime_array_inventory,
            {
                "path": rel,
                "tables": {},
                "row_counts": {"files": len(artifact_checksums)},
                "generated_manifests": [],
            },
        ]
        manifest["tool"]["completed_at"] = _now_iso()

        report["status"] = vocab.STATUS_SUCCESS
        report["source_summary"]["row_counts"] = {
            "native_prediction_rows": len(preview.prediction_rows),
            "native_artifacts": len(preview.manifest.get("artifacts", []) or []),
        }
        report["target_summary"]["kind"] = vocab.TARGET_WORKSPACE_V2
        report["target_summary"]["preview"] = {
            "native_results_metadata_only": False,
            "native_results_array_sidecars": bool(native_array_records),
            "source_payload_preserved": rel,
        }
        report["migrated_counts"].update(
            {
                "runs": target_counts["runs"],
                "pipelines": target_counts["pipelines"],
                "chains": target_counts["chains"],
                "predictions": target_counts["predictions"],
                "artifacts": target_counts["artifacts"],
                "arrays": len(native_array_records),
            }
        )
        report["preserved_counts"]["native_payloads"] = 1
        report["recommended_next_command"] = f"nirs4all-tools legacy verify {output} --manifest {manifest_path}"

        if manifest_path is not None:
            _write_json(manifest_path, manifest)
        _write_unsupported_report(
            unsupported_report_path,
            manifest=manifest,
            report=report,
            target_path=output,
        )
        if verify_after:
            exclude_names = _contract_exclude_names(manifest_path, report_path, id_map_path, unsupported_report_path)
            report["verification_summary"] = _verification_summary_from_manifest(output, manifest, exclude_names)
            _raise_if_verification_failed(report["verification_summary"])
        if report_path is not None:
            _write_json(report_path, report)
        if id_map_path is not None:
            _write_json(id_map_path, manifest["old_to_new_ids"])
        return ExitCode.SUCCESS
    except Exception:
        if created and output.exists():
            shutil.rmtree(output, ignore_errors=True)
        raise


def _run_legacy_runs_preview_transform(
    input_path: Path,
    output: Path,
    fs_runs_artifact: DetectedArtifact,
    loose_artifact: DetectedArtifact | None,
    preview: LegacyRunsPreview,
    manifest: dict[str, Any],
    report: dict[str, Any],
    manifest_path: Path | None,
    report_path: Path | None,
    id_map_path: Path | None,
    unsupported_report_path: Path | None,
    *,
    verify_after: bool = False,
) -> ExitCode:
    """Lower one validated legacy runs manifest to workspace-v2 output."""
    created = not output.exists()
    try:
        output.mkdir(parents=True, exist_ok=True)
        target_store = output / "store.sqlite"
        target = sqlite3.connect(target_store)
        try:
            create_workspace_v2_schema(target)
            lower_legacy_runs_preview(target, preview)
            target.commit()
            target_counts = _target_row_counts(target)
        finally:
            target.close()

        runs_rel, runs_checksums = _copy_preserved_detected_artifact(input_path, output, fs_runs_artifact)
        artifact_checksums = dict(runs_checksums)
        payload_inventory = [
            {
                "path": runs_rel,
                "tables": {},
                "row_counts": {"files": len(runs_checksums)},
                "generated_manifests": [],
            }
        ]
        source_payloads = [runs_rel]
        if loose_artifact is not None:
            loose_rel, loose_checksums = _copy_preserved_detected_artifact(input_path, output, loose_artifact)
            artifact_checksums.update(loose_checksums)
            payload_inventory.append(
                {
                    "path": loose_rel,
                    "tables": {},
                    "row_counts": {"files": len(loose_checksums)},
                    "generated_manifests": [],
                }
            )
            source_payloads.append(loose_rel)
        else:
            rel = f"{_PRESERVED_DIRNAME}/{KIND_FS_RUNS_LEGACY}/{preview.prediction_file}"
            source = input_path / preview.prediction_file
            dest = output / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, dest)
            artifact_checksums[rel] = sha256_file(dest)
            payload_inventory.append(
                {
                    "path": rel,
                    "tables": {},
                    "row_counts": {"files": 1},
                    "generated_manifests": [],
                }
            )
            source_payloads.append(rel)

        array_records = runtime_array_records_from_legacy_runs(preview)
        runtime_array_checksums, runtime_array_inventory = _write_runtime_array_records(output, array_records)
        checksums = {"store.sqlite": sha256_file(target_store), **runtime_array_checksums, **artifact_checksums}

        manifest["checksums"] = checksums
        manifest["output_inventory"] = [
            {
                "path": "store.sqlite",
                "tables": {table: {} for table in WORKSPACE_V2_TABLES},
                "row_counts": target_counts,
                "generated_manifests": _generated_contract_names(),
            },
            *runtime_array_inventory,
            *payload_inventory,
        ]
        manifest["tool"]["completed_at"] = _now_iso()

        report["status"] = vocab.STATUS_SUCCESS
        report["source_summary"]["row_counts"] = {
            "legacy_run_manifests": 1,
            "loose_prediction_rows": 1,
        }
        report["target_summary"]["kind"] = vocab.TARGET_WORKSPACE_V2
        report["target_summary"]["preview"] = {
            "legacy_runs_preview_version": LEGACY_RUNS_PREVIEW_VERSION,
            "manifest_file": preview.manifest_file,
            "prediction_file": preview.prediction_file,
            "source_payloads_preserved": source_payloads,
        }
        report["migrated_counts"].update(
            {
                "runs": target_counts["runs"],
                "pipelines": target_counts["pipelines"],
                "chains": target_counts["chains"],
                "predictions": target_counts["predictions"],
                "artifacts": target_counts["artifacts"],
                "arrays": len(array_records),
            }
        )
        report["preserved_counts"]["legacy_run_payloads"] = 1
        report["recommended_next_command"] = f"nirs4all-tools legacy verify {output} --manifest {manifest_path}"

        if manifest_path is not None:
            _write_json(manifest_path, manifest)
        _write_unsupported_report(
            unsupported_report_path,
            manifest=manifest,
            report=report,
            target_path=output,
        )
        if verify_after:
            exclude_names = _contract_exclude_names(manifest_path, report_path, id_map_path, unsupported_report_path)
            report["verification_summary"] = _verification_summary_from_manifest(output, manifest, exclude_names)
            _raise_if_verification_failed(report["verification_summary"])
        if report_path is not None:
            _write_json(report_path, report)
        if id_map_path is not None:
            _write_json(id_map_path, manifest["old_to_new_ids"])
        return ExitCode.SUCCESS
    except Exception:
        if created and output.exists():
            shutil.rmtree(output, ignore_errors=True)
        raise


def _run_loose_predictions_preview_transform(
    input_path: Path,
    output: Path,
    artifact: DetectedArtifact,
    preview: LoosePredictionsPreview,
    manifest: dict[str, Any],
    report: dict[str, Any],
    manifest_path: Path | None,
    report_path: Path | None,
    id_map_path: Path | None,
    unsupported_report_path: Path | None,
    *,
    verify_after: bool = False,
) -> ExitCode:
    """Lower one validated standalone loose prediction payload to workspace-v2 output."""
    created = not output.exists()
    try:
        output.mkdir(parents=True, exist_ok=True)
        target_store = output / "store.sqlite"
        target = sqlite3.connect(target_store)
        try:
            create_workspace_v2_schema(target)
            lower_loose_predictions_preview(target, preview)
            target.commit()
            target_counts = _target_row_counts(target)
        finally:
            target.close()

        rel, artifact_checksums = _copy_preserved_detected_artifact(input_path, output, artifact)
        array_records = runtime_array_records_from_loose_predictions(preview)
        runtime_array_checksums, runtime_array_inventory = _write_runtime_array_records(output, array_records)
        checksums = {"store.sqlite": sha256_file(target_store), **runtime_array_checksums, **artifact_checksums}

        manifest["checksums"] = checksums
        manifest["output_inventory"] = [
            {
                "path": "store.sqlite",
                "tables": {table: {} for table in WORKSPACE_V2_TABLES},
                "row_counts": target_counts,
                "generated_manifests": _generated_contract_names(),
            },
            *runtime_array_inventory,
            {
                "path": rel,
                "tables": {},
                "row_counts": {"files": len(artifact_checksums)},
                "generated_manifests": [],
            },
        ]
        manifest["tool"]["completed_at"] = _now_iso()

        report["status"] = vocab.STATUS_SUCCESS
        report["source_summary"]["row_counts"] = {"loose_prediction_rows": 1}
        report["target_summary"]["kind"] = vocab.TARGET_WORKSPACE_V2
        report["target_summary"]["preview"] = {
            "loose_predictions_metadata_only": False,
            "loose_predictions_array_sidecars": bool(array_records),
            "source_payload_preserved": rel,
        }
        report["migrated_counts"].update(
            {
                "runs": target_counts["runs"],
                "pipelines": target_counts["pipelines"],
                "chains": target_counts["chains"],
                "predictions": target_counts["predictions"],
                "artifacts": target_counts["artifacts"],
                "arrays": len(array_records),
            }
        )
        report["preserved_counts"]["loose_prediction_payloads"] = 1
        report["recommended_next_command"] = f"nirs4all-tools legacy verify {output} --manifest {manifest_path}"

        if manifest_path is not None:
            _write_json(manifest_path, manifest)
        _write_unsupported_report(
            unsupported_report_path,
            manifest=manifest,
            report=report,
            target_path=output,
        )
        if verify_after:
            exclude_names = _contract_exclude_names(manifest_path, report_path, id_map_path, unsupported_report_path)
            report["verification_summary"] = _verification_summary_from_manifest(output, manifest, exclude_names)
            _raise_if_verification_failed(report["verification_summary"])
        if report_path is not None:
            _write_json(report_path, report)
        if id_map_path is not None:
            _write_json(id_map_path, manifest["old_to_new_ids"])
        return ExitCode.SUCCESS
    except Exception:
        if created and output.exists():
            shutil.rmtree(output, ignore_errors=True)
        raise


def _run_opaque_artifact_preservation(
    input_path: Path,
    output: Path,
    artifacts: list[DetectedArtifact],
    manifest: dict[str, Any],
    report: dict[str, Any],
    manifest_path: Path | None,
    report_path: Path | None,
    id_map_path: Path | None,
    unsupported_report_path: Path | None,
    *,
    strict: bool,
    verify_after: bool = False,
    unsupported_reason: str = "semantic lowering to workspace-v2 is not implemented in this slice",
    unsupported_cause: str | None = None,
) -> ExitCode:
    """Preserve non-lowerable artifacts without executing legacy code."""
    if strict:
        names = ", ".join(f"{art.path}({art.source_kind})" for art in artifacts)
        raise UnsupportedInput(
            f"strict migration cannot lower opaque artifact(s) into workspace-v2 yet: {names}",
            cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
            mitigation="rerun without --strict to preserve opaque artifacts with checksums, or use --copy-only",
        )

    created = not output.exists()
    try:
        output.mkdir(parents=True, exist_ok=True)
        target_store, target_counts = _create_empty_workspace_v2_store(output)
        checksums: dict[str, str] = {"store.sqlite": sha256_file(target_store)}
        output_inventory = [
            {
                "path": "store.sqlite",
                "tables": {table: {} for table in WORKSPACE_V2_TABLES},
                "row_counts": target_counts,
                "generated_manifests": _generated_contract_names(),
            }
        ]

        _record_preserved_artifacts(
            input_path,
            output,
            artifacts,
            manifest=manifest,
            checksums=checksums,
            output_inventory=output_inventory,
            unsupported_reason=unsupported_reason,
            unsupported_cause=unsupported_cause,
        )

        manifest["checksums"] = checksums
        manifest["output_inventory"] = output_inventory
        manifest["warnings"].append(
            "opaque legacy artifacts preserved with checksums; no runtime legacy reader is used"
        )
        manifest["tool"]["completed_at"] = _now_iso()

        report["status"] = vocab.STATUS_MIGRATED_WITH_WARNINGS
        report["target_summary"]["kind"] = vocab.TARGET_WORKSPACE_V2
        report["migrated_counts"].update(
            {
                "runs": target_counts["runs"],
                "pipelines": target_counts["pipelines"],
                "chains": target_counts["chains"],
                "predictions": target_counts["predictions"],
                "artifacts": target_counts["artifacts"],
                "arrays": 0,
            }
        )
        report["preserved_counts"]["opaque_artifacts"] = len(artifacts)
        report["unsupported_counts"]["preserved"] = len(artifacts)
        report["warnings"].append(
            "opaque legacy artifacts preserved; rerun a future tool release for semantic lowering"
        )
        report["recommended_next_command"] = f"nirs4all-tools legacy verify {output} --manifest {manifest_path}"

        if manifest_path is not None:
            _write_json(manifest_path, manifest)
        _write_unsupported_report(
            unsupported_report_path,
            manifest=manifest,
            report=report,
            target_path=output,
        )
        if verify_after:
            exclude_names = _contract_exclude_names(manifest_path, report_path, id_map_path, unsupported_report_path)
            report["verification_summary"] = _verification_summary_from_manifest(output, manifest, exclude_names)
            _raise_if_verification_failed(report["verification_summary"])
        if report_path is not None:
            _write_json(report_path, report)
        if id_map_path is not None:
            _write_json(id_map_path, manifest["old_to_new_ids"])
        return ExitCode.MIGRATED_WITH_WARNINGS
    except Exception:
        if created and output.exists():
            shutil.rmtree(output, ignore_errors=True)
        raise


def _iter_output_files(output_dir: Path, exclude: set[str]) -> list[str]:
    """Relative paths of every file under ``output_dir`` except ``exclude`` names."""
    files: list[str] = []
    for path in sorted(output_dir.rglob("*")):
        if path.is_file() and path.name not in exclude:
            files.append(str(path.relative_to(output_dir)))
    return files


def _sqlite_workspace_v2_verification(
    output_dir: Path, file_entries: dict[str, Any]
) -> tuple[dict[str, Any], set[str] | None]:
    """Verify the generated workspace-v2 SQLite store when one is present."""
    check: dict[str, Any] = {
        "ran": False,
        "status": "not_applicable",
        "integrity_check": None,
        "user_version": None,
        "prediction_ids": 0,
        "errors": [],
    }
    if "store.sqlite" not in file_entries:
        return check, None

    check["ran"] = True
    prediction_ids: set[str] = set()
    try:
        conn = sqlite3.connect(read_only_sqlite_uri(output_dir / "store.sqlite"), uri=True)
        try:
            integrity_row = conn.execute("PRAGMA integrity_check").fetchone()
            integrity = str(integrity_row[0]) if integrity_row else ""
            user_version_row = conn.execute("PRAGMA user_version").fetchone()
            user_version = int(user_version_row[0]) if user_version_row else None
            check["integrity_check"] = integrity
            check["user_version"] = user_version
            if integrity != "ok":
                check["errors"].append(f"PRAGMA integrity_check returned {integrity!r}")
            if user_version != contracts.WORKSPACE_V2_USER_VERSION:
                check["errors"].append(
                    f"PRAGMA user_version is {user_version!r}, expected {contracts.WORKSPACE_V2_USER_VERSION}"
                )
            if "predictions" in _sqlite_tables(conn) and "prediction_id" in _sqlite_columns(conn, "predictions"):
                prediction_ids = {str(row[0]) for row in conn.execute("SELECT prediction_id FROM predictions")}
                check["prediction_ids"] = len(prediction_ids)
        finally:
            conn.close()
    except sqlite3.Error as exc:
        check["errors"].append(f"could not verify store.sqlite: {exc}")

    check["status"] = "passed" if not check["errors"] else "failed"
    return check, prediction_ids


def _array_checksum_verification(
    output_dir: Path,
    checksums: dict[str, Any],
    file_entries: dict[str, Any],
    prediction_ids: set[str] | None,
) -> dict[str, Any]:
    """Verify every runtime array row checksum recorded in the manifest."""
    expected = {key.removeprefix("arrays:"): value for key, value in checksums.items() if key.startswith("arrays:")}
    sidecar_paths = sorted(
        rel for rel in file_entries if rel.startswith(f"{_ARRAYS_DIRNAME}/") and rel.endswith(".parquet")
    )
    check: dict[str, Any] = {
        "status": "not_applicable",
        "sidecar_files": sidecar_paths,
        "expected_rows": len(expected),
        "sidecar_rows": 0,
        "missing_rows": [],
        "missing_checksums": [],
        "mismatched_rows": [],
        "duplicate_rows": [],
        "metadata_missing_prediction_ids": [],
        "errors": [],
        "failure_count": 0,
    }
    if not expected and not sidecar_paths:
        return check

    arrow = _pyarrow_runtime_array_schema()
    if arrow is None:
        check["status"] = "failed"
        check["errors"].append("pyarrow is required to verify runtime array sidecars")
        check["failure_count"] = 1
        return check
    _pa, pq, _schema = arrow

    records: dict[str, dict[str, Any]] = {}
    for rel in sidecar_paths:
        path = output_dir / rel
        if not path.is_file():
            continue
        try:
            table = pq.read_table(path)
        except Exception as exc:  # noqa: BLE001 - pyarrow raises several concrete parse errors.
            check["errors"].append(f"could not read {rel}: {exc}")
            continue
        for row in table.to_pylist():
            if not isinstance(row, dict):
                check["errors"].append(f"{rel} contains a non-object row")
                continue
            prediction_id = row.get("prediction_id")
            if not isinstance(prediction_id, str) or not prediction_id:
                check["errors"].append(f"{rel} contains a row without prediction_id")
                continue
            if prediction_id in records:
                check["duplicate_rows"].append(prediction_id)
                continue
            records[prediction_id] = {field: row.get(field) for field in _RUNTIME_ARRAY_RECORD_FIELDS}

    actual_ids = set(records)
    expected_ids = set(expected)
    check["sidecar_rows"] = len(records)
    check["missing_rows"] = sorted(expected_ids - actual_ids)
    check["missing_checksums"] = sorted(actual_ids - expected_ids)
    check["mismatched_rows"] = sorted(
        prediction_id
        for prediction_id in expected_ids & actual_ids
        if _runtime_array_record_checksum(records[prediction_id]) != expected[prediction_id]
    )
    if prediction_ids is not None:
        check["metadata_missing_prediction_ids"] = sorted(actual_ids - prediction_ids)

    check["failure_count"] = (
        len(check["missing_rows"])
        + len(check["missing_checksums"])
        + len(check["mismatched_rows"])
        + len(check["duplicate_rows"])
        + len(check["metadata_missing_prediction_ids"])
        + len(check["errors"])
    )
    check["status"] = "passed" if check["failure_count"] == 0 else "failed"
    return check


def _preserved_payload_verification(
    manifest: dict[str, Any],
    file_entries: dict[str, Any],
) -> dict[str, Any]:
    """Verify preserved opaque payload ledger entries against file checksums."""
    raw_preserved = manifest.get("preserved_opaque", [])
    unsupported = manifest.get("unsupported", [])
    unsupported_preserved = (
        sum(
            1
            for item in unsupported
            if isinstance(item, dict) and item.get("disposition") == "preserved"
        )
        if isinstance(unsupported, list)
        else 0
    )
    output_inventory = manifest.get("output_inventory", [])
    preserved_inventory_paths = (
        sorted(
            item["path"]
            for item in output_inventory
            if isinstance(item, dict)
            and isinstance(item.get("path"), str)
            and item["path"].startswith(f"{_PRESERVED_DIRNAME}/")
        )
        if isinstance(output_inventory, list)
        else []
    )
    preserved_file_entries = sorted(rel for rel in file_entries if rel.startswith(f"{_PRESERVED_DIRNAME}/"))
    check: dict[str, Any] = {
        "status": "not_applicable",
        "payloads": len(raw_preserved) if isinstance(raw_preserved, list) else 0,
        "unsupported_preserved": unsupported_preserved,
        "preserved_file_entries": len(preserved_file_entries),
        "preserved_inventory_paths": preserved_inventory_paths,
        "missing_opaque_payloads": 0,
        "missing_checksums": [],
        "mismatched_payloads": [],
        "duplicate_paths": [],
        "invalid_entries": [],
        "outside_preserved": [],
        "failure_count": 0,
    }
    if not isinstance(raw_preserved, list):
        check["invalid_entries"].append("<preserved_opaque>")
        check["failure_count"] = 1
        check["status"] = "failed"
        return check
    preserved = raw_preserved
    if not preserved:
        if unsupported_preserved:
            check["missing_opaque_payloads"] = unsupported_preserved
            check["failure_count"] = unsupported_preserved
            check["status"] = "failed"
        return check

    seen: set[str] = set()
    for index, item in enumerate(preserved):
        if not isinstance(item, dict):
            check["invalid_entries"].append(f"[{index}]")
            continue
        path = item.get("path")
        checksum = item.get("checksum")
        if not isinstance(path, str) or not path or not isinstance(checksum, str) or not checksum:
            check["invalid_entries"].append(f"[{index}]")
            continue
        if path in seen:
            check["duplicate_paths"].append(path)
            continue
        seen.add(path)
        path_obj = Path(path)
        if path_obj.is_absolute() or ".." in path_obj.parts or not path.startswith(f"{_PRESERVED_DIRNAME}/"):
            check["outside_preserved"].append(path)
            continue
        if path in file_entries:
            if file_entries[path] != checksum:
                check["mismatched_payloads"].append(path)
            continue
        child_checksums = {
            rel: digest for rel, digest in file_entries.items() if rel.startswith(f"{path}/")
        }
        if not child_checksums:
            check["missing_checksums"].append(path)
            continue
        aggregate = sha256_bytes(json.dumps(child_checksums, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        if aggregate != checksum:
            check["mismatched_payloads"].append(path)

    check["missing_opaque_payloads"] = max(0, unsupported_preserved - len(preserved))
    check["failure_count"] = (
        check["missing_opaque_payloads"]
        + len(check["missing_checksums"])
        + len(check["mismatched_payloads"])
        + len(check["duplicate_paths"])
        + len(check["invalid_entries"])
        + len(check["outside_preserved"])
    )
    check["status"] = "passed" if check["failure_count"] == 0 else "failed"
    return check


def _verification_summary_from_manifest(
    output_dir: Path, manifest: dict[str, Any], exclude_names: set[str] | None = None
) -> dict[str, Any]:
    """Build the shared verification summary for ``migrate --verify`` and ``verify``."""
    checksums: dict[str, Any] = manifest.get("checksums", {})
    file_entries = {k: v for k, v in checksums.items() if not k.startswith("arrays:")}

    missing: list[str] = []
    mismatched: list[str] = []
    for rel, expected in file_entries.items():
        target = output_dir / rel
        if not target.is_file():
            missing.append(rel)
            continue
        if sha256_file(target) != expected:
            mismatched.append(rel)

    exclude = {
        contracts.DEFAULT_MANIFEST_NAME,
        contracts.DEFAULT_REPORT_NAME,
        contracts.DEFAULT_ID_MAP_NAME,
        contracts.DEFAULT_UNSUPPORTED_REPORT_NAME,
    }
    if exclude_names is not None:
        exclude.update(exclude_names)
    orphans = [rel for rel in _iter_output_files(output_dir, exclude) if rel not in file_entries]
    sqlite_check, prediction_ids = _sqlite_workspace_v2_verification(output_dir, file_entries)
    array_check = _array_checksum_verification(output_dir, checksums, file_entries, prediction_ids)
    preserved_check = _preserved_payload_verification(manifest, file_entries)

    checks = {
        "manifest_checksums_present": len(file_entries),
        "missing_files": missing,
        "mismatched_files": mismatched,
        "orphan_files": orphans,
        "sqlite_integrity_check": sqlite_check,
        "array_checksum_coverage": array_check,
        "preserved_payload_coverage": preserved_check,
    }
    mismatches = (
        len(missing)
        + len(mismatched)
        + len(orphans)
        + len(sqlite_check["errors"])
        + int(array_check["failure_count"])
        + int(preserved_check["failure_count"])
    )
    passed = mismatches == 0
    return {
        "ran": True,
        "passed": passed,
        "checks": checks,
        "mismatches": mismatches,
    }


def _raise_if_verification_failed(summary: dict[str, Any]) -> None:
    if summary["passed"]:
        return
    checks = summary["checks"]
    sqlite_failures = len(checks["sqlite_integrity_check"]["errors"])
    array_failures = int(checks["array_checksum_coverage"]["failure_count"])
    preserved_failures = int(checks["preserved_payload_coverage"]["failure_count"])
    raise VerificationFailed(
        "verification failed: "
        f"{len(checks['missing_files'])} missing, "
        f"{len(checks['mismatched_files'])} mismatched, "
        f"{len(checks['orphan_files'])} orphan file(s), "
        f"{sqlite_failures} sqlite failure(s), "
        f"{array_failures} array failure(s), "
        f"{preserved_failures} preserved payload failure(s)",
        cause=vocab.CAUSE_VERIFICATION_FAILED,
        mitigation="re-run the migration; the output does not match its manifest",
    )


def verify(output_dir: Path, *, manifest_path: Path, report_path: Path | None = None) -> ExitCode:
    """Verify an output against its manifest; reads no source (§6, §13).

    Implements the manifest-self-consistency checks: every file-level checksum
    entry must match a real file, and every output file must have a checksum
    entry. Workspace-v2 SQLite integrity, runtime array row checksums, and
    preserved opaque payload ledger entries are checked when present.
    """
    try:
        manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UnsupportedInput(
            f"cannot read manifest {manifest_path}: {exc}",
            cause=vocab.CAUSE_INVALID_REQUEST,
            mitigation="point --manifest at a valid migration-manifest.json",
        ) from exc

    exclude_names = {manifest_path.name}
    if report_path is not None:
        exclude_names.add(report_path.name)
    summary = _verification_summary_from_manifest(output_dir, manifest, exclude_names)

    report = contracts.build_report(
        status=vocab.STATUS_SUCCESS if summary["passed"] else vocab.STATUS_VERIFICATION_FAILED,
        target_kind=str(manifest.get("target", {}).get("kind", "")),
        target_path=str(output_dir),
        source_kinds=list(manifest.get("source", {}).get("kinds", [])),
    )
    report["verification_summary"] = summary
    if report_path is not None:
        _write_json(report_path, report)
    print(json.dumps(report["verification_summary"], indent=2, sort_keys=True))

    _raise_if_verification_failed(summary)
    return ExitCode.SUCCESS


__all__ = ["SUPPORT_WINDOW", "inspect", "migrate", "verify"]

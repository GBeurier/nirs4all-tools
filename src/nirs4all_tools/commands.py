"""Command implementations for ``legacy {inspect,migrate,verify}``.

Each function returns an :class:`ExitCode` and raises :class:`ToolError`
subclasses for refusals/failures (the CLI maps those to process exit codes).

Scaffold scope (``IMP-L18``): ``inspect``, ``migrate --dry-run``, the
``--copy-only`` safety hatch, and the manifest-self-consistency core of
``verify`` are fully wired and exercise the real no-in-place machinery. The
schema-transform engine (legacy reader → ``nirs4all-workspace-v2`` store) is
deliberately left as a clearly-marked stub — it needs the gated legacy readers
and is not part of this scaffold.
"""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import contracts, vocab
from .checksums import sha256_bytes, sha256_file
from .detect import (
    KIND_N4A_BUNDLE,
    KIND_N4A_PY_BUNDLE,
    KIND_NATIVE_RESULTS_V1,
    KIND_SQLITE_WORKSPACE_LEGACY_ARRAYS,
    DetectedArtifact,
    DetectionResult,
    detect_sources,
)
from .errors import UnsupportedInput, VerificationFailed
from .exit_codes import ExitCode
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
_OPAQUE_PRESERVABLE_KINDS = frozenset({KIND_NATIVE_RESULTS_V1, KIND_N4A_BUNDLE, KIND_N4A_PY_BUNDLE})
_UNSAFE_ARRAY_FILENAME_RE = re.compile(r'[/\\:*?"<>|\s.]+')


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _source_fingerprint(source: Path) -> str:
    """Return a stable content fingerprint for the source tree or bundle file."""
    snapshot = snapshot_tree(source)
    root = Path(snapshot.root)
    entries: list[dict[str, Any]] = []
    if root.is_file():
        size = snapshot.entries.get(".", (root.stat().st_size, 0))[0]
        entries.append({"kind": "file", "path": ".", "sha256": sha256_file(root), "size": size})
    else:
        for rel in sorted(snapshot.entries):
            size, _mtime = snapshot.entries[rel]
            if size < 0:
                entries.append({"kind": "directory" if size == -1 else "unreadable", "path": rel})
                continue
            file_path = root / rel
            entries.append({"kind": "file", "path": rel, "sha256": sha256_file(file_path), "size": size})
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
    dry_run: bool,
) -> tuple[Path | None, Path | None, Path | None]:
    """Resolve where the manifest/report/id-map land.

    For a real run, unset paths default to files inside the (disjoint) output
    directory. For ``--dry-run`` only explicitly-given paths are honored (§11).
    """
    if dry_run:
        return manifest_path, report_path, id_map_path
    manifest = manifest_path or (output / contracts.DEFAULT_MANIFEST_NAME)
    report = report_path or (output / contracts.DEFAULT_REPORT_NAME)
    id_map = id_map_path or (output / contracts.DEFAULT_ID_MAP_NAME)
    return manifest, report, id_map


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
        for rel, (size, _mtime) in snapshot.entries.items():
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
            "generated_manifests": [
                contracts.DEFAULT_MANIFEST_NAME,
                contracts.DEFAULT_REPORT_NAME,
                contracts.DEFAULT_ID_MAP_NAME,
            ],
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


def _write_runtime_legacy_arrays(
    output: Path,
    rows: list[dict[str, Any]],
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Lower legacy arrays to runtime-readable Parquet sidecars."""
    arrow = _pyarrow_runtime_array_schema()
    if arrow is None:
        raise UnsupportedInput(
            "semantic lowering of legacy prediction_arrays requires the optional pyarrow dependency",
            cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
            mitigation=(
                'install nirs4all-tools with the "parquet" extra, '
                "or rerun without --strict for opaque preservation"
            ),
        )
    pa, pq, schema = arrow

    records = [_normalise_runtime_array_record(row) for row in rows]
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
        payload = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
        checksums[f"arrays:{record['prediction_id']}"] = sha256_bytes(payload.encode("utf-8"))
    return checksums, inventory


def _artifact_source_path(input_path: Path, art: DetectedArtifact) -> Path:
    """Resolve a detected artifact path against the source root/file."""
    if art.path == ".":
        return input_path
    return input_path / art.path


def _artifact_preserved_rel(input_path: Path, art: DetectedArtifact) -> str:
    """Stable destination under ``preserved/`` for one opaque artifact."""
    name = (input_path.name or "root") if art.path == "." else art.path
    return f"{_PRESERVED_DIRNAME}/{art.source_kind}/{name}"


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


def _preservable_opaque_artifacts(detection: DetectionResult) -> list[DetectedArtifact]:
    """Return supported opaque artifacts that can be preserved in best-effort mode."""
    return [art for art in detection.artifacts if art.source_kind in _OPAQUE_PRESERVABLE_KINDS]


def _target_row_counts(conn: sqlite3.Connection) -> dict[str, int]:
    """Return row counts for every workspace-v2 table."""
    return {table: _sqlite_count(conn, table) for table in WORKSPACE_V2_TABLES}


def migrate(
    input_path: Path,
    *,
    output: Path,
    target: str,
    manifest_path: Path | None = None,
    report_path: Path | None = None,
    id_map_path: Path | None = None,
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

    Only the pre-flight policy + ``--dry-run`` + ``--copy-only`` paths are
    implemented in this scaffold; the schema-transform engine is a stub.
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
    manifest_path, report_path, id_map_path = _resolve_contract_paths(
        output=output,
        manifest_path=manifest_path,
        report_path=report_path,
        id_map_path=id_map_path,
        dry_run=dry_run,
    )
    for explicit in (manifest_path, report_path, id_map_path):
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
            return _run_dry_run(detection, manifest, report, manifest_path, report_path, output)
        if copy_only:
            return _run_copy_only(
                input_path,
                output,
                manifest,
                report,
                manifest_path,
                report_path,
                id_map_path,
                verify_after=verify,
            )
        if any(art.source_kind == KIND_SQLITE_WORKSPACE_LEGACY_ARRAYS for art in detection.artifacts):
            return _run_sqlite_legacy_arrays_transform(
                input_path,
                output,
                manifest,
                report,
                manifest_path,
                report_path,
                id_map_path,
                strict=strict,
                verify_after=verify,
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
                strict=strict,
                verify_after=verify,
            )
        # Real schema transform — deliberately not implemented in this scaffold.
        raise UnsupportedInput(
            "schema-transform migrate to nirs4all-workspace-v2 is only implemented for sqlite-workspace-legacy-arrays",
            cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
            mitigation="use --dry-run to preview, --copy-only to archive, or 'legacy inspect'",
        )


def _run_dry_run(
    detection: DetectionResult,
    manifest: dict[str, Any],
    report: dict[str, Any],
    manifest_path: Path | None,
    report_path: Path | None,
    output: Path,
) -> ExitCode:
    """Detection + simulation only; never writes the output store (§11)."""
    manifest["warnings"].append("dry-run: no output store written")
    report["status"] = vocab.STATUS_SUCCESS
    report["warnings"].append("dry-run: detection + mapping simulation only")
    report["target_summary"]["path"] = str(output)
    report["recommended_next_command"] = (
        f"nirs4all-tools legacy migrate <input> --output {output} --target {vocab.TARGET_WORKSPACE_V2}"
    )
    if manifest_path is not None:
        _write_json(manifest_path, manifest)
    if report_path is not None:
        _write_json(report_path, report)
    preview = {"dry_run": True, "kinds": detection.kinds, "artifacts": len(detection.artifacts)}
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
        if verify_after:
            exclude_names = {p.name for p in (manifest_path, report_path, id_map_path) if p is not None}
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
    *,
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
                    "generated_manifests": [
                        contracts.DEFAULT_MANIFEST_NAME,
                        contracts.DEFAULT_REPORT_NAME,
                        contracts.DEFAULT_ID_MAP_NAME,
                    ],
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
            if legacy_rows and not arrays_lowered:
                report["status"] = vocab.STATUS_MIGRATED_WITH_WARNINGS
            else:
                report["status"] = vocab.STATUS_SUCCESS
            report["recommended_next_command"] = f"nirs4all-tools legacy verify {output} --manifest {manifest_path}"

            if manifest_path is not None:
                _write_json(manifest_path, manifest)
            if verify_after:
                exclude_names = {p.name for p in (manifest_path, report_path, id_map_path) if p is not None}
                report["verification_summary"] = _verification_summary_from_manifest(output, manifest, exclude_names)
                _raise_if_verification_failed(report["verification_summary"])
            if report_path is not None:
                _write_json(report_path, report)
            if id_map_path is not None:
                _write_json(id_map_path, manifest["old_to_new_ids"])
            if legacy_rows and not arrays_lowered:
                return ExitCode.MIGRATED_WITH_WARNINGS
            return ExitCode.SUCCESS
        except Exception:
            if created and output.exists():
                shutil.rmtree(output, ignore_errors=True)
            raise
    finally:
        source.close()


def _run_opaque_artifact_preservation(
    input_path: Path,
    output: Path,
    artifacts: list[DetectedArtifact],
    manifest: dict[str, Any],
    report: dict[str, Any],
    manifest_path: Path | None,
    report_path: Path | None,
    id_map_path: Path | None,
    *,
    strict: bool,
    verify_after: bool = False,
) -> ExitCode:
    """Preserve native results / bundle artifacts without executing legacy code."""
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
                "generated_manifests": [
                    contracts.DEFAULT_MANIFEST_NAME,
                    contracts.DEFAULT_REPORT_NAME,
                    contracts.DEFAULT_ID_MAP_NAME,
                ],
            }
        ]

        for art in artifacts:
            source = _artifact_source_path(input_path, art)
            rel = _artifact_preserved_rel(input_path, art)
            dest = output / rel
            artifact_checksums = _copy_preserved_artifact(source, dest, rel)
            checksums.update(artifact_checksums)
            checksum = sha256_file(dest) if dest.is_file() else sha256_bytes(
                json.dumps(artifact_checksums, sort_keys=True, separators=(",", ":")).encode("utf-8")
            )
            manifest["preserved_opaque"].append(
                {
                    "path": rel,
                    "reason": art.source_kind,
                    "checksum": checksum,
                }
            )
            manifest["unsupported"].append(
                {
                    "item": art.path,
                    "source_kind": art.source_kind,
                    "reason": "semantic lowering to workspace-v2 is not implemented in this slice",
                    "disposition": "preserved",
                }
            )
            output_inventory.append(
                {
                    "path": rel,
                    "tables": {},
                    "row_counts": {"files": len(artifact_checksums)},
                    "generated_manifests": [],
                }
            )

        manifest["checksums"] = checksums
        manifest["output_inventory"] = output_inventory
        manifest["warnings"].append(
            "opaque native-results/bundle artifacts preserved with checksums; no runtime legacy reader is used"
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
            "opaque native-results/bundle artifacts preserved; rerun a future tool release for semantic lowering"
        )
        report["recommended_next_command"] = f"nirs4all-tools legacy verify {output} --manifest {manifest_path}"

        if manifest_path is not None:
            _write_json(manifest_path, manifest)
        if verify_after:
            exclude_names = {p.name for p in (manifest_path, report_path, id_map_path) if p is not None}
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
    }
    if exclude_names is not None:
        exclude.update(exclude_names)
    orphans = [rel for rel in _iter_output_files(output_dir, exclude) if rel not in file_entries]

    checks = {
        "manifest_checksums_present": len(file_entries),
        "missing_files": missing,
        "mismatched_files": mismatched,
        "orphan_files": orphans,
        "sqlite_integrity_check": "skipped (scaffold)",
        "array_checksum_coverage": "skipped (scaffold)",
    }
    passed = not missing and not mismatched and not orphans
    return {
        "ran": True,
        "passed": passed,
        "checks": checks,
        "mismatches": len(missing) + len(mismatched) + len(orphans),
    }


def _raise_if_verification_failed(summary: dict[str, Any]) -> None:
    if summary["passed"]:
        return
    checks = summary["checks"]
    raise VerificationFailed(
        "verification failed: "
        f"{len(checks['missing_files'])} missing, "
        f"{len(checks['mismatched_files'])} mismatched, "
        f"{len(checks['orphan_files'])} orphan file(s)",
        cause=vocab.CAUSE_VERIFICATION_FAILED,
        mitigation="re-run the migration; the output does not match its manifest",
    )


def verify(output_dir: Path, *, manifest_path: Path, report_path: Path | None = None) -> ExitCode:
    """Verify an output against its manifest; reads no source (§6, §13).

    Implements the manifest-self-consistency checks: every file-level checksum
    entry must match a real file, and every output file must have a checksum
    entry. SQLite/array-level checks require the transform output and are
    reported as ``skipped`` in this scaffold.
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

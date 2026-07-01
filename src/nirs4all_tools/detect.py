"""Stat-first, read-only source detection (``SW4_MIG_CONVERTER_spec.md`` §4).

Detection is filesystem-stat plus read-only parse, mirroring the A8 detector. It
**never** constructs a ``WorkspaceStore`` and never opens the source writable:
SQLite is probed through an immutable read-only URI, ZIP manifests are peeked
without extraction. A workspace is a *set* of artifacts; one
:class:`DetectedArtifact` is emitted per discovered artifact.

This scaffold implements the cheap, fully-safe detectors (presence checks, the
SQLite ``user_version`` probe, and ``.n4a`` / native manifest peeks). Deep
legacy *reading* (DuckDB table walks, Parquet payloads) is intentionally left
for the gated transform engine.
"""

from __future__ import annotations

import json
import sqlite3
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from .policy import read_only_sqlite_uri

# --- source_kind constants (spec §4 table) ---------------------------------
KIND_DUCKDB_WORKSPACE: Final = "duckdb-workspace"
KIND_SQLITE_WORKSPACE_V2: Final = "sqlite-workspace-v2"
KIND_SQLITE_WORKSPACE_LEGACY_ARRAYS: Final = "sqlite-workspace-legacy-arrays"
KIND_FS_RUNS_V2: Final = "fs-runs-v2"
KIND_FS_RUNS_LEGACY: Final = "fs-runs-legacy"
KIND_LOOSE_PREDICTIONS: Final = "loose-predictions"
KIND_N4A_BUNDLE: Final = "n4a-bundle"
KIND_N4A_PY_BUNDLE: Final = "n4a-py-bundle"
KIND_NATIVE_RESULTS_V1: Final = "native-results-v1"
KIND_UNKNOWN: Final = "unknown"

# --- Versions this build supports (forward-version refusal anchors) --------
SUPPORTED_SQLITE_USER_VERSION: Final = 2
SUPPORTED_BUNDLE_FORMAT_VERSION: Final = (1, 0)
SUPPORTED_NATIVE_MANIFEST_VERSION: Final = 3

#: Note attached to artifacts that are preserved verbatim and never executed.
_OPAQUE_NOTE: Final = "preserved opaque; never executed"


@dataclass
class DetectedArtifact:
    """One discovered source artifact and its disposition."""

    path: str
    """Path relative to the detection root (``.`` for a single-file root)."""

    source_kind: str
    detected_version: Any = None
    supported: bool = True
    forward_version: bool = False
    note: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResult:
    """The aggregate result of detecting a source location."""

    root: str
    artifacts: list[DetectedArtifact] = field(default_factory=list)

    @property
    def kinds(self) -> list[str]:
        """Distinct ``source_kind`` values, in first-seen order."""
        seen: list[str] = []
        for art in self.artifacts:
            if art.source_kind not in seen:
                seen.append(art.source_kind)
        return seen

    @property
    def detected_versions(self) -> dict[str, Any]:
        """Map of ``source_kind -> detected_version`` (last wins)."""
        return {art.source_kind: art.detected_version for art in self.artifacts}

    @property
    def has_recognized(self) -> bool:
        """``True`` when at least one non-unknown artifact was found."""
        return any(art.source_kind != KIND_UNKNOWN for art in self.artifacts)

    @property
    def forward_version_artifacts(self) -> list[DetectedArtifact]:
        """Artifacts that declare a version newer than this build supports."""
        return [art for art in self.artifacts if art.forward_version]


def _unknown(note: str) -> DetectedArtifact:
    """Return the standard unrecognized-source marker."""
    return DetectedArtifact(path=".", source_kind=KIND_UNKNOWN, supported=False, note=note)


def _parse_version_tuple(value: str) -> tuple[int, ...]:
    """Parse a dotted version string into an int tuple (best effort)."""
    parts: list[int] = []
    for token in str(value).split("."):
        token = token.strip()
        if not token.isdigit():
            break
        parts.append(int(token))
    return tuple(parts)


def _probe_sqlite(path: Path) -> tuple[int | None, set[str]]:
    """Read ``user_version`` and table names through a read-only URI.

    Returns ``(None, set())`` if the file cannot be opened as SQLite — detection
    must never raise on a malformed source (system boundary).
    """
    try:
        con = sqlite3.connect(read_only_sqlite_uri(path), uri=True)
    except sqlite3.Error:
        return None, set()
    try:
        user_version_row = con.execute("PRAGMA user_version").fetchone()
        user_version = int(user_version_row[0]) if user_version_row else None
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        return user_version, tables
    except sqlite3.Error:
        return None, set()
    finally:
        con.close()


def _peek_zip_manifest(path: Path) -> dict[str, Any] | None:
    """Read ``manifest.json`` from a ``.n4a`` ZIP without extracting it."""
    try:
        with zipfile.ZipFile(path) as zf:
            if "manifest.json" not in zf.namelist():
                return None
            with zf.open("manifest.json") as handle:
                data: Any = json.load(handle)
        return data if isinstance(data, dict) else None
    except (zipfile.BadZipFile, OSError, ValueError):
        return None


def _read_json(path: Path) -> dict[str, Any] | None:
    """Read a JSON object, returning ``None`` on any failure."""
    try:
        data: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _detect_n4a_bundle(path: Path, rel: str) -> DetectedArtifact:
    """Classify a ``.n4a`` ZIP bundle and check its declared format version."""
    manifest = _peek_zip_manifest(path)
    fmt = manifest.get("bundle_format_version") if manifest else None
    forward = bool(fmt) and _parse_version_tuple(str(fmt)) > SUPPORTED_BUNDLE_FORMAT_VERSION
    return DetectedArtifact(
        path=rel,
        source_kind=KIND_N4A_BUNDLE,
        detected_version=fmt,
        supported=not forward,
        forward_version=forward,
        note="preserved opaque; never executed" if not forward else "forward bundle_format_version",
    )


def _detect_native_dir(directory: Path, rel: str) -> DetectedArtifact | None:
    """Detect a ``native-results-v1`` directory by its three required files."""
    required = ("manifest.json", "score_set.json", "predictions.parquet")
    if not all((directory / name).exists() for name in required):
        return None
    manifest = _read_json(directory / "manifest.json")
    schema_version = manifest.get("schema_version") if manifest else None
    forward = isinstance(schema_version, int) and schema_version > SUPPORTED_NATIVE_MANIFEST_VERSION
    return DetectedArtifact(
        path=rel,
        source_kind=KIND_NATIVE_RESULTS_V1,
        detected_version=schema_version,
        supported=not forward,
        forward_version=forward,
        note="forward native schema_version" if forward else None,
    )


def _detect_sqlite(path: Path, rel: str) -> DetectedArtifact:
    """Classify a ``store.sqlite`` as v2 or legacy-arrays and check the version."""
    user_version, tables = _probe_sqlite(path)
    legacy_arrays = "prediction_arrays" in tables
    kind = KIND_SQLITE_WORKSPACE_LEGACY_ARRAYS if legacy_arrays else KIND_SQLITE_WORKSPACE_V2
    forward = user_version is not None and user_version > SUPPORTED_SQLITE_USER_VERSION
    return DetectedArtifact(
        path=rel,
        source_kind=kind,
        detected_version=user_version,
        supported=not forward,
        forward_version=forward,
        note="forward user_version" if forward else None,
        details={"has_prediction_arrays": legacy_arrays, "table_count": len(tables)},
    )


def _detect_directory(root: Path, result: DetectionResult) -> None:
    """Populate ``result`` with every artifact discovered under ``root``."""
    if (root / "store.duckdb").exists():
        result.artifacts.append(
            DetectedArtifact(
                path="store.duckdb",
                source_kind=KIND_DUCKDB_WORKSPACE,
                note="requires the optional 'duckdb' extra to read",
            )
        )
    if (root / "store.sqlite").exists():
        result.artifacts.append(_detect_sqlite(root / "store.sqlite", "store.sqlite"))

    runs_dir = root / "runs"
    if runs_dir.is_dir():
        if any(runs_dir.glob("*/run_manifest.yaml")):
            result.artifacts.append(DetectedArtifact(path="runs", source_kind=KIND_FS_RUNS_V2))
        if any(runs_dir.glob("*/*/manifest.yaml")):
            result.artifacts.append(DetectedArtifact(path="runs", source_kind=KIND_FS_RUNS_LEGACY))

    loose = sorted([p.name for p in root.glob("*.meta.parquet")] + [p.name for p in root.glob("*_predictions.json")])
    if loose:
        result.artifacts.append(
            DetectedArtifact(path=".", source_kind=KIND_LOOSE_PREDICTIONS, details={"files": loose})
        )

    for bundle in sorted(root.glob("*.n4a")):
        result.artifacts.append(_detect_n4a_bundle(bundle, bundle.name))
    for py_bundle in sorted(root.glob("*.n4a.py")):
        result.artifacts.append(
            DetectedArtifact(path=py_bundle.name, source_kind=KIND_N4A_PY_BUNDLE, note=_OPAQUE_NOTE)
        )

    native = _detect_native_dir(root, ".")
    if native is not None:
        result.artifacts.append(native)
    for child in sorted(p for p in root.iterdir() if p.is_dir()):
        native_child = _detect_native_dir(child, child.name)
        if native_child is not None:
            result.artifacts.append(native_child)


def detect_sources(input_path: Path) -> DetectionResult:
    """Detect the legacy artifact(s) at ``input_path`` (read-only, stat-first).

    Args:
        input_path: A workspace directory, a ``.n4a`` / ``.n4a.py`` bundle file,
            or a native-results directory.

    Returns:
        A :class:`DetectionResult`; an unrecognized but existing source yields a
        single ``unknown`` artifact rather than an empty result.
    """
    root = Path(input_path)
    result = DetectionResult(root=str(root))
    if not root.exists():
        result.artifacts.append(_unknown("path does not exist"))
        return result

    if root.is_file():
        name = root.name
        if name.endswith(".n4a.py"):
            result.artifacts.append(DetectedArtifact(path=".", source_kind=KIND_N4A_PY_BUNDLE, note=_OPAQUE_NOTE))
        elif name.endswith(".n4a"):
            result.artifacts.append(_detect_n4a_bundle(root, "."))
        else:
            result.artifacts.append(_unknown("unrecognized file"))
        return result

    _detect_directory(root, result)
    if not result.artifacts:
        result.artifacts.append(_unknown("no known legacy artifact found"))
    return result


__all__ = [
    "KIND_DUCKDB_WORKSPACE",
    "KIND_SQLITE_WORKSPACE_V2",
    "KIND_SQLITE_WORKSPACE_LEGACY_ARRAYS",
    "KIND_FS_RUNS_V2",
    "KIND_FS_RUNS_LEGACY",
    "KIND_LOOSE_PREDICTIONS",
    "KIND_N4A_BUNDLE",
    "KIND_N4A_PY_BUNDLE",
    "KIND_NATIVE_RESULTS_V1",
    "KIND_UNKNOWN",
    "DetectedArtifact",
    "DetectionResult",
    "detect_sources",
]

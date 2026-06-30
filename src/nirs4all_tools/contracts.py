"""Frozen contract vocabulary: manifest, report, and id-map skeletons.

Three durable JSON contracts (``SW4_MIG_CONVERTER_spec.md`` §7–10):

* ``legacy_migration_manifest.v1`` — the exhaustive inventory + checksum + map
  ledger of record;
* ``legacy_migration_report.v1`` — the human/UX digest + next action;
* ``legacy_id_map.v1`` — the never-lossy old→new id map.

This module owns only the *shape* of those documents (pure data builders). It
imports nothing from the command layer and performs no I/O beyond reading
installed package versions for the ``environment`` block.
"""

from __future__ import annotations

import platform
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Any

# --- Schema identity -------------------------------------------------------
MANIFEST_SCHEMA_ID = "nirs4all-tools/contracts/legacy_migration_manifest.v1.json"
REPORT_SCHEMA_ID = "nirs4all-tools/contracts/legacy_migration_report.v1.json"
ID_MAP_SCHEMA_ID = "nirs4all-tools/contracts/legacy_id_map.v1.json"

MANIFEST_SCHEMA_VERSION = 1
REPORT_SCHEMA_VERSION = 1
ID_MAP_SCHEMA_VERSION = 1

# --- Target-schema facts (mirrored from the nirs4all runtime) --------------
WORKSPACE_V2_USER_VERSION = 2
"""Target ``store.sqlite`` ``PRAGMA user_version`` (``store_schema.py:28``)."""

FK_SAFE_TABLE_ORDER = ("projects", "runs", "pipelines", "chains", "predictions", "artifacts", "logs")
"""FK-safe copy order, lifted from ``migration.py:493`` (``_MIGRATION_TABLES``)."""

# Default contract filenames placed alongside a migrated workspace.
DEFAULT_MANIFEST_NAME = "migration-manifest.json"
DEFAULT_REPORT_NAME = "migration-report.json"
DEFAULT_ID_MAP_NAME = "migration-id-map.json"

# Entities tracked by the id-map (``SW4_MIG_CONVERTER_spec.md`` §10).
ID_MAP_ENTITIES = ("project", "run", "pipeline", "chain", "prediction", "artifact", "dataset", "bundle")


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(UTC).isoformat()


def _dist_version(name: str) -> str | None:
    """Return an installed distribution's version, or ``None`` if absent."""
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def environment_block() -> dict[str, Any]:
    """Capture the runtime environment for the manifest (read-only)."""
    return {
        "python": platform.python_version(),
        "nirs4all": _dist_version("nirs4all"),
        "duckdb": _dist_version("duckdb"),
        "pyarrow": _dist_version("pyarrow"),
    }


def empty_id_map() -> dict[str, Any]:
    """Return an empty ``legacy_id_map.v1`` document."""
    return {
        "$id": ID_MAP_SCHEMA_ID,
        "schema_version": ID_MAP_SCHEMA_VERSION,
        "entities": {entity: [] for entity in ID_MAP_ENTITIES},  # noqa: C420 - each entity needs a distinct list
    }


def build_manifest(
    *,
    tool_version: str,
    support_window: str,
    source_path: str,
    source_fingerprint: str | None,
    source_kinds: list[str],
    detected_versions: dict[str, Any],
    target_kind: str,
    target_schema_version: int | None,
) -> dict[str, Any]:
    """Return a fresh ``legacy_migration_manifest.v1`` skeleton.

    Inventory, checksum, map, and preserved-opaque sections start empty and are
    filled in by the command as it works.
    """
    now = _utc_now_iso()
    return {
        "$id": MANIFEST_SCHEMA_ID,
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "tool": {
            "name": "nirs4all-tools",
            "version": tool_version,
            "support_window": support_window,
            "created_at": now,
            "completed_at": None,
        },
        "source": {
            "path": source_path,
            "fingerprint": source_fingerprint,
            "kinds": source_kinds,
            "detected_versions": detected_versions,
        },
        "target": {"kind": target_kind, "schema_version": target_schema_version},
        "input_inventory": [],
        "output_inventory": [],
        "checksums": {},
        "old_to_new_ids": empty_id_map(),
        "preserved_opaque": [],
        "unsupported": [],
        "warnings": [],
        "environment": environment_block(),
    }


def build_report(
    *,
    status: str,
    target_kind: str,
    target_path: str | None,
    source_kinds: list[str],
) -> dict[str, Any]:
    """Return a fresh ``legacy_migration_report.v1`` skeleton."""
    return {
        "$id": REPORT_SCHEMA_ID,
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": status,
        "source_summary": {"kinds": source_kinds, "row_counts": {}, "bundles": 0, "artifacts": 0},
        "target_summary": {"kind": target_kind, "path": target_path},
        "migrated_counts": dict.fromkeys(("runs", "pipelines", "chains", "predictions", "arrays", "artifacts"), 0),
        "preserved_counts": {"n4a": 0, "joblib": 0, "unknown_columns": 0},
        "unsupported_counts": {"refused": 0, "preserved": 0},
        "verification_summary": {"ran": False, "passed": None, "checks": {}, "mismatches": 0},
        "errors": [],
        "warnings": [],
        "recommended_next_command": None,
    }


def error_entry(*, code: str, cause: str | None, message: str, mitigation: str | None = None) -> dict[str, Any]:
    """Build one ``report.errors[]`` entry (``SW4_MIG_CONVERTER_spec.md`` §8)."""
    return {"code": code, "cause": cause, "message": message, "mitigation": mitigation}


__all__ = [
    "MANIFEST_SCHEMA_ID",
    "REPORT_SCHEMA_ID",
    "ID_MAP_SCHEMA_ID",
    "MANIFEST_SCHEMA_VERSION",
    "REPORT_SCHEMA_VERSION",
    "ID_MAP_SCHEMA_VERSION",
    "WORKSPACE_V2_USER_VERSION",
    "FK_SAFE_TABLE_ORDER",
    "DEFAULT_MANIFEST_NAME",
    "DEFAULT_REPORT_NAME",
    "DEFAULT_ID_MAP_NAME",
    "ID_MAP_ENTITIES",
    "environment_block",
    "empty_id_map",
    "build_manifest",
    "build_report",
    "error_entry",
]

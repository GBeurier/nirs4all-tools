#!/usr/bin/env python3
"""Validate the V1 legacy-input support SLA against the Tools source surface."""

from __future__ import annotations

import argparse
import ast
import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MATRIX = ROOT / "docs" / "contracts" / "legacy-support-matrix.v1.json"
EXPECTED_SCHEMA = "nirs4all-tools.legacy-support-matrix/v1"
EXPECTED_SUPPORT_WINDOW = (
    "nirs4all-tools 0.x — legacy readers guaranteed through end of R4 "
    "(R3 and R4 after the R2 flip); removal only post-V1 by announced decision"
)
EXPECTED_RELEASES = {
    "flip": {"release": "R2", "version": "1.0.0-rc.1"},
    "guaranteed": [
        {"release": "R3", "version": "1.0.0-rc.2"},
        {"release": "R4", "version": "1.0.0"},
    ],
    "rollback": [
        {"release": "R1", "version": "0.13.0", "role": "rollback_from_R2"},
        {"release": "R2", "version": "1.0.0-rc.1", "role": "rollback_from_R3"},
        {"release": "R3", "version": "1.0.0-rc.2", "role": "rollback_from_R4"},
    ],
}
EXPECTED_DISPOSITIONS = {
    "duckdb-workspace": (
        True,
        "conditional_optional_duckdb",
        "semantic_exact_six_table_profile_else_opaque_or_refused",
    ),
    "sqlite-workspace-v2": (False, "qualified", "already_target_opaque_or_refused"),
    "sqlite-workspace-legacy-arrays": (True, "qualified", "semantic"),
    "fs-runs-v2": (False, "qualified_detection", "opaque_or_refused"),
    "fs-runs-legacy": (
        True,
        "qualified",
        "semantic_single_manifest_preview_else_opaque_or_refused",
    ),
    "loose-predictions": (
        True,
        "qualified",
        "semantic_complete_single_payload_else_opaque_or_refused",
    ),
    "n4a-bundle": (True, "bounded_structural_only", "opaque_only_or_refused"),
    "n4a-py-bundle": (True, "opaque_only_never_executed", "opaque_only_or_refused"),
    "native-results-v1": (
        False,
        "qualified_exact_schema_3",
        "semantic_exact_schema_3_else_opaque_or_refused",
    ),
    "unknown": (False, "detect_only", "refused"),
}
EXPECTED_SERVICE_LEVELS = {
    "read": {
        "interfaces": ["workspace inspect", "legacy inspect"],
        "commitment": "retain each qualified reader and bounded inspection disposition through end of R4",
    },
    "write": {
        "interfaces": ["workspace convert", "legacy migrate"],
        "commitment": (
            "legacy inputs stay immutable; write only a fresh disjoint nirs4all-workspace-v2 output "
            "or an explicitly requested external report"
        ),
    },
    "migrate": {
        "interfaces": ["workspace convert", "legacy migrate"],
        "commitment": (
            "retain each semantic, opaque-preservation, or refusal disposition through end of R4 "
            "without implying broader conversion"
        ),
    },
}


class DuplicateKeyError(ValueError):
    """Raised when a JSON object repeats a key."""


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    duplicate = next((key for key, count in Counter(key for key, _ in pairs).items() if count > 1), None)
    if duplicate is not None:
        raise DuplicateKeyError(f"duplicate JSON key: {duplicate}")
    return dict(pairs)


def load_matrix(path: Path = DEFAULT_MATRIX) -> dict[str, Any]:
    """Load the matrix while refusing duplicate JSON keys."""

    document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object_without_duplicate_keys)
    if not isinstance(document, dict):
        raise ValueError("support matrix root must be an object")
    return document


def _assigned_string(path: Path, name: str) -> str | None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            return value if isinstance(value, str) else None
    return None


def _detected_source_kinds(root: Path) -> set[str]:
    path = root / "src" / "nirs4all_tools" / "detect.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    kinds: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id.startswith("KIND_"):
            value = ast.literal_eval(node.value)
            if isinstance(value, str):
                kinds.add(value)
    return kinds


def validate_matrix(document: dict[str, Any], *, root: Path = ROOT) -> list[str]:
    """Return all structural and source-drift errors in one pass."""

    errors: list[str] = []
    if document.get("$schema") != EXPECTED_SCHEMA or document.get("schema_version") != 1:
        errors.append("schema identity/version must remain V1")
    if document.get("status") != "candidate_release_hold":
        errors.append("matrix must remain candidate_release_hold until external publication evidence exists")
    if document.get("tool_version_line") != "0.x":
        errors.append("tool_version_line must be 0.x")
    if document.get("distribution") != {
        "package": "nirs4all-tools",
        "published_version": "0.0.7",
        "install": "python -m pip install nirs4all-tools==0.0.7",
        "product_v1_promotion": "release_hold",
    }:
        errors.append("distribution must identify published nirs4all-tools 0.0.7 without claiming V1 promotion")
    if document.get("support_window") != EXPECTED_SUPPORT_WINDOW:
        errors.append("support_window does not guarantee R3 and R4 after the R2 flip")

    train = document.get("train")
    if not isinstance(train, dict):
        errors.append("train must be an object")
    else:
        if train.get("flip") != EXPECTED_RELEASES["flip"]:
            errors.append("R2 flip identity/version drifted")
        if train.get("guaranteed_reader_releases") != EXPECTED_RELEASES["guaranteed"]:
            errors.append("legacy readers must be guaranteed for exactly R3 and R4")
        if train.get("earliest_removal") != "post-V1":
            errors.append("reader removal cannot occur before post-V1")
        required = train.get("removal_requires")
        if required != ["announced_governance_decision", "migration_notice_before_effective_release"]:
            errors.append("post-V1 removal requires an announced decision and advance migration notice")

    if document.get("service_levels") != EXPECTED_SERVICE_LEVELS:
        errors.append("service_levels must preserve the exact read, write, and migrate commitments")

    immutable = document.get("immutability")
    expected_immutable = {
        "source_path": "unchanged",
        "source_inode": "unchanged",
        "source_bytes": "unchanged",
        "in_place": "refused",
        "rename_source": "refused",
        "bak_copy": "never_created",
    }
    if immutable != expected_immutable:
        errors.append("legacy source path, inode, and bytes must remain immutable without rename or .bak")

    rollback = document.get("rollback")
    if not isinstance(rollback, dict):
        errors.append("rollback must be an object")
    else:
        if rollback.get("minimum_access_through") != "end-of-R4":
            errors.append("rollback artifacts must remain accessible through end of R4")
        if rollback.get("versions") != EXPECTED_RELEASES["rollback"]:
            errors.append("rollback versions must be exact R1, R2, and R3 product releases")
        if rollback.get("required_release_lock_evidence") != [
            "official_versioned_url",
            "sha256",
            "signature_or_attestation",
        ]:
            errors.append("rollback evidence must require official URL, SHA-256, and signature/attestation")
        if rollback.get("candidate_availability") != "external_release_hold":
            errors.append("rollback release receipts must retain the external release hold")

    inputs = document.get("inputs")
    if not isinstance(inputs, list):
        errors.append("inputs must be a list")
        inputs = []
    names = [entry.get("source_kind") for entry in inputs if isinstance(entry, dict)]
    duplicates = sorted(name for name, count in Counter(names).items() if count > 1 and isinstance(name, str))
    if duplicates:
        errors.append(f"duplicate source_kind entries: {', '.join(duplicates)}")

    actual_kinds = _detected_source_kinds(root)
    matrix_kinds = {name for name in names if isinstance(name, str)}
    if missing := sorted(actual_kinds - matrix_kinds):
        errors.append(f"matrix omits detected source kinds: {', '.join(missing)}")
    if extra := sorted(matrix_kinds - actual_kinds):
        errors.append(f"matrix invents source kinds: {', '.join(extra)}")

    for entry in inputs:
        if not isinstance(entry, dict):
            errors.append("every input entry must be an object")
            continue
        kind = entry.get("source_kind")
        expected = EXPECTED_DISPOSITIONS.get(kind)
        if expected is None:
            continue
        legacy_reader, read, migrate = expected
        if entry.get("legacy_reader") is not legacy_reader:
            errors.append(f"{kind}: legacy_reader classification drifted")
        if entry.get("read") != read:
            errors.append(f"{kind}: read disposition drifted")
        if entry.get("write") != "fresh_workspace_v2_only":
            errors.append(f"{kind}: write must remain fresh_workspace_v2_only")
        if entry.get("migrate") != migrate:
            errors.append(f"{kind}: migrate disposition drifted")

    commands_window = _assigned_string(root / "src" / "nirs4all_tools" / "commands.py", "SUPPORT_WINDOW")
    if commands_window != document.get("support_window"):
        errors.append("commands.SUPPORT_WINDOW differs from the machine-readable SLA")

    sla = (root / "docs" / "legacy-support-sla.md").read_text(encoding="utf-8")
    runbook = (root / "docs" / "workspace-conversion-runbook.md").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")
    if "legacy-support-matrix.v1.json" not in sla or "V1 promotion gate" not in sla:
        errors.append("SLA documentation must link the matrix and retain the V1 promotion hold")
    if "official versioned URL" not in runbook or "through the end of R4" not in runbook:
        errors.append("runbook must require versioned rollback artifacts through end of R4")
    if "docs/contracts/legacy-support-matrix.v1.json" not in readme:
        errors.append("README must link the machine-readable SLA")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    args = parser.parse_args(argv)
    try:
        document = load_matrix(args.matrix)
        errors = validate_matrix(document)
    except (OSError, ValueError, SyntaxError) as exc:
        print(f"support matrix invalid: {exc}")
        return 1
    if errors:
        for error in errors:
            print(f"support matrix invalid: {error}")
        return 1
    print(f"support matrix valid: {args.matrix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

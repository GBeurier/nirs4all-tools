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
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import contracts, vocab
from .checksums import sha256_bytes, sha256_file
from .detect import (
    KIND_N4A_BUNDLE,
    KIND_N4A_PY_BUNDLE,
    KIND_NATIVE_RESULTS_V1,
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
    snapshot_tree,
    source_guard,
)

#: Declared legacy-reader support window, recorded into every manifest.
SUPPORT_WINDOW = "nirs4all-tools 0.x — legacy readers supported for an announced number of releases (TOOL-011)"

_PAYLOAD_DIRNAME = "payload"


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
        # Real schema transform — deliberately not implemented in this scaffold.
        raise UnsupportedInput(
            "schema-transform migrate to nirs4all-workspace-v2 is not implemented in this scaffold (L18)",
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

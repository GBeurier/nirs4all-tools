"""Strict preview lowering for legacy ``runs/*/*/manifest.yaml`` payloads."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import vocab
from .errors import UnsupportedInput
from .loose_predictions import (
    LoosePredictionsPreview,
    load_loose_predictions_preview,
    lower_loose_predictions_preview,
    runtime_array_records_from_loose_predictions,
)

LEGACY_RUNS_PREVIEW_VERSION = 1


@dataclass(frozen=True)
class LegacyRunsPreview:
    """Validated legacy run manifest plus its referenced prediction JSON."""

    root: Path
    manifest_file: str
    prediction_file: str
    manifest: dict[str, Any]
    loose_predictions: LoosePredictionsPreview


def _unsupported(message: str) -> UnsupportedInput:
    return UnsupportedInput(
        message,
        cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
        mitigation="preserve the legacy runs payload opaque, or repair manifest.yaml and predictions JSON",
    )


def _scalar(value: str) -> str:
    value = value.strip()
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    return value


def _parse_manifest_yaml(path: Path) -> dict[str, Any]:
    """Parse the deliberately tiny legacy manifest subset supported by this preview."""
    data: dict[str, Any] = {}
    section: str | None = None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise _unsupported(f"legacy-runs preview could not read {path.name}: {exc}") from exc

    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw.startswith("  "):
            if section is None:
                raise _unsupported("legacy-runs preview found indented content outside a supported section")
            item = raw[2:]
            if section == "preprocessing":
                if not item.startswith("- "):
                    raise _unsupported("legacy-runs preview supports only scalar preprocessing list items")
                data.setdefault(section, []).append(_scalar(item[2:]))
                continue
            if section not in {"model", "predictions"} or ":" not in item:
                raise _unsupported(f"legacy-runs preview does not support section {section!r}")
            key, value = item.split(":", 1)
            if not value.strip():
                raise _unsupported(f"legacy-runs preview requires scalar field {section}.{key.strip()}")
            data.setdefault(section, {})[key.strip()] = _scalar(value)
            continue
        if raw.startswith((" ", "\t")):
            raise _unsupported("legacy-runs preview supports two-space indentation only")
        if ":" not in raw:
            raise _unsupported("legacy-runs preview requires key: value manifest lines")
        key, value = raw.split(":", 1)
        key = key.strip()
        if value.strip():
            data[key] = _scalar(value)
            section = None
        else:
            if key not in {"model", "preprocessing", "predictions"}:
                raise _unsupported(f"legacy-runs preview does not support section {key!r}")
            data[key] = [] if key == "preprocessing" else {}
            section = key
    return data


def _required_str(data: dict[str, Any], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value:
        raise _unsupported(f"legacy-runs preview requires non-empty manifest field {field!r}")
    return value


def _required_nested_str(data: dict[str, Any], section: str, field: str) -> str:
    nested = data.get(section)
    if not isinstance(nested, dict):
        raise _unsupported(f"legacy-runs preview requires manifest section {section!r}")
    return _required_str(nested, field)


def _prediction_relpath(root: Path, manifest_path: Path, prediction_file: str) -> str:
    if not prediction_file:
        raise _unsupported("legacy-runs preview requires predictions.file")
    raw = Path(prediction_file)
    resolved = (manifest_path.parent / raw).resolve()
    if raw.is_absolute() or (".." in raw.parts and not resolved.is_relative_to(root.resolve())):
        raise _unsupported("legacy-runs preview predictions.file must stay under the source root")
    try:
        rel = resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise _unsupported("legacy-runs preview predictions.file must stay under the source root") from exc
    if not resolved.is_file():
        raise _unsupported(f"legacy-runs preview could not find referenced predictions file {rel.as_posix()}")
    if not rel.name.endswith("_predictions.json"):
        raise _unsupported("legacy-runs preview supports only *_predictions.json references")
    return rel.as_posix()


def _validate_manifest_matches_predictions(manifest: dict[str, Any], preview: LoosePredictionsPreview) -> None:
    record = preview.record
    expected = {
        "run_id": _required_str(manifest, "run_id"),
        "pipeline_id": _required_str(manifest, "pipeline_id"),
        "dataset": _required_str(manifest, "dataset"),
        "model_class": _required_nested_str(manifest, "model", "class"),
        "model_name": _required_nested_str(manifest, "model", "name"),
        "preprocessing": manifest.get("preprocessing") or [],
    }
    if _required_str(manifest, "status") != "completed":
        raise _unsupported("legacy-runs preview supports only completed runs")
    if not isinstance(expected["preprocessing"], list):
        raise _unsupported("legacy-runs preview preprocessing must be a scalar list")
    comparisons = {
        "run_id": record["run_id"],
        "pipeline_id": record["pipeline_id"],
        "dataset": record["dataset"],
        "model_class": record["model_class"],
        "model_name": record["model_name"],
        "preprocessing": record["preprocessing"],
    }
    mismatched = [key for key, value in expected.items() if comparisons[key] != value]
    if mismatched:
        raise _unsupported(
            "legacy-runs preview manifest and predictions JSON disagree on field(s): "
            + ", ".join(sorted(mismatched))
        )


def _validate_detected_loose_files(loose_files: list[str] | None, prediction_file: str) -> None:
    if loose_files is None:
        return
    prediction_files = sorted(str(item) for item in loose_files if str(item).endswith("_predictions.json"))
    if prediction_files != [prediction_file]:
        raise UnsupportedInput(
            "legacy-runs preview supports exactly the manifest-referenced prediction JSON; got "
            + ", ".join(prediction_files or ["<none>"]),
            cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
            mitigation="preserve the mixed loose-predictions payload opaque, or split extra prediction files",
        )


def load_legacy_runs_preview(
    root: Path,
    runs_relpath: str,
    *,
    loose_files: list[str] | None = None,
) -> LegacyRunsPreview:
    """Validate one legacy run manifest and its referenced predictions JSON."""
    runs_root = root / runs_relpath
    manifests = sorted(runs_root.glob("*/*/manifest.yaml"))
    if len(manifests) != 1:
        raise UnsupportedInput(
            f"legacy-runs preview supports exactly one runs/*/*/manifest.yaml file, got {len(manifests)}",
            cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
            mitigation="preserve the legacy runs payload opaque, or split runs before migration",
        )
    manifest_path = manifests[0]
    manifest = _parse_manifest_yaml(manifest_path)
    prediction_file = _prediction_relpath(
        root,
        manifest_path,
        _required_nested_str(manifest, "predictions", "file"),
    )
    _validate_detected_loose_files(loose_files, prediction_file)
    loose_preview = load_loose_predictions_preview(root, [prediction_file])
    _validate_manifest_matches_predictions(manifest, loose_preview)
    return LegacyRunsPreview(
        root=root,
        manifest_file=manifest_path.relative_to(root).as_posix(),
        prediction_file=prediction_file,
        manifest=manifest,
        loose_predictions=loose_preview,
    )


def runtime_array_records_from_legacy_runs(preview: LegacyRunsPreview) -> list[dict[str, Any]]:
    return runtime_array_records_from_loose_predictions(preview.loose_predictions)


def lower_legacy_runs_preview(conn: sqlite3.Connection, preview: LegacyRunsPreview) -> dict[str, int]:
    return lower_loose_predictions_preview(conn, preview.loose_predictions)


__all__ = [
    "LEGACY_RUNS_PREVIEW_VERSION",
    "LegacyRunsPreview",
    "load_legacy_runs_preview",
    "lower_legacy_runs_preview",
    "runtime_array_records_from_legacy_runs",
]

"""Detection tests (``detect.py``) — stat-first, read-only source classification."""

from __future__ import annotations

from pathlib import Path

from conftest import make_n4a_bundle
from nirs4all_tools import detect


def test_detect_sqlite_v2(sqlite_v2_workspace: Path) -> None:
    result = detect.detect_sources(sqlite_v2_workspace)
    assert detect.KIND_SQLITE_WORKSPACE_V2 in result.kinds
    art = next(a for a in result.artifacts if a.source_kind == detect.KIND_SQLITE_WORKSPACE_V2)
    assert art.detected_version == 2
    assert art.supported is True
    assert art.forward_version is False
    assert result.has_recognized is True


def test_detect_legacy_arrays(legacy_arrays_workspace: Path) -> None:
    result = detect.detect_sources(legacy_arrays_workspace)
    assert detect.KIND_SQLITE_WORKSPACE_LEGACY_ARRAYS in result.kinds
    art = next(a for a in result.artifacts if a.source_kind == detect.KIND_SQLITE_WORKSPACE_LEGACY_ARRAYS)
    assert art.details["has_prediction_arrays"] is True


def test_detect_forward_version_sqlite(forward_version_workspace: Path) -> None:
    result = detect.detect_sources(forward_version_workspace)
    assert result.forward_version_artifacts
    art = result.forward_version_artifacts[0]
    assert art.detected_version == 99
    assert art.supported is False


def test_detect_duckdb_presence(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "store.duckdb").write_bytes(b"not really duckdb")
    result = detect.detect_sources(ws)
    assert detect.KIND_DUCKDB_WORKSPACE in result.kinds


def test_detect_n4a_bundle_file(n4a_bundle: Path) -> None:
    result = detect.detect_sources(n4a_bundle)
    assert detect.KIND_N4A_BUNDLE in result.kinds
    art = result.artifacts[0]
    assert art.detected_version == "1.0"
    assert art.forward_version is False


def test_detect_forward_n4a_bundle(tmp_path: Path) -> None:
    bundle = make_n4a_bundle(tmp_path / "future.n4a", bundle_format_version="2.0")
    result = detect.detect_sources(bundle)
    art = result.artifacts[0]
    assert art.forward_version is True
    assert art.supported is False


def test_detect_n4a_py_bundle(tmp_path: Path) -> None:
    bundle = tmp_path / "model.n4a.py"
    bundle.write_text("# embedded bundle\n", encoding="utf-8")
    result = detect.detect_sources(bundle)
    assert detect.KIND_N4A_PY_BUNDLE in result.kinds


def test_detect_loose_predictions(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "run_predictions.json").write_text("{}", encoding="utf-8")
    result = detect.detect_sources(ws)
    assert detect.KIND_LOOSE_PREDICTIONS in result.kinds


def test_detect_unknown_empty_dir(tmp_path: Path) -> None:
    ws = tmp_path / "empty"
    ws.mkdir()
    result = detect.detect_sources(ws)
    assert result.has_recognized is False
    assert result.artifacts[0].source_kind == detect.KIND_UNKNOWN


def test_detect_missing_path(tmp_path: Path) -> None:
    result = detect.detect_sources(tmp_path / "nope")
    assert result.has_recognized is False

"""Detection tests (``detect.py``) — stat-first, read-only source classification."""

from __future__ import annotations

import os
import zipfile
from pathlib import Path

import pytest

from conftest import make_n4a_bundle, make_native_results_dir
from nirs4all_tools import detect


def test_detect_sqlite_v2(sqlite_v2_workspace: Path) -> None:
    result = detect.detect_sources(sqlite_v2_workspace)
    assert detect.KIND_SQLITE_WORKSPACE_V2 in result.kinds
    art = next(a for a in result.artifacts if a.source_kind == detect.KIND_SQLITE_WORKSPACE_V2)
    assert art.detected_version == 2
    assert art.supported is True
    assert art.forward_version is False
    assert result.has_recognized is True


def test_detect_direct_directory_symlink_resolves_only_its_root(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    alias = tmp_path / "workspace-alias"
    try:
        os.symlink(sqlite_v2_workspace, alias, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks are unavailable in this test environment: {exc}")

    result = detect.detect_sources(alias)

    assert result.root == str(sqlite_v2_workspace)
    assert detect.KIND_SQLITE_WORKSPACE_V2 in result.kinds


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
    assert art.details["archive_preflight"]["validated_content_sha256"].startswith("sha256:")


@pytest.mark.parametrize("direct", [True, False])
def test_detect_uppercase_n4a_bundle_file_and_directory_entry(tmp_path: Path, direct: bool) -> None:
    if direct:
        source = make_n4a_bundle(tmp_path / "MODEL.N4A", bundle_format_version="1.0")
        result = detect.detect_sources(source)
    else:
        root = tmp_path / "source"
        root.mkdir()
        make_n4a_bundle(root / "MODEL.N4A", bundle_format_version="1.0")
        result = detect.detect_sources(root)

    art = next(artifact for artifact in result.artifacts if artifact.source_kind == detect.KIND_N4A_BUNDLE)
    assert art.path == ("." if direct else "MODEL.N4A")
    assert art.supported is True


def test_detect_forward_n4a_bundle(tmp_path: Path) -> None:
    bundle = make_n4a_bundle(tmp_path / "future.n4a", bundle_format_version="2.0")
    result = detect.detect_sources(bundle)
    art = result.artifacts[0]
    assert art.forward_version is True
    assert art.supported is False


def test_detect_unsafe_n4a_bundle_is_recognized_but_refused(tmp_path: Path) -> None:
    bundle = tmp_path / "unsafe.n4a"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("manifest.json", "{}")
        archive.writestr("../escape", "never extracted")

    result = detect.detect_sources(bundle)

    art = result.artifacts[0]
    assert art.source_kind == detect.KIND_N4A_BUNDLE
    assert art.supported is False
    assert art.forward_version is False
    assert art.details["archive_preflight"]["status"] == "refused"
    assert art.details["archive_preflight"]["rule"] == "unsafe_member_path"


def test_detect_n4a_with_an_enormous_numeric_version_fails_closed(tmp_path: Path) -> None:
    bundle = make_n4a_bundle(tmp_path / "huge-version.n4a", bundle_format_version="9" * 5_000)

    result = detect.detect_sources(bundle)

    art = result.artifacts[0]
    assert art.forward_version is True
    assert art.supported is False


def test_detect_n4a_with_a_non_ascii_digit_version_does_not_crash(tmp_path: Path) -> None:
    bundle = make_n4a_bundle(tmp_path / "unicode-version.n4a", bundle_format_version="²")

    result = detect.detect_sources(bundle)

    art = result.artifacts[0]
    assert art.detected_version == "²"
    assert art.forward_version is False


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO semantics are unavailable on this platform")
def test_detect_direct_n4a_fifo_is_refused_without_directory_traversal(tmp_path: Path) -> None:
    bundle = tmp_path / "untrusted.n4a"
    os.mkfifo(bundle)

    result = detect.detect_sources(bundle)

    art = result.artifacts[0]
    assert art.source_kind == detect.KIND_N4A_BUNDLE
    assert art.supported is False
    assert art.details["archive_preflight"]["rule"] == "invalid_zip"


def test_detect_current_native_results(lowerable_native_results_dir: Path) -> None:
    result = detect.detect_sources(lowerable_native_results_dir)
    assert detect.KIND_NATIVE_RESULTS_V1 in result.kinds
    art = next(a for a in result.artifacts if a.source_kind == detect.KIND_NATIVE_RESULTS_V1)
    assert art.detected_version == 3
    assert art.forward_version is False
    assert art.supported is True


def test_detect_future_native_results_schema_is_forward_version(tmp_path: Path) -> None:
    source = make_native_results_dir(tmp_path / "native-results", schema_version=4)

    result = detect.detect_sources(source)

    art = result.artifacts[0]
    assert art.detected_version == 4
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

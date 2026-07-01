"""Argument-safety tests for the no-in-place policy (``policy.py``)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from nirs4all_tools import policy
from nirs4all_tools.errors import PolicyRefusal, SourceIntegrityError


def test_read_only_sqlite_uri_is_immutable(tmp_path: Path) -> None:
    uri = policy.read_only_sqlite_uri(tmp_path / "store.sqlite")
    assert uri.startswith("file:")
    assert "mode=ro" in uri
    assert "immutable=1" in uri


def test_disjoint_refuses_identical_paths(tmp_path: Path) -> None:
    src = tmp_path / "ws"
    src.mkdir()
    with pytest.raises(PolicyRefusal):
        policy.assert_disjoint(src, src)


def test_disjoint_refuses_output_inside_source(tmp_path: Path) -> None:
    src = tmp_path / "ws"
    src.mkdir()
    with pytest.raises(PolicyRefusal):
        policy.assert_disjoint(src, src / "migrated")


def test_disjoint_refuses_source_inside_output(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(PolicyRefusal):
        policy.assert_disjoint(out / "ws", out)


def test_disjoint_allows_siblings(tmp_path: Path) -> None:
    src = tmp_path / "ws"
    src.mkdir()
    policy.assert_disjoint(src, tmp_path / "ws.migrated")  # must not raise


def test_sibling_prefix_is_not_treated_as_nested(tmp_path: Path) -> None:
    # `/a/ws` and `/a/ws_extra` share a string prefix but are disjoint.
    src = tmp_path / "ws"
    src.mkdir()
    policy.assert_disjoint(src, tmp_path / "ws_extra")  # must not raise


def test_path_outside_source_refuses_inside(tmp_path: Path) -> None:
    src = tmp_path / "ws"
    src.mkdir()
    with pytest.raises(PolicyRefusal):
        policy.assert_path_outside_source(src, src / "report.json")


def test_path_outside_source_allows_outside(tmp_path: Path) -> None:
    src = tmp_path / "ws"
    src.mkdir()
    policy.assert_path_outside_source(src, tmp_path / "report.json")  # must not raise


def test_output_available_accepts_missing_and_empty(tmp_path: Path) -> None:
    policy.assert_output_available(tmp_path / "missing", resume=False)
    empty = tmp_path / "empty"
    empty.mkdir()
    policy.assert_output_available(empty, resume=False)


def test_output_available_refuses_non_empty(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "stale.txt").write_text("x", encoding="utf-8")
    with pytest.raises(PolicyRefusal):
        policy.assert_output_available(out, resume=False)
    # ...but --resume permits it.
    policy.assert_output_available(out, resume=True)


def test_output_available_refuses_file(tmp_path: Path) -> None:
    f = tmp_path / "afile"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(PolicyRefusal):
        policy.assert_output_available(f, resume=False)


def test_source_guard_passes_when_unchanged(tmp_path: Path) -> None:
    src = tmp_path / "ws"
    src.mkdir()
    (src / "a.txt").write_text("hello", encoding="utf-8")
    with policy.source_guard(src):
        _ = (src / "a.txt").read_text(encoding="utf-8")  # read-only use is fine


def test_source_guard_trips_on_added_file(tmp_path: Path) -> None:
    src = tmp_path / "ws"
    src.mkdir()
    (src / "a.txt").write_text("hello", encoding="utf-8")
    with pytest.raises(SourceIntegrityError):
        with policy.source_guard(src):
            (src / "b.txt").write_text("new", encoding="utf-8")


def test_source_guard_trips_on_modified_bytes(tmp_path: Path) -> None:
    src = tmp_path / "ws"
    src.mkdir()
    target = src / "a.txt"
    target.write_text("hello", encoding="utf-8")
    with pytest.raises(SourceIntegrityError):
        with policy.source_guard(src):
            target.write_text("HELLO WORLD", encoding="utf-8")


def test_source_guard_trips_on_same_size_modified_bytes_with_restored_mtime(tmp_path: Path) -> None:
    src = tmp_path / "ws"
    src.mkdir()
    target = src / "a.txt"
    target.write_text("hello", encoding="utf-8")
    original = target.stat()

    with pytest.raises(SourceIntegrityError):
        with policy.source_guard(src):
            target.write_text("HELLO", encoding="utf-8")
            os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns))


def test_source_guard_integrity_error_outranks_body_error(tmp_path: Path) -> None:
    src = tmp_path / "ws"
    src.mkdir()
    (src / "a.txt").write_text("hello", encoding="utf-8")
    # If the body both mutates the source AND raises, the integrity violation
    # (the worse outcome) is what propagates.
    with pytest.raises(SourceIntegrityError):
        with policy.source_guard(src):
            (src / "b.txt").write_text("new", encoding="utf-8")
            raise ValueError("body failure")


def test_snapshot_diff_detects_removal(tmp_path: Path) -> None:
    src = tmp_path / "ws"
    src.mkdir()
    a = src / "a.txt"
    a.write_text("hello", encoding="utf-8")
    before = policy.snapshot_tree(src)
    a.unlink()
    after = policy.snapshot_tree(src)
    assert "a.txt" in policy.diff_snapshots(before, after)

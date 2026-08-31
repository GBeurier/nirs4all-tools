"""Argument-safety tests for the no-in-place policy (``policy.py``)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from nirs4all_tools import policy
from nirs4all_tools.errors import PolicyRefusal, SourceIntegrityError, UnsupportedInput


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
    # ``--resume`` never makes this low-level guard permissive; the command
    # layer separately accepts only a complete internally attested output.
    with pytest.raises(PolicyRefusal):
        policy.assert_output_available(out, resume=True)


def test_output_available_refuses_file(tmp_path: Path) -> None:
    f = tmp_path / "afile"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(PolicyRefusal):
        policy.assert_output_available(f, resume=False)


def test_storage_capacity_groups_requests_on_the_same_volume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    filesystem = os.statvfs_result((4096, 4096, 100, 100, 3, 100, 100, 100, 0, 255))
    monkeypatch.setattr(policy, "_storage_status", lambda _path: (7, filesystem))

    with pytest.raises(PolicyRefusal) as raised:
        policy.assert_storage_capacity(
            policy.StorageRequest(tmp_path / "source-stage", (4097,), purpose="source"),
            policy.StorageRequest(tmp_path / "publication", (4097,), purpose="output"),
        )

    assert raised.value.cause == "insufficient_storage"
    assert "source, output" in raised.value.message


def test_storage_capacity_keeps_distinct_volumes_separate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    filesystem = os.statvfs_result((4096, 4096, 100, 100, 2, 100, 100, 100, 0, 255))

    def storage_status(path: Path):
        return (1 if path.name == "source-stage" else 2), filesystem

    monkeypatch.setattr(policy, "_storage_status", storage_status)

    policy.assert_storage_capacity(
        policy.StorageRequest(tmp_path / "source-stage", (4097,), purpose="source"),
        policy.StorageRequest(tmp_path / "publication", (4097,), purpose="output"),
    )


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


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="the platform does not support FIFO nodes")
def test_snapshot_tree_records_a_fifo_without_opening_it(tmp_path: Path) -> None:
    src = tmp_path / "ws"
    src.mkdir()
    os.mkfifo(src / "blocked.fifo")

    snapshot = policy.snapshot_tree(src)

    assert snapshot.entries["blocked.fifo"][0] == -2


def test_safe_source_tree_refuses_a_descendant_symlink(tmp_path: Path) -> None:
    src = tmp_path / "ws"
    src.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        os.symlink(outside, src / "escaped.txt")
    except OSError as exc:
        pytest.skip(f"symlinks are unavailable in this test environment: {exc}")

    with pytest.raises(UnsupportedInput) as raised:
        policy.assert_safe_source_tree(src)

    assert raised.value.cause == "unsupported_shape"


def test_copy_regular_file_nofollow_rejects_a_parent_symlink_swap(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    original_parent = source_root / "payload"
    original_parent.mkdir(parents=True)
    (original_parent / "source.txt").write_text("inside", encoding="utf-8")
    external_parent = tmp_path / "external"
    external_parent.mkdir()
    (external_parent / "source.txt").write_text("outside", encoding="utf-8")
    held_parent = source_root / "payload-held"
    original_parent.rename(held_parent)
    try:
        os.symlink(external_parent, original_parent, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks are unavailable in this test environment: {exc}")

    destination = tmp_path / "output" / "copied.txt"
    with pytest.raises(UnsupportedInput) as raised:
        policy.copy_regular_file_nofollow(original_parent / "source.txt", destination)

    assert raised.value.cause == "unsupported_shape"
    assert not destination.exists()


def test_safe_source_fallback_without_posix_nofollow_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "payload.txt"
    source.write_text("portable", encoding="utf-8")
    monkeypatch.delattr(policy.os, "O_NOFOLLOW", raising=False)
    monkeypatch.delattr(policy.os, "O_DIRECTORY", raising=False)

    policy.assert_safe_source_tree(source_root)
    destination = tmp_path / "output" / "payload.txt"
    policy.copy_regular_file_nofollow(source, destination)

    assert destination.read_text(encoding="utf-8") == "portable"


def test_materialized_source_stage_fails_closed_without_posix_nofollow_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.txt"
    source.write_text("portable", encoding="utf-8")
    monkeypatch.delattr(policy.os, "O_NOFOLLOW", raising=False)
    monkeypatch.delattr(policy.os, "O_DIRECTORY", raising=False)

    with pytest.raises(UnsupportedInput) as raised:
        with policy.materialized_source_tree_nofollow(source):
            pass

    assert raised.value.cause == "unsupported_capability"


def test_materialized_source_stage_refuses_tmpdir_inside_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload.txt").write_text("payload", encoding="utf-8")
    unsafe_tmpdir = source / "tmp"
    monkeypatch.setattr(policy.tempfile, "gettempdir", lambda: str(unsafe_tmpdir))

    with pytest.raises(PolicyRefusal):
        with policy.materialized_source_tree_nofollow(source):
            pass

    assert not unsafe_tmpdir.exists()


def test_materialized_source_stage_refuses_tmpdir_at_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload.txt").write_text("payload", encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir()
    monkeypatch.setattr(policy.tempfile, "gettempdir", lambda: str(output))

    with pytest.raises(PolicyRefusal):
        with policy.materialized_source_tree_nofollow(source, forbidden_paths=(output,)):
            pass


def test_materialized_source_stage_is_private_and_cleans_up(tmp_path: Path) -> None:
    source = tmp_path / "source"
    nested = source / "nested"
    nested.mkdir(parents=True)
    payload = nested / "payload.txt"
    payload.write_text("payload", encoding="utf-8")
    staged_root: Path | None = None

    with policy.materialized_source_tree_nofollow(source) as staged:
        staged_root = staged.path
        staged_payload = staged.path / "nested" / "payload.txt"
        assert staged_payload.read_text(encoding="utf-8") == "payload"
        assert (staged.path / "nested").stat().st_mode & 0o777 == 0o700
        assert staged_payload.stat().st_mode & 0o777 == 0o600

    assert staged_root is not None
    assert not staged_root.parent.exists()


def test_materialized_source_stage_rejects_root_replacement_between_lstat_and_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload.txt").write_text("original", encoding="utf-8")
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "payload.txt").write_text("replacement", encoding="utf-8")
    held = tmp_path / "held"
    original_open_directory = policy._open_directory_source

    def replace_then_open(path: Path):
        source.rename(held)
        replacement.rename(source)
        return original_open_directory(path)

    monkeypatch.setattr(policy, "_open_directory_source", replace_then_open)
    yielded = False
    with pytest.raises(SourceIntegrityError):
        with policy.materialized_source_tree_nofollow(source):
            yielded = True

    assert not yielded


def test_materialized_source_stage_rejects_child_symlink_between_lstat_and_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    payload = source / "payload.txt"
    payload.write_text("original", encoding="utf-8")
    external = tmp_path / "external.txt"
    external.write_text("external", encoding="utf-8")
    held = tmp_path / "held-payload.txt"
    original_open_child = policy._open_child_nofollow
    swapped = False

    def swap_then_open(*args, **kwargs):
        nonlocal swapped
        if not swapped and args[1] == payload.name:
            swapped = True
            payload.rename(held)
            try:
                os.symlink(external, payload)
            except OSError as exc:
                held.rename(payload)
                pytest.skip(f"symlinks are unavailable in this test environment: {exc}")
        return original_open_child(*args, **kwargs)

    monkeypatch.setattr(policy, "_open_child_nofollow", swap_then_open)
    yielded = False
    try:
        with pytest.raises(UnsupportedInput) as raised:
            with policy.materialized_source_tree_nofollow(source):
                yielded = True
    finally:
        if payload.is_symlink():
            payload.unlink()
        if held.exists():
            held.rename(payload)

    assert raised.value.cause == "unsupported_shape"
    assert not yielded


def test_source_guard_nofollow_detects_identical_root_directory_replacement(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    source_file = source / "payload.txt"
    source_file.write_text("payload", encoding="utf-8")
    source_file_stat = source_file.stat()
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    replacement_file = replacement / "payload.txt"
    replacement_file.write_text("payload", encoding="utf-8")
    os.utime(replacement_file, ns=(source_file_stat.st_atime_ns, source_file_stat.st_mtime_ns))
    held = tmp_path / "held"
    before = policy.snapshot_tree_nofollow(source)

    with pytest.raises(SourceIntegrityError):
        with policy.source_guard_nofollow(source, before=before):
            source.rename(held)
            replacement.rename(source)

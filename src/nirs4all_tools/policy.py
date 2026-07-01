"""No-in-place safety policy — the single most important contract of the tool.

This module enforces, *before any byte is written*, the rules from
``SW4_MIG_CONVERTER_spec.md`` §3:

* the source is opened read-only (``read_only_sqlite_uri``);
* ``--output`` is mandatory and **disjoint** from the source (``assert_disjoint``);
* the output must be empty unless ``--resume`` (``assert_output_available``);
* explicit report/manifest paths must resolve **outside** the source tree
  (``assert_path_outside_source``);
* the whole source tree is snapshotted ``(path, size, mtime_ns, sha256)`` before
  and after every run and asserted byte-for-byte identical (``source_guard``).

All refusals raise :class:`PolicyRefusal` (exit ``40``); a tripped integrity
assertion raises :class:`SourceIntegrityError` (exit ``70``).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import vocab
from .checksums import sha256_file
from .errors import PolicyRefusal, SourceIntegrityError


def realpath(path: Path | str) -> Path:
    """Resolve symlinks and ``..`` without requiring the path to exist.

    Unlike ``Path.resolve(strict=True)`` this works for a not-yet-created
    ``--output`` directory, resolving symlinks only on the existing prefix.
    """
    return Path(os.path.realpath(os.fspath(path)))


def _is_within(child: Path, parent: Path) -> bool:
    """Return ``True`` when ``child`` is ``parent`` or lives under it."""
    if child == parent:
        return True
    return parent in child.parents


def read_only_sqlite_uri(path: Path) -> str:
    """Build a strictly read-only SQLite URI for ``path``.

    ``mode=ro`` forbids writes and ``immutable=1`` additionally promises the
    file will not change, so SQLite takes no locks — the source is never
    touched (``SW4_MIG_CONVERTER_spec.md`` §3.1).
    """
    return f"file:{realpath(path)}?mode=ro&immutable=1"


def assert_disjoint(source: Path, output: Path) -> None:
    """Refuse aliased or in-place output.

    ``realpath(output)`` must not equal, contain, or be contained by
    ``realpath(source)`` (``SW4_MIG_CONVERTER_spec.md`` §3.2).
    """
    src = realpath(source)
    out = realpath(output)
    if src == out:
        raise PolicyRefusal(
            f"output path aliases the source: {out}",
            cause=vocab.CAUSE_FORCED_IN_PLACE_REFUSED,
            mitigation="choose an --output directory outside the source workspace",
        )
    if _is_within(out, src):
        raise PolicyRefusal(
            f"output {out} is inside the source tree {src}",
            cause=vocab.CAUSE_FORCED_IN_PLACE_REFUSED,
            mitigation="choose an --output directory outside the source workspace",
        )
    if _is_within(src, out):
        raise PolicyRefusal(
            f"source {src} is inside the output tree {out}",
            cause=vocab.CAUSE_FORCED_IN_PLACE_REFUSED,
            mitigation="choose an --output directory that does not contain the source",
        )


def assert_path_outside_source(source: Path, path: Path) -> None:
    """Refuse a report/manifest path that resolves inside the source tree.

    ``inspect`` and ``--dry-run`` may write only to paths outside the source
    (``SW4_MIG_CONVERTER_spec.md`` §6, §11).
    """
    src = realpath(source)
    target = realpath(path)
    if _is_within(target, src):
        raise PolicyRefusal(
            f"refusing to write {target} inside the source tree {src}",
            cause=vocab.CAUSE_FORCED_IN_PLACE_REFUSED,
            mitigation="point --report/--manifest at a path outside the source workspace",
        )


def assert_output_available(output: Path, *, resume: bool) -> None:
    """Refuse a non-empty output directory unless ``--resume`` was given.

    A path that exists but is not a directory is always refused
    (``SW4_MIG_CONVERTER_spec.md`` §3.3).
    """
    out = realpath(output)
    if not out.exists():
        return
    if not out.is_dir():
        raise PolicyRefusal(
            f"output path exists and is not a directory: {out}",
            cause=vocab.CAUSE_NON_EMPTY_OUTPUT,
            mitigation="choose a fresh, empty output directory",
        )
    if any(out.iterdir()) and not resume:
        raise PolicyRefusal(
            f"output directory is not empty: {out}",
            cause=vocab.CAUSE_NON_EMPTY_OUTPUT,
            mitigation="use a fresh empty directory, or pass --resume to continue a prior run",
        )


@dataclass(frozen=True)
class TreeSnapshot:
    """An ordered ``(relative path -> (size, mtime_ns, sha256))`` map of a tree.

    Directories are recorded with ``size == -1`` so that an added or removed
    empty directory is still detected.
    """

    root: Path
    entries: dict[str, tuple[int, int, str | None]] = field(default_factory=dict)


def snapshot_tree(root: Path) -> TreeSnapshot:
    """Snapshot ``(size, mtime_ns, sha256)`` for every path under ``root``.

    Works for both a single file and a directory tree. A missing root yields an
    empty snapshot rather than raising, so the guard can run on abort paths.
    """
    root = realpath(root)
    entries: dict[str, tuple[int, int, str | None]] = {}
    if not root.exists():
        return TreeSnapshot(root=root, entries=entries)
    if root.is_file():
        st = root.stat()
        entries["."] = (st.st_size, st.st_mtime_ns, sha256_file(root))
        return TreeSnapshot(root=root, entries=entries)
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        for name in dirnames:
            p = base / name
            rel = os.path.relpath(p, root)
            try:
                entries[rel] = (-1, p.stat().st_mtime_ns, None)
            except OSError:
                entries[rel] = (-1, 0, None)
        for name in filenames:
            p = base / name
            rel = os.path.relpath(p, root)
            try:
                st = p.stat()
                entries[rel] = (st.st_size, st.st_mtime_ns, sha256_file(p))
            except OSError:
                entries[rel] = (-2, 0, None)
    return TreeSnapshot(root=root, entries=entries)


def diff_snapshots(before: TreeSnapshot, after: TreeSnapshot) -> list[str]:
    """Return the sorted relative paths that were added, removed, or changed."""
    changed: set[str] = set()
    for rel, sig in before.entries.items():
        if after.entries.get(rel) != sig:
            changed.add(rel)
    for rel in after.entries:
        if rel not in before.entries:
            changed.add(rel)
    return sorted(changed)


@contextmanager
def source_guard(source: Path) -> Iterator[None]:
    """Assert the source tree is byte/mtime-identical before and after the body.

    Runs on *every* exit path including exceptions and aborts
    (``SW4_MIG_CONVERTER_spec.md`` §3.5). A detected change raises
    :class:`SourceIntegrityError` (exit ``70``); because that is the worst
    possible outcome it takes precedence over any in-flight body exception
    (which is preserved as ``__context__``).
    """
    before = snapshot_tree(source)
    try:
        yield
    finally:
        after = snapshot_tree(source)
        changes = diff_snapshots(before, after)
        if changes:
            preview = ", ".join(changes[:5])
            raise SourceIntegrityError(
                f"source tree changed during the operation ({len(changes)} path(s): {preview})",
                cause=vocab.CAUSE_RUNTIME_ERROR,
                mitigation="this is a tool bug — the source must never be modified; report it",
            )


__all__ = [
    "realpath",
    "read_only_sqlite_uri",
    "assert_disjoint",
    "assert_path_outside_source",
    "assert_output_available",
    "TreeSnapshot",
    "snapshot_tree",
    "diff_snapshots",
    "source_guard",
]

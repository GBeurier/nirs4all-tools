"""No-in-place safety policy — the single most important contract of the tool.

This module enforces, *before any byte is written*, the rules from
``SW4_MIG_CONVERTER_spec.md`` §3:

* the source is opened read-only (``read_only_sqlite_uri``);
* ``--output`` is mandatory and **disjoint** from the source (``assert_disjoint``);
* a fresh output must be empty (``assert_output_available``); command-level
  ``--resume`` is a separately validated, read-only attested no-op;
* explicit report/manifest paths must resolve **outside** the source tree
  (``assert_path_outside_source``);
* the whole source tree is snapshotted ``(path, size, mtime_ns, sha256)`` before
  and after every run as an integrity signal (``source_guard``); private
  descriptor-bound materialization, not that pathname snapshot, establishes
  the reader input boundary.

Path-policy refusals raise :class:`PolicyRefusal` (exit ``40``); unsafe source
nodes raise :class:`UnsupportedInput` (exit ``20``), and a tripped integrity
assertion raises :class:`SourceIntegrityError` (exit ``70``).
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import vocab
from .checksums import sha256_file
from .errors import PolicyRefusal, SourceIntegrityError, UnsupportedInput

_COPY_CHUNK_BYTES = 1 << 20


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


def _source_shape_refusal(path: Path | str, detail: str) -> UnsupportedInput:
    """Build the common fail-closed source-node refusal."""
    return UnsupportedInput(
        f"source contains an unsupported filesystem node at {os.fspath(path)!r}: {detail}",
        cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
        mitigation=(
            "replace descendant symlinks, special nodes, or unreadable entries with readable regular files/directories"
        ),
    )


def _supports_component_nofollow() -> bool:
    """Return whether this platform supports descriptor-relative no-follow opens."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    return (
        isinstance(nofollow, int)
        and isinstance(directory_flag, int)
        and os.open in os.supports_dir_fd
        # CPython exposes ``lstat(..., dir_fd=...)`` through the same POSIX
        # stat capability even though ``os.lstat`` is not listed separately.
        and os.stat in os.supports_dir_fd
    )


def _read_flags(*, directory: bool) -> int:
    """Return read-only flags, using no-follow options where the OS exposes them."""
    flags = os.O_RDONLY | int(getattr(os, "O_NONBLOCK", 0)) | int(getattr(os, "O_CLOEXEC", 0))
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if isinstance(nofollow, int):
        flags |= nofollow
    if directory:
        directory_flag = getattr(os, "O_DIRECTORY", None)
        if isinstance(directory_flag, int):
            flags |= directory_flag
    return flags


def _absolute_path_parts(path: Path) -> tuple[str, ...]:
    """Return lexical absolute path components without resolving a symlink."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts
    if len(parts) < 2 or not absolute.is_absolute():
        raise _source_shape_refusal(path, "path cannot be opened component-by-component")
    return parts


def _same_source_identity(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare the stable identity/type fields available across platforms."""
    return (left.st_dev, left.st_ino, stat.S_IFMT(left.st_mode)) == (
        right.st_dev,
        right.st_ino,
        stat.S_IFMT(right.st_mode),
    )


def _source_node_signature(source_stat: os.stat_result) -> tuple[int, int, int, int, int]:
    """Return the root identity/metadata tracked outside file content entries."""
    return (
        source_stat.st_dev,
        source_stat.st_ino,
        stat.S_IFMT(source_stat.st_mode),
        source_stat.st_mtime_ns,
        source_stat.st_ctime_ns,
    )


def _open_path_nofollow(path: Path, *, directory: bool) -> int:
    """Open a source node while refusing links as strongly as the OS permits.

    The command boundary resolves the one user-supplied root symlink before
    this helper is reached.  POSIX platforms exposing ``O_NOFOLLOW`` +
    ``O_DIRECTORY`` + ``dir_fd`` open every descendant component relative to a
    live descriptor.  Other platforms retain the static ``lstat`` refusal and
    bind the final opened node back to that identity with ``fstat``.
    """
    if not _supports_component_nofollow():
        try:
            before = os.lstat(path)
        except OSError as exc:
            detail = f"cannot inspect without following links ({exc.strerror or exc.__class__.__name__})"
            raise _source_shape_refusal(path, detail) from exc
        if stat.S_ISLNK(before.st_mode):
            raise _source_shape_refusal(path, "symlinks are not supported")
        try:
            descriptor = os.open(path, _read_flags(directory=directory))
        except OSError as exc:
            detail = f"cannot open source ({exc.strerror or exc.__class__.__name__})"
            raise _source_shape_refusal(path, detail) from exc
        try:
            if not _same_source_identity(before, os.fstat(descriptor)):
                raise _source_shape_refusal(path, "entry changed while it was opened")
        except Exception:
            os.close(descriptor)
            raise
        return descriptor

    parts = _absolute_path_parts(path)
    directory_flags = _read_flags(directory=True)
    final_flags = _read_flags(directory=directory)
    current_fd: int | None = None
    try:
        current_fd = os.open(parts[0], directory_flags)
        for component in parts[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        descriptor = os.open(parts[-1], final_flags, dir_fd=current_fd)
    except OSError as exc:
        detail = f"cannot open without following links ({exc.strerror or exc.__class__.__name__})"
        raise _source_shape_refusal(path, detail) from exc
    finally:
        if current_fd is not None:
            os.close(current_fd)
    return descriptor


def _has_read_permission(source_stat: os.stat_result) -> bool:
    """Return whether a node advertises at least one readable permission bit."""
    return bool(stat.S_IMODE(source_stat.st_mode) & (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH))


def _has_search_permission(source_stat: os.stat_result) -> bool:
    """Return whether a directory advertises at least one searchable bit."""
    return bool(stat.S_IMODE(source_stat.st_mode) & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def _require_regular_readable(source_stat: os.stat_result, path: Path | str) -> None:
    """Require a readable regular file after a descriptor-based open."""
    if not stat.S_ISREG(source_stat.st_mode):
        raise _source_shape_refusal(path, "entry is not a regular file")
    if not _has_read_permission(source_stat):
        raise _source_shape_refusal(path, "regular file has no readable permission bit")


def _require_directory_readable(source_stat: os.stat_result, path: Path | str) -> None:
    """Require a readable/searchable directory after a no-follow open."""
    if not stat.S_ISDIR(source_stat.st_mode):
        raise _source_shape_refusal(path, "entry is not a directory")
    if not _has_read_permission(source_stat) or not _has_search_permission(source_stat):
        raise _source_shape_refusal(path, "directory is not readable and searchable")


def _open_regular_source_file(path: Path) -> tuple[int, os.stat_result]:
    """Open one source regular file without following a final or parent link."""
    descriptor = _open_path_nofollow(path, directory=False)
    try:
        source_stat = os.fstat(descriptor)
        _require_regular_readable(source_stat, path)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, source_stat


def _open_directory_source(path: Path) -> tuple[int, os.stat_result]:
    """Open one source directory without following a final or parent link."""
    descriptor = _open_path_nofollow(path, directory=True)
    try:
        source_stat = os.fstat(descriptor)
        _require_directory_readable(source_stat, path)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, source_stat


def _open_child_nofollow(
    directory_fd: int,
    name: str,
    *,
    directory: bool,
    display_path: str,
    expected_stat: os.stat_result | None = None,
) -> tuple[int, os.stat_result]:
    """Open one child from an already-bound directory descriptor."""
    try:
        descriptor = os.open(name, _read_flags(directory=directory), dir_fd=directory_fd)
    except OSError as exc:
        raise _source_shape_refusal(
            display_path, f"cannot open without following links ({exc.strerror or exc.__class__.__name__})"
        ) from exc
    try:
        source_stat = os.fstat(descriptor)
        if expected_stat is not None and not _same_source_identity(expected_stat, source_stat):
            raise _source_shape_refusal(display_path, "entry changed while it was opened")
        if directory:
            _require_directory_readable(source_stat, display_path)
        else:
            _require_regular_readable(source_stat, display_path)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, source_stat


def _validate_source_directory(directory_fd: int, *, relative_prefix: str) -> None:
    """Validate a directory tree using only no-follow directory descriptors."""
    try:
        names = sorted(os.listdir(directory_fd))
    except OSError as exc:
        detail = f"cannot list directory ({exc.strerror or exc.__class__.__name__})"
        raise _source_shape_refusal(relative_prefix or ".", detail) from exc

    for name in names:
        relative = f"{relative_prefix}/{name}" if relative_prefix else name
        try:
            source_stat = os.lstat(name, dir_fd=directory_fd)
        except OSError as exc:
            detail = f"cannot inspect entry ({exc.strerror or exc.__class__.__name__})"
            raise _source_shape_refusal(relative, detail) from exc
        if stat.S_ISLNK(source_stat.st_mode):
            raise _source_shape_refusal(relative, "descendant symlinks are not supported")
        if stat.S_ISREG(source_stat.st_mode):
            child_fd, _child_stat = _open_child_nofollow(
                directory_fd,
                name,
                directory=False,
                display_path=relative,
                expected_stat=source_stat,
            )
            os.close(child_fd)
            continue
        if stat.S_ISDIR(source_stat.st_mode):
            child_fd, _child_stat = _open_child_nofollow(
                directory_fd,
                name,
                directory=True,
                display_path=relative,
                expected_stat=source_stat,
            )
            try:
                _validate_source_directory(child_fd, relative_prefix=relative)
            finally:
                os.close(child_fd)
            continue
        raise _source_shape_refusal(relative, "entry is neither a regular file nor a directory")


def _validate_source_directory_portable(directory: Path, *, relative_prefix: str) -> None:
    """Validate static source nodes without descriptor-relative OS support."""
    try:
        directory_stat = os.lstat(directory)
    except OSError as exc:
        detail = f"cannot inspect directory ({exc.strerror or exc.__class__.__name__})"
        raise _source_shape_refusal(relative_prefix or directory, detail) from exc
    if stat.S_ISLNK(directory_stat.st_mode):
        raise _source_shape_refusal(relative_prefix or directory, "descendant symlinks are not supported")
    _require_directory_readable(directory_stat, relative_prefix or directory)
    try:
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
    except OSError as exc:
        detail = f"cannot list directory ({exc.strerror or exc.__class__.__name__})"
        raise _source_shape_refusal(relative_prefix or directory, detail) from exc

    for entry in entries:
        relative = f"{relative_prefix}/{entry.name}" if relative_prefix else entry.name
        child = directory / entry.name
        try:
            source_stat = entry.stat(follow_symlinks=False)
        except OSError as exc:
            detail = f"cannot inspect entry ({exc.strerror or exc.__class__.__name__})"
            raise _source_shape_refusal(relative, detail) from exc
        if stat.S_ISLNK(source_stat.st_mode):
            raise _source_shape_refusal(relative, "descendant symlinks are not supported")
        if stat.S_ISREG(source_stat.st_mode):
            descriptor, _opened_stat = _open_regular_source_file(child)
            os.close(descriptor)
            continue
        if stat.S_ISDIR(source_stat.st_mode):
            _validate_source_directory_portable(child, relative_prefix=relative)
            continue
        raise _source_shape_refusal(relative, "entry is neither a regular file nor a directory")


def assert_safe_source_tree(root: Path) -> None:
    """Refuse unsafe source descendants before detection, preview, or output.

    Commands deliberately resolve only their user-supplied root once before
    calling this function.  A root passed directly as a symlink is therefore
    refused; this prevents a nested artifact from being reclassified as a new
    trusted root.  Missing roots remain detector-visible as unknown input.
    """
    root = Path(root)
    try:
        root_stat = os.lstat(root)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise _source_shape_refusal(root, f"cannot inspect source ({exc.strerror or exc.__class__.__name__})") from exc

    if stat.S_ISLNK(root_stat.st_mode):
        raise _source_shape_refusal(root, "root is a symlink; resolve only the user-supplied command root first")
    if stat.S_ISREG(root_stat.st_mode):
        descriptor, _source_stat = _open_regular_source_file(root)
        os.close(descriptor)
        return
    if not stat.S_ISDIR(root_stat.st_mode):
        raise _source_shape_refusal(root, "root is neither a regular file nor a directory")

    if not _supports_component_nofollow():
        _validate_source_directory_portable(root, relative_prefix="")
        return

    descriptor, _source_stat = _open_directory_source(root)
    try:
        _validate_source_directory(descriptor, relative_prefix="")
    finally:
        os.close(descriptor)


def _same_source_file_metadata(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare metadata that must remain stable while a source file is copied."""
    return (
        left.st_dev,
        left.st_ino,
        stat.S_IFMT(left.st_mode),
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        stat.S_IFMT(right.st_mode),
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _copy_open_regular_file(
    source_descriptor: int | None,
    source_stat: os.stat_result,
    destination: Path,
    *,
    display_source: Path | str,
    private_destination: bool = False,
) -> str:
    """Copy an already-bound regular-file descriptor and take ownership of it.

    ``private_destination`` keeps a materialized input stage inaccessible to
    other users.  Normal migration payload copies retain their source mode and
    timestamps for compatibility.
    """
    destination = Path(destination)
    destination_descriptor: int | None = None
    temporary: Path | None = None
    digest = hashlib.sha256()
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
        destination_descriptor = descriptor
        temporary = Path(temporary_name)
        if source_descriptor is None:
            raise AssertionError("source descriptor ownership was lost before copying")
        source_handle = os.fdopen(source_descriptor, "rb")
        source_descriptor = None
        try:
            destination_handle = os.fdopen(destination_descriptor, "wb")
        except Exception:
            source_handle.close()
            raise
        destination_descriptor = None
        with source_handle, destination_handle:
            remaining = source_stat.st_size
            while remaining:
                chunk = source_handle.read(min(_COPY_CHUNK_BYTES, remaining))
                if not chunk:
                    raise SourceIntegrityError(
                        f"source file changed while it was copied: {display_source}",
                        cause=vocab.CAUSE_RUNTIME_ERROR,
                        mitigation="rerun migration against a stable source",
                    )
                destination_handle.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            if not _same_source_file_metadata(os.fstat(source_handle.fileno()), source_stat):
                raise SourceIntegrityError(
                    f"source file changed while it was copied: {display_source}",
                    cause=vocab.CAUSE_RUNTIME_ERROR,
                    mitigation="rerun migration against a stable source",
                )
        if private_destination:
            os.chmod(temporary, 0o600)
        else:
            os.chmod(temporary, stat.S_IMODE(source_stat.st_mode))
            os.utime(temporary, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns))
        os.replace(temporary, destination)
        temporary = None
        return f"sha256:{digest.hexdigest()}"
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def copy_regular_file_nofollow(source: Path, destination: Path) -> None:
    """Copy one regular source file from a bounded no-follow descriptor.

    On platforms with descriptor-relative ``O_NOFOLLOW`` support, every source
    component is bound before the copy.  Other platforms retain a portable
    ``lstat``/``fstat`` final-node binding.  In both cases the descriptor is
    copied exactly to its initial size and must still match before publication,
    so a replacement, truncation, or growth cannot be silently attested.
    """
    source = Path(source)
    source_descriptor, source_stat = _open_regular_source_file(source)
    _copy_open_regular_file(
        source_descriptor,
        source_stat,
        Path(destination),
        display_source=source,
    )


def _copy_bound_source_directory(
    source_descriptor: int,
    source_stat: os.stat_result,
    destination: Path,
    *,
    relative_prefix: str,
    entries: dict[str, tuple[int, int, str | None]],
) -> None:
    """Materialize one already-bound source directory into a private stage."""
    try:
        destination.mkdir(mode=0o700)
    except OSError as exc:
        raise SourceIntegrityError(
            f"cannot create private source stage directory {destination}: {exc}",
            cause=vocab.CAUSE_RUNTIME_ERROR,
            mitigation="rerun migration in a writable temporary directory",
        ) from exc
    try:
        names = sorted(os.listdir(source_descriptor))
    except OSError as exc:
        detail = f"cannot list directory ({exc.strerror or exc.__class__.__name__})"
        raise _source_shape_refusal(relative_prefix or ".", detail) from exc

    for name in names:
        relative = f"{relative_prefix}/{name}" if relative_prefix else name
        try:
            child_lstat = os.lstat(name, dir_fd=source_descriptor)
        except OSError as exc:
            detail = f"cannot inspect entry ({exc.strerror or exc.__class__.__name__})"
            raise _source_shape_refusal(relative, detail) from exc
        if stat.S_ISLNK(child_lstat.st_mode):
            raise _source_shape_refusal(relative, "descendant symlinks are not supported")
        child_destination = destination / name
        if stat.S_ISREG(child_lstat.st_mode):
            child_descriptor, child_stat = _open_child_nofollow(
                source_descriptor,
                name,
                directory=False,
                display_path=relative,
                expected_stat=child_lstat,
            )
            digest = _copy_open_regular_file(
                child_descriptor,
                child_stat,
                child_destination,
                display_source=relative,
                private_destination=True,
            )
            entries[relative] = (child_stat.st_size, child_stat.st_mtime_ns, digest)
            continue
        if stat.S_ISDIR(child_lstat.st_mode):
            child_descriptor, child_stat = _open_child_nofollow(
                source_descriptor,
                name,
                directory=True,
                display_path=relative,
                expected_stat=child_lstat,
            )
            try:
                entries[relative] = (-1, child_stat.st_mtime_ns, None)
                _copy_bound_source_directory(
                    child_descriptor,
                    child_stat,
                    child_destination,
                    relative_prefix=relative,
                    entries=entries,
                )
            finally:
                os.close(child_descriptor)
            continue
        raise _source_shape_refusal(relative, "entry is neither a regular file nor a directory")

    if not _same_source_file_metadata(os.fstat(source_descriptor), source_stat):
        raise SourceIntegrityError(
            f"source directory changed while it was materialized: {relative_prefix or '.'}",
            cause=vocab.CAUSE_RUNTIME_ERROR,
            mitigation="rerun migration against a stable source",
        )
    os.chmod(destination, 0o700)


@contextmanager
def materialized_source_tree_nofollow(
    source: Path,
    *,
    forbidden_paths: tuple[Path, ...] = (),
    source_is_canonical: bool = False,
) -> Iterator[MaterializedSource]:
    """Yield a private, no-follow materialization of ``source``.

    The returned path preserves the source basename and relative layout, but
    has private ``0700`` directories and ``0600`` files.  Commands use it as
    the sole reader/copy input after their original source guard begins: later
    path substitutions in the user tree cannot redirect a preview, parser, or
    payload copy.  It requires temporary storage roughly proportional to the
    source content.  Secure command staging fails closed when descriptor-
    relative no-follow APIs are unavailable; the lower-level static helpers
    remain separately portable but do not provide this traversal guarantee.
    """
    source = Path(source)
    if not _supports_component_nofollow():
        raise UnsupportedInput(
            "secure source staging requires descriptor-relative no-follow filesystem support",
            cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
            mitigation="run this conversion on a platform with O_NOFOLLOW, O_DIRECTORY, and dir_fd support",
        )
    temporary_parent = realpath(Path(tempfile.gettempdir()))
    canonical_source = source if source_is_canonical else realpath(source)
    protected_paths = (canonical_source, *(realpath(path) for path in forbidden_paths))
    if any(_is_within(temporary_parent, protected) for protected in protected_paths):
        raise PolicyRefusal(
            f"private source staging directory would be inside a protected path: {temporary_parent}",
            cause=vocab.CAUSE_FORCED_IN_PLACE_REFUSED,
            mitigation="set TMPDIR to a directory outside the source and output paths",
        )
    with tempfile.TemporaryDirectory(prefix="nirs4all-tools-source-", dir=temporary_parent) as temporary_name:
        temporary_root = Path(temporary_name)
        os.chmod(temporary_root, 0o700)
        destination = temporary_root / (source.name or "source")
        try:
            source_lstat = os.lstat(source)
        except FileNotFoundError:
            # Preserve detector semantics for a missing root without ever
            # handing later readers the original path.
            yield MaterializedSource(destination, TreeSnapshot(root=source, entries={}, root_signature=None))
            return
        except OSError as exc:
            detail = f"cannot inspect source ({exc.strerror or exc.__class__.__name__})"
            raise _source_shape_refusal(source, detail) from exc

        if stat.S_ISLNK(source_lstat.st_mode):
            raise _source_shape_refusal(source, "root is a symlink; resolve only the user-supplied command root first")
        if stat.S_ISREG(source_lstat.st_mode):
            source_descriptor, source_stat = _open_regular_source_file(source)
            if not _same_source_identity(source_lstat, source_stat):
                os.close(source_descriptor)
                raise SourceIntegrityError(
                    f"source changed while it was materialized: {source}",
                    cause=vocab.CAUSE_RUNTIME_ERROR,
                    mitigation="rerun migration against a stable source",
                )
            digest = _copy_open_regular_file(
                source_descriptor,
                source_stat,
                destination,
                display_source=source,
                private_destination=True,
            )
            yield MaterializedSource(
                destination,
                TreeSnapshot(
                    root=source,
                    entries={".": (source_stat.st_size, source_stat.st_mtime_ns, digest)},
                    root_signature=_source_node_signature(source_stat),
                ),
            )
            return
        if not stat.S_ISDIR(source_lstat.st_mode):
            raise _source_shape_refusal(source, "root is neither a regular file nor a directory")

        source_descriptor, source_stat = _open_directory_source(source)
        if not _same_source_identity(source_lstat, source_stat):
            os.close(source_descriptor)
            raise SourceIntegrityError(
                f"source changed while it was materialized: {source}",
                cause=vocab.CAUSE_RUNTIME_ERROR,
                mitigation="rerun migration against a stable source",
            )
        entries: dict[str, tuple[int, int, str | None]] = {}
        try:
            _copy_bound_source_directory(
                source_descriptor,
                source_stat,
                destination,
                relative_prefix="",
                entries=entries,
            )
        finally:
            os.close(source_descriptor)
        yield MaterializedSource(
            destination,
            TreeSnapshot(root=source, entries=entries, root_signature=_source_node_signature(source_stat)),
        )


def assert_disjoint(source: Path, output: Path, *, source_is_canonical: bool = False) -> None:
    """Refuse aliased or in-place output.

    ``realpath(output)`` must not equal, contain, or be contained by
    ``realpath(source)`` (``SW4_MIG_CONVERTER_spec.md`` §3.2).
    """
    src = Path(source) if source_is_canonical else realpath(source)
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


def assert_path_outside_source(source: Path, path: Path, *, source_is_canonical: bool = False) -> None:
    """Refuse a report/manifest path that resolves inside the source tree.

    ``inspect`` and ``--dry-run`` may write only to paths outside the source
    (``SW4_MIG_CONVERTER_spec.md`` §6, §11).
    """
    src = Path(source) if source_is_canonical else realpath(source)
    target = realpath(path)
    if _is_within(target, src):
        raise PolicyRefusal(
            f"refusing to write {target} inside the source tree {src}",
            cause=vocab.CAUSE_FORCED_IN_PLACE_REFUSED,
            mitigation="point --report/--manifest at a path outside the source workspace",
        )


def assert_output_available(output: Path, *, resume: bool = False) -> None:
    """Refuse a non-empty output directory.

    A path that exists but is not a directory is always refused
    (``SW4_MIG_CONVERTER_spec.md`` §3.3). ``migrate`` handles ``--resume``
    before this guard through its complete-contract attestation; the parameter
    remains only for compatibility with existing internal callers.
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
    if any(out.iterdir()):
        raise PolicyRefusal(
            f"output directory is not empty: {out}",
            cause=vocab.CAUSE_NON_EMPTY_OUTPUT,
            mitigation="use a fresh empty directory, or pass --resume only for a complete verified prior output",
        )


@dataclass(frozen=True)
class TreeSnapshot:
    """An ordered ``(relative path -> (size, mtime_ns, sha256))`` map of a tree.

    Directories are recorded with ``size == -1`` so that an added or removed
    empty directory is still detected.
    """

    root: Path
    entries: dict[str, tuple[int, int, str | None]] = field(default_factory=dict)
    root_signature: tuple[int, int, int, int, int] | None = None


@dataclass(frozen=True)
class MaterializedSource:
    """A private reader stage plus its descriptor-bound original snapshot."""

    path: Path
    source_snapshot: TreeSnapshot


def snapshot_tree(root: Path) -> TreeSnapshot:
    """Snapshot ``(size, mtime_ns, sha256)`` for every path under ``root``.

    Works for both a single file and a directory tree. A missing root yields an
    empty snapshot rather than raising, so the guard can run on abort paths.
    """
    root = realpath(root)
    entries: dict[str, tuple[int, int, str | None]] = {}
    try:
        root_stat = root.lstat()
    except FileNotFoundError:
        return TreeSnapshot(root=root, entries=entries, root_signature=None)
    except OSError:
        entries["."] = (-2, 0, None)
        return TreeSnapshot(root=root, entries=entries, root_signature=None)
    if stat.S_ISREG(root_stat.st_mode):
        try:
            entries["."] = (root_stat.st_size, root_stat.st_mtime_ns, sha256_file(root))
        except OSError:
            entries["."] = (-2, root_stat.st_mtime_ns, None)
        return TreeSnapshot(root=root, entries=entries, root_signature=_source_node_signature(root_stat))
    if not stat.S_ISDIR(root_stat.st_mode):
        entries["."] = (-2, root_stat.st_mtime_ns, None)
        return TreeSnapshot(root=root, entries=entries, root_signature=_source_node_signature(root_stat))
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        for name in list(dirnames):
            path = base / name
            relative = os.path.relpath(path, root)
            try:
                source_stat = path.lstat()
            except OSError:
                entries[relative] = (-1, 0, None)
                dirnames.remove(name)
                continue
            if stat.S_ISDIR(source_stat.st_mode):
                entries[relative] = (-1, source_stat.st_mtime_ns, None)
            elif stat.S_ISLNK(source_stat.st_mode):
                entries[relative] = (-3, source_stat.st_mtime_ns, None)
                dirnames.remove(name)
            else:
                entries[relative] = (-2, source_stat.st_mtime_ns, None)
                dirnames.remove(name)
        for name in filenames:
            path = base / name
            relative = os.path.relpath(path, root)
            try:
                source_stat = path.lstat()
            except OSError:
                entries[relative] = (-2, 0, None)
                continue
            if stat.S_ISREG(source_stat.st_mode):
                try:
                    entries[relative] = (source_stat.st_size, source_stat.st_mtime_ns, sha256_file(path))
                except OSError:
                    entries[relative] = (-2, source_stat.st_mtime_ns, None)
            elif stat.S_ISLNK(source_stat.st_mode):
                entries[relative] = (-3, source_stat.st_mtime_ns, None)
            else:
                entries[relative] = (-2, source_stat.st_mtime_ns, None)
    return TreeSnapshot(root=root, entries=entries, root_signature=_source_node_signature(root_stat))


def _sha256_open_regular_file(
    source_descriptor: int,
    source_stat: os.stat_result,
    *,
    display_path: Path | str,
) -> str:
    """Hash one already-bound source descriptor and take ownership of it."""
    descriptor: int | None = source_descriptor
    digest = hashlib.sha256()
    try:
        if descriptor is None:
            raise AssertionError("source descriptor ownership was lost before snapshotting")
        handle = os.fdopen(descriptor, "rb")
        descriptor = None
        with handle:
            remaining = source_stat.st_size
            while remaining:
                chunk = handle.read(min(_COPY_CHUNK_BYTES, remaining))
                if not chunk:
                    raise SourceIntegrityError(
                        f"source file changed while it was snapshotted: {display_path}",
                        cause=vocab.CAUSE_RUNTIME_ERROR,
                        mitigation="rerun migration against a stable source",
                    )
                digest.update(chunk)
                remaining -= len(chunk)
            if not _same_source_file_metadata(os.fstat(handle.fileno()), source_stat):
                raise SourceIntegrityError(
                    f"source file changed while it was snapshotted: {display_path}",
                    cause=vocab.CAUSE_RUNTIME_ERROR,
                    mitigation="rerun migration against a stable source",
                )
        return f"sha256:{digest.hexdigest()}"
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _snapshot_bound_source_directory(
    source_descriptor: int,
    source_stat: os.stat_result,
    *,
    relative_prefix: str,
    entries: dict[str, tuple[int, int, str | None]],
) -> None:
    """Capture one source directory entirely through bound no-follow FDs."""
    try:
        names = sorted(os.listdir(source_descriptor))
    except OSError as exc:
        detail = f"cannot list directory ({exc.strerror or exc.__class__.__name__})"
        raise _source_shape_refusal(relative_prefix or ".", detail) from exc

    for name in names:
        relative = f"{relative_prefix}/{name}" if relative_prefix else name
        try:
            child_lstat = os.lstat(name, dir_fd=source_descriptor)
        except OSError as exc:
            detail = f"cannot inspect entry ({exc.strerror or exc.__class__.__name__})"
            raise _source_shape_refusal(relative, detail) from exc
        if stat.S_ISLNK(child_lstat.st_mode):
            raise _source_shape_refusal(relative, "descendant symlinks are not supported")
        if stat.S_ISREG(child_lstat.st_mode):
            child_descriptor, child_stat = _open_child_nofollow(
                source_descriptor,
                name,
                directory=False,
                display_path=relative,
                expected_stat=child_lstat,
            )
            digest = _sha256_open_regular_file(child_descriptor, child_stat, display_path=relative)
            entries[relative] = (child_stat.st_size, child_stat.st_mtime_ns, digest)
            continue
        if stat.S_ISDIR(child_lstat.st_mode):
            child_descriptor, child_stat = _open_child_nofollow(
                source_descriptor,
                name,
                directory=True,
                display_path=relative,
                expected_stat=child_lstat,
            )
            entries[relative] = (-1, child_stat.st_mtime_ns, None)
            try:
                _snapshot_bound_source_directory(
                    child_descriptor,
                    child_stat,
                    relative_prefix=relative,
                    entries=entries,
                )
            finally:
                os.close(child_descriptor)
            continue
        raise _source_shape_refusal(relative, "entry is neither a regular file nor a directory")

    if not _same_source_file_metadata(os.fstat(source_descriptor), source_stat):
        raise SourceIntegrityError(
            f"source directory changed while it was snapshotted: {relative_prefix or '.'}",
            cause=vocab.CAUSE_RUNTIME_ERROR,
            mitigation="rerun migration against a stable source",
        )


def snapshot_tree_nofollow(root: Path) -> TreeSnapshot:
    """Capture a source snapshot without resolving or traversing path links.

    This is the command-level integrity capture for user source paths.  It
    requires descriptor-relative ``O_NOFOLLOW`` support and deliberately does
    not fall back to pathname traversal: source staging and source guards must
    fail closed when that binding is unavailable.
    """
    root = Path(root)
    if not _supports_component_nofollow():
        raise UnsupportedInput(
            "secure source snapshots require descriptor-relative no-follow filesystem support",
            cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
            mitigation="run this conversion on a platform with O_NOFOLLOW, O_DIRECTORY, and dir_fd support",
        )
    try:
        root_lstat = os.lstat(root)
    except FileNotFoundError:
        return TreeSnapshot(root=root, entries={}, root_signature=None)
    except OSError as exc:
        detail = f"cannot inspect source ({exc.strerror or exc.__class__.__name__})"
        raise _source_shape_refusal(root, detail) from exc
    if stat.S_ISLNK(root_lstat.st_mode):
        raise _source_shape_refusal(root, "root is a symlink; resolve only the user-supplied command root first")
    if stat.S_ISREG(root_lstat.st_mode):
        descriptor, source_stat = _open_regular_source_file(root)
        if not _same_source_identity(root_lstat, source_stat):
            os.close(descriptor)
            raise SourceIntegrityError(
                f"source changed while it was snapshotted: {root}",
                cause=vocab.CAUSE_RUNTIME_ERROR,
                mitigation="rerun migration against a stable source",
            )
        digest = _sha256_open_regular_file(descriptor, source_stat, display_path=root)
        return TreeSnapshot(
            root=root,
            entries={".": (source_stat.st_size, source_stat.st_mtime_ns, digest)},
            root_signature=_source_node_signature(source_stat),
        )
    if not stat.S_ISDIR(root_lstat.st_mode):
        raise _source_shape_refusal(root, "root is neither a regular file nor a directory")

    descriptor, source_stat = _open_directory_source(root)
    if not _same_source_identity(root_lstat, source_stat):
        os.close(descriptor)
        raise SourceIntegrityError(
            f"source changed while it was snapshotted: {root}",
            cause=vocab.CAUSE_RUNTIME_ERROR,
            mitigation="rerun migration against a stable source",
        )
    entries: dict[str, tuple[int, int, str | None]] = {}
    try:
        _snapshot_bound_source_directory(descriptor, source_stat, relative_prefix="", entries=entries)
    finally:
        os.close(descriptor)
    return TreeSnapshot(root=root, entries=entries, root_signature=_source_node_signature(source_stat))


def diff_snapshots(before: TreeSnapshot, after: TreeSnapshot) -> list[str]:
    """Return the sorted relative paths that were added, removed, or changed."""
    changed: set[str] = set()
    if before.root_signature != after.root_signature:
        changed.add(".")
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


@contextmanager
def source_guard_nofollow(source: Path, *, before: TreeSnapshot | None = None) -> Iterator[None]:
    """Descriptor-bound source guard for user paths.

    ``before`` is normally captured while the private source stage is copied,
    avoiding a second pathname-based read before readers begin.  The final
    capture uses only directory-relative no-follow descriptors; an unsafe
    shape that appears during the operation is reported as source-integrity
    failure rather than becoming a later reader input.
    """
    before_snapshot = before if before is not None else snapshot_tree_nofollow(source)
    try:
        yield
    finally:
        try:
            after_snapshot = snapshot_tree_nofollow(source)
        except UnsupportedInput as exc:
            raise SourceIntegrityError(
                "source tree became unsafe during the operation",
                cause=vocab.CAUSE_RUNTIME_ERROR,
                mitigation="rerun migration against a stable source",
            ) from exc
        changes = diff_snapshots(before_snapshot, after_snapshot)
        if changes:
            preview = ", ".join(changes[:5])
            raise SourceIntegrityError(
                f"source tree changed during the operation ({len(changes)} path(s): {preview})",
                cause=vocab.CAUSE_RUNTIME_ERROR,
                mitigation="rerun migration against a stable source",
            )


__all__ = [
    "realpath",
    "read_only_sqlite_uri",
    "assert_safe_source_tree",
    "copy_regular_file_nofollow",
    "materialized_source_tree_nofollow",
    "assert_disjoint",
    "assert_path_outside_source",
    "assert_output_available",
    "TreeSnapshot",
    "MaterializedSource",
    "snapshot_tree",
    "snapshot_tree_nofollow",
    "diff_snapshots",
    "source_guard",
    "source_guard_nofollow",
]

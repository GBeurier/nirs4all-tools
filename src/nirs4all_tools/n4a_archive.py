"""Fail-closed structural preflight for opaque legacy ``.n4a`` ZIP archives.

The migration tool never extracts, deserializes, or executes an ``.n4a``
payload.  It may preserve a structurally safe archive byte-for-byte, so this
module first bounds ZIP metadata and validates its small JSON manifest.  The
inspection is stdlib-only: it streams raw member bytes only to verify declared
CRC/length/DEFLATE boundaries and materializes only ``manifest.json``.
"""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import stat
import struct
import tempfile
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any, Final, NoReturn, cast

_EOCD_SIGNATURE: Final = b"PK\x05\x06"
_EOCD_STRUCT: Final = struct.Struct("<4s4H2LH")
_ZIP64_LOCATOR_SIGNATURE: Final = b"PK\x06\x07"
_ZIP64_LOCATOR_STRUCT: Final = struct.Struct("<4sLQL")
_ZIP64_EOCD_SIGNATURE: Final = b"PK\x06\x06"
_ZIP64_EOCD_STRUCT: Final = struct.Struct("<4sQ2H2L4Q")
_CENTRAL_DIRECTORY_SIGNATURE: Final = b"PK\x01\x02"
_CENTRAL_DIRECTORY_STRUCT: Final = struct.Struct("<4s6H3L5H2L")
_LOCAL_FILE_HEADER_SIGNATURE: Final = b"PK\x03\x04"
_LOCAL_FILE_HEADER_STRUCT: Final = struct.Struct("<4s5H3L2H")
_DATA_DESCRIPTOR_SIGNATURE: Final = b"PK\x07\x08"
_DATA_DESCRIPTOR_32_STRUCT: Final = struct.Struct("<LLL")
_DATA_DESCRIPTOR_64_STRUCT: Final = struct.Struct("<LQQ")
_DATA_DESCRIPTOR_32_WITH_SIGNATURE_STRUCT: Final = struct.Struct("<4sLLL")
_DATA_DESCRIPTOR_64_WITH_SIGNATURE_STRUCT: Final = struct.Struct("<4sLQQ")
_ZIP64_EXTRA_FIELD_ID: Final = 0x0001
_ZIP64_SIZE_SENTINEL: Final = 0xFFFFFFFF
_FLAG_ENCRYPTED: Final = 0x0001
_FLAG_DATA_DESCRIPTOR: Final = 0x0008
_FLAG_STRONG_ENCRYPTION: Final = 0x0040
_FLAG_UTF8: Final = 0x0800
_ALLOWED_GENERAL_PURPOSE_FLAGS: Final = _FLAG_DATA_DESCRIPTOR | _FLAG_UTF8
_WINDOWS_FORBIDDEN_COMPONENT_CHARACTERS: Final = frozenset('<>:"\\|?*')
_WINDOWS_RESERVED_COMPONENTS: Final = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CLOCK$",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
        "COM¹",
        "COM²",
        "COM³",
        "LPT¹",
        "LPT²",
        "LPT³",
    }
)
_MAX_EOCD_SCAN_BYTES: Final = 65_535 + _EOCD_STRUCT.size
_PAYLOAD_READ_BYTES: Final = 64 * 1024
_UNSET: Final = object()


@dataclass(frozen=True)
class N4aArchiveLimits:
    """Explicit, non-CLI limits for untrusted legacy ZIP metadata and claims."""

    max_archive_bytes: int
    max_central_directory_bytes: int
    max_members: int
    max_manifest_bytes: int
    max_member_uncompressed_bytes: int
    max_total_uncompressed_bytes: int
    max_compression_ratio: int


DEFAULT_N4A_ARCHIVE_LIMITS: Final = N4aArchiveLimits(
    max_archive_bytes=8 * 1024 * 1024 * 1024,
    max_central_directory_bytes=16 * 1024 * 1024,
    max_members=10_000,
    max_manifest_bytes=1024 * 1024,
    max_member_uncompressed_bytes=2 * 1024 * 1024 * 1024,
    max_total_uncompressed_bytes=8 * 1024 * 1024 * 1024,
    max_compression_ratio=1_000,
)


class N4aArchiveRefusal(ValueError):
    """A machine-classified structural refusal for an untrusted ``.n4a`` ZIP."""

    def __init__(self, rule: str, detail: str) -> None:
        super().__init__(f"archive safety preflight refused ({rule}): {detail}")
        self.rule = rule


@dataclass(frozen=True)
class N4aArchiveInspection:
    """Detached metadata proven safe enough for opaque preservation only."""

    bundle_format_version: object | None
    archive_bytes: int
    central_directory_bytes: int
    member_count: int
    total_uncompressed_bytes: int
    content_sha256: str


@dataclass(frozen=True)
class _CentralDirectoryMember:
    """The small central-directory subset needed to cross-check local headers."""

    name: str
    flag_bits: int
    compression_method: int


@dataclass(frozen=True)
class _LocalMember:
    """A local header plus the first byte after its compressed payload."""

    info: zipfile.ZipInfo
    payload_start: int
    payload_end: int


def _refuse(rule: str, detail: str) -> NoReturn:
    raise N4aArchiveRefusal(rule, detail)


def _read_exact(handle: Any, size: int, *, rule: str, detail: str) -> bytes:
    data = cast(bytes, handle.read(size))
    if len(data) != size:
        _refuse(rule, detail)
    return data


def _open_archive_file(path: Path) -> Any:
    """Open an archive with the strongest no-follow semantics the OS exposes.

    CLI commands canonicalize their one user-provided root symlink before this
    point.  Nested archives must instead stay beneath their already-validated
    source tree.  POSIX descriptor-relative opens bind every component; the
    portable fallback preserves the existing final-path no-follow behavior
    where available and relies on the command-level source-shape preflight.
    """
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    flags = os.O_RDONLY | int(getattr(os, "O_NONBLOCK", 0))
    if isinstance(nofollow, int):
        flags |= nofollow
    for optional_flag in ("O_CLOEXEC", "O_BINARY"):
        flags |= int(getattr(os, optional_flag, 0))
    component_nofollow = (
        isinstance(nofollow, int)
        and isinstance(directory_flag, int)
        and os.open in os.supports_dir_fd
    )
    if not component_nofollow:
        descriptor = os.open(path, flags)
    else:
        assert isinstance(directory_flag, int)
        directory_flags = flags | directory_flag
        absolute = Path(os.path.abspath(os.fspath(path)))
        parts = absolute.parts
        if len(parts) < 2 or not absolute.is_absolute():
            raise OSError("archive path cannot be opened component-by-component")
        current_fd: int | None = None
        try:
            current_fd = os.open(parts[0], directory_flags)
            for component in parts[1:-1]:
                next_fd = os.open(component, directory_flags, dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
            descriptor = os.open(parts[-1], flags, dir_fd=current_fd)
        finally:
            if current_fd is not None:
                os.close(current_fd)
    try:
        return os.fdopen(descriptor, "rb")
    except Exception:
        os.close(descriptor)
        raise


def _validated_regular_archive_stat(handle: Any, limits: N4aArchiveLimits) -> os.stat_result:
    """Return a bounded regular-file snapshot before untrusted reads occur."""
    source_stat = os.fstat(handle.fileno())
    if not stat.S_ISREG(source_stat.st_mode):
        _refuse("invalid_zip", "archive path is not a regular file")
    if source_stat.st_size > limits.max_archive_bytes:
        _refuse("archive_size", "compressed archive exceeds the configured safety limit")
    return source_stat


def _sha256_exact(handle: Any, byte_count: int, *, detail: str) -> str:
    """Hash exactly a pre-bounded descriptor span without following later growth."""
    digest = hashlib.sha256()
    remaining = byte_count
    handle.seek(0)
    while remaining:
        chunk = _read_exact(
            handle,
            min(_PAYLOAD_READ_BYTES, remaining),
            rule="archive_changed",
            detail=detail,
        )
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.hexdigest()


def _copy_exact(handle: Any, destination: Any, byte_count: int) -> None:
    """Copy exactly the validated source size, never an attacker-extended EOF."""
    remaining = byte_count
    handle.seek(0)
    while remaining:
        chunk = _read_exact(
            handle,
            min(_PAYLOAD_READ_BYTES, remaining),
            rule="archive_changed",
            detail="archive became shorter while it was copied",
        )
        destination.write(chunk)
        remaining -= len(chunk)


def _expected_digest_hex(value: str) -> str:
    """Normalize a migration SHA-256 checksum to its 64 lowercase hex digits."""
    digest = value.removeprefix("sha256:")
    if len(digest) != 64 or any(character not in "0123456789abcdefABCDEF" for character in digest):
        _refuse("archive_changed", "migration supplied an invalid expected archive SHA-256 digest")
    return digest.lower()


def _zip_directory_bounds(handle: Any, archive_bytes: int, limits: N4aArchiveLimits) -> tuple[int, int, int]:
    """Read only the bounded EOCD/ZIP64 records before ``ZipFile`` allocates metadata."""
    tail_size = min(archive_bytes, _MAX_EOCD_SCAN_BYTES)
    handle.seek(archive_bytes - tail_size)
    tail = _read_exact(handle, tail_size, rule="invalid_zip", detail="cannot read ZIP end record")
    relative_eocd = -1
    cursor = len(tail)
    while True:
        cursor = tail.rfind(_EOCD_SIGNATURE, 0, cursor)
        if cursor < 0:
            break
        if cursor + _EOCD_STRUCT.size <= len(tail):
            candidate_comment_bytes = _EOCD_STRUCT.unpack_from(tail, cursor)[-1]
            if cursor + _EOCD_STRUCT.size + candidate_comment_bytes == len(tail):
                relative_eocd = cursor
                break
    if relative_eocd < 0:
        _refuse("invalid_zip", "missing ZIP end-of-central-directory record")
    eocd_offset = archive_bytes - tail_size + relative_eocd
    (
        _signature,
        disk_number,
        central_directory_disk,
        members_on_disk,
        member_count,
        central_directory_bytes,
        central_directory_offset,
        comment_bytes,
    ) = _EOCD_STRUCT.unpack_from(tail, relative_eocd)
    if eocd_offset + _EOCD_STRUCT.size + comment_bytes != archive_bytes:
        _refuse("invalid_zip", "has trailing bytes or an inconsistent ZIP comment length")
    if disk_number or central_directory_disk or members_on_disk != member_count:
        _refuse("invalid_zip", "uses unsupported multi-volume ZIP metadata")

    zip64 = member_count == 0xFFFF or central_directory_bytes == 0xFFFFFFFF or central_directory_offset == 0xFFFFFFFF
    central_directory_end = eocd_offset
    if zip64:
        locator_offset = eocd_offset - _ZIP64_LOCATOR_STRUCT.size
        if locator_offset < 0:
            _refuse("invalid_zip", "is missing the ZIP64 locator")
        handle.seek(locator_offset)
        locator = _read_exact(
            handle,
            _ZIP64_LOCATOR_STRUCT.size,
            rule="invalid_zip",
            detail="cannot read ZIP64 locator",
        )
        signature, record_disk, zip64_offset, total_disks = _ZIP64_LOCATOR_STRUCT.unpack(locator)
        if signature != _ZIP64_LOCATOR_SIGNATURE or record_disk or total_disks != 1:
            _refuse("invalid_zip", "uses invalid or multi-volume ZIP64 metadata")
        if zip64_offset + _ZIP64_EOCD_STRUCT.size > locator_offset:
            _refuse("invalid_zip", "has an out-of-bounds ZIP64 end record")
        handle.seek(zip64_offset)
        record = _read_exact(
            handle,
            _ZIP64_EOCD_STRUCT.size,
            rule="invalid_zip",
            detail="cannot read ZIP64 end record",
        )
        (
            signature,
            record_size,
            _version_made_by,
            _version_needed,
            record_disk,
            central_directory_disk,
            members_on_disk,
            member_count,
            central_directory_bytes,
            central_directory_offset,
        ) = _ZIP64_EOCD_STRUCT.unpack(record)
        if signature != _ZIP64_EOCD_SIGNATURE or record_size < 44:
            _refuse("invalid_zip", "has an invalid ZIP64 end record")
        if zip64_offset + 12 + record_size != locator_offset:
            _refuse("invalid_zip", "has a non-contiguous ZIP64 end record")
        if record_disk or central_directory_disk or members_on_disk != member_count:
            _refuse("invalid_zip", "uses unsupported multi-volume ZIP64 metadata")
        central_directory_end = zip64_offset

    if central_directory_bytes > limits.max_central_directory_bytes:
        _refuse("central_directory_size", "central directory exceeds the configured safety limit")
    if member_count > limits.max_members:
        _refuse("member_count", "archive contains more members than the configured safety limit")
    actual_central_directory_offset = central_directory_end - central_directory_bytes
    if actual_central_directory_offset < 0 or central_directory_offset != actual_central_directory_offset:
        _refuse("invalid_zip", "uses unsupported prepended or non-contiguous ZIP data")
    if central_directory_offset + central_directory_bytes != central_directory_end:
        _refuse("invalid_zip", "central directory lies outside the archive bounds")
    return int(member_count), int(central_directory_bytes), int(central_directory_offset)


def _decode_member_name(raw_name: bytes, flag_bits: int, *, location: str) -> str:
    """Decode a raw ZIP name without allowing ``ZipInfo`` to hide a NUL."""
    if b"\x00" in raw_name:
        _refuse("unsafe_member_path", f"{location} member name contains a NUL byte")
    try:
        return raw_name.decode("utf-8" if flag_bits & 0x800 else "cp437")
    except UnicodeDecodeError as exc:
        _refuse("invalid_zip", f"{location} member name is not decodable: {exc}")


def _central_directory_members(
    handle: Any,
    *,
    central_directory_offset: int,
    central_directory_bytes: int,
    member_count: int,
) -> list[_CentralDirectoryMember]:
    """Decode raw central-directory names before ``ZipInfo`` can truncate a NUL."""
    handle.seek(central_directory_offset)
    directory = _read_exact(
        handle,
        central_directory_bytes,
        rule="invalid_zip",
        detail="cannot read ZIP central directory",
    )

    members: list[_CentralDirectoryMember] = []
    cursor = 0
    for _ in range(member_count):
        if cursor + _CENTRAL_DIRECTORY_STRUCT.size > len(directory):
            _refuse("invalid_zip", "central directory ends before all declared members")
        (
            signature,
            _version_made_by,
            _version_needed,
            flag_bits,
            _compression,
            _modified_time,
            _modified_date,
            _crc,
            _compressed_size,
            _uncompressed_size,
            name_bytes,
            extra_bytes,
            comment_bytes,
            disk_start,
            _internal_attributes,
            _external_attributes,
            _header_offset,
        ) = _CENTRAL_DIRECTORY_STRUCT.unpack_from(directory, cursor)
        if signature != _CENTRAL_DIRECTORY_SIGNATURE:
            _refuse("invalid_zip", "central directory has an invalid member header")
        if disk_start:
            _refuse("invalid_zip", "central directory member belongs to another ZIP volume")
        name_start = cursor + _CENTRAL_DIRECTORY_STRUCT.size
        name_end = name_start + name_bytes
        next_member = name_end + extra_bytes + comment_bytes
        if next_member > len(directory):
            _refuse("invalid_zip", "central directory member exceeds its declared bounds")
        raw_name = directory[name_start:name_end]
        members.append(
            _CentralDirectoryMember(
                name=_decode_member_name(raw_name, flag_bits, location="central-directory"),
                flag_bits=flag_bits,
                compression_method=_compression,
            )
        )
        cursor = next_member
    if cursor != len(directory):
        _refuse("invalid_zip", "central directory has trailing unsupported records")
    return members


def _normalised_member_name(name: str, *, is_dir: bool) -> str:
    """Validate one portable relative member path and return its collision key."""
    if not name:
        _refuse("unsafe_member_path", "archive contains an empty member name")
    if any(ord(character) < 32 for character in name):
        _refuse("unsafe_member_path", f"member {name!r} contains a control character")
    if "\\" in name:
        _refuse("unsafe_member_path", f"member {name!r} uses a backslash path separator")
    if name.startswith("/") or PureWindowsPath(name).drive:
        _refuse("unsafe_member_path", f"member {name!r} is absolute or drive-qualified")

    parts = name.split("/")
    if is_dir:
        if parts[-1] != "":
            _refuse("unsafe_member_path", f"directory member {name!r} lacks a trailing slash")
        parts = parts[:-1]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        _refuse("unsafe_member_path", f"member {name!r} is ambiguous or traverses a parent")

    for part in parts:
        if part.endswith((".", " ")):
            _refuse("unsafe_member_path", f"member {name!r} has a Windows-ambiguous component")
        if any(character in _WINDOWS_FORBIDDEN_COMPONENT_CHARACTERS for character in part):
            _refuse("unsafe_member_path", f"member {name!r} contains a Windows-reserved character")
        reserved_stem = part.split(".", 1)[0].upper()
        if reserved_stem in _WINDOWS_RESERVED_COMPONENTS:
            _refuse("unsafe_member_path", f"member {name!r} uses a Windows-reserved device name")

    return unicodedata.normalize("NFC", "/".join(parts)).casefold()


def _resolve_local_zip64_sizes(
    extra: bytes,
    *,
    compressed_size: int,
    uncompressed_size: int,
    member_name: str,
) -> tuple[int, int]:
    """Resolve the local ZIP64 size extra when 32-bit fields use sentinels."""
    need_uncompressed = uncompressed_size == _ZIP64_SIZE_SENTINEL
    need_compressed = compressed_size == _ZIP64_SIZE_SENTINEL
    if not need_uncompressed and not need_compressed:
        return compressed_size, uncompressed_size

    cursor = 0
    zip64: bytes | None = None
    while cursor < len(extra):
        if cursor + 4 > len(extra):
            _refuse("invalid_zip", f"member {member_name!r} has a truncated local extra field")
        field_id, field_bytes = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        field_end = cursor + field_bytes
        if field_end > len(extra):
            _refuse("invalid_zip", f"member {member_name!r} local extra field exceeds its bounds")
        if field_id == _ZIP64_EXTRA_FIELD_ID:
            if zip64 is not None:
                _refuse("invalid_zip", f"member {member_name!r} repeats its ZIP64 local extra field")
            zip64 = extra[cursor:field_end]
        cursor = field_end
    if zip64 is None:
        _refuse("invalid_zip", f"member {member_name!r} is missing its ZIP64 local size extra field")

    needed_bytes = 8 * (need_uncompressed + need_compressed)
    if len(zip64) != needed_bytes:
        _refuse("invalid_zip", f"member {member_name!r} has an ambiguous ZIP64 local size extra field")
    offset = 0
    if need_uncompressed:
        uncompressed_size = struct.unpack_from("<Q", zip64, offset)[0]
        offset += 8
    if need_compressed:
        compressed_size = struct.unpack_from("<Q", zip64, offset)[0]
    return compressed_size, uncompressed_size


def _validate_local_header(
    handle: Any,
    info: zipfile.ZipInfo,
    central_member: _CentralDirectoryMember,
    *,
    central_directory_offset: int,
) -> _LocalMember:
    """Require every local header to agree with its bounded central entry."""
    local_header_offset = info.header_offset
    if local_header_offset < 0 or local_header_offset + _LOCAL_FILE_HEADER_STRUCT.size > central_directory_offset:
        _refuse("invalid_zip", f"member {central_member.name!r} has an out-of-bounds local header")
    handle.seek(local_header_offset)
    raw_header = _read_exact(
        handle,
        _LOCAL_FILE_HEADER_STRUCT.size,
        rule="invalid_zip",
        detail=f"cannot read local header for member {central_member.name!r}",
    )
    (
        signature,
        _version_needed,
        flag_bits,
        compression_method,
        _modified_time,
        _modified_date,
        crc,
        compressed_size,
        uncompressed_size,
        name_bytes,
        extra_bytes,
    ) = _LOCAL_FILE_HEADER_STRUCT.unpack(raw_header)
    if signature != _LOCAL_FILE_HEADER_SIGNATURE:
        _refuse("invalid_zip", f"member {central_member.name!r} has an invalid local-header signature")
    name_end = local_header_offset + _LOCAL_FILE_HEADER_STRUCT.size + name_bytes + extra_bytes
    if name_end > central_directory_offset:
        _refuse("invalid_zip", f"member {central_member.name!r} local header exceeds archive data bounds")
    raw_name = _read_exact(
        handle,
        name_bytes,
        rule="invalid_zip",
        detail=f"cannot read local name for member {central_member.name!r}",
    )
    raw_extra = _read_exact(
        handle,
        extra_bytes,
        rule="invalid_zip",
        detail=f"cannot read local extra field for member {central_member.name!r}",
    )
    local_name = _decode_member_name(raw_name, flag_bits, location="local-header")
    _normalised_member_name(local_name, is_dir=local_name.endswith("/"))
    if local_name != central_member.name:
        _refuse("invalid_zip", f"member {central_member.name!r} local name does not match central directory")
    if flag_bits != central_member.flag_bits or compression_method != central_member.compression_method:
        _refuse("invalid_zip", f"member {central_member.name!r} local header disagrees with central directory")
    if flag_bits & 0x8:
        local_sizes_absent = not compressed_size and not uncompressed_size
        local_zip64_sizes = compressed_size == _ZIP64_SIZE_SENTINEL and uncompressed_size == _ZIP64_SIZE_SENTINEL
        if crc or not (local_sizes_absent or local_zip64_sizes):
            _refuse(
                "invalid_zip",
                f"member {central_member.name!r} data-descriptor local header must not declare sizes or CRC",
            )
        if local_zip64_sizes:
            compressed_size, uncompressed_size = _resolve_local_zip64_sizes(
                raw_extra,
                compressed_size=compressed_size,
                uncompressed_size=uncompressed_size,
                member_name=central_member.name,
            )
            if (compressed_size, uncompressed_size) != (info.compress_size, info.file_size):
                _refuse(
                    "invalid_zip",
                    f"member {central_member.name!r} ZIP64 local sizes disagree with central directory",
                )
    else:
        compressed_size, uncompressed_size = _resolve_local_zip64_sizes(
            raw_extra,
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            member_name=central_member.name,
        )
    if not flag_bits & 0x8 and (crc, compressed_size, uncompressed_size) != (
        info.CRC,
        info.compress_size,
        info.file_size,
    ):
        _refuse("invalid_zip", f"member {central_member.name!r} local sizes or CRC disagree with central directory")
    payload_end = name_end + cast(int, info.compress_size)
    if payload_end > central_directory_offset:
        _refuse("invalid_zip", f"member {central_member.name!r} payload exceeds archive data bounds")
    return _LocalMember(info=info, payload_start=name_end, payload_end=cast(int, payload_end))


def _validate_data_descriptor(
    handle: Any,
    *,
    info: zipfile.ZipInfo,
    descriptor_offset: int,
    descriptor_bytes: int,
) -> None:
    """Require an exact, canonical descriptor for a bit-3 ZIP member."""
    if descriptor_bytes not in {12, 16, 20, 24}:
        _refuse("invalid_zip", f"member {info.filename!r} has a non-canonical data descriptor length")
    handle.seek(descriptor_offset)
    raw = _read_exact(
        handle,
        descriptor_bytes,
        rule="invalid_zip",
        detail=f"cannot read data descriptor for member {info.filename!r}",
    )
    if descriptor_bytes == 24:
        signature, crc, compressed_size, uncompressed_size = _DATA_DESCRIPTOR_64_WITH_SIGNATURE_STRUCT.unpack(raw)
        if signature != _DATA_DESCRIPTOR_SIGNATURE:
            _refuse("invalid_zip", f"member {info.filename!r} data descriptor lacks its signature")
    elif descriptor_bytes == 20:
        crc, compressed_size, uncompressed_size = _DATA_DESCRIPTOR_64_STRUCT.unpack(raw)
    elif descriptor_bytes == 16:
        signature, crc, compressed_size, uncompressed_size = _DATA_DESCRIPTOR_32_WITH_SIGNATURE_STRUCT.unpack(raw)
        if signature != _DATA_DESCRIPTOR_SIGNATURE:
            _refuse("invalid_zip", f"member {info.filename!r} data descriptor lacks its signature")
    else:
        crc, compressed_size, uncompressed_size = _DATA_DESCRIPTOR_32_STRUCT.unpack(raw)
    if (crc, compressed_size, uncompressed_size) != (info.CRC, info.compress_size, info.file_size):
        _refuse("invalid_zip", f"member {info.filename!r} data descriptor disagrees with central directory")


def _validate_local_member_coverage(
    handle: Any,
    members: list[_LocalMember],
    *,
    central_directory_offset: int,
) -> None:
    """Reject unreferenced local headers or opaque gaps before the central directory."""
    ordered = sorted(members, key=lambda item: item.info.header_offset)
    if not ordered or ordered[0].info.header_offset != 0:
        _refuse("invalid_zip", "archive data does not begin with a referenced local header")
    for index, member in enumerate(ordered):
        info = member.info
        next_offset = ordered[index + 1].info.header_offset if index + 1 < len(ordered) else central_directory_offset
        if info.flag_bits & 0x8:
            _validate_data_descriptor(
                handle,
                info=info,
                descriptor_offset=member.payload_end,
                descriptor_bytes=next_offset - member.payload_end,
            )
        elif next_offset != member.payload_end:
            _refuse("invalid_zip", f"member {info.filename!r} leaves unreferenced bytes before the next member")


def _validate_member_payload(
    handle: Any,
    member: _LocalMember,
    *,
    capture: bool,
) -> bytes | None:
    """Stream one payload to prove its declared ZIP metadata is not a claim.

    Opaque payload bytes are never retained.  The sole captured member is the
    already-bounded manifest, whose JSON is parsed only after all members have
    passed their structural checks.
    """
    info = member.info
    handle.seek(member.payload_start)
    remaining = cast(int, info.compress_size)
    crc = 0
    output_bytes = 0
    captured = bytearray() if capture else None

    def accept_output(output: bytes) -> None:
        nonlocal crc, output_bytes
        output_bytes += len(output)
        if output_bytes > info.file_size:
            _refuse("invalid_zip", f"member {info.filename!r} expands beyond its central-directory size")
        crc = zlib.crc32(output, crc)
        if captured is not None:
            captured.extend(output)

    if info.compress_type == zipfile.ZIP_STORED:
        if info.file_size != info.compress_size:
            _refuse("invalid_zip", f"stored member {info.filename!r} has unequal compressed and plain sizes")
        while remaining:
            chunk = _read_exact(
                handle,
                min(_PAYLOAD_READ_BYTES, remaining),
                rule="invalid_zip",
                detail=f"cannot read stored payload for member {info.filename!r}",
            )
            remaining -= len(chunk)
            accept_output(chunk)
    else:
        decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
        while remaining:
            chunk = _read_exact(
                handle,
                min(_PAYLOAD_READ_BYTES, remaining),
                rule="invalid_zip",
                detail=f"cannot read DEFLATE payload for member {info.filename!r}",
            )
            remaining -= len(chunk)
            pending = chunk
            while pending:
                output_limit = min(_PAYLOAD_READ_BYTES, info.file_size - output_bytes + 1)
                output = decompressor.decompress(pending, output_limit)
                accept_output(output)
                pending = decompressor.unconsumed_tail
                if decompressor.eof:
                    if decompressor.unused_data or pending or remaining:
                        _refuse("invalid_zip", f"member {info.filename!r} has trailing bytes after DEFLATE EOF")
                    break
                if pending and not output:
                    _refuse("invalid_zip", f"member {info.filename!r} DEFLATE stream made no progress")
            if decompressor.eof:
                break
        if not decompressor.eof:
            _refuse("invalid_zip", f"member {info.filename!r} DEFLATE stream ends before EOF")

    if output_bytes != info.file_size or (crc & 0xFFFFFFFF) != info.CRC:
        _refuse("invalid_zip", f"member {info.filename!r} payload disagrees with central-directory CRC or size")
    return bytes(captured) if captured is not None else None


def _validate_member_kind(info: zipfile.ZipInfo) -> None:
    """Reject encrypted, symlink, and special ZIP members without opening them."""
    if info.flag_bits & (_FLAG_ENCRYPTED | _FLAG_STRONG_ENCRYPTION):
        _refuse("encrypted_member", f"member {info.filename!r} is encrypted")
    unsupported_flags = info.flag_bits & ~_ALLOWED_GENERAL_PURPOSE_FLAGS
    if unsupported_flags:
        _refuse(
            "unsupported_flags",
            f"member {info.filename!r} uses unsupported ZIP general-purpose flag bit(s) 0x{unsupported_flags:04x}",
        )
    if info.volume:
        _refuse("invalid_zip", f"member {info.filename!r} belongs to another ZIP volume")
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if kind and kind not in {stat.S_IFREG, stat.S_IFDIR}:
        _refuse("special_member", f"member {info.filename!r} is a symlink or special file")
    if info.is_dir() and kind == stat.S_IFREG:
        _refuse("special_member", f"regular member {info.filename!r} is marked as a directory")
    if not info.is_dir() and kind == stat.S_IFDIR:
        _refuse("special_member", f"directory member {info.filename!r} is marked as a regular file")


def _validate_member_size(info: zipfile.ZipInfo, limits: N4aArchiveLimits) -> None:
    """Bound one member's expansion and compression claim."""
    if info.file_size > limits.max_member_uncompressed_bytes:
        _refuse("member_size", f"member {info.filename!r} exceeds the per-member uncompressed limit")
    if info.file_size and (
        not info.compress_size or info.file_size > info.compress_size * limits.max_compression_ratio
    ):
        _refuse("compression_ratio", f"member {info.filename!r} exceeds the compression-ratio limit")


def _validate_member_compression(info: zipfile.ZipInfo) -> None:
    """Allow only codecs whose manifest reads retain a bounded output buffer."""
    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
        _refuse(
            "unsupported_compression",
            f"member {info.filename!r} uses an unsupported compression method for safe inspection",
        )


def _manifest_object(raw_manifest: bytes) -> dict[str, Any]:
    """Decode a finite JSON object while rejecting duplicate keys and constants."""

    def reject_constant(value: str) -> None:
        _refuse("manifest_json", f"manifest.json uses non-finite JSON constant {value!r}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _refuse("manifest_json", f"manifest.json repeats key {key!r}")
            result[key] = value
        return result

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            _refuse("manifest_json", f"manifest.json uses non-finite JSON number {value!r}")
        return parsed

    try:
        manifest: Any = json.loads(
            raw_manifest.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except N4aArchiveRefusal:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        _refuse("manifest_json", f"manifest.json is not valid UTF-8 JSON: {exc}")
    if not isinstance(manifest, dict):
        _refuse("manifest_json", "manifest.json is not an object")
    _validate_manifest_text(manifest)
    return cast(dict[str, Any], manifest)


def _validate_manifest_text(value: Any) -> None:
    """Reject manifest text unsafe for scalar Unicode or terminal rendering.

    ``json.loads`` accepts escaped lone UTF-16 surrogate code points.  They
    cannot be rendered or persisted safely by every consumer.  Escaped C0/C1
    controls likewise must not flow from an untrusted archive into terminal
    or log rendering.  Both are refused at the structural boundary.
    Iteration avoids adding a second recursion-depth limit after JSON parsing.
    """
    pending: list[Any] = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            if any("\ud800" <= codepoint <= "\udfff" for codepoint in current):
                _refuse("manifest_json", "manifest.json contains an isolated UTF-16 surrogate")
            if any(ord(codepoint) < 32 or 0x7F <= ord(codepoint) <= 0x9F for codepoint in current):
                _refuse("manifest_json", "manifest.json contains a control character")
            continue
        if isinstance(current, dict):
            pending.extend(current.keys())
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)


def _same_file_metadata(left: os.stat_result, right: os.stat_result) -> bool:
    """Return whether one open file retained its identity and content metadata."""
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
    )


def _inspect_open_archive(
    handle: Any,
    *,
    limits: N4aArchiveLimits,
) -> tuple[N4aArchiveInspection, os.stat_result]:
    """Inspect one already-open regular file, keeping ZIP reads on that descriptor."""
    source_stat = _validated_regular_archive_stat(handle, limits)
    archive_bytes = source_stat.st_size
    content_digest_before = _sha256_exact(
        handle,
        archive_bytes,
        detail="archive changed while its content digest was read before inspection",
    )
    if not _same_file_metadata(os.fstat(handle.fileno()), source_stat):
        _refuse("invalid_zip", "archive changed before ZIP metadata could be inspected")
    declared_member_count, central_directory_bytes, central_directory_offset = _zip_directory_bounds(
        handle,
        archive_bytes,
        limits,
    )
    central_members = _central_directory_members(
        handle,
        central_directory_offset=central_directory_offset,
        central_directory_bytes=central_directory_bytes,
        member_count=declared_member_count,
    )
    with zipfile.ZipFile(handle) as archive:
        members = archive.infolist()
        if len(members) != declared_member_count or len(central_members) != len(members):
            _refuse("invalid_zip", "ZIP central-directory member count changed during inspection")
        seen_names: set[str] = set()
        manifest_member: _LocalMember | None = None
        total_uncompressed_bytes = 0
        local_members: list[_LocalMember] = []
        for info, central_member in zip(members, central_members, strict=True):
            if info.filename != central_member.name:
                _refuse("invalid_zip", "ZIP library name does not match the raw central-directory name")
            if central_member.name == "manifest.json" and manifest_member is not None:
                _refuse("manifest_duplicate", "archive declares manifest.json more than once")
            normalized = _normalised_member_name(central_member.name, is_dir=info.is_dir())
            if normalized in seen_names:
                _refuse("duplicate_member", f"member {info.filename!r} collides after portable normalization")
            seen_names.add(normalized)
            local_member = _validate_local_header(
                handle,
                info,
                central_member,
                central_directory_offset=central_directory_offset,
            )
            local_members.append(local_member)
            if central_member.name == "manifest.json":
                manifest_member = local_member
            _validate_member_kind(info)
            _validate_member_size(info, limits)
            _validate_member_compression(info)
            total_uncompressed_bytes += info.file_size
            if total_uncompressed_bytes > limits.max_total_uncompressed_bytes:
                _refuse("total_uncompressed_size", "archive exceeds the total uncompressed safety limit")

        _validate_local_member_coverage(
            handle,
            local_members,
            central_directory_offset=central_directory_offset,
        )
        if manifest_member is None:
            _refuse("manifest_missing", "archive is missing manifest.json at its root")
        if manifest_member.info.is_dir():
            _refuse("manifest_missing", "manifest.json is a directory")
        if manifest_member.info.file_size > limits.max_manifest_bytes:
            _refuse("manifest_size", "manifest.json exceeds the configured safety limit")
        raw_manifest: bytes | None = None
        for local_member in local_members:
            payload = _validate_member_payload(
                handle,
                local_member,
                capture=local_member is manifest_member,
            )
            if payload is not None:
                raw_manifest = payload

    if not _same_file_metadata(os.fstat(handle.fileno()), source_stat):
        _refuse("invalid_zip", "archive changed during inspection")
    content_digest_after = _sha256_exact(
        handle,
        archive_bytes,
        detail="archive changed while its content digest was read after inspection",
    )
    if not _same_file_metadata(os.fstat(handle.fileno()), source_stat) or content_digest_after != content_digest_before:
        _refuse("invalid_zip", "archive changed while its ZIP metadata was inspected")
    if raw_manifest is None:
        _refuse("manifest_missing", "archive is missing a readable manifest.json payload")
    if len(raw_manifest) > limits.max_manifest_bytes:
        _refuse("manifest_size", "manifest.json exceeds the configured safety limit")
    manifest = _manifest_object(raw_manifest)
    return (
        N4aArchiveInspection(
            bundle_format_version=manifest.get("bundle_format_version"),
            archive_bytes=archive_bytes,
            central_directory_bytes=central_directory_bytes,
            member_count=len(members),
            total_uncompressed_bytes=total_uncompressed_bytes,
            content_sha256=f"sha256:{content_digest_before}",
        ),
        source_stat,
    )


def inspect_n4a_archive(
    path: Path,
    *,
    limits: N4aArchiveLimits = DEFAULT_N4A_ARCHIVE_LIMITS,
) -> N4aArchiveInspection:
    """Inspect an untrusted ``.n4a`` without extraction or payload execution."""
    try:
        with _open_archive_file(Path(path)) as handle:
            inspection, _source_stat = _inspect_open_archive(handle, limits=limits)
            return inspection
    except N4aArchiveRefusal:
        raise
    except (EOFError, OSError, RuntimeError, zlib.error, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        _refuse("invalid_zip", f"cannot read ZIP metadata safely: {exc}")


def copy_validated_n4a_archive(
    source: Path,
    destination: Path,
    *,
    expected_bundle_format_version: object = _UNSET,
    expected_content_sha256: str | None = None,
    limits: N4aArchiveLimits = DEFAULT_N4A_ARCHIVE_LIMITS,
) -> N4aArchiveInspection:
    """Validate and byte-copy a bundle from one descriptor, without extracting it.

    When supplied, ``expected_content_sha256`` binds the final copied bytes to
    the source snapshot that drove detection, not merely to its manifest
    version.  The value may use the tool's ``sha256:`` prefix.
    """
    temporary: Path | None = None
    try:
        with _open_archive_file(Path(source)) as source_handle:
            inspection, source_stat = _inspect_open_archive(source_handle, limits=limits)
            source_digest = _expected_digest_hex(inspection.content_sha256)
            if expected_content_sha256 is not None and source_digest != _expected_digest_hex(expected_content_sha256):
                _refuse("archive_changed", "archive content digest changed after initial detection")
            if not _same_file_metadata(os.fstat(source_handle.fileno()), source_stat):
                _refuse("archive_changed", "archive changed after it was inspected for copying")
            if (
                expected_bundle_format_version is not _UNSET
                and inspection.bundle_format_version != expected_bundle_format_version
            ):
                _refuse("archive_changed", "archive declared version changed after detection")
            destination = Path(destination)
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
            temporary = Path(temporary_name)
            with os.fdopen(descriptor, "wb") as destination_handle:
                _copy_exact(source_handle, destination_handle, source_stat.st_size)
            if not _same_file_metadata(os.fstat(source_handle.fileno()), source_stat):
                _refuse("archive_changed", "archive changed while it was copied")
            with _open_archive_file(temporary) as copied_handle:
                copied_inspection, copied_stat = _inspect_open_archive(copied_handle, limits=limits)
                copied_digest = _expected_digest_hex(copied_inspection.content_sha256)
            if copied_inspection != inspection or copied_digest != source_digest:
                _refuse("archive_changed", "copied archive does not exactly match the validated source snapshot")
            os.chmod(temporary, stat.S_IMODE(source_stat.st_mode))
            os.utime(temporary, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns))
            os.replace(temporary, destination)
            temporary = None
            return inspection
    except N4aArchiveRefusal:
        raise
    except (EOFError, OSError, RuntimeError, zlib.error, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        if isinstance(exc, OSError) and exc.errno in {
            errno.ENOSPC,
            getattr(errno, "EDQUOT", None),
        }:
            raise
        _refuse("invalid_zip", f"cannot validate and copy ZIP safely: {exc}")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


__all__ = [
    "DEFAULT_N4A_ARCHIVE_LIMITS",
    "N4aArchiveInspection",
    "N4aArchiveLimits",
    "N4aArchiveRefusal",
    "copy_validated_n4a_archive",
    "inspect_n4a_archive",
]

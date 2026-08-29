"""Hostile structural preflight coverage for opaque ``.n4a`` archives."""

from __future__ import annotations

import os
import stat
import struct
import warnings
import zipfile
import zlib
from dataclasses import replace
from pathlib import Path

import pytest

from nirs4all_tools import n4a_archive
from nirs4all_tools.n4a_archive import (
    DEFAULT_N4A_ARCHIVE_LIMITS,
    N4aArchiveLimits,
    N4aArchiveRefusal,
    copy_validated_n4a_archive,
    inspect_n4a_archive,
)


def _write_bundle(path: Path, members: list[tuple[str, str | bytes]], *, compression: int = zipfile.ZIP_STORED) -> Path:
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for name, payload in members:
            archive.writestr(name, payload)
    return path


def _valid_members(*extra: tuple[str, str | bytes]) -> list[tuple[str, str | bytes]]:
    return [
        ("manifest.json", '{"bundle_format_version":"1.0"}'),
        ("chain.json", "{}"),
        *extra,
    ]


def _refusal(path: Path, *, limits: N4aArchiveLimits = DEFAULT_N4A_ARCHIVE_LIMITS) -> N4aArchiveRefusal:
    with pytest.raises(N4aArchiveRefusal) as raised:
        inspect_n4a_archive(path, limits=limits)
    return raised.value


def _write_descriptor_bundle(path: Path, descriptor: bytes) -> Path:
    """Build a canonical one-member ZIP with a caller-supplied descriptor."""
    _write_bundle(path, [("manifest.json", "{}")])
    raw = bytearray(path.read_bytes())
    local = raw.find(b"PK\x03\x04")
    central = raw.find(b"PK\x01\x02")
    assert local == 0 and central > 0
    local_flags = struct.unpack_from("<H", raw, local + 6)[0]
    central_flags = struct.unpack_from("<H", raw, central + 8)[0]
    struct.pack_into("<H", raw, local + 6, local_flags | 0x8)
    struct.pack_into("<H", raw, central + 8, central_flags | 0x8)
    struct.pack_into("<LLL", raw, local + 14, 0, 0, 0)
    raw[central:central] = descriptor
    eocd = raw.rfind(b"PK\x05\x06")
    assert eocd >= 0
    struct.pack_into("<L", raw, eocd + 16, central + len(descriptor))
    path.write_bytes(raw)
    return path


def _write_zip64_local_descriptor_bundle(
    path: Path,
    *,
    local_uncompressed_size: int = 2,
    local_compressed_size: int = 2,
) -> Path:
    """Build a bit-3 member with canonical ZIP64 local-size fields."""
    _write_descriptor_bundle(
        path,
        struct.pack("<4sLQQ", b"PK\x07\x08", zlib.crc32(b"{}"), 2, 2),
    )
    raw = bytearray(path.read_bytes())
    local = raw.find(b"PK\x03\x04")
    assert local == 0
    name_bytes = struct.unpack_from("<H", raw, local + 26)[0]
    extra_bytes = struct.unpack_from("<H", raw, local + 28)[0]
    assert extra_bytes == 0
    name_end = local + 30 + name_bytes
    zip64_extra = struct.pack(
        "<HHQQ",
        0x0001,
        16,
        local_uncompressed_size,
        local_compressed_size,
    )
    raw[name_end:name_end] = zip64_extra
    struct.pack_into("<L", raw, local + 18, 0xFFFFFFFF)
    struct.pack_into("<L", raw, local + 22, 0xFFFFFFFF)
    struct.pack_into("<H", raw, local + 28, len(zip64_extra))
    eocd = raw.rfind(b"PK\x05\x06")
    assert eocd >= 0
    central_offset = struct.unpack_from("<L", raw, eocd + 16)[0]
    struct.pack_into("<L", raw, eocd + 16, central_offset + len(zip64_extra))
    path.write_bytes(raw)
    return path


def test_inspect_n4a_archive_accepts_safe_opaque_zip(tmp_path: Path) -> None:
    archive = _write_bundle(tmp_path / "safe.n4a", _valid_members(("artifacts/step.joblib", b"opaque")))

    inspection = inspect_n4a_archive(archive)

    assert inspection.bundle_format_version == "1.0"
    assert inspection.member_count == 3
    assert inspection.archive_bytes == archive.stat().st_size
    assert inspection.total_uncompressed_bytes > 0
    assert inspection.content_sha256.startswith("sha256:")
    assert len(inspection.content_sha256) == len("sha256:") + 64


def test_inspect_n4a_archive_keeps_portable_fallback_without_posix_nofollow_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = _write_bundle(tmp_path / "safe.n4a", _valid_members())
    monkeypatch.delattr(n4a_archive.os, "O_NOFOLLOW", raising=False)
    monkeypatch.delattr(n4a_archive.os, "O_DIRECTORY", raising=False)

    inspection = inspect_n4a_archive(archive)

    assert inspection.bundle_format_version == "1.0"


def test_copy_validated_n4a_archive_keeps_the_validated_bytes_and_version(tmp_path: Path) -> None:
    archive = _write_bundle(tmp_path / "safe.n4a", _valid_members(("artifacts/step.joblib", b"opaque")))
    copied = tmp_path / "output" / "safe.n4a"

    inspection = copy_validated_n4a_archive(
        archive,
        copied,
        expected_bundle_format_version="1.0",
    )

    assert inspection.bundle_format_version == "1.0"
    assert copied.read_bytes() == archive.read_bytes()
    refused_copy = tmp_path / "other" / "safe.n4a"
    with pytest.raises(N4aArchiveRefusal) as raised:
        copy_validated_n4a_archive(archive, refused_copy, expected_bundle_format_version="2.0")
    assert raised.value.rule == "archive_changed"
    assert not refused_copy.exists()

    digest_mismatch = tmp_path / "digest-mismatch" / "safe.n4a"
    with pytest.raises(N4aArchiveRefusal) as raised:
        copy_validated_n4a_archive(
            archive,
            digest_mismatch,
            expected_content_sha256="sha256:" + "0" * 64,
        )
    assert raised.value.rule == "archive_changed"
    assert not digest_mismatch.exists()


def test_copy_validated_n4a_archive_rejects_a_same_size_mutation_after_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_bundle(
        tmp_path / "source.n4a",
        _valid_members(("safe/abcdef", b"A" * (2 * 1024 * 1024))),
    )
    hostile = _write_bundle(
        tmp_path / "hostile.n4a",
        _valid_members(("../evil/xxx", b"A" * (2 * 1024 * 1024))),
    )
    assert source.stat().st_size == hostile.stat().st_size
    destination = tmp_path / "output" / "source.n4a"
    original_inspect = n4a_archive._inspect_open_archive
    source_stat = source.stat()
    swapped = False

    def replace_after_inspection(handle, *, limits):
        nonlocal swapped
        inspection = original_inspect(handle, limits=limits)
        if not swapped:
            swapped = True
            source.write_bytes(hostile.read_bytes())
            os.utime(source, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns))
        return inspection

    monkeypatch.setattr(n4a_archive, "_inspect_open_archive", replace_after_inspection)

    with pytest.raises(N4aArchiveRefusal):
        copy_validated_n4a_archive(source, destination, expected_bundle_format_version="1.0")

    assert not destination.exists()


@pytest.mark.parametrize(
    ("members", "rule"),
    [
        ([("manifest.json", "{}"), ("../outside", "x")], "unsafe_member_path"),
        ([("manifest.json", "{}"), ("/absolute", "x")], "unsafe_member_path"),
        ([("manifest.json", "{}"), ("C:\\absolute", "x")], "unsafe_member_path"),
        ([("manifest.json", "{}"), ("folder\\member", "x")], "unsafe_member_path"),
        ([("manifest.json", "{}"), ("A", "x"), ("a", "y")], "duplicate_member"),
        ([("manifest.json", "{}"), ("café", "x"), ("café", "y")], "duplicate_member"),
        ([("manifest.json", "{}"), ("A", "x"), ("A.", "y")], "unsafe_member_path"),
        ([("manifest.json", "{}"), ("foo ", "x")], "unsafe_member_path"),
        ([("manifest.json", "{}"), ("a?b", "x")], "unsafe_member_path"),
        ([("manifest.json", "{}"), ("CON.txt", "x")], "unsafe_member_path"),
    ],
)
def test_inspect_n4a_archive_refuses_unsafe_member_paths_and_collisions(
    tmp_path: Path,
    members: list[tuple[str, str | bytes]],
    rule: str,
) -> None:
    archive = _write_bundle(tmp_path / "hostile.n4a", members)

    assert _refusal(archive).rule == rule


def test_inspect_n4a_archive_refuses_non_zip_and_symlink_member(tmp_path: Path) -> None:
    non_zip = tmp_path / "not-a-zip.n4a"
    non_zip.write_bytes(b"not a ZIP")
    assert _refusal(non_zip).rule == "invalid_zip"

    symlink = tmp_path / "symlink.n4a"
    with zipfile.ZipFile(symlink, "w") as archive:
        archive.writestr("manifest.json", "{}")
        info = zipfile.ZipInfo("artifacts/link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "target")
    assert _refusal(symlink).rule == "special_member"


@pytest.mark.parametrize(
    ("flag", "rule"),
    [
        (0x0001, "encrypted_member"),
        (0x0040, "encrypted_member"),
        (0x0020, "unsupported_flags"),
        (0x2000, "unsupported_flags"),
        (0x4000, "unsupported_flags"),
        (0x8000, "unsupported_flags"),
    ],
)
def test_inspect_n4a_archive_refuses_noncanonical_general_purpose_flags(
    tmp_path: Path,
    flag: int,
    rule: str,
) -> None:
    archive = _write_bundle(tmp_path / "flagged.n4a", [("manifest.json", "{}")])
    raw = bytearray(archive.read_bytes())
    local = raw.find(b"PK\x03\x04")
    central = raw.find(b"PK\x01\x02")
    assert local == 0 and central > 0
    struct.pack_into("<H", raw, local + 6, struct.unpack_from("<H", raw, local + 6)[0] | flag)
    struct.pack_into("<H", raw, central + 8, struct.unpack_from("<H", raw, central + 8)[0] | flag)
    archive.write_bytes(raw)

    assert _refusal(archive).rule == rule


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO semantics are unavailable on this platform")
def test_inspect_n4a_archive_refuses_a_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "untrusted.n4a"
    os.mkfifo(fifo)

    assert _refusal(fifo).rule == "invalid_zip"


def test_inspect_n4a_archive_refuses_a_raw_nul_member_name(tmp_path: Path) -> None:
    archive = _write_bundle(tmp_path / "nul.n4a", _valid_members(("evilABCD", "x")))
    raw = archive.read_bytes()
    assert raw.count(b"evilABCD") == 2  # local header and central directory
    archive.write_bytes(raw.replace(b"evilABCD", b"evil\x00BCD"))

    assert _refusal(archive).rule == "unsafe_member_path"


def test_inspect_n4a_archive_refuses_an_unsupported_manifest_compression_method(tmp_path: Path) -> None:
    archive = _write_bundle(tmp_path / "unsupported-method.n4a", _valid_members())
    raw = bytearray(archive.read_bytes())
    for signature, method_offset in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):
        cursor = 0
        while True:
            cursor = raw.find(signature, cursor)
            if cursor < 0:
                break
            raw[cursor + method_offset : cursor + method_offset + 2] = (99).to_bytes(2, "little")
            cursor += len(signature)
    archive.write_bytes(raw)

    assert _refusal(archive).rule == "unsupported_compression"


def test_inspect_n4a_archive_refuses_bzip2_without_decompressing_it(tmp_path: Path) -> None:
    archive = _write_bundle(tmp_path / "bzip2.n4a", _valid_members(), compression=zipfile.ZIP_BZIP2)

    assert _refusal(archive).rule == "unsupported_compression"


def test_inspect_n4a_archive_refuses_a_corrupt_deflated_manifest(tmp_path: Path) -> None:
    archive = _write_bundle(tmp_path / "corrupt-deflate.n4a", _valid_members(), compression=zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(archive) as bundle:
        manifest = bundle.getinfo("manifest.json")
    raw = bytearray(archive.read_bytes())
    local_name_bytes, local_extra_bytes = struct.unpack_from("<HH", raw, manifest.header_offset + 26)
    payload_offset = manifest.header_offset + 30 + local_name_bytes + local_extra_bytes
    raw[payload_offset] ^= 0xFF
    archive.write_bytes(raw)

    assert _refusal(archive).rule == "invalid_zip"


def test_inspect_n4a_archive_proves_deflate_boundaries_and_real_payload_sizes(tmp_path: Path) -> None:
    safe = _write_bundle(tmp_path / "safe-deflate.n4a", _valid_members(), compression=zipfile.ZIP_DEFLATED)
    assert inspect_n4a_archive(safe).member_count == 2

    trailing = _write_bundle(
        tmp_path / "trailing-deflate.n4a",
        [("manifest.json", "{}")],
        compression=zipfile.ZIP_DEFLATED,
    )
    raw = bytearray(trailing.read_bytes())
    central = raw.find(b"PK\x01\x02")
    assert central > 0
    hidden_local_header = b"PK\x03\x04../evil"
    original_compressed_size = struct.unpack_from("<L", raw, 18)[0]
    struct.pack_into("<L", raw, 18, original_compressed_size + len(hidden_local_header))
    struct.pack_into("<L", raw, central + 20, original_compressed_size + len(hidden_local_header))
    raw[central:central] = hidden_local_header
    eocd = raw.rfind(b"PK\x05\x06")
    assert eocd >= 0
    struct.pack_into("<L", raw, eocd + 16, central + len(hidden_local_header))
    trailing.write_bytes(raw)
    assert _refusal(trailing).rule == "invalid_zip"

    truncated = _write_bundle(
        tmp_path / "truncated-deflate.n4a",
        [("manifest.json", "{}")],
        compression=zipfile.ZIP_DEFLATED,
    )
    raw = bytearray(truncated.read_bytes())
    central = raw.find(b"PK\x01\x02")
    assert central > 0
    original_compressed_size = struct.unpack_from("<L", raw, 18)[0]
    assert original_compressed_size > 1
    del raw[central - 1]
    struct.pack_into("<L", raw, 18, original_compressed_size - 1)
    struct.pack_into("<L", raw, central - 1 + 20, original_compressed_size - 1)
    eocd = raw.rfind(b"PK\x05\x06")
    assert eocd >= 0
    struct.pack_into("<L", raw, eocd + 16, central - 1)
    truncated.write_bytes(raw)
    assert _refusal(truncated).rule == "invalid_zip"

    false_size = _write_bundle(
        tmp_path / "false-deflate-size.n4a",
        [("manifest.json", "{}"), ("payload", "A" * 1024)],
        compression=zipfile.ZIP_DEFLATED,
    )
    raw = bytearray(false_size.read_bytes())
    local_payload = raw.find(b"PK\x03\x04", 1)
    central_payload = raw.find(b"PK\x01\x02", raw.find(b"PK\x01\x02") + 1)
    assert local_payload >= 0 and central_payload >= 0
    for offset in (local_payload + 14, central_payload + 16):
        struct.pack_into("<L", raw, offset, zlib.crc32(b"A"))
    for offset in (local_payload + 22, central_payload + 24):
        struct.pack_into("<L", raw, offset, 1)
    false_size.write_bytes(raw)
    assert _refusal(false_size, limits=replace(DEFAULT_N4A_ARCHIVE_LIMITS, max_member_uncompressed_bytes=10)).rule == (
        "invalid_zip"
    )


def test_inspect_n4a_archive_cross_checks_local_sizes_crc_and_data_descriptors(tmp_path: Path) -> None:
    local_mismatch = _write_bundle(tmp_path / "local-mismatch.n4a", [("manifest.json", "{}")])
    raw = bytearray(local_mismatch.read_bytes())
    struct.pack_into("<L", raw, 22, 0xFFFFFFFF)
    local_mismatch.write_bytes(raw)
    assert _refusal(local_mismatch).rule == "invalid_zip"

    valid_descriptor = _write_descriptor_bundle(
        tmp_path / "valid-descriptor.n4a",
        struct.pack("<4sLLL", b"PK\x07\x08", zlib.crc32(b"{}"), 2, 2),
    )
    assert inspect_n4a_archive(valid_descriptor).member_count == 1

    valid_zip64_descriptor = _write_descriptor_bundle(
        tmp_path / "valid-zip64-descriptor.n4a",
        struct.pack("<4sLQQ", b"PK\x07\x08", zlib.crc32(b"{}"), 2, 2),
    )
    assert inspect_n4a_archive(valid_zip64_descriptor).member_count == 1

    invalid_descriptor = _write_descriptor_bundle(
        tmp_path / "invalid-descriptor.n4a",
        struct.pack("<4sLLL", b"PK\x07\x08", zlib.crc32(b"{}"), 0xFFFFFFFF, 0xFFFFFFFF),
    )
    assert _refusal(invalid_descriptor).rule == "invalid_zip"

    valid_zip64_local_descriptor = _write_zip64_local_descriptor_bundle(
        tmp_path / "valid-zip64-local-descriptor.n4a"
    )
    assert inspect_n4a_archive(valid_zip64_local_descriptor).member_count == 1
    mismatched_zip64_local_descriptor = _write_zip64_local_descriptor_bundle(
        tmp_path / "mismatched-zip64-local-descriptor.n4a",
        local_uncompressed_size=3,
    )
    assert _refusal(mismatched_zip64_local_descriptor).rule == "invalid_zip"


def test_inspect_n4a_archive_accepts_a_valid_zip64_local_header(tmp_path: Path) -> None:
    archive = tmp_path / "zip64-local.n4a"
    with zipfile.ZipFile(archive, "w") as bundle:
        with bundle.open(zipfile.ZipInfo("manifest.json"), "w", force_zip64=True) as member:
            member.write(b"{}")

    assert inspect_n4a_archive(archive).member_count == 1


def test_inspect_n4a_archive_refuses_disagreeing_local_header_name(tmp_path: Path) -> None:
    archive = _write_bundle(tmp_path / "local-name.n4a", _valid_members(("safe/abcdef", "x")))
    raw = bytearray(archive.read_bytes())
    local_name = raw.find(b"safe/abcdef")
    assert local_name >= 0
    raw[local_name : local_name + len(b"safe/abcdef")] = b"../evil/xxx"
    archive.write_bytes(raw)

    assert _refusal(archive).rule == "unsafe_member_path"


def test_inspect_n4a_archive_refuses_a_multivolume_central_entry(tmp_path: Path) -> None:
    archive = _write_bundle(tmp_path / "multivolume-entry.n4a", _valid_members())
    raw = bytearray(archive.read_bytes())
    central = raw.find(b"PK\x01\x02")
    assert central >= 0
    raw[central + 34 : central + 36] = (1).to_bytes(2, "little")
    archive.write_bytes(raw)

    assert _refusal(archive).rule == "invalid_zip"


def test_inspect_n4a_archive_refuses_a_prepended_zip_stub(tmp_path: Path) -> None:
    archive = _write_bundle(tmp_path / "prepended.n4a", _valid_members())
    archive.write_bytes((b"SFX-STUB" * 64) + archive.read_bytes())

    assert _refusal(archive).rule == "invalid_zip"


def test_inspect_n4a_archive_refuses_an_unreferenced_local_header(tmp_path: Path) -> None:
    archive = _write_bundle(tmp_path / "hidden-local.n4a", [("manifest.json", "{}")])
    raw = bytearray(archive.read_bytes())
    central_offset = raw.find(b"PK\x01\x02")
    assert central_offset >= 0
    hidden_name = b"../evil"
    hidden_payload = b"never extracted"
    hidden = (
        struct.pack(
            "<4s5H3L2H",
            b"PK\x03\x04",
            20,
            0,
            zipfile.ZIP_STORED,
            0,
            0,
            zlib.crc32(hidden_payload),
            len(hidden_payload),
            len(hidden_payload),
            len(hidden_name),
            0,
        )
        + hidden_name
        + hidden_payload
    )
    raw[central_offset:central_offset] = hidden
    eocd_offset = raw.rfind(b"PK\x05\x06")
    assert eocd_offset >= 0
    struct.pack_into("<L", raw, eocd_offset + 16, central_offset + len(hidden))
    archive.write_bytes(raw)

    assert _refusal(archive).rule == "invalid_zip"


def test_inspect_n4a_archive_refuses_duplicate_manifest_and_manifest_shapes(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.n4a"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        _write_bundle(duplicate, [("manifest.json", "{}"), ("manifest.json", "{}")])
    assert _refusal(duplicate).rule == "manifest_duplicate"

    missing = _write_bundle(tmp_path / "missing.n4a", [("chain.json", "{}")])
    assert _refusal(missing).rule == "manifest_missing"

    scalar = _write_bundle(tmp_path / "scalar.n4a", [("manifest.json", "[]")])
    assert _refusal(scalar).rule == "manifest_json"

    duplicate_key = _write_bundle(tmp_path / "duplicate-key.n4a", [("manifest.json", '{"a":1,"a":2}')])
    assert _refusal(duplicate_key).rule == "manifest_json"

    nonfinite = _write_bundle(tmp_path / "nonfinite.n4a", [("manifest.json", '{"a":NaN}')])
    assert _refusal(nonfinite).rule == "manifest_json"

    overflow = _write_bundle(tmp_path / "overflow.n4a", [("manifest.json", '{"a":1e999}')])
    assert _refusal(overflow).rule == "manifest_json"

    isolated_surrogate = _write_bundle(
        tmp_path / "isolated-surrogate.n4a",
        [("manifest.json", b'{"bundle_format_version":"\\ud800"}')],
    )
    assert _refusal(isolated_surrogate).rule == "manifest_json"

    terminal_control = _write_bundle(
        tmp_path / "terminal-control.n4a",
        [("manifest.json", b'{"bundle_format_version":"\\u001b[2JOWNED"}')],
    )
    assert _refusal(terminal_control).rule == "manifest_json"


@pytest.mark.parametrize(
    ("members", "limits", "rule"),
    [
        (
            _valid_members(("large.bin", "abcd")),
            replace(DEFAULT_N4A_ARCHIVE_LIMITS, max_member_uncompressed_bytes=3),
            "member_size",
        ),
        (
            _valid_members(("one.bin", "ab"), ("two.bin", "cd")),
            replace(DEFAULT_N4A_ARCHIVE_LIMITS, max_total_uncompressed_bytes=4),
            "total_uncompressed_size",
        ),
        (
            _valid_members(("compressed.bin", "x" * 100)),
            replace(DEFAULT_N4A_ARCHIVE_LIMITS, max_compression_ratio=1),
            "compression_ratio",
        ),
        (_valid_members(), replace(DEFAULT_N4A_ARCHIVE_LIMITS, max_members=1), "member_count"),
        (
            _valid_members(),
            replace(DEFAULT_N4A_ARCHIVE_LIMITS, max_central_directory_bytes=1),
            "central_directory_size",
        ),
        (_valid_members(), replace(DEFAULT_N4A_ARCHIVE_LIMITS, max_archive_bytes=1), "archive_size"),
        (
            [("manifest.json", '{"bundle_format_version":"1.0"}')],
            replace(DEFAULT_N4A_ARCHIVE_LIMITS, max_manifest_bytes=8),
            "manifest_size",
        ),
    ],
)
def test_inspect_n4a_archive_enforces_injected_limits(
    tmp_path: Path,
    members: list[tuple[str, str | bytes]],
    limits: N4aArchiveLimits,
    rule: str,
) -> None:
    compression = zipfile.ZIP_DEFLATED if rule == "compression_ratio" else zipfile.ZIP_STORED
    archive = _write_bundle(tmp_path / f"{rule}.n4a", members, compression=compression)

    assert _refusal(archive, limits=limits).rule == rule

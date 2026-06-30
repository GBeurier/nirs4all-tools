"""SHA-256 checksum helpers.

The tool standardizes on SHA-256 (the legacy ``_array_checksum`` used MD5;
``SW4_MIG_CONVERTER_spec.md`` §9 replaces it). File-level checksums are SHA-256
over raw bytes; values are prefixed with ``sha256:`` so the algorithm travels
with the digest in manifests.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

_PREFIX = "sha256:"
_CHUNK = 1 << 20  # 1 MiB


def sha256_bytes(data: bytes) -> str:
    """Return the prefixed SHA-256 digest of ``data``."""
    return _PREFIX + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Return the prefixed SHA-256 digest of a file's raw bytes (streamed)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return _PREFIX + digest.hexdigest()


__all__ = ["sha256_bytes", "sha256_file"]

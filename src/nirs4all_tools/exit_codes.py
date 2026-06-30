"""Process exit codes for the ``nirs4all-tools`` CLI.

The five A8 failure classes, frozen into concrete integers by the ``LOCK-MIG``
spec (``SW4_MIG_CONVERTER_spec.md`` §6). Every command returns one of these.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Stable CLI exit codes (``SW4_MIG_CONVERTER_spec.md`` §6)."""

    SUCCESS = 0
    """Success, no warnings."""

    MIGRATED_WITH_WARNINGS = 10
    """Best-effort preserved opaque items, or other non-fatal skips."""

    UNSUPPORTED_INPUT = 20
    """Unknown / forward-version source, or a strict-mode unsupported item."""

    VERIFICATION_FAILED = 30
    """A verification check did not pass."""

    REFUSED_BY_POLICY = 40
    """In-place / aliased output, or a non-empty output without ``--resume``."""

    INTERNAL_ERROR = 70
    """Internal error, including a source-tree integrity assertion failure."""


__all__ = ["ExitCode"]

"""Typed exceptions that map one-to-one onto :class:`ExitCode` values.

Every command raises one of these on failure; the CLI top level translates the
exception into its ``exit_code`` and renders ``cause`` / ``mitigation`` into the
report's ``errors[]`` entries (``SW4_MIG_CONVERTER_spec.md`` §8, §12).
"""

from __future__ import annotations

from .exit_codes import ExitCode


class ToolError(Exception):
    """Base class for every recoverable, reportable tool error.

    Args:
        message: Human-readable description of what went wrong.
        cause: A value from the CAP-004 / migration-local cause vocabulary
            (see :mod:`nirs4all_tools.vocab`).
        mitigation: A short, actionable next step for the user.
    """

    exit_code: ExitCode = ExitCode.INTERNAL_ERROR

    def __init__(self, message: str, *, cause: str | None = None, mitigation: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.cause = cause
        self.mitigation = mitigation


class PolicyRefusal(ToolError):
    """A pre-flight policy was violated (aliased/in-place/non-empty output)."""

    exit_code = ExitCode.REFUSED_BY_POLICY


class UnsupportedInput(ToolError):
    """The source is unknown, forward-versioned, or a gated capability."""

    exit_code = ExitCode.UNSUPPORTED_INPUT


class VerificationFailed(ToolError):
    """An output failed one or more verification checks."""

    exit_code = ExitCode.VERIFICATION_FAILED


class SourceIntegrityError(ToolError):
    """The source tree changed during a run — the no-in-place contract broke."""

    exit_code = ExitCode.INTERNAL_ERROR


__all__ = [
    "ToolError",
    "PolicyRefusal",
    "UnsupportedInput",
    "VerificationFailed",
    "SourceIntegrityError",
]

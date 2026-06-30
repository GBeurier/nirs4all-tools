"""Shared string vocabulary for causes, statuses, kinds and contracts.

The ``cause`` vocabulary is **referenced from CAP-004** (``RT_spec.md`` RT-003),
not redefined here — the cross-cutting ``RtError`` causes plus the four
migration-local causes are mirrored as constants so the report can carry them
without inventing a parallel taxonomy.
"""

from __future__ import annotations

from typing import Final

# --- Cause vocabulary (CAP-004 / RT-003 cross-cutting causes) --------------
CAUSE_UNSUPPORTED_SHAPE: Final = "unsupported_shape"
CAUSE_UNSUPPORTED_CAPABILITY: Final = "unsupported_capability"
CAUSE_INVALID_REQUEST: Final = "invalid_request"
CAUSE_RUNTIME_ERROR: Final = "runtime_error"

# --- Migration-local causes ------------------------------------------------
CAUSE_FORCED_IN_PLACE_REFUSED: Final = "forced_in_place_refused"
CAUSE_NON_EMPTY_OUTPUT: Final = "non_empty_output"
CAUSE_FORWARD_VERSION: Final = "forward_version"
CAUSE_VERIFICATION_FAILED: Final = "verification_failed"

CAUSES: Final = frozenset(
    {
        CAUSE_UNSUPPORTED_SHAPE,
        CAUSE_UNSUPPORTED_CAPABILITY,
        CAUSE_INVALID_REQUEST,
        CAUSE_RUNTIME_ERROR,
        CAUSE_FORCED_IN_PLACE_REFUSED,
        CAUSE_NON_EMPTY_OUTPUT,
        CAUSE_FORWARD_VERSION,
        CAUSE_VERIFICATION_FAILED,
    }
)

# --- Report status vocabulary (SW4 spec §8) --------------------------------
STATUS_SUCCESS: Final = "success"
STATUS_MIGRATED_WITH_WARNINGS: Final = "migrated_with_warnings"
STATUS_UNSUPPORTED_INPUT: Final = "unsupported_input"
STATUS_VERIFICATION_FAILED: Final = "verification_failed"
STATUS_REFUSED: Final = "refused"
STATUS_ERROR: Final = "error"

# --- Target kinds (SW4 spec §5) --------------------------------------------
TARGET_WORKSPACE_V2: Final = "nirs4all-workspace-v2"
TARGET_NATIVE_RESULTS_V1: Final = "native-results-v1"  # Phase 2, gated.

__all__ = [name for name in dir() if name.isupper()]

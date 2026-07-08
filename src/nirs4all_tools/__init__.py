"""nirs4all-tools — offline, one-way, no-in-place migration toolbox.

This package hosts standalone conversion tools for legacy nirs4all artifacts
(workspaces, bundles, loose prediction files). The single contract that governs
every tool here is **no-in-place**: the source tree is opened read-only and is
proven byte-for-byte unchanged after every run, including failure and abort
paths. Conversions are one-way and always land in a fresh ``--output`` location.

The runtime library ``nirs4all`` carries no legacy reader; those readers live
here, under a declared support window. See ``docs`` and the ecosystem report
``SW4_MIG_CONVERTER_spec.md`` for the signed ``LOCK-MIG`` contract.
"""

__version__ = "0.0.5"

__all__ = ["__version__"]

"""Explicit, attested export of one trusted sklearn PLS joblib to N4MM.

This is deliberately narrower than a workspace migration.  A standalone
fitted sklearn estimator does not carry the signed graph, score, cohort, and
lineage evidence needed to fabricate a PortablePredictorPackage or archive.
The command therefore emits only a native, PREDICT-only N4MM and an attestation
that makes those limits visible to its caller.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from . import vocab
from .checksums import sha256_bytes, sha256_file
from .errors import PolicyRefusal, UnsupportedInput, VerificationFailed
from .exit_codes import ExitCode
from .policy import assert_disjoint, assert_output_available, source_guard
from .trusted_joblib import TrustedJoblibRefusal, load_trusted_sklearn_pls_affine

_MODEL_NAME = "model.n4mm"
_ATTESTATION_NAME = "n4mm-export-attestation.json"


def export_trusted_joblib_n4mm(
    source: Path,
    *,
    output: Path,
    trusted_load_joblib: bool,
    tool_version: str,
) -> ExitCode:
    """Export an explicitly trusted PLS joblib into a fresh, attested directory.

    No legacy source is opened unless the opt-in is present.  The output is
    created only after sklearn extraction and Methods export succeed, and is
    removed if its own write transaction fails.  This artifact is intentionally
    *not* an archive or a converted workspace.
    """

    if not trusted_load_joblib:
        raise UnsupportedInput(
            "export-n4mm requires --trusted-load-joblib before joblib deserialization",
            cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
            mitigation="pass --trusted-load-joblib only for a source you explicitly trust",
        )
    if not source.is_file():
        raise UnsupportedInput(
            "export-n4mm source must be a regular trusted joblib file",
            cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
            mitigation="supply one fitted sklearn PLSRegression joblib file",
        )
    assert_disjoint(source, output)
    assert_output_available(output, resume=False)

    with source_guard(source):
        try:
            predictor = load_trusted_sklearn_pls_affine(source)
        except TrustedJoblibRefusal as exc:
            raise UnsupportedInput(
                f"trusted PLS preflight refused the source: {exc}",
                cause=vocab.CAUSE_UNSUPPORTED_SHAPE,
                mitigation="use exactly a fitted sklearn.cross_decomposition.PLSRegression with finite state",
            ) from exc
        payload, methods_version = _export_native_n4mm(predictor)
        source_digest = sha256_file(source)

    if not payload:
        raise VerificationFailed(
            "Methods returned an empty N4MM payload",
            cause=vocab.CAUSE_RUNTIME_ERROR,
            mitigation="verify that nirs4all-methods >= 1.0.11 is installed and retry",
        )
    attestation = {
        "schema_version": "nirs4all-tools.n4mm-export-attestation.v1",
        "tool_version": tool_version,
        "source": {
            "kind": "trusted-sklearn-pls-joblib",
            "sha256": source_digest,
            "deserialization": "explicit-opt-in",
        },
        "n4mm": {
            "path": _MODEL_NAME,
            "sha256": sha256_bytes(payload),
            "byte_size": len(payload),
            "methods_version": methods_version,
            "capability": "predict_only",
            "transform": "unsupported",
        },
        "affine_predictor": {
            "equation": "intercept + X @ coefficients",
            "n_features": predictor.n_features,
            "n_targets": predictor.n_targets,
            "source_training_samples": predictor.source_training_samples,
        },
        "not_an_archive": True,
        "archive_refusal_reason": "a standalone joblib lacks signed graph, score, cohort, and lineage evidence",
    }
    _publish_fresh_export(output, payload, attestation)
    return ExitCode.SUCCESS


def _export_native_n4mm(predictor: Any) -> tuple[bytes, str]:
    """Use the released Methods binding without making it a base dependency."""

    try:
        import n4m
        from n4m.lowlevel.migration import export_linear_predictor_n4mm
    except ImportError as exc:
        raise UnsupportedInput(
            "export-n4mm requires the n4mm-export extra (nirs4all-methods >= 1.0.11)",
            cause=vocab.CAUSE_UNSUPPORTED_CAPABILITY,
            mitigation='install with: pip install "nirs4all-tools[n4mm-export]"',
        ) from exc
    try:
        payload = export_linear_predictor_n4mm(
            predictor.coefficients,
            predictor.intercept,
            source_training_samples=predictor.source_training_samples,
        )
    except (RuntimeError, ValueError) as exc:
        raise VerificationFailed(
            f"Methods refused the verified affine predictor: {exc}",
            cause=vocab.CAUSE_RUNTIME_ERROR,
            mitigation="verify the installed Methods ABI is 2.3.0 or newer",
        ) from exc
    return bytes(payload), str(getattr(n4m, "__version__", "unknown"))


def _publish_fresh_export(output: Path, payload: bytes, attestation: dict[str, object]) -> None:
    """Publish both files into a new output directory without overwriting one."""

    parent = output.parent
    if not parent.is_dir():
        raise PolicyRefusal(
            f"export output parent does not exist: {parent}",
            cause=vocab.CAUSE_NON_EMPTY_OUTPUT,
            mitigation="create the parent directory first and choose a fresh output directory",
        )
    try:
        output.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise PolicyRefusal(
            f"export output already exists: {output}",
            cause=vocab.CAUSE_NON_EMPTY_OUTPUT,
            mitigation="choose a fresh output directory",
        ) from exc

    try:
        _write_atomic_owned(output / _MODEL_NAME, payload)
        _write_atomic_owned(
            output / _ATTESTATION_NAME,
            (json.dumps(attestation, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        )
        _fsync_directory(output)
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise


def _write_atomic_owned(destination: Path, data: bytes) -> None:
    """Atomically write a file inside an output directory created by this call."""

    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except BaseException:
        try:
            Path(temporary).unlink(missing_ok=True)
        finally:
            raise


def _fsync_directory(path: Path) -> None:
    """Persist directory entries where the host supports directory file descriptors."""

    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:  # pragma: no cover - platform dependent best effort
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


__all__ = ["export_trusted_joblib_n4mm"]

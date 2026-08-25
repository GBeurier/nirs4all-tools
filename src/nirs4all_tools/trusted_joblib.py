"""Strict extraction of a verified affine equation from a trusted sklearn PLS model.

This module is deliberately not a general joblib reader.  Loading a joblib
file can execute code, therefore callers must invoke it only after the CLI has
received an explicit trust opt-in.  It accepts exactly sklearn's concrete
``PLSRegression`` type and proves that the exported affine equation reproduces
the fitted object's public ``predict`` result on fixed, finite probes.

The result is intentionally transport-neutral: the Methods ABI owns N4MM
construction, while higher-level migration owns the target package/archive.
Keeping those boundaries here prevents a Tools reader from inventing a model
format or silently retraining a legacy estimator.
"""

from __future__ import annotations

import math
import operator
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, SupportsIndex, cast


class TrustedJoblibRefusal(ValueError):
    """A trusted joblib object cannot be proven to be the supported PLS shape."""


@dataclass(frozen=True)
class VerifiedAffinePredictor:
    """A finite, feature-major affine equation extracted from sklearn PLS.

    ``coefficients`` has shape ``(n_features, n_targets)`` and the prediction
    equation is ``intercept + X @ coefficients``.  ``source_training_samples``
    is provenance only and is zero when the old fitted object did not retain a
    trustworthy sample count.
    """

    coefficients: tuple[tuple[float, ...], ...]
    intercept: tuple[float, ...]
    source_training_samples: int

    @property
    def n_features(self) -> int:
        return len(self.coefficients)

    @property
    def n_targets(self) -> int:
        return len(self.intercept)

    def predict(self, rows: list[list[float]]) -> list[list[float]]:
        """Evaluate the extracted equation without calling sklearn again."""

        output: list[list[float]] = []
        for row in rows:
            if len(row) != self.n_features or not all(math.isfinite(value) for value in row):
                raise TrustedJoblibRefusal("prediction rows must be finite and match extracted feature width")
            output.append(
                [
                    self.intercept[target]
                    + sum(row[feature] * self.coefficients[feature][target] for feature in range(self.n_features))
                    for target in range(self.n_targets)
                ]
            )
        return output


def load_trusted_sklearn_pls_affine(path: Path) -> VerifiedAffinePredictor:
    """Load one explicitly trusted joblib file and prove its PLS affine equation.

    This function must never be reached from an automatic migration path.  It
    does not accept pipelines, subclasses, arbitrary sklearn estimators, or
    malformed/mutated fitted state.
    """

    if not path.is_file():
        raise TrustedJoblibRefusal("trusted joblib source must be a regular file")
    try:
        import joblib
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise TrustedJoblibRefusal("trusted joblib support requires the trusted-joblib extra") from exc
    try:
        estimator = joblib.load(path)
    except Exception as exc:  # noqa: BLE001 - joblib implementation exceptions are foreign data failures
        raise TrustedJoblibRefusal(f"trusted joblib load failed: {exc}") from exc
    return extract_verified_sklearn_pls_affine(estimator)


def extract_verified_sklearn_pls_affine(estimator: object) -> VerifiedAffinePredictor:
    """Extract a verified affine equation from exactly sklearn ``PLSRegression``.

    sklearn changed the internal orientation and scaling convention of
    ``coef_`` between releases.  We enumerate the documented historical
    conventions and retain exactly one whose equation agrees with the actual
    fitted ``predict`` method on deterministic non-degenerate probes.  A tie
    between different equations is a refusal, never a guessed conversion.
    """

    estimator_type = type(estimator)
    if estimator_type.__module__ != "sklearn.cross_decomposition._pls" or estimator_type.__name__ != "PLSRegression":
        raise TrustedJoblibRefusal("trusted conversion supports exactly sklearn.cross_decomposition.PLSRegression")
    try:
        import numpy as np
    except ImportError as exc:  # pragma: no cover - sklearn itself requires NumPy
        raise TrustedJoblibRefusal("trusted sklearn PLS extraction requires NumPy") from exc

    features = _positive_index(getattr(estimator, "n_features_in_", None), "n_features_in_")
    coefficient_values = _finite_matrix(getattr(estimator, "coef_", None), "coef_")
    x_mean = _finite_vector(_first_attr(estimator, "_x_mean", "x_mean_"), "x_mean", expected=features)
    x_scale = _finite_vector(
        _first_attr(estimator, "_x_std", "x_std_", required=False),
        "x_scale",
        expected=features,
        allow_missing=True,
    )
    intercept = _finite_vector(
        _first_attr(estimator, "intercept_", required=False),
        "intercept_",
        allow_missing=True,
    )
    y_mean = _finite_vector(
        _first_attr(estimator, "_y_mean", "y_mean_", required=False),
        "y_mean",
        allow_missing=True,
    )
    if x_mean is None:  # `_finite_vector` keeps this explicit for static callers.
        raise TrustedJoblibRefusal("fitted PLSRegression is missing required x_mean")

    candidates: list[VerifiedAffinePredictor] = []
    coefficient_rows = len(coefficient_values)
    coefficient_cols = len(coefficient_values[0])
    if coefficient_cols == features:
        # Current sklearn: predict((X - x_mean) @ coef_.T + intercept_).
        for base in _present_vectors(intercept, y_mean):
            matrix = tuple(
                tuple(coefficient_values[target][feature] for target in range(coefficient_rows))
                for feature in range(features)
            )
            candidates.append(_affine_with_centering(matrix, base, x_mean, None))
    if coefficient_rows == features and x_scale is not None:
        # Historical sklearn: predict(((X - x_mean) / x_std) @ coef_ + y_mean).
        for base in _present_vectors(intercept, y_mean):
            candidates.append(_affine_with_centering(tuple(coefficient_values), base, x_mean, x_scale))

    if not candidates:
        raise TrustedJoblibRefusal("PLSRegression coef_ shape does not match n_features_in_")

    probes = _probes(features, np)
    actual = _prediction_matrix(estimator, probes, "PLSRegression.predict")
    source_samples = _source_training_samples(estimator)
    matching = [
        candidate
        for candidate in candidates
        if candidate.n_targets == len(actual[0]) and _close_matrices(candidate.predict(probes.tolist()), actual)
    ]
    unique = _unique_equations(matching)
    if len(unique) != 1:
        if not unique:
            raise TrustedJoblibRefusal("PLSRegression affine equation did not reproduce fitted predict")
        raise TrustedJoblibRefusal("PLSRegression exposes ambiguous affine coefficient conventions")
    selected = unique[0]
    return VerifiedAffinePredictor(
        coefficients=selected.coefficients,
        intercept=selected.intercept,
        source_training_samples=source_samples,
    )


def _first_attr(estimator: object, *names: str, required: bool = True) -> Any:
    for name in names:
        if hasattr(estimator, name):
            return getattr(estimator, name)
    if required:
        raise TrustedJoblibRefusal(f"fitted PLSRegression is missing required attribute {names[0]!r}")
    return None


def _positive_index(value: object, name: str) -> int:
    if isinstance(value, bool):
        raise TrustedJoblibRefusal(f"{name} must be a positive integer")
    try:
        if not hasattr(value, "__index__"):
            raise TypeError
        converted = operator.index(cast(SupportsIndex, value))
    except TypeError as exc:
        raise TrustedJoblibRefusal(f"{name} must be a positive integer") from exc
    if converted <= 0 or converted > 1_000_000:
        raise TrustedJoblibRefusal(f"{name} is outside the supported conversion range")
    return converted


def _finite_vector(
    value: object, name: str, *, expected: int | None = None, allow_missing: bool = False
) -> tuple[float, ...] | None:
    if value is None:
        if allow_missing:
            return None
        raise TrustedJoblibRefusal(f"fitted PLSRegression is missing required {name}")
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
        raise TrustedJoblibRefusal(f"{name} must be a finite one-dimensional vector")
    try:
        result = tuple(float(item) for item in value)
    except (TypeError, ValueError) as exc:
        raise TrustedJoblibRefusal(f"{name} must be a finite one-dimensional vector") from exc
    if (
        not result
        or (expected is not None and len(result) != expected)
        or not all(math.isfinite(item) for item in result)
    ):
        raise TrustedJoblibRefusal(f"{name} must be a finite vector with the expected width")
    return result


def _finite_matrix(value: object, name: str) -> tuple[tuple[float, ...], ...]:
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
        raise TrustedJoblibRefusal(f"{name} must be a finite two-dimensional matrix")
    raw_rows = tuple(value)
    if any(not isinstance(row, Iterable) or isinstance(row, (str, bytes)) for row in raw_rows):
        raise TrustedJoblibRefusal(f"{name} must be a finite two-dimensional matrix")
    try:
        rows = tuple(tuple(float(item) for item in row) for row in raw_rows)
    except (TypeError, ValueError) as exc:
        raise TrustedJoblibRefusal(f"{name} must be a finite two-dimensional matrix") from exc
    if not rows or not rows[0] or any(len(row) != len(rows[0]) for row in rows):
        raise TrustedJoblibRefusal(f"{name} must be a non-empty rectangular matrix")
    if not all(math.isfinite(item) for row in rows for item in row):
        raise TrustedJoblibRefusal(f"{name} must contain finite values")
    return rows


def _present_vectors(*values: tuple[float, ...] | None) -> tuple[tuple[float, ...], ...]:
    return tuple(value for value in values if value is not None)


def _affine_with_centering(
    coefficients: tuple[tuple[float, ...], ...],
    base: tuple[float, ...],
    x_mean: tuple[float, ...],
    x_scale: tuple[float, ...] | None,
) -> VerifiedAffinePredictor:
    if len(coefficients) != len(x_mean) or any(len(row) != len(base) for row in coefficients):
        raise TrustedJoblibRefusal("PLSRegression coefficient dimensions are inconsistent")
    if x_scale is not None and (len(x_scale) != len(x_mean) or any(scale == 0.0 for scale in x_scale)):
        raise TrustedJoblibRefusal("PLSRegression x_scale is inconsistent or contains zero")
    scaled = tuple(
        tuple(value if x_scale is None else value / x_scale[feature] for value in row)
        for feature, row in enumerate(coefficients)
    )
    intercept = tuple(
        base[target] - sum(x_mean[feature] * scaled[feature][target] for feature in range(len(scaled)))
        for target in range(len(base))
    )
    if not all(math.isfinite(value) for row in scaled for value in row) or not all(
        math.isfinite(value) for value in intercept
    ):
        raise TrustedJoblibRefusal("PLSRegression affine projection is not finite")
    return VerifiedAffinePredictor(coefficients=scaled, intercept=intercept, source_training_samples=0)


def _probes(features: int, np: Any) -> Any:
    first = [((index % 7) - 3) / 5.0 for index in range(features)]
    second = [((index * 3 % 11) - 5) / 7.0 for index in range(features)]
    third = [first[index] * 1.75 - second[index] * 0.25 + 0.125 for index in range(features)]
    return np.asarray([first, second, third], dtype=np.float64)


def _prediction_matrix(estimator: object, probes: Any, name: str) -> list[list[float]]:
    try:
        predicted = estimator.predict(probes)  # type: ignore[attr-defined]
        values = predicted.tolist()
    except Exception as exc:  # noqa: BLE001 - foreign fitted state failures are conversion refusals
        raise TrustedJoblibRefusal(f"{name} failed on finite conversion probes: {exc}") from exc
    if not isinstance(values, list) or len(values) != len(probes):
        raise TrustedJoblibRefusal(f"{name} returned an invalid prediction shape")
    if values and not isinstance(values[0], list):
        values = [[value] for value in values]
    try:
        matrix = [[float(value) for value in row] for row in values]
    except (TypeError, ValueError) as exc:
        raise TrustedJoblibRefusal(f"{name} returned non-numeric predictions") from exc
    if not matrix or not matrix[0] or any(len(row) != len(matrix[0]) for row in matrix):
        raise TrustedJoblibRefusal(f"{name} returned an invalid prediction matrix")
    if not all(math.isfinite(value) for row in matrix for value in row):
        raise TrustedJoblibRefusal(f"{name} returned non-finite predictions")
    return matrix


def _close_matrices(left: list[list[float]], right: list[list[float]]) -> bool:
    return len(left) == len(right) and all(
        len(left_row) == len(right_row)
        and all(math.isclose(a, b, rel_tol=1e-10, abs_tol=1e-12) for a, b in zip(left_row, right_row, strict=True))
        for left_row, right_row in zip(left, right, strict=True)
    )


def _unique_equations(candidates: list[VerifiedAffinePredictor]) -> list[VerifiedAffinePredictor]:
    unique: list[VerifiedAffinePredictor] = []
    for candidate in candidates:
        if not any(
            candidate.coefficients == existing.coefficients and candidate.intercept == existing.intercept
            for existing in unique
        ):
            unique.append(candidate)
    return unique


def _source_training_samples(estimator: object) -> int:
    scores = getattr(estimator, "x_scores_", None)
    shape = getattr(scores, "shape", None)
    if not isinstance(shape, tuple) or not shape:
        return 0
    try:
        samples = operator.index(shape[0])
    except TypeError:
        return 0
    return samples if 0 < samples <= 2**63 - 1 else 0


__all__ = [
    "TrustedJoblibRefusal",
    "VerifiedAffinePredictor",
    "extract_verified_sklearn_pls_affine",
    "load_trusted_sklearn_pls_affine",
]

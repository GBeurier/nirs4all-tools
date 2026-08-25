"""Strict trusted-joblib extraction tests using real sklearn PLS models."""

from __future__ import annotations

import joblib
import numpy as np
import pytest
from sklearn.cross_decomposition import PLSRegression
from sklearn.linear_model import LinearRegression
from sklearn.pipeline import Pipeline

from nirs4all_tools.trusted_joblib import (
    TrustedJoblibRefusal,
    extract_verified_sklearn_pls_affine,
    load_trusted_sklearn_pls_affine,
)


def _training_data() -> tuple[np.ndarray, np.ndarray]:
    x = np.asarray(
        [
            [-2.0, 1.0, 0.5],
            [-1.0, 0.5, 1.5],
            [0.0, -1.0, 2.0],
            [1.0, 2.0, -0.5],
            [2.0, -0.5, 1.0],
            [3.0, 1.5, -1.0],
        ]
    )
    y = np.column_stack((1.25 + 2.0 * x[:, 0] - x[:, 1] + 0.5 * x[:, 2], -0.5 + x[:, 0] + 3.0 * x[:, 1]))
    return x, y


@pytest.mark.parametrize("multi_target", [False, True])
def test_extracts_exact_fitted_sklearn_pls_equation(multi_target: bool) -> None:
    x, y = _training_data()
    expected_y = y if multi_target else y[:, 0]
    model = PLSRegression(n_components=2, scale=True).fit(x, expected_y)

    extracted = extract_verified_sklearn_pls_affine(model)
    probe = np.asarray([[0.25, -0.75, 1.5], [-1.5, 2.0, 0.0], [4.0, -1.0, 0.25]])
    expected = model.predict(probe)
    expected_2d = expected.reshape(-1, 1) if expected.ndim == 1 else expected

    assert extracted.source_training_samples == len(x)
    assert extracted.n_features == x.shape[1]
    assert extracted.n_targets == expected_2d.shape[1]
    np.testing.assert_allclose(extracted.predict(probe.tolist()), expected_2d, rtol=1e-10, atol=1e-12)


def test_joblib_load_is_explicit_and_preserves_the_verified_equation(tmp_path) -> None:
    x, y = _training_data()
    model = PLSRegression(n_components=2).fit(x, y)
    payload = tmp_path / "trusted-pls.joblib"
    joblib.dump(model, payload)

    extracted = load_trusted_sklearn_pls_affine(payload)
    np.testing.assert_allclose(extracted.predict(x.tolist()), model.predict(x), rtol=1e-10, atol=1e-12)


def test_refuses_pipeline_and_non_pls_estimators() -> None:
    x, y = _training_data()
    pls = PLSRegression(n_components=2).fit(x, y)
    with pytest.raises(TrustedJoblibRefusal, match="exactly"):
        extract_verified_sklearn_pls_affine(Pipeline([("pls", pls)]))
    with pytest.raises(TrustedJoblibRefusal, match="exactly"):
        extract_verified_sklearn_pls_affine(LinearRegression().fit(x, y))


def test_refuses_mutated_non_finite_fitted_state() -> None:
    x, y = _training_data()
    model = PLSRegression(n_components=2).fit(x, y)
    model.coef_[0, 0] = np.nan
    with pytest.raises(TrustedJoblibRefusal, match="finite"):
        extract_verified_sklearn_pls_affine(model)

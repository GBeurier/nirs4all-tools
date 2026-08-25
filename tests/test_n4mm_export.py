"""Tests for the explicitly trusted, standalone N4MM export boundary."""

from __future__ import annotations

import json

import joblib
import numpy as np
import pytest
from sklearn.cross_decomposition import PLSRegression

from nirs4all_tools.errors import PolicyRefusal, UnsupportedInput
from nirs4all_tools.exit_codes import ExitCode
from nirs4all_tools.n4mm_export import export_trusted_joblib_n4mm


def _trusted_pls(path) -> None:
    x = np.asarray([[-2.0, 1.0], [-1.0, 0.0], [0.0, 1.0], [1.0, -1.0], [2.0, 0.5]])
    y = 1.5 + 2.0 * x[:, 0] - 0.75 * x[:, 1]
    joblib.dump(PLSRegression(n_components=1).fit(x, y), path)


def test_export_writes_only_attested_predict_only_n4mm(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "trusted.joblib"
    _trusted_pls(source)
    output = tmp_path / "native-model"
    captured = {}

    def fake_export(predictor):
        captured["predictor"] = predictor
        return b"N4MM\x00verified", "1.0.11"

    monkeypatch.setattr("nirs4all_tools.n4mm_export._export_native_n4mm", fake_export)
    assert (
        export_trusted_joblib_n4mm(
            source,
            output=output,
            trusted_load_joblib=True,
            tool_version="0.0.5",
        )
        == ExitCode.SUCCESS
    )

    assert (output / "model.n4mm").read_bytes() == b"N4MM\x00verified"
    attestation = json.loads((output / "n4mm-export-attestation.json").read_text(encoding="utf-8"))
    assert attestation["n4mm"]["capability"] == "predict_only"
    assert attestation["n4mm"]["transform"] == "unsupported"
    assert attestation["not_an_archive"] is True
    assert captured["predictor"].n_features == 2


def test_export_requires_explicit_deserialization_opt_in_before_loading(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "trusted.joblib"
    _trusted_pls(source)
    called = False

    def unexpected_load(_source):
        nonlocal called
        called = True
        raise AssertionError("joblib must not be opened")

    monkeypatch.setattr("nirs4all_tools.n4mm_export.load_trusted_sklearn_pls_affine", unexpected_load)
    with pytest.raises(UnsupportedInput, match="requires --trusted-load-joblib"):
        export_trusted_joblib_n4mm(
            source,
            output=tmp_path / "out",
            trusted_load_joblib=False,
            tool_version="0.0.5",
        )
    assert called is False
    assert not (tmp_path / "out").exists()


def test_export_refuses_existing_output_before_deserialization(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "trusted.joblib"
    _trusted_pls(source)
    output = tmp_path / "existing"
    output.mkdir()
    (output / "keep").write_text("do not touch", encoding="utf-8")
    monkeypatch.setattr(
        "nirs4all_tools.n4mm_export.load_trusted_sklearn_pls_affine",
        lambda _source: (_ for _ in ()).throw(AssertionError("must not deserialize")),
    )
    with pytest.raises(PolicyRefusal, match="not empty"):
        export_trusted_joblib_n4mm(
            source,
            output=output,
            trusted_load_joblib=True,
            tool_version="0.0.5",
        )
    assert (output / "keep").read_text(encoding="utf-8") == "do not touch"

from __future__ import annotations

import copy
from pathlib import Path

import pytest
from scripts.validate_support_matrix import DuplicateKeyError, load_matrix, validate_matrix

ROOT = Path(__file__).resolve().parents[1]


def test_checked_in_support_matrix_matches_source_and_docs() -> None:
    assert validate_matrix(load_matrix(), root=ROOT) == []


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda doc: doc["inputs"].pop(), "omits detected source kinds"),
        (lambda doc: doc["inputs"].append(copy.deepcopy(doc["inputs"][0])), "duplicate source_kind"),
        (lambda doc: doc["train"].update(guaranteed_reader_releases=[]), "guaranteed for exactly R3 and R4"),
        (lambda doc: doc["train"].update(earliest_removal="R4"), "cannot occur before post-V1"),
        (
            lambda doc: doc["service_levels"]["read"].update(commitment="best effort"),
            "exact read, write, and migrate commitments",
        ),
        (lambda doc: doc["immutability"].update(source_bytes="mutable"), "must remain immutable"),
        (lambda doc: doc["inputs"][0].update(write="legacy_in_place"), "fresh_workspace_v2_only"),
        (lambda doc: doc["rollback"].update(versions=[]), "exact R1, R2, and R3"),
    ],
)
def test_validator_refuses_support_contract_drift(mutate: object, message: str) -> None:
    document = copy.deepcopy(load_matrix())
    mutate(document)  # type: ignore[operator]
    assert any(message in error for error in validate_matrix(document, root=ROOT))


def test_loader_refuses_duplicate_json_keys(tmp_path: Path) -> None:
    matrix = tmp_path / "duplicate.json"
    matrix.write_text('{"schema_version": 1, "schema_version": 1}', encoding="utf-8")
    with pytest.raises(DuplicateKeyError, match="duplicate JSON key: schema_version"):
        load_matrix(matrix)

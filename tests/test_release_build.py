from __future__ import annotations

import gzip
import hashlib
import io
import json
import re
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from scripts.build_release import normalize_sdist, source_date_epoch
from scripts.write_release_sbom import release_sbom, write_release_sbom

ROOT = Path(__file__).resolve().parents[1]


def _write_varying_sdist(path: Path, *, mtime: float, owner: str) -> None:
    payload = b"same artifact content\n"
    with (
        path.open("wb") as raw_output,
        gzip.GzipFile(filename=path.name, mode="wb", fileobj=raw_output, mtime=int(mtime)) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        member = tarfile.TarInfo("nirs4all_tools-0.0.7/payload.txt")
        member.size = len(payload)
        member.mtime = mtime
        member.uid = 1000
        member.gid = 1000
        member.uname = owner
        member.gname = owner
        archive.addfile(member, io.BytesIO(payload))


def test_normalize_sdist_is_byte_reproducible(tmp_path: Path) -> None:
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    _write_varying_sdist(first, mtime=1_800_000_000.125, owner="first")
    _write_varying_sdist(second, mtime=1_900_000_000.875, owner="second")

    normalize_sdist(first, 1_700_000_000)
    normalize_sdist(second, 1_700_000_000)

    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first, mode="r:gz") as archive:
        member = archive.getmember("nirs4all_tools-0.0.7/payload.txt")
        assert member.mtime == 1_700_000_000
        assert member.uid == member.gid == 0
        assert member.uname == member.gname == ""
        assert member.pax_headers == {}


def test_source_date_epoch_rejects_invalid_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-an-epoch")
    with pytest.raises(ValueError, match="integer Unix timestamp"):
        source_date_epoch()


def test_release_build_toolchain_is_exactly_pinned() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    requirements = [Requirement(value) for value in pyproject["build-system"]["requires"]]
    assert {requirement.name for requirement in requirements} == {"setuptools", "wheel"}
    for requirement in requirements:
        pins = list(requirement.specifier)
        assert len(pins) == 1 and pins[0].operator == "==" and "*" not in pins[0].version
    workflow = (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
    assert "python -m pip install build==1.6.0 twine==7.0.0" in workflow
    assert "python scripts/build_release.py" in workflow
    actions = re.findall(r"uses:\s*([\w/-]+)@([^\s]+)", workflow)
    assert {name for name, _ in actions} >= {"actions/checkout", "actions/setup-python"}
    assert all(re.fullmatch(r"[a-f0-9]{40}", revision) for _, revision in actions)


def _write_test_wheel(path: Path) -> None:
    metadata = """Metadata-Version: 2.4
Name: nirs4all-tools
Version: 0.0.7
License-Expression: CECILL-2.1 OR AGPL-3.0-or-later
Requires-Dist: pyarrow>=14.0.0; extra == \"parquet\"

Test wheel.
"""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("nirs4all_tools-0.0.7.dist-info/METADATA", metadata)


def test_release_sbom_binds_source_and_both_distributions(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = dist / "nirs4all_tools-0.0.7-py3-none-any.whl"
    sdist = dist / "nirs4all_tools-0.0.7.tar.gz"
    _write_test_wheel(wheel)
    sdist.write_bytes(b"test sdist")
    commit = "a" * 40

    document = release_sbom(wheel, sdist, commit)

    component = document["metadata"]["component"]
    assert component["version"] == "0.0.7"
    assert component["purl"] == "pkg:pypi/nirs4all-tools@0.0.7"
    assert component["hashes"] == [
        {"alg": "SHA-256", "content": hashlib.sha256(wheel.read_bytes()).hexdigest()}
    ]
    properties = {item["name"]: item["value"] for item in component["properties"]}
    assert properties["nirs4all:source:commit"] == commit
    assert properties["nirs4all:artifact:sdist:sha256"] == hashlib.sha256(sdist.read_bytes()).hexdigest()
    assert properties["nirs4all:declared-requires-dist:1"].startswith("pyarrow>=14.0.0")


def test_release_sbom_output_is_reproducible(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_test_wheel(dist / "nirs4all_tools-0.0.7-py3-none-any.whl")
    (dist / "nirs4all_tools-0.0.7.tar.gz").write_bytes(b"test sdist")
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    write_release_sbom(dist, first, "b" * 40)
    write_release_sbom(dist, second, "b" * 40)

    assert first.read_bytes() == second.read_bytes()
    assert json.loads(first.read_text(encoding="utf-8"))["metadata"]["component"]["version"] == "0.0.7"

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

import pytest
from scripts.build_release import normalize_sdist, source_date_epoch


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

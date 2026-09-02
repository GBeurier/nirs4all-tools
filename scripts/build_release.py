"""Build reproducible nirs4all-tools release archives.

``setuptools`` currently leaves build-time, fractional mtimes and local owner
names in the PAX headers of generated sdists. ``SOURCE_DATE_EPOCH`` alone is
therefore insufficient. This helper builds with a stable epoch and rewrites
the sdist metadata without extracting or changing member contents.
"""

from __future__ import annotations

import argparse
import copy
import gzip
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def source_date_epoch() -> int:
    """Return the explicit epoch, or the checked-out commit timestamp."""
    raw_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if raw_epoch is None:
        raw_epoch = subprocess.run(
            ["git", "show", "-s", "--format=%ct", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    try:
        epoch = int(raw_epoch)
    except ValueError as exc:
        raise ValueError("SOURCE_DATE_EPOCH must be an integer Unix timestamp") from exc
    if epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must not be negative")
    return epoch


def normalize_sdist(path: Path, epoch: int) -> None:
    """Canonicalize tar and gzip metadata in one built sdist."""
    temporary = path.with_name(f".{path.name}.normalized")
    try:
        with (
            tarfile.open(path, mode="r:gz") as source,
            temporary.open("wb") as raw_output,
            gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw_output,
                mtime=epoch,
            ) as compressed_output,
            tarfile.open(
                fileobj=compressed_output,
                mode="w",
                format=tarfile.PAX_FORMAT,
            ) as target,
        ):
            for member in sorted(source.getmembers(), key=lambda item: item.name):
                normalized = copy.copy(member)
                normalized.uid = 0
                normalized.gid = 0
                normalized.uname = ""
                normalized.gname = ""
                normalized.mtime = epoch
                normalized.pax_headers = {}
                payload = source.extractfile(member) if member.isfile() else None
                target.addfile(normalized, payload)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def build_release(outdir: Path) -> list[Path]:
    """Build the wheel and one normalized sdist into ``outdir``."""
    epoch = source_date_epoch()
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = str(epoch)
    outdir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".n4a-build-", dir=outdir.parent) as staging_raw:
        staging = Path(staging_raw)
        subprocess.run(
            [sys.executable, "-m", "build", "--outdir", str(staging)],
            check=True,
            env=environment,
        )
        sdists = sorted(staging.glob("*.tar.gz"))
        if len(sdists) != 1:
            raise RuntimeError(f"expected exactly one sdist in {staging}, found {len(sdists)}")
        normalize_sdist(sdists[0], epoch)
        destinations = []
        for artifact in sorted(path for path in staging.iterdir() if path.is_file()):
            destination = outdir / artifact.name
            os.replace(artifact, destination)
            destinations.append(destination)
    return destinations


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outdir", type=Path, default=Path("dist"))
    args = parser.parse_args()
    for artifact in build_release(args.outdir):
        print(artifact)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

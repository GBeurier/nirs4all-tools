"""Write a reproducible CycloneDX SBOM for the base release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from email.parser import Parser
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _wheel_metadata(wheel: Path) -> tuple[str, str, str, list[str]]:
    with zipfile.ZipFile(wheel) as archive:
        candidates = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(candidates) != 1:
            raise ValueError(f"expected exactly one wheel METADATA file, found {len(candidates)}")
        metadata = Parser().parsestr(archive.read(candidates[0]).decode("utf-8"))
    name = metadata["Name"]
    version = metadata["Version"]
    license_expression = metadata["License-Expression"]
    if not name or not version or not license_expression:
        raise ValueError("wheel metadata must declare Name, Version, and License-Expression")
    return name, version, license_expression, metadata.get_all("Requires-Dist", [])


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def source_commit() -> str:
    """Return the exact checked-out source commit."""
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError(f"invalid Git commit identity: {commit!r}")
    return commit


def release_sbom(wheel: Path, sdist: Path, commit: str) -> dict[str, Any]:
    """Build a deterministic CycloneDX 1.6 document."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("commit must be a full lowercase SHA-1")
    name, version, license_expression, requirements = _wheel_metadata(wheel)
    canonical_name = _canonical_name(name)
    expected_prefix = canonical_name.replace("-", "_") + f"-{version}"
    if not wheel.name.startswith(expected_prefix) or not sdist.name.startswith(expected_prefix):
        raise ValueError("wheel and sdist filenames do not match their package metadata")
    purl = f"pkg:pypi/{canonical_name}@{version}"
    properties = [
        {"name": "nirs4all:source:commit", "value": commit},
        {"name": "nirs4all:artifact:wheel", "value": wheel.name},
        {"name": "nirs4all:artifact:wheel:sha256", "value": _sha256(wheel)},
        {"name": "nirs4all:artifact:sdist", "value": sdist.name},
        {"name": "nirs4all:artifact:sdist:sha256", "value": _sha256(sdist)},
        {"name": "nirs4all:sbom:scope", "value": "base wheel; optional extras not installed"},
    ]
    properties.extend(
        {"name": f"nirs4all:declared-requires-dist:{index}", "value": requirement}
        for index, requirement in enumerate(sorted(requirements), start=1)
    )
    component = {
        "bom-ref": purl,
        "hashes": [{"alg": "SHA-256", "content": _sha256(wheel)}],
        "licenses": [{"expression": license_expression}],
        "name": canonical_name,
        "properties": properties,
        "purl": purl,
        "type": "library",
        "version": version,
    }
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "dependencies": [{"ref": purl}],
        "metadata": {
            "component": component,
            "properties": [{"name": "cdx:reproducible", "value": "true"}],
            "tools": {
                "components": [
                    {
                        "name": "nirs4all-tools-write-release-sbom",
                        "type": "application",
                        "version": "1",
                    }
                ]
            },
        },
        "specVersion": "1.6",
        "version": 1,
    }


def write_release_sbom(dist_dir: Path, output: Path, commit: str) -> None:
    """Find one wheel and sdist, then write their canonical SBOM."""
    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError(f"expected one wheel and one sdist in {dist_dir}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(release_sbom(wheels[0], sdists[0], commit), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", default=None)
    args = parser.parse_args()
    write_release_sbom(args.dist_dir, args.output, args.source_commit or source_commit())
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

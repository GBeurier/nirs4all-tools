from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_complete_dual_license_texts_are_part_of_package_metadata() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert project["license"] == "CECILL-2.1 OR AGPL-3.0-or-later"
    assert project["license-files"] == [
        "LICENSE",
        "LICENSES/*.txt",
        "LICENSES/COMMERCIAL-LICENSE*.md",
    ]
    expected = {
        "LICENSES/CeCILL-2.1.txt": "4ea234937bc7b0aa5247e436690d1eb9324875bc7590ecde50befd38e35190a5",
        "LICENSES/AGPL-3.0-or-later.txt": "d8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee",
    }
    for relative, digest in expected.items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == digest


def test_commercial_notices_name_this_distribution() -> None:
    for name in ("COMMERCIAL-LICENSE.md", "COMMERCIAL-LICENSE_FR.md"):
        notice = (ROOT / "LICENSES" / name).read_text(encoding="utf-8")
        assert "nirs4all-tools" in notice
        assert "nirs4all-core" not in notice

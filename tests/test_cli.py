"""End-to-end CLI tests: ``main(argv)`` dispatch and exit-code mapping."""

from __future__ import annotations

from pathlib import Path

import pytest

from nirs4all_tools import __version__
from nirs4all_tools.cli import main
from nirs4all_tools.exit_codes import ExitCode


def test_version_flag_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_subcommand_is_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 2
    assert main(["legacy"]) == 2


def test_inspect_recognized_returns_zero(sqlite_v2_workspace: Path) -> None:
    assert main(["legacy", "inspect", str(sqlite_v2_workspace)]) == int(ExitCode.SUCCESS)


def test_inspect_unknown_returns_twenty(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["legacy", "inspect", str(empty), "--format", "text"]) == int(ExitCode.UNSUPPORTED_INPUT)


def test_migrate_aliased_output_returns_forty(sqlite_v2_workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["legacy", "migrate", str(sqlite_v2_workspace), "--output", str(sqlite_v2_workspace)])
    assert code == int(ExitCode.REFUSED_BY_POLICY)
    assert "forced_in_place_refused" in capsys.readouterr().err


def test_migrate_native_target_returns_twenty(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    code = main(
        [
            "legacy",
            "migrate",
            str(sqlite_v2_workspace),
            "--output",
            str(tmp_path / "out"),
            "--target",
            "native-results-v1",
        ]
    )
    assert code == int(ExitCode.UNSUPPORTED_INPUT)


def test_migrate_dry_run_returns_zero(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    code = main(
        [
            "legacy",
            "migrate",
            str(sqlite_v2_workspace),
            "--output",
            str(tmp_path / "out"),
            "--dry-run",
            "--manifest",
            str(tmp_path / "preview.json"),
        ]
    )
    assert code == int(ExitCode.SUCCESS)
    assert not (tmp_path / "out").exists()


def test_migrate_copy_only_then_verify_via_cli(sqlite_v2_workspace: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert main(["legacy", "migrate", str(sqlite_v2_workspace), "--output", str(out), "--copy-only"]) == int(
        ExitCode.SUCCESS
    )
    code = main(["legacy", "verify", str(out), "--manifest", str(out / "migration-manifest.json")])
    assert code == int(ExitCode.SUCCESS)

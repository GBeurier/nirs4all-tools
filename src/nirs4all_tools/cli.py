"""``nirs4all-tools`` command-line surface (``SW4_MIG_CONVERTER_spec.md`` §6).

```
nirs4all-tools --version
nirs4all-tools legacy inspect <input> [--format json|text] [--report PATH]
nirs4all-tools legacy migrate <input> --output DIR --target nirs4all-workspace-v2
                                      [--manifest PATH] [--report PATH] [--id-map PATH]
                                      [--checksums sha256]
                                      [--dry-run | --verify]
                                      [--strict | --best-effort]
                                      [--copy-only] [--resume] [--trusted-load-joblib]
nirs4all-tools legacy verify <output-dir> --manifest PATH [--report PATH]
```
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, commands, vocab
from .errors import ToolError
from .exit_codes import ExitCode

_USAGE_ERROR = 2  # argparse convention for usage problems (distinct from domain codes)


def _cmd_inspect(args: argparse.Namespace) -> ExitCode:
    return commands.inspect(args.input, fmt=args.format, report_path=args.report)


def _cmd_migrate(args: argparse.Namespace) -> ExitCode:
    return commands.migrate(
        args.input,
        output=args.output,
        target=args.target,
        manifest_path=args.manifest,
        report_path=args.report,
        id_map_path=args.id_map,
        checksums_algo=args.checksums,
        dry_run=args.dry_run,
        verify=args.verify,
        strict=args.strict,
        copy_only=args.copy_only,
        resume=args.resume,
        trusted_load_joblib=args.trusted_load_joblib,
        tool_version=__version__,
    )


def _cmd_verify(args: argparse.Namespace) -> ExitCode:
    return commands.verify(args.output_dir, manifest_path=args.manifest, report_path=args.report)


def build_parser() -> argparse.ArgumentParser:
    """Construct the full argument parser."""
    parser = argparse.ArgumentParser(
        prog="nirs4all-tools",
        description="Offline, one-way, no-in-place migration tools for legacy nirs4all artifacts.",
    )
    parser.add_argument("--version", action="version", version=f"nirs4all-tools {__version__}")

    groups = parser.add_subparsers(dest="group")
    legacy = groups.add_parser("legacy", help="legacy artifact conversion tools")
    legacy_cmds = legacy.add_subparsers(dest="command")

    insp = legacy_cmds.add_parser("inspect", help="read-only detection of a legacy source")
    insp.add_argument("input", type=Path, help="legacy workspace directory or bundle file")
    insp.add_argument("--format", choices=["json", "text"], default="json", help="output format")
    insp.add_argument(
        "--report", type=Path, default=None, help="write the inspection document to PATH (outside the source)"
    )
    insp.set_defaults(func=_cmd_inspect)

    mig = legacy_cmds.add_parser("migrate", help="convert a legacy source into a fresh output (no-in-place)")
    mig.add_argument("input", type=Path, help="legacy workspace directory or bundle file (read-only)")
    mig.add_argument("--output", type=Path, required=True, help="fresh output directory (must be disjoint from input)")
    mig.add_argument(
        "--target",
        choices=[vocab.TARGET_WORKSPACE_V2, vocab.TARGET_NATIVE_RESULTS_V1],
        default=vocab.TARGET_WORKSPACE_V2,
        help="target schema (native-results-v1 is Phase-2, gated)",
    )
    mig.add_argument(
        "--manifest", type=Path, default=None, help="manifest path (default: <output>/migration-manifest.json)"
    )
    mig.add_argument("--report", type=Path, default=None, help="report path (default: <output>/migration-report.json)")
    mig.add_argument(
        "--id-map", dest="id_map", type=Path, default=None, help="id-map path (default: <output>/migration-id-map.json)"
    )
    mig.add_argument("--checksums", choices=["sha256"], default="sha256", help="checksum algorithm")
    mode = mig.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", dest="dry_run", action="store_true", help="detect + simulate; write no output store")
    mode.add_argument("--verify", action="store_true", help="migrate, then fully verify the output")
    effort = mig.add_mutually_exclusive_group()
    effort.add_argument("--strict", action="store_true", help="abort on the first unsupported item")
    effort.add_argument(
        "--best-effort", dest="best_effort", action="store_true", help="preserve unsupported items opaque (default)"
    )
    mig.add_argument(
        "--copy-only", dest="copy_only", action="store_true", help="faithful checksummed copy, no schema transform"
    )
    mig.add_argument(
        "--resume", action="store_true", help="continue into a non-empty output validated by a prior manifest"
    )
    mig.add_argument(
        "--trusted-load-joblib",
        dest="trusted_load_joblib",
        action="store_true",
        help="opt-in to loading trusted joblib artifacts",
    )
    mig.set_defaults(func=_cmd_migrate)

    ver = legacy_cmds.add_parser("verify", help="verify an output against its manifest (reads no source)")
    ver.add_argument("output_dir", type=Path, metavar="output-dir", help="migrated output directory")
    ver.add_argument("--manifest", type=Path, required=True, help="manifest produced by a prior migrate run")
    ver.add_argument("--report", type=Path, default=None, help="write the verification report to PATH")
    ver.set_defaults(func=_cmd_verify)

    return parser


def _print_error(exc: ToolError) -> None:
    payload = {
        "error": {
            "code": exc.exit_code.name,
            "exit_code": int(exc.exit_code),
            "cause": exc.cause,
            "message": exc.message,
            "mitigation": exc.mitigation,
        }
    }
    print(json.dumps(payload, indent=2), file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    """Entry point: parse args, dispatch, map :class:`ToolError` to exit codes."""
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help(sys.stderr)
        return _USAGE_ERROR
    try:
        code = func(args)
    except ToolError as exc:
        _print_error(exc)
        return int(exc.exit_code)
    return int(code)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

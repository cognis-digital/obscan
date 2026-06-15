"""Command-line interface for OBSCAN.

Examples
--------
    # Lint an OpenAPI file (human-readable table)
    obscan lint openapi.json

    # Machine-readable output for CI pipelines
    obscan lint openapi.json --format json | jq .

    # Treat warnings as failures too
    obscan lint openapi.json --fail-on warning

Exit codes:
    0  no findings at or above the failure threshold
    1  conformance findings at/above threshold (default: error) — fails CI
    2  usage / input error (bad file, invalid JSON, not an OpenAPI doc)
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    DocumentError,
    Severity,
    load_document,
    lint_document,
    summarize,
    has_failures,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "OBSCAN — Open Banking / FAPI / PSD2 conformance linter for "
            "OpenAPI documents. Fails your CI on non-compliant OAuth, consent "
            "scope and PSD2 endpoint definitions."
        ),
        epilog=(
            "examples:\n"
            "  obscan lint openapi.json\n"
            "  obscan lint openapi.json --format json | jq .\n"
            "  obscan lint openapi.json --fail-on warning\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    sub = parser.add_subparsers(dest="command")

    lint = sub.add_parser(
        "lint",
        help="lint an OpenAPI document for Open Banking / FAPI conformance",
        description="Lint an OpenAPI JSON document and report conformance findings.",
    )
    lint.add_argument("file", help="path to an OpenAPI JSON document")
    lint.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )
    lint.add_argument(
        "--fail-on",
        choices=("error", "warning", "info"),
        default="error",
        help="minimum severity that causes a non-zero exit (default: error)",
    )
    return parser


def _render_table(file: str, findings, counts) -> str:
    lines = []
    lines.append(f"OBSCAN report for {file}")
    lines.append("=" * max(24, len(file) + 18))
    if not findings:
        lines.append("No conformance findings. ✓")
    else:
        width = max(len(f.rule_id) for f in findings)
        for f in findings:
            sev = f.severity.value.upper().ljust(7)
            loc = f"  @ {f.path}" if f.path else ""
            lines.append(f"[{sev}] {f.rule_id.ljust(width)}  {f.message}{loc}")
    lines.append("-" * max(24, len(file) + 18))
    lines.append(
        f"errors: {counts['error']}  "
        f"warnings: {counts['warning']}  "
        f"info: {counts['info']}"
    )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "lint":
        parser.print_help()
        return 0

    try:
        doc = load_document(args.file)
    except DocumentError as exc:
        print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
        return 2

    try:
        findings = lint_document(doc)
    except TypeError as exc:
        print(f"{TOOL_NAME}: internal error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"{TOOL_NAME}: unexpected error during linting: {exc}", file=sys.stderr)
        return 2

    counts = summarize(findings)
    fail_on = Severity(args.fail_on)

    try:
        if args.format == "json":
            payload = {
                "tool": TOOL_NAME,
                "version": TOOL_VERSION,
                "file": args.file,
                "summary": counts,
                "failed": has_failures(findings, fail_on),
                "findings": [f.to_dict() for f in findings],
            }
            print(json.dumps(payload, indent=2))
        else:
            print(_render_table(args.file, findings, counts))
    except BrokenPipeError:
        # stdout closed mid-stream (e.g. piped to `head`); not an error.
        pass
    except OSError as exc:
        print(f"{TOOL_NAME}: output error: {exc}", file=sys.stderr)
        return 2

    return 1 if has_failures(findings, fail_on) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

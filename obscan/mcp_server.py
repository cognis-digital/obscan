"""OBSCAN MCP server — exposes lint_file() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from obscan.core import DocumentError, lint_file, summarize, has_failures


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-obscan[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install the MCP extra: pip install 'cognis-obscan[mcp]'")
        return 1
    app = FastMCP("obscan")

    @app.tool()
    def obscan_scan(target: str) -> str:
        """Conformance and security linter for Open Banking / FAPI APIs.

        Validates OAuth flows, consent scopes, and PSD2 endpoints against
        the spec. Returns JSON findings.
        """
        if not target:
            return json.dumps({"error": "target path must not be empty"})
        try:
            findings = lint_file(target)
        except DocumentError as exc:
            return json.dumps({"error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"error": f"unexpected error: {exc}"})
        counts = summarize(findings)
        return json.dumps(
            {
                "summary": counts,
                "failed": has_failures(findings),
                "findings": [f.to_dict() for f in findings],
            },
            indent=2,
        )

    app.run()
    return 0

"""OBSCAN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from obscan.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-obscan[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-obscan[mcp]'")
        return 1
    app = FastMCP("obscan")

    @app.tool()
    def obscan_scan(target: str) -> str:
        """Conformance and security linter for Open Banking / FAPI APIs: validates OAuth flows, consent scopes, and PSD2 endpoints against the spec.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0

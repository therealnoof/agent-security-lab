"""
=============================================================
 MCP Server — per-agent capability manifest (Module 2)
=============================================================
 Loads capabilities.json and exposes a single helper used by
 server.py to filter both list_tools (so the LLM never sees
 a tool its agent has no business calling) and call_tool
 (defense-in-depth: fail closed if a model somehow asks for
 a tool that isn't in its menu).

 Manifest format (capabilities.json):
   {
     "<oauth client id>": ["<allowed tool name>", ...],
     ...
   }

 Anything not in the manifest gets the empty set -> deny all.
 The MCP_SKIP_AUTH escape hatch (used by Slice A demos) flips
 this open by setting the contextvar in auth.py to a sentinel
 that means "all tools".
=============================================================
"""

import json
import os
from pathlib import Path

_DEFAULT_PATH = Path(__file__).parent / "capabilities.json"
MANIFEST_PATH = os.environ.get("MCP_CAPABILITY_MANIFEST", str(_DEFAULT_PATH))

# Sentinel for "all tools allowed" (used by SKIP_AUTH path).
ALL_TOOLS = "*"

with open(MANIFEST_PATH) as f:
    _MANIFEST: dict[str, list[str]] = json.load(f)


def allowed_tools(client_id: str | None) -> set[str] | str:
    """
    Return the set of tool names the given OAuth client may invoke.
    Returns the ALL_TOOLS sentinel when client_id == ALL_TOOLS.
    Empty set means default-deny (no manifest entry).
    """
    if client_id == ALL_TOOLS:
        return ALL_TOOLS
    if not client_id:
        return set()
    return set(_MANIFEST.get(client_id, []))


def is_allowed(client_id: str | None, tool_name: str) -> bool:
    granted = allowed_tools(client_id)
    if granted == ALL_TOOLS:
        return True
    return tool_name in granted

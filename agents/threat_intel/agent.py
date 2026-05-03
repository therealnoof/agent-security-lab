"""
=============================================================
 THREAT-INTEL AGENT — second vertical slice (Module 0.5)
=============================================================
 What this file does:
   The Threat-Intel agent investigates indicators of
   compromise (IPs, alerts, etc.) using the SOC tools that
   the MCP server exposes. Unlike the Triage agent (which
   has no tools and only plans), this agent is a TOOL USER:
   it talks to the LLM through the F5 AI Security proxy,
   the LLM emits "function calls" describing which tool to
   run, and we execute them via MCP and feed the results
   back. That cycle repeats until the LLM stops calling
   tools and produces a final assessment.

   This is the canonical agentic loop — the same shape used
   by Cursor, Claude Code, and most "do something for me"
   agents in production. It is also the loop that goes
   wrong in the PocketOS / Cursor / Apr-2026 incident: the
   model decides what tool to call, and if the tool can do
   something destructive, the model can do it.

   In Module 0.5 there is no OAuth and the MCP server is
   wide-open: any caller can invoke any tool. Module 1
   adds OAuth scoping; Module 2 adds per-agent capability
   manifests on the MCP server.

 What the BYOA platform sees:
   - Every LLM call is tagged with this agent's session ID,
     distinct from Triage's session ID. So in F5's UI you
     get TWO trails for the same lab run, and you can flip
     between them to see how each agent reasoned.
   - The model's tool-call decisions appear in the chain of
     thought — that's how you "see the agent decide" before
     it acts.
=============================================================
"""

import asyncio
import json
import os
import sys
import uuid
from datetime import datetime, timezone

import httpx
import openai
from openai import OpenAI
from mcp import ClientSession
from mcp.client.sse import sse_client


# -------------------------------------------------------
# CONFIGURATION (from environment — see .env.example)
# -------------------------------------------------------
AGENT_NAME = os.environ.get("AGENT_NAME", "threat-intel")
LAB_RUN_ID = os.environ.get("LAB_RUN_ID") or uuid.uuid4().hex[:8]

CALYPSOAI_TOKEN = os.environ.get("CALYPSOAI_TOKEN")
CALYPSOAI_OPENAI_API_BASE = os.environ.get("CALYPSOAI_OPENAI_API_BASE")
CALYPSOAI_MODEL = os.environ.get("CALYPSOAI_MODEL", "gpt-4o-mini")

# MCP server reachable inside the docker network.
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://mcp-server:8000/sse")

# Safety guard: stop after this many tool-calling rounds even
# if the LLM keeps wanting to call more. A confused agent
# could otherwise loop forever; in production this is the
# single cheapest guardrail you can add.
MAX_ITERATIONS = int(os.environ.get("MAX_ITERATIONS", "8"))

# OAuth (Module 2). Identical pattern to the Remediation agent —
# fetch a client_credentials token and present it on the MCP SSE
# connection. Threat-Intel's Keycloak client is granted only
# `mcp:read`, and Module 2's capability manifest filters its
# tool menu to the SOC investigation tools.
KEYCLOAK_ISSUER     = os.environ.get("KEYCLOAK_ISSUER")
OAUTH_CLIENT_ID     = os.environ.get("OAUTH_CLIENT_ID", "agent-threat-intel")
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "agent-threat-intel-secret-change-me")

if not CALYPSOAI_TOKEN or not CALYPSOAI_OPENAI_API_BASE:
    sys.exit(
        "Missing CALYPSOAI_TOKEN or CALYPSOAI_OPENAI_API_BASE. "
        "Copy .env.example to .env and fill them in."
    )

# -------------------------------------------------------
# Per-run session ID — distinct from Triage's, so BYOA
# shows separate trails for each agent in the same run.
# -------------------------------------------------------
session_id = "-".join([
    LAB_RUN_ID,
    AGENT_NAME,
    datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
    uuid.uuid4().hex[:6],
])

# -------------------------------------------------------
# OpenAI client pointed at the F5/Calypso proxy.
# Same three-line BYOA pattern as Triage. Anything you
# already have an OpenAI client for can be re-pointed here
# without code changes beyond these three params.
# -------------------------------------------------------
client = OpenAI(
    api_key=CALYPSOAI_TOKEN,
    base_url=CALYPSOAI_OPENAI_API_BASE,
    default_headers={"x-cai-metadata-session-id": session_id},
)


# -------------------------------------------------------
# System prompt: define the agent's role and demand a
# strict final-output shape so a downstream consumer
# (or, for now, you) can parse it.
#
# Note we do NOT enumerate the tools here — the OpenAI
# function-calling protocol is what tells the model what
# tools exist. We just describe how to USE them.
# -------------------------------------------------------
SYSTEM_PROMPT = """\
You are the Threat-Intel agent in a SOC Incident Response team.
Your job: investigate ONE indicator of compromise (an IP, an alert
id, or a short task description) and produce a structured assessment.

Process:
  1. Use the tools available to you to gather facts. Do not speculate.
  2. Stop calling tools as soon as you can answer the task.
  3. When you stop, your final reply MUST be a single JSON object,
     and nothing else, with this exact shape:

{
  "investigated_indicator": "<the IP / alert id / subject you looked at>",
  "tools_used":             ["<tool name 1>", "<tool name 2>", ...],
  "findings":               ["<short factual statement>", "..."],
  "risk_score":             "low" | "medium" | "high" | "critical",
  "recommended_action":     "block" | "monitor" | "escalate" | "no-action",
  "rationale":              "<one sentence tying findings to the score>"
}

Constraints:
  - Do not invent facts. Every entry in `findings` must come from a tool result.
  - Prefer fewer, decisive tool calls over many speculative ones.
  - If a tool returns an error, decide whether to retry once or proceed without it.
"""

# Default task used if no TASK_DESCRIPTION env var is set. Mirrors
# the IP that appears in the default Triage alert so you can run
# Triage and Threat-Intel back-to-back and see them work the same case.
DEFAULT_TASK = (
    "Investigate source IP 185.220.101.45. Check its reputation and "
    "where it is hosted. Recommend whether to block."
)


def mcp_tool_to_openai_function(mcp_tool) -> dict:
    """
    Translate one MCP tool descriptor into the OpenAI function-calling
    schema the chat-completions API expects in its `tools` parameter.

    MCP tool fields we care about:
      .name        — function name (must be a valid identifier)
      .description — what the tool does (the LLM reads this to choose)
      .inputSchema — JSON Schema for the arguments
    """
    return {
        "type": "function",
        "function": {
            "name": mcp_tool.name,
            "description": mcp_tool.description or "",
            "parameters": mcp_tool.inputSchema or {"type": "object", "properties": {}},
        },
    }


async def fetch_oauth_token() -> str | None:
    """
    client_credentials grant against Keycloak. Returns None when no
    issuer is configured (lets the agent be run without OAuth for
    early debugging). Identical to the Remediation agent's helper.
    """
    if not KEYCLOAK_ISSUER:
        return None

    token_url = f"{KEYCLOAK_ISSUER.rstrip('/')}/protocol/openid-connect/token"
    print(f"[{AGENT_NAME}] fetching OAuth token from {token_url}", flush=True)

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            token_url,
            data={"grant_type": "client_credentials"},
            auth=(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET),
        )
    if resp.status_code != 200:
        print(
            f"[{AGENT_NAME}] !!! token fetch failed: "
            f"HTTP {resp.status_code} {resp.text[:200]}",
            flush=True,
        )
        sys.exit(2)

    body = resp.json()
    print(
        f"[{AGENT_NAME}] got token, scopes: {body.get('scope', '<none>')}, "
        f"expires_in={body.get('expires_in')}s",
        flush=True,
    )
    return body["access_token"]


def assistant_message(msg) -> dict:
    """
    Build the dict shape the OpenAI API expects when echoing an
    assistant turn back into the conversation. We rebuild it
    explicitly (rather than .model_dump()) so we drop any extra
    fields that some upstream models reject.
    """
    out: dict = {"role": "assistant", "content": msg.content}
    if msg.tool_calls:
        out["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                },
            }
            for tc in msg.tool_calls
        ]
    return out


async def run() -> None:
    task = os.environ.get("TASK_DESCRIPTION") or DEFAULT_TASK

    print(f"[{AGENT_NAME}] session_id   = {session_id}", flush=True)
    print(f"[{AGENT_NAME}] proxy        = {CALYPSOAI_OPENAI_API_BASE}", flush=True)
    print(f"[{AGENT_NAME}] model        = {CALYPSOAI_MODEL}", flush=True)
    print(f"[{AGENT_NAME}] mcp          = {MCP_SERVER_URL}", flush=True)
    print(f"[{AGENT_NAME}] task         = {task}", flush=True)

    token = await fetch_oauth_token()
    headers = {"Authorization": f"Bearer {token}"} if token else None
    print(
        f"[{AGENT_NAME}] mcp auth     = {'OAuth bearer' if token else 'anonymous'}",
        flush=True,
    )

    print(f"[{AGENT_NAME}] ─── connecting to MCP and listing tools ───", flush=True)

    # Connect to the MCP server, discover tools, run the agent loop.
    # `sse_client` opens an SSE stream; `ClientSession` wraps it in
    # the MCP protocol handshake.
    async with sse_client(MCP_SERVER_URL, headers=headers) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as mcp_session:
            await mcp_session.initialize()

            mcp_tools = (await mcp_session.list_tools()).tools
            tool_index = {t.name: t for t in mcp_tools}
            openai_tools = [mcp_tool_to_openai_function(t) for t in mcp_tools]

            print(
                f"[{AGENT_NAME}] tools advertised by MCP: "
                + ", ".join(sorted(tool_index)),
                flush=True,
            )

            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": task},
            ]

            for iteration in range(1, MAX_ITERATIONS + 1):
                print(f"[{AGENT_NAME}] ─── round {iteration}: calling proxy ───", flush=True)
                try:
                    resp = client.chat.completions.create(
                        model=CALYPSOAI_MODEL,
                        messages=messages,
                        tools=openai_tools,
                    )
                except openai.APIStatusError as e:
                    # Module 4: F5 AI Guardrails refused the prompt mid-loop.
                    print(
                        f"[{AGENT_NAME}] ─── BLOCKED at the proxy "
                        f"(HTTP {e.status_code}) on round {iteration} ───",
                        flush=True,
                    )
                    try:
                        print(json.dumps(e.response.json(), indent=2), flush=True)
                    except Exception:
                        print(e.response.text[:1000], flush=True)
                    print(
                        f"[{AGENT_NAME}] Look up session {session_id} in F5 AI Security "
                        f"(Projects → your Agent project → Sessions → Outcome Analysis).",
                        flush=True,
                    )
                    return
                msg = resp.choices[0].message
                messages.append(assistant_message(msg))

                if not msg.tool_calls:
                    # Final answer: the model produced content with no
                    # further tool calls. Print and exit.
                    print(f"[{AGENT_NAME}] ─── final assessment ───", flush=True)
                    print(msg.content, flush=True)
                    print(
                        f"[{AGENT_NAME}] ─── done. Look up session "
                        f"{session_id} in F5 AI Security ───",
                        flush=True,
                    )
                    return

                # Execute every tool call the model emitted this round.
                for tc in msg.tool_calls:
                    tool_name = tc.function.name
                    try:
                        tool_args = json.loads(tc.function.arguments or "{}")
                    except json.JSONDecodeError as e:
                        result_text = f'{{"error": "agent emitted invalid JSON args: {e}"}}'
                    else:
                        if tool_name not in tool_index:
                            result_text = f'{{"error": "tool {tool_name!r} not advertised by MCP"}}'
                        else:
                            print(
                                f"[{AGENT_NAME}]   tool call: {tool_name}({json.dumps(tool_args)})",
                                flush=True,
                            )
                            try:
                                result = await mcp_session.call_tool(tool_name, tool_args)
                                # MCP tool results come back as a list of content
                                # blocks. For our text-returning tools, .text
                                # is what we want.
                                result_text = "\n".join(
                                    getattr(block, "text", str(block))
                                    for block in result.content
                                )
                            except Exception as e:
                                result_text = f'{{"error": "tool execution failed: {e}"}}'

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result_text,
                    })

            # If we get here, the model kept asking for more tools and
            # blew through MAX_ITERATIONS. That's a real production
            # failure mode — call it out instead of silently exiting.
            print(
                f"[{AGENT_NAME}] !!! reached MAX_ITERATIONS={MAX_ITERATIONS} "
                "without a final assessment — aborting.",
                flush=True,
            )
            sys.exit(2)


if __name__ == "__main__":
    asyncio.run(run())

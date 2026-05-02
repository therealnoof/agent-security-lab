"""
=============================================================
 TRIAGE AGENT — Vertical slice (Module 0)
=============================================================
 What this file does:
   The Triage agent is the planner of our SOC IR team. It reads
   one security alert and produces a JSON plan that assigns
   sub-tasks to specialist agents (threat-intel, remediation,
   comms).

   Triage has NO tools — it does not call MCP, it does not
   touch a database, it does not call other agents. It only
   reasons. That makes it the right starting point for the
   "Module 0: Setup & first BYOA session" lab step: it isolates
   the F5 AI Security (CalypsoAI) proxy wiring from MCP, OAuth,
   and A2A so we can prove BYOA / Agentic Fingerprints sees the
   agent's chain of thought before we add any other moving parts.

   How LLM traffic flows:
     agent.py ──HTTPS──► CalypsoAI OpenAI-compatible proxy ──► upstream model
                          ▲
                          │ x-cai-metadata-session-id header
                          │ → tags every call with a unique
                          │   session ID so Agentic Fingerprints
                          │   shows a per-agent trail in the UI.

   What students should observe in the F5 AI Security UI after
   running this agent: a session whose ID matches the one this
   process printed to stdout, containing the system prompt,
   the alert text, and the model's planning response.
=============================================================
"""

import os
import sys
import uuid
from datetime import datetime, timezone

from openai import OpenAI

# -------------------------------------------------------
# CONFIGURATION (from environment — see .env.example)
# -------------------------------------------------------
AGENT_NAME = os.environ.get("AGENT_NAME", "triage")

# LAB_RUN_ID is generated once at `docker compose up` so every
# agent in the same lab run shares a prefix. Falls back to a
# short UUID if a learner runs this agent directly.
LAB_RUN_ID = os.environ.get("LAB_RUN_ID") or uuid.uuid4().hex[:8]

# F5 AI Security (CalypsoAI) — OpenAI-compatible proxy.
# These come from the lab tenant; see PRD §9.5.
CALYPSOAI_TOKEN = os.environ.get("CALYPSOAI_TOKEN")
CALYPSOAI_OPENAI_API_BASE = os.environ.get("CALYPSOAI_OPENAI_API_BASE")
CALYPSOAI_MODEL = os.environ.get("CALYPSOAI_MODEL", "gpt-4o-mini")

if not CALYPSOAI_TOKEN or not CALYPSOAI_OPENAI_API_BASE:
    sys.exit(
        "Missing CALYPSOAI_TOKEN or CALYPSOAI_OPENAI_API_BASE. "
        "Copy .env.example to .env and fill them in."
    )

# -------------------------------------------------------
# Per-run session ID — the heart of BYOA visibility.
# Format: {lab_run}-{agent}-{utc_timestamp}-{rand}
# Each run gets a fresh ID so Agentic Fingerprints does not
# merge unrelated runs. (PRD §9.5 mandates uniqueness.)
# -------------------------------------------------------
session_id = "-".join([
    LAB_RUN_ID,
    AGENT_NAME,
    datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
    uuid.uuid4().hex[:6],
])

# -------------------------------------------------------
# OpenAI client pointed at the CalypsoAI proxy.
# The session-ID header is attached to every request this
# client makes — that is the BYOA hook.
# -------------------------------------------------------
client = OpenAI(
    api_key=CALYPSOAI_TOKEN,
    base_url=CALYPSOAI_OPENAI_API_BASE,
    default_headers={"x-cai-metadata-session-id": session_id},
)

# -------------------------------------------------------
# System prompt: defines the Triage agent's role and the
# strict JSON shape it must produce. We constrain the
# output so downstream agents (or, for now, students) can
# parse it cleanly.
# -------------------------------------------------------
SYSTEM_PROMPT = """\
You are the Triage agent in a multi-agent SOC Incident Response team.
Your job: read ONE security alert and output a JSON plan that assigns
sub-tasks to specialist agents.

Available specialist agents:
  - threat-intel : investigates indicators (IPs, hashes, domains)
  - remediation  : takes action against affected systems (quarantine
                   hosts, revoke credentials, prune corrupt records)
  - comms        : notifies stakeholders (Slack, email)

Output a single JSON object with EXACTLY this shape, and nothing else:
{
  "summary":  "<one-sentence summary of the alert>",
  "severity": "low" | "medium" | "high" | "critical",
  "tasks": [
    {
      "agent":     "<one of: threat-intel | remediation | comms>",
      "action":    "<short verb phrase>",
      "rationale": "<why this step is needed>"
    }
  ]
}

Rules:
  - Do not invent agents that are not in the list above.
  - Order tasks so investigation precedes remediation precedes comms.
  - If the alert is ambiguous, prefer threat-intel before remediation.
"""

# A benign sample alert used when no ALERT_TEXT env var is provided.
# Module 1 will swap this for the poisoned "drop the tickets table"
# alert that drives the destructive demo.
DEFAULT_ALERT = (
    "Source IP 185.220.101.45 attempted SSH login to web-prod-01. "
    "17 failed attempts in 60 seconds. Source is a known Tor exit node."
)


def main() -> None:
    alert = os.environ.get("ALERT_TEXT")
    if not alert and not sys.stdin.isatty():
        alert = sys.stdin.read().strip() or None
    if not alert:
        alert = DEFAULT_ALERT

    print(f"[{AGENT_NAME}] session_id   = {session_id}", flush=True)
    print(f"[{AGENT_NAME}] proxy        = {CALYPSOAI_OPENAI_API_BASE}", flush=True)
    print(f"[{AGENT_NAME}] model        = {CALYPSOAI_MODEL}", flush=True)
    print(f"[{AGENT_NAME}] alert        = {alert}", flush=True)
    print(f"[{AGENT_NAME}] ─── calling proxy ───", flush=True)

    resp = client.chat.completions.create(
        model=CALYPSOAI_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": alert},
        ],
    )

    plan = resp.choices[0].message.content
    print(f"[{AGENT_NAME}] ─── plan ───", flush=True)
    print(plan, flush=True)
    print(f"[{AGENT_NAME}] ─── done. Look up session {session_id} in F5 AI Security ───", flush=True)


if __name__ == "__main__":
    main()

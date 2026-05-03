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

import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone

import httpx
import openai
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

# A2A (Module 3). When COMMS_A2A_URL is set, after producing its
# JSON plan Triage will dispatch any task assigned to "comms" to
# the Comms agent's A2A endpoint. The OAuth token identifies the
# caller; the receiver checks our identity against its agent card.
KEYCLOAK_ISSUER     = os.environ.get("KEYCLOAK_ISSUER")
OAUTH_CLIENT_ID     = os.environ.get("OAUTH_CLIENT_ID", "agent-triage")
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "agent-triage-secret-change-me")
COMMS_A2A_URL       = os.environ.get("COMMS_A2A_URL")  # e.g. http://comms:9100

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
  - comms        : notifies stakeholders. Two skills:
                     * notify-internal — post to internal SOC Slack
                     * notify-external — send email to a party OUTSIDE
                       the organization (data egress; destructive)

Output a single JSON object with EXACTLY this shape, and nothing else:
{
  "summary":  "<one-sentence summary of the alert>",
  "severity": "low" | "medium" | "high" | "critical",
  "tasks": [
    {
      "agent":     "<one of: threat-intel | remediation | comms>",
      "skill":     "<for comms: 'notify-internal' or 'notify-external'; otherwise omit>",
      "action":    "<short verb phrase>",
      "rationale": "<why this step is needed>",
      "payload":   { ... optional dict of args for the skill ... }
    }
  ]
}

Rules:
  - Do not invent agents that are not in the list above.
  - Order tasks so investigation precedes remediation precedes comms.
  - If the alert is ambiguous, prefer threat-intel before remediation.
  - For comms tasks include a `skill` and a `payload` matching the chosen skill.
"""

# A benign sample alert used when no ALERT_TEXT env var is provided.
# Module 1 will swap this for the poisoned "drop the tickets table"
# alert that drives the destructive demo.
DEFAULT_ALERT = (
    "Source IP 185.220.101.45 attempted SSH login to web-prod-01. "
    "17 failed attempts in 60 seconds. Source is a known Tor exit node."
)


def fetch_oauth_token() -> str | None:
    """
    Synchronous (Triage's main is sync) client_credentials grant
    against Keycloak. Returns None when no issuer is configured —
    that path skips A2A dispatch entirely (early debugging).
    """
    if not KEYCLOAK_ISSUER:
        return None
    token_url = f"{KEYCLOAK_ISSUER.rstrip('/')}/protocol/openid-connect/token"
    print(f"[{AGENT_NAME}] fetching OAuth token from {token_url}", flush=True)
    resp = httpx.post(
        token_url,
        data={"grant_type": "client_credentials"},
        auth=(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET),
        timeout=10.0,
    )
    if resp.status_code != 200:
        print(
            f"[{AGENT_NAME}] !!! token fetch failed: HTTP {resp.status_code} {resp.text[:200]}",
            flush=True,
        )
        return None
    body = resp.json()
    print(
        f"[{AGENT_NAME}] got token, scopes: {body.get('scope', '<none>')}, "
        f"expires_in={body.get('expires_in')}s",
        flush=True,
    )
    return body["access_token"]


def parse_plan(plan_text: str) -> dict | None:
    """Strip markdown fences (Gemini sometimes adds them) and parse JSON."""
    s = plan_text.strip()
    s = re.sub(r"^```(?:json)?\s*", "", s)
    s = re.sub(r"\s*```\s*$", "", s)
    try:
        return json.loads(s)
    except Exception as e:
        print(f"[{AGENT_NAME}] !!! could not parse plan as JSON: {e}", flush=True)
        return None


def dispatch_to_comms(task: dict, token: str | None) -> None:
    """
    A2A dispatch: POST the task's payload to the Comms agent's skill
    endpoint. Identity is the OAuth Bearer token; the receiver
    consults its agent card to authorize.
    """
    if not COMMS_A2A_URL:
        print(f"[{AGENT_NAME}] (skipping dispatch: COMMS_A2A_URL not set)", flush=True)
        return

    skill = task.get("skill") or "notify-internal"
    url = f"{COMMS_A2A_URL.rstrip('/')}/a2a/skills/{skill}"
    payload = task.get("payload") or {
        "subject": "(no subject)",
        "body": task.get("action") or "(no body)",
    }

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    print(f"[{AGENT_NAME}] A2A → POST {url}  skill={skill}", flush=True)
    try:
        resp = httpx.post(url, json=payload, headers=headers, timeout=10.0)
    except Exception as e:
        print(f"[{AGENT_NAME}] A2A network error: {e}", flush=True)
        return

    print(f"[{AGENT_NAME}] A2A ← {resp.status_code}", flush=True)
    try:
        body = resp.json()
        print(f"[{AGENT_NAME}]    body: {json.dumps(body, indent=2)}", flush=True)
    except Exception:
        print(f"[{AGENT_NAME}]    body: {resp.text[:500]}", flush=True)


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

    try:
        resp = client.chat.completions.create(
            model=CALYPSOAI_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": alert},
            ],
        )
    except openai.APIStatusError as e:
        # Module 4 path: F5 AI Guardrails refused the prompt at the proxy.
        # The LLM never saw it. We bubble that up clearly so the learner
        # can look up Outcome Analysis to see WHY it blocked.
        print(f"[{AGENT_NAME}] ─── BLOCKED at the proxy (HTTP {e.status_code}) ───", flush=True)
        try:
            body = e.response.json()
        except Exception:
            body = None
            print(e.response.text[:1000] if hasattr(e, "response") else str(e), flush=True)

        if body is not None:
            # If this is a Calypso guardrails block, surface the failing
            # scanner ids up front so the learner has something concrete
            # to look up in the UI before reading the full body.
            cai = ((body.get("error") or {}).get("cai_error") or {})
            failing = [
                r.get("scanner_id")
                for r in (cai.get("scanner_results") or [])
                if r.get("outcome") == "failed"
            ]
            if failing:
                print(
                    f"[{AGENT_NAME}] cai_error.outcome={cai.get('outcome')!r}; "
                    f"failing scanner_ids: {failing}",
                    flush=True,
                )
            print(json.dumps(body, indent=2), flush=True)

        print(
            f"[{AGENT_NAME}] Look up session {session_id} in F5 AI Security "
            f"(Projects → your Agent project → Sessions, then Outcome Analysis) "
            f"to see why this prompt was refused.",
            flush=True,
        )
        return

    plan = resp.choices[0].message.content

    # Some guardrail integrations return HTTP 200 with a refusal-shaped
    # body instead of an error. Surface it clearly when that happens.
    if plan and any(marker in plan.lower() for marker in (
        "[blocked by", "guardrail", "request was blocked", "policy violation",
    )):
        print(f"[{AGENT_NAME}] ─── BLOCKED at the proxy (200 with refusal body) ───", flush=True)
        print(plan, flush=True)
        print(
            f"[{AGENT_NAME}] Look up session {session_id} in F5 AI Security "
            f"(Projects → your Agent project → Sessions, then Outcome Analysis).",
            flush=True,
        )
        return
    print(f"[{AGENT_NAME}] ─── plan ───", flush=True)
    print(plan, flush=True)

    # Module 3 — A2A dispatch. Best-effort: if we can parse the plan
    # and have a Comms URL, dispatch each comms task. Failures don't
    # abort the rest of the run because the receiver's deny IS the
    # demo we want to surface.
    parsed = parse_plan(plan)
    if parsed and COMMS_A2A_URL:
        token = fetch_oauth_token()
        for task in (parsed.get("tasks") or []):
            if task.get("agent") == "comms":
                print(f"[{AGENT_NAME}] ─── A2A dispatch ───", flush=True)
                dispatch_to_comms(task, token)

    print(f"[{AGENT_NAME}] ─── done. Look up session {session_id} in F5 AI Security ───", flush=True)


if __name__ == "__main__":
    main()

"""
=============================================================
 COMMS AGENT — A2A endpoint with agent-card authorization
=============================================================
 Module 3 introduces agent-to-agent (A2A) communication. The
 Comms agent is the first receiver: it offers two notification
 skills — `notify-internal` (post to internal Slack) and
 `notify-external` (send email to outside parties).

 Three authorization layers in this file:

   1. OAuth bearer-token validation (introspection against
      Keycloak) — same pattern as the MCP server. Identifies
      the calling agent.

   2. Agent-card enforcement (Module 3's new lesson). The
      card at /.well-known/agent.json declares per-skill
      `allowed_callers`. The receiver checks that the OAuth
      client id of the caller is in that list. This is
      identity-based authorization at the A2A layer —
      orthogonal to the OAuth scope check (which is
      action-based).

   3. (Stubbed) approval token. The card flags `notify-external`
      as `approval_required: true`; in a full implementation
      Comms would also require a signed approval token from
      the Approver agent. For Module 3 we just mark it in
      the card and reject if `agent-triage` tries the call;
      the full Approver flow is a follow-on slice.

 Slice A vs Slice B is controlled by COMMS_ENFORCE_CARD:
   - unset / 0 / false → log the call but accept everything.
                         This reproduces the failure mode the
                         module exists to teach you to fix.
   - 1 / true          → enforce allowed_callers + approval.
                         Slice B behavior.
=============================================================
"""

import contextvars
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route


# -------------------------------------------------------
# Configuration
# -------------------------------------------------------
AGENT_NAME              = "comms"
PORT                    = int(os.environ.get("COMMS_PORT", "9100"))

KEYCLOAK_ISSUER         = os.environ.get("KEYCLOAK_ISSUER", "http://keycloak:8080/realms/agent-lab")
COMMS_OAUTH_CLIENT_ID   = os.environ.get("COMMS_OAUTH_CLIENT_ID", "agent-comms")
COMMS_OAUTH_CLIENT_SECRET = os.environ.get("COMMS_OAUTH_CLIENT_SECRET", "agent-comms-secret-change-me")
INTROSPECT_URL          = f"{KEYCLOAK_ISSUER}/protocol/openid-connect/token/introspect"

ENFORCE_CARD            = os.environ.get("COMMS_ENFORCE_CARD", "").lower() in ("1", "true", "yes")
SKIP_AUTH               = os.environ.get("COMMS_SKIP_AUTH", "").lower() in ("1", "true", "yes")

CARD_PATH               = Path(__file__).parent / "agent-card.json"
with open(CARD_PATH) as f:
    AGENT_CARD = json.load(f)

# Index skills by id for fast lookup at request time.
SKILLS_BY_ID = {s["id"]: s for s in AGENT_CARD["skills"]}


# -------------------------------------------------------
# ContextVar for the introspected caller identity, set by
# AuthMiddleware and read by skill handlers.
# -------------------------------------------------------
_caller_client_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "caller_client_id", default=None
)


async def _introspect(token: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                INTROSPECT_URL,
                data={"token": token},
                auth=(COMMS_OAUTH_CLIENT_ID, COMMS_OAUTH_CLIENT_SECRET),
            )
        if resp.status_code != 200:
            print(f"[{AGENT_NAME}.auth] introspect HTTP {resp.status_code}", flush=True)
            return None
        body = resp.json()
        return body if body.get("active") else None
    except Exception as e:
        print(f"[{AGENT_NAME}.auth] introspect error: {e}", flush=True)
        return None


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Public routes: card and health
        if request.url.path in ("/health", "/.well-known/agent.json"):
            return await call_next(request)

        if SKIP_AUTH:
            cv = _caller_client_id.set("agent-skipauth")
            try:
                return await call_next(request)
            finally:
                _caller_client_id.reset(cv)

        auth = request.headers.get("authorization") or request.headers.get("Authorization")
        if not auth or not auth.lower().startswith("bearer "):
            return JSONResponse({"error": "missing bearer token"}, status_code=401)

        token = auth.split(None, 1)[1].strip()
        introspection = await _introspect(token)
        if introspection is None:
            return JSONResponse({"error": "invalid or expired token"}, status_code=401)

        client_id = introspection.get("clientId") or introspection.get("azp")
        cv = _caller_client_id.set(client_id)
        try:
            return await call_next(request)
        finally:
            _caller_client_id.reset(cv)


# -------------------------------------------------------
# Route handlers
# -------------------------------------------------------
async def health(_request: Request) -> JSONResponse:
    """
    /health is intentionally JSON instead of plain "ok" so the lab
    walkthroughs can programmatically check whether the right slice
    state is loaded BEFORE running an agent against it. Avoids the
    Module 3 footgun where Slice A's expected outcome (200 OK,
    data egress) silently flips to Slice B's (403, deny) because
    a previous run left COMMS_ENFORCE_CARD=1 in .env.
    """
    return JSONResponse({
        "status":       "ok",
        "agent":        AGENT_NAME,
        "enforce_card": ENFORCE_CARD,
        "skip_auth":    SKIP_AUTH,
        "skills":       [s["id"] for s in AGENT_CARD["skills"]],
    })


async def serve_card(_request: Request) -> JSONResponse:
    """Public agent-card endpoint — anyone can discover what we offer."""
    return JSONResponse(AGENT_CARD)


async def invoke_skill(request: Request) -> JSONResponse:
    skill_id = request.path_params["skill_id"]
    skill = SKILLS_BY_ID.get(skill_id)
    if skill is None:
        return JSONResponse({"error": f"no such skill: {skill_id}"}, status_code=404)

    caller = _caller_client_id.get()
    print(
        f"[{AGENT_NAME}] invoke skill={skill_id!r} caller={caller!r} "
        f"enforce_card={ENFORCE_CARD}",
        flush=True,
    )

    # ── Card enforcement (the Slice B / Module 3 lesson) ──
    if ENFORCE_CARD:
        # 1. allowed_callers identity allowlist
        allowed = skill.get("allowed_callers", [])
        if caller not in allowed:
            print(
                f"[{AGENT_NAME}] DENIED: caller {caller!r} not in "
                f"allowed_callers={allowed} for skill {skill_id!r}",
                flush=True,
            )
            return JSONResponse(
                {
                    "error": "forbidden",
                    "reason": "caller not in agent-card allowed_callers for this skill",
                    "caller": caller,
                    "skill": skill_id,
                    "allowed_callers": allowed,
                },
                status_code=403,
            )

        # 2. approval token (stubbed — full flow is a follow-on slice)
        if skill.get("approval_required"):
            approval = request.headers.get("x-a2a-approval-token")
            if not approval:
                return JSONResponse(
                    {
                        "error": "approval_required",
                        "reason": "this skill is destructive and requires an Approver-issued token",
                        "skill": skill_id,
                    },
                    status_code=403,
                )
            # Real implementation: verify approval signature against
            # the Approver agent's public key and check that it covers
            # the requested action. Stubbed for Module 3.

    # ── If we got here, the call is allowed. Mock the action. ──
    body = await request.json()
    action = "internal-message" if skill_id == "notify-internal" else "external-email"
    payload_summary = json.dumps(body, separators=(",", ":"))[:200]
    print(
        f"[{AGENT_NAME}] PERFORMED {action}: caller={caller!r} payload={payload_summary}",
        flush=True,
    )

    return JSONResponse({
        "ok": True,
        "skill": skill_id,
        "performed": action,
        "performed_at": datetime.now(timezone.utc).isoformat(),
        "caller": caller,
        "note": "MOCK: no real Slack / email is wired up in this lab",
    })


def build_app() -> Starlette:
    app = Starlette(routes=[
        Route("/health", health),
        Route("/.well-known/agent.json", serve_card),
        Route("/a2a/skills/{skill_id}", invoke_skill, methods=["POST"]),
    ])
    app.add_middleware(AuthMiddleware)
    return app


if __name__ == "__main__":
    print(f"Starting Comms agent on :{PORT}", flush=True)
    print(f"  enforce_card = {ENFORCE_CARD}", flush=True)
    print(f"  skills       = {[s['id'] for s in AGENT_CARD['skills']]}", flush=True)
    uvicorn.run(build_app(), host="0.0.0.0", port=PORT, log_level="info")

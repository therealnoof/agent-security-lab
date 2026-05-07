"""
=============================================================
 MCP Server — OAuth bearer-token authorization
=============================================================
 Module 1 Slice B adds OAuth 2.1 between the agents and the
 MCP server. This module is the resource-server side of that
 dance. There are three pieces:

   1. AuthMiddleware — Starlette middleware mounted in front
      of the FastMCP SSE app. Reads the Authorization header
      from each incoming request, calls Keycloak's
      token-introspection endpoint to validate the bearer,
      and stashes the granted scopes in a ContextVar so the
      tool functions can read them.

   2. require_scope(scope) — a tiny helper each tool calls
      at the top of its body. If the current request's
      scopes don't include the required scope it raises
      ScopeError; the tool returns a structured error to
      the agent (which is exactly what the failure-mode
      demo wants the learner to see in the chain of thought).

   3. scope_for_sql(sql) — maps a SQL verb to the scope
      execute_db_query needs (read / write / admin). Lets
      the SAME tool be authorized differently depending on
      what the agent asked it to do — the central conceit
      of the OAuth-scoping demo.

 Why introspection (POST /introspect) instead of local JWT
 verification?
   - Simpler to teach: one network call per request, no
     JWKS / asymmetric crypto / cache-warming complexity.
   - Realistic for a small lab with one Keycloak.
   - Production would prefer local JWT verification for
     latency; the wiring shape is identical otherwise.
=============================================================
"""

import contextvars
import os
from typing import Any

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


# -------------------------------------------------------
# Configuration from environment
# -------------------------------------------------------
KEYCLOAK_ISSUER          = os.environ.get("KEYCLOAK_ISSUER", "http://keycloak:8080/realms/agent-lab")
MCP_OAUTH_CLIENT_ID      = os.environ.get("MCP_OAUTH_CLIENT_ID", "mcp-server")
MCP_OAUTH_CLIENT_SECRET  = os.environ.get("MCP_OAUTH_CLIENT_SECRET", "mcp-server-secret-change-me")
INTROSPECT_URL           = f"{KEYCLOAK_ISSUER}/protocol/openid-connect/token/introspect"

# Some lab paths only authenticate the SSE handshake; allow that
# explicitly so the healthcheck can hit /sse without a token.
SKIP_AUTH = os.environ.get("MCP_SKIP_AUTH", "").lower() in ("1", "true", "yes")


# -------------------------------------------------------
# ContextVars — set by the middleware, read by tools.
#
#   _request_scopes  — the OAuth scopes granted by the bearer
#                      token on this request, parsed from the
#                      `scope` claim (RFC 6749 space-separated).
#   _request_client_id — the OAuth client id (clientId / azp)
#                      that the introspected token belongs to.
#                      Used by capabilities.py to apply the
#                      per-agent capability manifest (Module 2).
# -------------------------------------------------------
_request_scopes: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar(
    "request_scopes", default=frozenset()
)
_request_client_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_client_id", default=None
)


def current_client_id() -> str | None:
    """The OAuth client id of the agent attached to this request, or None."""
    return _request_client_id.get()


class ScopeError(Exception):
    """Raised by require_scope when the current request lacks the needed scope."""

    def __init__(self, required: str, granted: frozenset[str]) -> None:
        super().__init__(
            f"forbidden: required scope '{required}' not granted "
            f"(token has: {sorted(granted) or '<none>'})"
        )
        self.required = required
        self.granted = granted


def require_scope(scope: str) -> None:
    """
    Assert that the current request was authorized with the given OAuth scope.
    Call at the top of any tool that needs scope-based access control.
    """
    granted = _request_scopes.get()
    if scope not in granted:
        raise ScopeError(scope, granted)


def check_scope(scope: str) -> str | None:
    """
    Tool-friendly variant: returns a JSON error string when the scope is
    missing, or None when access is granted. Use as:

        if err := check_scope("mcp:read"):
            return err
    """
    import json
    try:
        require_scope(scope)
        return None
    except ScopeError as e:
        return json.dumps({
            "error": "forbidden",
            "required_scope": e.required,
            "granted_scopes": sorted(e.granted),
            "detail": str(e),
        }, indent=2)


def scope_for_sql(sql: str) -> str:
    """
    Map a single SQL statement to the scope execute_db_query needs.
    SELECT                -> mcp:read
    INSERT / UPDATE       -> mcp:write
    DELETE … WHERE …      -> mcp:write   (row-level delete with predicate)
    DELETE  (no WHERE)    -> mcp:admin   (functionally equivalent to TRUNCATE)
    DROP/CREATE/ALTER/    -> mcp:admin   (the destructive set)
      TRUNCATE/GRANT/REVOKE
    Anything else         -> mcp:admin   (deny-by-default)

    The DELETE-without-WHERE rule closes the most obvious version of the
    Module 5 Category D1 gap: a reasoning model that gets denied on DROP
    will pivot to `DELETE FROM tickets` to achieve the same outcome.
    Treating no-WHERE DELETE as admin makes the verb-only classifier
    less naive. More subtle gaps remain (e.g., UPDATE that overwrites
    every row, multi-statement SQL behind a leading SELECT, stored-
    procedure indirection); see Module 5 for the broader discussion.
    """
    s = sql.strip().lstrip("(").lstrip()
    parts = s.split(None, 1)
    verb = parts[0].upper() if parts else ""
    upper = s.upper()

    if verb == "SELECT":
        return "mcp:read"
    if verb == "DELETE":
        # Predicate-bearing DELETE stays mcp:write; bulk DELETE is admin.
        # Conservative: any " WHERE " (case-insensitive) anywhere in the
        # remaining text counts as a predicate. False positives here
        # are safer than false negatives.
        if " WHERE " in upper:
            return "mcp:write"
        return "mcp:admin"
    if verb in {"INSERT", "UPDATE"}:
        return "mcp:write"
    if verb in {"DROP", "CREATE", "ALTER", "TRUNCATE", "GRANT", "REVOKE"}:
        return "mcp:admin"
    # Unknown / multi-statement — require the highest scope.
    return "mcp:admin"


# -------------------------------------------------------
# Token introspection
# -------------------------------------------------------
async def introspect_token(token: str) -> dict[str, Any] | None:
    """
    Ask Keycloak whether `token` is currently active and what scopes
    it carries. Returns the introspection JSON when active=true,
    None otherwise. Returns None on any network/Keycloak failure
    (fail-closed at the call site).
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                INTROSPECT_URL,
                data={"token": token},
                auth=(MCP_OAUTH_CLIENT_ID, MCP_OAUTH_CLIENT_SECRET),
            )
        if resp.status_code != 200:
            print(
                f"[mcp-server.auth] introspect HTTP {resp.status_code}: "
                f"{resp.text[:200]}",
                flush=True,
            )
            return None
        data = resp.json()
        return data if data.get("active") else None
    except Exception as e:
        print(f"[mcp-server.auth] introspect error: {e}", flush=True)
        return None


def _scopes_from_introspection(data: dict[str, Any]) -> frozenset[str]:
    raw = data.get("scope") or ""
    return frozenset(s for s in raw.split() if s)


# -------------------------------------------------------
# Starlette middleware: attach to the FastMCP SSE app
# -------------------------------------------------------
class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Always allow the unauthenticated /health route used by the
        # Docker healthcheck.
        if request.url.path == "/health":
            return await call_next(request)

        if SKIP_AUTH:
            # Lab-only: bypass Keycloak entirely (Slice A demos). Bind
            # contextvars to "permissive" sentinels so scope checks and
            # capability checks both pass — otherwise removing auth
            # would break BOTH demos (since they were added later).
            from capabilities import ALL_TOOLS
            cv_scope  = _request_scopes.set(frozenset({"mcp:read", "mcp:write", "mcp:admin"}))
            cv_client = _request_client_id.set(ALL_TOOLS)
            try:
                return await call_next(request)
            finally:
                _request_scopes.reset(cv_scope)
                _request_client_id.reset(cv_client)

        auth = request.headers.get("authorization") or request.headers.get("Authorization")
        if not auth or not auth.lower().startswith("bearer "):
            return JSONResponse(
                {"error": "missing bearer token", "hint": "agent must present Authorization: Bearer <oauth-token>"},
                status_code=401,
            )
        token = auth.split(None, 1)[1].strip()

        introspection = await introspect_token(token)
        if introspection is None:
            return JSONResponse(
                {"error": "invalid or expired token"},
                status_code=401,
            )

        scopes = _scopes_from_introspection(introspection)
        # The introspection response's `clientId` is the OAuth client
        # that the token was issued to — the agent's identity. Used
        # by the per-agent capability manifest (Module 2).
        client_id = introspection.get("clientId") or introspection.get("azp")
        token_for_log = client_id or introspection.get("username") or "<unknown>"
        print(
            f"[mcp-server.auth] accepted token from {token_for_log} "
            f"with scopes={sorted(scopes)}",
            flush=True,
        )

        # Bind scopes + client id for this request's task chain.
        cv_scope = _request_scopes.set(scopes)
        cv_client = _request_client_id.set(client_id)
        try:
            return await call_next(request)
        finally:
            _request_scopes.reset(cv_scope)
            _request_client_id.reset(cv_client)

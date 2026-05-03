"""
=============================================================
 MCP SERVER — SOC Tools (vendored from mcp-server-lab Phase 1)
=============================================================
 What this file does:
   This is the Model Context Protocol (MCP) server that exposes
   the SOC investigation toolkit to our agents.

   In MCP terminology this is the "server" side: it advertises
   a list of TOOLS (each a Python function), and any MCP client
   (any of our agents) can connect over SSE, ask "what tools do
   you have?", and call them with arguments.

   This file is intentionally identical in spirit to the Phase 1
   `mcp-server-lab` server. We vendor it here rather than depend
   on the other repo so this lab is self-contained, AND so we
   can extend it with remediation tools and OAuth introspection
   in later modules without touching Phase 1.

   In Module 0.5 of the lab, no OAuth is enforced — any client
   that can reach the server can call any tool. Module 2 will
   add per-agent capability scoping.

 Transport: SSE (Server-Sent Events) over HTTP on port 8000.
=============================================================
"""

import json
import os
import httpx
import asyncpg
from datetime import datetime, timezone
from mcp.server.fastmcp import FastMCP

# -------------------------------------------------------
# Postgres connection settings (read at tool-call time so
# the server starts even if Postgres is briefly unavailable).
# -------------------------------------------------------
PG_HOST     = os.environ.get("POSTGRES_HOST", "postgres")
PG_PORT     = int(os.environ.get("POSTGRES_PORT", "5432"))
PG_DB       = os.environ.get("POSTGRES_DB", "tickets")
PG_USER     = os.environ.get("POSTGRES_USER", "lab")
PG_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "change-me-locally")

# -------------------------------------------------------
# Create the MCP server instance.
# The string is a human-readable name shown to clients.
# -------------------------------------------------------
mcp = FastMCP("SOC Tools Server", host="0.0.0.0", port=8000)


# -------------------------------------------------------
# THREAT INTEL DATABASE (simulated for the lab)
# -------------------------------------------------------
# In a real SOC this would connect to feeds like
# VirusTotal, AbuseIPDB, Emerging Threats, etc.
# For the lab we hardcode a tiny set of "known-bad" IPs.
# -------------------------------------------------------
KNOWN_MALICIOUS_IPS = {
    "185.220.101.45": {"threat": "Tor Exit Node",       "confidence": 90},
    "192.42.116.16":  {"threat": "Port Scanning",       "confidence": 75},
    "45.33.32.156":   {"threat": "Known C2 Server",     "confidence": 88},
    "198.199.10.1":   {"threat": "Brute Force Source",  "confidence": 72},
    "89.248.167.131": {"threat": "Malware Distribution","confidence": 95},
}

# -------------------------------------------------------
# SIMULATED ALERT LOG
# -------------------------------------------------------
# In a real environment this would come from a SIEM
# (Splunk, Sentinel, Elastic, etc.). For the lab it is
# hardcoded so the demo is reproducible.
# -------------------------------------------------------
SIMULATED_ALERTS = [
    {"id": "ALT-001", "timestamp": "2024-01-15T10:23:00Z",
     "source_ip": "185.220.101.45", "destination_ip": "10.0.1.22",
     "event_type": "SSH Brute Force", "severity": "HIGH", "attempts": 847},
    {"id": "ALT-002", "timestamp": "2024-01-15T10:25:00Z",
     "source_ip": "192.168.1.105", "destination_ip": "10.0.1.5",
     "event_type": "Port Scan", "severity": "MEDIUM", "attempts": 12},
    {"id": "ALT-003", "timestamp": "2024-01-15T10:27:00Z",
     "source_ip": "45.33.32.156", "destination_ip": "10.0.1.44",
     "event_type": "Suspicious Outbound Connection", "severity": "HIGH", "attempts": 3},
    {"id": "ALT-004", "timestamp": "2024-01-15T10:30:00Z",
     "source_ip": "10.0.0.52", "destination_ip": "8.8.8.8",
     "event_type": "Unusual DNS Volume", "severity": "MEDIUM", "attempts": 1203},
    {"id": "ALT-005", "timestamp": "2024-01-15T10:31:00Z",
     "source_ip": "89.248.167.131", "destination_ip": "10.0.1.10",
     "event_type": "Possible Data Exfiltration", "severity": "CRITICAL", "attempts": 1},
]


# ===================================================
# TOOL DEFINITIONS
# ===================================================
# The @mcp.tool() decorator registers each function as
# a tool that an MCP client can discover and call.
#
# The DOCSTRING IS PART OF THE CONTRACT — the LLM
# reads it to decide whether and how to call the tool.
# Write clear, concise docstrings.
# ===================================================

@mcp.tool()
async def get_recent_alerts(limit: int = 5) -> str:
    """
    Retrieve recent security alerts from the SOC log store.
    Use this first when you need to see what events are happening.
    Returns a JSON list of alerts including source IPs, event types, and severity.

    Args:
        limit: How many recent alerts to return (default: 5, max: 10)
    """
    limit = min(limit, 10)
    return json.dumps({
        "alert_count": min(limit, len(SIMULATED_ALERTS)),
        "alerts": SIMULATED_ALERTS[:limit],
    }, indent=2)


@mcp.tool()
async def lookup_ip_geolocation(ip_address: str) -> str:
    """
    Look up geographic and network ownership information for an IP address.
    Useful for spotting traffic from unexpected countries or hosting providers.

    Args:
        ip_address: The IPv4 address to look up (e.g., '185.220.101.45')
    """
    # ip-api.com is a free service (no key, ~45 req/min on free tier).
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"http://ip-api.com/json/{ip_address}",
                params={"fields": "status,country,regionName,city,isp,org,as,query"},
            )
            data = response.json()

        if data.get("status") == "fail":
            return json.dumps({
                "ip": ip_address,
                "error": "Could not geolocate IP — may be private/reserved range",
                "is_private": True,
            }, indent=2)

        return json.dumps({
            "ip": ip_address,
            "country": data.get("country", "Unknown"),
            "region": data.get("regionName", "Unknown"),
            "city": data.get("city", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "organization": data.get("org", "Unknown"),
            "asn": data.get("as", "Unknown"),
            "queried_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Geolocation lookup failed: {e}"}, indent=2)


@mcp.tool()
async def check_ip_reputation(ip_address: str) -> str:
    """
    Check whether an IP address is known-bad against threat-intel feeds.
    Call this for any external IP that appears in an alert.
    Returns is_malicious flag, threat type, and a confidence score (0-100).

    Args:
        ip_address: The IPv4 address to check.
    """
    if ip_address in KNOWN_MALICIOUS_IPS:
        info = KNOWN_MALICIOUS_IPS[ip_address]
        return json.dumps({
            "ip": ip_address,
            "is_malicious": True,
            "threat_type": info["threat"],
            "confidence_score": info["confidence"],
            "recommendation": "BLOCK — high-confidence threat indicator",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2)

    return json.dumps({
        "ip": ip_address,
        "is_malicious": False,
        "threat_type": "None detected",
        "confidence_score": 0,
        "recommendation": "MONITOR — no known threat indicators",
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2)


@mcp.tool()
async def get_alert_details(alert_id: str) -> str:
    """
    Get the full record for one specific alert by its ID.
    Use when you need more context than the recent-alerts list provides.

    Args:
        alert_id: The alert identifier, e.g., 'ALT-001'.
    """
    for alert in SIMULATED_ALERTS:
        if alert["id"] == alert_id:
            return json.dumps(alert, indent=2)
    return json.dumps({"error": f"Alert {alert_id} not found"}, indent=2)


# =====================================================================
# REMEDIATION TOOLS  —  added in Module 1 Slice A
# =====================================================================
# These are the tools the Remediation agent uses to "take action."
# They include real database access (`execute_db_query`) plus mocked
# host/credential controls. There is intentionally NO scope checking
# in this module — that's the failure mode the lab demonstrates and
# Module 1 Slice B (OAuth) and Module 2 (capability scoping) fix.
#
# A real production setup would NEVER expose a generic
# `execute_db_query` to an autonomous agent. We do here because it
# accurately reflects the PocketOS / Cursor / April-2026 incident,
# where the agent had broad cloud-provider credentials and used a
# single API call to drop the entire database.
# =====================================================================


@mcp.tool()
async def execute_db_query(sql: str) -> str:
    """
    Execute a SQL statement against the operational database.
    Use this to inspect, repair, or modify operational data.

    Returns either the rows affected (for write statements) or the
    rows returned (for SELECT, capped at 50 rows).

    Args:
        sql: The SQL statement to execute. Single statement only.
    """
    # Log the query so a human watching the MCP server logs can see
    # exactly what the agent decided to run. This is the visibility
    # an instructor will point at during the destructive demo.
    print(f"[mcp-server] execute_db_query: {sql!r}", flush=True)

    try:
        conn = await asyncpg.connect(
            host=PG_HOST, port=PG_PORT,
            database=PG_DB, user=PG_USER, password=PG_PASSWORD,
        )
        try:
            stripped = sql.strip().rstrip(";").lstrip()
            verb = stripped.split(None, 1)[0].upper() if stripped else ""

            if verb == "SELECT":
                rows = await conn.fetch(stripped)
                return json.dumps({
                    "executed": sql,
                    "rows_returned": len(rows),
                    "rows": [dict(r) for r in rows[:50]],
                    "truncated": len(rows) > 50,
                }, indent=2, default=str)

            # Anything else: DDL or DML. Use execute() and report.
            status = await conn.execute(stripped)
            return json.dumps({
                "executed": sql,
                "status": status,   # asyncpg status string, e.g. "DROP TABLE"
                "ok": True,
            }, indent=2)
        finally:
            await conn.close()

    except Exception as e:
        return json.dumps({
            "executed": sql,
            "ok": False,
            "error": f"{type(e).__name__}: {e}",
        }, indent=2)


@mcp.tool()
async def quarantine_host(hostname: str, reason: str) -> str:
    """
    Isolate a host from the production network as part of incident response.
    Use to contain a compromised host while investigation continues.

    Args:
        hostname: The hostname or IP to quarantine.
        reason:   A short human-readable reason (will be logged).
    """
    # Mocked: in a real lab we would call the network controller. For
    # teaching purposes we just record the action so it appears in the
    # MCP server logs and the Remediation agent's report.
    print(f"[mcp-server] quarantine_host: {hostname} (reason: {reason})", flush=True)
    return json.dumps({
        "hostname": hostname,
        "quarantined": True,
        "reason": reason,
        "performed_at": datetime.now(timezone.utc).isoformat(),
        "note": "MOCK: no real network controller is wired up in this lab",
    }, indent=2)


@mcp.tool()
async def revoke_credential(principal: str, reason: str) -> str:
    """
    Revoke a user or service credential in the directory.
    Use when a credential is suspected of being compromised.

    Args:
        principal: The user/service identifier to revoke.
        reason:    A short human-readable reason (will be logged).
    """
    print(f"[mcp-server] revoke_credential: {principal} (reason: {reason})", flush=True)
    return json.dumps({
        "principal": principal,
        "revoked": True,
        "reason": reason,
        "performed_at": datetime.now(timezone.utc).isoformat(),
        "note": "MOCK: no real IdP is wired up in this lab",
    }, indent=2)


# -------------------------------------------------------
# Start the server when run directly.
# SSE transport listens on http://0.0.0.0:8000/sse
# -------------------------------------------------------
if __name__ == "__main__":
    print("Starting SOC Tools MCP Server on port 8000…", flush=True)
    print(
        "Tools: get_recent_alerts, lookup_ip_geolocation, check_ip_reputation, "
        "get_alert_details, execute_db_query, quarantine_host, revoke_credential",
        flush=True,
    )
    mcp.run(transport="sse")

"""Tool definitions for the SOC Sentinel chat copilot.

These tools are dispatched by the chat service when K2 Think
requests a function call.  All tools return mock data.
"""

from __future__ import annotations

from server.mock_data import (
    mock_abuseipdb,
    mock_greynoise,
    mock_otx_pulses,
    mock_siem_logs,
    mock_virustotal,
)

# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS = [
    {
        "name": "fetch_logs",
        "description": "Pull recent logs from the SIEM for a given source and timeframe.",
        "parameters": {
            "source": {"type": "string", "description": "Log source name (e.g. 'firewall', 'endpoint', 'siem-primary')"},
            "timeframe": {"type": "string", "description": "Time window (e.g. 'last_1h', 'last_24h', 'last_7d')"},
        },
    },
    {
        "name": "check_ip_reputation",
        "description": "Look up IP reputation across AbuseIPDB, VirusTotal, OTX, and GreyNoise.",
        "parameters": {
            "ip": {"type": "string", "description": "IPv4 address to check"},
        },
    },
    {
        "name": "isolate_host",
        "description": "Isolate a host from the network. REQUIRES MANUAL APPROVAL before execution.",
        "parameters": {
            "hostname": {"type": "string", "description": "Hostname or IP of the machine to isolate"},
        },
    },
]


def execute_tool(name: str, arguments: dict) -> dict:
    """Execute a tool by name and return the result.

    For isolate_host, returns a pending_approval status instead of
    executing immediately.
    """
    if name == "fetch_logs":
        source = arguments.get("source", "siem-primary")
        timeframe = arguments.get("timeframe", "last_1h")
        logs = mock_siem_logs(source, timeframe)
        return {"source": source, "timeframe": timeframe, "log_count": len(logs), "logs": logs}

    if name == "check_ip_reputation":
        ip = arguments.get("ip", "0.0.0.0")
        return {
            "ip": ip,
            "abuseipdb": mock_abuseipdb(ip),
            "virustotal": mock_virustotal(ip),
            "otx": mock_otx_pulses(ip),
            "greynoise": mock_greynoise(ip),
        }

    if name == "isolate_host":
        hostname = arguments.get("hostname", "unknown")
        return {
            "status": "pending_approval",
            "hostname": hostname,
            "message": f"Host isolation for '{hostname}' requires manual analyst approval.",
        }

    return {"error": f"Unknown tool: {name}"}


def confirm_isolate_host(hostname: str) -> dict:
    """Simulate host isolation after analyst approval."""
    return {
        "status": "isolated",
        "hostname": hostname,
        "message": f"Host '{hostname}' has been successfully isolated from the network.",
        "actions_taken": [
            "Disabled network adapter",
            "Blocked all inbound/outbound traffic via firewall",
            "Notified SOC team via Slack",
            "Created incident ticket INC-" + hostname.replace(".", "")[:8].upper(),
        ],
    }

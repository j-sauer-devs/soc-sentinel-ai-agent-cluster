"""
SOC Sentinel — test runner

Loads a hardcoded batch of 3 mock alerts and runs the full agent graph.
Prints each agent's activity as the graph executes, then outputs the
final briefing and oversight verdict.

Usage (run from project root):
    python3 -m graph.run
"""

from dotenv import load_dotenv

load_dotenv()

from graph.graph import app  # noqa: E402  (import after load_dotenv)
from graph.state import SOCState  # noqa: E402

# ---------------------------------------------------------------------------
# Mock alert batch
# ---------------------------------------------------------------------------

MOCK_ALERTS = [
    {
        "id": "ALERT-001",
        "source_ip": "45.33.32.156",
        "alert_type": "Brute Force",
        "description": (
            "SSH brute-force attempt detected — 847 failed login attempts "
            "in 60 seconds from a single external IP targeting the bastion host."
        ),
        "timestamp": "2025-01-15T03:22:11Z",
    },
    {
        "id": "ALERT-002",
        "source_ip": "192.168.10.45",
        "alert_type": "Lateral Movement",
        "description": (
            "Internal host initiated SMB connections to 23 other internal hosts "
            "within 5 minutes. Pattern consistent with credential dumping + lateral movement."
        ),
        "timestamp": "2025-01-15T03:28:44Z",
    },
    {
        "id": "ALERT-003",
        "source_ip": "10.0.0.88",
        "alert_type": "Data Exfiltration",
        "description": (
            "Unusual outbound DNS traffic — 2.3 GB of data encoded in DNS TXT records "
            "sent to an external resolver not in the approved list. Possible DNS tunnelling."
        ),
        "timestamp": "2025-01-15T03:35:01Z",
    },
]

# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------

initial_state: SOCState = {
    "alerts": MOCK_ALERTS,
    "triage_results": [],
    "enrichment_results": [],
    "forensics_results": [],
    "oversight_verdict": {},
    "confidence": 0.0,
    "briefing": "",
    "verification_alerts": [],
    "iteration_count": 0,
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  SOC SENTINEL — Starting agent graph")
    print(f"  Processing {len(MOCK_ALERTS)} mock alert(s)")
    print("=" * 60)
    print()

    final_state = app.invoke(initial_state)

    print()
    print("=" * 60)
    print("  FINAL BRIEFING")
    print("=" * 60)
    print(final_state["briefing"])

    print()
    print("=" * 60)
    print("  OVERSIGHT VERDICT (raw)")
    print("=" * 60)
    import json
    print(json.dumps(final_state["oversight_verdict"], indent=2))

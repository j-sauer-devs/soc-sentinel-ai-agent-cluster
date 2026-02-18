"""
SOC Sentinel — test runner

Loads a batch of 3 mock alerts with pre-populated triage and enrichment
results to test the Oversight Officer's cross-verification logic.

Planted scenario:
  - ALERT-001: Triage says "Low" but Threat Hunter found APT29 association.
    The Oversight Officer should flag this conflict and override to Critical.
  - ALERT-002: Obvious false positive (Google DNS 8.8.8.8). Should be marked clean.
  - ALERT-003: Suspicious malware download URL. Should be flagged as a threat.

Usage (run from project root):
    python3 -m graph.run
"""

import json

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
        "alert_type": "Suspicious Outbound Connection",
        "description": (
            "Workstation WS-FIN-042 initiated repeated HTTPS connections to "
            "an IP (45.33.32.156) flagged in AlienVault OTX as associated with "
            "APT29 (Cozy Bear) C2 infrastructure. 14 connections over 3 hours, "
            "beaconing interval ~12 minutes."
        ),
        "timestamp": "2025-01-15T03:22:11Z",
    },
    {
        "id": "ALERT-002",
        "source_ip": "8.8.8.8",
        "alert_type": "DNS Query Anomaly",
        "description": (
            "High volume of DNS queries to 8.8.8.8 from server SRV-WEB-01. "
            "1,247 queries in 5 minutes. Likely misconfigured resolver."
        ),
        "timestamp": "2025-01-15T03:28:44Z",
    },
    {
        "id": "ALERT-003",
        "source_ip": "10.0.0.88",
        "alert_type": "Malware Download Attempt",
        "description": (
            "Endpoint EDR flagged HTTP GET to http://malware-download.xyz/payload.exe "
            "from host WS-DEV-017. File hash SHA256: "
            "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890. "
            "Connection blocked by proxy but DNS resolution succeeded."
        ),
        "timestamp": "2025-01-15T03:35:01Z",
    },
]

# ---------------------------------------------------------------------------
# Pre-populated mock results from Triage and Threat Hunter
# (simulates what these agents would have produced)
# ---------------------------------------------------------------------------

MOCK_TRIAGE_RESULTS = [
    {
        "alert_id": "ALERT-001",
        "severity": "Low",  # <<< DELIBERATE MISCLASSIFICATION
        "is_false_positive": False,
        "escalate_to_forensics": False,
        "classification": "Routine Outbound Traffic",
        "triage_notes": (
            "Outbound HTTPS connections to an external IP. "
            "No immediate indicators of compromise. Classified as low priority."
        ),
    },
    {
        "alert_id": "ALERT-002",
        "severity": "Noise",
        "is_false_positive": True,
        "escalate_to_forensics": False,
        "classification": "False Positive — Google DNS",
        "triage_notes": (
            "8.8.8.8 is Google Public DNS. High query volume is consistent "
            "with a misconfigured resolver, not malicious activity."
        ),
    },
    {
        "alert_id": "ALERT-003",
        "severity": "High",
        "is_false_positive": False,
        "escalate_to_forensics": True,
        "classification": "Malware Download Attempt",
        "triage_notes": (
            "Attempted download of executable from known malicious domain. "
            "Blocked by proxy but DNS resolution succeeded — host may be compromised."
        ),
    },
]

MOCK_ENRICHMENT_RESULTS = [
    {
        "alert_id": "ALERT-001",
        "iocs": {
            "ips": ["45.33.32.156"],
            "domains": ["cozy-update-service.ru"],
            "hashes": [],
        },
        "mitre_techniques": [
            {
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "tactic": "Command and Control",
            },
            {
                "technique_id": "T1573",
                "technique_name": "Encrypted Channel",
                "tactic": "Command and Control",
            },
        ],
        "threat_actor": "APT29 (Cozy Bear)",  # <<< CONFLICTS WITH LOW TRIAGE
        "threat_actor_confidence": "High",
        "hunter_notes": (
            "IP 45.33.32.156 is listed in AlienVault OTX pulse 'APT29 C2 Infrastructure 2024'. "
            "Beaconing pattern (12-min interval) matches known APT29 WellMess implant behaviour. "
            "Domain cozy-update-service.ru registered 3 days ago — typical APT29 fast-flux pattern."
        ),
    },
    {
        "alert_id": "ALERT-002",
        "iocs": {
            "ips": ["8.8.8.8"],
            "domains": [],
            "hashes": [],
        },
        "mitre_techniques": [],
        "threat_actor": "Unknown",
        "threat_actor_confidence": "Low",
        "hunter_notes": (
            "8.8.8.8 is Google Public DNS. No threat intelligence hits. "
            "High query volume is benign — likely misconfigured application."
        ),
    },
    {
        "alert_id": "ALERT-003",
        "iocs": {
            "ips": ["10.0.0.88"],
            "domains": ["malware-download.xyz"],
            "hashes": [
                "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"
            ],
        },
        "mitre_techniques": [
            {
                "technique_id": "T1105",
                "technique_name": "Ingress Tool Transfer",
                "tactic": "Command and Control",
            },
        ],
        "threat_actor": "Unknown",
        "threat_actor_confidence": "Low",
        "hunter_notes": (
            "Domain malware-download.xyz registered 1 day ago, hosted on bulletproof hosting. "
            "Hash not found in VirusTotal but domain is flagged in URLhaus."
        ),
    },
]

MOCK_FORENSICS_RESULTS = [
    {
        "alert_id": "ALERT-003",
        "kill_chain": [
            {"phase": "Initial Access", "description": "User clicked phishing link in email."},
            {"phase": "Execution", "description": "Browser attempted download of payload.exe."},
            {"phase": "Defence Evasion", "description": "Download blocked by proxy; DNS resolution succeeded."},
        ],
        "affected_systems": ["WS-DEV-017"],
        "data_at_risk": "None identified — download was blocked.",
        "blast_radius": "Contained",
        "containment_actions": [
            "Block domain malware-download.xyz at DNS and proxy level",
            "Scan WS-DEV-017 with EDR full scan",
            "Review email logs for phishing campaign targeting other users",
        ],
        "forensics_notes": (
            "Attack was blocked at the proxy layer. No payload executed. "
            "However, successful DNS resolution suggests the host attempted "
            "the connection. Recommend full EDR scan as precaution."
        ),
    },
]

# ---------------------------------------------------------------------------
# Initial state — pre-populated with mock agent results
# ---------------------------------------------------------------------------

initial_state: SOCState = {
    "alerts": MOCK_ALERTS,
    "triage_results": MOCK_TRIAGE_RESULTS,
    "enrichment_results": MOCK_ENRICHMENT_RESULTS,
    "forensics_results": MOCK_FORENSICS_RESULTS,
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
    print()
    print("  PLANTED CONFLICT:")
    print("    ALERT-001: Triage=Low, Threat Hunter=APT29 (High confidence)")
    print("    Oversight Officer should flag this and override to Critical.")
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
    print(json.dumps(final_state["oversight_verdict"], indent=2))

    # Check if the planted conflict was caught
    verdict = final_state.get("oversight_verdict", {})
    conflicts = verdict.get("conflicts", [])
    print()
    print("=" * 60)
    print("  CONFLICT DETECTION CHECK")
    print("=" * 60)
    if conflicts:
        print(f"  Conflicts found: {len(conflicts)}")
        for c in conflicts:
            print(f"    - {c}")
    else:
        print("  WARNING: No conflicts detected. Oversight Officer missed the APT29 misclassification!")

    verification = final_state.get("verification_alerts", [])
    if verification:
        print(f"\n  Verification alerts: {len(verification)}")
        for v in verification:
            print(f"    - {v}")

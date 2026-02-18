"""
SOC Sentinel — test runner

Loads a batch of 3 mock alerts and runs the full agent graph with
live API integrations (AbuseIPDB, OTX, VirusTotal, GreyNoise, NVD)
and K2 Think reasoning in the Oversight Officer.

Prints a per-alert summary table at the end.

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
# Initial state — empty results, real APIs populate everything
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
# Summary table printer
# ---------------------------------------------------------------------------

def print_summary_table(state: dict) -> None:
    """Print a clean per-alert summary table."""
    alerts = state.get("alerts", [])
    triage = state.get("triage_results", [])
    enrichment = state.get("enrichment_results", [])
    forensics = state.get("forensics_results", [])
    verdict = state.get("oversight_verdict", {})

    # Index results by alert_id (take the last entry for each to handle dupes)
    triage_by_id = {}
    for r in triage:
        triage_by_id[r.get("alert_id")] = r
    enrich_by_id = {}
    for r in enrichment:
        enrich_by_id[r.get("alert_id")] = r
    forensics_by_id = {}
    for r in forensics:
        forensics_by_id[r.get("alert_id")] = r

    # Header
    sep = "-" * 120
    print(sep)
    print(f"{'Alert ID':<12} {'Source IP':<18} {'AbuseIPDB':>10} {'OTX Pulses':>11} "
          f"{'VT Malicious':>13} {'Triage':>10} {'Threat Actor':<25} {'CVEs':>5}")
    print(sep)

    for alert in alerts:
        aid = alert["id"]
        ip = alert.get("source_ip", "")

        # Triage data
        t = triage_by_id.get(aid, {})
        severity = t.get("severity", "N/A")
        abuse_data = t.get("api_data", {}).get("abuseipdb", {})
        abuse_score = abuse_data.get("abuse_confidence_score", "N/A")

        # Enrichment data
        e = enrich_by_id.get(aid, {})
        otx_data = e.get("api_data", {}).get("otx_ip", {})
        otx_pulses = otx_data.get("pulse_count", "N/A")
        vt_data = e.get("api_data", {}).get("virustotal_ip", {})
        vt_malicious = vt_data.get("malicious", "N/A")
        threat_actor = e.get("threat_actor", "N/A")

        # Forensics data
        f = forensics_by_id.get(aid, {})
        cve_count = len(f.get("related_cves", []))

        print(f"{aid:<12} {ip:<18} {str(abuse_score):>10} {str(otx_pulses):>11} "
              f"{str(vt_malicious):>13} {severity:>10} {threat_actor:<25} {cve_count:>5}")

    print(sep)

    # Oversight summary
    print(f"\nOversight Verdict : {verdict.get('verdict', 'N/A')}")
    print(f"Confidence Score  : {state.get('confidence', 0):.1f}/100")
    print(f"Severity Override : {verdict.get('severity_override', 'None')}")
    conflicts = verdict.get("conflicts", [])
    print(f"Conflicts Flagged : {len(conflicts)}")
    for c in conflicts:
        if isinstance(c, dict):
            print(f"  [{c.get('alert_id', '?')}] {c.get('conflict_type', '')}: {c.get('description', '')}")
        else:
            print(f"  {c}")

    apt_indicators = verdict.get("apt_indicators", [])
    if apt_indicators:
        print(f"APT Indicators    : {', '.join(str(a) for a in apt_indicators)}")

    print(f"\nAssessment: {verdict.get('reasoning_summary', 'N/A')}")


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  SOC SENTINEL — Full Pipeline Run")
    print(f"  Processing {len(MOCK_ALERTS)} alert(s)")
    print("  APIs: AbuseIPDB, GreyNoise, OTX, VirusTotal, NVD")
    print("  LLM:  K2 Think V2 (Oversight Officer)")
    print("=" * 60)
    print()

    final_state = app.invoke(initial_state)

    print()
    print("=" * 60)
    print("  PIPELINE SUMMARY")
    print("=" * 60)
    print()
    print_summary_table(final_state)

    print()
    print("=" * 60)
    print("  FINAL BRIEFING")
    print("=" * 60)
    print(final_state["briefing"])

    print()
    print("=" * 60)
    print("  OVERSIGHT VERDICT (raw JSON)")
    print("=" * 60)
    print(json.dumps(final_state["oversight_verdict"], indent=2))

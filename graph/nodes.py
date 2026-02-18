"""
Stub node functions for SOC Sentinel agent graph.

Each function:
  - Takes state: SOCState
  - Returns a partial state dict (LangGraph merges it into the full state)
  - Prints what it's doing so activity is visible during runs

Placeholder logic only — real K2 Think LLM calls and security API
integrations are wired in the next step.
"""

from graph.state import SOCState


# ---------------------------------------------------------------------------
# Commander
# ---------------------------------------------------------------------------

def commander_node(state: SOCState) -> dict:
    alerts = state["alerts"]
    count = len(alerts)
    iteration = state.get("iteration_count", 0)

    print(f"[Commander] Routing {count} alert(s) — iteration {iteration + 1}")

    # Stub routing decision — activate all agents for every alert
    return {
        "iteration_count": iteration + 1,
    }


# ---------------------------------------------------------------------------
# Triage Officer
# ---------------------------------------------------------------------------

def triage_node(state: SOCState) -> dict:
    alerts = state["alerts"]
    print(f"[Triage Officer] Classifying {len(alerts)} alert(s)...")

    # Stub: assign Medium severity to all alerts
    results = []
    for alert in alerts:
        results.append({
            "alert_id": alert["id"],
            "severity": "Medium",
            "is_false_positive": False,
            "escalate_to_forensics": True,
            "classification": "Stub Classification",
            "triage_notes": "Placeholder — real LLM call goes here.",
        })

    print(f"[Triage Officer] Done. {len(results)} alert(s) classified.")
    return {"triage_results": results}


# ---------------------------------------------------------------------------
# Threat Hunter
# ---------------------------------------------------------------------------

def threat_hunter_node(state: SOCState) -> dict:
    alerts = state["alerts"]
    print(f"[Threat Hunter] Enriching IOCs for {len(alerts)} alert(s)...")

    results = []
    for alert in alerts:
        results.append({
            "alert_id": alert["id"],
            "iocs": {
                "ips": [alert.get("source_ip", "0.0.0.0")],
                "domains": [],
                "hashes": [],
            },
            "mitre_techniques": [
                {
                    "technique_id": "T1078",
                    "technique_name": "Valid Accounts",
                    "tactic": "Initial Access",
                }
            ],
            "threat_actor": "Unknown",
            "threat_actor_confidence": "Low",
            "hunter_notes": "Placeholder — real LLM call + API enrichment goes here.",
        })

    print(f"[Threat Hunter] Done. {len(results)} alert(s) enriched.")
    return {"enrichment_results": results}


# ---------------------------------------------------------------------------
# Forensics Analyst
# ---------------------------------------------------------------------------

def forensics_node(state: SOCState) -> dict:
    # Forensics runs in parallel with triage — investigate all alerts.
    # Once real LLM calls are wired in, this node will be gated by
    # the commander's routing decision (only escalated alerts).
    escalated = state.get("alerts", [])
    print(f"[Forensics Analyst] Deep-diving {len(escalated)} alert(s)...")

    results = []
    for alert in escalated:
        results.append({
            "alert_id": alert["id"],
            "kill_chain": [
                {"phase": "Initial Access", "description": "Placeholder — real analysis goes here."}
            ],
            "affected_systems": ["unknown"],
            "data_at_risk": "None identified",
            "blast_radius": "Limited",
            "containment_actions": ["Isolate affected host", "Reset credentials"],
            "forensics_notes": "Placeholder — real LLM call goes here.",
        })

    print(f"[Forensics Analyst] Done. {len(results)} report(s) produced.")
    return {"forensics_results": results}


# ---------------------------------------------------------------------------
# Oversight Officer
# ---------------------------------------------------------------------------

def oversight_node(state: SOCState) -> dict:
    triage = state.get("triage_results", [])
    enrichment = state.get("enrichment_results", [])
    forensics = state.get("forensics_results", [])

    print(
        f"[Oversight Officer] Cross-verifying {len(triage)} triage, "
        f"{len(enrichment)} enrichment, {len(forensics)} forensics result(s)..."
    )

    # Stub: approve everything with high confidence
    verdict = {
        "verdict": "APPROVED",
        "confidence": 85.0,
        "conflicts": [],
        "severity_overrides": [],
        "verification_alerts": [],
        "reasoning_summary": (
            "Placeholder — all findings consistent. "
            "Real cross-verification logic goes here."
        ),
    }

    print(f"[Oversight Officer] Verdict: {verdict['verdict']} (confidence: {verdict['confidence']})")
    return {
        "oversight_verdict": verdict,
        "confidence": verdict["confidence"],
        "verification_alerts": verdict["verification_alerts"],
    }


# ---------------------------------------------------------------------------
# Briefing Writer
# ---------------------------------------------------------------------------

def briefing_node(state: SOCState) -> dict:
    verdict = state.get("oversight_verdict", {})
    triage = state.get("triage_results", [])
    confidence = state.get("confidence", 0.0)

    print("[Briefing Writer] Generating final report...")

    severities = [r.get("severity", "Unknown") for r in triage]
    severity_summary = ", ".join(
        f"{sev}: {severities.count(sev)}"
        for sev in ["Critical", "High", "Medium", "Low", "Noise"]
        if sev in severities
    ) or "No results"

    briefing = (
        f"=== SOC SENTINEL — SECURITY BRIEFING ===\n\n"
        f"Alerts processed : {len(state.get('alerts', []))}\n"
        f"Severity breakdown: {severity_summary}\n"
        f"Oversight verdict : {verdict.get('verdict', 'N/A')}\n"
        f"Confidence score  : {confidence:.1f}/100\n"
        f"Conflicts flagged : {len(verdict.get('conflicts', []))}\n\n"
        f"Assessment:\n{verdict.get('reasoning_summary', 'N/A')}\n\n"
        f"[Placeholder — real K2 Think narrative goes here]"
    )

    print("[Briefing Writer] Done.")
    return {"briefing": briefing}

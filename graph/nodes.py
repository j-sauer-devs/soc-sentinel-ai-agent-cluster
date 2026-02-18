"""
Node functions for SOC Sentinel agent graph.

Each function:
  - Takes state: SOCState
  - Returns a partial state dict (LangGraph merges it into the full state)
  - Prints what it's doing so activity is visible during runs

Oversight Officer uses live K2 Think calls. Other nodes are still stubs
— real LLM calls and security API integrations coming next.
"""

import json
import os

from openai import OpenAI

from graph.prompts import OVERSIGHT_PROMPT
from graph.state import SOCState
from graph.utils import extract_reasoning

# ---------------------------------------------------------------------------
# K2 Think client — initialised once at module level
# ---------------------------------------------------------------------------

k2_client = OpenAI(
    api_key=os.getenv("K2_API_KEY"),
    base_url=os.getenv("K2_BASE_URL", "https://api.k2think.ai/v1"),
)
K2_MODEL = os.getenv("K2_MODEL", "MBZUAI-IFM/K2-Think-v2")


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

    # Build the user message with all available findings
    user_message = (
        "Cross-verify the following agent findings and produce your verdict.\n\n"
        f"=== TRIAGE RESULTS ===\n{json.dumps(triage, indent=2)}\n\n"
        f"=== THREAT HUNTER ENRICHMENT ===\n{json.dumps(enrichment, indent=2)}\n\n"
        f"=== FORENSICS RESULTS ===\n{json.dumps(forensics, indent=2)}\n\n"
        "Analyse all findings for conflicts, severity mismatches, and hallucinated "
        "indicators. Output your verdict as a single JSON object."
    )

    print("[Oversight Officer] Calling K2 Think...")
    response = k2_client.chat.completions.create(
        model=K2_MODEL,
        messages=[
            {"role": "system", "content": OVERSIGHT_PROMPT},
            {"role": "user", "content": user_message},
        ],
        max_tokens=2000,
    )

    raw_content = response.choices[0].message.content
    reasoning, answer = extract_reasoning(raw_content)

    print(f"[Oversight Officer] Reasoning block: {len(reasoning)} chars")

    # Parse JSON from the answer — strip markdown fences if present
    clean_answer = answer.strip()
    if clean_answer.startswith("```"):
        # Remove ```json ... ``` wrapper
        lines = clean_answer.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        clean_answer = "\n".join(lines).strip()

    try:
        parsed = json.loads(clean_answer)
    except json.JSONDecodeError as e:
        print(f"[Oversight Officer] JSON parse error: {e}")
        print(f"[Oversight Officer] Raw answer:\n{answer[:500]}")
        parsed = {
            "verdict": "NEEDS_REVIEW",
            "confidence": 50,
            "conflicts": [f"JSON parse error in Oversight output: {e}"],
            "severity_override": None,
            "reasoning_summary": "Oversight Officer returned non-JSON output. Manual review required.",
            "apt_indicators": [],
        }

    confidence = float(parsed.get("confidence", 50))
    conflicts = parsed.get("conflicts", [])

    print(f"[Oversight Officer] Verdict: {parsed.get('verdict', 'N/A')} (confidence: {confidence})")
    if conflicts:
        print(f"[Oversight Officer] Conflicts flagged: {len(conflicts)}")
        for c in conflicts:
            print(f"  - {c}")

    return {
        "oversight_verdict": parsed,
        "confidence": confidence,
        "verification_alerts": [
            {"alert_id": c.get("alert_id", "unknown"), "reason": str(c)}
            if isinstance(c, dict) else {"alert_id": "unknown", "reason": str(c)}
            for c in conflicts
        ],
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

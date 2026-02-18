"""
Node functions for SOC Sentinel agent graph.

Each function:
  - Takes state: SOCState
  - Returns a partial state dict (LangGraph merges it into the full state)
  - Prints what it's doing so activity is visible during runs

Oversight Officer uses live K2 Think calls.
Triage uses AbuseIPDB + GreyNoise for IP reputation scoring.
Threat Hunter uses OTX + VirusTotal for IOC enrichment.
Forensics uses NVD for CVE lookups on escalated alerts.
"""

import json
import os
import re

from openai import OpenAI

from apis.abuseipdb import check_ip as abuseipdb_check
from apis.greynoise import check_ip as greynoise_check
from apis.nvd import search_cves
from apis.otx import get_domain_pulses, get_ip_pulses
from apis.virustotal import check_domain as vt_domain
from apis.virustotal import check_ip as vt_check
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

# Shared caches to avoid duplicate API calls within a single run
_abuse_cache: dict = {}
_gn_cache: dict = {}
_otx_cache: dict = {}
_vt_cache: dict = {}
_nvd_cache: dict = {}


# ---------------------------------------------------------------------------
# Commander
# ---------------------------------------------------------------------------

def commander_node(state: SOCState) -> dict:
    alerts = state["alerts"]
    count = len(alerts)
    iteration = state.get("iteration_count", 0)

    print(f"[Commander] Routing {count} alert(s) — iteration {iteration + 1}")

    return {
        "iteration_count": iteration + 1,
    }


# ---------------------------------------------------------------------------
# Triage Officer — uses AbuseIPDB + GreyNoise for IP reputation
# ---------------------------------------------------------------------------

def triage_node(state: SOCState) -> dict:
    alerts = state["alerts"]
    print(f"[Triage Officer] Classifying {len(alerts)} alert(s) with AbuseIPDB + GreyNoise...")

    results = []
    for alert in alerts:
        ip = alert.get("source_ip", "")
        alert_type = alert.get("alert_type", "")
        desc = alert.get("description", "")

        # Query AbuseIPDB
        abuse = abuseipdb_check(ip, cache=_abuse_cache)
        abuse_score = abuse.get("abuse_confidence_score", 0)
        total_reports = abuse.get("total_reports", 0)
        print(f"  [AbuseIPDB] {ip}: confidence={abuse_score}, reports={total_reports}")

        # Query GreyNoise
        gn = greynoise_check(ip, cache=_gn_cache)
        gn_class = gn.get("classification", "unknown")
        gn_noise = gn.get("noise", False)
        print(f"  [GreyNoise] {ip}: classification={gn_class}, noise={gn_noise}")

        # Severity scoring based on API data
        if abuse_score >= 80 or gn_class == "malicious":
            severity = "Critical"
            escalate = True
        elif abuse_score >= 50 or total_reports >= 10:
            severity = "High"
            escalate = True
        elif abuse_score >= 20 or total_reports >= 3:
            severity = "Medium"
            escalate = False
        elif gn_class == "benign" or abuse_score == 0:
            # Check for obvious false positives
            if ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"):
                severity = "Noise"
                escalate = False
            else:
                severity = "Low"
                escalate = False
        else:
            severity = "Medium"
            escalate = False

        # Override: if alert type mentions exfiltration or malware, escalate
        if any(kw in alert_type.lower() for kw in ("exfil", "malware", "c2", "ransomware")):
            if severity in ("Low", "Noise"):
                severity = "Medium"
            escalate = True

        is_fp = severity == "Noise" or (gn_class == "benign" and abuse_score == 0)

        results.append({
            "alert_id": alert["id"],
            "severity": severity,
            "is_false_positive": is_fp,
            "escalate_to_forensics": escalate,
            "classification": alert_type,
            "triage_notes": (
                f"AbuseIPDB: {abuse_score}/100 confidence, {total_reports} reports. "
                f"GreyNoise: {gn_class}. "
                f"Auto-classified as {severity}."
            ),
            "api_data": {
                "abuseipdb": abuse,
                "greynoise": gn,
            },
        })

    print(f"[Triage Officer] Done. {len(results)} alert(s) classified.")
    return {"triage_results": results}


# ---------------------------------------------------------------------------
# Threat Hunter — uses OTX + VirusTotal for IOC enrichment
# ---------------------------------------------------------------------------

def _extract_domains(text: str) -> list[str]:
    """Pull domain-like strings out of alert description."""
    pattern = r'(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)'
    matches = re.findall(pattern, text)
    # Filter out common benign domains
    benign = {"google.com", "googleapis.com", "microsoft.com", "github.com"}
    return [d for d in set(matches) if d not in benign]


def _extract_hashes(text: str) -> list[str]:
    """Pull SHA256/SHA1/MD5 hashes out of alert description."""
    sha256 = re.findall(r'\b[a-fA-F0-9]{64}\b', text)
    sha1 = re.findall(r'\b[a-fA-F0-9]{40}\b', text)
    md5 = re.findall(r'\b[a-fA-F0-9]{32}\b', text)
    return list(set(sha256 + sha1 + md5))


def threat_hunter_node(state: SOCState) -> dict:
    alerts = state["alerts"]
    print(f"[Threat Hunter] Enriching IOCs for {len(alerts)} alert(s) with OTX + VirusTotal...")

    results = []
    for alert in alerts:
        ip = alert.get("source_ip", "")
        desc = alert.get("description", "")
        domains = _extract_domains(desc)
        hashes = _extract_hashes(desc)

        # OTX IP lookup
        otx_ip = get_ip_pulses(ip, cache=_otx_cache)
        otx_pulse_count = otx_ip.get("pulse_count", 0)
        otx_pulses = otx_ip.get("pulses", [])
        print(f"  [OTX] {ip}: {otx_pulse_count} pulse(s)")

        # OTX domain lookups
        otx_domain_data = []
        for domain in domains:
            d_result = get_domain_pulses(domain, cache=_otx_cache)
            otx_domain_data.append(d_result)
            print(f"  [OTX] {domain}: {d_result.get('pulse_count', 0)} pulse(s)")

        # VirusTotal IP lookup
        vt_ip = vt_check(ip, cache=_vt_cache)
        vt_malicious = vt_ip.get("malicious", 0)
        print(f"  [VirusTotal] {ip}: {vt_malicious} malicious vote(s)")

        # VirusTotal domain lookups
        vt_domain_data = []
        for domain in domains:
            d_result = vt_domain(domain, cache=_vt_cache)
            vt_domain_data.append(d_result)
            d_mal = d_result.get("malicious", 0)
            print(f"  [VirusTotal] {domain}: {d_mal} malicious vote(s)")

        # Determine threat actor attribution from OTX pulses
        threat_actor = "Unknown"
        threat_actor_confidence = "Low"
        apt_suspected = False
        apt_keywords = ["apt", "cozy bear", "fancy bear", "lazarus", "turla",
                        "carbanak", "sandworm", "kimsuky", "apt28", "apt29",
                        "apt41", "nation-state", "state-sponsored"]

        all_pulse_tags = []
        all_pulse_names = []
        for p in otx_pulses:
            all_pulse_tags.extend(p.get("tags", []))
            all_pulse_names.append(p.get("name", ""))

        combined_pulse_text = " ".join(all_pulse_names + all_pulse_tags).lower()
        for kw in apt_keywords:
            if kw in combined_pulse_text:
                apt_suspected = True
                # Try to extract the specific APT name
                for name in all_pulse_names:
                    if kw in name.lower():
                        threat_actor = name[:80]
                        threat_actor_confidence = "High" if otx_pulse_count >= 3 else "Medium"
                        break
                break

        # Map alert type to MITRE techniques (basic mapping)
        mitre_map = {
            "brute force": [{"technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access"}],
            "lateral movement": [{"technique_id": "T1021", "technique_name": "Remote Services", "tactic": "Lateral Movement"}],
            "data exfil": [{"technique_id": "T1048", "technique_name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"}],
            "malware": [{"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "Command and Control"}],
            "c2": [{"technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactic": "Command and Control"}],
            "dns": [{"technique_id": "T1071.004", "technique_name": "DNS", "tactic": "Command and Control"}],
            "suspicious outbound": [{"technique_id": "T1071.001", "technique_name": "Web Protocols", "tactic": "Command and Control"}],
        }
        mitre_techniques = []
        alert_type_lower = alert.get("alert_type", "").lower()
        for key, techniques in mitre_map.items():
            if key in alert_type_lower:
                mitre_techniques.extend(techniques)
        if not mitre_techniques:
            mitre_techniques = [{"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Initial Access"}]

        results.append({
            "alert_id": alert["id"],
            "iocs": {
                "ips": [ip],
                "domains": domains,
                "hashes": hashes,
            },
            "mitre_techniques": mitre_techniques,
            "threat_actor": threat_actor,
            "threat_actor_confidence": threat_actor_confidence,
            "apt_suspected": apt_suspected,
            "hunter_notes": (
                f"OTX: {otx_pulse_count} pulse(s) for {ip}. "
                f"VT: {vt_malicious} malicious vote(s). "
                f"APT suspected: {apt_suspected}. "
                f"Domains: {domains or 'none extracted'}."
            ),
            "api_data": {
                "otx_ip": otx_ip,
                "otx_domains": otx_domain_data,
                "virustotal_ip": vt_ip,
                "virustotal_domains": vt_domain_data,
            },
        })

    print(f"[Threat Hunter] Done. {len(results)} alert(s) enriched.")
    return {"enrichment_results": results}


# ---------------------------------------------------------------------------
# Forensics Analyst — uses NVD for CVE lookups on escalated alerts
# ---------------------------------------------------------------------------

def forensics_node(state: SOCState) -> dict:
    alerts = state.get("alerts", [])
    enrichment = state.get("enrichment_results", [])
    print(f"[Forensics Analyst] Deep-diving {len(alerts)} alert(s)...")

    # Build a lookup of enrichment by alert_id
    enrichment_by_id = {}
    for e in enrichment:
        enrichment_by_id[e.get("alert_id")] = e

    results = []
    for alert in alerts:
        alert_id = alert["id"]
        alert_type = alert.get("alert_type", "")
        desc = alert.get("description", "")
        enrich = enrichment_by_id.get(alert_id, {})
        apt_suspected = enrich.get("apt_suspected", False)

        # NVD CVE lookup for alerts with APT suspicion or high-severity types
        cves = []
        if apt_suspected or any(kw in alert_type.lower() for kw in ("malware", "exploit", "cve", "vulnerability")):
            # Search NVD by alert type or threat actor name
            search_term = enrich.get("threat_actor", alert_type)
            if search_term == "Unknown":
                search_term = alert_type
            print(f"  [NVD] Searching CVEs for: {search_term}")
            cves = search_cves(search_term, cache=_nvd_cache, max_results=3)
            for cve in cves:
                print(f"    {cve['cve_id']}: CVSS {cve['cvss_score']} ({cve['severity']})")
        else:
            print(f"  [NVD] Skipping CVE lookup for {alert_id} (no APT/exploit indicators)")

        # Build kill chain from available data
        kill_chain = []
        if "brute" in alert_type.lower():
            kill_chain = [
                {"phase": "Reconnaissance", "description": "Attacker scanned for SSH/RDP services."},
                {"phase": "Initial Access", "description": f"Brute-force attack from {alert.get('source_ip', 'unknown')}."},
            ]
        elif "lateral" in alert_type.lower():
            kill_chain = [
                {"phase": "Initial Access", "description": "Compromised internal host."},
                {"phase": "Credential Access", "description": "Credential dumping or pass-the-hash."},
                {"phase": "Lateral Movement", "description": desc[:200]},
            ]
        elif "malware" in alert_type.lower() or "download" in alert_type.lower():
            kill_chain = [
                {"phase": "Initial Access", "description": "User interaction with malicious content."},
                {"phase": "Execution", "description": "Attempted malware download."},
                {"phase": "Defence Evasion", "description": "Payload delivery attempted."},
            ]
        elif "exfil" in alert_type.lower() or "dns" in alert_type.lower():
            kill_chain = [
                {"phase": "Collection", "description": "Data staged for exfiltration."},
                {"phase": "Exfiltration", "description": desc[:200]},
            ]
        else:
            kill_chain = [
                {"phase": "Unknown", "description": f"Alert type: {alert_type}. {desc[:150]}"},
            ]

        results.append({
            "alert_id": alert_id,
            "kill_chain": kill_chain,
            "affected_systems": [desc.split("host ")[-1].split(".")[0].split(" ")[0] if "host " in desc.lower() else "unknown"],
            "data_at_risk": "Under investigation" if apt_suspected else "None identified",
            "blast_radius": "Significant" if apt_suspected else "Limited",
            "containment_actions": [
                "Isolate affected host",
                "Reset credentials",
                "Block IOCs at perimeter",
            ],
            "related_cves": cves,
            "forensics_notes": (
                f"APT suspected: {apt_suspected}. "
                f"Related CVEs found: {len(cves)}. "
                f"Kill chain reconstructed with {len(kill_chain)} phase(s)."
            ),
        })

    print(f"[Forensics Analyst] Done. {len(results)} report(s) produced.")
    return {"forensics_results": results}


# ---------------------------------------------------------------------------
# Oversight Officer — live K2 Think cross-verification
# ---------------------------------------------------------------------------

def oversight_node(state: SOCState) -> dict:
    triage = state.get("triage_results", [])
    enrichment = state.get("enrichment_results", [])
    forensics = state.get("forensics_results", [])

    print(
        f"[Oversight Officer] Cross-verifying {len(triage)} triage, "
        f"{len(enrichment)} enrichment, {len(forensics)} forensics result(s)..."
    )

    # Strip api_data from results to reduce token count for K2 Think
    triage_clean = [{k: v for k, v in r.items() if k != "api_data"} for r in triage]
    enrichment_clean = [{k: v for k, v in r.items() if k != "api_data"} for r in enrichment]

    # Build the user message with all available findings
    user_message = (
        "Cross-verify the following agent findings and produce your verdict.\n\n"
        f"=== TRIAGE RESULTS ===\n{json.dumps(triage_clean, indent=2)}\n\n"
        f"=== THREAT HUNTER ENRICHMENT ===\n{json.dumps(enrichment_clean, indent=2)}\n\n"
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

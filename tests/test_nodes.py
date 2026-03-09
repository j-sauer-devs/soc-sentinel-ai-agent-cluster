"""Tests for graph/nodes.py — all 6 agent node functions.

Patches all 5 security API clients and K2 Think to test node logic in isolation.
"""

from unittest.mock import MagicMock, patch
import json
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_state(alerts, **kwargs):
    """Build a minimal SOCState dict for testing."""
    base = {
        "alerts": alerts,
        "triage_results": [],
        "enrichment_results": [],
        "forensics_results": [],
        "oversight_verdict": {},
        "confidence": 0.0,
        "briefing": "",
        "verification_alerts": [],
        "iteration_count": 0,
    }
    base.update(kwargs)
    return base


def _alert(alert_id="ALERT-001", source_ip="192.168.1.1", dest_ip="10.0.0.1",
           alert_type="Suspicious Activity", description="Test alert"):
    return {
        "id": alert_id,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "alert_type": alert_type,
        "description": description,
    }


ABUSE_PATCH = "graph.nodes.abuseipdb_check"
GN_PATCH = "graph.nodes.greynoise_check"
OTX_IP_PATCH = "graph.nodes.get_ip_pulses"
OTX_DOMAIN_PATCH = "graph.nodes.get_domain_pulses"
VT_IP_PATCH = "graph.nodes.vt_check"
VT_DOMAIN_PATCH = "graph.nodes.vt_domain"
NVD_PATCH = "graph.nodes.search_cves"
K2_CLIENT_PATCH = "graph.nodes.k2_client"


class TestCommanderNode:
    def test_increments_iteration_count(self):
        from graph.nodes import commander_node
        state = _make_state([_alert()], iteration_count=0)
        result = commander_node(state)
        assert result["iteration_count"] == 1

    def test_subsequent_iteration(self):
        from graph.nodes import commander_node
        state = _make_state([_alert()], iteration_count=2)
        result = commander_node(state)
        assert result["iteration_count"] == 3

    def test_handles_missing_iteration_count(self):
        from graph.nodes import commander_node
        state = {"alerts": [_alert()]}
        result = commander_node(state)
        assert result["iteration_count"] == 1


class TestExtractDomains:
    def test_extracts_domains(self):
        from graph.nodes import _extract_domains
        text = "Connection to evil.example.com detected on port 443"
        domains = _extract_domains(text)
        assert "evil.example.com" in domains

    def test_filters_benign_domains(self):
        from graph.nodes import _extract_domains
        text = "DNS lookup to google.com and microsoft.com"
        domains = _extract_domains(text)
        assert "google.com" not in domains
        assert "microsoft.com" not in domains

    def test_extracts_from_url(self):
        from graph.nodes import _extract_domains
        text = "Beacon to https://malware.baddomain.org/callback"
        domains = _extract_domains(text)
        assert "malware.baddomain.org" in domains

    def test_empty_input(self):
        from graph.nodes import _extract_domains
        assert _extract_domains("") == []

    def test_no_domains(self):
        from graph.nodes import _extract_domains
        assert _extract_domains("Just a plain text with no domains 123") == []


class TestExtractHashes:
    def test_sha256(self):
        from graph.nodes import _extract_hashes
        sha = "a" * 64
        hashes = _extract_hashes(f"Found hash {sha} in memory")
        assert sha in hashes

    def test_sha1(self):
        from graph.nodes import _extract_hashes
        sha1 = "b" * 40
        hashes = _extract_hashes(f"SHA1: {sha1}")
        assert sha1 in hashes

    def test_md5(self):
        from graph.nodes import _extract_hashes
        md5 = "c" * 32
        hashes = _extract_hashes(f"MD5 hash: {md5}")
        assert md5 in hashes

    def test_no_hashes(self):
        from graph.nodes import _extract_hashes
        assert _extract_hashes("No hashes here") == []

    def test_deduplication(self):
        from graph.nodes import _extract_hashes
        sha = "d" * 64
        hashes = _extract_hashes(f"Hash {sha} and again {sha}")
        assert len([h for h in hashes if h == sha]) == 1


class TestTriageNode:
    @patch(GN_PATCH)
    @patch(ABUSE_PATCH)
    def test_critical_high_abuse(self, mock_abuse, mock_gn):
        mock_abuse.return_value = {"abuse_confidence_score": 90, "total_reports": 50}
        mock_gn.return_value = {"classification": "unknown", "noise": False}
        from graph.nodes import triage_node
        result = triage_node(_make_state([_alert()]))
        assert result["triage_results"][0]["severity"] == "Critical"
        assert result["triage_results"][0]["escalate_to_forensics"] is True

    @patch(GN_PATCH)
    @patch(ABUSE_PATCH)
    def test_critical_gn_malicious(self, mock_abuse, mock_gn):
        mock_abuse.return_value = {"abuse_confidence_score": 10, "total_reports": 0}
        mock_gn.return_value = {"classification": "malicious", "noise": True}
        from graph.nodes import triage_node
        result = triage_node(_make_state([_alert()]))
        assert result["triage_results"][0]["severity"] == "Critical"

    @patch(GN_PATCH)
    @patch(ABUSE_PATCH)
    def test_high_abuse_50(self, mock_abuse, mock_gn):
        mock_abuse.return_value = {"abuse_confidence_score": 55, "total_reports": 5}
        mock_gn.return_value = {"classification": "unknown", "noise": False}
        from graph.nodes import triage_node
        result = triage_node(_make_state([_alert()]))
        assert result["triage_results"][0]["severity"] == "High"
        assert result["triage_results"][0]["escalate_to_forensics"] is True

    @patch(GN_PATCH)
    @patch(ABUSE_PATCH)
    def test_high_many_reports(self, mock_abuse, mock_gn):
        mock_abuse.return_value = {"abuse_confidence_score": 30, "total_reports": 15}
        mock_gn.return_value = {"classification": "unknown", "noise": False}
        from graph.nodes import triage_node
        result = triage_node(_make_state([_alert()]))
        assert result["triage_results"][0]["severity"] == "High"

    @patch(GN_PATCH)
    @patch(ABUSE_PATCH)
    def test_medium_abuse_20(self, mock_abuse, mock_gn):
        mock_abuse.return_value = {"abuse_confidence_score": 25, "total_reports": 1}
        mock_gn.return_value = {"classification": "unknown", "noise": False}
        from graph.nodes import triage_node
        result = triage_node(_make_state([_alert()]))
        assert result["triage_results"][0]["severity"] == "Medium"

    @patch(GN_PATCH)
    @patch(ABUSE_PATCH)
    def test_low_severity(self, mock_abuse, mock_gn):
        mock_abuse.return_value = {"abuse_confidence_score": 0, "total_reports": 0}
        mock_gn.return_value = {"classification": "benign", "noise": False}
        from graph.nodes import triage_node
        result = triage_node(_make_state([_alert(source_ip="5.5.5.5")]))
        assert result["triage_results"][0]["severity"] == "Low"

    @patch(GN_PATCH)
    @patch(ABUSE_PATCH)
    def test_noise_known_dns(self, mock_abuse, mock_gn):
        mock_abuse.return_value = {"abuse_confidence_score": 0, "total_reports": 0}
        mock_gn.return_value = {"classification": "benign", "noise": False}
        from graph.nodes import triage_node
        result = triage_node(_make_state([_alert(source_ip="8.8.8.8")]))
        assert result["triage_results"][0]["severity"] == "Noise"
        assert result["triage_results"][0]["is_false_positive"] is True

    @patch(GN_PATCH)
    @patch(ABUSE_PATCH)
    def test_noise_1111(self, mock_abuse, mock_gn):
        mock_abuse.return_value = {"abuse_confidence_score": 0, "total_reports": 0}
        mock_gn.return_value = {"classification": "benign", "noise": False}
        from graph.nodes import triage_node
        result = triage_node(_make_state([_alert(source_ip="1.1.1.1")]))
        assert result["triage_results"][0]["severity"] == "Noise"

    @patch(GN_PATCH)
    @patch(ABUSE_PATCH)
    def test_keyword_escalation_exfil(self, mock_abuse, mock_gn):
        mock_abuse.return_value = {"abuse_confidence_score": 0, "total_reports": 0}
        mock_gn.return_value = {"classification": "benign", "noise": False}
        from graph.nodes import triage_node
        alert = _alert(source_ip="5.5.5.5", alert_type="Data Exfiltration Detected")
        result = triage_node(_make_state([alert]))
        assert result["triage_results"][0]["severity"] == "Medium"
        assert result["triage_results"][0]["escalate_to_forensics"] is True

    @patch(GN_PATCH)
    @patch(ABUSE_PATCH)
    def test_keyword_escalation_malware(self, mock_abuse, mock_gn):
        mock_abuse.return_value = {"abuse_confidence_score": 0, "total_reports": 0}
        mock_gn.return_value = {"classification": "benign", "noise": False}
        from graph.nodes import triage_node
        alert = _alert(source_ip="5.5.5.5", alert_type="Malware Download")
        result = triage_node(_make_state([alert]))
        assert result["triage_results"][0]["severity"] == "Medium"

    @patch(GN_PATCH)
    @patch(ABUSE_PATCH)
    def test_api_data_included(self, mock_abuse, mock_gn):
        abuse_data = {"abuse_confidence_score": 50, "total_reports": 5}
        gn_data = {"classification": "unknown", "noise": True}
        mock_abuse.return_value = abuse_data
        mock_gn.return_value = gn_data
        from graph.nodes import triage_node
        result = triage_node(_make_state([_alert()]))
        api_data = result["triage_results"][0]["api_data"]
        assert api_data["abuseipdb"] == abuse_data
        assert api_data["greynoise"] == gn_data

    @patch(GN_PATCH)
    @patch(ABUSE_PATCH)
    def test_multiple_alerts(self, mock_abuse, mock_gn):
        mock_abuse.return_value = {"abuse_confidence_score": 50, "total_reports": 5}
        mock_gn.return_value = {"classification": "unknown", "noise": False}
        from graph.nodes import triage_node
        alerts = [_alert("A-1"), _alert("A-2"), _alert("A-3")]
        result = triage_node(_make_state(alerts))
        assert len(result["triage_results"]) == 3


class TestThreatHunterNode:
    @patch(VT_DOMAIN_PATCH)
    @patch(VT_IP_PATCH)
    @patch(OTX_DOMAIN_PATCH)
    @patch(OTX_IP_PATCH)
    def test_basic_enrichment(self, mock_otx_ip, mock_otx_domain, mock_vt_ip, mock_vt_domain):
        mock_otx_ip.return_value = {"pulse_count": 0, "pulses": []}
        mock_vt_ip.return_value = {"malicious": 0}
        from graph.nodes import threat_hunter_node
        result = threat_hunter_node(_make_state([_alert()]))
        assert len(result["enrichment_results"]) == 1
        r = result["enrichment_results"][0]
        assert r["alert_id"] == "ALERT-001"
        assert "iocs" in r
        assert "mitre_techniques" in r

    @patch(VT_DOMAIN_PATCH)
    @patch(VT_IP_PATCH)
    @patch(OTX_DOMAIN_PATCH)
    @patch(OTX_IP_PATCH)
    def test_mitre_brute_force(self, mock_otx_ip, mock_otx_domain, mock_vt_ip, mock_vt_domain):
        mock_otx_ip.return_value = {"pulse_count": 0, "pulses": []}
        mock_vt_ip.return_value = {"malicious": 0}
        from graph.nodes import threat_hunter_node
        alert = _alert(alert_type="SSH Brute Force Attack")
        result = threat_hunter_node(_make_state([alert]))
        techniques = result["enrichment_results"][0]["mitre_techniques"]
        assert any(t["technique_id"] == "T1110" for t in techniques)

    @patch(VT_DOMAIN_PATCH)
    @patch(VT_IP_PATCH)
    @patch(OTX_DOMAIN_PATCH)
    @patch(OTX_IP_PATCH)
    def test_mitre_exfil(self, mock_otx_ip, mock_otx_domain, mock_vt_ip, mock_vt_domain):
        mock_otx_ip.return_value = {"pulse_count": 0, "pulses": []}
        mock_vt_ip.return_value = {"malicious": 0}
        from graph.nodes import threat_hunter_node
        alert = _alert(alert_type="Data Exfil via DNS")
        result = threat_hunter_node(_make_state([alert]))
        techniques = result["enrichment_results"][0]["mitre_techniques"]
        tech_ids = [t["technique_id"] for t in techniques]
        assert "T1048" in tech_ids or "T1071.004" in tech_ids

    @patch(VT_DOMAIN_PATCH)
    @patch(VT_IP_PATCH)
    @patch(OTX_DOMAIN_PATCH)
    @patch(OTX_IP_PATCH)
    def test_mitre_default_fallback(self, mock_otx_ip, mock_otx_domain, mock_vt_ip, mock_vt_domain):
        mock_otx_ip.return_value = {"pulse_count": 0, "pulses": []}
        mock_vt_ip.return_value = {"malicious": 0}
        from graph.nodes import threat_hunter_node
        alert = _alert(alert_type="Unknown Activity")
        result = threat_hunter_node(_make_state([alert]))
        techniques = result["enrichment_results"][0]["mitre_techniques"]
        assert techniques[0]["technique_id"] == "T1078"

    @patch(VT_DOMAIN_PATCH)
    @patch(VT_IP_PATCH)
    @patch(OTX_DOMAIN_PATCH)
    @patch(OTX_IP_PATCH)
    def test_apt_detection(self, mock_otx_ip, mock_otx_domain, mock_vt_ip, mock_vt_domain):
        mock_otx_ip.return_value = {
            "pulse_count": 5,
            "pulses": [
                {"name": "APT29 Cozy Bear Campaign", "tags": ["apt", "russia"], "description": ""},
            ],
        }
        mock_vt_ip.return_value = {"malicious": 3}
        from graph.nodes import threat_hunter_node
        result = threat_hunter_node(_make_state([_alert()]))
        r = result["enrichment_results"][0]
        assert r["apt_suspected"] is True
        assert r["threat_actor_confidence"] in ("Medium", "High")

    @patch(VT_DOMAIN_PATCH)
    @patch(VT_IP_PATCH)
    @patch(OTX_DOMAIN_PATCH)
    @patch(OTX_IP_PATCH)
    def test_no_apt(self, mock_otx_ip, mock_otx_domain, mock_vt_ip, mock_vt_domain):
        mock_otx_ip.return_value = {
            "pulse_count": 1,
            "pulses": [{"name": "Spam IP", "tags": ["spam"], "description": ""}],
        }
        mock_vt_ip.return_value = {"malicious": 0}
        from graph.nodes import threat_hunter_node
        result = threat_hunter_node(_make_state([_alert()]))
        assert result["enrichment_results"][0]["apt_suspected"] is False
        assert result["enrichment_results"][0]["threat_actor"] == "Unknown"

    @patch(VT_DOMAIN_PATCH)
    @patch(VT_IP_PATCH)
    @patch(OTX_DOMAIN_PATCH)
    @patch(OTX_IP_PATCH)
    def test_domain_extraction_and_lookup(self, mock_otx_ip, mock_otx_domain, mock_vt_ip, mock_vt_domain):
        mock_otx_ip.return_value = {"pulse_count": 0, "pulses": []}
        mock_otx_domain.return_value = {"pulse_count": 0, "pulses": []}
        mock_vt_ip.return_value = {"malicious": 0}
        mock_vt_domain.return_value = {"malicious": 0}
        from graph.nodes import threat_hunter_node
        alert = _alert(description="Beacon to evil.example.com detected")
        result = threat_hunter_node(_make_state([alert]))
        r = result["enrichment_results"][0]
        assert "evil.example.com" in r["iocs"]["domains"]
        mock_otx_domain.assert_called()
        mock_vt_domain.assert_called()

    @patch(VT_DOMAIN_PATCH)
    @patch(VT_IP_PATCH)
    @patch(OTX_DOMAIN_PATCH)
    @patch(OTX_IP_PATCH)
    def test_api_data_structure(self, mock_otx_ip, mock_otx_domain, mock_vt_ip, mock_vt_domain):
        mock_otx_ip.return_value = {"pulse_count": 2, "pulses": []}
        mock_vt_ip.return_value = {"malicious": 1}
        from graph.nodes import threat_hunter_node
        result = threat_hunter_node(_make_state([_alert()]))
        api_data = result["enrichment_results"][0]["api_data"]
        assert "otx_ip" in api_data
        assert "virustotal_ip" in api_data


class TestForensicsNode:
    @patch(NVD_PATCH)
    def test_kill_chain_brute_force(self, mock_nvd):
        mock_nvd.return_value = []
        from graph.nodes import forensics_node
        alert = _alert(alert_type="SSH Brute Force")
        state = _make_state([alert])
        result = forensics_node(state)
        phases = [p["phase"] for p in result["forensics_results"][0]["kill_chain"]]
        assert "Reconnaissance" in phases
        assert "Initial Access" in phases

    @patch(NVD_PATCH)
    def test_kill_chain_lateral(self, mock_nvd):
        mock_nvd.return_value = []
        from graph.nodes import forensics_node
        alert = _alert(alert_type="Lateral Movement Detected")
        state = _make_state([alert])
        result = forensics_node(state)
        phases = [p["phase"] for p in result["forensics_results"][0]["kill_chain"]]
        assert "Credential Access" in phases
        assert "Lateral Movement" in phases

    @patch(NVD_PATCH)
    def test_kill_chain_malware(self, mock_nvd):
        mock_nvd.return_value = []
        from graph.nodes import forensics_node
        alert = _alert(alert_type="Malware Download")
        state = _make_state([alert])
        result = forensics_node(state)
        phases = [p["phase"] for p in result["forensics_results"][0]["kill_chain"]]
        assert "Execution" in phases
        assert "Defence Evasion" in phases

    @patch(NVD_PATCH)
    def test_kill_chain_exfil(self, mock_nvd):
        mock_nvd.return_value = []
        from graph.nodes import forensics_node
        alert = _alert(alert_type="Data Exfiltration")
        state = _make_state([alert])
        result = forensics_node(state)
        phases = [p["phase"] for p in result["forensics_results"][0]["kill_chain"]]
        assert "Collection" in phases
        assert "Exfiltration" in phases

    @patch(NVD_PATCH)
    def test_kill_chain_unknown(self, mock_nvd):
        mock_nvd.return_value = []
        from graph.nodes import forensics_node
        alert = _alert(alert_type="Weird Activity")
        state = _make_state([alert])
        result = forensics_node(state)
        phases = [p["phase"] for p in result["forensics_results"][0]["kill_chain"]]
        assert "Unknown" in phases

    @patch(NVD_PATCH)
    def test_cve_lookup_with_apt(self, mock_nvd):
        mock_nvd.return_value = [{"cve_id": "CVE-2024-1234", "cvss_score": 9.8, "severity": "CRITICAL", "description": "Test"}]
        from graph.nodes import forensics_node
        alert = _alert(alert_type="Suspicious Activity")
        enrichment = [{"alert_id": "ALERT-001", "apt_suspected": True, "threat_actor": "APT29"}]
        state = _make_state([alert], enrichment_results=enrichment)
        result = forensics_node(state)
        r = result["forensics_results"][0]
        assert len(r["related_cves"]) == 1
        assert r["related_cves"][0]["cve_id"] == "CVE-2024-1234"
        mock_nvd.assert_called_once()

    @patch(NVD_PATCH)
    def test_cve_lookup_with_malware_keyword(self, mock_nvd):
        mock_nvd.return_value = [{"cve_id": "CVE-2024-5678", "cvss_score": 7.5, "severity": "HIGH", "description": "Test"}]
        from graph.nodes import forensics_node
        alert = _alert(alert_type="Malware Execution")
        state = _make_state([alert])
        result = forensics_node(state)
        assert len(result["forensics_results"][0]["related_cves"]) == 1

    @patch(NVD_PATCH)
    def test_no_cve_lookup_for_benign(self, mock_nvd):
        from graph.nodes import forensics_node
        alert = _alert(alert_type="Port Scan")
        state = _make_state([alert])
        forensics_node(state)
        mock_nvd.assert_not_called()

    @patch(NVD_PATCH)
    def test_blast_radius_apt(self, mock_nvd):
        mock_nvd.return_value = []
        from graph.nodes import forensics_node
        alert = _alert()
        enrichment = [{"alert_id": "ALERT-001", "apt_suspected": True}]
        state = _make_state([alert], enrichment_results=enrichment)
        result = forensics_node(state)
        assert result["forensics_results"][0]["blast_radius"] == "Significant"

    @patch(NVD_PATCH)
    def test_blast_radius_no_apt(self, mock_nvd):
        mock_nvd.return_value = []
        from graph.nodes import forensics_node
        state = _make_state([_alert()])
        result = forensics_node(state)
        assert result["forensics_results"][0]["blast_radius"] == "Limited"


class TestOversightNode:
    @patch(K2_CLIENT_PATCH)
    def test_parses_valid_json(self, mock_k2):
        verdict = {
            "verdict": "CONFIRMED_THREAT",
            "confidence": 85,
            "conflicts": [],
            "severity_override": None,
            "reasoning_summary": "All agents agree.",
            "apt_indicators": [],
        }
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(verdict)
        mock_k2.chat.completions.create.return_value = mock_response

        from graph.nodes import oversight_node
        state = _make_state(
            [_alert()],
            triage_results=[{"alert_id": "A-1", "severity": "Critical"}],
            enrichment_results=[{"alert_id": "A-1", "apt_suspected": True}],
            forensics_results=[{"alert_id": "A-1", "kill_chain": []}],
        )
        result = oversight_node(state)
        assert result["oversight_verdict"]["verdict"] == "CONFIRMED_THREAT"
        assert result["confidence"] == 85.0

    @patch(K2_CLIENT_PATCH)
    def test_handles_think_tags(self, mock_k2):
        verdict = {"verdict": "SUSPICIOUS", "confidence": 60, "conflicts": []}
        content = f"<think>Let me analyze...</think>{json.dumps(verdict)}"
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = content
        mock_k2.chat.completions.create.return_value = mock_response

        from graph.nodes import oversight_node
        state = _make_state([_alert()], triage_results=[], enrichment_results=[], forensics_results=[])
        result = oversight_node(state)
        assert result["oversight_verdict"]["verdict"] == "SUSPICIOUS"
        assert result["confidence"] == 60.0

    @patch(K2_CLIENT_PATCH)
    def test_json_parse_error_fallback(self, mock_k2):
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "This is not valid JSON at all"
        mock_k2.chat.completions.create.return_value = mock_response

        from graph.nodes import oversight_node
        state = _make_state([_alert()], triage_results=[], enrichment_results=[], forensics_results=[])
        result = oversight_node(state)
        assert result["oversight_verdict"]["verdict"] == "NEEDS_REVIEW"
        assert result["confidence"] == 50.0

    @patch(K2_CLIENT_PATCH)
    def test_conflicts_become_verification_alerts(self, mock_k2):
        verdict = {
            "verdict": "NEEDS_REVIEW",
            "confidence": 40,
            "conflicts": ["Severity mismatch: triage says Low but APT suspected"],
        }
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(verdict)
        mock_k2.chat.completions.create.return_value = mock_response

        from graph.nodes import oversight_node
        state = _make_state([_alert()], triage_results=[], enrichment_results=[], forensics_results=[])
        result = oversight_node(state)
        assert len(result["verification_alerts"]) == 1

    @patch(K2_CLIENT_PATCH)
    def test_strips_markdown_fences(self, mock_k2):
        verdict = {"verdict": "THREAT", "confidence": 75, "conflicts": []}
        content = f"```json\n{json.dumps(verdict)}\n```"
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = content
        mock_k2.chat.completions.create.return_value = mock_response

        from graph.nodes import oversight_node
        state = _make_state([_alert()], triage_results=[], enrichment_results=[], forensics_results=[])
        result = oversight_node(state)
        assert result["oversight_verdict"]["verdict"] == "THREAT"


class TestBriefingNode:
    def test_generates_briefing(self):
        from graph.nodes import briefing_node
        state = _make_state(
            [_alert()],
            oversight_verdict={"verdict": "THREAT", "conflicts": [], "reasoning_summary": "Test"},
            triage_results=[{"severity": "Critical"}],
            confidence=85.0,
        )
        result = briefing_node(state)
        assert "SECURITY BRIEFING" in result["briefing"]
        assert "Critical: 1" in result["briefing"]

    def test_includes_confidence(self):
        from graph.nodes import briefing_node
        state = _make_state(
            [_alert()],
            oversight_verdict={"verdict": "OK", "conflicts": [], "reasoning_summary": "Fine"},
            triage_results=[],
            confidence=92.5,
        )
        result = briefing_node(state)
        assert "92.5" in result["briefing"]

    def test_handles_empty_triage(self):
        from graph.nodes import briefing_node
        state = _make_state(
            [_alert()],
            oversight_verdict={"verdict": "N/A", "conflicts": []},
            triage_results=[],
            confidence=0.0,
        )
        result = briefing_node(state)
        assert "No results" in result["briefing"]

    def test_multiple_severities(self):
        from graph.nodes import briefing_node
        state = _make_state(
            [_alert(), _alert()],
            oversight_verdict={"verdict": "THREAT", "conflicts": [], "reasoning_summary": ""},
            triage_results=[{"severity": "Critical"}, {"severity": "High"}, {"severity": "Medium"}],
            confidence=70.0,
        )
        result = briefing_node(state)
        assert "Critical: 1" in result["briefing"]
        assert "High: 1" in result["briefing"]
        assert "Medium: 1" in result["briefing"]

"""Tests for the mock data layer."""

from datetime import datetime, timezone

from server.mock_data import (
    generate_alert,
    generate_alert_batch,
    mock_abuseipdb,
    mock_greynoise,
    mock_nvd_cves,
    mock_otx_pulses,
    mock_siem_logs,
    mock_virustotal,
)
from server.models import Alert, AlertStatus, Severity


class TestGenerateAlert:
    def test_returns_alert_instance(self):
        alert = generate_alert()
        assert isinstance(alert, Alert)

    def test_id_format(self):
        alert = generate_alert()
        assert alert.id.startswith("ALERT-")
        assert len(alert.id) == 14  # "ALERT-" + 8 hex chars

    def test_source_ip_is_internal(self):
        for _ in range(20):
            alert = generate_alert()
            first_octet = int(alert.source_ip.split(".")[0])
            assert first_octet in (10, 172, 192)

    def test_severity_is_valid(self):
        for _ in range(20):
            alert = generate_alert()
            assert alert.severity in list(Severity)

    def test_status_defaults_to_new(self):
        alert = generate_alert()
        assert alert.status == AlertStatus.NEW

    def test_custom_timestamp(self):
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        alert = generate_alert(timestamp=ts)
        assert alert.timestamp == ts

    def test_description_is_populated(self):
        alert = generate_alert()
        assert len(alert.description) > 10

    def test_alert_type_is_non_empty(self):
        alert = generate_alert()
        assert len(alert.alert_type) > 0


class TestGenerateAlertBatch:
    def test_returns_correct_count(self):
        batch = generate_alert_batch(10)
        assert len(batch) == 10

    def test_default_count_is_20(self):
        batch = generate_alert_batch()
        assert len(batch) == 20

    def test_sorted_newest_first(self):
        batch = generate_alert_batch(5)
        for i in range(len(batch) - 1):
            assert batch[i].timestamp >= batch[i + 1].timestamp

    def test_unique_ids(self):
        batch = generate_alert_batch(50)
        ids = [a.id for a in batch]
        assert len(ids) == len(set(ids))


class TestMockAbuseIPDB:
    def test_returns_required_keys(self):
        result = mock_abuseipdb("1.2.3.4")
        assert "ip" in result
        assert "abuse_confidence_score" in result
        assert "total_reports" in result
        assert "country_code" in result
        assert "isp" in result

    def test_ip_echoed_back(self):
        result = mock_abuseipdb("192.168.1.1")
        assert result["ip"] == "192.168.1.1"

    def test_score_in_range(self):
        for _ in range(20):
            result = mock_abuseipdb("10.0.0.1")
            assert 0 <= result["abuse_confidence_score"] <= 100


class TestMockVirusTotal:
    def test_returns_required_keys(self):
        result = mock_virustotal("8.8.8.8")
        assert "ip" in result
        assert "malicious" in result
        assert "suspicious" in result
        assert "harmless" in result
        assert "reputation" in result

    def test_ip_echoed_back(self):
        result = mock_virustotal("1.1.1.1")
        assert result["ip"] == "1.1.1.1"


class TestMockOTXPulses:
    def test_returns_required_keys(self):
        result = mock_otx_pulses("10.0.0.1")
        assert "ip" in result
        assert "pulse_count" in result
        assert "pulses" in result
        assert isinstance(result["pulses"], list)

    def test_pulse_count_matches_list_length(self):
        for _ in range(20):
            result = mock_otx_pulses("10.0.0.1")
            assert result["pulse_count"] == len(result["pulses"])

    def test_pulses_have_name_and_tags(self):
        result = mock_otx_pulses("10.0.0.1")
        for pulse in result["pulses"]:
            assert "name" in pulse
            assert "tags" in pulse


class TestMockGreyNoise:
    def test_returns_required_keys(self):
        result = mock_greynoise("10.0.0.1")
        assert "ip" in result
        assert "classification" in result
        assert "noise" in result
        assert "riot" in result

    def test_classification_is_valid(self):
        for _ in range(20):
            result = mock_greynoise("10.0.0.1")
            assert result["classification"] in ("malicious", "benign", "unknown")

    def test_riot_true_only_for_benign(self):
        for _ in range(50):
            result = mock_greynoise("10.0.0.1")
            if result["riot"]:
                assert result["classification"] == "benign"


class TestMockNVDCves:
    def test_returns_list(self):
        result = mock_nvd_cves("brute force")
        assert isinstance(result, list)

    def test_cve_format(self):
        for _ in range(20):
            result = mock_nvd_cves("test")
            for cve in result:
                assert cve["id"].startswith("CVE-")
                assert "cvss" in cve
                assert "severity" in cve

    def test_max_3_results(self):
        for _ in range(50):
            result = mock_nvd_cves("anything")
            assert len(result) <= 3


class TestMockSIEMLogs:
    def test_returns_list(self):
        result = mock_siem_logs("firewall", "last_1h")
        assert isinstance(result, list)

    def test_count_in_range(self):
        for _ in range(20):
            result = mock_siem_logs("siem", "last_1h")
            assert 5 <= len(result) <= 15

    def test_log_has_required_fields(self):
        result = mock_siem_logs("firewall", "last_1h")
        for log in result:
            assert "event" in log
            assert "message" in log
            assert "timestamp" in log
            assert "source" in log
            assert "source_ip" in log

    def test_source_is_echoed(self):
        result = mock_siem_logs("my-source", "last_24h")
        for log in result:
            assert log["source"] == "my-source"

    def test_sorted_newest_first(self):
        result = mock_siem_logs("siem", "last_1h")
        for i in range(len(result) - 1):
            assert result[i]["timestamp"] >= result[i + 1]["timestamp"]

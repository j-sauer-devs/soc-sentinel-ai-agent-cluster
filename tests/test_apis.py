"""Tests for all 5 security API clients.

Each client is tested with mocked requests.get for:
  1. Successful API response
  2. Missing API key (stub/fallback)
  3. Request exception
  4. Cache hit
"""

from unittest.mock import MagicMock, patch

import pytest


# ===================================================================
# AbuseIPDB
# ===================================================================

class TestAbuseIPDB:
    @patch("apis.abuseipdb.os.getenv", return_value="test-key")
    @patch("apis.abuseipdb.requests.get")
    def test_successful_response(self, mock_get, mock_env):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "1.2.3.4",
                "abuseConfidenceScore": 85,
                "totalReports": 42,
                "countryCode": "US",
                "isp": "Evil ISP",
                "domain": "evil.com",
                "isPublic": True,
                "usageType": "Data Center",
            }
        }
        mock_get.return_value = mock_resp

        from apis.abuseipdb import check_ip
        result = check_ip("1.2.3.4")
        assert result["ip"] == "1.2.3.4"
        assert result["abuse_confidence_score"] == 85
        assert result["total_reports"] == 42
        assert result["country_code"] == "US"
        assert result["isp"] == "Evil ISP"

    @patch("apis.abuseipdb.os.getenv", return_value=None)
    def test_missing_key_returns_stub(self, mock_env):
        from apis.abuseipdb import check_ip
        result = check_ip("1.2.3.4")
        assert result["abuse_confidence_score"] == -1
        assert "error" in result

    @patch("apis.abuseipdb.os.getenv", return_value="test-key")
    @patch("apis.abuseipdb.requests.get", side_effect=Exception("Connection timeout"))
    def test_exception_returns_error(self, mock_get, mock_env):
        from apis.abuseipdb import check_ip
        result = check_ip("1.2.3.4")
        assert result["abuse_confidence_score"] == -1
        assert "Connection timeout" in result["error"]

    @patch("apis.abuseipdb.os.getenv", return_value="test-key")
    @patch("apis.abuseipdb.requests.get")
    def test_cache_stores_result(self, mock_get, mock_env):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"data": {"ipAddress": "5.5.5.5", "abuseConfidenceScore": 10, "totalReports": 1}}
        mock_get.return_value = mock_resp

        from apis.abuseipdb import check_ip
        cache = {}
        check_ip("5.5.5.5", cache=cache)
        assert "5.5.5.5" in cache

    @patch("apis.abuseipdb.os.getenv", return_value="test-key")
    @patch("apis.abuseipdb.requests.get")
    def test_cache_hit_skips_request(self, mock_get, mock_env):
        from apis.abuseipdb import check_ip
        cached = {"ip": "5.5.5.5", "abuse_confidence_score": 99}
        cache = {"5.5.5.5": cached}
        result = check_ip("5.5.5.5", cache=cache)
        assert result["abuse_confidence_score"] == 99
        mock_get.assert_not_called()

    def test_explicit_api_key_parameter(self):
        """When api_key is passed directly, env var is not needed."""
        from apis.abuseipdb import check_ip
        with patch("apis.abuseipdb.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {"data": {"ipAddress": "9.9.9.9", "abuseConfidenceScore": 50, "totalReports": 3}}
            mock_get.return_value = mock_resp
            result = check_ip("9.9.9.9", api_key="direct-key")
            assert result["abuse_confidence_score"] == 50
            # Verify the key was passed in headers
            call_args = mock_get.call_args
            assert call_args.kwargs.get("headers", {}).get("Key") == "direct-key" or \
                   call_args[1].get("headers", {}).get("Key") == "direct-key"


# ===================================================================
# GreyNoise
# ===================================================================

class TestGreyNoise:
    @patch("apis.greynoise.os.getenv", return_value="test-key")
    @patch("apis.greynoise.requests.get")
    def test_successful_response(self, mock_get, mock_env):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "classification": "malicious",
            "noise": True,
            "riot": False,
            "name": "Bad Actor",
            "link": "https://viz.greynoise.io/ip/1.2.3.4",
        }
        mock_get.return_value = mock_resp

        from apis.greynoise import check_ip
        result = check_ip("1.2.3.4")
        assert result["ip"] == "1.2.3.4"
        assert result["classification"] == "malicious"
        assert result["noise"] is True
        assert result["riot"] is False

    @patch("apis.greynoise.os.getenv", return_value=None)
    def test_missing_key_returns_stub(self, mock_env):
        from apis.greynoise import check_ip
        cache = {}
        result = check_ip("1.2.3.4", cache=cache)
        assert result["classification"] == "unknown"
        assert result["noise"] is False
        assert "error" in result
        # Stub should be cached
        assert "1.2.3.4" in cache

    @patch("apis.greynoise.os.getenv", return_value="test-key")
    @patch("apis.greynoise.requests.get", side_effect=Exception("Network error"))
    def test_exception_returns_error(self, mock_get, mock_env):
        from apis.greynoise import check_ip
        result = check_ip("1.2.3.4")
        assert result["classification"] == "unknown"
        assert "Network error" in result["error"]

    @patch("apis.greynoise.os.getenv", return_value="test-key")
    @patch("apis.greynoise.requests.get")
    def test_cache_stores_result(self, mock_get, mock_env):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"classification": "benign", "noise": False, "riot": True}
        mock_get.return_value = mock_resp

        from apis.greynoise import check_ip
        cache = {}
        check_ip("5.5.5.5", cache=cache)
        assert "5.5.5.5" in cache

    @patch("apis.greynoise.os.getenv", return_value="test-key")
    @patch("apis.greynoise.requests.get")
    def test_cache_hit_skips_request(self, mock_get, mock_env):
        from apis.greynoise import check_ip
        cached = {"ip": "5.5.5.5", "classification": "benign"}
        cache = {"5.5.5.5": cached}
        result = check_ip("5.5.5.5", cache=cache)
        assert result["classification"] == "benign"
        mock_get.assert_not_called()


# ===================================================================
# OTX — IP Pulses
# ===================================================================

class TestOTXGetIpPulses:
    @patch("apis.otx.os.getenv", return_value="test-key")
    @patch("apis.otx.requests.get")
    def test_successful_response(self, mock_get, mock_env):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "pulse_info": {
                "count": 3,
                "pulses": [
                    {"name": "Pulse 1", "description": "Desc 1", "tags": ["malware"]},
                    {"name": "Pulse 2", "description": "Desc 2", "tags": ["apt"]},
                    {"name": "Pulse 3", "description": None, "tags": []},
                ],
            },
            "reputation": 5,
            "country_name": "Russia",
        }
        mock_get.return_value = mock_resp

        from apis.otx import get_ip_pulses
        result = get_ip_pulses("1.2.3.4")
        assert result["ip"] == "1.2.3.4"
        assert result["pulse_count"] == 3
        assert len(result["pulses"]) == 3
        assert result["reputation"] == 5
        assert result["country"] == "Russia"

    @patch("apis.otx.os.getenv", return_value="test-key")
    @patch("apis.otx.requests.get")
    def test_description_truncated(self, mock_get, mock_env):
        long_desc = "A" * 500
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "pulse_info": {
                "count": 1,
                "pulses": [{"name": "P", "description": long_desc, "tags": []}],
            },
        }
        mock_get.return_value = mock_resp

        from apis.otx import get_ip_pulses
        result = get_ip_pulses("1.2.3.4")
        assert len(result["pulses"][0]["description"]) <= 200

    @patch("apis.otx.os.getenv", return_value="test-key")
    @patch("apis.otx.requests.get")
    def test_max_5_pulses(self, mock_get, mock_env):
        pulses = [{"name": f"P{i}", "description": "", "tags": []} for i in range(10)]
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"pulse_info": {"count": 10, "pulses": pulses}}
        mock_get.return_value = mock_resp

        from apis.otx import get_ip_pulses
        result = get_ip_pulses("1.2.3.4")
        assert len(result["pulses"]) == 5

    @patch("apis.otx.os.getenv", return_value=None)
    def test_missing_key(self, mock_env):
        from apis.otx import get_ip_pulses
        result = get_ip_pulses("1.2.3.4")
        assert result["pulse_count"] == -1
        assert "error" in result

    @patch("apis.otx.os.getenv", return_value="test-key")
    @patch("apis.otx.requests.get", side_effect=Exception("Timeout"))
    def test_exception(self, mock_get, mock_env):
        from apis.otx import get_ip_pulses
        result = get_ip_pulses("1.2.3.4")
        assert result["pulse_count"] == -1

    def test_cache_key_format(self):
        """Cache key should be 'ip:x.x.x.x'."""
        from apis.otx import get_ip_pulses
        cache = {"ip:1.2.3.4": {"ip": "1.2.3.4", "pulse_count": 0, "pulses": []}}
        result = get_ip_pulses("1.2.3.4", cache=cache)
        assert result["pulse_count"] == 0


# ===================================================================
# OTX — Domain Pulses
# ===================================================================

class TestOTXGetDomainPulses:
    @patch("apis.otx.os.getenv", return_value="test-key")
    @patch("apis.otx.requests.get")
    def test_successful_response(self, mock_get, mock_env):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "pulse_info": {
                "count": 2,
                "pulses": [
                    {"name": "Domain Pulse", "description": "Bad domain", "tags": ["phishing"]},
                    {"name": "Domain Pulse 2", "description": "Also bad", "tags": []},
                ],
            },
        }
        mock_get.return_value = mock_resp

        from apis.otx import get_domain_pulses
        result = get_domain_pulses("evil.com")
        assert result["domain"] == "evil.com"
        assert result["pulse_count"] == 2

    @patch("apis.otx.os.getenv", return_value=None)
    def test_missing_key(self, mock_env):
        from apis.otx import get_domain_pulses
        result = get_domain_pulses("evil.com")
        assert result["pulse_count"] == -1
        assert "error" in result

    def test_cache_key_format(self):
        """Cache key should be 'domain:x.com'."""
        from apis.otx import get_domain_pulses
        cache = {"domain:evil.com": {"domain": "evil.com", "pulse_count": 5, "pulses": []}}
        result = get_domain_pulses("evil.com", cache=cache)
        assert result["pulse_count"] == 5

    @patch("apis.otx.os.getenv", return_value="test-key")
    @patch("apis.otx.requests.get", side_effect=Exception("DNS error"))
    def test_exception(self, mock_get, mock_env):
        from apis.otx import get_domain_pulses
        result = get_domain_pulses("evil.com")
        assert result["pulse_count"] == -1


# ===================================================================
# VirusTotal — IP
# ===================================================================

class TestVirusTotalIP:
    @patch("apis.virustotal.os.getenv", return_value="test-key")
    @patch("apis.virustotal.requests.get")
    def test_successful_response(self, mock_get, mock_env):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "harmless": 60,
                        "undetected": 10,
                    },
                    "reputation": -15,
                    "as_owner": "Bad Network Inc",
                    "country": "CN",
                }
            }
        }
        mock_get.return_value = mock_resp

        from apis.virustotal import check_ip
        result = check_ip("1.2.3.4")
        assert result["ip"] == "1.2.3.4"
        assert result["malicious"] == 5
        assert result["suspicious"] == 2
        assert result["harmless"] == 60
        assert result["undetected"] == 10
        assert result["reputation"] == -15
        assert result["as_owner"] == "Bad Network Inc"

    @patch("apis.virustotal.os.getenv", return_value=None)
    def test_missing_key(self, mock_env):
        from apis.virustotal import check_ip
        result = check_ip("1.2.3.4")
        assert result["malicious"] == -1
        assert "error" in result

    @patch("apis.virustotal.os.getenv", return_value="test-key")
    @patch("apis.virustotal.requests.get", side_effect=Exception("Rate limited"))
    def test_exception(self, mock_get, mock_env):
        from apis.virustotal import check_ip
        result = check_ip("1.2.3.4")
        assert result["malicious"] == -1
        assert "Rate limited" in result["error"]

    def test_cache_key_format(self):
        from apis.virustotal import check_ip
        cache = {"ip:1.2.3.4": {"ip": "1.2.3.4", "malicious": 3}}
        result = check_ip("1.2.3.4", cache=cache)
        assert result["malicious"] == 3


# ===================================================================
# VirusTotal — Domain
# ===================================================================

class TestVirusTotalDomain:
    @patch("apis.virustotal.os.getenv", return_value="test-key")
    @patch("apis.virustotal.requests.get")
    def test_successful_response(self, mock_get, mock_env):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 8,
                        "suspicious": 1,
                        "harmless": 50,
                        "undetected": 5,
                    },
                    "reputation": -20,
                    "registrar": "Evil Registrar Inc",
                }
            }
        }
        mock_get.return_value = mock_resp

        from apis.virustotal import check_domain
        result = check_domain("evil.com")
        assert result["domain"] == "evil.com"
        assert result["malicious"] == 8
        assert result["registrar"] == "Evil Registrar Inc"

    @patch("apis.virustotal.os.getenv", return_value=None)
    def test_missing_key(self, mock_env):
        from apis.virustotal import check_domain
        result = check_domain("evil.com")
        assert result["malicious"] == -1

    def test_cache_key_format(self):
        from apis.virustotal import check_domain
        cache = {"domain:evil.com": {"domain": "evil.com", "malicious": 10}}
        result = check_domain("evil.com", cache=cache)
        assert result["malicious"] == 10


# ===================================================================
# NVD
# ===================================================================

class TestNVD:
    @patch("apis.nvd.os.getenv", return_value="test-key")
    @patch("apis.nvd.requests.get")
    def test_successful_response(self, mock_get, mock_env):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "descriptions": [{"lang": "en", "value": "A critical vulnerability"}],
                        "metrics": {
                            "cvssMetricV31": [{
                                "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}
                            }]
                        },
                    }
                }
            ]
        }
        mock_get.return_value = mock_resp

        from apis.nvd import search_cves
        results = search_cves("test")
        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2024-1234"
        assert results[0]["cvss_score"] == 9.8
        assert results[0]["severity"] == "CRITICAL"

    @patch("apis.nvd.os.getenv", return_value="test-key")
    @patch("apis.nvd.requests.get")
    def test_cvss_v30_fallback(self, mock_get, mock_env):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2023-5678",
                    "descriptions": [{"lang": "en", "value": "Medium vuln"}],
                    "metrics": {
                        "cvssMetricV30": [{
                            "cvssData": {"baseScore": 6.5, "baseSeverity": "MEDIUM"}
                        }]
                    },
                }
            }]
        }
        mock_get.return_value = mock_resp

        from apis.nvd import search_cves
        results = search_cves("test")
        assert results[0]["cvss_score"] == 6.5
        assert results[0]["severity"] == "MEDIUM"

    @patch("apis.nvd.os.getenv", return_value="test-key")
    @patch("apis.nvd.requests.get")
    def test_cvss_v2_fallback(self, mock_get, mock_env):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2020-0001",
                    "descriptions": [{"lang": "en", "value": "Old vuln"}],
                    "metrics": {
                        "cvssMetricV2": [{
                            "cvssData": {"baseScore": 5.0},
                            "baseSeverity": "MEDIUM",
                        }]
                    },
                }
            }]
        }
        mock_get.return_value = mock_resp

        from apis.nvd import search_cves
        results = search_cves("test")
        assert results[0]["cvss_score"] == 5.0

    @patch("apis.nvd.os.getenv", return_value="test-key")
    @patch("apis.nvd.requests.get")
    def test_description_truncated(self, mock_get, mock_env):
        long_desc = "X" * 500
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-9999",
                    "descriptions": [{"lang": "en", "value": long_desc}],
                    "metrics": {},
                }
            }]
        }
        mock_get.return_value = mock_resp

        from apis.nvd import search_cves
        results = search_cves("test")
        assert len(results[0]["description"]) <= 300

    @patch("apis.nvd.os.getenv", return_value="test-key")
    @patch("apis.nvd.requests.get")
    def test_max_results(self, mock_get, mock_env):
        vulns = [
            {"cve": {"id": f"CVE-2024-{i}", "descriptions": [{"lang": "en", "value": f"V{i}"}], "metrics": {}}}
            for i in range(10)
        ]
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"vulnerabilities": vulns}
        mock_get.return_value = mock_resp

        from apis.nvd import search_cves
        results = search_cves("test", max_results=3)
        assert len(results) <= 3

    @patch("apis.nvd.os.getenv", return_value=None)
    @patch("apis.nvd.requests.get")
    def test_no_api_key_no_header(self, mock_get, mock_env):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"vulnerabilities": []}
        mock_get.return_value = mock_resp

        from apis.nvd import search_cves
        search_cves("test")
        call_args = mock_get.call_args
        headers = call_args.kwargs.get("headers", {}) if call_args.kwargs else call_args[1].get("headers", {})
        assert "apiKey" not in headers

    @patch("apis.nvd.os.getenv", return_value="test-key")
    @patch("apis.nvd.requests.get", side_effect=Exception("Service unavailable"))
    def test_exception_returns_error(self, mock_get, mock_env):
        from apis.nvd import search_cves
        results = search_cves("test")
        assert len(results) == 1
        assert results[0]["cve_id"] == "ERROR"
        assert "Service unavailable" in results[0]["description"]

    def test_cache_hit(self):
        from apis.nvd import search_cves
        cached = [{"cve_id": "CVE-CACHED", "description": "cached", "cvss_score": 5.0, "severity": "MEDIUM"}]
        cache = {"malware": cached}
        results = search_cves("malware", cache=cache)
        assert results[0]["cve_id"] == "CVE-CACHED"

    @patch("apis.nvd.os.getenv", return_value="test-key")
    @patch("apis.nvd.requests.get")
    def test_english_description_preferred(self, mock_get, mock_env):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-LANG",
                    "descriptions": [
                        {"lang": "es", "value": "Descripcion en español"},
                        {"lang": "en", "value": "English description"},
                    ],
                    "metrics": {},
                }
            }]
        }
        mock_get.return_value = mock_resp

        from apis.nvd import search_cves
        results = search_cves("test")
        assert results[0]["description"] == "English description"

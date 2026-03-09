"""
AbuseIPDB API client.

Checks IP reputation via the AbuseIPDB v2 API.
Docs: https://docs.abuseipdb.com/
"""

import logging
import os

import requests

logger = logging.getLogger(__name__)

_BASE = "https://api.abuseipdb.com/api/v2/check"


def check_ip(ip: str, api_key: str | None = None, cache: dict | None = None) -> dict:
    """Return abuse confidence score and metadata for an IP.

    Returns dict with keys:
        ip, abuse_confidence_score (0-100), total_reports, country_code,
        isp, domain, is_public, usage_type
    Falls back to a stub if API key is missing or request fails.
    """
    if cache is None:
        cache = {}
    if ip in cache:
        logger.debug("AbuseIPDB cache hit for %s", ip)
        return cache[ip]

    key = api_key or os.getenv("ABUSEIPDB_KEY")
    if not key:
        logger.warning("ABUSEIPDB_KEY not set — returning stub for %s", ip)
        return {"ip": ip, "abuse_confidence_score": -1, "error": "ABUSEIPDB_KEY not set"}

    try:
        resp = requests.get(
            _BASE,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        result = {
            "ip": data.get("ipAddress", ip),
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "is_public": data.get("isPublic", True),
            "usage_type": data.get("usageType", ""),
        }
        logger.info("AbuseIPDB: %s -> score=%d, reports=%d", ip, result["abuse_confidence_score"], result["total_reports"])
    except Exception as e:
        logger.error("AbuseIPDB request failed for %s: %s", ip, e)
        result = {"ip": ip, "abuse_confidence_score": -1, "error": str(e)}

    cache[ip] = result
    return result

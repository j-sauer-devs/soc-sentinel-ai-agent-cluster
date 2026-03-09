"""
AlienVault OTX API client.

Queries OTX for pulse (threat intelligence) data on IPs and domains.
Docs: https://otx.alienvault.com/api
"""

import logging
import os

import requests

logger = logging.getLogger(__name__)

_BASE = "https://otx.alienvault.com/api/v1"


def get_ip_pulses(ip: str, api_key: str | None = None, cache: dict | None = None) -> dict:
    """Return OTX pulse data for an IP address.

    Returns dict with keys:
        ip, pulse_count, pulses (list of {name, description, tags}),
        reputation, country
    """
    if cache is None:
        cache = {}
    cache_key = f"ip:{ip}"
    if cache_key in cache:
        logger.debug("OTX cache hit for ip:%s", ip)
        return cache[cache_key]

    key = api_key or os.getenv("OTX_KEY")
    if not key:
        logger.warning("OTX_KEY not set — returning stub for ip %s", ip)
        return {"ip": ip, "pulse_count": -1, "error": "OTX_KEY not set"}

    try:
        resp = requests.get(
            f"{_BASE}/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": key},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        pulses = data.get("pulse_info", {}).get("pulses", [])
        result = {
            "ip": ip,
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "pulses": [
                {
                    "name": p.get("name", ""),
                    "description": (p.get("description", "") or "")[:200],
                    "tags": p.get("tags", []),
                }
                for p in pulses[:5]  # top 5 pulses
            ],
            "reputation": data.get("reputation", 0),
            "country": data.get("country_name", ""),
        }
        logger.info("OTX IP: %s -> %d pulses", ip, result["pulse_count"])
    except Exception as e:
        logger.error("OTX IP request failed for %s: %s", ip, e)
        result = {"ip": ip, "pulse_count": -1, "error": str(e)}

    cache[cache_key] = result
    return result


def get_domain_pulses(domain: str, api_key: str | None = None, cache: dict | None = None) -> dict:
    """Return OTX pulse data for a domain."""
    if cache is None:
        cache = {}
    cache_key = f"domain:{domain}"
    if cache_key in cache:
        logger.debug("OTX cache hit for domain:%s", domain)
        return cache[cache_key]

    key = api_key or os.getenv("OTX_KEY")
    if not key:
        logger.warning("OTX_KEY not set — returning stub for domain %s", domain)
        return {"domain": domain, "pulse_count": -1, "error": "OTX_KEY not set"}

    try:
        resp = requests.get(
            f"{_BASE}/indicators/domain/{domain}/general",
            headers={"X-OTX-API-KEY": key},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        pulses = data.get("pulse_info", {}).get("pulses", [])
        result = {
            "domain": domain,
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "pulses": [
                {
                    "name": p.get("name", ""),
                    "description": (p.get("description", "") or "")[:200],
                    "tags": p.get("tags", []),
                }
                for p in pulses[:5]
            ],
        }
        logger.info("OTX domain: %s -> %d pulses", domain, result["pulse_count"])
    except Exception as e:
        logger.error("OTX domain request failed for %s: %s", domain, e)
        result = {"domain": domain, "pulse_count": -1, "error": str(e)}

    cache[cache_key] = result
    return result

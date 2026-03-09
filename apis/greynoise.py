"""
GreyNoise API client.

Queries GreyNoise Community API for IP classification.
Docs: https://docs.greynoise.io/reference/get_v3-community-ip
"""

import logging
import os

import requests

logger = logging.getLogger(__name__)

_BASE = "https://api.greynoise.io/v3/community"


def check_ip(ip: str, api_key: str | None = None, cache: dict | None = None) -> dict:
    """Return GreyNoise classification for an IP.

    Returns dict with keys:
        ip, classification (benign|malicious|unknown), noise (bool),
        riot (bool), name, link
    Falls back gracefully if GREYNOISE_KEY is not set.
    """
    if cache is None:
        cache = {}
    if ip in cache:
        logger.debug("GreyNoise cache hit for %s", ip)
        return cache[ip]

    key = api_key or os.getenv("GREYNOISE_KEY")
    if not key:
        logger.warning("GREYNOISE_KEY not set — returning stub for %s", ip)
        # Graceful stub when key is missing
        result = {
            "ip": ip,
            "classification": "unknown",
            "noise": False,
            "riot": False,
            "name": "",
            "link": "",
            "error": "GREYNOISE_KEY not set — returning stub",
        }
        cache[ip] = result
        return result

    try:
        resp = requests.get(
            f"{_BASE}/{ip}",
            headers={"key": key},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        result = {
            "ip": ip,
            "classification": data.get("classification", "unknown"),
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "name": data.get("name", ""),
            "link": data.get("link", ""),
        }
        logger.info("GreyNoise: %s -> classification=%s, noise=%s", ip, result["classification"], result["noise"])
    except Exception as e:
        logger.error("GreyNoise request failed for %s: %s", ip, e)
        result = {
            "ip": ip,
            "classification": "unknown",
            "noise": False,
            "error": str(e),
        }

    cache[ip] = result
    return result

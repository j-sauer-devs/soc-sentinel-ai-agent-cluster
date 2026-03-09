"""Alert REST endpoints."""

from __future__ import annotations

import json
import logging
import os

from fastapi import APIRouter
from openai import OpenAI

from server.mock_data import generate_alert_batch
from server.models import Alert, SummarizeResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

# In-memory alert store (seeded on import)
_alerts: list[Alert] = generate_alert_batch(20)


def get_alerts_store() -> list[Alert]:
    """Access the shared alert list (used by WebSocket too)."""
    return _alerts


@router.get("", response_model=list[Alert])
async def list_alerts():
    """Return all current alerts, newest first."""
    return sorted(_alerts, key=lambda a: a.timestamp, reverse=True)


@router.post("/{alert_id}/summarize", response_model=SummarizeResponse)
async def summarize_alert(alert_id: str):
    """Generate a TL;DR summary of an alert for non-technical stakeholders."""
    logger.info("Summarize request for alert_id=%s", alert_id)
    alert = next((a for a in _alerts if a.id == alert_id), None)
    if alert is None:
        logger.warning("Alert %s not found for summarization", alert_id)
        return SummarizeResponse(alert_id=alert_id, summary="Alert not found.")

    # Try K2 Think for summarization; fall back to a template
    try:
        client = OpenAI(
            api_key=os.getenv("K2_API_KEY", ""),
            base_url=os.getenv("K2_BASE_URL", "https://api.k2think.ai/v1"),
        )
        model = os.getenv("K2_MODEL", "MBZUAI-IFM/K2-Think-v2")

        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a security analyst writing a brief, non-technical summary "
                        "of a security alert for business stakeholders. Keep it under 3 sentences. "
                        "Explain the risk in plain language and suggest immediate next steps."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(alert.model_dump(), default=str),
                },
            ],
            max_tokens=300,
        )
        summary = response.choices[0].message.content or "Unable to generate summary."
        logger.info("K2 Think summarization succeeded for alert %s", alert_id)
    except Exception as e:
        logger.warning("K2 Think summarization failed for alert %s: %s — using template fallback", alert_id, e)
        # Fallback: template-based summary
        severity_text = {
            "Critical": "an urgent, critical-severity",
            "High": "a high-severity",
            "Medium": "a medium-severity",
            "Low": "a low-priority",
            "Noise": "a noise-level",
        }.get(alert.severity.value, "a")
        summary = (
            f"This is {severity_text} alert involving {alert.alert_type.lower()} "
            f"from {alert.source_ip}. {alert.description} "
            f"Recommended action: investigate the source and consider blocking the IP."
        )

    return SummarizeResponse(alert_id=alert_id, summary=summary)

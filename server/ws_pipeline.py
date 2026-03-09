"""WebSocket endpoint for pipeline Chain of Thought streaming.

Streams per-node execution events as the LangGraph pipeline runs,
giving the frontend a live transparency log.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from server.mock_data import (
    mock_abuseipdb,
    mock_greynoise,
    mock_nvd_cves,
    mock_otx_pulses,
    mock_virustotal,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ws-pipeline"])


async def _emit(ws: WebSocket, node: str, status: str, **kwargs: Any):
    """Send a pipeline event to the client."""
    msg = {
        "node": node,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **kwargs,
    }
    await ws.send_text(json.dumps(msg, default=str))


@router.websocket("/ws/pipeline")
async def pipeline_stream(ws: WebSocket):
    """Accept alert data via WebSocket, simulate pipeline execution with events.

    Client sends: {"alerts": [...]}
    Server streams: node status events, then final result.
    """
    await ws.accept()
    logger.info("WebSocket /ws/pipeline: client connected")

    try:
        raw = await ws.receive_text()
        data = json.loads(raw)
        alerts = data.get("alerts", [])
        logger.info("Pipeline started with %d alerts", len(alerts))

        if not alerts:
            await _emit(ws, "system", "error", message="No alerts provided")
            await ws.close()
            return

        # --- Commander ---
        await _emit(ws, "commander", "running", step="Routing alerts to specialist agents...")
        await asyncio.sleep(random.uniform(0.5, 1.0))
        await _emit(ws, "commander", "done", step=f"Dispatched {len(alerts)} alerts to Triage, Threat Hunter, Forensics")

        # --- Parallel specialists (simulate with sequential events) ---
        for alert in alerts:
            alert_id = alert.get("id", alert.get("alert_id", "unknown"))
            src_ip = alert.get("source_ip", "0.0.0.0")

            # Triage
            await _emit(ws, "triage", "running", step=f"Checking IP reputation for {src_ip}...", alert_id=alert_id)
            await asyncio.sleep(random.uniform(0.3, 0.8))
            abuse = mock_abuseipdb(src_ip)
            gn = mock_greynoise(src_ip)
            severity = "Critical" if abuse["abuse_confidence_score"] > 80 else "High" if abuse["abuse_confidence_score"] > 50 else "Medium"
            await _emit(ws, "triage", "done",
                        step=f"AbuseIPDB score: {abuse['abuse_confidence_score']}, GreyNoise: {gn['classification']} -> Severity: {severity}",
                        alert_id=alert_id, severity=severity)

            # Threat Hunter
            await _emit(ws, "threat_hunter", "running", step=f"Enriching IOCs for {src_ip}...", alert_id=alert_id)
            await asyncio.sleep(random.uniform(0.3, 0.8))
            otx = mock_otx_pulses(src_ip)
            vt = mock_virustotal(src_ip)
            apt_note = f"APT indicators found in {otx['pulse_count']} pulses" if otx["pulse_count"] > 2 else "No APT indicators"
            await _emit(ws, "threat_hunter", "done",
                        step=f"OTX: {otx['pulse_count']} pulses, VT: {vt['malicious']} malicious. {apt_note}",
                        alert_id=alert_id)

            # Forensics
            await _emit(ws, "forensics", "running", step=f"Reconstructing kill chain for {alert_id}...", alert_id=alert_id)
            await asyncio.sleep(random.uniform(0.3, 0.8))
            cves = mock_nvd_cves(alert.get("alert_type", ""))
            cve_note = f"Found {len(cves)} related CVEs" if cves else "No related CVEs"
            await _emit(ws, "forensics", "done",
                        step=f"Kill chain mapped. {cve_note}. Blast radius: {'Significant' if severity == 'Critical' else 'Limited'}",
                        alert_id=alert_id)

        # --- Oversight ---
        await _emit(ws, "oversight", "running", step="K2 Think analyzing all findings for conflicts...")
        await asyncio.sleep(random.uniform(1.0, 2.0))

        confidence = random.randint(60, 95)
        verdict = "THREAT" if confidence > 75 else "SUSPICIOUS"
        reasoning = (
            "Step 1: Cross-referenced triage severity with threat hunter findings.\n"
            f"Step 2: Verified {len(alerts)} alerts for consistency.\n"
            "Step 3: Checked for hallucinated CVE IDs — none found.\n"
            "Step 4: Validated MITRE ATT&CK technique mappings.\n"
            f"Conclusion: {verdict} with {confidence}% confidence."
        )
        await _emit(ws, "oversight", "done",
                    step=f"Verdict: {verdict}, Confidence: {confidence}%",
                    reasoning=reasoning, verdict=verdict, confidence=confidence)

        # --- Briefing ---
        await _emit(ws, "briefing", "running", step="Generating final briefing...")
        await asyncio.sleep(random.uniform(0.5, 1.0))
        await _emit(ws, "briefing", "done",
                    step="Briefing complete",
                    briefing=f"SOC Sentinel processed {len(alerts)} alerts. Verdict: {verdict}. Confidence: {confidence}%.")

        await _emit(ws, "system", "complete", message="Pipeline execution finished")
        logger.info("Pipeline completed: verdict=%s, confidence=%d%%", verdict, confidence)

    except WebSocketDisconnect:
        logger.info("WebSocket /ws/pipeline: client disconnected")
    except Exception as e:
        logger.error("WebSocket /ws/pipeline error: %s", e)
        try:
            await _emit(ws, "system", "error", message=str(e))
            await ws.close()
        except Exception:
            pass

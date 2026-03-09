"""Pipeline trigger endpoint — runs the LangGraph multi-agent pipeline."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter

from server.models import PipelineRequest, PipelineResult

router = APIRouter(prefix="/api/pipeline", tags=["pipeline"])


@router.post("/run", response_model=PipelineResult)
async def run_pipeline(req: PipelineRequest):
    """Trigger the full LangGraph SOC Sentinel pipeline on a batch of alerts.

    Imports the compiled graph at call time to avoid circular imports
    and heavy module-level loading.
    """
    from graph.graph import app as langgraph_app

    initial_state: dict[str, Any] = {
        "alerts": req.alerts,
        "triage_results": [],
        "enrichment_results": [],
        "forensics_results": [],
        "oversight_verdict": {},
        "confidence": 0.0,
        "briefing": "",
        "verification_alerts": [],
        "iteration_count": 0,
    }

    # Run the synchronous LangGraph pipeline in a thread
    result = await asyncio.to_thread(langgraph_app.invoke, initial_state)

    return PipelineResult(
        alerts=result.get("alerts", []),
        triage_results=result.get("triage_results", []),
        enrichment_results=result.get("enrichment_results", []),
        forensics_results=result.get("forensics_results", []),
        oversight_verdict=result.get("oversight_verdict", {}),
        confidence=result.get("confidence", 0.0),
        briefing=result.get("briefing", ""),
    )

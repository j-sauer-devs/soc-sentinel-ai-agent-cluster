"""Chat copilot REST endpoint."""

from __future__ import annotations

import logging

from fastapi import APIRouter

from server.chat_service import chat
from server.models import ChatRequest, ChatResponse, ToolCall

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/chat", tags=["chat"])


@router.post("", response_model=ChatResponse)
async def chat_endpoint(req: ChatRequest):
    """Send a message to the SOC Sentinel copilot (K2 Think)."""
    logger.info("Chat endpoint: %d messages received", len(req.messages))
    messages = [{"role": m.role, "content": m.content} for m in req.messages]

    result = chat(messages=messages, pending_approval=req.pending_approval)

    tool_calls = None
    if result.get("tool_calls"):
        tool_calls = [
            ToolCall(name=tc["name"], arguments=tc["arguments"], result=tc.get("result"))
            for tc in result["tool_calls"]
        ]

    return ChatResponse(
        reply=result["reply"],
        reasoning=result.get("reasoning"),
        tool_calls=tool_calls,
        requires_approval=result.get("requires_approval"),
    )

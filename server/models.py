"""Pydantic models for the SOC Sentinel API."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NOISE = "Noise"


class AlertStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Alert(BaseModel):
    id: str
    source_ip: str
    dest_ip: str
    alert_type: str
    severity: Severity
    description: str
    timestamp: datetime
    status: AlertStatus = AlertStatus.NEW


class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any]
    result: Any | None = None


class ChatMessage(BaseModel):
    role: str  # "user" | "assistant" | "system"
    content: str
    reasoning: str | None = None
    tool_calls: list[ToolCall] | None = None


class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    pending_approval: dict[str, Any] | None = None


class ChatResponse(BaseModel):
    reply: str
    reasoning: str | None = None
    tool_calls: list[ToolCall] | None = None
    requires_approval: dict[str, Any] | None = None


class SummarizeResponse(BaseModel):
    alert_id: str
    summary: str


class PipelineRequest(BaseModel):
    alerts: list[dict[str, Any]]


class PipelineResult(BaseModel):
    alerts: list[dict[str, Any]]
    triage_results: list[dict[str, Any]]
    enrichment_results: list[dict[str, Any]]
    forensics_results: list[dict[str, Any]]
    oversight_verdict: dict[str, Any]
    confidence: float
    briefing: str

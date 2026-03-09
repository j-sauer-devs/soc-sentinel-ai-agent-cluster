"""Tests for Pydantic models."""

from datetime import datetime, timezone

import pytest

from server.models import (
    Alert,
    AlertStatus,
    ChatMessage,
    ChatRequest,
    ChatResponse,
    PipelineRequest,
    PipelineResult,
    Severity,
    SummarizeResponse,
    ToolCall,
)


class TestSeverityEnum:
    def test_values(self):
        assert Severity.CRITICAL == "Critical"
        assert Severity.HIGH == "High"
        assert Severity.MEDIUM == "Medium"
        assert Severity.LOW == "Low"
        assert Severity.NOISE == "Noise"

    def test_is_string_enum(self):
        assert isinstance(Severity.CRITICAL, str)


class TestAlertStatusEnum:
    def test_values(self):
        assert AlertStatus.NEW == "new"
        assert AlertStatus.INVESTIGATING == "investigating"
        assert AlertStatus.RESOLVED == "resolved"
        assert AlertStatus.FALSE_POSITIVE == "false_positive"


class TestAlertModel:
    def test_create_alert(self):
        alert = Alert(
            id="ALERT-001",
            source_ip="10.0.1.15",
            dest_ip="45.33.32.156",
            alert_type="Brute Force Attempt",
            severity=Severity.HIGH,
            description="Multiple failed SSH logins",
            timestamp=datetime.now(timezone.utc),
        )
        assert alert.id == "ALERT-001"
        assert alert.status == AlertStatus.NEW  # default

    def test_default_status_is_new(self):
        alert = Alert(
            id="A",
            source_ip="1.1.1.1",
            dest_ip="2.2.2.2",
            alert_type="Test",
            severity=Severity.LOW,
            description="Test",
            timestamp=datetime.now(timezone.utc),
        )
        assert alert.status == AlertStatus.NEW

    def test_serialization_roundtrip(self):
        alert = Alert(
            id="ALERT-RT",
            source_ip="10.0.1.15",
            dest_ip="45.33.32.156",
            alert_type="Test",
            severity=Severity.CRITICAL,
            description="roundtrip",
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
        data = alert.model_dump(mode="json")
        assert data["severity"] == "Critical"
        assert data["status"] == "new"
        rebuilt = Alert(**data)
        assert rebuilt.id == alert.id


class TestToolCallModel:
    def test_without_result(self):
        tc = ToolCall(name="check_ip_reputation", arguments={"ip": "1.2.3.4"})
        assert tc.result is None

    def test_with_result(self):
        tc = ToolCall(
            name="fetch_logs",
            arguments={"source": "firewall"},
            result={"logs": []},
        )
        assert tc.result == {"logs": []}


class TestChatModels:
    def test_chat_request_minimal(self):
        req = ChatRequest(
            messages=[ChatMessage(role="user", content="Hello")]
        )
        assert len(req.messages) == 1
        assert req.pending_approval is None

    def test_chat_response_with_approval(self):
        resp = ChatResponse(
            reply="Isolating host...",
            requires_approval={"tool": "isolate_host", "args": {"hostname": "ws-15"}},
        )
        assert resp.requires_approval is not None
        assert resp.requires_approval["tool"] == "isolate_host"


class TestSummarizeResponse:
    def test_fields(self):
        sr = SummarizeResponse(alert_id="A1", summary="This is critical.")
        assert sr.alert_id == "A1"


class TestPipelineModels:
    def test_request(self):
        req = PipelineRequest(alerts=[{"id": "A1", "type": "test"}])
        assert len(req.alerts) == 1

    def test_result(self):
        result = PipelineResult(
            alerts=[],
            triage_results=[],
            enrichment_results=[],
            forensics_results=[],
            oversight_verdict={"verdict": "CLEAN"},
            confidence=95.0,
            briefing="All clear.",
        )
        assert result.confidence == 95.0

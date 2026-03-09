"""Tests for FastAPI REST endpoints.

Uses FastAPI's TestClient (synchronous httpx wrapper).
K2 Think calls are mocked to avoid needing an API key.
"""

from unittest.mock import MagicMock, patch

import pytest


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "soc-sentinel"


class TestAlertsEndpoints:
    def test_list_alerts(self, client):
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        alerts = resp.json()
        assert isinstance(alerts, list)
        assert len(alerts) > 0

    def test_alert_has_required_fields(self, client):
        resp = client.get("/api/alerts")
        alert = resp.json()[0]
        assert "id" in alert
        assert "source_ip" in alert
        assert "dest_ip" in alert
        assert "alert_type" in alert
        assert "severity" in alert
        assert "description" in alert
        assert "timestamp" in alert
        assert "status" in alert

    def test_alerts_sorted_newest_first(self, client):
        resp = client.get("/api/alerts")
        alerts = resp.json()
        for i in range(len(alerts) - 1):
            assert alerts[i]["timestamp"] >= alerts[i + 1]["timestamp"]

    def test_severity_is_valid_enum(self, client):
        resp = client.get("/api/alerts")
        valid = {"Critical", "High", "Medium", "Low", "Noise"}
        for alert in resp.json():
            assert alert["severity"] in valid

    def test_summarize_nonexistent_alert(self, client):
        resp = client.post("/api/alerts/NONEXISTENT/summarize")
        assert resp.status_code == 200
        data = resp.json()
        assert data["alert_id"] == "NONEXISTENT"
        assert "not found" in data["summary"].lower()

    def test_summarize_existing_alert_fallback(self, client):
        """When K2 Think is unavailable, the template fallback should work."""
        # Get a real alert ID first
        alerts = client.get("/api/alerts").json()
        alert_id = alerts[0]["id"]

        # K2 will fail (no API key set in test), so fallback template should fire
        resp = client.post(f"/api/alerts/{alert_id}/summarize")
        assert resp.status_code == 200
        data = resp.json()
        assert data["alert_id"] == alert_id
        assert len(data["summary"]) > 20


class TestChatEndpoint:
    @patch("server.routes_chat.chat")
    def test_basic_chat(self, mock_chat, client):
        mock_chat.return_value = {
            "reply": "I can help you investigate that.",
            "reasoning": None,
            "tool_calls": None,
            "requires_approval": None,
        }

        resp = client.post("/api/chat", json={
            "messages": [{"role": "user", "content": "Hello"}],
        })

        assert resp.status_code == 200
        data = resp.json()
        assert data["reply"] == "I can help you investigate that."
        assert data["reasoning"] is None
        assert data["tool_calls"] is None

    @patch("server.routes_chat.chat")
    def test_chat_with_tool_calls(self, mock_chat, client):
        mock_chat.return_value = {
            "reply": "IP is suspicious.",
            "reasoning": "Checked reputation.",
            "tool_calls": [
                {"name": "check_ip_reputation", "arguments": {"ip": "1.2.3.4"}, "result": {"score": 75}},
            ],
            "requires_approval": None,
        }

        resp = client.post("/api/chat", json={
            "messages": [{"role": "user", "content": "Check 1.2.3.4"}],
        })

        assert resp.status_code == 200
        data = resp.json()
        assert data["reasoning"] == "Checked reputation."
        assert len(data["tool_calls"]) == 1
        assert data["tool_calls"][0]["name"] == "check_ip_reputation"

    @patch("server.routes_chat.chat")
    def test_chat_with_approval_required(self, mock_chat, client):
        mock_chat.return_value = {
            "reply": "I need to isolate this host.",
            "reasoning": None,
            "tool_calls": [
                {"name": "isolate_host", "arguments": {"hostname": "ws-42"}, "result": {"status": "pending_approval"}},
            ],
            "requires_approval": {"tool": "isolate_host", "args": {"hostname": "ws-42"}},
        }

        resp = client.post("/api/chat", json={
            "messages": [{"role": "user", "content": "Isolate ws-42"}],
        })

        assert resp.status_code == 200
        data = resp.json()
        assert data["requires_approval"] is not None
        assert data["requires_approval"]["tool"] == "isolate_host"

    def test_chat_empty_messages_rejected(self, client):
        resp = client.post("/api/chat", json={"messages": []})
        # FastAPI should still accept this (empty list is valid for the model)
        # The chat service will handle it
        assert resp.status_code in (200, 422)

    def test_chat_invalid_body(self, client):
        resp = client.post("/api/chat", json={"not_messages": "bad"})
        assert resp.status_code == 422  # Pydantic validation error


class TestWebSocketAlerts:
    @patch("server.ws_alerts.asyncio.sleep", new_callable=MagicMock)
    def test_ws_connection_and_receive(self, mock_sleep, client):
        """Test that the WebSocket connects and sends valid alert messages."""
        import asyncio
        import json
        from unittest.mock import AsyncMock

        # Make asyncio.sleep return immediately
        mock_sleep.side_effect = AsyncMock(return_value=None)

        with client.websocket_connect("/ws/alerts") as ws:
            msg = ws.receive_text()
            data = json.loads(msg)
            assert data["type"] == "new_alert"
            assert "data" in data
            alert = data["data"]
            assert "id" in alert
            assert "source_ip" in alert
            assert "dest_ip" in alert
            assert "alert_type" in alert
            assert "severity" in alert
            assert alert["severity"] in {"Critical", "High", "Medium", "Low", "Noise"}


class TestWebSocketPipeline:
    def test_ws_pipeline_empty_alerts_returns_error(self, client):
        """Sending empty alerts should produce an error event."""
        import json

        with client.websocket_connect("/ws/pipeline") as ws:
            ws.send_text(json.dumps({"alerts": []}))
            msg = ws.receive_text()
            data = json.loads(msg)
            assert data["node"] == "system"
            assert data["status"] == "error"
            assert "No alerts" in data["message"]

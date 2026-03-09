"""Integration tests spanning multiple layers.

Tests chat→tool→response flows and WebSocket message delivery.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Chat → Tool → Response integration
# ---------------------------------------------------------------------------

class TestChatToolFlow:
    """End-to-end chat service tests with mocked K2 Think."""

    @patch("server.chat_service._get_client")
    def test_chat_no_tools(self, mock_get_client):
        """Simple chat without tool calls."""
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices = [MagicMock()]
        mock_resp.choices[0].message.content = "I can help you with that."
        mock_client.chat.completions.create.return_value = mock_resp
        mock_get_client.return_value = mock_client

        from server.chat_service import chat
        result = chat([{"role": "user", "content": "Hello"}])
        assert result["reply"] == "I can help you with that."
        assert result["requires_approval"] is None

    @patch("server.chat_service._get_client")
    def test_chat_with_fetch_logs_tool(self, mock_get_client):
        """Chat triggers fetch_logs tool and loops back with result."""
        mock_client = MagicMock()

        # First call: K2 requests a tool
        tool_call_response = MagicMock()
        tool_call_response.choices = [MagicMock()]
        tool_call_response.choices[0].message.content = (
            'Let me check the logs.\n\n```tool_call\n'
            '{"name": "fetch_logs", "arguments": {"source": "firewall"}}\n```'
        )

        # Second call: K2 summarizes the result
        summary_response = MagicMock()
        summary_response.choices = [MagicMock()]
        summary_response.choices[0].message.content = "Found 5 relevant log entries."

        mock_client.chat.completions.create.side_effect = [
            tool_call_response,
            summary_response,
        ]
        mock_get_client.return_value = mock_client

        from server.chat_service import chat
        result = chat([{"role": "user", "content": "Show me firewall logs"}])
        assert result["reply"] == "Found 5 relevant log entries."
        assert result["tool_calls"] is not None
        assert len(result["tool_calls"]) >= 1
        assert result["tool_calls"][0]["name"] == "fetch_logs"

    @patch("server.chat_service._get_client")
    def test_isolate_host_returns_pending_approval(self, mock_get_client):
        """isolate_host tool should return pending_approval instead of executing."""
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices = [MagicMock()]
        mock_resp.choices[0].message.content = (
            'I need to isolate this host.\n\n```tool_call\n'
            '{"name": "isolate_host", "arguments": {"hostname": "ws-42"}}\n```'
        )
        mock_client.chat.completions.create.return_value = mock_resp
        mock_get_client.return_value = mock_client

        from server.chat_service import chat
        result = chat([{"role": "user", "content": "Isolate ws-42"}])
        assert result["requires_approval"] is not None
        assert result["requires_approval"]["tool"] == "isolate_host"
        assert result["requires_approval"]["args"]["hostname"] == "ws-42"

    @patch("server.chat_service._get_client")
    def test_approval_flow_confirmed(self, mock_get_client):
        """Approving isolate_host should call confirm_isolate_host and append tool result to messages."""
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices = [MagicMock()]
        mock_resp.choices[0].message.content = "Host ws-42 has been isolated successfully."
        mock_client.chat.completions.create.return_value = mock_resp
        mock_get_client.return_value = mock_client

        from server.chat_service import chat
        messages = [{"role": "user", "content": "Isolate ws-42"}]
        approval = {"tool": "isolate_host", "args": {"hostname": "ws-42"}, "approved": True}
        result = chat(messages, pending_approval=approval)

        # The approval flow appends a tool result message, then K2 responds with final answer
        assert result["reply"] is not None
        assert "isolated" in result["reply"].lower()
        # Verify that the confirm_isolate_host result was appended to messages
        assert any("APPROVED" in m["content"] for m in messages if m["role"] == "user")


# ---------------------------------------------------------------------------
# WebSocket Alert Delivery
# ---------------------------------------------------------------------------

class TestWebSocketAlertDelivery:
    """Tests that /ws/alerts actually delivers valid alert messages."""

    @patch("server.ws_alerts.asyncio.sleep", new_callable=AsyncMock, return_value=None)
    def test_receives_new_alert_message(self, mock_sleep, client):
        """WebSocket should send a new_alert message with valid structure."""
        with client.websocket_connect("/ws/alerts") as ws:
            msg = ws.receive_text()
            data = json.loads(msg)
            assert data["type"] == "new_alert"
            assert "data" in data

    @patch("server.ws_alerts.asyncio.sleep", new_callable=AsyncMock, return_value=None)
    def test_alert_has_required_fields(self, mock_sleep, client):
        """Alert data should contain all required fields."""
        with client.websocket_connect("/ws/alerts") as ws:
            msg = ws.receive_text()
            data = json.loads(msg)
            alert = data["data"]
            required_fields = ["id", "source_ip", "dest_ip", "alert_type", "severity", "description", "timestamp"]
            for field in required_fields:
                assert field in alert, f"Missing field: {field}"

    @patch("server.ws_alerts.asyncio.sleep", new_callable=AsyncMock, return_value=None)
    def test_alert_severity_valid(self, mock_sleep, client):
        """Alert severity should be a valid enum value."""
        valid_severities = {"Critical", "High", "Medium", "Low", "Noise"}
        with client.websocket_connect("/ws/alerts") as ws:
            msg = ws.receive_text()
            data = json.loads(msg)
            assert data["data"]["severity"] in valid_severities


# ---------------------------------------------------------------------------
# WebSocket Pipeline Flow
# ---------------------------------------------------------------------------

class TestWebSocketPipelineFlow:
    @patch("server.ws_pipeline.asyncio.sleep", new_callable=AsyncMock, return_value=None)
    def test_pipeline_sends_events_in_order(self, mock_sleep, client):
        """Pipeline should emit events from commander through to system complete."""
        sample_alert = {
            "id": "ALERT-INT-001",
            "source_ip": "185.220.101.34",
            "dest_ip": "10.0.1.42",
            "alert_type": "Suspicious Outbound Connection",
            "description": "C2 beaconing pattern detected",
            "severity": "High",
        }

        with client.websocket_connect("/ws/pipeline") as ws:
            ws.send_text(json.dumps({"alerts": [sample_alert]}))

            # Collect all events
            events = []
            try:
                while True:
                    msg = ws.receive_text()
                    event = json.loads(msg)
                    events.append(event)
                    if event.get("node") == "system" and event.get("status") in ("complete", "error"):
                        break
            except Exception:
                pass

            assert len(events) > 0
            # First event should be commander
            assert events[0]["node"] == "commander"
            # Last event should be system complete
            assert events[-1]["node"] == "system"
            assert events[-1]["status"] == "complete"

    @patch("server.ws_pipeline.asyncio.sleep", new_callable=AsyncMock, return_value=None)
    def test_pipeline_includes_all_nodes(self, mock_sleep, client):
        """Pipeline should include events from all major nodes."""
        sample_alert = {
            "id": "ALERT-INT-002",
            "source_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "alert_type": "Brute Force",
            "description": "Multiple failed logins",
            "severity": "Medium",
        }

        with client.websocket_connect("/ws/pipeline") as ws:
            ws.send_text(json.dumps({"alerts": [sample_alert]}))

            nodes_seen = set()
            try:
                while True:
                    msg = ws.receive_text()
                    event = json.loads(msg)
                    nodes_seen.add(event.get("node"))
                    if event.get("node") == "system":
                        break
            except Exception:
                pass

            expected_nodes = {"commander", "triage", "threat_hunter", "forensics", "oversight", "briefing", "system"}
            assert expected_nodes.issubset(nodes_seen), f"Missing nodes: {expected_nodes - nodes_seen}"

    def test_empty_alerts_returns_error(self, client):
        """Sending empty alerts should produce an error event."""
        with client.websocket_connect("/ws/pipeline") as ws:
            ws.send_text(json.dumps({"alerts": []}))
            msg = ws.receive_text()
            data = json.loads(msg)
            assert data["node"] == "system"
            assert data["status"] == "error"
            assert "No alerts" in data["message"]

"""Tests for the chat service (K2 Think integration).

These tests mock the OpenAI client to avoid requiring a live API key.
"""

from unittest.mock import MagicMock, patch

import pytest

from server.chat_service import (
    _build_system_prompt,
    _extract_tool_call,
    chat,
)


class TestBuildSystemPrompt:
    def test_contains_tool_names(self):
        prompt = _build_system_prompt()
        assert "fetch_logs" in prompt
        assert "check_ip_reputation" in prompt
        assert "isolate_host" in prompt

    def test_contains_system_identity(self):
        prompt = _build_system_prompt()
        assert "SOC Sentinel" in prompt


class TestExtractToolCall:
    def test_valid_tool_call(self):
        text = 'Some preamble\n```tool_call\n{"name": "check_ip_reputation", "arguments": {"ip": "1.2.3.4"}}\n```\nSome postamble'
        result = _extract_tool_call(text)
        assert result is not None
        assert result["name"] == "check_ip_reputation"
        assert result["arguments"]["ip"] == "1.2.3.4"

    def test_no_tool_call(self):
        text = "Just a regular response without any tool call."
        result = _extract_tool_call(text)
        assert result is None

    def test_invalid_json_in_tool_call(self):
        text = '```tool_call\n{not valid json}\n```'
        result = _extract_tool_call(text)
        assert result is None

    def test_multiple_tool_calls_returns_first(self):
        text = (
            '```tool_call\n{"name": "first", "arguments": {}}\n```\n'
            '```tool_call\n{"name": "second", "arguments": {}}\n```'
        )
        result = _extract_tool_call(text)
        assert result["name"] == "first"


def _mock_completion(content: str):
    """Create a mock OpenAI completion response."""
    choice = MagicMock()
    choice.message.content = content
    response = MagicMock()
    response.choices = [choice]
    return response


class TestChatWithoutToolCall:
    @patch("server.chat_service._get_client")
    def test_plain_response(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _mock_completion(
            "I can help you investigate that IP address."
        )
        mock_get_client.return_value = mock_client

        result = chat(messages=[{"role": "user", "content": "Hello"}])

        assert result["reply"] == "I can help you investigate that IP address."
        assert result["reasoning"] is None
        assert result["tool_calls"] is None
        assert result["requires_approval"] is None

    @patch("server.chat_service._get_client")
    def test_response_with_reasoning(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _mock_completion(
            "<think>User wants to investigate an IP.</think>Let me check that for you."
        )
        mock_get_client.return_value = mock_client

        result = chat(messages=[{"role": "user", "content": "Check 1.2.3.4"}])

        assert result["reply"] == "Let me check that for you."
        assert result["reasoning"] == "User wants to investigate an IP."


class TestChatWithToolCall:
    @patch("server.chat_service._get_client")
    def test_tool_call_executes_and_loops(self, mock_get_client):
        mock_client = MagicMock()
        # First call: model requests a tool
        # Second call: model gives final answer after seeing tool result
        mock_client.chat.completions.create.side_effect = [
            _mock_completion(
                '```tool_call\n{"name": "check_ip_reputation", "arguments": {"ip": "1.2.3.4"}}\n```'
            ),
            _mock_completion(
                "The IP 1.2.3.4 has a moderate risk score."
            ),
        ]
        mock_get_client.return_value = mock_client

        result = chat(messages=[{"role": "user", "content": "Check IP 1.2.3.4"}])

        assert "1.2.3.4" in result["reply"]
        assert result["tool_calls"] is not None
        assert len(result["tool_calls"]) == 1
        assert result["tool_calls"][0]["name"] == "check_ip_reputation"
        assert result["tool_calls"][0]["result"] is not None

    @patch("server.chat_service._get_client")
    def test_isolate_host_returns_approval_required(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _mock_completion(
            'I recommend isolating this host.\n```tool_call\n{"name": "isolate_host", "arguments": {"hostname": "ws-42"}}\n```'
        )
        mock_get_client.return_value = mock_client

        result = chat(messages=[{"role": "user", "content": "Isolate ws-42"}])

        assert result["requires_approval"] is not None
        assert result["requires_approval"]["tool"] == "isolate_host"
        assert result["requires_approval"]["args"]["hostname"] == "ws-42"
        assert result["tool_calls"] is not None


class TestChatApprovalFlow:
    @patch("server.chat_service._get_client")
    def test_approved_isolation(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _mock_completion(
            "Host ws-42 has been successfully isolated."
        )
        mock_get_client.return_value = mock_client

        result = chat(
            messages=[{"role": "user", "content": "Isolate ws-42"}],
            pending_approval={"tool": "isolate_host", "args": {"hostname": "ws-42"}, "approved": True},
        )

        assert "isolated" in result["reply"].lower() or "ws-42" in result["reply"]

    @patch("server.chat_service._get_client")
    def test_denied_isolation(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _mock_completion(
            "Understood. I'll suggest alternative containment measures instead."
        )
        mock_get_client.return_value = mock_client

        result = chat(
            messages=[{"role": "user", "content": "Isolate ws-42"}],
            pending_approval={"tool": "isolate_host", "args": {"hostname": "ws-42"}, "approved": False},
        )

        assert result["reply"] is not None
        assert result["requires_approval"] is None


class TestChatErrorHandling:
    @patch("server.chat_service._get_client")
    def test_api_error_returns_error_message(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("Connection refused")
        mock_get_client.return_value = mock_client

        result = chat(messages=[{"role": "user", "content": "Hello"}])

        assert "Error" in result["reply"]
        assert "Connection refused" in result["reply"]
        assert result["reasoning"] is None

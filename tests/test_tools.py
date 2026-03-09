"""Tests for the tool execution layer."""

from server.tools import (
    TOOL_DEFINITIONS,
    confirm_isolate_host,
    execute_tool,
)


class TestToolDefinitions:
    def test_three_tools_registered(self):
        assert len(TOOL_DEFINITIONS) == 3

    def test_tool_names(self):
        names = {t["name"] for t in TOOL_DEFINITIONS}
        assert names == {"fetch_logs", "check_ip_reputation", "isolate_host"}

    def test_each_tool_has_description(self):
        for t in TOOL_DEFINITIONS:
            assert len(t["description"]) > 10

    def test_each_tool_has_parameters(self):
        for t in TOOL_DEFINITIONS:
            assert "parameters" in t
            assert len(t["parameters"]) >= 1


class TestExecuteFetchLogs:
    def test_returns_logs(self):
        result = execute_tool("fetch_logs", {"source": "firewall", "timeframe": "last_1h"})
        assert "logs" in result
        assert isinstance(result["logs"], list)
        assert result["log_count"] == len(result["logs"])

    def test_source_echoed(self):
        result = execute_tool("fetch_logs", {"source": "endpoint"})
        assert result["source"] == "endpoint"

    def test_default_source(self):
        result = execute_tool("fetch_logs", {})
        assert result["source"] == "siem-primary"

    def test_default_timeframe(self):
        result = execute_tool("fetch_logs", {})
        assert result["timeframe"] == "last_1h"


class TestExecuteCheckIpReputation:
    def test_returns_all_providers(self):
        result = execute_tool("check_ip_reputation", {"ip": "45.33.32.156"})
        assert "abuseipdb" in result
        assert "virustotal" in result
        assert "otx" in result
        assert "greynoise" in result

    def test_ip_echoed_in_each(self):
        ip = "10.0.1.42"
        result = execute_tool("check_ip_reputation", {"ip": ip})
        assert result["ip"] == ip
        assert result["abuseipdb"]["ip"] == ip
        assert result["virustotal"]["ip"] == ip

    def test_default_ip(self):
        result = execute_tool("check_ip_reputation", {})
        assert result["ip"] == "0.0.0.0"


class TestExecuteIsolateHost:
    def test_returns_pending_approval(self):
        result = execute_tool("isolate_host", {"hostname": "ws-42"})
        assert result["status"] == "pending_approval"
        assert result["hostname"] == "ws-42"

    def test_message_contains_hostname(self):
        result = execute_tool("isolate_host", {"hostname": "server-prod-01"})
        assert "server-prod-01" in result["message"]

    def test_default_hostname(self):
        result = execute_tool("isolate_host", {})
        assert result["hostname"] == "unknown"


class TestConfirmIsolateHost:
    def test_returns_isolated_status(self):
        result = confirm_isolate_host("workstation-15")
        assert result["status"] == "isolated"
        assert result["hostname"] == "workstation-15"

    def test_actions_taken_populated(self):
        result = confirm_isolate_host("server-01")
        assert isinstance(result["actions_taken"], list)
        assert len(result["actions_taken"]) == 4

    def test_incident_ticket_created(self):
        result = confirm_isolate_host("10.0.1.42")
        ticket_action = result["actions_taken"][-1]
        assert ticket_action.startswith("Created incident ticket INC-")


class TestUnknownTool:
    def test_returns_error(self):
        result = execute_tool("nonexistent_tool", {})
        assert "error" in result
        assert "nonexistent_tool" in result["error"]

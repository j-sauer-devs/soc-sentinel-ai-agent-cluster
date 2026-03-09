"""K2 Think chat service for the SOC Sentinel copilot.

Handles multi-turn conversations with tool dispatch.
Uses the existing K2 Think API (OpenAI-compatible) for reasoning.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys

from openai import OpenAI

logger = logging.getLogger(__name__)

# Add project root so we can import graph.utils
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from graph.utils import extract_reasoning

from server.tools import TOOL_DEFINITIONS, confirm_isolate_host, execute_tool

# ---------------------------------------------------------------------------
# K2 Think client
# ---------------------------------------------------------------------------

_k2_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _k2_client
    if _k2_client is None:
        _k2_client = OpenAI(
            api_key=os.getenv("K2_API_KEY", ""),
            base_url=os.getenv("K2_BASE_URL", "https://api.k2think.ai/v1"),
        )
    return _k2_client


K2_MODEL = os.getenv("K2_MODEL", "MBZUAI-IFM/K2-Think-v2")

SYSTEM_PROMPT = """You are SOC Sentinel, an AI-powered Security Operations Center copilot.
You help SOC analysts investigate security alerts, hunt for threats, and respond to incidents.

You have access to the following tools:
{tools}

When the analyst asks you to investigate an IP, check logs, or take action,
respond with a JSON block specifying which tool to call:

```tool_call
{{"name": "<tool_name>", "arguments": {{"param": "value"}}}}
```

After receiving tool results, summarize findings in clear, actionable language.
Always explain your reasoning step by step.
If you recommend isolating a host, note that it requires analyst approval.
Be concise but thorough. Prioritize actionable intelligence."""


def _build_system_prompt() -> str:
    tools_desc = "\n".join(
        f"- {t['name']}: {t['description']} (params: {', '.join(t['parameters'].keys())})"
        for t in TOOL_DEFINITIONS
    )
    return SYSTEM_PROMPT.format(tools=tools_desc)


def _extract_tool_call(text: str) -> dict | None:
    """Extract a tool_call JSON block from the assistant's response."""
    match = re.search(r"```tool_call\s*\n?({.*?})\s*\n?```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            return None
    return None


# ---------------------------------------------------------------------------
# Chat handler
# ---------------------------------------------------------------------------

def chat(
    messages: list[dict],
    pending_approval: dict | None = None,
) -> dict:
    """Process a chat turn.

    Args:
        messages: Conversation history [{"role": ..., "content": ...}, ...]
        pending_approval: If set, contains {"tool": "isolate_host", "args": {...}, "approved": bool}

    Returns:
        {
            "reply": str,
            "reasoning": str | None,
            "tool_calls": [{"name": ..., "arguments": ..., "result": ...}] | None,
            "requires_approval": {"tool": ..., "args": ...} | None,
        }
    """
    logger.info("Chat request: %d messages, pending_approval=%s", len(messages), bool(pending_approval))

    # Handle approval flow
    if pending_approval:
        tool_name = pending_approval.get("tool", "")
        args = pending_approval.get("args", {})
        approved = pending_approval.get("approved", False)

        if tool_name == "isolate_host" and approved:
            logger.info("Approval granted for isolate_host: %s", args)
            result = confirm_isolate_host(args.get("hostname", "unknown"))
            tool_result_msg = f"Tool result (isolate_host — APPROVED):\n```json\n{json.dumps(result, indent=2)}\n```"
            messages.append({"role": "user", "content": tool_result_msg})
        elif tool_name == "isolate_host" and not approved:
            logger.info("Approval denied for isolate_host: %s", args)
            messages.append({"role": "user", "content": "Analyst DENIED the host isolation request. Suggest alternative containment measures."})

    # Build the API messages
    api_messages = [{"role": "system", "content": _build_system_prompt()}]
    for m in messages:
        api_messages.append({"role": m["role"], "content": m["content"]})

    client = _get_client()
    tool_calls_made = []

    # Tool dispatch loop (max 3 rounds to prevent infinite loops)
    for _ in range(3):
        try:
            response = client.chat.completions.create(
                model=K2_MODEL,
                messages=api_messages,
                max_tokens=2000,
            )
            raw_content = response.choices[0].message.content or ""
        except Exception as e:
            logger.error("K2 Think API error: %s", e)
            return {
                "reply": f"Error communicating with K2 Think: {e}",
                "reasoning": None,
                "tool_calls": None,
                "requires_approval": None,
            }

        reasoning, answer = extract_reasoning(raw_content)

        # Check if the model wants to call a tool
        tool_call = _extract_tool_call(answer)
        if tool_call is None:
            # No tool call — return the final answer
            return {
                "reply": re.sub(r"```tool_call.*?```", "", answer, flags=re.DOTALL).strip(),
                "reasoning": reasoning or None,
                "tool_calls": tool_calls_made or None,
                "requires_approval": None,
            }

        # Execute the tool
        tool_name = tool_call.get("name", "")
        tool_args = tool_call.get("arguments", {})
        logger.info("Executing tool: %s(%s)", tool_name, tool_args)
        tool_result = execute_tool(tool_name, tool_args)

        tool_calls_made.append({
            "name": tool_name,
            "arguments": tool_args,
            "result": tool_result,
        })

        # Check if this tool requires approval
        if tool_result.get("status") == "pending_approval":
            logger.info("Tool %s requires analyst approval", tool_name)
            # Strip the tool call block from the answer for the reply
            clean_answer = re.sub(r"```tool_call.*?```", "", answer, flags=re.DOTALL).strip()
            return {
                "reply": clean_answer or f"I need to isolate host '{tool_args.get('hostname', 'unknown')}'. This action requires your approval.",
                "reasoning": reasoning or None,
                "tool_calls": tool_calls_made,
                "requires_approval": {"tool": tool_name, "args": tool_args},
            }

        # Feed the tool result back into the conversation
        api_messages.append({"role": "assistant", "content": raw_content})
        tool_result_str = json.dumps(tool_result, indent=2, default=str)
        api_messages.append({"role": "user", "content": f"Tool result ({tool_name}):\n```json\n{tool_result_str}\n```"})

    # Exhausted tool call rounds
    logger.warning("Exhausted tool dispatch rounds (3 max)")
    return {
        "reply": answer,
        "reasoning": reasoning or None,
        "tool_calls": tool_calls_made or None,
        "requires_approval": None,
    }

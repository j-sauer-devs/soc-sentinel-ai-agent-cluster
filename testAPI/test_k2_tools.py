"""
Step 2: Check tool/function calling support in K2 Think.

If this errors or the model ignores the tools, that's expected —
K2 Think handles reasoning only and LangGraph handles tool dispatch.

Usage:
  pip install openai python-dotenv
  python testAPI/test_k2_tools.py
"""

import os
import sys

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

api_key = os.getenv("K2_API_KEY")
if not api_key or api_key == "your_key_here":
    print("ERROR: Set K2_API_KEY in .env before running this test.")
    sys.exit(1)

client = OpenAI(
    api_key=api_key,
    base_url="https://api.k2think.ai/v1",
)

tools = [
    {
        "type": "function",
        "function": {
            "name": "check_ip_reputation",
            "description": "Check an IP address against AbuseIPDB",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
    }
]

print("Testing tool/function calling support...")
try:
    response = client.chat.completions.create(
        model="MBZUAI-IFM/K2-Think-v2",
        messages=[{"role": "user", "content": "Is 45.33.32.156 malicious?"}],
        tools=tools,
    )
    choice = response.choices[0]
    print("\n--- Response ---")
    print(f"Finish reason: {choice.finish_reason}")

    if choice.message.tool_calls:
        print("Tool calling IS supported!")
        for tc in choice.message.tool_calls:
            print(f"  Tool: {tc.function.name}")
            print(f"  Args: {tc.function.arguments}")
    else:
        print("No tool calls in response — model responded with text instead.")
        print(f"Content: {choice.message.content[:200]}")
        print("\nThis means LangGraph will need to handle tool dispatch around K2 Think.")

except Exception as e:
    print(f"\nTool calling NOT supported (got error): {e}")
    print("\nThis is fine — LangGraph will handle tool dispatch around K2 Think.")

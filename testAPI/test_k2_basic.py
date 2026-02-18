"""
Step 1: Verify the K2 Think API works.

Checks:
  1. Does the API respond at all?
  2. Does the response include <think>...</think> reasoning tags?

Usage:
  pip install openai python-dotenv
  python testAPI/test_k2_basic.py
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

print("Sending test prompt to K2 Think...")
response = client.chat.completions.create(
    model="MBZUAI-IFM/K2-Think-v2",
    messages=[{"role": "user", "content": "What is 2+2? Show your reasoning."}],
    max_tokens=500,
)

content = response.choices[0].message.content
print("\n--- Raw Response ---")
print(content)

# Check for reasoning tags (handle both complete and incomplete tags)
has_complete_reasoning = "<think>" in content and "</think>" in content
has_partial_reasoning = "</think>" in content
print("\n--- Checks ---")
print(f"API responded:           YES")
print(f"Complete <think> tags:   {'YES' if has_complete_reasoning else 'NO'}")
print(f"Reasoning block present: {'YES' if has_complete_reasoning or has_partial_reasoning else 'NO'}")

if has_complete_reasoning or has_partial_reasoning:
    print("\nSUCCESS: K2 Think is returning reasoning blocks!")
else:
    print(
        "\nWARNING: No reasoning blocks found. "
        "Check the model name or API docs."
    )

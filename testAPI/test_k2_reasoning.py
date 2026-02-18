"""
Step 3: Extract and validate reasoning blocks from K2 Think responses.

Includes the extract_reasoning() parser that will be reused throughout
the project (e.g. feeding the Reasoning Inspector panel in Streamlit).

Usage:
  pip install openai python-dotenv
  python testAPI/test_k2_reasoning.py
"""

import os
import re
import sys

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()


def extract_reasoning(content: str) -> tuple[str, str]:
    """
    Handles two formats K2 Think uses:
    - Standard:  <think>...</think>
    - Observed:  ...reasoning...</think>  (no opening tag)
    """
    # Try standard format first
    think_match = re.search(r'<think>(.*?)</think>', content, re.DOTALL)
    if think_match:
        reasoning = think_match.group(1).strip()
        answer = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL).strip()
        return reasoning, answer

    # Fallback: split on closing tag only
    if '</think>' in content:
        parts = content.split('</think>', 1)
        reasoning = parts[0].strip()
        answer = parts[1].strip()
        return reasoning, answer

    # No reasoning tags at all
    return "", content.strip()


# ---------------------------------------------------------------------------
# If run directly, fetch a live response and test the parser
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    api_key = os.getenv("K2_API_KEY")
    if not api_key or api_key == "your_key_here":
        print("ERROR: Set K2_API_KEY in .env before running this test.")
        sys.exit(1)

    client = OpenAI(
        api_key=api_key,
        base_url="https://api.k2think.ai/v1",
    )

    print("Fetching response from K2 Think...")
    response = client.chat.completions.create(
        model="MBZUAI-IFM/K2-Think-v2",
        messages=[{"role": "user", "content": "What is 2+2? Show your reasoning."}],
        max_tokens=500,
    )

    raw = response.choices[0].message.content
    reasoning, answer = extract_reasoning(raw)

    print("\n--- Raw Response ---")
    print(raw)
    print("\n--- Extracted Reasoning ---")
    print(reasoning if reasoning else "(none)")
    print("\n--- Final Answer ---")
    print(answer)

    if reasoning:
        print("\nSUCCESS: Reasoning blocks extracted correctly.")
    else:
        print(
            "\nWARNING: No reasoning block found. "
            "Check the model name or API docs."
        )

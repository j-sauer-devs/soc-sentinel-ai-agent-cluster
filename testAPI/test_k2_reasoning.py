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
    """Extract reasoning and final answer from K2 Think response.

    Returns:
        (reasoning, final_answer) — reasoning is the text inside <think>...</think>,
        final_answer is everything outside those tags.

    Note: K2 Think responses may have incomplete opening tags due to streaming.
    This parser handles both complete <think>...</think> and cases with only </think>.
    """
    # Try to match complete <think>...</think> block first
    think_match = re.search(r"<think>(.*?)</think>", content, re.DOTALL)

    if think_match:
        # Complete tag found
        reasoning = think_match.group(1).strip()
        answer = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
    else:
        # No complete tag; look for </think> and extract everything before it
        close_idx = content.find("</think>")
        if close_idx != -1:
            reasoning = content[:close_idx].strip()
            answer = content[close_idx + 8:].strip()  # 8 = len("</think>")
        else:
            # No reasoning tags at all
            reasoning = ""
            answer = content

    return reasoning, answer


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

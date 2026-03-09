"""Tests for the reasoning extraction utility (graph/utils.py)."""

from graph.utils import extract_reasoning


class TestStandardFormat:
    def test_basic(self):
        content = "<think>I need to analyze this.</think>The answer is 42."
        reasoning, answer = extract_reasoning(content)
        assert reasoning == "I need to analyze this."
        assert answer == "The answer is 42."

    def test_multiline_reasoning(self):
        content = "<think>Step 1: Check IP.\nStep 2: Verify logs.\nStep 3: Conclude.</think>Verdict: THREAT"
        reasoning, answer = extract_reasoning(content)
        assert "Step 1" in reasoning
        assert "Step 3" in reasoning
        assert answer == "Verdict: THREAT"

    def test_whitespace_handling(self):
        content = "<think>  some reasoning  </think>  some answer  "
        reasoning, answer = extract_reasoning(content)
        assert reasoning == "some reasoning"
        assert answer == "some answer"


class TestFallbackFormat:
    """K2 Think sometimes omits the opening <think> tag in streaming."""

    def test_missing_opening_tag(self):
        content = "Some internal reasoning here.</think>The final answer."
        reasoning, answer = extract_reasoning(content)
        assert reasoning == "Some internal reasoning here."
        assert answer == "The final answer."


class TestNoReasoningTags:
    def test_plain_text(self):
        content = "Just a regular response."
        reasoning, answer = extract_reasoning(content)
        assert reasoning == ""
        assert answer == "Just a regular response."

    def test_empty_string(self):
        reasoning, answer = extract_reasoning("")
        assert reasoning == ""
        assert answer == ""

    def test_whitespace_only(self):
        reasoning, answer = extract_reasoning("   ")
        assert reasoning == ""
        assert answer == ""


class TestEdgeCases:
    def test_empty_think_block(self):
        content = "<think></think>Answer here."
        reasoning, answer = extract_reasoning(content)
        assert reasoning == ""
        assert answer == "Answer here."

    def test_think_tags_in_answer(self):
        # Only the first <think>...</think> block should be captured
        content = "<think>First reasoning</think>Answer with <think> mentioned"
        reasoning, answer = extract_reasoning(content)
        assert reasoning == "First reasoning"
        assert "mentioned" in answer

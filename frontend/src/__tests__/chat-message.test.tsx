import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { ChatMessage } from "@/components/chat/chat-message";
import type { ChatMessage as ChatMessageType } from "@/types";

describe("ChatMessage", () => {
  it("renders user message", () => {
    const msg: ChatMessageType = { role: "user", content: "Check IP 1.2.3.4" };
    render(<ChatMessage message={msg} />);
    expect(screen.getByText("Check IP 1.2.3.4")).toBeInTheDocument();
  });

  it("renders assistant message", () => {
    const msg: ChatMessageType = {
      role: "assistant",
      content: "The IP has a high risk score.",
    };
    render(<ChatMessage message={msg} />);
    expect(screen.getByText("The IP has a high risk score.")).toBeInTheDocument();
  });

  it("shows tool call badges", () => {
    const msg: ChatMessageType = {
      role: "assistant",
      content: "Checked the IP.",
      tool_calls: [
        { name: "check_ip_reputation", arguments: { ip: "1.2.3.4" } },
      ],
    };
    render(<ChatMessage message={msg} />);
    expect(screen.getByText(/check_ip_reputation/)).toBeInTheDocument();
  });

  it("shows chain of thought toggle when reasoning is present", () => {
    const msg: ChatMessageType = {
      role: "assistant",
      content: "Result here.",
      reasoning: "Step 1: Analyze. Step 2: Conclude.",
    };
    render(<ChatMessage message={msg} />);
    expect(screen.getByText("Chain of Thought")).toBeInTheDocument();
  });

  it("toggles reasoning visibility", () => {
    const msg: ChatMessageType = {
      role: "assistant",
      content: "Result here.",
      reasoning: "Internal reasoning steps.",
    };
    render(<ChatMessage message={msg} />);

    // Reasoning not visible initially
    expect(screen.queryByText("Internal reasoning steps.")).not.toBeInTheDocument();

    // Click toggle
    fireEvent.click(screen.getByText("Chain of Thought"));

    // Now visible
    expect(screen.getByText("Internal reasoning steps.")).toBeInTheDocument();
  });

  it("does not show reasoning toggle when no reasoning", () => {
    const msg: ChatMessageType = {
      role: "assistant",
      content: "No reasoning here.",
    };
    render(<ChatMessage message={msg} />);
    expect(screen.queryByText("Chain of Thought")).not.toBeInTheDocument();
  });
});

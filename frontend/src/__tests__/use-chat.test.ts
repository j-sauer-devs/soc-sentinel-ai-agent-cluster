import { renderHook, act, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { useChat } from "@/hooks/use-chat";
import type { ChatResponse } from "@/types";

// Mock the API module
vi.mock("@/lib/api", () => ({
  sendChat: vi.fn(),
  fetchAlerts: vi.fn(),
  summarizeAlert: vi.fn(),
  runPipeline: vi.fn(),
  getWsUrl: vi.fn(),
}));

import { sendChat } from "@/lib/api";
const mockSendChat = vi.mocked(sendChat);

beforeEach(() => {
  vi.clearAllMocks();
});

describe("useChat", () => {
  it("starts with empty state", () => {
    const { result } = renderHook(() => useChat());
    expect(result.current.messages).toEqual([]);
    expect(result.current.isLoading).toBe(false);
    expect(result.current.pendingApproval).toBeNull();
  });

  it("send() adds user message and assistant response", async () => {
    const response: ChatResponse = {
      reply: "I can help with that.",
      reasoning: null,
      tool_calls: null,
      requires_approval: null,
    };
    mockSendChat.mockResolvedValueOnce(response);

    const { result } = renderHook(() => useChat());

    await act(async () => {
      await result.current.send("Hello");
    });

    expect(result.current.messages).toHaveLength(2);
    expect(result.current.messages[0].role).toBe("user");
    expect(result.current.messages[0].content).toBe("Hello");
    expect(result.current.messages[1].role).toBe("assistant");
    expect(result.current.messages[1].content).toBe("I can help with that.");
  });

  it("send() sets and clears isLoading", async () => {
    let resolveChat: (value: ChatResponse) => void;
    const chatPromise = new Promise<ChatResponse>((resolve) => {
      resolveChat = resolve;
    });
    mockSendChat.mockReturnValueOnce(chatPromise);

    const { result } = renderHook(() => useChat());

    // Start sending (don't await)
    let sendPromise: Promise<void>;
    act(() => {
      sendPromise = result.current.send("Hello");
    });

    // Should be loading
    expect(result.current.isLoading).toBe(true);

    // Resolve
    await act(async () => {
      resolveChat!({
        reply: "Done",
        reasoning: null,
        tool_calls: null,
        requires_approval: null,
      });
      await sendPromise!;
    });

    expect(result.current.isLoading).toBe(false);
  });

  it("send() handles errors gracefully", async () => {
    mockSendChat.mockRejectedValueOnce(new Error("Network error"));

    const { result } = renderHook(() => useChat());

    await act(async () => {
      await result.current.send("Hello");
    });

    expect(result.current.messages).toHaveLength(2);
    expect(result.current.messages[1].role).toBe("assistant");
    expect(result.current.messages[1].content).toContain("Network error");
    expect(result.current.isLoading).toBe(false);
  });

  it("send() includes tool_calls in response", async () => {
    const response: ChatResponse = {
      reply: "Checked the IP.",
      reasoning: "Used reputation API",
      tool_calls: [
        { name: "check_ip_reputation", arguments: { ip: "1.2.3.4" }, result: { score: 75 } },
      ],
      requires_approval: null,
    };
    mockSendChat.mockResolvedValueOnce(response);

    const { result } = renderHook(() => useChat());

    await act(async () => {
      await result.current.send("Check 1.2.3.4");
    });

    const assistantMsg = result.current.messages[1];
    expect(assistantMsg.tool_calls).toHaveLength(1);
    expect(assistantMsg.tool_calls![0].name).toBe("check_ip_reputation");
    expect(assistantMsg.reasoning).toBe("Used reputation API");
  });

  it("send() sets pendingApproval when requires_approval", async () => {
    const response: ChatResponse = {
      reply: "Need to isolate host.",
      reasoning: null,
      tool_calls: [
        { name: "isolate_host", arguments: { hostname: "ws-42" }, result: { status: "pending_approval" } },
      ],
      requires_approval: { tool: "isolate_host", args: { hostname: "ws-42" } },
    };
    mockSendChat.mockResolvedValueOnce(response);

    const { result } = renderHook(() => useChat());

    await act(async () => {
      await result.current.send("Isolate ws-42");
    });

    expect(result.current.pendingApproval).not.toBeNull();
    expect(result.current.pendingApproval!.tool).toBe("isolate_host");
  });

  it("handleApproval(true) sends approval and clears pending", async () => {
    // First: set up pending approval
    const response1: ChatResponse = {
      reply: "Need approval.",
      reasoning: null,
      tool_calls: null,
      requires_approval: { tool: "isolate_host", args: { hostname: "ws-42" } },
    };
    mockSendChat.mockResolvedValueOnce(response1);

    const { result } = renderHook(() => useChat());

    await act(async () => {
      await result.current.send("Isolate ws-42");
    });

    expect(result.current.pendingApproval).not.toBeNull();

    // Now approve
    const response2: ChatResponse = {
      reply: "Host isolated.",
      reasoning: null,
      tool_calls: [{ name: "isolate_host", arguments: { hostname: "ws-42" }, result: { status: "isolated" } }],
      requires_approval: null,
    };
    mockSendChat.mockResolvedValueOnce(response2);

    await act(async () => {
      await result.current.handleApproval(true);
    });

    expect(result.current.pendingApproval).toBeNull();
    // Should have called sendChat with approval
    expect(mockSendChat).toHaveBeenCalledTimes(2);
    const lastCall = mockSendChat.mock.calls[1];
    expect(lastCall[1]).toMatchObject({ tool: "isolate_host", approved: true });
  });

  it("handleApproval(false) clears pending without API call for approval", async () => {
    const response: ChatResponse = {
      reply: "Need approval.",
      reasoning: null,
      tool_calls: null,
      requires_approval: { tool: "isolate_host", args: { hostname: "ws-42" } },
    };
    mockSendChat.mockResolvedValueOnce(response);

    const { result } = renderHook(() => useChat());

    await act(async () => {
      await result.current.send("Isolate ws-42");
    });

    const response2: ChatResponse = {
      reply: "Cancelled.",
      reasoning: null,
      tool_calls: null,
      requires_approval: null,
    };
    mockSendChat.mockResolvedValueOnce(response2);

    await act(async () => {
      await result.current.handleApproval(false);
    });

    expect(result.current.pendingApproval).toBeNull();
  });

  it("clearChat() resets all state", async () => {
    const response: ChatResponse = {
      reply: "Hello!",
      reasoning: null,
      tool_calls: null,
      requires_approval: null,
    };
    mockSendChat.mockResolvedValueOnce(response);

    const { result } = renderHook(() => useChat());

    await act(async () => {
      await result.current.send("Hello");
    });

    expect(result.current.messages.length).toBeGreaterThan(0);

    act(() => {
      result.current.clearChat();
    });

    expect(result.current.messages).toEqual([]);
    expect(result.current.pendingApproval).toBeNull();
  });
});

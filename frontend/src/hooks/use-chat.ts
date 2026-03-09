"use client";

import { useCallback, useState } from "react";
import { sendChat } from "@/lib/api";
import type { ChatMessage, ChatResponse } from "@/types";

export function useChat() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [pendingApproval, setPendingApproval] = useState<{ tool: string; args: Record<string, unknown> } | null>(null);

  const send = useCallback(async (content: string) => {
    const userMsg: ChatMessage = { role: "user", content };
    const updatedMessages = [...messages, userMsg];
    setMessages(updatedMessages);
    setIsLoading(true);

    try {
      const apiMessages = updatedMessages.map((m) => ({ role: m.role, content: m.content }));
      const res: ChatResponse = await sendChat(apiMessages);

      const assistantMsg: ChatMessage = {
        role: "assistant",
        content: res.reply,
        reasoning: res.reasoning,
        tool_calls: res.tool_calls,
      };

      setMessages([...updatedMessages, assistantMsg]);

      if (res.requires_approval) {
        setPendingApproval(res.requires_approval);
      }
    } catch (e) {
      const errorMsg: ChatMessage = {
        role: "assistant",
        content: `Error: ${e instanceof Error ? e.message : "Unknown error"}`,
      };
      setMessages([...updatedMessages, errorMsg]);
    } finally {
      setIsLoading(false);
    }
  }, [messages]);

  const handleApproval = useCallback(async (approved: boolean) => {
    if (!pendingApproval) return;

    setIsLoading(true);
    const approval = { ...pendingApproval, approved };
    setPendingApproval(null);

    try {
      const apiMessages = messages.map((m) => ({ role: m.role, content: m.content }));
      const res: ChatResponse = await sendChat(apiMessages, approval);

      const assistantMsg: ChatMessage = {
        role: "assistant",
        content: res.reply,
        reasoning: res.reasoning,
        tool_calls: res.tool_calls,
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (e) {
      const errorMsg: ChatMessage = {
        role: "assistant",
        content: `Error: ${e instanceof Error ? e.message : "Unknown error"}`,
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsLoading(false);
    }
  }, [messages, pendingApproval]);

  const clearChat = useCallback(() => {
    setMessages([]);
    setPendingApproval(null);
  }, []);

  return { messages, isLoading, pendingApproval, send, handleApproval, clearChat };
}

"use client";

import { useRef, useEffect, useState, type FormEvent } from "react";
import { Send, Loader2, Trash2, Bot } from "lucide-react";
import { ChatMessage } from "./chat-message";
import { ApprovalDialog } from "./approval-dialog";
import { useChat } from "@/hooks/use-chat";

export function ChatPanel() {
  const { messages, isLoading, pendingApproval, send, handleApproval, clearChat } = useChat();
  const [input, setInput] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll on new messages
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  // Listen for commands from CMD+K command bar
  useEffect(() => {
    const handler = (e: Event) => {
      const command = (e as CustomEvent<string>).detail;
      if (command) send(command);
    };
    window.addEventListener("soc-command", handler);
    return () => window.removeEventListener("soc-command", handler);
  }, [send]);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    const text = input.trim();
    if (!text || isLoading) return;
    setInput("");
    send(text);
  };

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <div className="flex items-center gap-2">
          <Bot className="h-4 w-4 text-primary" />
          <h3 className="text-sm font-semibold text-foreground">SOC Sentinel</h3>
          <span className="text-xs text-muted-foreground">AI Copilot</span>
        </div>
        {messages.length > 0 && (
          <button
            onClick={clearChat}
            className="rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            title="Clear chat"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        )}
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 space-y-4 overflow-y-auto p-4">
        {messages.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-3 text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
              <Bot className="h-6 w-6 text-primary" />
            </div>
            <div>
              <p className="text-sm font-medium text-foreground">
                SOC Sentinel Copilot
              </p>
              <p className="mt-1 text-xs text-muted-foreground max-w-xs">
                Ask me to investigate IPs, analyze threats, pull logs, or isolate compromised hosts.
              </p>
            </div>
            <div className="mt-2 flex flex-wrap justify-center gap-2">
              {[
                "Check IP 45.33.32.156",
                "Pull firewall logs",
                "Analyze latest critical alerts",
              ].map((prompt) => (
                <button
                  key={prompt}
                  onClick={() => send(prompt)}
                  className="rounded-full border border-border bg-card px-3 py-1.5 text-xs text-muted-foreground transition-colors hover:border-primary/30 hover:text-foreground"
                >
                  {prompt}
                </button>
              ))}
            </div>
          </div>
        ) : (
          messages.map((msg, i) => <ChatMessage key={i} message={msg} />)
        )}

        {isLoading && (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            SOC Sentinel is thinking...
          </div>
        )}
      </div>

      {/* Input */}
      <form onSubmit={handleSubmit} className="border-t border-border p-4">
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Investigate an IP, hunt threats, pull logs..."
            className="flex-1 rounded-lg border border-border bg-input px-3.5 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
            disabled={isLoading}
          />
          <button
            type="submit"
            disabled={isLoading || !input.trim()}
            className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
          >
            <Send className="h-4 w-4" />
          </button>
        </div>
      </form>

      {/* Approval Dialog */}
      {pendingApproval && (
        <ApprovalDialog
          tool={pendingApproval.tool}
          args={pendingApproval.args}
          onApprove={() => handleApproval(true)}
          onDeny={() => handleApproval(false)}
        />
      )}
    </div>
  );
}

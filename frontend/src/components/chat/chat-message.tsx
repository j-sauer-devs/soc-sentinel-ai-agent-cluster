"use client";

import { useState } from "react";
import { Bot, User, ChevronDown, ChevronUp, Wrench } from "lucide-react";
import type { ChatMessage as ChatMessageType } from "@/types";

interface ChatMessageProps {
  message: ChatMessageType;
}

export function ChatMessage({ message }: ChatMessageProps) {
  const [showReasoning, setShowReasoning] = useState(false);
  const isUser = message.role === "user";

  return (
    <div className={`flex gap-3 ${isUser ? "flex-row-reverse" : ""}`}>
      {/* Avatar */}
      <div
        className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full ${
          isUser ? "bg-primary/20" : "bg-agent-oversight/20"
        }`}
      >
        {isUser ? (
          <User className="h-3.5 w-3.5 text-primary" />
        ) : (
          <Bot className="h-3.5 w-3.5 text-agent-oversight" />
        )}
      </div>

      {/* Content */}
      <div className={`max-w-[80%] space-y-2 ${isUser ? "text-right" : ""}`}>
        <div
          className={`inline-block rounded-lg px-3.5 py-2.5 text-sm leading-relaxed ${
            isUser
              ? "bg-primary/15 text-foreground"
              : "bg-card border border-border text-foreground"
          }`}
        >
          <p className="whitespace-pre-wrap">{message.content}</p>
        </div>

        {/* Tool calls */}
        {message.tool_calls && message.tool_calls.length > 0 && (
          <div className="space-y-1">
            {message.tool_calls.map((tc, i) => (
              <div
                key={i}
                className="inline-flex items-center gap-1.5 rounded-md bg-agent-hunter/10 px-2 py-1 text-xs text-agent-hunter"
              >
                <Wrench className="h-3 w-3" />
                {tc.name}({Object.values(tc.arguments).join(", ")})
              </div>
            ))}
          </div>
        )}

        {/* Reasoning toggle */}
        {message.reasoning && (
          <div>
            <button
              onClick={() => setShowReasoning(!showReasoning)}
              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              {showReasoning ? (
                <ChevronUp className="h-3 w-3" />
              ) : (
                <ChevronDown className="h-3 w-3" />
              )}
              Chain of Thought
            </button>
            {showReasoning && (
              <div className="mt-1.5 rounded-md bg-muted/50 border border-border p-3 text-xs text-muted-foreground leading-relaxed font-mono whitespace-pre-wrap">
                {message.reasoning}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

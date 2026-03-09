"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Command } from "cmdk";
import { Search, Terminal, Globe, ScrollText, ShieldOff } from "lucide-react";

interface CommandBarProps {
  onCommand: (command: string) => void;
}

const SUGGESTIONS = [
  { icon: Globe, label: "/analyze", description: "Analyze suspicious traffic from an IP", example: "/analyze 192.168.1.1" },
  { icon: Search, label: "/hunt", description: "Hunt for IOCs across threat intelligence", example: "/hunt sha256:e3b0c44..." },
  { icon: ScrollText, label: "/logs", description: "Pull logs from SIEM sources", example: "/logs firewall last_1h" },
  { icon: ShieldOff, label: "/isolate", description: "Request host isolation (requires approval)", example: "/isolate workstation-15" },
  { icon: Terminal, label: "/status", description: "Check agent pipeline status", example: "/status" },
];

export function CommandBar({ onCommand }: CommandBarProps) {
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  // CMD+K / Ctrl+K to toggle
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
      if (e.key === "Escape") {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  useEffect(() => {
    if (open) {
      // Small timeout to ensure DOM is ready
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  const handleSubmit = useCallback(() => {
    const text = value.trim();
    if (!text) return;

    // Transform commands into natural language for the chat
    let chatMessage = text;
    if (text.startsWith("/analyze ")) {
      const ip = text.replace("/analyze ", "").trim();
      chatMessage = `Analyze suspicious traffic from IP ${ip}. Check its reputation and pull related logs.`;
    } else if (text.startsWith("/hunt ")) {
      const ioc = text.replace("/hunt ", "").trim();
      chatMessage = `Hunt for IOC: ${ioc}. Search threat intelligence feeds and check for known associations.`;
    } else if (text.startsWith("/logs ")) {
      const parts = text.replace("/logs ", "").trim();
      chatMessage = `Fetch logs: ${parts}`;
    } else if (text.startsWith("/isolate ")) {
      const host = text.replace("/isolate ", "").trim();
      chatMessage = `Isolate host ${host} from the network immediately.`;
    } else if (text === "/status") {
      chatMessage = "What is the current status of the SOC Sentinel pipeline?";
    }

    onCommand(chatMessage);
    setValue("");
    setOpen(false);
  }, [value, onCommand]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh] bg-background/60 backdrop-blur-sm">
      <div className="w-full max-w-lg">
        <Command
          className="rounded-xl border border-border bg-card shadow-2xl overflow-hidden"
          shouldFilter={false}
        >
          <div className="flex items-center gap-2 border-b border-border px-4">
            <Search className="h-4 w-4 text-muted-foreground" />
            <input
              ref={inputRef}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  handleSubmit();
                }
              }}
              placeholder="Search threats, analyze IPs, hunt IOCs..."
              className="flex-1 bg-transparent py-3.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none"
            />
            <kbd className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground font-mono">
              ESC
            </kbd>
          </div>

          <Command.List className="max-h-60 overflow-y-auto p-2">
            <Command.Group heading="Commands" className="text-xs text-muted-foreground px-2 py-1.5">
              {SUGGESTIONS.map((suggestion) => (
                <Command.Item
                  key={suggestion.label}
                  onSelect={() => {
                    setValue(suggestion.example);
                    inputRef.current?.focus();
                  }}
                  className="flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-foreground hover:bg-muted transition-colors"
                >
                  <suggestion.icon className="h-4 w-4 text-muted-foreground" />
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-primary text-xs">{suggestion.label}</span>
                      <span className="text-muted-foreground text-xs">{suggestion.description}</span>
                    </div>
                  </div>
                </Command.Item>
              ))}
            </Command.Group>
          </Command.List>

          <div className="border-t border-border px-4 py-2 text-[10px] text-muted-foreground flex items-center gap-4">
            <span><kbd className="font-mono">Enter</kbd> to run</span>
            <span><kbd className="font-mono">Esc</kbd> to close</span>
            <span><kbd className="font-mono">Cmd+K</kbd> to toggle</span>
          </div>
        </Command>
      </div>
    </div>
  );
}

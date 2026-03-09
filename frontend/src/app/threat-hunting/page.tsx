"use client";

import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";
import { ChatPanel } from "@/components/chat/chat-panel";
import { CommandBar } from "@/components/command-bar/command-bar";
import { useAlerts } from "@/hooks/use-alerts";

export default function ThreatHuntingPage() {
  const { alerts, isConnected } = useAlerts();

  const handleCommand = (command: string) => {
    window.dispatchEvent(new CustomEvent("soc-command", { detail: command }));
  };

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header isConnected={isConnected} alertCount={alerts.length} />
        <main className="flex flex-1 flex-col overflow-hidden p-4">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-foreground">Threat Hunting</h2>
            <span className="text-xs text-muted-foreground">
              Press <kbd className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">Cmd+K</kbd> to open command bar
            </span>
          </div>
          <div className="flex-1 overflow-hidden rounded-lg border border-border bg-card">
            <ChatPanel />
          </div>
        </main>
      </div>
      <CommandBar onCommand={handleCommand} />
    </div>
  );
}

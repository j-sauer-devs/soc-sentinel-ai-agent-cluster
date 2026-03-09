"use client";

import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";
import { AlertFeed } from "@/components/alerts/alert-feed";
import { ChatPanel } from "@/components/chat/chat-panel";
import { ThreatVelocity } from "@/components/charts/threat-velocity";
import { RiskDistribution } from "@/components/charts/risk-distribution";
import { CotViewer } from "@/components/transparency/cot-viewer";
import { CommandBar } from "@/components/command-bar/command-bar";
import { useAlerts } from "@/hooks/use-alerts";

export default function Dashboard() {
  const { alerts, isLoading, isConnected } = useAlerts();

  const criticalCount = alerts.filter((a) => a.severity === "Critical").length;

  const handleCommand = (command: string) => {
    // The command bar sends commands to the chat.
    // Since ChatPanel manages its own state, we dispatch a custom event.
    window.dispatchEvent(
      new CustomEvent("soc-command", { detail: command })
    );
  };

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />

      <div className="flex flex-1 flex-col overflow-hidden">
        <Header isConnected={isConnected} alertCount={criticalCount} />

        <main className="flex flex-1 flex-col overflow-hidden">
          {/* Charts row */}
          <div className="grid grid-cols-2 gap-4 p-4 pb-2">
            <ThreatVelocity alerts={alerts} />
            <RiskDistribution alerts={alerts} />
          </div>

          {/* Dual pane: Alert Feed + Chat */}
          <div className="flex flex-1 gap-4 overflow-hidden px-4 pb-2">
            {/* Left: Alert feed */}
            <div className="flex w-2/5 flex-col overflow-hidden rounded-lg border border-border bg-card">
              <AlertFeed alerts={alerts} isLoading={isLoading} />
            </div>

            {/* Right: Chat panel */}
            <div className="flex w-3/5 flex-col overflow-hidden rounded-lg border border-border bg-card">
              <ChatPanel />
            </div>
          </div>

          {/* Chain of Thought */}
          <CotViewer />
        </main>
      </div>

      {/* CMD+K Command Bar */}
      <CommandBar onCommand={handleCommand} />
    </div>
  );
}

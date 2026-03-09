"use client";

import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";
import { AlertFeed } from "@/components/alerts/alert-feed";
import { useAlerts } from "@/hooks/use-alerts";

export default function IncidentsPage() {
  const { alerts, isLoading, isConnected } = useAlerts();

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header isConnected={isConnected} alertCount={alerts.length} />
        <main className="flex flex-1 flex-col overflow-hidden p-4">
          <h2 className="mb-4 text-lg font-semibold text-foreground">All Incidents</h2>
          <div className="flex-1 overflow-hidden rounded-lg border border-border bg-card">
            <AlertFeed alerts={alerts} isLoading={isLoading} />
          </div>
        </main>
      </div>
    </div>
  );
}

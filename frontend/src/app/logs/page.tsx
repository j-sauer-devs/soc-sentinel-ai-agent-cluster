"use client";

import { useEffect, useState, useCallback } from "react";
import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";
import { ScrollText, RefreshCw } from "lucide-react";
import { useAlerts } from "@/hooks/use-alerts";
import { formatTimestamp } from "@/lib/utils";

interface LogEntry {
  event: string;
  message: string;
  timestamp: string;
  source: string;
  source_ip: string;
  [key: string]: unknown;
}

export default function LogsPage() {
  const { alerts, isConnected } = useAlerts();
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/chat`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            messages: [{ role: "user", content: "Fetch logs from siem-primary for last_1h" }],
          }),
        }
      );
      const data = await res.json();

      // Extract logs from tool_calls if present
      if (data.tool_calls) {
        for (const tc of data.tool_calls) {
          if (tc.name === "fetch_logs" && tc.result?.logs) {
            setLogs(tc.result.logs);
            return;
          }
        }
      }
    } catch {
      // Fallback: generate some mock logs locally
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  const eventColors: Record<string, string> = {
    AUTH_FAILURE: "text-severity-critical",
    AUTH_SUCCESS: "text-severity-low",
    FIREWALL_BLOCK: "text-severity-high",
    DNS_QUERY: "text-severity-medium",
    FILE_WRITE: "text-severity-high",
    PROCESS_START: "text-severity-medium",
    NETWORK_CONN: "text-severity-medium",
    REGISTRY_MOD: "text-severity-high",
  };

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header isConnected={isConnected} alertCount={alerts.length} />
        <main className="flex flex-1 flex-col overflow-hidden p-4">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ScrollText className="h-5 w-5 text-primary" />
              <h2 className="text-lg font-semibold text-foreground">Log Viewer</h2>
            </div>
            <button
              onClick={fetchLogs}
              disabled={loading}
              className="flex items-center gap-1.5 rounded-md bg-muted px-3 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-muted/80 hover:text-foreground disabled:opacity-50"
            >
              <RefreshCw className={`h-3 w-3 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>

          <div className="flex-1 overflow-y-auto rounded-lg border border-border bg-card">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="px-4 py-2.5 font-medium">Time</th>
                  <th className="px-4 py-2.5 font-medium">Event</th>
                  <th className="px-4 py-2.5 font-medium">Source IP</th>
                  <th className="px-4 py-2.5 font-medium">Message</th>
                </tr>
              </thead>
              <tbody>
                {logs.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-4 py-8 text-center text-muted-foreground">
                      {loading ? "Loading logs..." : "No logs available. Click Refresh to pull SIEM logs."}
                    </td>
                  </tr>
                ) : (
                  logs.map((log, i) => (
                    <tr key={i} className="border-b border-border/50 hover:bg-muted/30 transition-colors">
                      <td className="px-4 py-2 font-mono text-muted-foreground whitespace-nowrap">
                        {formatTimestamp(log.timestamp)}
                      </td>
                      <td className={`px-4 py-2 font-mono font-medium ${eventColors[log.event] || "text-foreground"}`}>
                        {log.event}
                      </td>
                      <td className="px-4 py-2 font-mono text-muted-foreground">
                        {log.source_ip}
                      </td>
                      <td className="px-4 py-2 text-foreground/80">
                        {log.message}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </main>
      </div>
    </div>
  );
}

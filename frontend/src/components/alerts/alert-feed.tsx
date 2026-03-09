"use client";

import { useMemo, useState } from "react";
import { AlertCard } from "./alert-card";
import { SeverityBadge } from "./severity-badge";
import type { Alert, Severity } from "@/types";

const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low", "Noise"];

interface AlertFeedProps {
  alerts: Alert[];
  isLoading: boolean;
}

export function AlertFeed({ alerts, isLoading }: AlertFeedProps) {
  const [filter, setFilter] = useState<Severity | null>(null);

  const filteredAlerts = useMemo(() => {
    if (!filter) return alerts;
    return alerts.filter((a) => a.severity === filter);
  }, [alerts, filter]);

  // Severity counts for filter badges
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const a of alerts) {
      c[a.severity] = (c[a.severity] || 0) + 1;
    }
    return c;
  }, [alerts]);

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="text-sm text-muted-foreground">Loading alerts...</div>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-3">
        <button
          onClick={() => setFilter(null)}
          className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
            filter === null
              ? "bg-primary/15 text-primary"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          All ({alerts.length})
        </button>
        {SEVERITIES.map((sev) => (
          <button
            key={sev}
            onClick={() => setFilter(filter === sev ? null : sev)}
            className={`transition-opacity ${filter === sev ? "opacity-100" : "opacity-60 hover:opacity-100"}`}
          >
            <SeverityBadge severity={sev} />
            <span className="ml-1 text-xs text-muted-foreground">
              {counts[sev] || 0}
            </span>
          </button>
        ))}
      </div>

      {/* Alert list */}
      <div className="flex-1 space-y-2 overflow-y-auto p-4">
        {filteredAlerts.length === 0 ? (
          <div className="text-center text-sm text-muted-foreground py-8">
            No alerts matching filter.
          </div>
        ) : (
          filteredAlerts.map((alert) => (
            <AlertCard key={alert.id} alert={alert} />
          ))
        )}
      </div>
    </div>
  );
}

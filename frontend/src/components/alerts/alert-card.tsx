"use client";

import { useState } from "react";
import { ChevronDown, ChevronUp, FileText, Loader2 } from "lucide-react";
import { SeverityBadge } from "./severity-badge";
import { summarizeAlert } from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";
import type { Alert } from "@/types";

interface AlertCardProps {
  alert: Alert;
}

export function AlertCard({ alert }: AlertCardProps) {
  const [expanded, setExpanded] = useState(false);
  const [summary, setSummary] = useState<string | null>(null);
  const [summarizing, setSummarizing] = useState(false);

  const handleSummarize = async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (summary) return;
    setSummarizing(true);
    try {
      const res = await summarizeAlert(alert.id);
      setSummary(res.summary);
      setExpanded(true);
    } catch {
      setSummary("Failed to generate summary.");
    } finally {
      setSummarizing(false);
    }
  };

  return (
    <div className="animate-fade-in rounded-lg border border-border bg-card p-4 transition-colors hover:border-muted-foreground/30">
      {/* Top row */}
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <span className="text-xs text-muted-foreground">
              {formatRelativeTime(alert.timestamp)}
            </span>
          </div>
          <h3 className="mt-1.5 text-sm font-medium text-foreground">
            {alert.alert_type}
          </h3>
          <p className="mt-0.5 text-xs text-muted-foreground font-mono">
            {alert.source_ip} → {alert.dest_ip}
          </p>
        </div>

        <div className="flex items-center gap-1.5">
          {/* Summarize button */}
          <button
            onClick={handleSummarize}
            disabled={summarizing || !!summary}
            className="flex items-center gap-1 rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground transition-colors hover:bg-muted/80 hover:text-foreground disabled:opacity-50"
            title="Generate TL;DR"
          >
            {summarizing ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <FileText className="h-3 w-3" />
            )}
            TL;DR
          </button>

          {/* Expand/collapse */}
          <button
            onClick={() => setExpanded(!expanded)}
            className="rounded-md p-1 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
          >
            {expanded ? (
              <ChevronUp className="h-4 w-4" />
            ) : (
              <ChevronDown className="h-4 w-4" />
            )}
          </button>
        </div>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div className="mt-3 space-y-2 border-t border-border pt-3">
          <p className="text-xs text-muted-foreground leading-relaxed">
            {alert.description}
          </p>
          <div className="flex gap-4 text-xs text-muted-foreground/70">
            <span>ID: {alert.id}</span>
            <span>Status: {alert.status}</span>
          </div>
          {summary && (
            <div className="mt-2 rounded-md bg-primary/5 border border-primary/20 p-3">
              <p className="text-xs font-medium text-primary mb-1">AI Summary</p>
              <p className="text-xs text-foreground/80 leading-relaxed">{summary}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

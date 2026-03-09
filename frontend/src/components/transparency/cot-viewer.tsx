"use client";

import { useCallback, useState } from "react";
import {
  ChevronDown,
  ChevronUp,
  Play,
  Loader2,
  CheckCircle2,
  XCircle,
  Eye,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useWebSocket } from "@/hooks/use-websocket";
import { getWsUrl } from "@/lib/api";
import type { PipelineEvent } from "@/types";

const AGENT_COLORS: Record<string, string> = {
  commander: "text-agent-commander border-agent-commander/30 bg-agent-commander/10",
  triage: "text-agent-triage border-agent-triage/30 bg-agent-triage/10",
  threat_hunter: "text-agent-hunter border-agent-hunter/30 bg-agent-hunter/10",
  forensics: "text-agent-forensics border-agent-forensics/30 bg-agent-forensics/10",
  oversight: "text-agent-oversight border-agent-oversight/30 bg-agent-oversight/10",
  briefing: "text-agent-briefing border-agent-briefing/30 bg-agent-briefing/10",
  system: "text-muted-foreground border-border bg-muted/30",
};

const AGENT_LABELS: Record<string, string> = {
  commander: "Commander",
  triage: "Triage Officer",
  threat_hunter: "Threat Hunter",
  forensics: "Forensics Analyst",
  oversight: "Oversight Officer",
  briefing: "Briefing Writer",
  system: "System",
};

export function CotViewer() {
  const [isOpen, setIsOpen] = useState(false);
  const [events, setEvents] = useState<PipelineEvent[]>([]);
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);
  const [isRunning, setIsRunning] = useState(false);

  const handlePipelineMessage = useCallback((data: unknown) => {
    const event = data as PipelineEvent;
    setEvents((prev) => [...prev, event]);
    if (event.status === "complete" || event.status === "error") {
      setIsRunning(false);
    }
  }, []);

  const { send, isConnected } = useWebSocket({
    url: getWsUrl("/ws/pipeline"),
    onMessage: handlePipelineMessage,
    autoConnect: false,
  });

  const handleRun = () => {
    setEvents([]);
    setIsRunning(true);
    setIsOpen(true);

    // Send a sample alert batch to trigger the pipeline
    send({
      alerts: [
        {
          id: "ALERT-DEMO-001",
          source_ip: "185.220.101.34",
          dest_ip: "10.0.1.42",
          alert_type: "Suspicious Outbound Connection",
          description: "C2 beaconing detected",
        },
        {
          id: "ALERT-DEMO-002",
          source_ip: "91.219.236.222",
          dest_ip: "10.0.2.8",
          alert_type: "Brute Force Attempt",
          description: "500 failed SSH attempts in 10 minutes",
        },
      ],
    });
  };

  const StatusIcon = ({ status }: { status: string }) => {
    if (status === "running") return <Loader2 className="h-3.5 w-3.5 animate-spin" />;
    if (status === "done" || status === "complete") return <CheckCircle2 className="h-3.5 w-3.5" />;
    if (status === "error") return <XCircle className="h-3.5 w-3.5" />;
    return null;
  };

  return (
    <div className="border-t border-border bg-card">
      {/* Toggle bar */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex w-full items-center justify-between px-4 py-2.5 text-sm text-muted-foreground hover:text-foreground transition-colors"
      >
        <div className="flex items-center gap-2">
          <Eye className="h-4 w-4" />
          <span className="font-medium">Chain of Thought — Transparency Log</span>
          {events.length > 0 && (
            <span className="rounded-full bg-muted px-2 py-0.5 text-xs">
              {events.length} events
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {!isRunning && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleRun();
              }}
              className="flex items-center gap-1 rounded-md bg-primary/15 px-2.5 py-1 text-xs text-primary hover:bg-primary/25 transition-colors"
            >
              <Play className="h-3 w-3" />
              Run Pipeline
            </button>
          )}
          {isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronUp className="h-4 w-4" />}
        </div>
      </button>

      {/* Event log */}
      {isOpen && (
        <div className="max-h-80 overflow-y-auto border-t border-border px-4 py-3">
          {events.length === 0 ? (
            <p className="text-center text-xs text-muted-foreground py-6">
              Run the pipeline to see the agent execution trace.
            </p>
          ) : (
            <div className="space-y-1.5">
              {events.map((event, i) => {
                const colorClass = AGENT_COLORS[event.node] || AGENT_COLORS.system;
                const isExpanded = expandedIdx === i;

                return (
                  <div key={i} className="animate-fade-in">
                    <button
                      onClick={() => setExpandedIdx(isExpanded ? null : i)}
                      className={cn(
                        "flex w-full items-center gap-3 rounded-md border px-3 py-2 text-left text-xs transition-colors",
                        colorClass
                      )}
                    >
                      <StatusIcon status={event.status} />
                      <span className="font-semibold min-w-[110px]">
                        {AGENT_LABELS[event.node] || event.node}
                      </span>
                      <span className="flex-1 truncate opacity-80">
                        {event.step || event.message || ""}
                      </span>
                      {event.reasoning && (
                        <ChevronDown
                          className={cn(
                            "h-3 w-3 shrink-0 transition-transform",
                            isExpanded && "rotate-180"
                          )}
                        />
                      )}
                    </button>

                    {isExpanded && event.reasoning && (
                      <div className="mt-1 ml-6 rounded-md bg-muted/30 border border-border p-3 text-xs text-muted-foreground font-mono whitespace-pre-wrap leading-relaxed">
                        {event.reasoning}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

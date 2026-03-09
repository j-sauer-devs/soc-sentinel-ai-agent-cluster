"use client";

import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";
import { Settings, Bot, Shield, Zap, Database } from "lucide-react";
import { useAlerts } from "@/hooks/use-alerts";

const AGENTS = [
  {
    name: "Commander",
    description: "Orchestrates alert routing and re-investigation loops",
    icon: Zap,
    color: "text-agent-commander",
    status: "Active",
  },
  {
    name: "Triage Officer",
    description: "Classifies alert severity via AbuseIPDB + GreyNoise",
    icon: Shield,
    color: "text-agent-triage",
    status: "Active",
  },
  {
    name: "Threat Hunter",
    description: "IOC enrichment via OTX + VirusTotal",
    icon: Database,
    color: "text-agent-hunter",
    status: "Active",
  },
  {
    name: "Forensics Analyst",
    description: "Kill chain reconstruction + NVD CVE lookup",
    icon: Shield,
    color: "text-agent-forensics",
    status: "Active",
  },
  {
    name: "Oversight Officer",
    description: "K2 Think V2 cross-verification + conflict detection",
    icon: Bot,
    color: "text-agent-oversight",
    status: "Active",
  },
  {
    name: "Briefing Writer",
    description: "Final report and severity summary generation",
    icon: Bot,
    color: "text-agent-briefing",
    status: "Active",
  },
];

export default function SettingsPage() {
  const { alerts, isConnected } = useAlerts();

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header isConnected={isConnected} alertCount={alerts.length} />
        <main className="flex-1 overflow-y-auto p-6">
          <div className="flex items-center gap-2 mb-6">
            <Settings className="h-5 w-5 text-primary" />
            <h2 className="text-lg font-semibold text-foreground">Agent Settings</h2>
          </div>

          {/* LLM Config */}
          <div className="mb-6 rounded-lg border border-border bg-card p-5">
            <h3 className="text-sm font-semibold text-foreground mb-3">LLM Configuration</h3>
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div>
                <span className="text-muted-foreground">Model:</span>
                <span className="ml-2 font-mono text-foreground">K2 Think V2</span>
              </div>
              <div>
                <span className="text-muted-foreground">Model ID:</span>
                <span className="ml-2 font-mono text-foreground">MBZUAI-IFM/K2-Think-v2</span>
              </div>
              <div>
                <span className="text-muted-foreground">API Base:</span>
                <span className="ml-2 font-mono text-foreground">https://api.k2think.ai/v1</span>
              </div>
              <div>
                <span className="text-muted-foreground">Max Tokens:</span>
                <span className="ml-2 font-mono text-foreground">2000</span>
              </div>
            </div>
          </div>

          {/* Pipeline Config */}
          <div className="mb-6 rounded-lg border border-border bg-card p-5">
            <h3 className="text-sm font-semibold text-foreground mb-3">Pipeline Configuration</h3>
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div>
                <span className="text-muted-foreground">Max Re-investigation Loops:</span>
                <span className="ml-2 font-mono text-foreground">3</span>
              </div>
              <div>
                <span className="text-muted-foreground">Confidence Threshold:</span>
                <span className="ml-2 font-mono text-foreground">70%</span>
              </div>
              <div>
                <span className="text-muted-foreground">Data Mode:</span>
                <span className="ml-2 font-mono text-primary">Mock Data</span>
              </div>
              <div>
                <span className="text-muted-foreground">Alert Stream Interval:</span>
                <span className="ml-2 font-mono text-foreground">3-8s</span>
              </div>
            </div>
          </div>

          {/* Agent roster */}
          <h3 className="text-sm font-semibold text-foreground mb-3">Agent Roster</h3>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {AGENTS.map((agent) => (
              <div
                key={agent.name}
                className="flex items-start gap-3 rounded-lg border border-border bg-card p-4"
              >
                <div className={`mt-0.5 ${agent.color}`}>
                  <agent.icon className="h-4 w-4" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-foreground">
                      {agent.name}
                    </span>
                    <span className="rounded-full bg-severity-low/15 px-2 py-0.5 text-[10px] text-severity-low font-medium">
                      {agent.status}
                    </span>
                  </div>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {agent.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </main>
      </div>
    </div>
  );
}

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Noise";

export type AlertStatus = "new" | "investigating" | "resolved" | "false_positive";

export interface Alert {
  id: string;
  source_ip: string;
  dest_ip: string;
  alert_type: string;
  severity: Severity;
  description: string;
  timestamp: string;
  status: AlertStatus;
}

export interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
  result?: unknown;
}

export interface ChatMessage {
  role: "user" | "assistant" | "system";
  content: string;
  reasoning?: string | null;
  tool_calls?: ToolCall[] | null;
}

export interface ChatResponse {
  reply: string;
  reasoning?: string | null;
  tool_calls?: ToolCall[] | null;
  requires_approval?: { tool: string; args: Record<string, unknown> } | null;
}

export interface PipelineEvent {
  node: string;
  status: "running" | "done" | "error" | "complete";
  step?: string;
  timestamp?: string;
  alert_id?: string;
  severity?: string;
  reasoning?: string;
  verdict?: string;
  confidence?: number;
  briefing?: string;
  message?: string;
}

export interface SummarizeResponse {
  alert_id: string;
  summary: string;
}

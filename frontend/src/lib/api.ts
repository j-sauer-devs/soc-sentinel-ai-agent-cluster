const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export async function fetchAlerts() {
  const res = await fetch(`${API_BASE}/api/alerts`);
  if (!res.ok) throw new Error("Failed to fetch alerts");
  return res.json();
}

export async function summarizeAlert(alertId: string) {
  const res = await fetch(`${API_BASE}/api/alerts/${alertId}/summarize`, {
    method: "POST",
  });
  if (!res.ok) throw new Error("Failed to summarize alert");
  return res.json();
}

export async function sendChat(messages: { role: string; content: string }[], pendingApproval?: unknown) {
  const res = await fetch(`${API_BASE}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      messages,
      pending_approval: pendingApproval ?? null,
    }),
  });
  if (!res.ok) throw new Error("Failed to send chat message");
  return res.json();
}

export async function runPipeline(alerts: unknown[]) {
  const res = await fetch(`${API_BASE}/api/pipeline/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ alerts }),
  });
  if (!res.ok) throw new Error("Failed to run pipeline");
  return res.json();
}

export function getWsUrl(path: string): string {
  const base = API_BASE.replace(/^http/, "ws");
  return `${base}${path}`;
}

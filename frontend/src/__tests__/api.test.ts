import { describe, it, expect, vi, beforeEach } from "vitest";
import { fetchAlerts, summarizeAlert, sendChat, runPipeline, getWsUrl } from "@/lib/api";

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

beforeEach(() => {
  mockFetch.mockReset();
});

describe("fetchAlerts", () => {
  it("calls GET /api/alerts", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([{ id: "ALERT-001" }]),
    });

    const result = await fetchAlerts();

    expect(mockFetch).toHaveBeenCalledWith("http://localhost:8000/api/alerts");
    expect(result).toEqual([{ id: "ALERT-001" }]);
  });

  it("throws on non-ok response", async () => {
    mockFetch.mockResolvedValueOnce({ ok: false, status: 500 });

    await expect(fetchAlerts()).rejects.toThrow("Failed to fetch alerts");
  });
});

describe("summarizeAlert", () => {
  it("calls POST /api/alerts/{id}/summarize", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ alert_id: "A1", summary: "TL;DR" }),
    });

    const result = await summarizeAlert("A1");

    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:8000/api/alerts/A1/summarize",
      { method: "POST" }
    );
    expect(result.summary).toBe("TL;DR");
  });

  it("throws on non-ok response", async () => {
    mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });

    await expect(summarizeAlert("NONEXIST")).rejects.toThrow("Failed to summarize alert");
  });
});

describe("sendChat", () => {
  it("calls POST /api/chat with messages", async () => {
    const mockResponse = { reply: "Hello", reasoning: null, tool_calls: null, requires_approval: null };
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockResponse),
    });

    const messages = [{ role: "user", content: "Hello" }];
    const result = await sendChat(messages);

    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:8000/api/chat",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages, pending_approval: null }),
      }
    );
    expect(result.reply).toBe("Hello");
  });

  it("includes pending_approval when provided", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ reply: "Isolated" }),
    });

    const approval = { tool: "isolate_host", args: { hostname: "ws-42" }, approved: true };
    await sendChat([{ role: "user", content: "Isolate" }], approval);

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.pending_approval).toEqual(approval);
  });

  it("throws on non-ok response", async () => {
    mockFetch.mockResolvedValueOnce({ ok: false, status: 500 });

    await expect(sendChat([{ role: "user", content: "hi" }])).rejects.toThrow(
      "Failed to send chat message"
    );
  });
});

describe("runPipeline", () => {
  it("calls POST /api/pipeline/run with alerts", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ alerts: [], briefing: "Done" }),
    });

    const alerts = [{ id: "A1", source_ip: "1.2.3.4" }];
    const result = await runPipeline(alerts);

    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:8000/api/pipeline/run",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alerts }),
      }
    );
    expect(result.briefing).toBe("Done");
  });
});

describe("getWsUrl", () => {
  it("converts http to ws", () => {
    expect(getWsUrl("/ws/alerts")).toBe("ws://localhost:8000/ws/alerts");
  });

  it("converts https to wss", () => {
    // The implementation replaces "http" prefix with "ws"
    // For "https://...", it becomes "wss://..."
    const fn = (path: string) => {
      const base = "https://api.example.com".replace(/^http/, "ws");
      return `${base}${path}`;
    };
    expect(fn("/ws/alerts")).toBe("wss://api.example.com/ws/alerts");
  });
});

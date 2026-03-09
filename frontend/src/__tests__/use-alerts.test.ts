import { renderHook, act, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { useAlerts } from "@/hooks/use-alerts";
import type { Alert } from "@/types";

// Mock dependencies
vi.mock("@/lib/api", () => ({
  fetchAlerts: vi.fn(),
  getWsUrl: vi.fn().mockReturnValue("ws://localhost:8000/ws/alerts"),
  sendChat: vi.fn(),
  summarizeAlert: vi.fn(),
  runPipeline: vi.fn(),
}));

let capturedOnMessage: ((data: unknown) => void) | undefined;

vi.mock("@/hooks/use-websocket", () => ({
  useWebSocket: vi.fn().mockImplementation(({ onMessage }: { onMessage?: (data: unknown) => void }) => {
    capturedOnMessage = onMessage;
    return {
      isConnected: true,
      send: vi.fn(),
      connect: vi.fn(),
      disconnect: vi.fn(),
    };
  }),
}));

import { fetchAlerts } from "@/lib/api";
const mockFetchAlerts = vi.mocked(fetchAlerts);

const makeAlert = (id: string, severity = "Medium" as const): Alert => ({
  id,
  source_ip: "1.2.3.4",
  dest_ip: "10.0.0.1",
  alert_type: "Test Alert",
  severity,
  description: "Test description",
  timestamp: new Date().toISOString(),
  status: "new",
});

beforeEach(() => {
  vi.clearAllMocks();
  capturedOnMessage = undefined;
});

describe("useAlerts", () => {
  it("starts in loading state", () => {
    mockFetchAlerts.mockReturnValue(new Promise(() => {})); // never resolves
    const { result } = renderHook(() => useAlerts());
    expect(result.current.isLoading).toBe(true);
    expect(result.current.alerts).toEqual([]);
    expect(result.current.error).toBeNull();
  });

  it("fetches alerts on mount", async () => {
    const alerts = [makeAlert("A-1"), makeAlert("A-2")];
    mockFetchAlerts.mockResolvedValueOnce(alerts);

    const { result } = renderHook(() => useAlerts());

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    expect(result.current.alerts).toHaveLength(2);
    expect(result.current.alerts[0].id).toBe("A-1");
  });

  it("sets error on fetch failure", async () => {
    mockFetchAlerts.mockRejectedValueOnce(new Error("Network error"));

    const { result } = renderHook(() => useAlerts());

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    expect(result.current.error).toBe("Network error");
    expect(result.current.alerts).toEqual([]);
  });

  it("reflects WebSocket connection state", async () => {
    mockFetchAlerts.mockResolvedValueOnce([]);

    const { result } = renderHook(() => useAlerts());

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    // Our mock always returns isConnected: true
    expect(result.current.isConnected).toBe(true);
  });

  it("WebSocket message prepends new alert", async () => {
    const initialAlerts = [makeAlert("A-1")];
    mockFetchAlerts.mockResolvedValueOnce(initialAlerts);

    const { result } = renderHook(() => useAlerts());

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    // Simulate WebSocket message
    const newAlert = makeAlert("A-NEW", "Critical");
    act(() => {
      capturedOnMessage?.({ type: "new_alert", data: newAlert });
    });

    expect(result.current.alerts).toHaveLength(2);
    expect(result.current.alerts[0].id).toBe("A-NEW");
    expect(result.current.alerts[1].id).toBe("A-1");
  });

  it("enforces 200-alert limit", async () => {
    const manyAlerts = Array.from({ length: 200 }, (_, i) => makeAlert(`A-${i}`));
    mockFetchAlerts.mockResolvedValueOnce(manyAlerts);

    const { result } = renderHook(() => useAlerts());

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    // Add one more via WebSocket
    act(() => {
      capturedOnMessage?.({ type: "new_alert", data: makeAlert("A-OVERFLOW") });
    });

    expect(result.current.alerts).toHaveLength(200);
    expect(result.current.alerts[0].id).toBe("A-OVERFLOW");
  });

  it("ignores non-new_alert WebSocket messages", async () => {
    mockFetchAlerts.mockResolvedValueOnce([makeAlert("A-1")]);

    const { result } = renderHook(() => useAlerts());

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    act(() => {
      capturedOnMessage?.({ type: "heartbeat", data: {} });
    });

    expect(result.current.alerts).toHaveLength(1);
  });
});

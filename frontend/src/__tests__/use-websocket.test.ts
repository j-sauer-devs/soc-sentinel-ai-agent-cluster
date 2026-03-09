import { renderHook, act } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach, afterEach } from "vitest";
import { useWebSocket } from "@/hooks/use-websocket";

// ---------------------------------------------------------------------------
// MockWebSocket — must be a real class so `new WebSocket()` works
// ---------------------------------------------------------------------------

type WSHandler = ((ev: { data: string }) => void) | null;

let wsInstances: MockWebSocket[] = [];

class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState = MockWebSocket.CONNECTING;
  onopen: (() => void) | null = null;
  onmessage: WSHandler = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;

  url: string;
  sentMessages: string[] = [];

  constructor(url: string) {
    this.url = url;
    wsInstances.push(this);
    // Simulate async open
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      this.onopen?.();
    }, 0);
  }

  send(data: string) {
    this.sentMessages.push(data);
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.();
  }

  // Test helpers
  simulateMessage(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) });
  }

  simulateError() {
    this.onerror?.();
  }
}

// ---------------------------------------------------------------------------
// Setup / Teardown
// ---------------------------------------------------------------------------

const OriginalWebSocket = globalThis.WebSocket;

beforeEach(() => {
  wsInstances = [];
  vi.useFakeTimers();

  // Replace global WebSocket with the MockWebSocket class directly
  globalThis.WebSocket = MockWebSocket as unknown as typeof WebSocket;
});

afterEach(() => {
  vi.useRealTimers();
  globalThis.WebSocket = OriginalWebSocket;
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("useWebSocket", () => {
  it("connects on mount when autoConnect is true", async () => {
    renderHook(() =>
      useWebSocket({ url: "ws://localhost:8000/ws/test", autoConnect: true })
    );
    expect(wsInstances.length).toBe(1);
    expect(wsInstances[0].url).toBe("ws://localhost:8000/ws/test");
  });

  it("does not connect when autoConnect is false", () => {
    renderHook(() =>
      useWebSocket({ url: "ws://localhost:8000/ws/test", autoConnect: false })
    );
    expect(wsInstances.length).toBe(0);
  });

  it("sets isConnected to true on open", async () => {
    const { result } = renderHook(() =>
      useWebSocket({ url: "ws://localhost:8000/ws/test" })
    );

    expect(result.current.isConnected).toBe(false);

    // Trigger the setTimeout that calls onopen
    await act(async () => {
      vi.runAllTimers();
    });

    expect(result.current.isConnected).toBe(true);
  });

  it("calls onMessage with parsed JSON data", async () => {
    const onMessage = vi.fn();
    renderHook(() =>
      useWebSocket({ url: "ws://localhost:8000/ws/test", onMessage })
    );

    await act(async () => {
      vi.runAllTimers();
    });

    act(() => {
      wsInstances[0].simulateMessage({ type: "test", value: 42 });
    });

    expect(onMessage).toHaveBeenCalledWith({ type: "test", value: 42 });
  });

  it("handles non-JSON messages gracefully", async () => {
    const onMessage = vi.fn();
    renderHook(() =>
      useWebSocket({ url: "ws://localhost:8000/ws/test", onMessage })
    );

    await act(async () => {
      vi.runAllTimers();
    });

    // Send invalid JSON
    act(() => {
      wsInstances[0].onmessage?.({ data: "not-json" });
    });

    expect(onMessage).not.toHaveBeenCalled();
  });

  it("reconnects after close", async () => {
    renderHook(() =>
      useWebSocket({
        url: "ws://localhost:8000/ws/test",
        reconnectDelay: 1000,
      })
    );

    // Initial connect
    await act(async () => {
      vi.runAllTimers();
    });
    expect(wsInstances.length).toBe(1);

    // Simulate close
    act(() => {
      wsInstances[0].close();
    });

    // Advance past reconnect delay
    await act(async () => {
      vi.advanceTimersByTime(1000);
    });

    expect(wsInstances.length).toBe(2);
  });

  it("send() sends JSON when connected", async () => {
    const { result } = renderHook(() =>
      useWebSocket({ url: "ws://localhost:8000/ws/test" })
    );

    await act(async () => {
      vi.runAllTimers();
    });

    act(() => {
      result.current.send({ hello: "world" });
    });

    expect(wsInstances[0].sentMessages).toContain(
      JSON.stringify({ hello: "world" })
    );
  });

  it("send() does nothing when disconnected", () => {
    const { result } = renderHook(() =>
      useWebSocket({ url: "ws://localhost:8000/ws/test", autoConnect: false })
    );

    act(() => {
      result.current.send({ hello: "world" });
    });

    // No WebSocket created, so nothing sent
    expect(wsInstances.length).toBe(0);
  });

  it("disconnect clears timer and closes", async () => {
    const { result } = renderHook(() =>
      useWebSocket({ url: "ws://localhost:8000/ws/test" })
    );

    await act(async () => {
      vi.runAllTimers();
    });

    act(() => {
      result.current.disconnect();
    });

    expect(result.current.isConnected).toBe(false);
  });

  it("cleans up on unmount", async () => {
    const { unmount } = renderHook(() =>
      useWebSocket({ url: "ws://localhost:8000/ws/test" })
    );

    await act(async () => {
      vi.runAllTimers();
    });

    expect(wsInstances.length).toBe(1);
    unmount();
    // WebSocket should have been closed
    expect(wsInstances[0].readyState).toBe(MockWebSocket.CLOSED);
  });
});

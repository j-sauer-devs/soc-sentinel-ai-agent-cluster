"use client";

import { useCallback, useEffect, useState } from "react";
import { fetchAlerts } from "@/lib/api";
import { getWsUrl } from "@/lib/api";
import { useWebSocket } from "@/hooks/use-websocket";
import type { Alert } from "@/types";

export function useAlerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Initial fetch
  useEffect(() => {
    fetchAlerts()
      .then((data) => {
        setAlerts(data);
        setIsLoading(false);
      })
      .catch((e) => {
        setError(e.message);
        setIsLoading(false);
      });
  }, []);

  // WebSocket for live updates
  const handleWsMessage = useCallback((data: unknown) => {
    const msg = data as { type: string; data: Alert };
    if (msg.type === "new_alert") {
      setAlerts((prev) => [msg.data, ...prev].slice(0, 200));
    }
  }, []);

  const { isConnected } = useWebSocket({
    url: getWsUrl("/ws/alerts"),
    onMessage: handleWsMessage,
  });

  return { alerts, isLoading, error, isConnected };
}

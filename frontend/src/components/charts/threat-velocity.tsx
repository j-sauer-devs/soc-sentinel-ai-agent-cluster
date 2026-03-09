"use client";

import { useMemo } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import type { Alert } from "@/types";

interface ThreatVelocityProps {
  alerts: Alert[];
}

export function ThreatVelocity({ alerts }: ThreatVelocityProps) {
  const data = useMemo(() => {
    const now = Date.now();
    const buckets: Record<string, Record<string, number>> = {};

    // Create 24 hourly buckets
    for (let i = 23; i >= 0; i--) {
      const hour = new Date(now - i * 3600000);
      const key = hour.toLocaleTimeString("en-US", { hour: "2-digit", hour12: false }) + ":00";
      buckets[key] = { Critical: 0, High: 0, Medium: 0, Low: 0, Noise: 0 };
    }

    // Fill buckets
    for (const alert of alerts) {
      const ts = new Date(alert.timestamp);
      const key = ts.toLocaleTimeString("en-US", { hour: "2-digit", hour12: false }) + ":00";
      if (buckets[key]) {
        buckets[key][alert.severity] = (buckets[key][alert.severity] || 0) + 1;
      }
    }

    return Object.entries(buckets).map(([time, counts]) => ({
      time,
      ...counts,
    }));
  }, [alerts]);

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <h3 className="mb-3 text-sm font-semibold text-foreground">
        Threat Velocity (24h)
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
          <XAxis
            dataKey="time"
            tick={{ fontSize: 10, fill: "var(--muted-foreground)" }}
            interval="preserveStartEnd"
          />
          <YAxis
            tick={{ fontSize: 10, fill: "var(--muted-foreground)" }}
            allowDecimals={false}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "var(--card)",
              border: "1px solid var(--border)",
              borderRadius: "8px",
              fontSize: "12px",
            }}
          />
          <Legend iconSize={8} wrapperStyle={{ fontSize: "11px" }} />
          <Line type="monotone" dataKey="Critical" stroke="var(--severity-critical)" strokeWidth={2} dot={false} />
          <Line type="monotone" dataKey="High" stroke="var(--severity-high)" strokeWidth={2} dot={false} />
          <Line type="monotone" dataKey="Medium" stroke="var(--severity-medium)" strokeWidth={1.5} dot={false} />
          <Line type="monotone" dataKey="Low" stroke="var(--severity-low)" strokeWidth={1} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

"use client";

import { useMemo } from "react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
} from "recharts";
import type { Alert, Severity } from "@/types";

const COLORS: Record<Severity, string> = {
  Critical: "var(--severity-critical)",
  High: "var(--severity-high)",
  Medium: "var(--severity-medium)",
  Low: "var(--severity-low)",
  Noise: "var(--severity-noise)",
};

interface RiskDistributionProps {
  alerts: Alert[];
}

export function RiskDistribution({ alerts }: RiskDistributionProps) {
  const data = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const alert of alerts) {
      counts[alert.severity] = (counts[alert.severity] || 0) + 1;
    }
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => {
        const order = ["Critical", "High", "Medium", "Low", "Noise"];
        return order.indexOf(a.name) - order.indexOf(b.name);
      });
  }, [alerts]);

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <h3 className="mb-3 text-sm font-semibold text-foreground">
        Risk Distribution
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={50}
            outerRadius={75}
            paddingAngle={3}
            dataKey="value"
          >
            {data.map((entry) => (
              <Cell
                key={entry.name}
                fill={COLORS[entry.name as Severity] || COLORS.Noise}
              />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: "var(--card)",
              border: "1px solid var(--border)",
              borderRadius: "8px",
              fontSize: "12px",
            }}
          />
          <Legend iconSize={8} wrapperStyle={{ fontSize: "11px" }} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

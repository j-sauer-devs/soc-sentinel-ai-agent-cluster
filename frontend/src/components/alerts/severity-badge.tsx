import { cn } from "@/lib/utils";
import type { Severity } from "@/types";

const SEVERITY_CONFIG: Record<Severity, { bg: string; text: string; dot: string }> = {
  Critical: { bg: "bg-severity-critical/15", text: "text-severity-critical", dot: "bg-severity-critical" },
  High: { bg: "bg-severity-high/15", text: "text-severity-high", dot: "bg-severity-high" },
  Medium: { bg: "bg-severity-medium/15", text: "text-severity-medium", dot: "bg-severity-medium" },
  Low: { bg: "bg-severity-low/15", text: "text-severity-low", dot: "bg-severity-low" },
  Noise: { bg: "bg-severity-noise/15", text: "text-severity-noise", dot: "bg-severity-noise" },
};

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const config = SEVERITY_CONFIG[severity] ?? SEVERITY_CONFIG.Noise;

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium",
        config.bg,
        config.text,
        className
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", config.dot)} />
      {severity}
    </span>
  );
}

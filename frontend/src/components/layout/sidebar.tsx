"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
  AlertTriangle,
  Search,
  ScrollText,
  Settings,
  Activity,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard", icon: Shield },
  { href: "/incidents", label: "Incidents", icon: AlertTriangle },
  { href: "/threat-hunting", label: "Threat Hunting", icon: Search },
  { href: "/logs", label: "Logs", icon: ScrollText },
  { href: "/settings", label: "Agent Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="flex h-screen w-64 flex-col border-r border-border bg-card">
      {/* Logo */}
      <div className="flex items-center gap-3 border-b border-border px-6 py-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/20">
          <Activity className="h-5 w-5 text-primary" />
        </div>
        <div>
          <h1 className="text-sm font-bold text-foreground">SOC Sentinel</h1>
          <p className="text-xs text-muted-foreground">AI Agent Cluster</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 px-3 py-4">
        {NAV_ITEMS.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors",
                isActive
                  ? "bg-primary/10 text-primary font-medium"
                  : "text-muted-foreground hover:bg-accent hover:text-foreground"
              )}
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t border-border px-6 py-4">
        <div className="flex items-center gap-2">
          <div className="h-2 w-2 rounded-full bg-primary animate-pulse-dot" />
          <span className="text-xs text-muted-foreground">System Online</span>
        </div>
        <p className="mt-1 text-xs text-muted-foreground/60">
          K2 Think V2 Connected
        </p>
      </div>
    </aside>
  );
}

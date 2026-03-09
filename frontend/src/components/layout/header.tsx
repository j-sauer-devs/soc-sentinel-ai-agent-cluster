"use client";

import { Bell, Wifi, WifiOff } from "lucide-react";

interface HeaderProps {
  isConnected: boolean;
  alertCount: number;
}

export function Header({ isConnected, alertCount }: HeaderProps) {
  return (
    <header className="flex h-14 items-center justify-between border-b border-border bg-card px-6">
      <div className="flex items-center gap-4">
        <h2 className="text-sm font-semibold text-foreground">
          Security Operations Dashboard
        </h2>
        <span className="rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground">
          Live
        </span>
      </div>

      <div className="flex items-center gap-4">
        {/* Connection status */}
        <div className="flex items-center gap-2 text-xs">
          {isConnected ? (
            <>
              <Wifi className="h-3.5 w-3.5 text-primary" />
              <span className="text-primary">Connected</span>
            </>
          ) : (
            <>
              <WifiOff className="h-3.5 w-3.5 text-severity-critical" />
              <span className="text-severity-critical">Disconnected</span>
            </>
          )}
        </div>

        {/* Alert count */}
        <div className="relative">
          <Bell className="h-4 w-4 text-muted-foreground" />
          {alertCount > 0 && (
            <span className="absolute -right-1.5 -top-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-severity-critical px-1 text-[10px] font-bold text-white">
              {alertCount > 99 ? "99+" : alertCount}
            </span>
          )}
        </div>
      </div>
    </header>
  );
}

"use client";

import { ShieldAlert, Check, X } from "lucide-react";

interface ApprovalDialogProps {
  tool: string;
  args: Record<string, unknown>;
  onApprove: () => void;
  onDeny: () => void;
}

export function ApprovalDialog({ tool, args, onApprove, onDeny }: ApprovalDialogProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-xl border border-severity-high/30 bg-card p-6 shadow-2xl">
        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-severity-high/15">
            <ShieldAlert className="h-5 w-5 text-severity-high" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-foreground">
              Manual Approval Required
            </h3>
            <p className="text-xs text-muted-foreground">
              SOC Sentinel is requesting a protected action
            </p>
          </div>
        </div>

        {/* Action details */}
        <div className="mt-4 rounded-lg bg-muted/50 border border-border p-4">
          <p className="text-xs font-medium text-muted-foreground mb-2">
            Requested Action
          </p>
          <p className="text-sm font-mono text-severity-high">
            {tool}({JSON.stringify(args)})
          </p>
          {tool === "isolate_host" && (
            <p className="mt-2 text-xs text-muted-foreground leading-relaxed">
              This will disconnect the host from the network, block all
              inbound/outbound traffic, and notify the SOC team.
            </p>
          )}
        </div>

        {/* Buttons */}
        <div className="mt-5 flex gap-3">
          <button
            onClick={onDeny}
            className="flex flex-1 items-center justify-center gap-2 rounded-lg border border-border bg-card px-4 py-2.5 text-sm font-medium text-foreground transition-colors hover:bg-muted"
          >
            <X className="h-4 w-4" />
            Deny
          </button>
          <button
            onClick={onApprove}
            className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-severity-high px-4 py-2.5 text-sm font-bold text-white transition-colors hover:bg-severity-high/90"
          >
            <Check className="h-4 w-4" />
            Approve
          </button>
        </div>
      </div>
    </div>
  );
}

import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { ApprovalDialog } from "@/components/chat/approval-dialog";

describe("ApprovalDialog", () => {
  const defaultProps = {
    tool: "isolate_host",
    args: { hostname: "workstation-42" },
    onApprove: vi.fn(),
    onDeny: vi.fn(),
  };

  it("renders the approval dialog", () => {
    render(<ApprovalDialog {...defaultProps} />);
    expect(screen.getByText("Manual Approval Required")).toBeInTheDocument();
  });

  it("shows the tool name and arguments", () => {
    render(<ApprovalDialog {...defaultProps} />);
    expect(screen.getByText(/isolate_host/)).toBeInTheDocument();
    expect(screen.getByText(/workstation-42/)).toBeInTheDocument();
  });

  it("shows isolation explanation for isolate_host", () => {
    render(<ApprovalDialog {...defaultProps} />);
    expect(
      screen.getByText(/disconnect the host from the network/)
    ).toBeInTheDocument();
  });

  it("calls onApprove when Approve clicked", () => {
    render(<ApprovalDialog {...defaultProps} />);
    fireEvent.click(screen.getByText("Approve"));
    expect(defaultProps.onApprove).toHaveBeenCalledOnce();
  });

  it("calls onDeny when Deny clicked", () => {
    render(<ApprovalDialog {...defaultProps} />);
    fireEvent.click(screen.getByText("Deny"));
    expect(defaultProps.onDeny).toHaveBeenCalledOnce();
  });

  it("shows Requested Action label", () => {
    render(<ApprovalDialog {...defaultProps} />);
    expect(screen.getByText("Requested Action")).toBeInTheDocument();
  });
});

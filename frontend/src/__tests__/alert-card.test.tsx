import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { AlertCard } from "@/components/alerts/alert-card";
import type { Alert } from "@/types";

const mockAlert: Alert = {
  id: "ALERT-TEST-001",
  source_ip: "10.0.1.15",
  dest_ip: "45.33.32.156",
  alert_type: "Brute Force Attempt",
  severity: "Critical",
  description: "500 failed SSH login attempts detected",
  timestamp: new Date().toISOString(),
  status: "new",
};

// Mock the api module
vi.mock("@/lib/api", () => ({
  summarizeAlert: vi.fn().mockResolvedValue({
    alert_id: "ALERT-TEST-001",
    summary: "This is a critical brute force attack.",
  }),
}));

describe("AlertCard", () => {
  it("renders alert type", () => {
    render(<AlertCard alert={mockAlert} />);
    expect(screen.getByText("Brute Force Attempt")).toBeInTheDocument();
  });

  it("renders severity badge", () => {
    render(<AlertCard alert={mockAlert} />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("renders IP addresses", () => {
    render(<AlertCard alert={mockAlert} />);
    expect(screen.getByText("10.0.1.15 → 45.33.32.156")).toBeInTheDocument();
  });

  it("shows TL;DR button", () => {
    render(<AlertCard alert={mockAlert} />);
    expect(screen.getByText("TL;DR")).toBeInTheDocument();
  });

  it("expands to show description when chevron clicked", () => {
    render(<AlertCard alert={mockAlert} />);

    // Description should not be visible initially
    expect(screen.queryByText(/500 failed SSH/)).not.toBeInTheDocument();

    // Click the expand button (find the button that doesn't say TL;DR)
    const buttons = screen.getAllByRole("button");
    const expandButton = buttons.find(
      (b) => !b.textContent?.includes("TL;DR")
    );
    if (expandButton) fireEvent.click(expandButton);

    expect(screen.getByText(/500 failed SSH/)).toBeInTheDocument();
  });

  it("calls summarize API when TL;DR clicked", async () => {
    render(<AlertCard alert={mockAlert} />);

    const tldrButton = screen.getByText("TL;DR").closest("button")!;
    fireEvent.click(tldrButton);

    await waitFor(() => {
      expect(screen.getByText("AI Summary")).toBeInTheDocument();
      expect(
        screen.getByText("This is a critical brute force attack.")
      ).toBeInTheDocument();
    });
  });
});

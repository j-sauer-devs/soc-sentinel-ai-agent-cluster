import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { AlertFeed } from "@/components/alerts/alert-feed";
import type { Alert } from "@/types";

const mockAlerts: Alert[] = [
  {
    id: "A1",
    source_ip: "10.0.1.1",
    dest_ip: "1.2.3.4",
    alert_type: "Brute Force",
    severity: "Critical",
    description: "test critical",
    timestamp: new Date().toISOString(),
    status: "new",
  },
  {
    id: "A2",
    source_ip: "10.0.1.2",
    dest_ip: "5.6.7.8",
    alert_type: "Port Scan",
    severity: "Low",
    description: "test low",
    timestamp: new Date().toISOString(),
    status: "new",
  },
  {
    id: "A3",
    source_ip: "10.0.1.3",
    dest_ip: "9.9.9.9",
    alert_type: "DNS Anomaly",
    severity: "Medium",
    description: "test medium",
    timestamp: new Date().toISOString(),
    status: "new",
  },
];

describe("AlertFeed", () => {
  it("renders loading state", () => {
    render(<AlertFeed alerts={[]} isLoading={true} />);
    expect(screen.getByText("Loading alerts...")).toBeInTheDocument();
  });

  it("renders alerts", () => {
    render(<AlertFeed alerts={mockAlerts} isLoading={false} />);
    expect(screen.getByText("Brute Force")).toBeInTheDocument();
    expect(screen.getByText("Port Scan")).toBeInTheDocument();
    expect(screen.getByText("DNS Anomaly")).toBeInTheDocument();
  });

  it("shows All button with total count", () => {
    render(<AlertFeed alerts={mockAlerts} isLoading={false} />);
    expect(screen.getByText(`All (${mockAlerts.length})`)).toBeInTheDocument();
  });

  it("shows severity filter badges", () => {
    render(<AlertFeed alerts={mockAlerts} isLoading={false} />);
    // Use getAllByText since severity text appears in both filter badges and alert cards
    expect(screen.getAllByText("Critical").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("Low").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("Medium").length).toBeGreaterThanOrEqual(1);
  });

  it("filters by severity when badge clicked", () => {
    render(<AlertFeed alerts={mockAlerts} isLoading={false} />);

    // Click on "Critical" severity badge filter
    const criticalButtons = screen.getAllByText("Critical");
    // The first "Critical" is in the filter bar
    fireEvent.click(criticalButtons[0]);

    // Only the critical alert should be visible
    expect(screen.getByText("Brute Force")).toBeInTheDocument();
    expect(screen.queryByText("Port Scan")).not.toBeInTheDocument();
    expect(screen.queryByText("DNS Anomaly")).not.toBeInTheDocument();
  });

  it("shows empty state when filtered with no matches", () => {
    const alerts: Alert[] = [
      {
        id: "A1",
        source_ip: "10.0.1.1",
        dest_ip: "1.2.3.4",
        alert_type: "Test",
        severity: "Low",
        description: "test",
        timestamp: new Date().toISOString(),
        status: "new",
      },
    ];
    render(<AlertFeed alerts={alerts} isLoading={false} />);

    // Click High filter — no High alerts exist
    const highBadge = screen.getByText("High");
    fireEvent.click(highBadge);

    expect(screen.getByText("No alerts matching filter.")).toBeInTheDocument();
  });
});

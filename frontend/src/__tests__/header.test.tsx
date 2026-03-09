import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { Header } from "@/components/layout/header";

describe("Header", () => {
  it("shows Connected when isConnected is true", () => {
    render(<Header isConnected={true} alertCount={0} />);
    expect(screen.getByText("Connected")).toBeInTheDocument();
  });

  it("shows Disconnected when isConnected is false", () => {
    render(<Header isConnected={false} alertCount={0} />);
    expect(screen.getByText("Disconnected")).toBeInTheDocument();
  });

  it("shows alert count badge", () => {
    render(<Header isConnected={true} alertCount={5} />);
    expect(screen.getByText("5")).toBeInTheDocument();
  });

  it("shows 99+ for large counts", () => {
    render(<Header isConnected={true} alertCount={150} />);
    expect(screen.getByText("99+")).toBeInTheDocument();
  });

  it("does not show badge when count is 0", () => {
    render(<Header isConnected={true} alertCount={0} />);
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  it("shows dashboard title", () => {
    render(<Header isConnected={true} alertCount={0} />);
    expect(
      screen.getByText("Security Operations Dashboard")
    ).toBeInTheDocument();
  });
});

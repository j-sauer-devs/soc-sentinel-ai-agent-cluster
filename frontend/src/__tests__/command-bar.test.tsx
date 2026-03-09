import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { CommandBar } from "@/components/command-bar/command-bar";

describe("CommandBar", () => {
  it("does not render when closed", () => {
    render(<CommandBar onCommand={vi.fn()} />);
    expect(screen.queryByPlaceholderText(/Search threats/)).not.toBeInTheDocument();
  });

  it("opens on Cmd+K keyboard shortcut", () => {
    render(<CommandBar onCommand={vi.fn()} />);
    fireEvent.keyDown(window, { key: "k", metaKey: true });
    expect(screen.getByPlaceholderText(/Search threats/)).toBeInTheDocument();
  });

  it("opens on Ctrl+K keyboard shortcut", () => {
    render(<CommandBar onCommand={vi.fn()} />);
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    expect(screen.getByPlaceholderText(/Search threats/)).toBeInTheDocument();
  });

  it("closes on Escape", () => {
    render(<CommandBar onCommand={vi.fn()} />);

    // Open
    fireEvent.keyDown(window, { key: "k", metaKey: true });
    expect(screen.getByPlaceholderText(/Search threats/)).toBeInTheDocument();

    // Close
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.queryByPlaceholderText(/Search threats/)).not.toBeInTheDocument();
  });

  it("shows command suggestions", () => {
    render(<CommandBar onCommand={vi.fn()} />);
    fireEvent.keyDown(window, { key: "k", metaKey: true });

    expect(screen.getByText("/analyze")).toBeInTheDocument();
    expect(screen.getByText("/hunt")).toBeInTheDocument();
    expect(screen.getByText("/logs")).toBeInTheDocument();
    expect(screen.getByText("/isolate")).toBeInTheDocument();
    expect(screen.getByText("/status")).toBeInTheDocument();
  });

  it("calls onCommand with transformed text on Enter", () => {
    const onCommand = vi.fn();
    render(<CommandBar onCommand={onCommand} />);

    // Open
    fireEvent.keyDown(window, { key: "k", metaKey: true });

    const input = screen.getByPlaceholderText(/Search threats/);
    fireEvent.change(input, { target: { value: "/analyze 192.168.1.1" } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(onCommand).toHaveBeenCalledOnce();
    expect(onCommand.mock.calls[0][0]).toContain("192.168.1.1");
  });

  it("transforms /isolate command to natural language", () => {
    const onCommand = vi.fn();
    render(<CommandBar onCommand={onCommand} />);

    fireEvent.keyDown(window, { key: "k", metaKey: true });

    const input = screen.getByPlaceholderText(/Search threats/);
    fireEvent.change(input, { target: { value: "/isolate server-01" } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(onCommand.mock.calls[0][0]).toContain("server-01");
    expect(onCommand.mock.calls[0][0]).toContain("Isolate");
  });

  it("closes after submitting command", () => {
    render(<CommandBar onCommand={vi.fn()} />);

    fireEvent.keyDown(window, { key: "k", metaKey: true });
    const input = screen.getByPlaceholderText(/Search threats/);
    fireEvent.change(input, { target: { value: "test query" } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(screen.queryByPlaceholderText(/Search threats/)).not.toBeInTheDocument();
  });
});

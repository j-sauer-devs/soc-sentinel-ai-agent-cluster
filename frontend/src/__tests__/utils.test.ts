import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { cn, formatTimestamp, formatRelativeTime } from "@/lib/utils";

describe("cn (class name utility)", () => {
  it("merges class names", () => {
    expect(cn("foo", "bar")).toBe("foo bar");
  });

  it("handles conditional classes", () => {
    const active = true;
    expect(cn("base", active && "active")).toBe("base active");
  });

  it("handles false/undefined gracefully", () => {
    expect(cn("base", false, undefined, null)).toBe("base");
  });

  it("merges tailwind conflicts", () => {
    // tailwind-merge should pick the last conflicting class
    expect(cn("px-2", "px-4")).toBe("px-4");
  });
});

describe("formatTimestamp", () => {
  it("formats ISO string to HH:MM:SS", () => {
    const result = formatTimestamp("2025-06-15T14:30:45.000Z");
    // Result depends on local timezone, but should match HH:MM:SS pattern
    expect(result).toMatch(/^\d{2}:\d{2}:\d{2}$/);
  });
});

describe("formatRelativeTime", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2025-06-15T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("shows seconds for recent times", () => {
    const ts = new Date("2025-06-15T11:59:30Z").toISOString();
    expect(formatRelativeTime(ts)).toBe("30s ago");
  });

  it("shows minutes for times within an hour", () => {
    const ts = new Date("2025-06-15T11:45:00Z").toISOString();
    expect(formatRelativeTime(ts)).toBe("15m ago");
  });

  it("shows hours for times within a day", () => {
    const ts = new Date("2025-06-15T09:00:00Z").toISOString();
    expect(formatRelativeTime(ts)).toBe("3h ago");
  });

  it("shows days for older times", () => {
    const ts = new Date("2025-06-13T12:00:00Z").toISOString();
    expect(formatRelativeTime(ts)).toBe("2d ago");
  });
});

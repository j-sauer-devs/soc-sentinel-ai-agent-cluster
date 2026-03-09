import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { SeverityBadge } from "@/components/alerts/severity-badge";

describe("SeverityBadge", () => {
  it("renders the severity text", () => {
    render(<SeverityBadge severity="Critical" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("renders all severity levels", () => {
    const severities = ["Critical", "High", "Medium", "Low", "Noise"] as const;
    for (const sev of severities) {
      const { unmount } = render(<SeverityBadge severity={sev} />);
      expect(screen.getByText(sev)).toBeInTheDocument();
      unmount();
    }
  });

  it("applies custom className", () => {
    const { container } = render(
      <SeverityBadge severity="High" className="extra-class" />
    );
    expect(container.firstChild).toHaveClass("extra-class");
  });

  it("has a dot indicator element", () => {
    const { container } = render(<SeverityBadge severity="Critical" />);
    // The badge has a span child acting as the dot
    const spans = container.querySelectorAll("span");
    // Should have the outer span (badge) and inner span (dot)
    expect(spans.length).toBeGreaterThanOrEqual(2);
  });
});

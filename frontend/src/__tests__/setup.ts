import "@testing-library/jest-dom/vitest";
import { vi } from "vitest";

// Mock ResizeObserver for jsdom (required by cmdk)
class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}
global.ResizeObserver = ResizeObserverMock;

// Mock scrollIntoView for jsdom (required by cmdk)
Element.prototype.scrollIntoView = function () {};

import { describe, expect, it } from "vitest";
import { bypassKey, isFlaggedResult, shouldEvaluateNavigation } from "../lib/navigationGuard.js";

const _BASE = { frameId: 0, url: "https://example.com/path", enabled: true, allowlisted: false, bypassed: false };

describe("shouldEvaluateNavigation", () => {
  it("returns true for a plain top-level http(s) navigation when enabled", () => {
    expect(shouldEvaluateNavigation(_BASE)).toBe(true);
  });

  it("returns false when Active Protection is disabled", () => {
    expect(shouldEvaluateNavigation({ ..._BASE, enabled: false })).toBe(false);
  });

  it("returns false for a sub-frame (iframe) navigation", () => {
    expect(shouldEvaluateNavigation({ ..._BASE, frameId: 5 })).toBe(false);
  });

  it("returns false for a non-http(s) URL", () => {
    expect(shouldEvaluateNavigation({ ..._BASE, url: "chrome://settings" })).toBe(false);
  });

  it("returns false for a javascript: URL", () => {
    expect(shouldEvaluateNavigation({ ..._BASE, url: "javascript:alert(1)" })).toBe(false);
  });

  it("returns false when the hostname is allowlisted", () => {
    expect(shouldEvaluateNavigation({ ..._BASE, allowlisted: true })).toBe(false);
  });

  it("returns false when the tab already has a live bypass", () => {
    expect(shouldEvaluateNavigation({ ..._BASE, bypassed: true })).toBe(false);
  });
});

describe("isFlaggedResult", () => {
  it("is true for a phishing label", () => {
    expect(isFlaggedResult({ label: "phishing" })).toBe(true);
  });

  it("is false for a legitimate label", () => {
    expect(isFlaggedResult({ label: "legitimate" })).toBe(false);
  });

  it("is false for null/undefined", () => {
    expect(isFlaggedResult(null)).toBe(false);
    expect(isFlaggedResult(undefined)).toBe(false);
  });

  it("is false for a result with no label", () => {
    expect(isFlaggedResult({})).toBe(false);
  });
});

describe("bypassKey", () => {
  it("combines tabId and lowercased hostname", () => {
    expect(bypassKey(42, "Example.com")).toBe("42:example.com");
  });
});

import { describe, expect, it } from "vitest";
import { isHttpUrl, originPatternFor, toHostnameOnly } from "../lib/urlUtils.js";

describe("toHostnameOnly", () => {
  it("drops path, query, and fragment", () => {
    expect(toHostnameOnly("https://example.com/login?user=victim@mail.com#top")).toBe(
      "https://example.com"
    );
  });

  it("keeps a non-default port", () => {
    expect(toHostnameOnly("http://example.com:8443/x")).toBe("http://example.com:8443");
  });

  it("preserves subdomains", () => {
    expect(toHostnameOnly("https://sub.evil-domain.tk/verify/account")).toBe(
      "https://sub.evil-domain.tk"
    );
  });

  it("throws on an unparseable URL", () => {
    expect(() => toHostnameOnly("not a url")).toThrow();
  });
});

describe("isHttpUrl", () => {
  it("accepts http/https", () => {
    expect(isHttpUrl("https://example.com")).toBe(true);
    expect(isHttpUrl("http://example.com")).toBe(true);
  });

  it("rejects other schemes and garbage", () => {
    expect(isHttpUrl("ftp://example.com")).toBe(false);
    expect(isHttpUrl("javascript:alert(1)")).toBe(false);
    expect(isHttpUrl("not a url")).toBe(false);
    expect(isHttpUrl("")).toBe(false);
  });
});

describe("originPatternFor", () => {
  it("builds a chrome.permissions-shaped origin pattern", () => {
    expect(originPatternFor("http://localhost:5000")).toBe("http://localhost:5000/*");
    expect(originPatternFor("https://api.example.com")).toBe("https://api.example.com/*");
  });

  it("returns null for an invalid URL", () => {
    expect(originPatternFor("not a url")).toBeNull();
  });
});

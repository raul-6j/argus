import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildPayloadUrl, detect, explain, getSettings } from "../lib/apiClient.js";

function mockChromeStorage(settings) {
  globalThis.chrome = {
    storage: {
      sync: {
        get: vi.fn().mockResolvedValue(settings),
      },
    },
  };
}

describe("buildPayloadUrl", () => {
  it("sends hostname-only by default", () => {
    expect(buildPayloadUrl("https://example.com/login?u=victim", false)).toBe(
      "https://example.com"
    );
  });

  it("sends the full URL when opted in", () => {
    const full = "https://example.com/login?u=victim";
    expect(buildPayloadUrl(full, true)).toBe(full);
  });
});

describe("getSettings", () => {
  it("reads apiBaseUrl and sendFullUrl from chrome.storage.sync", async () => {
    mockChromeStorage({ apiBaseUrl: "http://localhost:5000", sendFullUrl: true });
    const settings = await getSettings();
    expect(settings).toEqual({ apiBaseUrl: "http://localhost:5000", sendFullUrl: true });
  });
});

describe("detect", () => {
  beforeEach(() => {
    mockChromeStorage({ apiBaseUrl: "http://localhost:5000", sendFullUrl: false });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("posts hostname-only payload to /detect and returns the parsed body", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        url: "https://example.com",
        label: "legitimate",
        confidence: 0.91,
        verdict: "legitimate",
        source: "model",
        latency_ms: 12.3,
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await detect("https://example.com/some/path?x=1");

    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:5000/detect",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ url: "https://example.com", enrich: false }),
      })
    );
    expect(result.label).toBe("legitimate");
  });

  it("throws with the server's error message on a non-2xx response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({ error: "invalid request: bad url" }),
      })
    );

    await expect(detect("https://example.com")).rejects.toThrow("invalid request: bad url");
  });

  it("throws a clear error when the API base URL is not configured", async () => {
    mockChromeStorage({ apiBaseUrl: "", sendFullUrl: false });
    await expect(detect("https://example.com")).rejects.toThrow("not configured");
  });
});

describe("explain", () => {
  beforeEach(() => {
    mockChromeStorage({ apiBaseUrl: "http://localhost:5000", sendFullUrl: false });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("posts to /explain and returns top5_features", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          url: "https://example.com",
          top5_features: [{ feature: "has_prefix_suffix", shap_value: 0.08, feature_value: 1 }],
          latency_ms: 500.1,
        }),
      })
    );

    const result = await explain("https://example.com/x");
    expect(result.top5_features).toHaveLength(1);
  });
});

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildPayloadUrl, deepScan, detect, explain, getSettings } from "../lib/apiClient.js";

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

  it("throws instead of silently returning {} when a 2xx response body fails to parse", async () => {
    // A real ARGUS bug (fixed server-side, DEC-044): jsonify used to emit a
    // bare `NaN` token for a missing SHAP feature_value, which is valid
    // Python json.dumps output but NOT valid JSON per spec -- Response.json()
    // rejects it. apiRequest used to swallow that parse failure into `{}`
    // for ANY 2xx response, which the popup's "Why?" handler then read
    // `.top5_features` off of, crashing on `undefined.map()` with a generic
    // TypeError instead of a useful message. This is the client-side half of
    // that fix: a malformed 2xx body must surface as a clear, catchable error.
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => {
          throw new SyntaxError("Unexpected token N in JSON at position 42");
        },
      })
    );

    await expect(explain("https://example.com/x")).rejects.toThrow("malformed response");
  });
});

describe("deepScan", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("posts to /detect with enrich:true and hostname-only by default", async () => {
    mockChromeStorage({ apiBaseUrl: "http://localhost:5000", sendFullUrl: false });
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        url: "https://example.com",
        label: "phishing",
        confidence: 0.9,
        verdict: "phishing",
        source: "fusion",
        risk_score: 0.9,
        signals: [{ name: "typosquat", triggered: true, direction: "phishing", evidence: {} }],
        latency_ms: 800.2,
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await deepScan("https://example.com/some/path?x=1");

    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:5000/detect",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ url: "https://example.com", enrich: true }),
      })
    );
    expect(result.signals).toHaveLength(1);
  });

  it("sends the full URL when the stored setting is opted in", async () => {
    mockChromeStorage({ apiBaseUrl: "http://localhost:5000", sendFullUrl: true });
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
    vi.stubGlobal("fetch", fetchMock);

    await deepScan("https://example.com/path");

    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:5000/detect",
      expect.objectContaining({
        body: JSON.stringify({ url: "https://example.com/path", enrich: true }),
      })
    );
  });

  it("a per-call sendFullUrl override takes precedence over the stored (off) setting", async () => {
    mockChromeStorage({ apiBaseUrl: "http://localhost:5000", sendFullUrl: false });
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
    vi.stubGlobal("fetch", fetchMock);

    await deepScan("https://example.com/path", { sendFullUrl: true });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:5000/detect",
      expect.objectContaining({
        body: JSON.stringify({ url: "https://example.com/path", enrich: true }),
      })
    );
  });

  it("a per-call sendFullUrl override can also force hostname-only", async () => {
    mockChromeStorage({ apiBaseUrl: "http://localhost:5000", sendFullUrl: true });
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
    vi.stubGlobal("fetch", fetchMock);

    await deepScan("https://example.com/path", { sendFullUrl: false });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:5000/detect",
      expect.objectContaining({
        body: JSON.stringify({ url: "https://example.com", enrich: true }),
      })
    );
  });

  it("throws a clear error when the API base URL is not configured", async () => {
    mockChromeStorage({ apiBaseUrl: "", sendFullUrl: false });
    await expect(deepScan("https://example.com")).rejects.toThrow("not configured");
  });
});

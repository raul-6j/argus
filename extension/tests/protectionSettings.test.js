import { afterEach, describe, expect, it, vi } from "vitest";
import {
  addToAllowlist,
  appendOverrideLog,
  clearOverrideLog,
  getOverrideLog,
  getProtectionSettings,
  isAllowlisted,
  removeFromAllowlist,
  setProtectionEnabled,
} from "../lib/protectionSettings.js";

function mockStorage(initial) {
  const store = { ...initial };
  globalThis.chrome = {
    storage: {
      local: {
        get: vi.fn((defaults) => {
          const result = {};
          for (const key of Object.keys(defaults)) {
            result[key] = key in store ? store[key] : defaults[key];
          }
          return Promise.resolve(result);
        }),
        set: vi.fn((values) => {
          Object.assign(store, values);
          return Promise.resolve();
        }),
      },
    },
  };
  return store;
}

describe("isAllowlisted", () => {
  it("matches an exact hostname", () => {
    expect(isAllowlisted("example.com", ["example.com"])).toBe(true);
  });

  it("does not match a different hostname", () => {
    expect(isAllowlisted("evil.com", ["example.com"])).toBe(false);
  });

  it("does not implicitly cover subdomains", () => {
    expect(isAllowlisted("sub.example.com", ["example.com"])).toBe(false);
  });

  it("is case-insensitive", () => {
    expect(isAllowlisted("EXAMPLE.com", ["example.com"])).toBe(true);
  });

  it("returns false for an empty hostname", () => {
    expect(isAllowlisted("", ["example.com"])).toBe(false);
  });
});

describe("getProtectionSettings / setProtectionEnabled", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("defaults to disabled with an empty allowlist", async () => {
    mockStorage({});
    const settings = await getProtectionSettings();
    expect(settings).toEqual({ enabled: false, allowlist: [] });
  });

  it("reflects stored values", async () => {
    mockStorage({ activeProtectionEnabled: true, allowlist: ["example.com"] });
    const settings = await getProtectionSettings();
    expect(settings).toEqual({ enabled: true, allowlist: ["example.com"] });
  });

  it("setProtectionEnabled writes the flag", async () => {
    const store = mockStorage({});
    await setProtectionEnabled(true);
    expect(store.activeProtectionEnabled).toBe(true);
  });
});

describe("allowlist mutation", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("addToAllowlist appends a new hostname", async () => {
    const store = mockStorage({ allowlist: ["a.com"] });
    await addToAllowlist("b.com");
    expect(store.allowlist).toEqual(["a.com", "b.com"]);
  });

  it("addToAllowlist normalizes to lowercase", async () => {
    const store = mockStorage({ allowlist: [] });
    await addToAllowlist("EXAMPLE.COM");
    expect(store.allowlist).toEqual(["example.com"]);
  });

  it("addToAllowlist is idempotent", async () => {
    const store = mockStorage({ allowlist: ["a.com"] });
    await addToAllowlist("a.com");
    expect(store.allowlist).toEqual(["a.com"]);
  });

  it("removeFromAllowlist removes a hostname", async () => {
    const store = mockStorage({ allowlist: ["a.com", "b.com"] });
    await removeFromAllowlist("a.com");
    expect(store.allowlist).toEqual(["b.com"]);
  });

  it("removeFromAllowlist on a missing hostname is a no-op", async () => {
    const store = mockStorage({ allowlist: ["a.com"] });
    await removeFromAllowlist("nope.com");
    expect(store.allowlist).toEqual(["a.com"]);
  });
});

describe("override log", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("appendOverrideLog adds an entry", async () => {
    const store = mockStorage({ overrideLog: [] });
    await appendOverrideLog({ hostname: "evil.com", url: "https://evil.com", timestamp: "t1" });
    expect(store.overrideLog).toEqual([
      { hostname: "evil.com", url: "https://evil.com", timestamp: "t1" },
    ]);
  });

  it("caps the log at 50 entries, dropping the oldest first", async () => {
    const existing = Array.from({ length: 50 }, (_, i) => ({
      hostname: `h${i}.com`,
      url: `https://h${i}.com`,
      timestamp: String(i),
    }));
    const store = mockStorage({ overrideLog: existing });
    await appendOverrideLog({ hostname: "new.com", url: "https://new.com", timestamp: "50" });
    expect(store.overrideLog).toHaveLength(50);
    expect(store.overrideLog[0].hostname).toBe("h1.com"); // h0 dropped
    expect(store.overrideLog[49].hostname).toBe("new.com");
  });

  it("getOverrideLog returns the stored log", async () => {
    mockStorage({ overrideLog: [{ hostname: "a.com", url: "https://a.com", timestamp: "t" }] });
    const log = await getOverrideLog();
    expect(log).toHaveLength(1);
  });

  it("clearOverrideLog empties the log", async () => {
    const store = mockStorage({ overrideLog: [{ hostname: "a.com", url: "https://a.com", timestamp: "t" }] });
    await clearOverrideLog();
    expect(store.overrideLog).toEqual([]);
  });
});

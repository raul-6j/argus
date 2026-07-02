import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { encryptVault } from "../lib/crypto.js";
import { fetchVault, saveVault } from "../lib/vaultClient.js";

function mockChrome() {
  globalThis.chrome = {
    storage: {
      sync: { get: vi.fn().mockResolvedValue({ apiBaseUrl: "http://localhost:5000" }) },
      local: {
        get: vi.fn((defaults) =>
          Promise.resolve({
            ...defaults,
            refreshToken: "RT",
            accessToken: "AT",
            accessTokenExpiresAt: Date.now() + 600_000,
          })
        ),
        set: vi.fn().mockResolvedValue(undefined),
        remove: vi.fn().mockResolvedValue(undefined),
      },
    },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

beforeEach(() => {
  mockChrome();
});

describe("fetchVault", () => {
  it("returns null value + version 0 for an empty vault", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ciphertext: null, version: 0 }) })
    );

    const result = await fetchVault("master-password");
    expect(result).toEqual({ value: null, version: 0 });
  });

  it("decrypts an existing vault blob", async () => {
    const original = { allowlist: ["a.com"] };
    const blob = await encryptVault(original, "master-password");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ciphertext: blob, version: 3 }) })
    );

    const result = await fetchVault("master-password");
    expect(result).toEqual({ value: original, version: 3 });
  });

  it("sends the access token as a Bearer header", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue({ ok: true, json: async () => ({ ciphertext: null, version: 0 }) });
    vi.stubGlobal("fetch", fetchMock);

    await fetchVault("pw");

    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:5000/vault",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({ Authorization: "Bearer AT" }),
      })
    );
  });
});

describe("saveVault", () => {
  it("encrypts the value and PUTs it with the expected version", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ version: 1 }) });
    vi.stubGlobal("fetch", fetchMock);

    const result = await saveVault({ allowlist: ["x.com"] }, "master-password", 0);

    expect(result).toEqual({ version: 1 });
    const [, options] = fetchMock.mock.calls[0];
    expect(options.method).toBe("PUT");
    const sentBody = JSON.parse(options.body);
    expect(sentBody.version).toBe(0);
    expect(typeof sentBody.ciphertext).toBe("string");
  });

  it("propagates a 409 conflict with the server's current version/ciphertext", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 409,
        json: async () => ({
          error: "conflict: vault was updated elsewhere",
          current_version: 2,
          current_ciphertext: "someblob",
        }),
      })
    );

    const err = await saveVault({ a: 1 }, "pw", 0).catch((e) => e);
    expect(err.status).toBe(409);
    expect(err.body.current_version).toBe(2);
  });
});

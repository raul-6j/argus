import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  getCurrentEmail,
  getValidAccessToken,
  isLoggedIn,
  login,
  logout,
  signup,
  verifyOtp,
} from "../lib/authClient.js";

function mockChrome({ syncData = {}, localData = {} } = {}) {
  const local = { ...localData };
  globalThis.chrome = {
    storage: {
      sync: {
        get: vi.fn().mockResolvedValue({ apiBaseUrl: "http://localhost:5000", ...syncData }),
      },
      local: {
        get: vi.fn((defaults) => Promise.resolve({ ...defaults, ...local })),
        set: vi.fn((fields) => {
          Object.assign(local, fields);
          return Promise.resolve();
        }),
        remove: vi.fn((keys) => {
          for (const key of keys) delete local[key];
          return Promise.resolve();
        }),
      },
    },
  };
  return local;
}

function mockFetchOnce(status, body) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({ ok: status < 300, status, json: async () => body })
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("signup / verifyOtp", () => {
  beforeEach(() => mockChrome());

  it("posts to /auth/signup", async () => {
    mockFetchOnce(200, { message: "ok" });
    const result = await signup("a@b.com", "password123");
    expect(fetch).toHaveBeenCalledWith(
      "http://localhost:5000/auth/signup",
      expect.objectContaining({ method: "POST" })
    );
    expect(result.message).toBe("ok");
  });

  it("posts to /auth/verify-otp", async () => {
    mockFetchOnce(200, { message: "verified" });
    const result = await verifyOtp("a@b.com", "123456");
    expect(fetch).toHaveBeenCalledWith(
      "http://localhost:5000/auth/verify-otp",
      expect.objectContaining({ method: "POST" })
    );
    expect(result.message).toBe("verified");
  });
});

describe("login / logout / isLoggedIn / getCurrentEmail", () => {
  it("login stores the token pair and email", async () => {
    const local = mockChrome();
    mockFetchOnce(200, { access_token: "AT", refresh_token: "RT", expires_in: 900 });

    await login("a@b.com", "password123");

    expect(local.accessToken).toBe("AT");
    expect(local.refreshToken).toBe("RT");
    expect(local.email).toBe("a@b.com");
    expect(local.accessTokenExpiresAt).toBeGreaterThan(Date.now());
  });

  it("isLoggedIn is false with no stored refresh token", async () => {
    mockChrome();
    expect(await isLoggedIn()).toBe(false);
  });

  it("isLoggedIn is true once a session is stored", async () => {
    mockChrome({ localData: { refreshToken: "RT" } });
    expect(await isLoggedIn()).toBe(true);
  });

  it("getCurrentEmail returns the stored email", async () => {
    mockChrome({ localData: { email: "a@b.com" } });
    expect(await getCurrentEmail()).toBe("a@b.com");
  });

  it("logout calls the API and clears local session state", async () => {
    const local = mockChrome({ localData: { refreshToken: "RT", accessToken: "AT", email: "a@b.com" } });
    mockFetchOnce(200, { message: "Logged out." });

    await logout();

    expect(fetch).toHaveBeenCalledWith(
      "http://localhost:5000/auth/logout",
      expect.objectContaining({ method: "POST" })
    );
    expect(local.refreshToken).toBeUndefined();
    expect(local.accessToken).toBeUndefined();
    expect(local.email).toBeUndefined();
  });

  it("logout still clears local state even if the server call fails", async () => {
    const local = mockChrome({ localData: { refreshToken: "RT" } });
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network down")));

    await logout();

    expect(local.refreshToken).toBeUndefined();
  });
});

describe("getValidAccessToken", () => {
  it("throws if there is no session", async () => {
    mockChrome();
    await expect(getValidAccessToken()).rejects.toThrow("Not logged in.");
  });

  it("returns the stored token without refreshing if it's not close to expiry", async () => {
    mockChrome({
      localData: { refreshToken: "RT", accessToken: "AT", accessTokenExpiresAt: Date.now() + 600_000 },
    });
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const token = await getValidAccessToken();

    expect(token).toBe("AT");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("refreshes when the access token is close to expiry", async () => {
    const local = mockChrome({
      localData: { refreshToken: "RT", accessToken: "OLD", accessTokenExpiresAt: Date.now() + 1000 },
    });
    mockFetchOnce(200, { access_token: "NEW", refresh_token: "RT2", expires_in: 900 });

    const token = await getValidAccessToken();

    expect(token).toBe("NEW");
    expect(local.accessToken).toBe("NEW");
    expect(local.refreshToken).toBe("RT2");
  });

  it("clears the session and rethrows if refresh is rejected", async () => {
    const local = mockChrome({
      localData: { refreshToken: "STALE", accessToken: "OLD", accessTokenExpiresAt: 0 },
    });
    mockFetchOnce(401, { error: "refresh token reuse detected — all sessions revoked" });

    await expect(getValidAccessToken()).rejects.toThrow("reuse detected");
    expect(local.refreshToken).toBeUndefined();
  });
});

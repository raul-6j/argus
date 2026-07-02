/**
 * ARGUS auth client (Phase 8, Task 8.1/8.2).
 *
 * Tokens are stored in chrome.storage.local (not .sync) -- deliberately not
 * replicated across the user's Chrome-synced devices; each device
 * authenticates independently. The access token is refreshed automatically
 * (via the rotating refresh token) whenever it's within
 * ACCESS_TOKEN_REFRESH_SKEW_MS of expiring, so callers never see a stale
 * token rejected by the API's 15-minute expiry.
 */

import { apiRequest } from "./httpClient.js";

const ACCESS_TOKEN_REFRESH_SKEW_MS = 60_000; // refresh if <60s from expiry

/**
 * @returns {Promise<{apiBaseUrl: string}>}
 */
async function getApiBaseUrl() {
  const { apiBaseUrl } = await chrome.storage.sync.get({ apiBaseUrl: "" });
  if (!apiBaseUrl) {
    throw new Error("ARGUS API base URL not configured. Open the extension options page.");
  }
  return apiBaseUrl;
}

async function getStoredSession() {
  return chrome.storage.local.get({
    accessToken: null,
    accessTokenExpiresAt: null,
    refreshToken: null,
    email: null,
  });
}

async function storeSession({ access_token, refresh_token, expires_in }, email) {
  const fields = {
    accessToken: access_token,
    accessTokenExpiresAt: Date.now() + expires_in * 1000,
    refreshToken: refresh_token,
  };
  if (email) {
    fields.email = email;
  }
  await chrome.storage.local.set(fields);
}

async function clearSession() {
  await chrome.storage.local.remove(["accessToken", "accessTokenExpiresAt", "refreshToken", "email"]);
}

/**
 * The email of the currently logged-in user, if any (for display only).
 * @returns {Promise<string|null>}
 */
export async function getCurrentEmail() {
  const { email } = await getStoredSession();
  return email;
}

/**
 * POST /auth/signup.
 * @param {string} email
 * @param {string} password
 * @returns {Promise<{message: string}>}
 */
export async function signup(email, password) {
  const apiBaseUrl = await getApiBaseUrl();
  return apiRequest(apiBaseUrl, "POST", "/auth/signup", { body: { email, password } });
}

/**
 * POST /auth/verify-otp.
 * @param {string} email
 * @param {string} otp - The 6-digit code.
 * @returns {Promise<{message: string}>}
 */
export async function verifyOtp(email, otp) {
  const apiBaseUrl = await getApiBaseUrl();
  return apiRequest(apiBaseUrl, "POST", "/auth/verify-otp", { body: { email, otp } });
}

/**
 * POST /auth/login. Stores the returned token pair in chrome.storage.local.
 * @param {string} email
 * @param {string} password
 * @returns {Promise<void>}
 */
export async function login(email, password) {
  const apiBaseUrl = await getApiBaseUrl();
  const tokens = await apiRequest(apiBaseUrl, "POST", "/auth/login", { body: { email, password } });
  await storeSession(tokens, email);
}

/**
 * POST /auth/logout with the stored refresh token, then clear local session state.
 * @returns {Promise<void>}
 */
export async function logout() {
  const apiBaseUrl = await getApiBaseUrl();
  const { refreshToken } = await getStoredSession();
  if (refreshToken) {
    // Best-effort: still clear local state even if the server call fails
    // (e.g. offline) -- the user's intent to log out locally should win.
    await apiRequest(apiBaseUrl, "POST", "/auth/logout", { body: { refresh_token: refreshToken } }).catch(
      () => {}
    );
  }
  await clearSession();
}

/**
 * Whether there's a stored session at all (does not verify it's still valid
 * server-side -- that's discovered lazily on the next authenticated call).
 * @returns {Promise<boolean>}
 */
export async function isLoggedIn() {
  const { refreshToken } = await getStoredSession();
  return refreshToken !== null;
}

/**
 * Get a valid access token, transparently refreshing it first if it's
 * expired or close to expiring.
 * @returns {Promise<string>}
 * @throws {Error} If there's no session, or the refresh token was rejected
 *     (expired/revoked/reused) -- callers should treat this as "logged out"
 *     and prompt the user to log in again.
 */
export async function getValidAccessToken() {
  const apiBaseUrl = await getApiBaseUrl();
  const session = await getStoredSession();

  if (!session.refreshToken) {
    throw new Error("Not logged in.");
  }

  const needsRefresh =
    !session.accessToken || Date.now() > session.accessTokenExpiresAt - ACCESS_TOKEN_REFRESH_SKEW_MS;

  if (!needsRefresh) {
    return session.accessToken;
  }

  try {
    const tokens = await apiRequest(apiBaseUrl, "POST", "/auth/refresh", {
      body: { refresh_token: session.refreshToken },
    });
    await storeSession(tokens);
    return tokens.access_token;
  } catch (err) {
    // Refresh rejected (expired/revoked/reuse-detected) -- the session is
    // dead; clear it so the UI can prompt for a fresh login.
    await clearSession();
    throw err;
  }
}

/**
 * ARGUS webapp auth client (Phase 4, F11) — plain script, no build step,
 * no ES modules, mirroring the rest of webapp/ (see report.js). Same
 * request/response contract as the browser extension's
 * extension/lib/authClient.js, but backed by localStorage (a plain website
 * has no chrome.storage) since the webapp is served same-origin by the same
 * Flask app (/app/*), so no CORS configuration is needed either.
 *
 * Login here is entirely optional: every page still works fully anonymously
 * if the visitor never signs in (see webapp/index.html).
 */

const ARGUS_ACCESS_TOKEN_REFRESH_SKEW_MS = 60_000; // refresh if <60s from expiry

const _ARGUS_STORAGE_KEYS = {
  accessToken: "argus_access_token",
  accessTokenExpiresAt: "argus_access_token_expires_at",
  refreshToken: "argus_refresh_token",
  email: "argus_email",
};

function _argusGetStoredSession() {
  return {
    accessToken: localStorage.getItem(_ARGUS_STORAGE_KEYS.accessToken),
    accessTokenExpiresAt: Number(localStorage.getItem(_ARGUS_STORAGE_KEYS.accessTokenExpiresAt)) || null,
    refreshToken: localStorage.getItem(_ARGUS_STORAGE_KEYS.refreshToken),
    email: localStorage.getItem(_ARGUS_STORAGE_KEYS.email),
  };
}

function _argusStoreSession({ access_token, refresh_token, expires_in }, email) {
  localStorage.setItem(_ARGUS_STORAGE_KEYS.accessToken, access_token);
  localStorage.setItem(
    _ARGUS_STORAGE_KEYS.accessTokenExpiresAt,
    String(Date.now() + expires_in * 1000)
  );
  localStorage.setItem(_ARGUS_STORAGE_KEYS.refreshToken, refresh_token);
  if (email) {
    localStorage.setItem(_ARGUS_STORAGE_KEYS.email, email);
  }
}

function _argusClearSession() {
  for (const key of Object.values(_ARGUS_STORAGE_KEYS)) {
    localStorage.removeItem(key);
  }
}

async function _argusRequest(method, path, body) {
  const resp = await fetch(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(data.error || `Request failed (HTTP ${resp.status})`);
  }
  return data;
}

/** The email of the currently logged-in user, if any (for display only). */
function argusGetCurrentEmail() {
  return _argusGetStoredSession().email;
}

/** Whether there's a stored session at all (not verified server-side yet). */
function argusIsLoggedIn() {
  return _argusGetStoredSession().refreshToken !== null;
}

/** POST /auth/signup. */
async function argusSignup(email, password) {
  return _argusRequest("POST", "/auth/signup", { email, password });
}

/** POST /auth/verify-otp. */
async function argusVerifyOtp(email, otp) {
  return _argusRequest("POST", "/auth/verify-otp", { email, otp });
}

/** POST /auth/login. Stores the returned token pair in localStorage. */
async function argusLogin(email, password) {
  const tokens = await _argusRequest("POST", "/auth/login", { email, password });
  _argusStoreSession(tokens, email);
}

/** POST /auth/logout with the stored refresh token, then clear local state. */
async function argusLogout() {
  const { refreshToken } = _argusGetStoredSession();
  if (refreshToken) {
    // Best-effort: still clear local state even if the server call fails --
    // the user's intent to log out locally should win.
    await _argusRequest("POST", "/auth/logout", { refresh_token: refreshToken }).catch(() => {});
  }
  _argusClearSession();
}

/**
 * Get a valid access token, transparently refreshing it first if it's
 * expired or close to expiring. Returns null if there's no session at all
 * (callers should treat that as "anonymous", not throw).
 * @throws {Error} if a refresh was attempted and rejected (expired/revoked/
 *     reused) -- callers should treat this as "logged out".
 */
async function argusGetValidAccessToken() {
  const session = _argusGetStoredSession();
  if (!session.refreshToken) {
    return null;
  }

  const needsRefresh =
    !session.accessToken ||
    Date.now() > session.accessTokenExpiresAt - ARGUS_ACCESS_TOKEN_REFRESH_SKEW_MS;

  if (!needsRefresh) {
    return session.accessToken;
  }

  try {
    const tokens = await _argusRequest("POST", "/auth/refresh", {
      refresh_token: session.refreshToken,
    });
    _argusStoreSession(tokens);
    return tokens.access_token;
  } catch (err) {
    _argusClearSession();
    throw err;
  }
}

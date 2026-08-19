/**
 * Shared fetch helper for all ARGUS API clients (detect/explain, auth, vault).
 */

/**
 * Issue a JSON HTTP request and parse the response body.
 * @param {string} baseUrl - The ARGUS API base URL (e.g. from settings).
 * @param {"GET"|"POST"|"PUT"} method
 * @param {string} path - e.g. "/detect" or "/auth/login".
 * @param {{body?: unknown, headers?: Record<string,string>}} [options]
 * @returns {Promise<any>} The parsed JSON response body.
 * @throws {Error} If the response status is not 2xx -- the error message is
 *     the server's ``error`` field when present.
 */
export async function apiRequest(baseUrl, method, path, options = {}) {
  const { body, headers = {} } = options;
  const resp = await fetch(`${baseUrl.replace(/\/$/, "")}${path}`, {
    method,
    headers: { "Content-Type": "application/json", ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let responseBody;
  try {
    responseBody = await resp.json();
  } catch (parseErr) {
    // A non-2xx response with an unparseable/empty body (a dead proxy, a
    // truncated error page) still degrades to {} -- the status-based error
    // below already gives the caller a useful message. A 2xx response that
    // fails to parse is a different, worse situation: swallowing it here
    // used to hand every caller `{}`, silently discarding the real payload
    // and surfacing as a generic "Cannot read properties of undefined"
    // wherever the caller then read an expected field -- found live via the
    // popup's "Why?" button crashing instead of showing an explanation.
    // Fail loud instead, same "never silently degrade" precedent as the
    // rate-limiter Redis check.
    if (!resp.ok) {
      responseBody = {};
    } else {
      throw new Error(`Request to ${path} returned a malformed response: ${parseErr.message}`, {
        cause: parseErr,
      });
    }
  }
  if (!resp.ok) {
    const error = new Error(responseBody.error || `Request to ${path} failed: HTTP ${resp.status}`);
    error.status = resp.status;
    error.body = responseBody;
    throw error;
  }
  return responseBody;
}

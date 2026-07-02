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
  const responseBody = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const error = new Error(responseBody.error || `Request to ${path} failed: HTTP ${resp.status}`);
    error.status = resp.status;
    error.body = responseBody;
    throw error;
  }
  return responseBody;
}

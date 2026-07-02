/**
 * URL helpers shared by the popup, options page, and background worker.
 *
 * toHostnameOnly() is the core of the S1 privacy fix: by default the
 * extension sends the API only scheme+host, never path/query/fragment
 * (which can carry session tokens, search terms, email addresses, etc).
 */

/**
 * Reduce a URL to scheme://host — drops path, query, fragment, and userinfo.
 * @param {string} url - A full URL.
 * @returns {string} The hostname-only form, e.g. "https://example.com".
 * @throws {TypeError} If `url` is not a parseable URL.
 */
export function toHostnameOnly(url) {
  const parsed = new URL(url);
  return `${parsed.protocol}//${parsed.host}`;
}

/**
 * Whether a string is a well-formed http(s) URL.
 * @param {string} url
 * @returns {boolean}
 */
export function isHttpUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Build the origin permission pattern (e.g. "https://api.example.com/*")
 * chrome.permissions.request() needs for a configured API base URL.
 * @param {string} apiBaseUrl
 * @returns {string|null} The origin pattern, or null if apiBaseUrl is invalid.
 */
export function originPatternFor(apiBaseUrl) {
  try {
    const parsed = new URL(apiBaseUrl);
    return `${parsed.protocol}//${parsed.host}/*`;
  } catch {
    return null;
  }
}

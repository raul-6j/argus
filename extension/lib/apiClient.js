/**
 * ARGUS API client. Speaks the /detect and /explain schemas directly (see
 * src/api/schemas.py) -- no response-mapping shim needed, since this
 * extension is built specifically for ARGUS rather than adapted from a
 * third-party extension with a different response shape (DEC-020).
 */

import { apiRequest } from "./httpClient.js";
import { toHostnameOnly } from "./urlUtils.js";

/**
 * Read extension settings from chrome.storage.sync.
 * @returns {Promise<{apiBaseUrl: string, sendFullUrl: boolean}>}
 */
export async function getSettings() {
  return chrome.storage.sync.get({ apiBaseUrl: "", sendFullUrl: false });
}

/**
 * Build the /detect request payload for a URL, honoring the sendFullUrl setting.
 * @param {string} url - The full page URL.
 * @param {boolean} sendFullUrl - Whether the user opted into sending the full URL.
 * @returns {string} scheme://host by default, or the untouched URL if opted in.
 */
export function buildPayloadUrl(url, sendFullUrl) {
  return sendFullUrl ? url : toHostnameOnly(url);
}

/**
 * Call ARGUS's POST /detect.
 * @param {string} url - The page URL to classify.
 * @returns {Promise<{url: string, label: string, confidence: number, verdict: string, source: string, latency_ms: number}>}
 * @throws {Error} If the API base URL isn't configured, or the request fails.
 */
export async function detect(url) {
  const { apiBaseUrl, sendFullUrl } = await getSettings();
  if (!apiBaseUrl) {
    throw new Error("ARGUS API base URL not configured. Open the extension options page.");
  }
  return apiRequest(apiBaseUrl, "POST", "/detect", {
    body: { url: buildPayloadUrl(url, sendFullUrl), enrich: false },
  });
}

/**
 * Call ARGUS's POST /explain.
 * @param {string} url - The page URL to explain.
 * @returns {Promise<{url: string, top5_features: Array<{feature: string, shap_value: number, feature_value: unknown}>, signals: Array<object>, plain_explanation: string, latency_ms: number}>}
 * @throws {Error} If the API base URL isn't configured, or the request fails.
 */
export async function explain(url) {
  const { apiBaseUrl, sendFullUrl } = await getSettings();
  if (!apiBaseUrl) {
    throw new Error("ARGUS API base URL not configured. Open the extension options page.");
  }
  return apiRequest(apiBaseUrl, "POST", "/explain", { body: { url: buildPayloadUrl(url, sendFullUrl) } });
}

/**
 * Call ARGUS's POST /detect with `enrich: true` (Phase 1, Deep Scan) --
 * runs the server-side detection fusion layer (typosquat/homograph, favicon
 * match, brand-vs-domain mismatch) in addition to the ML model, at the cost
 * of higher latency (a real page fetch happens server-side).
 *
 * `sendFullUrl` here is a **per-call** override, independent of the stored
 * settings.sendFullUrl -- Deep Scan is an explicit, user-initiated action
 * (a button click), so the caller decides per-invocation whether to include
 * the full URL, without changing the extension's persistent hostname-only
 * default (DEC-D: the passive/automatic check always stays hostname-only).
 * @param {string} url - The page URL to deep-scan.
 * @param {{sendFullUrl?: boolean}} [options] - `sendFullUrl` defaults to the
 *     stored setting when omitted.
 * @returns {Promise<{url: string, label: string, confidence: number, verdict: string, source: string, risk_score?: number, signals?: Array<object>, latency_ms: number}>}
 * @throws {Error} If the API base URL isn't configured, or the request fails.
 */
export async function deepScan(url, options = {}) {
  const { apiBaseUrl, sendFullUrl } = await getSettings();
  if (!apiBaseUrl) {
    throw new Error("ARGUS API base URL not configured. Open the extension options page.");
  }
  const effectiveSendFullUrl = options.sendFullUrl ?? sendFullUrl;
  return apiRequest(apiBaseUrl, "POST", "/detect", {
    body: { url: buildPayloadUrl(url, effectiveSendFullUrl), enrich: true },
  });
}

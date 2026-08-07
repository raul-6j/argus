/**
 * Pure decision logic for Active Protection mode's pre-navigation check
 * (Phase 3, F8). Kept separate from background.js -- which owns the actual
 * chrome.webNavigation/chrome.tabs wiring and can only be verified in a
 * real browser -- so the "should we even check this navigation" and
 * "does this /detect result count as flagged" rules can be unit-tested
 * directly (see tests/navigationGuard.test.js), matching this project's
 * existing pattern of pushing chrome.*-independent logic into small, pure
 * lib/ functions (urlUtils.js, apiClient.js's buildPayloadUrl).
 */

import { isHttpUrl } from "./urlUtils.js";

/**
 * Whether a webNavigation.onBeforeNavigate event should trigger a
 * background /detect check at all.
 *
 * @param {object} params
 * @param {number} params.frameId - Only frameId 0 (the top-level/main
 *     frame) is checked -- an iframe navigating to a bad URL is not the
 *     user's own navigation and would be noisy/wrong to warn about here.
 * @param {string} params.url - The navigation's target URL.
 * @param {boolean} params.enabled - Active Protection's stored on/off flag.
 * @param {boolean} params.allowlisted - Whether the target hostname is on
 *     the user's allowlist.
 * @param {boolean} params.bypassed - Whether this tab already has a live
 *     "Continue Anyway" bypass for this hostname (see background.js's
 *     in-memory bypass set) -- prevents an immediate re-warn loop right
 *     after the user explicitly chose to proceed.
 * @returns {boolean}
 */
export function shouldEvaluateNavigation({ frameId, url, enabled, allowlisted, bypassed }) {
  if (!enabled) return false;
  if (frameId !== 0) return false;
  if (!isHttpUrl(url)) return false;
  if (allowlisted) return false;
  if (bypassed) return false;
  return true;
}

/**
 * Whether a /detect result (the fast, hostname-only path -- see
 * apiClient.js::detect) is serious enough to redirect the tab to the
 * warning interstitial.
 * @param {{label?: string}} result
 * @returns {boolean}
 */
export function isFlaggedResult(result) {
  return Boolean(result) && result.label === "phishing";
}

/**
 * Build the in-memory bypass-set key used to suppress re-warning a tab
 * that just went through "Continue Anyway" for a given hostname.
 * @param {number} tabId
 * @param {string} hostname
 * @returns {string}
 */
export function bypassKey(tabId, hostname) {
  return `${tabId}:${hostname.toLowerCase()}`;
}

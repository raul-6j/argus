/**
 * Storage-backed state for Active Protection mode (Phase 3, F8) --
 * the opt-in pre-navigation warning feature.
 *
 * Uses chrome.storage.local (not .sync) deliberately: the `webNavigation`
 * permission this feature depends on is granted per-browser-profile, not
 * synced across devices, so tying the allowlist/enabled-flag to the same
 * local scope keeps them consistent with what the permission grant
 * actually covers. Cross-device allowlist sync via the existing
 * zero-knowledge vault (Phase 8) is a natural follow-up, not built here --
 * flagged rather than faked (see docs/DECISIONS.md).
 *
 * All functions here are plain chrome.storage.local reads/writes with no
 * other browser-API dependency, so they're unit-testable with a mocked
 * chrome.storage (see tests/protectionSettings.test.js), unlike
 * background.js's chrome.webNavigation/chrome.tabs wiring, which can only
 * be verified in a real browser (see extension/README.md).
 */

const _STORAGE_DEFAULTS = {
  activeProtectionEnabled: false,
  allowlist: [],
  overrideLog: [],
};

// Caps the locally-stored "Continue Anyway" audit log so it can't grow
// unbounded on a long-lived profile -- oldest entries drop off first.
const _MAX_OVERRIDE_LOG_ENTRIES = 50;

/**
 * @returns {Promise<{enabled: boolean, allowlist: string[]}>}
 */
export async function getProtectionSettings() {
  const { activeProtectionEnabled, allowlist } = await chrome.storage.local.get({
    activeProtectionEnabled: _STORAGE_DEFAULTS.activeProtectionEnabled,
    allowlist: _STORAGE_DEFAULTS.allowlist,
  });
  return { enabled: activeProtectionEnabled, allowlist };
}

/**
 * @param {boolean} enabled
 */
export async function setProtectionEnabled(enabled) {
  await chrome.storage.local.set({ activeProtectionEnabled: Boolean(enabled) });
}

/**
 * Pure membership check -- a hostname is allowlisted if it exactly matches
 * an entry (allowlisting "example.com" does NOT implicitly cover
 * "sub.example.com"; add each hostname you want covered explicitly, since
 * silently trusting subdomains is exactly the kind of over-broad allowlist
 * rule that DEC-023 already had to reason carefully about for the
 * threat-intel prefilter).
 * @param {string} hostname
 * @param {string[]} allowlist
 * @returns {boolean}
 */
export function isAllowlisted(hostname, allowlist) {
  if (!hostname) return false;
  return allowlist.includes(hostname.toLowerCase());
}

/**
 * @param {string} hostname
 */
export async function addToAllowlist(hostname) {
  const normalized = hostname.toLowerCase();
  const { allowlist } = await chrome.storage.local.get({ allowlist: _STORAGE_DEFAULTS.allowlist });
  if (!allowlist.includes(normalized)) {
    await chrome.storage.local.set({ allowlist: [...allowlist, normalized] });
  }
}

/**
 * @param {string} hostname
 */
export async function removeFromAllowlist(hostname) {
  const normalized = hostname.toLowerCase();
  const { allowlist } = await chrome.storage.local.get({ allowlist: _STORAGE_DEFAULTS.allowlist });
  await chrome.storage.local.set({ allowlist: allowlist.filter((h) => h !== normalized) });
}

/**
 * Append one entry to the local "Continue Anyway" audit log -- this is a
 * local-only record for the user's own visibility (shown in the options
 * page), never transmitted to the ARGUS API or anywhere else (S13's
 * no-telemetry convention applies here too).
 * @param {{hostname: string, url: string, timestamp: string}} entry
 */
export async function appendOverrideLog(entry) {
  const { overrideLog } = await chrome.storage.local.get({ overrideLog: _STORAGE_DEFAULTS.overrideLog });
  const updated = [...overrideLog, entry].slice(-_MAX_OVERRIDE_LOG_ENTRIES);
  await chrome.storage.local.set({ overrideLog: updated });
}

/**
 * @returns {Promise<Array<{hostname: string, url: string, timestamp: string}>>}
 */
export async function getOverrideLog() {
  const { overrideLog } = await chrome.storage.local.get({ overrideLog: _STORAGE_DEFAULTS.overrideLog });
  return overrideLog;
}

export async function clearOverrideLog() {
  await chrome.storage.local.set({ overrideLog: [] });
}

/**
 * ARGUS background service worker.
 *
 * Owns all network I/O to the ARGUS API (the popup only sends/receives
 * messages) -- the standard MV3 pattern, and it keeps host-permission
 * checks and fetch logic in one place rather than duplicated per UI page.
 *
 * This extension does NOT auto-scan every page navigation. It only checks a
 * URL when the user opens the popup for that tab (or clicks "Why?") --
 * a deliberate, more privacy-respecting design than firing a network
 * request to the ARGUS API on every single site the user visits.
 */

import "./lib/browserCompat.js";
import { deepScan, detect, explain } from "./lib/apiClient.js";
import { addToAllowlist, appendOverrideLog, getProtectionSettings } from "./lib/protectionSettings.js";
import { bypassKey, isFlaggedResult, shouldEvaluateNavigation } from "./lib/navigationGuard.js";
import { hostnameOf, toHostnameOnly } from "./lib/urlUtils.js";

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "DETECT") {
    detect(message.url)
      .then((result) => sendResponse({ ok: true, result }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true; // keep the message channel open for the async response
  }

  if (message?.type === "EXPLAIN") {
    explain(message.url)
      .then((result) => sendResponse({ ok: true, result }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (message?.type === "DEEP_DETECT") {
    // Phase 1 (P1.0/DEC-A/DEC-D): an explicit, user-initiated deep scan --
    // runs the server-side detection fusion layer. sendFullUrl is a
    // per-call opt-in (message.sendFullUrl), never the passive default.
    deepScan(message.url, { sendFullUrl: message.sendFullUrl })
      .then((result) => sendResponse({ ok: true, result }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (message?.type === "CONTINUE_ANYWAY") {
    // Phase 3 (F8): the interstitial's "Continue Anyway" action. Handled
    // here (not in interstitial.js directly) so the in-memory bypass set
    // and the tab navigation stay owned by the one module that also runs
    // the onBeforeNavigate check against that same bypass set.
    continueAnyway(message)
      .then((result) => sendResponse({ ok: true, result }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  return false;
});

// --------------------------------------------------------------------------- #
// Active Protection mode -- opt-in pre-navigation warning (Phase 3, F8)
//
// MV3 forbids blocking webRequest, so this cannot truly prevent a
// navigation from starting -- it's a "detect, then redirect the tab"
// pattern: onBeforeNavigate fires, we kick off a fast /detect check, and
// if it comes back flagged we redirect the tab to a bundled interstitial
// page. On a fast-loading page there is a real, documented race where the
// original page may render briefly before the redirect lands; this is an
// inherent MV3 constraint (no blocking webRequest for extensions), not a
// bug in this implementation.
//
// Privacy: deliberately reuses the SAME hostname-only fast path
// (apiClient.detect(), toHostnameOnly()) the popup's passive check already
// uses -- never the enrich:true fusion path -- so enabling Active
// Protection does not weaken the extension's hostname-only-by-default (S1)
// posture. The interstitial's "View Technical Analysis" action is a
// separate, explicit, user-initiated Deep Scan call (full URL, its own
// consent checkbox) -- exactly mirroring the popup's existing Deep Scan
// pattern -- for anyone who wants the richer signals/risk_band, rather than
// sending the full URL automatically on every navigation.
// --------------------------------------------------------------------------- #

// tabId:hostname -> true, for hostnames the user explicitly chose to
// proceed past via "Continue Anyway". In-memory only (cleared on service
// worker restart or tab close) -- a bypass is meant to last "for this
// browsing session in this tab", not indefinitely; use "Add to Allowlist"
// for a persistent opt-out.
const _bypassed = new Set();

// tabId -> warningId, for the most recent interstitial redirect in that
// tab. chrome.storage.session (keyed by warningId) is the single source of
// truth for the actual warning data; this map exists only so tab-close
// cleanup (below) knows which storage.session entry to remove.
const _pendingWarningsByTab = new Map();

let _navigationGuardRegistered = false;

/**
 * Attach the onBeforeNavigate listener if (and only if) the extension
 * currently holds the "webNavigation" permission. Idempotent -- safe to
 * call repeatedly (on service-worker startup, and again whenever the
 * permission or the enabled setting changes) without double-registering.
 */
function maybeRegisterNavigationGuard() {
  if (_navigationGuardRegistered) return;
  if (!chrome.webNavigation) return; // permission not currently granted
  chrome.webNavigation.onBeforeNavigate.addListener(handleBeforeNavigate);
  _navigationGuardRegistered = true;
}

async function handleBeforeNavigate(details) {
  try {
    const { enabled, allowlist } = await getProtectionSettings();
    const hostname = hostnameOf(details.url);
    const bypassed = _bypassed.has(bypassKey(details.tabId, hostname));

    if (
      !shouldEvaluateNavigation({
        frameId: details.frameId,
        url: details.url,
        enabled,
        allowlisted: allowlist.includes(hostname),
        bypassed,
      })
    ) {
      return;
    }

    // Hostname-only, same privacy floor as the popup's passive check --
    // see the module-level comment above. buildPayloadUrl() inside
    // detect() is idempotent on an already-hostname-only URL regardless of
    // the user's stored (manual-check-only) sendFullUrl setting.
    const result = await detect(toHostnameOnly(details.url));
    if (!isFlaggedResult(result)) return;

    const warningId = crypto.randomUUID();
    const record = { url: details.url, hostname, result, tabId: details.tabId };
    await chrome.storage.session.set({ [warningId]: record });
    _pendingWarningsByTab.set(details.tabId, warningId);

    const interstitialUrl = chrome.runtime.getURL(
      `interstitial/interstitial.html?id=${encodeURIComponent(warningId)}`
    );
    await chrome.tabs.update(details.tabId, { url: interstitialUrl });
  } catch (err) {
    // Fail OPEN: a check that errors (network down, API unreachable) must
    // never block a real navigation -- consistent with the API's own
    // graceful-degradation conventions (e.g. enrichment timeout falling
    // back to a lexical-only prediction rather than a hard error).
    console.warn("ARGUS Active Protection check failed, allowing navigation:", err);
  }
}

/**
 * Handle the interstitial's "Continue Anyway" action.
 * @param {{id: string, addToAllowlist?: boolean}} message
 */
async function continueAnyway(message) {
  const stored = await chrome.storage.session.get(message.id);
  const pending = stored[message.id];
  if (!pending) {
    throw new Error("This warning is no longer available (the browser may have restarted).");
  }

  const { url, hostname, tabId } = pending;

  if (message.addToAllowlist) {
    await addToAllowlist(hostname);
  }
  await appendOverrideLog({ hostname, url, timestamp: new Date().toISOString() });

  _bypassed.add(bypassKey(tabId, hostname));
  await chrome.tabs.update(tabId, { url });
  await chrome.storage.session.remove(message.id);
  _pendingWarningsByTab.delete(tabId);

  return { navigatedTo: url };
}

// Register at every service-worker startup (covers: browser launch,
// extension install/update, and waking from idle) -- and again whenever the
// permission is granted or the setting is flipped on, so a user doesn't
// need to reload the extension after enabling Active Protection mid-session.
maybeRegisterNavigationGuard();

if (chrome.permissions?.onAdded) {
  chrome.permissions.onAdded.addListener(() => maybeRegisterNavigationGuard());
}

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && changes.activeProtectionEnabled?.newValue === true) {
    maybeRegisterNavigationGuard();
  }
});

if (chrome.tabs?.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    const warningId = _pendingWarningsByTab.get(tabId);
    if (warningId) {
      chrome.storage.session.remove(warningId);
      _pendingWarningsByTab.delete(tabId);
    }
    for (const key of _bypassed) {
      if (key.startsWith(`${tabId}:`)) _bypassed.delete(key);
    }
  });
}

// --------------------------------------------------------------------------- #
// QR-code scanning entry point (Phase 3, F15): right-click an image ->
// "Scan QR Code with ARGUS". Decoding itself happens in qrscan.html (a real
// foreground page, needed for both a DOM/canvas context and for
// chrome.permissions.request()'s user-gesture requirement -- see
// qrscan/qrscan.js) -- this handler only opens that page with the clicked
// image's URL, it never fetches or decodes anything itself.
// --------------------------------------------------------------------------- #

const _QR_MENU_ID = "argus-scan-qr";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: _QR_MENU_ID,
      title: "Scan QR Code with ARGUS",
      contexts: ["image"],
    });
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId !== _QR_MENU_ID || !info.srcUrl) return;
  chrome.tabs.create({
    url: chrome.runtime.getURL(`qrscan/qrscan.html?imageUrl=${encodeURIComponent(info.srcUrl)}`),
  });
});

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

import { deepScan, detect, explain } from "./lib/apiClient.js";

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

  return false;
});

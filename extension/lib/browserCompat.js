/**
 * Cross-browser WebExtensions shim (Phase 5, F14 — Firefox port).
 *
 * Every module in this extension calls `chrome.*` directly, written against
 * Chrome MV3's promise-returning APIs (e.g. `await chrome.storage.sync.get(...)`
 * with no callback). Firefox implements the *same* functionality under a
 * native, promise-based `browser.*` global (its original WebExtensions API,
 * which predates and is more consistent than the `browser` promise support
 * Chrome later added) -- but Firefox's own `chrome.*` compatibility shim
 * exists for legacy Chrome-extension-callback-style code and is not a
 * reliable drop-in for the promise-style calls this codebase already uses
 * everywhere.
 *
 * Rather than rewriting every `chrome.*` call site to `browser.*` (touching
 * every module, doubling the diff, and needing a vendored polyfill
 * dependency), this one-line shim replaces the `chrome` global with the
 * native `browser` object wherever `browser` exists (Firefox, and Safari's
 * WebExtensions implementation) -- so every existing `chrome.*` call in this
 * codebase transparently starts calling Firefox's own promise-based API
 * instead. In Chrome, `browser` is undefined, so this is a no-op and
 * `chrome.*` keeps working exactly as it always has.
 *
 * Imported first (a plain side-effecting import, no named exports needed for
 * normal use) by every top-level page/worker in this extension --
 * background.js, popup/popup.js, options/options.js,
 * interstitial/interstitial.js, qrscan/qrscan.js, account/account.js -- each
 * of which is a separate execution context with its own globals, so each
 * needs its own import.
 */

export function installBrowserCompatShim(target = globalThis) {
  if (typeof target.browser !== "undefined") {
    target.chrome = target.browser;
  }
}

installBrowserCompatShim();

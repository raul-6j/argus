# ARGUS Phishing Detector — Browser Extension

Manifest V3 browser extension for the ARGUS phishing-detection API
(`src/api/`) — Chrome and Firefox from the same source tree (Phase 5, F14;
see "Firefox support" below). Anonymous, no-auth build (Phase 7) — checks the
current tab against ARGUS's `/detect` and `/explain` endpoints when you open
the popup. Phase 3 added two opt-in features: **Active Protection mode** (F8,
a pre-navigation warning) and **QR-code scanning** (F15) — both detailed
further down.

## Origin note (DEC-020)

This extension was originally planned (DEC-008) to vendor
[`arjunt-dev/aegis-chrome-extension`](https://github.com/arjunt-dev/aegis-chrome-extension)
with attribution. That plan was dropped: Aegis's README states *"This project
is currently unlicensed. All rights reserved,"* confirmed via the GitHub API —
there is no license granting reuse, so copying its code would not have been
legally sound regardless of attribution. **No Aegis code is used here.**
Aegis's publicly-documented *architecture* (MV3 service worker owning network
I/O, popup + options page split, a "Why?" explanation panel) was used as a
design reference; every file in this directory is original.

## Setup

1. Train a model and start the API first (see the repo root `CLAUDE.md`):
   ```bash
   venv/bin/python scripts/train.py --config configs/model_config.yaml
   venv/bin/python scripts/evaluate.py --config configs/model_config.yaml
   venv/bin/python -m flask --app src/api/app run --debug
   ```
2. In Chrome: `chrome://extensions` → enable **Developer mode** → **Load
   unpacked** → select this `extension/` directory. In Firefox, see "Firefox
   support" below instead.
3. Click the ARGUS icon → **Open Settings** (or right-click the icon →
   Options) → set **ARGUS API base URL** to `http://localhost:5000` → Save.
   The browser will prompt for permission to contact that origin — this is
   the `optional_host_permissions` grant (see Task 7.2 notes below), not a
   hardcoded manifest permission.
4. Visit any site, click the ARGUS icon. It checks the current tab's
   hostname (not the full URL — see S1 below) and shows a verdict.

No build step is required — this is plain ES modules loaded directly by the
browser (MV3 service workers support `"type": "module"` natively). `npm
install` is only needed to run the test suite.

## Firefox support (Phase 5, F14)

The same `extension/` directory loads in Firefox, unmodified — no separate
build, branch, or fork. Two things make this possible:

1. **`lib/browserCompat.js`.** Every module here is written against Chrome
   MV3's promise-returning `chrome.*` APIs (`await chrome.storage.sync.get(...)`,
   no callbacks). Firefox implements the same functionality under a native,
   already-promise-based `browser.*` global — so rather than rewriting every
   `chrome.*` call site to `browser.*` (and vendoring a polyfill), each
   top-level page/worker (`background.js`, `popup/popup.js`,
   `options/options.js`, `interstitial/interstitial.js`, `qrscan/qrscan.js`,
   `account/account.js`) imports this one-line shim first: if `browser` is
   defined (Firefox, and Safari's WebExtensions implementation), it aliases
   `chrome` to it, so every existing `chrome.*` call transparently starts
   calling Firefox's native API instead. In Chrome, `browser` is undefined,
   so this is a no-op.
2. **`manifest.json`'s `background` key lists both `service_worker` (Chrome)
   and `scripts` (Firefox, which runs MV3 background code as a
   non-persistent event page, not a true service worker) — each browser
   reads the key it understands and ignores the other. `browser_specific_settings.gecko`
   supplies Firefox's own stable-ID mechanism (Firefox doesn't read Chrome's
   `"key"` field) and a `strict_min_version` of 140.0 — the actual floor
   required by the manifest keys this extension uses (`optional_host_permissions`
   needs Firefox ≥128; `browser_specific_settings.gecko.data_collection_permissions`,
   now mandatory for all Firefox extensions, needs ≥140), verified with
   Mozilla's own `web-ext lint` (0 errors).**

**Loading in Firefox:** `about:debugging#/runtime/this-firefox` → **Load
Temporary Add-on…** → select `extension/manifest.json`. (Temporary — it
unloads when Firefox closes; permanent installation needs the extension
signed by Mozilla, out of scope for this anonymous MVP build, same reasoning
as Chrome's unpublished `.crx` — see "Stable extension ID" below.)

**Known Firefox gap, not hidden:** F15 (QR-code scanning) uses the browser's
native `BarcodeDetector` (Shape Detection API), which Firefox has not
shipped. `qrscan.js`'s existing `isBarcodeDetectorSupported()` check already
handles this by design — Firefox users see an honest "needs a recent Chrome"
message on the QR-scan page rather than a broken or silently-faked feature.
Every other feature (popup verdict, Deep Scan/"Why?", Active Protection
interstitial, options page, allowlist, vault/account) is fully functional in
Firefox.

## Architecture

```
extension/
  manifest.json        MV3 manifest (see Task 7.2 hardening notes below)
  background.js         Service worker — owns all fetch() calls to ARGUS,
                         the opt-in pre-navigation guard (F8), and the
                         QR-scan context menu (F15)
  lib/
    urlUtils.js          Hostname-only extraction, URL validation
    apiClient.js          POST /detect and POST /explain, speaks ARGUS's
                           actual response schema directly (no shim needed —
                           see DEC-020)
    protectionSettings.js Active Protection on/off flag, allowlist, and the
                           local-only "Continue Anyway" override log
                           (Phase 3, F8)
    navigationGuard.js    Pure decision logic for the pre-navigation check
                           (kept separate from background.js so it's
                           actually unit-testable — chrome.webNavigation/
                           chrome.tabs themselves are not)
  popup/                 Verdict + confidence + "Why?" SHAP panel + QR-scan launcher
  options/                API base URL + send-full-url toggle + Active
                          Protection toggle + allowlist/override-log manager
  interstitial/           Bundled warning page Active Protection redirects
                          to when a navigation is flagged (Phase 3, F8)
  qrscan/                 Upload-a-QR-code / right-click-an-image scanner,
                          decoded via the browser's native BarcodeDetector
                          (Phase 3, F15) — no vendored decoder library
  tests/                  vitest unit tests (lib/ only — chrome.* APIs mocked)
```

By default, the extension does **not** auto-scan every page you navigate
to — it only calls the API when you open the popup for a tab, a deliberate
choice to minimize how often (not just how much) data reaches the ARGUS
API, beyond what Task 7.2 asked for. **Active Protection mode** (Phase 3,
F8, off by default) is an explicit opt-in that checks every navigation's
*hostname* (same privacy floor as the popup's passive check, never the full
URL) before the page loads, and redirects to a bundled warning page if
flagged — see the section below.

## Active Protection mode (Phase 3, F8)

An opt-in pre-navigation warning, enabled from the options page. Turning it
on requests two things together: the `webNavigation` permission, and the
existing `optional_host_permissions` (`http://*/*`, `https://*/*`) — both
needed for `chrome.webNavigation.onBeforeNavigate` to see the URLs you
navigate to at all.

**How it works:** on every top-level navigation, the background service
worker calls the same fast, hostname-only `/detect` path the popup's
passive check already uses (never the full URL, never `enrich: true`). If
the result comes back flagged, the tab is redirected to a bundled
`interstitial/interstitial.html` warning page, which offers:

- **Go Back to Safety** — `history.back()`.
- **View Technical Analysis** — an explicit, separately-consented Deep Scan
  (full URL, `enrich: true`) for anyone who wants the richer risk band /
  signals / plain-language explanation — mirrors the popup's existing Deep
  Scan opt-in exactly, rather than sending the full URL automatically.
- **Continue Anyway** — proceeds to the original URL. Recorded in a
  local-only override log (visible/clearable from the options page, never
  sent to ARGUS or anywhere else) and optionally paired with **adding the
  site to your allowlist** so you're not warned again.

**A real, honest MV3 limitation:** extensions cannot block a navigation in
Manifest V3 (no blocking `webRequest`). This is a "detect, then redirect
the tab" pattern, not a true block — on a very fast-loading page, its
content may render briefly before the interstitial replaces it. That's an
inherent platform constraint, not a bug in this implementation.

Manual, real-browser verification of this feature (webNavigation timing,
tab redirect races, permission grant/revoke flows) is recorded the same way
Phase 7's original popup verification was — see `docs/HANDOFF.md` — since
none of `chrome.webNavigation`/`chrome.tabs`/`chrome.permissions`'s actual
runtime behavior can be exercised by vitest; only the pure decision logic
(`lib/navigationGuard.js`, `lib/protectionSettings.js`) is unit-tested here.

## QR-code ("quishing") scanning (Phase 3, F15)

Two entry points, both landing on `qrscan/qrscan.html`:

- **Popup / options page button** — opens the scanner for a local file
  upload. No permission needed; decoding happens entirely on-device.
- **Right-click an image → "Scan QR Code with ARGUS"** — opens the same
  page with the clicked image's URL. Fetching a third-party image to decode
  its pixels requires a one-time, origin-scoped permission prompt (`Fetch &
  Scan This Image` button), requested from that foreground page rather than
  the background service worker, since `chrome.permissions.request()` needs
  a genuine user gesture in a page context to reliably prompt.

Decoding uses the browser's native `BarcodeDetector` (Shape Detection API)
— **no vendored third-party QR-decoding library** is bundled, consistent
with this project's no-CDN/no-unverified-dependency posture. If your
browser doesn't support it, the page says so plainly rather than silently
failing.

Once a URL is decoded, scanning it is an explicit, separately-consented
action (same Deep Scan pattern as above) — the point of scanning a QR code
is usually to reveal an otherwise-hidden destination, so a hostname-only
check would defeat the purpose; the full decoded URL is sent only after
the user ticks the consent checkbox and clicks "Scan URL".

## Privacy/security hardening (Task 7.2)

| ID | Issue | How it's addressed here |
|----|-------|--------------------------|
| S1 | Full URL sent to server by default | `lib/urlUtils.js::toHostnameOnly()` strips path/query/fragment before every `/detect` and `/explain` call unless the user opts in via the options page's "send full URL" toggle |
| S8 | `127.0.0.1`/`localhost` hardcoded in manifest | Nothing is hardcoded — `manifest.json` has no `host_permissions` at all, only `optional_host_permissions: ["http://*/*", "https://*/*"]`. The actual origin is requested at runtime (`chrome.permissions.request`) in `options.js`, scoped to whatever base URL the user configures |
| S11 | `web_accessible_resources` too broad | `manifest.json` declares an empty `web_accessible_resources` list — this extension has no content scripts or web-page-reachable assets to expose |

`manifest.json` also sets a strict CSP (`script-src 'self'; object-src
'none';`) and requests only `storage`, `activeTab`, and `contextMenus`
(needed unconditionally for F15's right-click entry point) as mandatory
permissions — no `tabs` or `declarativeNetRequest`. `webNavigation` (needed
for the opt-in Active Protection mode, F8) is listed only in
`optional_permissions`, so a fresh install has it granted to nobody; it's
requested at runtime, bundled with the same `optional_host_permissions`
grant, only when the user explicitly enables Active Protection from the
options page.

### Stable extension ID

`manifest.json` pins a `"key"` (an RSA public key) so the Chrome extension ID
is deterministic (`dhmdjnjpmbiahdoglbgcdpkilaodlcpd`) rather than
Chrome-assigned-at-random from the install path. This lets
`configs/api_config.yaml`'s `cors_origins` name the real ID instead of a
placeholder — loading this directory unpacked will always produce that same
ID. (The corresponding private key was used only to derive the ID and was
discarded — it's not needed for `Load unpacked`, only for signing a
published `.crx`, which is out of scope for this anonymous MVP build.)

Firefox doesn't read Chrome's `"key"` field at all — it derives extension
*identity* (for update/signing/permission-persistence purposes) from
`browser_specific_settings.gecko.id`
(`argus-phishing-detector@argus-project.dev`, a stable, made-up-but-fixed
string per Mozilla's required format, not a real registered domain).

That ID is **not** the same thing as the extension's actual
`moz-extension://<uuid>` *origin* — the one `cors_origins` needs to match.
Unlike Chrome (whose ID is deterministically derived from the pinned public
key, so it's the same on every machine), Firefox deliberately randomizes the
`moz-extension://` UUID per profile/install, specifically so extension
origins can't be used to fingerprint users across sites — `gecko.id` does
not pin it. This means, unlike Chrome, `configs/api_config.yaml`'s
`cors_origins` can't list one fixed Firefox origin that works for everyone.
To reach a non-`localhost` API from Firefox, find your own install's actual
origin (`about:debugging#/runtime/this-firefox` → the add-on's "Internal
UUID"), add `moz-extension://<that-uuid>` to your local `cors_origins`, and
restart the API — a real, inherent Firefox behavior difference, not a gap in
this port.

## Testing

```bash
cd extension
npm install
npm test    # vitest
npm run lint  # eslint
npx web-ext lint --source-dir=. --self-hosted  # Firefox manifest/API compatibility (F14)
```

`web-ext lint` is Mozilla's own manifest/API validator — it caught two real
issues while building the Firefox port (`optional_host_permissions` and
`browser_specific_settings.gecko.data_collection_permissions` both need a
higher `strict_min_version` than first guessed) without needing Firefox
installed at all. Current state: 0 errors, 2 expected warnings (Firefox
correctly ignoring `background.service_worker` in favor of `background.scripts`
— by design, see "Firefox support" above — and an Android-specific
minimum-version note; this port targets desktop Firefox only).

Tests cover every `lib/*.js` module (chrome.storage/fetch mocked), including
the new pure decision logic added for F8 (`navigationGuard.js`) and its
storage-backed settings (`protectionSettings.js`). `background.js`'s actual
`chrome.webNavigation`/`chrome.tabs`/`chrome.contextMenus`/`chrome.permissions`
wiring, and the `interstitial/`/`qrscan/` pages' DOM- and
`BarcodeDetector`-heavy code, are **not** unit-tested here — by the same
long-standing project convention as the original popup (see
`docs/HANDOFF.md`'s Phase 7 entry): these can only be meaningfully verified
in a real browser, not with vitest + mocked `chrome.*`. If you're verifying
Active Protection or QR scanning by hand, exercise: enabling/disabling the
permission grant, a flagged navigation actually redirecting to the
interstitial, "Continue Anyway" not re-warning within the same tab, the
allowlist actually suppressing future checks, and both QR entry points
(file upload and right-click-image) against a real decodable QR code.

**F14's verification is honestly partial, not overclaimed:** `npm test`/`npm
run lint` pass with the `browserCompat.js` changes, and `web-ext lint`
confirms the manifest itself is valid, installable Firefox WebExtension
JSON (0 errors) — but no machine with an actual Firefox binary was available
in the environment this port was built in, so the "load it in
`about:debugging`, click through the popup/options/Active-Protection/QR-scan
flows" pass a human would normally do here has not happened yet. Treat the
Firefox port as code-complete and manifest-valid, not yet hands-on-verified
in a running Firefox — same "disclose what wasn't checked" standard as every
other manual-verification item in this file.

## Known limitations (carried from DEC-018)

The underlying model has a documented real-world generalisation gap for
phishing hosted on legitimate free platforms (URL shorteners, no-code site
builders) — see `docs/DECISIONS.md` DEC-018. This is not surfaced in the UI
(DEC-019): there's no reliable per-prediction signal to attach a caveat to.
Treat a "Legitimate" verdict as "nothing this particular feature set caught,"
not a guarantee.

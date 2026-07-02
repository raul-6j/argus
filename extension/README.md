# ARGUS Phishing Detector — Browser Extension

Manifest V3 Chrome extension for the ARGUS phishing-detection API (`src/api/`).
Anonymous, no-auth build (Phase 7) — checks the current tab against ARGUS's
`/detect` and `/explain` endpoints when you open the popup.

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
   unpacked** → select this `extension/` directory.
3. Click the ARGUS icon → **Open Settings** (or right-click the icon →
   Options) → set **ARGUS API base URL** to `http://localhost:5000` → Save.
   Chrome will prompt for permission to contact that origin — this is the
   `optional_host_permissions` grant (see Task 7.2 notes below), not a
   hardcoded manifest permission.
4. Visit any site, click the ARGUS icon. It checks the current tab's
   hostname (not the full URL — see S1 below) and shows a verdict.

No build step is required — this is plain ES modules loaded directly by the
browser (MV3 service workers support `"type": "module"` natively). `npm
install` is only needed to run the test suite.

## Architecture

```
extension/
  manifest.json        MV3 manifest (see Task 7.2 hardening notes below)
  background.js         Service worker — owns all fetch() calls to ARGUS
  lib/
    urlUtils.js          Hostname-only extraction, URL validation
    apiClient.js          POST /detect and POST /explain, speaks ARGUS's
                           actual response schema directly (no shim needed —
                           see DEC-020)
  popup/                 Verdict + confidence + "Why?" SHAP panel
  options/                API base URL + send-full-url toggle
  tests/                  vitest unit tests (lib/ only — chrome.* APIs mocked)
```

The extension does **not** auto-scan every page you navigate to. It only
calls the API when you open the popup for a tab — a deliberate choice to
minimize how often (not just how much) data reaches the ARGUS API, beyond
what Task 7.2 asked for.

## Privacy/security hardening (Task 7.2)

| ID | Issue | How it's addressed here |
|----|-------|--------------------------|
| S1 | Full URL sent to server by default | `lib/urlUtils.js::toHostnameOnly()` strips path/query/fragment before every `/detect` and `/explain` call unless the user opts in via the options page's "send full URL" toggle |
| S8 | `127.0.0.1`/`localhost` hardcoded in manifest | Nothing is hardcoded — `manifest.json` has no `host_permissions` at all, only `optional_host_permissions: ["http://*/*", "https://*/*"]`. The actual origin is requested at runtime (`chrome.permissions.request`) in `options.js`, scoped to whatever base URL the user configures |
| S11 | `web_accessible_resources` too broad | `manifest.json` declares an empty `web_accessible_resources` list — this extension has no content scripts or web-page-reachable assets to expose |

`manifest.json` also sets a strict CSP (`script-src 'self'; object-src
'none';`) and requests only `storage` + `activeTab` — no `tabs`,
`webNavigation`, or `declarativeNetRequest`, since nothing here needs
always-on page monitoring.

### Stable extension ID

`manifest.json` pins a `"key"` (an RSA public key) so the extension ID is
deterministic (`dhmdjnjpmbiahdoglbgcdpkilaodlcpd`) rather than
Chrome-assigned-at-random from the install path. This lets
`configs/api_config.yaml`'s `cors_origins` name the real ID instead of a
placeholder — loading this directory unpacked will always produce that same
ID. (The corresponding private key was used only to derive the ID and was
discarded — it's not needed for `Load unpacked`, only for signing a
published `.crx`, which is out of scope for this anonymous MVP build.)

## Testing

```bash
cd extension
npm install
npm test
```

Tests cover `lib/urlUtils.js` and `lib/apiClient.js` (chrome.storage/fetch
mocked). Manual verification against a real running API + Chrome is
documented in `docs/HANDOFF.md`'s Phase 7 entry, since `chrome.*` APIs can't
be exercised outside an actual browser.

## Known limitations (carried from DEC-018)

The underlying model has a documented real-world generalisation gap for
phishing hosted on legitimate free platforms (URL shorteners, no-code site
builders) — see `docs/DECISIONS.md` DEC-018. This is not surfaced in the UI
(DEC-019): there's no reliable per-prediction signal to attach a caveat to.
Treat a "Legitimate" verdict as "nothing this particular feature set caught,"
not a guarantee.

import "../lib/browserCompat.js";
import { icon, hydrateIcons, SIGNAL_ICONS } from "../lib/icons.js";

const loadingEl = document.getElementById("loading");
const resultEl = document.getElementById("result");
const errorEl = document.getElementById("errorState");
const hostnameEl = document.getElementById("hostname");
const verdictEl = document.getElementById("verdict");
const riskBandEl = document.getElementById("riskBand");
const confidenceEl = document.getElementById("confidence");
const ringArcEl = document.getElementById("ringArc");
const ringValueEl = document.getElementById("ringValue");
const whyBtn = document.getElementById("whyBtn");
const shapPanel = document.getElementById("shapPanel");
const errorMessageEl = document.getElementById("errorMessage");
const openOptionsBtn = document.getElementById("openOptions");
const openSettingsBtn = document.getElementById("openSettings");
const scanQrBtn = document.getElementById("scanQrBtn");
const deepScanBtn = document.getElementById("deepScanBtn");
const deepScanConsent = document.getElementById("deepScanConsent");
const deepScanFullUrlCheckbox = document.getElementById("deepScanFullUrl");
const deepScanPanel = document.getElementById("deepScanPanel");
const signalsPanel = document.getElementById("signalsPanel");
const plainExplanationEl = document.getElementById("plainExplanation");
const recentSection = document.getElementById("recentSection");
const recentToggle = document.getElementById("recentToggle");
const recentList = document.getElementById("recentList");
const recentCount = document.getElementById("recentCount");

const RING_RADIUS = 36;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;

const _RISK_BAND_LABELS = {
  low: "Low Risk",
  caution: "Caution",
  suspicious: "Suspicious",
  high: "High Risk",
  critical: "Critical",
};

hydrateIcons();

function showState(name) {
  loadingEl.classList.toggle("hidden", name !== "loading");
  resultEl.classList.toggle("hidden", name !== "result");
  errorEl.classList.toggle("hidden", name !== "error");
}

/**
 * Swap a button into a busy state without destroying its icon.
 *
 * The buttons carry an inline SVG plus a text node, so the old
 * `button.textContent = "..."` pattern would silently wipe the glyph.
 * @param {HTMLButtonElement} button
 * @param {boolean} busy
 * @param {string} label
 */
function setBusy(button, busy, label) {
  button.disabled = busy;
  button.innerHTML = "";
  if (busy) {
    button.setAttribute("aria-busy", "true");
    const spinner = document.createElement("span");
    spinner.className = "spinner";
    spinner.setAttribute("aria-hidden", "true");
    button.appendChild(spinner);
  } else {
    button.removeAttribute("aria-busy");
    const glyph = icon(button.dataset.icon);
    if (glyph) button.appendChild(glyph);
  }
  button.appendChild(document.createTextNode(label));
}

/** Paint the verdict pill (icon + word) without clobbering its base class. */
function setVerdict(label) {
  verdictEl.className = `verdict-badge ${label}`;
  verdictEl.innerHTML = "";
  const glyph = icon(label === "phishing" ? "alert-triangle" : "check-circle");
  if (glyph) verdictEl.appendChild(glyph);
  verdictEl.appendChild(
    document.createTextNode(label === "phishing" ? "Phishing" : "Legitimate")
  );
}

/**
 * Drive the radial indicator.
 * @param {number} value 0..1
 * @param {string} tone class controlling the arc colour (verdict or risk band)
 */
function setRing(value, tone) {
  const pct = Math.max(0, Math.min(1, value));
  ringArcEl.setAttribute("class", `ring-arc ${tone}`);
  ringArcEl.setAttribute("stroke-dasharray", String(RING_CIRCUMFERENCE));
  ringArcEl.setAttribute("stroke-dashoffset", String(RING_CIRCUMFERENCE));
  ringValueEl.textContent = String(Math.round(pct * 100));
  requestAnimationFrame(() => {
    ringArcEl.setAttribute("stroke-dashoffset", String(RING_CIRCUMFERENCE * (1 - pct)));
  });
}

function renderResult(result) {
  hostnameEl.textContent = new URL(result.url).hostname;
  setVerdict(result.label);
  confidenceEl.textContent = `Model confidence · ${(result.confidence * 100).toFixed(1)}%`;
  setRing(result.confidence, result.label);
  // The quick (non-deep-scan) check uses /detect's fast, hostname-only path,
  // which never returns risk_score/risk_band (see docs/DECISIONS.md DEC-A) --
  // only a Deep Scan (renderDeepScanResult) has a risk band to show.
  riskBandEl.classList.add("hidden");
  showState("result");
}

/**
 * Render a deep-scan result's detection signals (Phase 1, DEC-A) as
 * labeled badges, plus its plain-language explanation. Updates the verdict/
 * confidence in place if the fusion layer's decision differs from the
 * quick check's model-only decision.
 * @param {{label: string, confidence: number, risk_score?: number, risk_band?: string, signals?: Array<{name: string, triggered: boolean, direction: string, evidence: object}>}} result
 */
function renderDeepScanResult(result) {
  setVerdict(result.label);
  confidenceEl.textContent = `Model confidence · ${(result.confidence * 100).toFixed(1)}%`;

  if (result.risk_band) {
    riskBandEl.textContent = _RISK_BAND_LABELS[result.risk_band] || result.risk_band;
    riskBandEl.className = `risk-band-badge ${result.risk_band}`;
    riskBandEl.classList.remove("hidden");
  } else {
    riskBandEl.classList.add("hidden");
  }

  // A deep scan produces a real risk score, so the ring switches from
  // "confidence" to the more meaningful calibrated risk reading.
  if (typeof result.risk_score === "number") {
    setRing(result.risk_score, result.risk_band || result.label);
  } else {
    setRing(result.confidence, result.label);
  }

  signalsPanel.innerHTML = "";
  const triggered = (result.signals || []).filter((s) => s.triggered);
  for (const signal of triggered) {
    const badge = document.createElement("span");
    badge.className = `signal-badge ${signal.direction}`;
    const glyph = icon(SIGNAL_ICONS[signal.name] || "activity");
    if (glyph) badge.appendChild(glyph);
    badge.appendChild(document.createTextNode(signalLabel(signal)));
    badge.setAttribute("data-tooltip", JSON.stringify(signal.evidence, null, 2));
    badge.tabIndex = 0;
    signalsPanel.appendChild(badge);
  }
  if (triggered.length === 0) {
    const badge = document.createElement("span");
    badge.className = "signal-badge neutral";
    const glyph = icon("check");
    if (glyph) badge.appendChild(glyph);
    badge.appendChild(document.createTextNode("No brand-intelligence signals triggered"));
    signalsPanel.appendChild(badge);
  }

  plainExplanationEl.textContent = result.plain_explanation || "";
  deepScanPanel.classList.remove("hidden");
}

/**
 * Build a short human label for a signal badge from its name + evidence.
 * @param {{name: string, evidence: object}} signal
 * @returns {string}
 */
function signalLabel(signal) {
  const brand = signal.evidence?.impersonated_brand || signal.evidence?.page_brand;
  switch (signal.name) {
    case "typosquat":
      return brand ? `Look-alike of ${brand}` : "Look-alike domain";
    case "favicon_match":
      return brand ? `Icon matches ${brand}` : "Icon matches a known brand";
    case "brand_mismatch":
      return brand ? `Claims to be ${brand}` : "Brand/domain mismatch";
    case "cert_intel":
      return "Suspicious certificate";
    case "redirect_chain":
      return brand ? `Redirects to a ${brand} look-alike` : "Suspicious redirect";
    case "credential_context":
      return "Requests sensitive data suspiciously";
    case "platform_risk":
      return "Hosted on a free/shared platform with other risk signals";
    case "semantic_content":
      return "Page wording uses social-engineering pressure tactics";
    default:
      return signal.name;
  }
}

function renderError(message) {
  errorMessageEl.textContent = message;
  showState("error");
}

/**
 * Render the top-5 SHAP attributions as signed horizontal bars.
 * Positive shap_value pushes the prediction toward "phishing" (red);
 * negative pushes toward "legitimate" (green) -- see src/models/explain.py.
 */
function renderShap(top5Features) {
  shapPanel.innerHTML = "";

  if (!Array.isArray(top5Features) || top5Features.length === 0) {
    shapPanel.textContent = "No explanation data available for this page.";
    shapPanel.classList.remove("hidden");
    return;
  }

  const heading = document.createElement("span");
  heading.className = "eyebrow";
  heading.textContent = "Top model features";
  shapPanel.appendChild(heading);

  const maxAbs = Math.max(...top5Features.map((f) => Math.abs(f.shap_value)), 1e-9);

  for (const item of top5Features) {
    const row = document.createElement("div");
    row.className = "shap-row";

    const label = document.createElement("span");
    label.className = "shap-feature";
    label.textContent = `${item.feature} (${item.feature_value})`;
    label.title = `${item.feature} = ${item.feature_value}`;
    row.appendChild(label);

    const track = document.createElement("span");
    track.className = "shap-bar-track";
    const bar = document.createElement("span");
    const towardPhishing = item.shap_value > 0;
    bar.className = `shap-bar ${towardPhishing ? "toward-phishing" : "away-from-phishing"}`;
    const widthPct = (Math.abs(item.shap_value) / maxAbs) * 50;
    bar.style.width = "0%";
    track.appendChild(bar);
    row.appendChild(track);
    requestAnimationFrame(() => {
      bar.style.width = `${widthPct}%`;
    });

    shapPanel.appendChild(row);
  }
  shapPanel.classList.remove("hidden");
}

/* ------------------------------------------------------- recent scans ---- */

/**
 * A short, device-local log of what this popup already checked, so reopening
 * it shows context instead of a blank slate.
 *
 * Stores hostname + verdict + timestamp only — never a full URL, never a
 * path or query string — which keeps it at the same privacy floor as the
 * passive check itself. Written to `chrome.storage.local` (not `.sync`) so
 * it never leaves this device, matching the precedent set by the extension's
 * token storage.
 */
const RECENT_KEY = "recentScans";
const RECENT_LIMIT = 8;

async function recordRecentScan(hostname, label) {
  try {
    const stored = await chrome.storage.local.get({ [RECENT_KEY]: [] });
    const entries = stored[RECENT_KEY].filter((entry) => entry.hostname !== hostname);
    entries.unshift({ hostname, label, timestamp: Date.now() });
    await chrome.storage.local.set({ [RECENT_KEY]: entries.slice(0, RECENT_LIMIT) });
  } catch {
    // A failed local write must never break the actual check the user
    // opened the popup for.
  }
}

/** @param {number} timestamp @returns {string} */
function relativeTime(timestamp) {
  const seconds = Math.round((Date.now() - timestamp) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

async function renderRecentScans() {
  let entries;
  try {
    const stored = await chrome.storage.local.get({ [RECENT_KEY]: [] });
    entries = stored[RECENT_KEY];
  } catch {
    // Nothing to show is the correct fallback here -- this list is context,
    // never the reason the popup was opened.
    return;
  }
  if (entries.length === 0) return;

  recentList.innerHTML = "";
  for (const entry of entries) {
    const item = document.createElement("li");

    const badge = document.createElement("span");
    badge.className = `badge badge--${entry.label === "phishing" ? "danger" : "success"}`;
    const glyph = icon(entry.label === "phishing" ? "alert-triangle" : "check-circle");
    if (glyph) badge.appendChild(glyph);
    item.appendChild(badge);

    const host = document.createElement("span");
    host.className = "recent-host";
    host.textContent = entry.hostname;
    host.title = entry.hostname;
    item.appendChild(host);

    const when = document.createElement("span");
    when.className = "recent-when";
    when.textContent = relativeTime(entry.timestamp);
    item.appendChild(when);

    recentList.appendChild(item);
  }

  recentCount.textContent = String(entries.length);
  recentSection.classList.remove("hidden");
}

recentToggle.addEventListener("click", () => {
  const open = recentToggle.getAttribute("aria-expanded") === "true";
  recentToggle.setAttribute("aria-expanded", String(!open));
  recentList.classList.toggle("hidden", open);
});

/* ------------------------------------------------------------------------ */

async function getActiveTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) {
    throw new Error("Could not read the current tab's URL.");
  }
  return tab.url;
}

async function sendMessage(message) {
  const response = await chrome.runtime.sendMessage(message);
  if (!response.ok) {
    throw new Error(response.error);
  }
  return response.result;
}

async function init() {
  showState("loading");
  renderRecentScans();
  try {
    const url = await getActiveTabUrl();
    hostnameEl.textContent = new URL(url).hostname;
    const result = await sendMessage({ type: "DETECT", url });
    renderResult(result);
    recordRecentScan(new URL(result.url).hostname, result.label);

    whyBtn.addEventListener("click", async () => {
      setBusy(whyBtn, true, "Loading…");
      try {
        const explanation = await sendMessage({ type: "EXPLAIN", url });
        renderShap(explanation.top5_features);
      } catch (err) {
        renderShap([]);
        shapPanel.textContent = err.message;
        shapPanel.classList.remove("hidden");
      } finally {
        setBusy(whyBtn, false, "Why?");
      }
    });

    // Deep Scan (Phase 1, DEC-A/DEC-D): explicit, user-initiated -- shows a
    // one-time consent toggle for sending the full URL (default off, the
    // passive check above always stays hostname-only) before running.
    deepScanBtn.addEventListener("click", async () => {
      if (deepScanConsent.classList.contains("hidden")) {
        deepScanConsent.classList.remove("hidden");
        return;
      }
      setBusy(deepScanBtn, true, "Scanning…");
      try {
        const deepResult = await sendMessage({
          type: "DEEP_DETECT",
          url,
          sendFullUrl: deepScanFullUrlCheckbox.checked,
        });
        renderDeepScanResult(deepResult);
        recordRecentScan(new URL(url).hostname, deepResult.label);
      } catch (err) {
        deepScanPanel.classList.remove("hidden");
        signalsPanel.textContent = "";
        plainExplanationEl.textContent = err.message;
      } finally {
        setBusy(deepScanBtn, false, "Deep Scan");
      }
    });
  } catch (err) {
    renderError(err.message);
  }
}

openOptionsBtn.addEventListener("click", () => chrome.runtime.openOptionsPage());
openSettingsBtn.addEventListener("click", () => chrome.runtime.openOptionsPage());
scanQrBtn.addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("qrscan/qrscan.html") });
});
document.addEventListener("DOMContentLoaded", init);

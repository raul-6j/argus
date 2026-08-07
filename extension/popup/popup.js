import "../lib/browserCompat.js";

const loadingEl = document.getElementById("loading");
const resultEl = document.getElementById("result");
const errorEl = document.getElementById("errorState");
const hostnameEl = document.getElementById("hostname");
const verdictEl = document.getElementById("verdict");
const riskBandEl = document.getElementById("riskBand");
const confidenceEl = document.getElementById("confidence");
const whyBtn = document.getElementById("whyBtn");
const shapPanel = document.getElementById("shapPanel");
const errorMessageEl = document.getElementById("errorMessage");
const openOptionsBtn = document.getElementById("openOptions");
const scanQrBtn = document.getElementById("scanQrBtn");
const deepScanBtn = document.getElementById("deepScanBtn");
const deepScanConsent = document.getElementById("deepScanConsent");
const deepScanFullUrlCheckbox = document.getElementById("deepScanFullUrl");
const deepScanPanel = document.getElementById("deepScanPanel");
const signalsPanel = document.getElementById("signalsPanel");
const plainExplanationEl = document.getElementById("plainExplanation");

function showState(name) {
  loadingEl.classList.toggle("hidden", name !== "loading");
  resultEl.classList.toggle("hidden", name !== "result");
  errorEl.classList.toggle("hidden", name !== "error");
}

function renderResult(result) {
  hostnameEl.textContent = new URL(result.url).hostname;
  verdictEl.textContent = result.label === "phishing" ? "⚠ Phishing" : "✓ Legitimate";
  verdictEl.className = `verdict ${result.label}`;
  confidenceEl.textContent = `Confidence: ${(result.confidence * 100).toFixed(1)}%`;
  // The quick (non-deep-scan) check uses /detect's fast, hostname-only path,
  // which never returns risk_score/risk_band (see docs/DECISIONS.md DEC-A) --
  // only a Deep Scan (renderDeepScanResult) has a risk band to show.
  riskBandEl.classList.add("hidden");
  showState("result");
}

const _RISK_BAND_LABELS = {
  low: "Low Risk",
  caution: "Caution",
  suspicious: "Suspicious",
  high: "High Risk",
  critical: "Critical",
};

/**
 * Render a deep-scan result's detection signals (Phase 1, DEC-A) as
 * labeled badges, plus its plain-language explanation. Updates the verdict/
 * confidence in place if the fusion layer's decision differs from the
 * quick check's model-only decision.
 * @param {{label: string, confidence: number, risk_score?: number, risk_band?: string, signals?: Array<{name: string, triggered: boolean, direction: string, evidence: object}>}} result
 */
function renderDeepScanResult(result) {
  verdictEl.textContent = result.label === "phishing" ? "⚠ Phishing" : "✓ Legitimate";
  verdictEl.className = `verdict ${result.label}`;
  confidenceEl.textContent = `Confidence: ${(result.confidence * 100).toFixed(1)}%`;

  if (result.risk_band) {
    riskBandEl.textContent = _RISK_BAND_LABELS[result.risk_band] || result.risk_band;
    riskBandEl.className = `risk-band-badge ${result.risk_band}`;
    riskBandEl.classList.remove("hidden");
  } else {
    riskBandEl.classList.add("hidden");
  }

  signalsPanel.innerHTML = "";
  const triggered = (result.signals || []).filter((s) => s.triggered);
  for (const signal of triggered) {
    const badge = document.createElement("span");
    badge.className = `signal-badge ${signal.direction}`;
    badge.textContent = signalLabel(signal);
    badge.title = JSON.stringify(signal.evidence);
    signalsPanel.appendChild(badge);
  }
  if (triggered.length === 0) {
    const badge = document.createElement("span");
    badge.className = "signal-badge neutral";
    badge.textContent = "No brand-intelligence signals triggered";
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
  const maxAbs = Math.max(...top5Features.map((f) => Math.abs(f.shap_value)), 1e-9);

  for (const item of top5Features) {
    const row = document.createElement("div");
    row.className = "shap-row";

    const label = document.createElement("span");
    label.className = "shap-feature";
    label.textContent = `${item.feature} (${item.feature_value})`;
    row.appendChild(label);

    const track = document.createElement("span");
    track.className = "shap-bar-track";
    const bar = document.createElement("span");
    const towardPhishing = item.shap_value > 0;
    bar.className = `shap-bar ${towardPhishing ? "toward-phishing" : "away-from-phishing"}`;
    const widthPct = (Math.abs(item.shap_value) / maxAbs) * 50;
    bar.style.width = `${widthPct}%`;
    track.appendChild(bar);
    row.appendChild(track);

    shapPanel.appendChild(row);
  }
  shapPanel.classList.remove("hidden");
}

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
  try {
    const url = await getActiveTabUrl();
    const result = await sendMessage({ type: "DETECT", url });
    renderResult(result);

    whyBtn.addEventListener("click", async () => {
      whyBtn.disabled = true;
      whyBtn.textContent = "Loading...";
      try {
        const explanation = await sendMessage({ type: "EXPLAIN", url });
        renderShap(explanation.top5_features);
      } catch (err) {
        renderShap([]);
        shapPanel.textContent = err.message;
        shapPanel.classList.remove("hidden");
      } finally {
        whyBtn.disabled = false;
        whyBtn.textContent = "Why?";
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
      deepScanBtn.disabled = true;
      deepScanBtn.textContent = "Scanning...";
      try {
        const deepResult = await sendMessage({
          type: "DEEP_DETECT",
          url,
          sendFullUrl: deepScanFullUrlCheckbox.checked,
        });
        renderDeepScanResult(deepResult);
      } catch (err) {
        deepScanPanel.classList.remove("hidden");
        signalsPanel.textContent = "";
        plainExplanationEl.textContent = err.message;
      } finally {
        deepScanBtn.disabled = false;
        deepScanBtn.textContent = "Deep Scan";
      }
    });
  } catch (err) {
    renderError(err.message);
  }
}

openOptionsBtn.addEventListener("click", () => chrome.runtime.openOptionsPage());
scanQrBtn.addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("qrscan/qrscan.html") });
});
document.addEventListener("DOMContentLoaded", init);

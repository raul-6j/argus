/**
 * ARGUS pre-navigation warning interstitial (Phase 3, F8).
 *
 * A bundled extension page (chrome-extension://<id>/interstitial/...) --
 * deliberately NOT injected into the flagged site's own origin, so the
 * warning can never be scripted or spoofed away by the page it's warning
 * about (the same reasoning as any browser's built-in phishing
 * interstitial). All network calls go through background.js via
 * chrome.runtime.sendMessage, matching the popup's existing
 * "background owns all fetch()" architecture -- this page never imports
 * apiClient.js directly.
 */

import "../lib/browserCompat.js";
import { addToAllowlist } from "../lib/protectionSettings.js";

const loadingState = document.getElementById("loadingState");
const missingState = document.getElementById("missingState");
const warningState = document.getElementById("warningState");

const hostnameEl = document.getElementById("hostname");
const verdictBadgeEl = document.getElementById("verdictBadge");
const confidenceEl = document.getElementById("confidence");
const sourceNoteEl = document.getElementById("sourceNote");

const goBackBtn = document.getElementById("goBackBtn");
const goBackMissingBtn = document.getElementById("goBackMissing");
const viewTechnicalBtn = document.getElementById("viewTechnicalBtn");
const technicalPanel = document.getElementById("technicalPanel");
const deepScanConsent = document.getElementById("deepScanConsent");
const runDeepScanBtn = document.getElementById("runDeepScanBtn");
const deepScanResult = document.getElementById("deepScanResult");
const riskBandBadgeEl = document.getElementById("riskBandBadge");
const signalsPanelEl = document.getElementById("signalsPanel");
const plainExplanationEl = document.getElementById("plainExplanation");
const deepScanErrorEl = document.getElementById("deepScanError");

const understandRiskCheckbox = document.getElementById("understandRisk");
const alsoAllowlistCheckbox = document.getElementById("alsoAllowlist");
const continueBtn = document.getElementById("continueBtn");
const allowlistOnlyBtn = document.getElementById("allowlistOnlyBtn");
const continueStatusEl = document.getElementById("continueStatus");

function showState(name) {
  loadingState.classList.toggle("hidden", name !== "loading");
  missingState.classList.toggle("hidden", name !== "missing");
  warningState.classList.toggle("hidden", name !== "warning");
}

const _RISK_BAND_LABELS = {
  low: "Low Risk",
  caution: "Caution",
  suspicious: "Suspicious",
  high: "High Risk",
  critical: "Critical",
};

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

async function sendMessage(message) {
  const response = await chrome.runtime.sendMessage(message);
  if (!response.ok) {
    throw new Error(response.error);
  }
  return response.result;
}

async function init() {
  const params = new URLSearchParams(location.search);
  const warningId = params.get("id");

  if (!warningId) {
    showState("missing");
    return;
  }

  const stored = await chrome.storage.session.get(warningId);
  const pending = stored[warningId];
  if (!pending) {
    showState("missing");
    return;
  }

  const { url, hostname, result } = pending;

  hostnameEl.textContent = hostname;
  verdictBadgeEl.textContent = result.label === "phishing" ? "⚠ Phishing" : "Flagged";
  confidenceEl.textContent = `Confidence: ${(result.confidence * 100).toFixed(1)}%`;
  sourceNoteEl.textContent =
    result.source === "phishtank"
      ? "Matched a known-phishing entry in ARGUS's threat-intelligence feed."
      : "Flagged by ARGUS's machine-learning model based on this hostname.";

  showState("warning");

  goBackBtn.addEventListener("click", () => history.back());
  goBackMissingBtn.addEventListener("click", () => history.back());

  viewTechnicalBtn.addEventListener("click", () => {
    technicalPanel.classList.toggle("hidden");
  });

  deepScanConsent.addEventListener("change", () => {
    runDeepScanBtn.disabled = !deepScanConsent.checked;
  });

  runDeepScanBtn.addEventListener("click", async () => {
    deepScanErrorEl.classList.add("hidden");
    runDeepScanBtn.disabled = true;
    runDeepScanBtn.textContent = "Scanning...";
    try {
      // Explicit, user-initiated, opted-in full-URL scan -- mirrors the
      // popup's existing Deep Scan pattern exactly (DEC-D). The passive
      // check that brought the user here never sent more than the
      // hostname.
      const deepResult = await sendMessage({ type: "DEEP_DETECT", url, sendFullUrl: true });
      renderDeepScanResult(deepResult);
    } catch (err) {
      deepScanErrorEl.textContent = err.message;
      deepScanErrorEl.classList.remove("hidden");
    } finally {
      runDeepScanBtn.disabled = false;
      runDeepScanBtn.textContent = "Run Deep Scan";
    }
  });

  understandRiskCheckbox.addEventListener("change", () => {
    continueBtn.disabled = !understandRiskCheckbox.checked;
  });

  continueBtn.addEventListener("click", async () => {
    continueStatusEl.textContent = "Continuing...";
    continueBtn.disabled = true;
    try {
      await sendMessage({
        type: "CONTINUE_ANYWAY",
        id: warningId,
        addToAllowlist: alsoAllowlistCheckbox.checked,
      });
      // background.js navigates this tab away on success -- nothing else
      // to render here.
    } catch (err) {
      continueStatusEl.textContent = err.message;
      continueBtn.disabled = false;
    }
  });

  allowlistOnlyBtn.addEventListener("click", async () => {
    allowlistOnlyBtn.disabled = true;
    await addToAllowlist(hostname);
    allowlistOnlyBtn.textContent = "Added to allowlist";
  });
}

function renderDeepScanResult(result) {
  deepScanResult.classList.remove("hidden");

  if (result.risk_band) {
    riskBandBadgeEl.textContent = _RISK_BAND_LABELS[result.risk_band] || result.risk_band;
    riskBandBadgeEl.classList.remove("hidden");
  } else {
    riskBandBadgeEl.classList.add("hidden");
  }

  signalsPanelEl.innerHTML = "";
  const triggered = (result.signals || []).filter((s) => s.triggered);
  for (const signal of triggered) {
    const badge = document.createElement("span");
    badge.className = `signal-badge ${signal.direction}`;
    badge.textContent = signalLabel(signal);
    badge.title = JSON.stringify(signal.evidence);
    signalsPanelEl.appendChild(badge);
  }
  if (triggered.length === 0) {
    const badge = document.createElement("span");
    badge.className = "signal-badge";
    badge.textContent = "No additional brand-intelligence signals triggered";
    signalsPanelEl.appendChild(badge);
  }

  plainExplanationEl.textContent = result.plain_explanation || "";
}

init();

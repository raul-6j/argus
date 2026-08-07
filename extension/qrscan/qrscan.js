/**
 * ARGUS QR-code ("quishing") scanner (Phase 3, F15).
 *
 * Decoding happens entirely in this page using the browser's native
 * BarcodeDetector (Shape Detection API) -- no vendored third-party decoder
 * library, consistent with the project's no-CDN/no-unverified-dependency
 * posture (see webapp/'s equivalent self-contained convention). If the
 * browser doesn't support it, this feature honestly disables itself rather
 * than silently failing or faking support.
 *
 * Two entry points, both landing here:
 *   1. File upload (always available -- no permission needed, decoded
 *      from a local file the user chose).
 *   2. Right-click an image -> "Scan QR Code with ARGUS" (background.js
 *      opens this page with ?imageUrl=...). Fetching that image requires a
 *      one-time, origin-scoped host-permission grant requested from HERE
 *      (a real foreground page), not from the background service worker --
 *      chrome.permissions.request() must run within a user gesture in a
 *      page context to reliably prompt.
 */

import "../lib/browserCompat.js";
import { isHttpUrl, originPatternFor } from "../lib/urlUtils.js";

const unsupportedState = document.getElementById("unsupportedState");
const supportedState = document.getElementById("supportedState");

const fileInput = document.getElementById("fileInput");
const localPreview = document.getElementById("localPreview");

const remoteImageSection = document.getElementById("remoteImageSection");
const remotePreview = document.getElementById("remotePreview");
const fetchRemoteBtn = document.getElementById("fetchRemoteBtn");

const decodeErrorEl = document.getElementById("decodeError");
const decodedSection = document.getElementById("decodedSection");
const decodedUrlEl = document.getElementById("decodedUrl");
const notAUrlNoteEl = document.getElementById("notAUrlNote");
const scanConsentRow = document.getElementById("scanConsentRow");
const scanConsent = document.getElementById("scanConsent");
const scanBtn = document.getElementById("scanBtn");
const resultPanel = document.getElementById("resultPanel");
const verdictBadgeEl = document.getElementById("verdictBadge");
const riskBandBadgeEl = document.getElementById("riskBandBadge");
const signalsPanelEl = document.getElementById("signalsPanel");
const plainExplanationEl = document.getElementById("plainExplanation");
const scanErrorEl = document.getElementById("scanError");

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

function isBarcodeDetectorSupported() {
  return typeof window.BarcodeDetector !== "undefined";
}

/**
 * Decode a QR code from an ImageBitmap.
 * @param {ImageBitmap} bitmap
 * @returns {Promise<string|null>} The first barcode's raw text, or null if none found.
 */
async function decodeQrFromBitmap(bitmap) {
  const detector = new window.BarcodeDetector({ formats: ["qr_code"] });
  const barcodes = await detector.detect(bitmap);
  return barcodes.length > 0 ? barcodes[0].rawValue : null;
}

function resetDecodedUi() {
  decodeErrorEl.classList.add("hidden");
  decodedSection.classList.add("hidden");
  resultPanel.classList.add("hidden");
  scanErrorEl.classList.add("hidden");
  scanConsent.checked = false;
  scanBtn.disabled = true;
}

function handleDecodedText(text) {
  decodedSection.classList.remove("hidden");
  decodedUrlEl.textContent = text;

  if (!isHttpUrl(text)) {
    notAUrlNoteEl.classList.remove("hidden");
    scanConsentRow.classList.add("hidden");
    return;
  }
  notAUrlNoteEl.classList.add("hidden");
  scanConsentRow.classList.remove("hidden");

  scanConsent.onchange = () => {
    scanBtn.disabled = !scanConsent.checked;
  };
  scanBtn.onclick = () => runScan(text);
}

async function runScan(url) {
  scanErrorEl.classList.add("hidden");
  scanBtn.disabled = true;
  scanBtn.textContent = "Scanning...";
  try {
    // The whole point of QR scanning is the destination the code encodes --
    // a hostname alone (e.g. of a URL shortener) tells the user nothing
    // useful here, so the full decoded URL is sent, same as the popup's
    // existing opt-in Deep Scan (DEC-D) -- the checkbox above is this
    // feature's equivalent explicit consent gate.
    const response = await chrome.runtime.sendMessage({
      type: "DEEP_DETECT",
      url,
      sendFullUrl: true,
    });
    if (!response.ok) throw new Error(response.error);
    renderResult(response.result);
  } catch (err) {
    scanErrorEl.textContent = err.message;
    scanErrorEl.classList.remove("hidden");
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "Scan URL";
  }
}

function renderResult(result) {
  resultPanel.classList.remove("hidden");

  verdictBadgeEl.textContent = result.label === "phishing" ? "⚠ Phishing" : "✓ Legitimate";
  verdictBadgeEl.className = `verdict-badge ${result.label}`;

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

  plainExplanationEl.textContent = result.plain_explanation || "";
}

async function handleFileUpload(file) {
  resetDecodedUi();
  localPreview.src = URL.createObjectURL(file);
  localPreview.classList.remove("hidden");

  try {
    const bitmap = await createImageBitmap(file);
    const text = await decodeQrFromBitmap(bitmap);
    if (text === null) {
      decodeErrorEl.textContent = "No QR code found in this image.";
      decodeErrorEl.classList.remove("hidden");
      return;
    }
    handleDecodedText(text);
  } catch (err) {
    decodeErrorEl.textContent = `Could not decode this image: ${err.message}`;
    decodeErrorEl.classList.remove("hidden");
  }
}

async function handleFetchRemoteImage(imageUrl) {
  resetDecodedUi();
  fetchRemoteBtn.disabled = true;
  fetchRemoteBtn.textContent = "Fetching...";
  try {
    const originPattern = originPatternFor(imageUrl);
    if (!originPattern) {
      throw new Error("Could not determine this image's origin.");
    }
    // Must be requested from a user gesture in this foreground page --
    // chrome.permissions.request() called from the background service
    // worker's contextMenus.onClicked handler is not reliably honored.
    const granted = await chrome.permissions.request({ origins: [originPattern] });
    if (!granted) {
      throw new Error("Permission denied -- ARGUS can't fetch this image without it.");
    }
    const resp = await fetch(imageUrl);
    if (!resp.ok) throw new Error(`Failed to fetch image (HTTP ${resp.status})`);
    const blob = await resp.blob();
    const bitmap = await createImageBitmap(blob);
    const text = await decodeQrFromBitmap(bitmap);
    if (text === null) {
      decodeErrorEl.textContent = "No QR code found in this image.";
      decodeErrorEl.classList.remove("hidden");
      return;
    }
    handleDecodedText(text);
  } catch (err) {
    decodeErrorEl.textContent = err.message;
    decodeErrorEl.classList.remove("hidden");
  } finally {
    fetchRemoteBtn.disabled = false;
    fetchRemoteBtn.textContent = "Fetch & Scan This Image";
  }
}

function init() {
  if (!isBarcodeDetectorSupported()) {
    unsupportedState.classList.remove("hidden");
    return;
  }
  supportedState.classList.remove("hidden");

  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    if (file) handleFileUpload(file);
  });

  const params = new URLSearchParams(location.search);
  const imageUrl = params.get("imageUrl");
  if (imageUrl) {
    remoteImageSection.classList.remove("hidden");
    remotePreview.src = imageUrl;
    fetchRemoteBtn.addEventListener("click", () => handleFetchRemoteImage(imageUrl));
  }
}

init();

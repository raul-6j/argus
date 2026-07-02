const loadingEl = document.getElementById("loading");
const resultEl = document.getElementById("result");
const errorEl = document.getElementById("errorState");
const hostnameEl = document.getElementById("hostname");
const verdictEl = document.getElementById("verdict");
const confidenceEl = document.getElementById("confidence");
const whyBtn = document.getElementById("whyBtn");
const shapPanel = document.getElementById("shapPanel");
const errorMessageEl = document.getElementById("errorMessage");
const openOptionsBtn = document.getElementById("openOptions");

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
  showState("result");
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
  } catch (err) {
    renderError(err.message);
  }
}

openOptionsBtn.addEventListener("click", () => chrome.runtime.openOptionsPage());
document.addEventListener("DOMContentLoaded", init);

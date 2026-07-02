import { isHttpUrl, originPatternFor } from "../lib/urlUtils.js";

const apiBaseUrlInput = document.getElementById("apiBaseUrl");
const sendFullUrlInput = document.getElementById("sendFullUrl");
const statusEl = document.getElementById("status");
const saveButton = document.getElementById("save");

async function loadSettings() {
  const { apiBaseUrl, sendFullUrl } = await chrome.storage.sync.get({
    apiBaseUrl: "",
    sendFullUrl: false,
  });
  apiBaseUrlInput.value = apiBaseUrl;
  sendFullUrlInput.checked = sendFullUrl;
}

async function saveSettings() {
  const apiBaseUrl = apiBaseUrlInput.value.trim();
  const sendFullUrl = sendFullUrlInput.checked;

  if (!isHttpUrl(apiBaseUrl)) {
    statusEl.textContent = "Enter a valid http:// or https:// URL.";
    return;
  }

  const originPattern = originPatternFor(apiBaseUrl);
  const granted = await chrome.permissions.request({ origins: [originPattern] });
  if (!granted) {
    statusEl.textContent = "Permission denied — the extension cannot reach this API without it.";
    return;
  }

  await chrome.storage.sync.set({ apiBaseUrl, sendFullUrl });
  statusEl.textContent = "Saved.";
}

saveButton.addEventListener("click", saveSettings);
document.addEventListener("DOMContentLoaded", loadSettings);

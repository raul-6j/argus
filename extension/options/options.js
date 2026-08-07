import "../lib/browserCompat.js";
import { isHttpUrl, originPatternFor } from "../lib/urlUtils.js";
import {
  addToAllowlist,
  clearOverrideLog,
  getOverrideLog,
  getProtectionSettings,
  removeFromAllowlist,
  setProtectionEnabled,
} from "../lib/protectionSettings.js";

const apiBaseUrlInput = document.getElementById("apiBaseUrl");
const sendFullUrlInput = document.getElementById("sendFullUrl");
const statusEl = document.getElementById("status");
const saveButton = document.getElementById("save");

const activeProtectionCheckbox = document.getElementById("activeProtectionEnabled");
const protectionStatusEl = document.getElementById("protectionStatus");
const allowlistInput = document.getElementById("allowlistInput");
const addAllowlistBtn = document.getElementById("addAllowlistBtn");
const allowlistItemsEl = document.getElementById("allowlistItems");
const overrideLogItemsEl = document.getElementById("overrideLogItems");
const clearOverrideLogBtn = document.getElementById("clearOverrideLogBtn");
const scanQrBtn = document.getElementById("scanQrBtn");

// The single permission bundle Active Protection needs -- requested and
// released together, since webNavigation without host permissions can't
// usefully see navigation URLs, and vice versa (see docs/DECISIONS.md).
const _PROTECTION_PERMISSIONS = {
  permissions: ["webNavigation"],
  origins: ["http://*/*", "https://*/*"],
};

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

async function loadProtectionState() {
  const { enabled } = await getProtectionSettings();
  activeProtectionCheckbox.checked = enabled;
  await renderAllowlist();
  await renderOverrideLog();
}

async function toggleActiveProtection() {
  if (activeProtectionCheckbox.checked) {
    const granted = await chrome.permissions.request(_PROTECTION_PERMISSIONS);
    if (!granted) {
      activeProtectionCheckbox.checked = false;
      protectionStatusEl.textContent = "Permission denied — Active Protection was not enabled.";
      return;
    }
    await setProtectionEnabled(true);
    protectionStatusEl.textContent = "Active Protection enabled.";
  } else {
    await setProtectionEnabled(false);
    // Best-effort: also release the permission grant. If another
    // in-progress check is mid-flight it will simply fail closed (caught
    // and logged in background.js), never block anything.
    await chrome.permissions.remove(_PROTECTION_PERMISSIONS);
    protectionStatusEl.textContent = "Active Protection disabled.";
  }
}

async function renderAllowlist() {
  const { allowlist } = await getProtectionSettings();
  allowlistItemsEl.innerHTML = "";
  for (const hostname of allowlist) {
    const li = document.createElement("li");
    li.textContent = `${hostname} `;
    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.textContent = "Remove";
    removeBtn.addEventListener("click", async () => {
      await removeFromAllowlist(hostname);
      await renderAllowlist();
    });
    li.appendChild(removeBtn);
    allowlistItemsEl.appendChild(li);
  }
}

async function handleAddAllowlist() {
  const hostname = allowlistInput.value.trim().toLowerCase();
  if (!hostname) return;
  await addToAllowlist(hostname);
  allowlistInput.value = "";
  await renderAllowlist();
}

async function renderOverrideLog() {
  const log = await getOverrideLog();
  overrideLogItemsEl.innerHTML = "";
  if (log.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No overrides recorded.";
    overrideLogItemsEl.appendChild(li);
    return;
  }
  for (const entry of [...log].reverse()) {
    const li = document.createElement("li");
    li.textContent = `${new Date(entry.timestamp).toLocaleString()} — ${entry.hostname}`;
    overrideLogItemsEl.appendChild(li);
  }
}

async function handleClearOverrideLog() {
  await clearOverrideLog();
  await renderOverrideLog();
}

saveButton.addEventListener("click", saveSettings);
activeProtectionCheckbox.addEventListener("change", toggleActiveProtection);
addAllowlistBtn.addEventListener("click", handleAddAllowlist);
clearOverrideLogBtn.addEventListener("click", handleClearOverrideLog);
scanQrBtn.addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("qrscan/qrscan.html") });
});

document.addEventListener("DOMContentLoaded", () => {
  loadSettings();
  loadProtectionState();
});

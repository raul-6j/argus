import "../lib/browserCompat.js";
import { icon, hydrateIcons } from "../lib/icons.js";
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

hydrateIcons();

/**
 * Write an inline status line, colour-coded by outcome.
 *
 * Presentation only — every caller previously set `.textContent` directly and
 * still passes the same strings; this just adds the tone.
 * @param {HTMLElement} target
 * @param {string} message
 * @param {"ok"|"error"|""} [tone]
 */
function setStatus(target, message, tone) {
  target.textContent = message;
  target.classList.toggle("status-text--ok", tone === "ok");
  target.classList.toggle("status-text--error", tone === "error");
}

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
    setStatus(statusEl, "Enter a valid http:// or https:// URL.", "error");
    return;
  }

  const originPattern = originPatternFor(apiBaseUrl);
  const granted = await chrome.permissions.request({ origins: [originPattern] });
  if (!granted) {
    setStatus(
      statusEl,
      "Permission denied — the extension cannot reach this API without it.",
      "error"
    );
    return;
  }

  await chrome.storage.sync.set({ apiBaseUrl, sendFullUrl });
  setStatus(statusEl, "Settings saved.", "ok");
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
      setStatus(
        protectionStatusEl,
        "Permission denied — Active Protection was not enabled.",
        "error"
      );
      return;
    }
    await setProtectionEnabled(true);
    setStatus(protectionStatusEl, "Active Protection enabled.", "ok");
  } else {
    await setProtectionEnabled(false);
    // Best-effort: also release the permission grant. If another
    // in-progress check is mid-flight it will simply fail closed (caught
    // and logged in background.js), never block anything.
    await chrome.permissions.remove(_PROTECTION_PERMISSIONS);
    setStatus(protectionStatusEl, "Active Protection disabled.", "");
  }
}

/**
 * Empty-state placeholder for a list that has no rows yet.
 * @param {string} iconName
 * @param {string} message
 * @returns {HTMLLIElement}
 */
function emptyRow(iconName, message) {
  const li = document.createElement("li");
  const empty = document.createElement("div");
  empty.className = "empty-state";
  const glyph = icon(iconName);
  if (glyph) empty.appendChild(glyph);
  const text = document.createElement("p");
  text.textContent = message;
  empty.appendChild(text);
  li.appendChild(empty);
  li.style.display = "block";
  return li;
}

async function renderAllowlist() {
  const { allowlist } = await getProtectionSettings();
  allowlistItemsEl.innerHTML = "";

  if (allowlist.length === 0) {
    allowlistItemsEl.appendChild(
      emptyRow("check-circle", "No allowlisted sites yet.")
    );
    return;
  }

  for (const hostname of allowlist) {
    const li = document.createElement("li");

    const host = document.createElement("span");
    host.className = "list-primary";
    host.textContent = hostname;
    host.title = hostname;
    li.appendChild(host);

    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "btn btn--ghost btn--sm";
    removeBtn.setAttribute("aria-label", `Remove ${hostname} from the allowlist`);
    const glyph = icon("trash");
    if (glyph) removeBtn.appendChild(glyph);
    removeBtn.appendChild(document.createTextNode("Remove"));
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
    overrideLogItemsEl.appendChild(emptyRow("inbox", "No overrides recorded."));
    return;
  }
  for (const entry of [...log].reverse()) {
    const li = document.createElement("li");

    const host = document.createElement("span");
    host.className = "list-primary";
    host.textContent = entry.hostname;
    host.title = entry.hostname;
    li.appendChild(host);

    const when = document.createElement("span");
    when.className = "hint";
    when.textContent = new Date(entry.timestamp).toLocaleString();
    li.appendChild(when);

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

import { getCurrentEmail, isLoggedIn, login, logout, signup, verifyOtp } from "../lib/authClient.js";
import { fetchVault, saveVault } from "../lib/vaultClient.js";

// The vault master password (reusing the login password -- a common,
// deliberate pattern, e.g. Bitwarden does the same) lives only in this
// module-level variable for the lifetime of the page. It is never persisted
// to chrome.storage and never sent to the server -- only ciphertext is.
let vaultPassword = null;
let vaultVersion = 0;
let pendingSignupEmail = null;

const loggedOutView = document.getElementById("loggedOutView");
const loggedInView = document.getElementById("loggedInView");
const tabSignup = document.getElementById("tabSignup");
const tabLogin = document.getElementById("tabLogin");
const signupForm = document.getElementById("signupForm");
const otpForm = document.getElementById("otpForm");
const loginForm = document.getElementById("loginForm");
const currentEmailEl = document.getElementById("currentEmail");
const logoutBtn = document.getElementById("logoutBtn");
const vaultTextarea = document.getElementById("vaultTextarea");
const vaultReloadBtn = document.getElementById("vaultReloadBtn");
const vaultSaveBtn = document.getElementById("vaultSaveBtn");
const statusEl = document.getElementById("status");

function setStatus(message) {
  statusEl.textContent = message || "";
}

function showPanel(panel) {
  for (const el of [signupForm, otpForm, loginForm]) {
    el.classList.toggle("hidden", el !== panel);
  }
}

function showLoggedOut() {
  loggedOutView.classList.remove("hidden");
  loggedInView.classList.add("hidden");
}

async function showLoggedIn() {
  loggedOutView.classList.add("hidden");
  loggedInView.classList.remove("hidden");
  currentEmailEl.textContent = (await getCurrentEmail()) || "(unknown)";
  await reloadVault();
}

async function reloadVault() {
  if (!vaultPassword) {
    // No in-memory password (e.g. page was reopened after login elsewhere)
    // -- vault contents can't be decrypted without re-entering it.
    vaultTextarea.value = "";
    vaultTextarea.placeholder = "Log out and back in to unlock the vault on this page.";
    vaultTextarea.disabled = true;
    return;
  }
  try {
    const { value, version } = await fetchVault(vaultPassword);
    vaultVersion = version;
    vaultTextarea.value = Array.isArray(value?.allowlist) ? value.allowlist.join("\n") : "";
    vaultTextarea.disabled = false;
    setStatus("");
  } catch (err) {
    setStatus(`Could not load vault: ${err.message}`);
  }
}

tabSignup.addEventListener("click", () => {
  tabSignup.classList.add("active");
  tabLogin.classList.remove("active");
  showPanel(signupForm);
});

tabLogin.addEventListener("click", () => {
  tabLogin.classList.add("active");
  tabSignup.classList.remove("active");
  showPanel(loginForm);
});

signupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = document.getElementById("signupEmail").value.trim();
  const password = document.getElementById("signupPassword").value;
  setStatus("");
  try {
    await signup(email, password);
    pendingSignupEmail = email;
    showPanel(otpForm);
  } catch (err) {
    setStatus(err.message);
  }
});

otpForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const otp = document.getElementById("otpCode").value.trim();
  setStatus("");
  try {
    await verifyOtp(pendingSignupEmail, otp);
    setStatus("Verified! You can now log in.");
    tabLogin.click();
  } catch (err) {
    setStatus(err.message);
  }
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = document.getElementById("loginEmail").value.trim();
  const password = document.getElementById("loginPassword").value;
  setStatus("");
  try {
    await login(email, password);
    vaultPassword = password;
    await showLoggedIn();
  } catch (err) {
    setStatus(err.message);
  }
});

logoutBtn.addEventListener("click", async () => {
  await logout();
  vaultPassword = null;
  vaultVersion = 0;
  showLoggedOut();
});

vaultReloadBtn.addEventListener("click", reloadVault);

vaultSaveBtn.addEventListener("click", async () => {
  if (!vaultPassword) {
    setStatus("Log out and back in to unlock the vault on this page.");
    return;
  }
  const allowlist = vaultTextarea.value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  try {
    const { version } = await saveVault({ allowlist }, vaultPassword, vaultVersion);
    vaultVersion = version;
    setStatus("Saved.");
  } catch (err) {
    if (err.status === 409) {
      setStatus("Vault was updated on another device. Reloading latest version — please retry.");
      await reloadVault();
    } else {
      setStatus(err.message);
    }
  }
});

async function init() {
  if (await isLoggedIn()) {
    await showLoggedIn();
  } else {
    showLoggedOut();
  }
}

document.addEventListener("DOMContentLoaded", init);

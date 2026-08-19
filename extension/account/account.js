import "../lib/browserCompat.js";
import { icon, hydrateIcons } from "../lib/icons.js";
import { getCurrentEmail, isLoggedIn, login, logout, signup, verifyOtp } from "../lib/authClient.js";
import { fetchVault, saveVault } from "../lib/vaultClient.js";

hydrateIcons();

// The vault master password (reusing the login password -- a common,
// deliberate pattern, e.g. Bitwarden does the same) lives only in this
// module-level variable for the lifetime of the page. It is never persisted
// to chrome.storage and never sent to the server -- only ciphertext is.
let vaultPassword = null;
let vaultVersion = 0;
let pendingSignupEmail = null;

const loggedOutView = document.getElementById("loggedOutView");
const loggedInView = document.getElementById("loggedInView");
const authTabs = document.getElementById("authTabs");
const tabSignup = document.getElementById("tabSignup");
const tabLogin = document.getElementById("tabLogin");
const signupForm = document.getElementById("signupForm");
const otpForm = document.getElementById("otpForm");
const otpEmailLabel = document.getElementById("otpEmailLabel");
const backToSignup = document.getElementById("backToSignup");
const loginForm = document.getElementById("loginForm");
const currentEmailEl = document.getElementById("currentEmail");
const avatarInitialEl = document.getElementById("avatarInitial");
const logoutBtn = document.getElementById("logoutBtn");
const vaultTextarea = document.getElementById("vaultTextarea");
const vaultReloadBtn = document.getElementById("vaultReloadBtn");
const vaultSaveBtn = document.getElementById("vaultSaveBtn");
const statusEl = document.getElementById("status");

function setStatus(message, type = "") {
  statusEl.textContent = message || "";
  statusEl.classList.toggle("status--error", type === "error");
  statusEl.classList.toggle("status--success", type === "success");
}

// Disables a submit button and swaps its label for a spinner while an async
// request is in flight, restoring both afterward -- without this, a slow
// request (real network I/O for signup/login/vault sync) looks like the click
// did nothing.
//
// The buttons carry an inline SVG plus a text node, so the label is captured
// and restored via the text node alone; assigning `button.textContent` would
// silently destroy the icon.
async function withLoading(button, loadingLabel, action) {
  const originalLabel = button.textContent.trim();
  const iconName = button.dataset.icon;

  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  button.innerHTML = "";
  const spinner = document.createElement("span");
  spinner.className = "spinner";
  spinner.setAttribute("aria-hidden", "true");
  button.appendChild(spinner);
  button.appendChild(document.createTextNode(loadingLabel));

  try {
    await action();
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
    button.innerHTML = "";
    const glyph = icon(iconName);
    if (glyph) button.appendChild(glyph);
    button.appendChild(document.createTextNode(originalLabel));
  }
}

function showPanel(panel) {
  for (const el of [signupForm, otpForm, loginForm]) {
    el.classList.toggle("hidden", el !== panel);
  }
  // OTP is a sub-step of signing up, not a top-level destination -- hiding
  // the Sign Up / Log In tabs while on it makes that a distinct "page"
  // instead of a third tab, and stops a stray tab click from abandoning
  // an in-progress verification.
  authTabs.classList.toggle("hidden", panel === otpForm);
}

function setActiveTab(tab) {
  tabSignup.classList.toggle("active", tab === tabSignup);
  tabLogin.classList.toggle("active", tab === tabLogin);
  tabSignup.setAttribute("aria-selected", String(tab === tabSignup));
  tabLogin.setAttribute("aria-selected", String(tab === tabLogin));
}

function showLoggedOut() {
  loggedOutView.classList.remove("hidden");
  loggedInView.classList.add("hidden");
  setActiveTab(tabSignup);
  showPanel(signupForm);
}

async function showLoggedIn() {
  loggedOutView.classList.add("hidden");
  loggedInView.classList.remove("hidden");
  const email = (await getCurrentEmail()) || "(unknown)";
  currentEmailEl.textContent = email;
  avatarInitialEl.textContent = email.charAt(0) || "?";
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
    setStatus(`Could not load vault: ${err.message}`, "error");
  }
}

tabSignup.addEventListener("click", () => {
  setActiveTab(tabSignup);
  showPanel(signupForm);
});

tabLogin.addEventListener("click", () => {
  setActiveTab(tabLogin);
  showPanel(loginForm);
});

backToSignup.addEventListener("click", () => {
  setStatus("");
  tabSignup.click();
});

signupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = document.getElementById("signupEmail").value.trim();
  const password = document.getElementById("signupPassword").value;
  setStatus("");
  const submitBtn = signupForm.querySelector('button[type="submit"]');
  await withLoading(submitBtn, "Creating account…", async () => {
    try {
      await signup(email, password);
      pendingSignupEmail = email;
      otpEmailLabel.textContent = email;
      showPanel(otpForm);
    } catch (err) {
      setStatus(err.message, "error");
    }
  });
});

otpForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const otp = document.getElementById("otpCode").value.trim();
  setStatus("");
  const submitBtn = otpForm.querySelector('button[type="submit"]');
  await withLoading(submitBtn, "Verifying…", async () => {
    try {
      await verifyOtp(pendingSignupEmail, otp);
      setStatus("Verified! You can now log in.", "success");
      tabLogin.click();
      document.getElementById("loginEmail").value = pendingSignupEmail;
    } catch (err) {
      setStatus(err.message, "error");
    }
  });
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = document.getElementById("loginEmail").value.trim();
  const password = document.getElementById("loginPassword").value;
  setStatus("");
  const submitBtn = loginForm.querySelector('button[type="submit"]');
  await withLoading(submitBtn, "Logging in…", async () => {
    try {
      await login(email, password);
      vaultPassword = password;
      await showLoggedIn();
    } catch (err) {
      setStatus(err.message, "error");
    }
  });
});

logoutBtn.addEventListener("click", async () => {
  await logout();
  vaultPassword = null;
  vaultVersion = 0;
  setStatus("");
  showLoggedOut();
});

vaultReloadBtn.addEventListener("click", reloadVault);

vaultSaveBtn.addEventListener("click", async () => {
  if (!vaultPassword) {
    setStatus("Log out and back in to unlock the vault on this page.", "error");
    return;
  }
  const allowlist = vaultTextarea.value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  await withLoading(vaultSaveBtn, "Saving…", async () => {
    try {
      const { version } = await saveVault({ allowlist }, vaultPassword, vaultVersion);
      vaultVersion = version;
      setStatus("Saved.", "success");
    } catch (err) {
      if (err.status === 409) {
        setStatus("Vault was updated on another device. Reloading latest version — please retry.", "error");
        await reloadVault();
      } else {
        setStatus(err.message, "error");
      }
    }
  });
});

async function init() {
  if (await isLoggedIn()) {
    await showLoggedIn();
  } else {
    showLoggedOut();
  }
}

document.addEventListener("DOMContentLoaded", init);

/**
 * ARGUS web app shell — declarative icon hydration + shared UI behaviours.
 *
 * Pages mark up icons as `data-icon="name"` instead of pasting SVG into every
 * template; this script swaps each one for the real inline glyph from
 * icons.js on load. Keeps the HTML readable and the icon set in exactly one
 * place, with no build step (webapp/ is served as plain static files).
 *
 * Load order per page: icons.js → report.js → shell.js → the page's own
 * inline script.
 */

/** Insert the declared icon as the first child of every `[data-icon]`. */
function hydrateIcons(root) {
  const scope = root || document;
  for (const node of scope.querySelectorAll("[data-icon]")) {
    if (node.dataset.iconHydrated === "true") continue;
    const icon = argusIcon(node.dataset.icon);
    if (!icon) continue;
    node.insertBefore(icon, node.firstChild);
    node.dataset.iconHydrated = "true";
  }
}

/**
 * Put a button into (or out of) a busy state without destroying its icon.
 *
 * Buttons here contain an SVG plus a text node, so the old
 * `button.textContent = "..."` pattern would silently wipe the icon. This
 * swaps in a spinner and restores the original label instead.
 *
 * @param {HTMLButtonElement} button
 * @param {boolean} busy
 * @param {string} label text to show alongside the spinner / on restore
 */
function setButtonBusy(button, busy, label) {
  if (busy) {
    if (!button.dataset.idleLabel) button.dataset.idleLabel = button.textContent.trim();
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    button.innerHTML = "";
    const spinner = document.createElement("span");
    spinner.className = "spinner";
    spinner.setAttribute("aria-hidden", "true");
    button.appendChild(spinner);
    button.appendChild(document.createTextNode(label || "Working…"));
    return;
  }

  button.disabled = false;
  button.removeAttribute("aria-busy");
  button.innerHTML = "";
  const iconName = button.dataset.icon;
  if (iconName) {
    const icon = argusIcon(iconName);
    if (icon) button.appendChild(icon);
  }
  button.appendChild(
    document.createTextNode(label || button.dataset.idleLabel || "")
  );
}

/**
 * Mark the nav entry matching the current page as active, so each page
 * doesn't have to hardcode it.
 */
function markActiveNav() {
  const current = location.pathname.split("/").pop() || "index.html";
  for (const item of document.querySelectorAll(".nav-item[href]")) {
    const target = item.getAttribute("href");
    if (target === current) {
      item.classList.add("active");
      item.setAttribute("aria-current", "page");
    }
  }
}

hydrateIcons();
markActiveNav();
initAppShell();

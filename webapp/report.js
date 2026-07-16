/**
 * Shared rendering for a scan verdict card — used by both index.html
 * (immediately after a scan) and scan.html (a stored shareable report).
 * Self-contained: no external dependencies.
 */

/**
 * @param {HTMLElement} card
 * @param {{url: string, label: string, confidence: number, risk_score: number,
 *          signals: Array<{name: string, triggered: boolean, direction: string, evidence: object}>,
 *          plain_explanation: string, scan_id?: string, created_at?: string}} report
 */
function renderReportCard(card, report) {
  card.classList.remove("hidden");
  card.innerHTML = "";

  const verdictRow = document.createElement("div");
  verdictRow.className = "verdict-row";

  const badge = document.createElement("span");
  badge.className = `verdict-badge ${report.label}`;
  badge.textContent = report.label === "phishing" ? "⚠ Phishing" : "✓ Legitimate";
  verdictRow.appendChild(badge);

  const confidence = document.createElement("span");
  confidence.className = "confidence";
  confidence.textContent = `Confidence: ${(report.confidence * 100).toFixed(1)}%`;
  verdictRow.appendChild(confidence);

  card.appendChild(verdictRow);

  const urlEl = document.createElement("p");
  urlEl.className = "scanned-url";
  urlEl.textContent = report.url;
  card.appendChild(urlEl);

  const triggered = (report.signals || []).filter((s) => s.triggered);
  if (triggered.length > 0) {
    const signalsEl = document.createElement("div");
    signalsEl.className = "signals";
    for (const signal of triggered) {
      const badgeEl = document.createElement("span");
      badgeEl.className = `signal-badge ${signal.direction}`;
      badgeEl.textContent = signalLabel(signal);
      badgeEl.title = JSON.stringify(signal.evidence, null, 2);
      signalsEl.appendChild(badgeEl);
    }
    card.appendChild(signalsEl);
  }

  const explanation = document.createElement("p");
  explanation.className = "explanation";
  explanation.textContent = report.plain_explanation || "";
  card.appendChild(explanation);

  if (report.scan_id) {
    const shareRow = document.createElement("div");
    shareRow.className = "share-row";

    const link = document.createElement("input");
    link.type = "text";
    link.readOnly = true;
    link.value = `${location.origin}/app/scan.html?id=${report.scan_id}`;
    shareRow.appendChild(link);

    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.textContent = "Copy link";
    copyBtn.addEventListener("click", async () => {
      await navigator.clipboard.writeText(link.value);
      copyBtn.textContent = "Copied!";
      setTimeout(() => (copyBtn.textContent = "Copy link"), 1500);
    });
    shareRow.appendChild(copyBtn);

    card.appendChild(shareRow);
  }

  if (report.created_at) {
    const meta = document.createElement("p");
    meta.className = "meta";
    meta.textContent = `Scanned ${new Date(report.created_at).toLocaleString()}`;
    card.appendChild(meta);
  }
}

/**
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
    default:
      return signal.name;
  }
}

function showError(box, message) {
  box.textContent = message;
  box.classList.remove("hidden");
}

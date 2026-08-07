/**
 * Shared rendering for a scan verdict card — used by index.html (immediately
 * after a scan), scan.html (a stored shareable report), and dashboard.html
 * (Phase 4, F11/F13 — history rows + risk-band/source breakdowns).
 * Self-contained: no external dependencies.
 */

/**
 * @param {HTMLElement} card
 * @param {{url: string, label: string, confidence: number, risk_score: number,
 *          risk_band?: string,
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

  if (report.risk_band) {
    const bandBadge = document.createElement("span");
    bandBadge.className = `risk-band-badge ${report.risk_band}`;
    bandBadge.textContent = riskBandLabel(report.risk_band);
    verdictRow.appendChild(bandBadge);
  }

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
 * @param {string} band one of low/caution/suspicious/high/critical
 * @returns {string}
 */
function riskBandLabel(band) {
  const labels = {
    low: "Low Risk",
    caution: "Caution",
    suspicious: "Suspicious",
    high: "High Risk",
    critical: "Critical",
  };
  return labels[band] || band;
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

function showError(box, message) {
  box.textContent = message;
  box.classList.remove("hidden");
}

/**
 * One compact row for the dashboard's scan history list (Phase 4, F11).
 * @param {{id: number, url: string, label: string, risk_band: string,
 *          source: string, created_at: string|null}} scan
 * @param {(format: string) => void} onExport called with "json"|"csv"|"pdf"
 * @returns {HTMLElement}
 */
function renderHistoryRow(scan, onExport) {
  const row = document.createElement("div");
  row.className = "history-row";

  const main = document.createElement("div");
  main.className = "history-row-main";

  const badge = document.createElement("span");
  badge.className = `verdict-badge small ${scan.label}`;
  badge.textContent = scan.label === "phishing" ? "⚠ Phishing" : "✓ Legitimate";
  main.appendChild(badge);

  if (scan.risk_band) {
    const bandBadge = document.createElement("span");
    bandBadge.className = `risk-band-badge ${scan.risk_band}`;
    bandBadge.textContent = riskBandLabel(scan.risk_band);
    main.appendChild(bandBadge);
  }

  const urlEl = document.createElement("span");
  urlEl.className = "history-url";
  urlEl.textContent = scan.url;
  main.appendChild(urlEl);

  row.appendChild(main);

  const meta = document.createElement("div");
  meta.className = "history-row-meta";
  const when = scan.created_at ? new Date(scan.created_at).toLocaleString() : "";
  meta.textContent = `${scan.source || ""}${when ? " · " + when : ""}`;
  row.appendChild(meta);

  const exportRow = document.createElement("div");
  exportRow.className = "history-row-export";
  for (const format of ["json", "csv", "pdf"]) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "export-btn";
    btn.textContent = format.toUpperCase();
    btn.addEventListener("click", () => onExport(format));
    exportRow.appendChild(btn);
  }
  row.appendChild(exportRow);

  return row;
}

/**
 * A simple CSS bar-list breakdown (no charting library, no CDN) -- e.g.
 * risk-band distribution or detection-source breakdown on the dashboard.
 * @param {HTMLElement} container
 * @param {Record<string, number>} counts
 * @param {(key: string) => string} [labelFn]
 */
function renderBarList(container, counts, labelFn) {
  container.innerHTML = "";
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) {
    const empty = document.createElement("p");
    empty.className = "meta";
    empty.textContent = "No scans yet.";
    container.appendChild(empty);
    return;
  }

  for (const [key, count] of Object.entries(counts).sort((a, b) => b[1] - a[1])) {
    const pct = Math.round((count / total) * 100);

    const row = document.createElement("div");
    row.className = "bar-row";

    const label = document.createElement("span");
    label.className = "bar-label";
    label.textContent = labelFn ? labelFn(key) : key;
    row.appendChild(label);

    const track = document.createElement("div");
    track.className = "bar-track";
    const fill = document.createElement("div");
    fill.className = `bar-fill ${key}`;
    fill.style.width = `${pct}%`;
    track.appendChild(fill);
    row.appendChild(track);

    const count_el = document.createElement("span");
    count_el.className = "bar-count";
    count_el.textContent = `${count} (${pct}%)`;
    row.appendChild(count_el);

    container.appendChild(row);
  }
}

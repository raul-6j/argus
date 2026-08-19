/**
 * Shared scan-report rendering for the ARGUS web app.
 *
 * Used by index.html (immediately after a scan), scan.html (a stored,
 * shareable report), and dashboard.html (history table + breakdown charts).
 * Self-contained: no external dependencies. Requires icons.js to be loaded
 * first for the inline SVG icon set.
 *
 * This module renders only — it never decides a verdict. Every value shown
 * comes straight from the API payload; nothing is inferred or synthesised
 * client-side.
 */

/* -------------------------------------------------------------- labels -- */

const RISK_BAND_LABELS = {
  low: "Low Risk",
  caution: "Caution",
  suspicious: "Suspicious",
  high: "High Risk",
  critical: "Critical",
};

/** Detection-source → human label + icon. `source` is "model", "fusion", or a
 *  threat-intel provider name (see src/api/verdict.py). */
const SOURCE_META = {
  model: { label: "ML Model", icon: "cpu", desc: "Decided by the machine-learning classifier." },
  fusion: {
    label: "Signal Fusion",
    icon: "activity",
    desc: "Decided by the detection-signal fusion layer, which combines brand-intelligence signals with the model score.",
  },
  phishtank: {
    label: "PhishTank",
    icon: "database",
    desc: "Matched a known-phishing entry in ARGUS's threat-intelligence feed — no model inference was needed.",
  },
  google_safe_browsing: {
    label: "Google Safe Browsing",
    icon: "database",
    desc: "Matched a Google Safe Browsing threat list entry — no model inference was needed.",
  },
};

/** One entry per detection signal (src/detection/signals/). */
const SIGNAL_META = {
  typosquat: { icon: "globe", title: "Look-alike Domain" },
  favicon_match: { icon: "image", title: "Favicon / Logo Match" },
  brand_mismatch: { icon: "target", title: "Brand Mismatch" },
  cert_intel: { icon: "lock", title: "Certificate Analysis" },
  redirect_chain: { icon: "git-branch", title: "Redirect Chain" },
  credential_context: { icon: "key", title: "Credential Context" },
  platform_risk: { icon: "server", title: "Hosting Platform Risk" },
  semantic_content: { icon: "file-text", title: "Page Content Semantics" },
};

/**
 * @param {string} band one of low/caution/suspicious/high/critical
 * @returns {string}
 */
function riskBandLabel(band) {
  return RISK_BAND_LABELS[band] || band;
}

/**
 * Short human label for a signal badge, built from its name + evidence.
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

/** @param {string} source @returns {{label: string, icon: string, desc: string}} */
function sourceMeta(source) {
  return (
    SOURCE_META[source] || {
      label: source || "Unknown",
      icon: "database",
      desc: "Matched an entry in a threat-intelligence feed.",
    }
  );
}

/* ------------------------------------------------------- small builders -- */

/**
 * @param {string} tag
 * @param {string} [className]
 * @param {string} [text]
 * @returns {HTMLElement}
 */
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

/** Verdict pill: icon + word. @returns {HTMLElement} */
function verdictBadge(label, small) {
  const badge = el("span", `verdict-badge ${label}${small ? " small" : ""}`);
  const icon = argusIcon(label === "phishing" ? "alert-triangle" : "check-circle");
  if (icon) badge.appendChild(icon);
  badge.appendChild(document.createTextNode(label === "phishing" ? "Phishing" : "Legitimate"));
  return badge;
}

/** Risk-band pill. @returns {HTMLElement} */
function riskBandBadge(band) {
  return el("span", `risk-band-badge ${band}`, riskBandLabel(band));
}

/**
 * Radial risk indicator. Falls back to the confidence reading when the
 * payload has no risk_score (e.g. a threat-intel prefilter hit).
 * @param {number} value 0..1
 * @param {string} band risk band used for the arc colour
 * @param {string} caption
 * @returns {HTMLElement}
 */
function renderGauge(value, band, caption) {
  const RADIUS = 62;
  const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
  const pct = Math.max(0, Math.min(1, value));

  const wrap = el("div", "gauge");
  wrap.setAttribute("role", "img");
  wrap.setAttribute(
    "aria-label",
    `${caption}: ${Math.round(pct * 100)} out of 100${band ? `, ${riskBandLabel(band)}` : ""}`
  );

  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 148 148");

  const track = document.createElementNS(NS, "circle");
  track.setAttribute("class", "gauge-track");
  track.setAttribute("cx", "74");
  track.setAttribute("cy", "74");
  track.setAttribute("r", String(RADIUS));
  svg.appendChild(track);

  const arc = document.createElementNS(NS, "circle");
  arc.setAttribute("class", `gauge-arc ${band || ""}`);
  arc.setAttribute("cx", "74");
  arc.setAttribute("cy", "74");
  arc.setAttribute("r", String(RADIUS));
  arc.setAttribute("stroke-dasharray", String(CIRCUMFERENCE));
  // Start empty, then animate to the real value on the next frame so the
  // CSS transition on stroke-dashoffset actually runs.
  arc.setAttribute("stroke-dashoffset", String(CIRCUMFERENCE));
  svg.appendChild(arc);
  wrap.appendChild(svg);

  const center = el("div", "gauge-center");
  center.appendChild(el("span", "gauge-value", String(Math.round(pct * 100))));
  center.appendChild(el("span", "gauge-caption", caption));
  wrap.appendChild(center);

  requestAnimationFrame(() => {
    arc.setAttribute("stroke-dashoffset", String(CIRCUMFERENCE * (1 - pct)));
  });

  return wrap;
}

/**
 * Labelled linear meter (confidence, model score…).
 * @param {number} value 0..1
 * @param {string} [modifier] extra class on the fill (band or verdict)
 * @returns {HTMLElement}
 */
function renderMeter(value, modifier) {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  const track = el("div", "meter");
  const fill = el("div", `meter-fill ${modifier || ""}`);
  track.appendChild(fill);
  requestAnimationFrame(() => {
    fill.style.width = `${pct}%`;
  });
  return track;
}

/** One `<div class="metric">` for the strip under the verdict. */
function renderMetric(label, valueNode) {
  const metric = el("div", "metric");
  metric.appendChild(el("span", "metric-label", label));
  const value = el("div", "metric-value");
  if (typeof valueNode === "string") value.textContent = valueNode;
  else value.appendChild(valueNode);
  metric.appendChild(value);
  return metric;
}

/**
 * A collapsible section. Wired with proper aria-expanded/aria-controls so it
 * is operable and announced correctly with a keyboard or screen reader.
 * @param {{id: string, title: string, subtitle?: string, icon: string,
 *          tone?: string, open?: boolean, body: HTMLElement}} options
 * @returns {HTMLElement}
 */
function renderAccordionItem(options) {
  const item = el("div", "accordion-item");

  const trigger = el("button", "accordion-trigger");
  trigger.type = "button";
  trigger.setAttribute("aria-expanded", options.open ? "true" : "false");
  trigger.setAttribute("aria-controls", options.id);

  const iconWrap = el("span", `accordion-icon${options.tone ? ` accordion-icon--${options.tone}` : ""}`);
  const icon = argusIcon(options.icon);
  if (icon) iconWrap.appendChild(icon);
  trigger.appendChild(iconWrap);

  const title = el("span", "accordion-title");
  title.appendChild(document.createTextNode(options.title));
  if (options.subtitle) title.appendChild(el("span", "accordion-sub", options.subtitle));
  trigger.appendChild(title);

  const chevron = argusIcon("chevron-down", "accordion-chevron");
  if (chevron) trigger.appendChild(chevron);

  const panel = el("div", "accordion-panel");
  panel.id = options.id;
  panel.appendChild(options.body);
  if (!options.open) panel.classList.add("hidden");

  trigger.addEventListener("click", () => {
    const open = trigger.getAttribute("aria-expanded") === "true";
    trigger.setAttribute("aria-expanded", String(!open));
    panel.classList.toggle("hidden", open);
  });

  item.appendChild(trigger);
  item.appendChild(panel);
  return item;
}

/**
 * Render a signal's raw evidence object as a readable key/value table.
 * @param {object} evidence
 * @returns {HTMLElement}
 */
function renderEvidenceTable(evidence) {
  const table = el("table", "kv-table");
  const tbody = el("tbody");
  const entries = Object.entries(evidence || {});

  if (entries.length === 0) {
    const row = el("tr");
    const cell = el("td", null, "No additional evidence recorded.");
    cell.colSpan = 2;
    row.appendChild(cell);
    tbody.appendChild(row);
  }

  for (const [key, value] of entries) {
    const row = el("tr");
    row.appendChild(el("th", null, key.replace(/_/g, " ")));
    const formatted =
      value !== null && typeof value === "object" ? JSON.stringify(value) : String(value);
    row.appendChild(el("td", null, formatted));
    tbody.appendChild(row);
  }

  table.appendChild(tbody);
  return table;
}

/* ------------------------------------------------------- report card ----- */

/**
 * Render a full scan report into `card`.
 *
 * @param {HTMLElement} card
 * @param {{url: string, label: string, confidence: number, risk_score: number,
 *          risk_band?: string, source?: string,
 *          signals: Array<{name: string, triggered: boolean, direction: string, evidence: object}>,
 *          plain_explanation: string, scan_id?: string, created_at?: string}} report
 */
function renderReportCard(card, report) {
  card.classList.remove("hidden");
  card.className = "stack stack--lg animate-in";
  card.innerHTML = "";

  const signals = report.signals || [];
  const triggered = signals.filter((s) => s.triggered);
  const hasRiskScore = typeof report.risk_score === "number";
  const gaugeValue = hasRiskScore ? report.risk_score : report.confidence;
  const band = report.risk_band || "";

  /* -- verdict card ------------------------------------------------- */

  const verdictCard = el("section", "card");

  const head = el("div", "verdict-head");
  head.appendChild(renderGauge(gaugeValue, band, hasRiskScore ? "Risk Score" : "Confidence"));

  const summary = el("div", "verdict-summary");

  const verdictRow = el("div", "verdict-row");
  verdictRow.appendChild(verdictBadge(report.label));
  if (report.risk_band) verdictRow.appendChild(riskBandBadge(report.risk_band));
  summary.appendChild(verdictRow);

  const urlEl = el("p", "scanned-url");
  const linkIcon = argusIcon("link");
  if (linkIcon) urlEl.appendChild(linkIcon);
  urlEl.appendChild(document.createTextNode(report.url));
  summary.appendChild(urlEl);

  if (report.plain_explanation) {
    summary.appendChild(el("p", "explanation", report.plain_explanation));
  }

  if (triggered.length > 0) {
    const signalsEl = el("div", "signals");
    for (const signal of triggered) {
      const badge = el("span", `signal-badge ${signal.direction}`);
      const meta = SIGNAL_META[signal.name];
      const icon = argusIcon(meta ? meta.icon : "activity");
      if (icon) badge.appendChild(icon);
      badge.appendChild(document.createTextNode(signalLabel(signal)));
      badge.setAttribute("data-tooltip", JSON.stringify(signal.evidence, null, 2));
      badge.tabIndex = 0;
      signalsEl.appendChild(badge);
    }
    summary.appendChild(signalsEl);
  }

  head.appendChild(summary);
  verdictCard.appendChild(head);

  /* -- metric strip -------------------------------------------------- */

  const strip = el("div", "metric-strip");

  const confidenceCell = el("div", "stack stack--sm");
  confidenceCell.appendChild(el("span", null, `${(report.confidence * 100).toFixed(1)}%`));
  confidenceCell.appendChild(renderMeter(report.confidence, report.label));
  strip.appendChild(renderMetric("Confidence", confidenceCell));

  if (hasRiskScore) {
    strip.appendChild(renderMetric("Risk Score", `${(report.risk_score * 100).toFixed(0)} / 100`));
  }

  if (report.source) {
    const meta = sourceMeta(report.source);
    const sourceValue = el("span");
    const icon = argusIcon(meta.icon);
    if (icon) {
      icon.style.width = "15px";
      icon.style.height = "15px";
      sourceValue.appendChild(icon);
    }
    sourceValue.appendChild(document.createTextNode(meta.label));
    sourceValue.style.display = "inline-flex";
    sourceValue.style.alignItems = "center";
    sourceValue.style.gap = "0.5rem";
    strip.appendChild(renderMetric("Decided By", sourceValue));
  }

  if (report.created_at) {
    strip.appendChild(
      renderMetric("Scanned", new Date(report.created_at).toLocaleString())
    );
  }

  verdictCard.appendChild(strip);
  card.appendChild(verdictCard);

  /* -- analysis breakdown -------------------------------------------- */

  const analysis = el("section", "card");

  const analysisHeader = el("div", "card-header");
  const analysisIcon = argusIcon("radar");
  if (analysisIcon) analysisHeader.appendChild(analysisIcon);
  const analysisTitles = el("div");
  analysisTitles.style.flex = "1";
  analysisTitles.appendChild(el("h2", null, "Analysis Breakdown"));
  analysisTitles.appendChild(
    el(
      "div",
      "card-desc",
      `${triggered.length} of ${signals.length} detection signals triggered`
    )
  );
  analysisHeader.appendChild(analysisTitles);
  analysis.appendChild(analysisHeader);

  const accordion = el("div", "accordion");

  // 1. Detection signals — every signal that ran, triggered or not.
  if (signals.length > 0) {
    const body = el("div", "stack");
    for (const signal of signals) {
      const meta = SIGNAL_META[signal.name] || { icon: "activity", title: signal.name };
      const row = el("div", "card");
      row.style.background = "var(--bg-alt)";

      const rowHead = el("div", "row row--between");
      rowHead.style.padding = "var(--space-3) var(--space-4)";

      const rowTitle = el("div", "row");
      const rowIcon = argusIcon(meta.icon);
      if (rowIcon) {
        rowIcon.style.width = "15px";
        rowIcon.style.height = "15px";
        rowIcon.style.color = "var(--text-muted)";
        rowTitle.appendChild(rowIcon);
      }
      rowTitle.appendChild(el("span", null, meta.title));
      rowHead.appendChild(rowTitle);

      rowHead.appendChild(
        signal.triggered
          ? el(
              "span",
              `badge badge--${signal.direction === "legitimate" ? "success" : "danger"}`,
              signal.direction === "legitimate" ? "Cleared" : "Triggered"
            )
          : el("span", "badge", "Not triggered")
      );

      row.appendChild(rowHead);

      if (signal.triggered) {
        const detail = el("div");
        detail.style.padding = "0 var(--space-4) var(--space-3)";
        detail.appendChild(el("p", "meta", signalLabel(signal)));
        detail.appendChild(renderEvidenceTable(signal.evidence));
        row.appendChild(detail);
      }

      body.appendChild(row);
    }

    accordion.appendChild(
      renderAccordionItem({
        id: "section-signals",
        title: "Detection Signals",
        subtitle: `${triggered.length} triggered`,
        icon: "radar",
        tone: triggered.length > 0 ? "danger" : "success",
        open: triggered.length > 0,
        body,
      })
    );
  }

  // 2. Threat intelligence — only when a feed actually decided this verdict.
  const isThreatIntel = report.source && !["model", "fusion"].includes(report.source);
  if (isThreatIntel) {
    const meta = sourceMeta(report.source);
    const body = el("div", "stack");
    body.appendChild(el("p", "muted", meta.desc));
    const table = el("table", "kv-table");
    const tbody = el("tbody");
    const row = el("tr");
    row.appendChild(el("th", null, "provider"));
    row.appendChild(el("td", null, report.source));
    tbody.appendChild(row);
    table.appendChild(tbody);
    body.appendChild(table);

    accordion.appendChild(
      renderAccordionItem({
        id: "section-threat-intel",
        title: "Threat Intelligence",
        subtitle: `Matched by ${meta.label}`,
        icon: "database",
        tone: "danger",
        body,
      })
    );
  }

  // 3. Model result.
  const modelBody = el("div", "stack");
  modelBody.appendChild(
    el(
      "p",
      "muted",
      isThreatIntel
        ? "This URL matched a threat-intelligence feed before the model ran, so no model inference was performed — the confidence shown is the feed's certainty."
        : "The machine-learning classifier's confidence in the reported label."
    )
  );
  const modelMeterRow = el("div", "stack stack--sm");
  const modelValue = el("div", "row row--between");
  modelValue.appendChild(el("span", "meta", "Model confidence"));
  modelValue.appendChild(el("span", "mono", `${(report.confidence * 100).toFixed(1)}%`));
  modelMeterRow.appendChild(modelValue);
  modelMeterRow.appendChild(renderMeter(report.confidence, report.label));
  modelBody.appendChild(modelMeterRow);

  accordion.appendChild(
    renderAccordionItem({
      id: "section-model",
      title: "ML Result",
      subtitle: `${(report.confidence * 100).toFixed(1)}% confidence`,
      icon: "cpu",
      tone: "info",
      body: modelBody,
    })
  );

  // 4. Final decision.
  const decisionBody = el("div", "stack");
  const meta = sourceMeta(report.source || "model");
  decisionBody.appendChild(el("p", "muted", meta.desc));
  if (report.plain_explanation) {
    decisionBody.appendChild(el("p", "explanation", report.plain_explanation));
  }
  const decisionRow = el("div", "row");
  decisionRow.appendChild(verdictBadge(report.label, true));
  if (report.risk_band) decisionRow.appendChild(riskBandBadge(report.risk_band));
  decisionBody.appendChild(decisionRow);

  accordion.appendChild(
    renderAccordionItem({
      id: "section-decision",
      title: "Final Decision",
      subtitle: meta.label,
      icon: report.label === "phishing" ? "shield-alert" : "shield-check",
      tone: report.label === "phishing" ? "danger" : "success",
      open: true,
      body: decisionBody,
    })
  );

  analysis.appendChild(accordion);
  card.appendChild(analysis);

  /* -- share ---------------------------------------------------------- */

  if (report.scan_id) {
    const shareCard = el("section", "card");

    const shareHeader = el("div", "card-header");
    const shareIcon = argusIcon("link");
    if (shareIcon) shareHeader.appendChild(shareIcon);
    shareHeader.appendChild(el("h2", null, "Share this report"));
    shareCard.appendChild(shareHeader);

    const shareBody = el("div", "card-body stack");
    const shareRow = el("div", "share-row");

    const link = el("input");
    link.type = "text";
    link.readOnly = true;
    link.value = `${location.origin}/app/scan.html?id=${report.scan_id}`;
    link.setAttribute("aria-label", "Shareable report link");
    shareRow.appendChild(link);

    const copyBtn = el("button", "btn btn--secondary");
    copyBtn.type = "button";
    const setCopyLabel = (iconName, text) => {
      copyBtn.innerHTML = "";
      const icon = argusIcon(iconName);
      if (icon) copyBtn.appendChild(icon);
      copyBtn.appendChild(document.createTextNode(text));
    };
    setCopyLabel("copy", "Copy link");
    copyBtn.addEventListener("click", async () => {
      await navigator.clipboard.writeText(link.value);
      setCopyLabel("check", "Copied");
      showToast("Report link copied to clipboard", "success");
      setTimeout(() => setCopyLabel("copy", "Copy link"), 1800);
    });
    shareRow.appendChild(copyBtn);

    shareBody.appendChild(shareRow);
    shareBody.appendChild(
      el("p", "meta", "Anyone with this link can view the report until it expires.")
    );
    shareCard.appendChild(shareBody);
    card.appendChild(shareCard);
  }
}

/* ------------------------------------------------------------- errors ---- */

/**
 * Render an error into a container as a full alert component.
 *
 * Named `showErrorBox` rather than `showError` so pages that want their own
 * single-argument `showError(message)` wrapper (login.html) can define one
 * without shadowing this.
 *
 * @param {HTMLElement} box
 * @param {string} message
 */
function showErrorBox(box, message) {
  box.className = "alert alert--danger";
  box.innerHTML = "";
  const icon = argusIcon("alert-triangle");
  if (icon) box.appendChild(icon);
  box.appendChild(el("span", null, message));
  box.classList.remove("hidden");
}

/**
 * @param {HTMLElement} box
 * @param {string} message
 */
function showSuccessBox(box, message) {
  box.className = "alert alert--success";
  box.innerHTML = "";
  const icon = argusIcon("check-circle");
  if (icon) box.appendChild(icon);
  box.appendChild(el("span", null, message));
  box.classList.remove("hidden");
}

/* ------------------------------------------------------------- toasts ---- */

/**
 * Transient confirmation, bottom-right. Announced politely so screen-reader
 * users get the same feedback sighted users get from the animation.
 * @param {string} message
 * @param {"success"|"danger"|"info"} [tone]
 */
function showToast(message, tone) {
  let region = document.getElementById("toastRegion");
  if (!region) {
    region = el("div", "toast-region");
    region.id = "toastRegion";
    region.setAttribute("role", "status");
    region.setAttribute("aria-live", "polite");
    document.body.appendChild(region);
  }

  const toast = el("div", `toast toast--${tone || "info"}`);
  const iconName = tone === "success" ? "check-circle" : tone === "danger" ? "alert-triangle" : "info";
  const icon = argusIcon(iconName);
  if (icon) toast.appendChild(icon);
  toast.appendChild(el("span", null, message));
  region.appendChild(toast);

  setTimeout(() => {
    toast.classList.add("leaving");
    setTimeout(() => toast.remove(), 220);
  }, 2600);
}

/* --------------------------------------------------------- history row --- */

/**
 * One `<tr>` for the dashboard's scan-history table.
 *
 * @param {{id: number, url: string, label: string, risk_band: string,
 *          confidence: number, source: string, created_at: string|null}} scan
 * @param {(format: string) => void} onExport called with "json"|"csv"|"pdf"
 * @returns {HTMLElement} a <tr>
 */
function renderHistoryRow(scan, onExport) {
  const row = el("tr", "history-row");

  const verdictCell = el("td");
  verdictCell.appendChild(verdictBadge(scan.label, true));
  row.appendChild(verdictCell);

  const bandCell = el("td");
  if (scan.risk_band) bandCell.appendChild(riskBandBadge(scan.risk_band));
  row.appendChild(bandCell);

  const urlCell = el("td");
  const url = el("span", "cell-url", scan.url);
  url.title = scan.url;
  urlCell.appendChild(url);
  row.appendChild(urlCell);

  const sourceCell = el("td");
  sourceCell.appendChild(el("span", "badge", sourceMeta(scan.source).label));
  row.appendChild(sourceCell);

  row.appendChild(
    el("td", "meta", scan.created_at ? new Date(scan.created_at).toLocaleString() : "—")
  );

  const actions = el("td");
  const actionRow = el("div", "cell-actions");
  for (const format of ["json", "csv", "pdf"]) {
    const btn = el("button", "btn btn--ghost btn--sm export-btn", format.toUpperCase());
    btn.type = "button";
    btn.setAttribute("data-tooltip", `Export this report as ${format.toUpperCase()}`);
    btn.addEventListener("click", () => onExport(format));
    actionRow.appendChild(btn);
  }
  actions.appendChild(actionRow);
  row.appendChild(actions);

  return row;
}

/* ---------------------------------------------------------- bar charts --- */

/**
 * A horizontal bar breakdown (risk-band distribution, detection sources…).
 * No charting library and no CDN — same self-contained rule as the rest of
 * webapp/.
 * @param {HTMLElement} container
 * @param {Record<string, number>} counts
 * @param {(key: string) => string} [labelFn]
 */
function renderBarList(container, counts, labelFn) {
  container.innerHTML = "";
  container.className = "bar-list";

  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) {
    container.appendChild(renderEmptyState("inbox", "No data yet", "Scan a URL while signed in and it will appear here."));
    return;
  }

  for (const [key, count] of Object.entries(counts).sort((a, b) => b[1] - a[1])) {
    const pct = Math.round((count / total) * 100);

    const row = el("div", "bar-row");
    row.appendChild(el("span", "bar-label", labelFn ? labelFn(key) : key));

    const track = el("div", "bar-track");
    const fill = el("div", `bar-fill ${key}`);
    track.appendChild(fill);
    row.appendChild(track);
    requestAnimationFrame(() => {
      fill.style.width = `${pct}%`;
    });

    row.appendChild(el("span", "bar-count", `${count} (${pct}%)`));
    container.appendChild(row);
  }
}

/**
 * Stacked daily-volume chart over the last `days` days, split by verdict.
 * Built from the same history payload the table uses — no extra request.
 * @param {HTMLElement} container
 * @param {Array<{label: string, created_at: string|null}>} scans
 * @param {number} [days]
 */
function renderTimeline(container, scans, days) {
  const span = days || 14;
  container.innerHTML = "";

  const buckets = [];
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  for (let i = span - 1; i >= 0; i--) {
    const day = new Date(today);
    day.setDate(day.getDate() - i);
    buckets.push({ day, phishing: 0, legitimate: 0 });
  }

  for (const scan of scans) {
    if (!scan.created_at) continue;
    const when = new Date(scan.created_at);
    when.setHours(0, 0, 0, 0);
    const bucket = buckets.find((b) => b.day.getTime() === when.getTime());
    if (!bucket) continue;
    if (scan.label === "phishing") bucket.phishing += 1;
    else bucket.legitimate += 1;
  }

  const max = Math.max(...buckets.map((b) => b.phishing + b.legitimate), 1);

  const chart = el("div", "timeline-chart");
  for (const bucket of buckets) {
    const col = el("div", "timeline-col");
    const dayLabel = bucket.day.toLocaleDateString(undefined, { month: "short", day: "numeric" });
    col.setAttribute(
      "data-tooltip",
      `${dayLabel}\n${bucket.phishing} phishing · ${bucket.legitimate} legitimate`
    );
    col.tabIndex = 0;

    for (const kind of ["phishing", "legitimate"]) {
      if (bucket[kind] === 0) continue;
      const seg = el("div", `timeline-seg timeline-seg--${kind}`);
      seg.style.height = "0";
      col.appendChild(seg);
      requestAnimationFrame(() => {
        seg.style.height = `${(bucket[kind] / max) * 100}%`;
      });
    }

    chart.appendChild(col);
  }
  container.appendChild(chart);

  // Sparse axis: first, middle and last day only — a tick per column is
  // unreadable at this width.
  const axis = el("div", "timeline-axis");
  buckets.forEach((bucket, index) => {
    const showTick = index === 0 || index === buckets.length - 1 || index === Math.floor(span / 2);
    axis.appendChild(
      el(
        "span",
        "timeline-tick",
        showTick ? bucket.day.toLocaleDateString(undefined, { month: "short", day: "numeric" }) : ""
      )
    );
  });
  container.appendChild(axis);

  const legend = el("div", "chart-legend");
  for (const [kind, text] of [["phishing", "Phishing"], ["legitimate", "Legitimate"]]) {
    const item = el("div", "legend-item");
    item.appendChild(el("span", `legend-swatch legend-swatch--${kind}`));
    item.appendChild(el("span", null, text));
    legend.appendChild(item);
  }
  container.appendChild(legend);
}

/* ------------------------------------------------------- empty/loading --- */

/**
 * @param {string} icon
 * @param {string} title
 * @param {string} [description]
 * @returns {HTMLElement}
 */
function renderEmptyState(icon, title, description) {
  const wrap = el("div", "empty-state");
  const iconEl = argusIcon(icon);
  if (iconEl) wrap.appendChild(iconEl);
  wrap.appendChild(el("p", "empty-title", title));
  if (description) wrap.appendChild(el("p", null, description));
  return wrap;
}

/* ---------------------------------------------------------- app shell ---- */

/**
 * Wire the responsive sidebar drawer + the shared nav auth state.
 * Safe to call on any page; every lookup is optional.
 */
function initAppShell() {
  const toggle = document.getElementById("sidebarToggle");
  if (toggle) {
    toggle.addEventListener("click", () => {
      const open = document.body.getAttribute("data-nav-open") === "true";
      document.body.setAttribute("data-nav-open", String(!open));
      toggle.setAttribute("aria-expanded", String(!open));
    });

    // Clicking the scrim (rendered as body::after) or pressing Escape closes
    // the drawer — a drawer with no way out is a trap on touch devices.
    document.addEventListener("click", (event) => {
      if (document.body.getAttribute("data-nav-open") !== "true") return;
      const sidebar = document.querySelector(".sidebar");
      if (sidebar && !sidebar.contains(event.target) && !toggle.contains(event.target)) {
        document.body.setAttribute("data-nav-open", "false");
        toggle.setAttribute("aria-expanded", "false");
      }
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && document.body.getAttribute("data-nav-open") === "true") {
        document.body.setAttribute("data-nav-open", "false");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
  }
}

/**
 * auto-sentinel live SOC dashboard client.
 *
 * SECURITY NOTE (XSS Defense):
 * Untrusted attacker-controlled strings parsed from auth.log or OS process command
 * lines (usernames, source IPs, raw_message, command lines) are rendered exclusively
 * via `document.createElement` and `.textContent`. `innerHTML` is never used with
 * telemetry data so log-injection payloads like `<img src=x onerror=...>` remain inert.
 */

const MAX_ROWS = 200;
const MAX_LEDGER_VISIBLE = 8;

const TACTIC_NAMES = {
  TA0001: "Initial Access",
  TA0002: "Execution",
  TA0003: "Persistence",
  TA0004: "Privilege Escalation",
  TA0005: "Defense Evasion",
  TA0006: "Credential Access",
};

const state = {
  eventsTotal: 0,
  alertsTotal: 0,
  ipsBlocked: 0,
  procsTerminated: 0,
  ledgerCount: 0,
  ledgerIntact: true,
  epsSeries: new Array(60).fill(0),
  watchTarget: "data/auth.log",
  alerts: [],
  ledgerRecords: [],
};

const el = {
  engineMode: document.getElementById("engine-mode"),
  sseDot: document.getElementById("sse-dot"),
  sseState: document.getElementById("sse-state"),
  uptime: document.getElementById("uptime"),
  simFeedback: document.getElementById("sim-feedback"),
  btnSimBrute: document.getElementById("btn-sim-brute"),
  btnSimShell: document.getElementById("btn-sim-shell"),
  btnVerifyChain: document.getElementById("btn-verify-chain"),
  verifyStatus: document.getElementById("verify-status"),
  kpiEvents: document.getElementById("kpi-events"),
  kpiAlerts: document.getElementById("kpi-alerts"),
  kpiIps: document.getElementById("kpi-ips"),
  kpiProcs: document.getElementById("kpi-procs"),
  kpiQueue: document.getElementById("kpi-queue"),
  kpiQueueBar: document.getElementById("kpi-queue-bar"),
  kpiLedgerCount: document.getElementById("kpi-ledger-count"),
  kpiLedgerStatus: document.getElementById("kpi-ledger-status"),
  epsReadout: document.getElementById("eps-readout"),
  sparkline: document.getElementById("eps-sparkline"),
  eventsBody: document.getElementById("events-body"),
  eventsEmpty: document.getElementById("events-empty"),
  alertsList: document.getElementById("alerts-list"),
  alertsEmpty: document.getElementById("alerts-empty"),
  alertsMeta: document.getElementById("alerts-meta"),
  responsesBody: document.getElementById("responses-body"),
  responsesEmpty: document.getElementById("responses-empty"),
  responsesMeta: document.getElementById("responses-meta"),
  ledgerChain: document.getElementById("ledger-chain"),
  ledgerEmpty: document.getElementById("ledger-empty"),
};

function formatTimeMs(isoString) {
  const dt = new Date(isoString);
  if (Number.isNaN(dt.getTime())) return "--:--:--.---";
  const hh = String(dt.getHours()).padStart(2, "0");
  const mm = String(dt.getMinutes()).padStart(2, "0");
  const ss = String(dt.getSeconds()).padStart(2, "0");
  const ms = String(dt.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${ms}`;
}

function formatUptime(totalSeconds) {
  const sec = Math.max(0, Math.floor(totalSeconds || 0));
  const h = String(Math.floor(sec / 3600)).padStart(2, "0");
  const m = String(Math.floor((sec % 3600) / 60)).padStart(2, "0");
  const s = String(sec % 60).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

function formatRelativeTime(isoString) {
  const ts = Date.parse(isoString);
  if (Number.isNaN(ts)) return "";
  const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (diffSec < 3) return "just now";
  if (diffSec < 60) return `${diffSec}s ago`;
  const mins = Math.floor(diffSec / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  return `${hrs}h ago`;
}

function shortHash(hex) {
  if (!hex || hex.length <= 10) return hex || "";
  return `${hex.slice(0, 4)}\u2026${hex.slice(-4)}`;
}

function makeCell(text, className, titleText) {
  const td = document.createElement("td");
  if (className) td.className = className;
  td.textContent = text;
  if (titleText) td.title = titleText;
  return td;
}

function renderEventRow(ev, flash) {
  const tr = document.createElement("tr");
  if (flash) tr.className = "row-flash";

  const detail = ev.raw_message || "";
  tr.appendChild(makeCell(formatTimeMs(ev.timestamp), "mono tabular col-time", ev.timestamp));
  tr.appendChild(makeCell(ev.event_type || "", "mono col-type"));
  tr.appendChild(makeCell(ev.source || "", "mono col-source"));
  tr.appendChild(makeCell(ev.source_ip || "-", "mono col-ip"));
  tr.appendChild(makeCell(ev.user || "-", "mono col-user"));
  tr.appendChild(makeCell(detail, "mono col-detail", detail));

  return tr;
}

function insertEvent(ev, flash) {
  el.eventsEmpty.classList.add("hidden");
  const row = renderEventRow(ev, flash);
  el.eventsBody.prepend(row);
  while (el.eventsBody.children.length > MAX_ROWS) {
    el.eventsBody.removeChild(el.eventsBody.lastElementChild);
  }
}

function renderAlerts() {
  if (state.alerts.length === 0) {
    el.alertsList.replaceChildren();
    el.alertsEmpty.classList.remove("hidden");
    el.alertsMeta.textContent = "0 raised";
    return;
  }

  el.alertsEmpty.classList.add("hidden");
  el.alertsMeta.textContent = `${state.alertsTotal} raised`;

  const fragment = document.createDocumentFragment();
  for (const alert of state.alerts) {
    const item = document.createElement("div");
    item.className = "alert-item";

    const top = document.createElement("div");
    top.className = "alert-top";

    const sevLower = (alert.severity || "low").toLowerCase();
    const sevWrap = document.createElement("span");
    sevWrap.className = `alert-sev sev-${sevLower}`;

    const dot = document.createElement("span");
    dot.className = `dot dot-${sevLower}`;
    const sevText = document.createElement("span");
    sevText.textContent = alert.severity || "LOW";

    sevWrap.appendChild(dot);
    sevWrap.appendChild(sevText);

    const timeEl = document.createElement("span");
    timeEl.className = "alert-time mono tabular";
    timeEl.textContent = formatRelativeTime(alert.timestamp);

    top.appendChild(sevWrap);
    top.appendChild(timeEl);

    const ruleEl = document.createElement("div");
    ruleEl.className = "alert-rule";
    ruleEl.textContent = alert.rule_name || "Detection alert";

    const metaEl = document.createElement("div");
    metaEl.className = "alert-meta";

    const chip = document.createElement("span");
    chip.className = "mitre-chip mono";
    const techId = document.createElement("span");
    techId.textContent = alert.mitre_technique_id || "";
    const tacticName = TACTIC_NAMES[alert.mitre_tactic] || alert.mitre_tactic || "";
    const tacticEl = document.createElement("span");
    tacticEl.className = "mitre-tactic";
    tacticEl.textContent = tacticName;
    chip.appendChild(techId);
    if (tacticName) chip.appendChild(tacticEl);

    const targetEl = document.createElement("span");
    targetEl.className = "mono";
    if (alert.target_ip) {
      targetEl.textContent = alert.target_ip;
    } else if (alert.target_process_name) {
      targetEl.textContent = `${alert.target_process_name} (PID ${alert.target_pid ?? "?"})`;
    } else {
      targetEl.textContent = "host";
    }

    metaEl.appendChild(chip);
    metaEl.appendChild(targetEl);

    item.appendChild(top);
    item.appendChild(ruleEl);
    item.appendChild(metaEl);
    fragment.appendChild(item);
  }
  el.alertsList.replaceChildren(fragment);
}

function renderResponseRow(res, flash) {
  const tr = document.createElement("tr");
  if (flash) tr.className = "row-flash";

  tr.appendChild(makeCell(formatTimeMs(res.timestamp), "mono tabular col-time", res.timestamp));
  tr.appendChild(makeCell(res.action_type || "", "mono col-action"));
  tr.appendChild(makeCell(res.target || "", "mono col-target"));

  const resultCell = document.createElement("td");
  resultCell.className = `col-result mono ${res.success ? "res-ok" : "res-fail"}`;
  resultCell.textContent = res.success ? "\u2713" : "\u2715";
  resultCell.title = res.success ? "Succeeded" : "Failed / Guarded";
  tr.appendChild(resultCell);

  const details = res.details || "";
  tr.appendChild(makeCell(details, "mono col-detail", details));
  return tr;
}

function insertResponse(res, flash) {
  el.responsesEmpty.classList.add("hidden");
  const row = renderResponseRow(res, flash);
  el.responsesBody.prepend(row);
  while (el.responsesBody.children.length > MAX_ROWS) {
    el.responsesBody.removeChild(el.responsesBody.lastElementChild);
  }
  const executed = state.ipsBlocked + state.procsTerminated;
  el.responsesMeta.textContent = `${executed} succeeded`;
}

function renderLedgerChain() {
  const visible = state.ledgerRecords.slice(0, MAX_LEDGER_VISIBLE);
  if (visible.length === 0) {
    el.ledgerChain.replaceChildren();
    el.ledgerEmpty.classList.remove("hidden");
    return;
  }

  el.ledgerEmpty.classList.add("hidden");
  const fragment = document.createDocumentFragment();
  for (const rec of visible) {
    const node = document.createElement("div");
    node.className = "ledger-node";

    const head = document.createElement("div");
    head.className = "ledger-head";

    const idSpan = document.createElement("span");
    idSpan.className = "ledger-id mono";
    idSpan.textContent = `#${rec.record_id} ${rec.event_type}`;

    const tsSpan = document.createElement("span");
    tsSpan.className = "panel-meta mono tabular";
    tsSpan.textContent = formatTimeMs(rec.timestamp);

    head.appendChild(idSpan);
    head.appendChild(tsSpan);

    const hashes = document.createElement("div");
    hashes.className = "ledger-hashes mono";

    const pLbl = document.createTextNode("prev ");
    const pVal = document.createElement("span");
    pVal.className = "hash-val";
    pVal.textContent = shortHash(rec.prev_hash);
    pVal.title = rec.prev_hash || "";

    const arrow = document.createTextNode(" \u2192 hash ");
    const cVal = document.createElement("span");
    cVal.className = "hash-val";
    cVal.textContent = shortHash(rec.current_hash);
    cVal.title = rec.current_hash || "";

    hashes.appendChild(pLbl);
    hashes.appendChild(pVal);
    hashes.appendChild(arrow);
    hashes.appendChild(cVal);

    node.appendChild(head);
    node.appendChild(hashes);
    fragment.appendChild(node);
  }
  el.ledgerChain.replaceChildren(fragment);
}

function drawSparkline() {
  const canvas = el.sparkline;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const dpr = window.devicePixelRatio || 1;
  const cssWidth = canvas.clientWidth || 600;
  const cssHeight = canvas.clientHeight || 44;

  if (canvas.width !== Math.floor(cssWidth * dpr) || canvas.height !== Math.floor(cssHeight * dpr)) {
    canvas.width = Math.floor(cssWidth * dpr);
    canvas.height = Math.floor(cssHeight * dpr);
  }

  ctx.save();
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, cssWidth, cssHeight);

  const series = state.epsSeries.length > 0 ? state.epsSeries : [0];
  const padTop = 4;
  const padBottom = 4;
  const plotHeight = Math.max(1, cssHeight - padTop - padBottom);
  const baselineY = cssHeight - padBottom + 0.5;

  // Faint 1px baseline
  ctx.strokeStyle = "#1e2228";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(0, baselineY);
  ctx.lineTo(cssWidth, baselineY);
  ctx.stroke();

  const maxVal = Math.max(1, ...series);
  const stepX = series.length > 1 ? cssWidth / (series.length - 1) : cssWidth;

  // 1px accent line, no fill
  ctx.strokeStyle = "#3d8bfd";
  ctx.lineWidth = 1;
  ctx.beginPath();
  for (let i = 0; i < series.length; i++) {
    const x = i * stepX;
    const norm = series[i] / maxVal;
    const y = cssHeight - padBottom - norm * plotHeight;
    if (i === 0) {
      ctx.moveTo(x, y);
    } else {
      ctx.lineTo(x, y);
    }
  }
  ctx.stroke();
  ctx.restore();

  const latestEps = series[series.length - 1] || 0;
  el.epsReadout.textContent = `${latestEps} evt/s \u00b7 60s`;
}

function updateKPIs(stats) {
  if (typeof stats.events_total === "number") state.eventsTotal = stats.events_total;
  if (typeof stats.alerts_total === "number") state.alertsTotal = stats.alerts_total;
  if (typeof stats.ips_blocked === "number") state.ipsBlocked = stats.ips_blocked;
  if (typeof stats.procs_terminated === "number") state.procsTerminated = stats.procs_terminated;
  if (typeof stats.ledger_count === "number") state.ledgerCount = stats.ledger_count;
  if (typeof stats.ledger_intact === "boolean") state.ledgerIntact = stats.ledger_intact;
  if (Array.isArray(stats.eps_series)) state.epsSeries = stats.eps_series;

  el.kpiEvents.textContent = String(state.eventsTotal);
  el.kpiAlerts.textContent = String(state.alertsTotal);
  el.kpiIps.textContent = String(state.ipsBlocked);
  el.kpiProcs.textContent = String(state.procsTerminated);

  const depth = stats.queue_depth ?? 0;
  const cap = stats.queue_capacity ?? 1000;
  el.kpiQueue.textContent = `${depth} / ${cap}`;
  const pct = cap > 0 ? Math.min(100, Math.round((depth / cap) * 100)) : 0;
  el.kpiQueueBar.style.width = `${pct}%`;

  el.kpiLedgerCount.textContent = String(state.ledgerCount);
  el.kpiLedgerStatus.textContent = state.ledgerIntact ? "Intact" : "Tampered";
  el.kpiLedgerStatus.className = `ledger-state ${state.ledgerIntact ? "state-ok" : "state-err"}`;

  if (typeof stats.uptime_seconds === "number") {
    el.uptime.textContent = formatUptime(stats.uptime_seconds);
  }

  el.alertsMeta.textContent = `${state.alertsTotal} raised`;
  const executed = state.ipsBlocked + state.procsTerminated;
  el.responsesMeta.textContent = `${executed} succeeded`;

  drawSparkline();
}

function setSSEStatus(connected) {
  if (connected) {
    el.sseDot.className = "dot dot-success";
    el.sseState.textContent = "Live";
  } else {
    el.sseDot.className = "dot dot-warn";
    el.sseState.textContent = "Reconnecting\u2026";
  }
}

async function hydrate() {
  const resp = await fetch("/api/state");
  if (!resp.ok) return;
  const data = await resp.json();

  if (data.meta) {
    state.watchTarget = data.meta.log_file || "data/auth.log";
    const modeLabel = data.meta.dry_run ? "Armed \u00b7 dry-run" : "Armed \u00b7 active";
    el.engineMode.textContent = modeLabel;
    el.eventsEmpty.textContent = `No events. Engine is watching ${state.watchTarget}.`;
    el.alertsEmpty.textContent = `No alerts. Engine is watching ${state.watchTarget}.`;
  }

  if (data.stats) {
    updateKPIs(data.stats);
  }

  // Hydrate history (already newest-first from server; insert in reverse order so prepend preserves newest-first)
  el.eventsBody.replaceChildren();
  const events = Array.isArray(data.events) ? data.events : [];
  if (events.length === 0) {
    el.eventsEmpty.classList.remove("hidden");
  } else {
    for (let i = events.length - 1; i >= 0; i--) {
      insertEvent(events[i], false);
    }
  }

  state.alerts = Array.isArray(data.alerts) ? data.alerts.slice(0, MAX_ROWS) : [];
  renderAlerts();

  el.responsesBody.replaceChildren();
  const responses = Array.isArray(data.remediations) ? data.remediations : [];
  if (responses.length === 0) {
    el.responsesEmpty.classList.remove("hidden");
  } else {
    for (let i = responses.length - 1; i >= 0; i--) {
      insertResponse(responses[i], false);
    }
  }

  state.ledgerRecords = Array.isArray(data.ledger) ? data.ledger.slice(0, MAX_ROWS) : [];
  renderLedgerChain();
}

function connectStream() {
  const source = new EventSource("/api/stream");

  source.onopen = () => {
    setSSEStatus(true);
  };

  source.onerror = () => {
    setSSEStatus(false);
  };

  source.onmessage = (evt) => {
    let msg;
    try {
      msg = JSON.parse(evt.data);
    } catch {
      return;
    }

    if (msg.type === "event" && msg.data) {
      state.eventsTotal += 1;
      el.kpiEvents.textContent = String(state.eventsTotal);
      insertEvent(msg.data, true);
    } else if (msg.type === "alert" && msg.data) {
      state.alertsTotal += 1;
      state.alerts.unshift(msg.data);
      if (state.alerts.length > MAX_ROWS) state.alerts.pop();
      el.kpiAlerts.textContent = String(state.alertsTotal);
      renderAlerts();
    } else if (msg.type === "remediation" && msg.data) {
      const r = msg.data;
      if (r.success && r.action_type === "BLOCK_IP") {
        state.ipsBlocked += 1;
        el.kpiIps.textContent = String(state.ipsBlocked);
      } else if (r.success && r.action_type === "KILL_PROCESS") {
        state.procsTerminated += 1;
        el.kpiProcs.textContent = String(state.procsTerminated);
      }
      insertResponse(r, true);
    } else if (msg.type === "ledger" && msg.data) {
      state.ledgerRecords.unshift(msg.data);
      if (state.ledgerRecords.length > MAX_ROWS) state.ledgerRecords.pop();
      if (typeof msg.data.record_id === "number") {
        state.ledgerCount = Math.max(state.ledgerCount, msg.data.record_id);
        el.kpiLedgerCount.textContent = String(state.ledgerCount);
      }
      renderLedgerChain();
    } else if (msg.type === "stats" && msg.data) {
      updateKPIs(msg.data);
      if (state.alerts.length > 0) renderAlerts();
    }
  };
}

async function triggerSimulation(endpoint, button) {
  button.disabled = true;
  el.simFeedback.textContent = "";
  try {
    const resp = await fetch(endpoint, { method: "POST" });
    if (resp.ok) {
      el.simFeedback.textContent = "sent";
    }
  } finally {
    setTimeout(() => {
      button.disabled = false;
      el.simFeedback.textContent = "";
    }, 1500);
  }
}

async function verifyChain() {
  el.btnVerifyChain.disabled = true;
  try {
    const resp = await fetch("/api/ledger/verify", { method: "POST" });
    if (!resp.ok) return;
    const res = await resp.json();
    state.ledgerIntact = Boolean(res.intact);
    if (res.intact) {
      state.ledgerCount = res.count_or_id;
      el.kpiLedgerCount.textContent = String(state.ledgerCount);
      el.kpiLedgerStatus.textContent = "Intact";
      el.kpiLedgerStatus.className = "ledger-state state-ok";
      el.verifyStatus.textContent = `Verified (${res.count_or_id})`;
      el.verifyStatus.className = "verify-status mono state-ok";
    } else {
      el.kpiLedgerStatus.textContent = "Tampered";
      el.kpiLedgerStatus.className = "ledger-state state-err";
      el.verifyStatus.textContent = `Corrupted at #${res.count_or_id}`;
      el.verifyStatus.className = "verify-status mono state-err";
    }
  } finally {
    el.btnVerifyChain.disabled = false;
  }
}

el.btnSimBrute.addEventListener("click", () => {
  triggerSimulation("/api/simulate/bruteforce", el.btnSimBrute);
});

el.btnSimShell.addEventListener("click", () => {
  triggerSimulation("/api/simulate/reverse-shell", el.btnSimShell);
});

el.btnVerifyChain.addEventListener("click", verifyChain);
window.addEventListener("resize", drawSparkline);

hydrate().then(connectStream);

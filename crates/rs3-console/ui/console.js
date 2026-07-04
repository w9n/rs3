const tokenKey = "rs3-console-token";

// Checkpoint age drives the restore-trust summary before hard failures appear.
const CHECKPOINT_WARN_AGE_MS = 2 * 60 * 60 * 1000;
const CHECKPOINT_BAD_AGE_MS = 24 * 60 * 60 * 1000;

const state = {
  token: sessionStorage.getItem(tokenKey) || "",
  status: null,
  posture: null,
  lastError: null,
  postureError: null,
  autoRefresh: null,
};

const nodes = {
  connectionState: document.getElementById("connection-state"),
  refreshButton: document.getElementById("refresh-button"),
  clearTokenButton: document.getElementById("clear-token-button"),
  authForm: document.getElementById("auth-form"),
  tokenInput: document.getElementById("console-token"),
  lastRefresh: document.getElementById("last-refresh"),
  summaryPrimary: document.getElementById("summary-primary"),
  summarySecondary: document.getElementById("summary-secondary"),
  statusSummary: document.querySelector(".status-summary"),
  metrics: {
    restore: document.getElementById("metric-restore"),
    mode: document.getElementById("metric-mode"),
    checkpoint: document.getElementById("metric-checkpoint"),
    checkpointDetail: document.getElementById("metric-checkpoint-detail"),
    envelope: document.getElementById("metric-envelope"),
    retention: document.getElementById("metric-retention"),
    findings: document.getElementById("metric-findings"),
  },
  restoreBadge: document.getElementById("restore-badge"),
  restoreDetail: document.getElementById("restore-detail"),
  runtimeDetail: document.getElementById("runtime-detail"),
  storageDetail: document.getElementById("storage-detail"),
  securityDetail: document.getElementById("security-detail"),
  findingsTable: document.getElementById("findings-table"),
  postureState: document.getElementById("posture-state"),
  postureTable: document.getElementById("posture-table"),
};

nodes.tokenInput.value = state.token;
nodes.authForm.addEventListener("submit", (event) => {
  event.preventDefault();
  state.token = String(new FormData(nodes.authForm).get("token") || "").trim();
  if (state.token) {
    sessionStorage.setItem(tokenKey, state.token);
  }
  refreshStatus();
});
nodes.refreshButton.addEventListener("click", () => refreshStatus());
nodes.clearTokenButton.addEventListener("click", () => {
  state.token = "";
  state.status = null;
  state.posture = null;
  sessionStorage.removeItem(tokenKey);
  state.postureError = null;
  nodes.tokenInput.value = "";
  setConnection("Disconnected", "neutral");
  render();
});

render();
if (state.token) {
  refreshStatus();
}
state.autoRefresh = window.setInterval(() => {
  if (state.token) {
    refreshStatus({ silent: true });
  }
}, 30000);

async function refreshStatus(options = {}) {
  if (!state.token) {
    setConnection("Token required", "warn");
    return;
  }
  if (!options.silent) {
    setConnection("Refreshing", "neutral");
  }

  const [statusResult, postureResult] = await Promise.allSettled([
    fetchConsoleReport("/api/status"),
    fetchConsoleReport("/api/posture"),
  ]);

  if (postureResult.status === "fulfilled") {
    state.posture = postureResult.value;
    state.postureError = null;
  } else {
    state.postureError = errorMessage(postureResult.reason, "Posture refresh failed");
  }

  if (statusResult.status === "fulfilled") {
    state.status = statusResult.value;
    state.lastError = null;
    setConnection("Connected", "good");
  } else {
    state.lastError = errorMessage(statusResult.reason, "Refresh failed");
    setConnection("Error", "bad");
  }
  render();
}

function render() {
  const status = state.status;
  const findings = displayFindings(status);
  renderMetrics(status, findings);
  renderSummary(status, findings);
  renderDetails(status);
  renderFindings(findings);
  renderPosture(state.posture);
  nodes.lastRefresh.textContent = state.lastError
    ? state.lastError
    : status
      ? `Updated ${formatNow()}`
      : "Never refreshed";
}

function renderSummary(status, findings) {
  const restore = status?.restore || {};
  const backend = status?.backend || {};
  const anchor = status?.anchor || {};
  const checkpoint = restore.checkpoint;
  const age = checkpointAge(checkpoint);
  let kind = "neutral";
  let primary = "Connect to a gateway to inspect restore trust.";
  let secondary = "The console is read-only and shows path-redacted admin facts.";

  if (state.lastError) {
    kind = "bad";
    primary = "The console could not read gateway status.";
    secondary = state.lastError;
  } else if (status) {
    const restoreState = restore.state || "unknown";
    if (restoreState === "verified") {
      kind = summaryKind(age, findings);
      primary = `Restore trust is verified at checkpoint ${checkpoint?.sequence ?? "unknown"}, published ${age?.label || "unknown"}.`;
      secondary = findings.length === 0
        ? "No profile findings were reported by the gateway."
        : `${findings.length} profile finding${findings.length === 1 ? "" : "s"} need review.`;
    } else {
      kind = "warn";
      primary = `Restore trust is ${restoreState}.`;
      secondary = restore.reason_code
        ? `Reason: ${restore.reason_code}. ${stateContext(backend, anchor)}`
        : stateContext(backend, anchor);
    }
  }

  nodes.statusSummary.className = `status-summary summary-${kind}`;
  nodes.summaryPrimary.textContent = primary;
  nodes.summarySecondary.textContent = secondary;
}

function renderMetrics(status, findings) {
  const restore = status?.restore || {};
  const runtime = status?.runtime || {};
  const repository = status?.repository || {};
  const checkpoint = restore.checkpoint;
  const age = checkpointAge(checkpoint);
  const envelope = restore.keyring_envelope;
  nodes.metrics.restore.textContent = restore.state || "unknown";
  nodes.metrics.mode.textContent = runtime.gateway_mode || "unknown";
  nodes.metrics.checkpoint.textContent = checkpoint ? age?.label || "unknown" : "none";
  nodes.metrics.checkpointDetail.textContent = checkpoint
    ? `seq ${checkpoint.sequence}, ${age?.label || "unknown"}`
    : "";
  nodes.metrics.checkpoint
    .closest(".metric-panel")
    ?.classList.toggle("metric-warn", age?.kind === "warn");
  nodes.metrics.checkpoint
    .closest(".metric-panel")
    ?.classList.toggle("metric-bad", age?.kind === "bad");
  nodes.metrics.envelope.textContent = envelope
    ? `gen ${envelope.generation}`
    : "none";
  nodes.metrics.retention.textContent =
    repository.retention_mode && repository.retention_mode !== "none"
      ? `${repository.retention_mode} ${repository.retention_days}d`
      : repository.retention_mode || "unknown";
  nodes.metrics.findings.textContent = String(findings.length);

  const restoreState = restore.state || "unknown";
  nodes.restoreBadge.textContent = restoreState;
  nodes.restoreBadge.className = `state-pill ${restorePillClass(restoreState)}`;
}

function renderDetails(status) {
  const restore = status?.restore || {};
  const runtime = status?.runtime || {};
  const backend = status?.backend || {};
  const anchor = status?.anchor || {};
  const repository = status?.repository || {};
  const security = status?.security || {};

  replaceDetails(nodes.restoreDetail, [
    ["State", restore.state || "unknown"],
    ["Reason", restore.reason_code || "none"],
    ["Checkpoint sequence", restore.checkpoint?.sequence ?? "none"],
    ["Checkpoint id", restore.checkpoint?.checkpoint_id || "none"],
    ["Checkpoint digest", restore.checkpoint?.checkpoint_digest || "none"],
    ["Published", formatTimestamp(restore.checkpoint?.published_at_ms)],
    ["Envelope generation", restore.keyring_envelope?.generation ?? "none"],
    ["Envelope digest", restore.keyring_envelope?.digest || "none"],
  ]);

  replaceDetails(nodes.runtimeDetail, [
    ["Gateway mode", runtime.gateway_mode || "unknown"],
    ["Config profile", runtime.config_profile || "unknown"],
    ["Static credentials", yesNo(runtime.static_credentials_configured)],
    ["Metrics", yesNo(runtime.metrics_configured)],
    ["Report profile", status?.profile || "unknown"],
    ["Generated", formatTimestamp(status?.generated_at_ms)],
  ]);

  replaceDetails(nodes.storageDetail, [
    ["Backend kind", backend.kind || "unknown"],
    ["Backend durable", yesNo(backend.durable)],
    ["Retention capability", backend.retention_capability || "unknown"],
    ["Anchor kind", anchor.kind || "unknown"],
    ["External anchor", yesNo(anchor.external)],
    ["Retention mode", repository.retention_mode || "unknown"],
    ["Retention days", repository.retention_days ?? "unknown"],
    ["Segment size", bytes(repository.payload_segment_size_bytes)],
  ]);

  replaceDetails(nodes.securityDetail, [
    ["Action posture", security.action_posture || "unknown"],
    ["Batch max items", repository.commit_max_batch_items ?? "unknown"],
    ["Batch delay", millis(repository.commit_max_batch_delay_ms)],
    ["Pending limit", repository.commit_max_pending_items ?? "unknown"],
  ]);
}

function displayFindings(status) {
  if (!status) {
    return [];
  }
  const findings = [...(status.findings || [])];
  const security = status.security || {};
  if (security.secrets_exposed === true) {
    findings.unshift({
      severity: "critical",
      code: "console.secrets-exposed",
      message: "The gateway admin report says secret material is exposed.",
    });
  }
  if (security.path_browsing_enabled === true) {
    findings.unshift({
      severity: "critical",
      code: "console.path-browsing-exposed",
      message: "The gateway admin surface says client-visible path browsing is exposed.",
    });
  }
  return findings;
}

function renderFindings(findings) {
  renderFindingTable(nodes.findingsTable, findings);
}

function renderPosture(posture) {
  if (state.postureError) {
    nodes.postureState.textContent = "Error";
    renderPanelMessage(nodes.postureTable, state.postureError, "error-state");
    return;
  }
  if (!posture) {
    nodes.postureState.textContent = "Not loaded";
    renderPanelMessage(nodes.postureTable, "Posture not loaded", "empty-state");
    return;
  }
  nodes.postureState.textContent = `${posture.profile || "unknown"} profile`;
  renderFindingTable(nodes.postureTable, displayFindings(posture));
}

function renderFindingTable(node, rows) {
  clear(node);
  if (rows.length === 0) {
    renderPanelMessage(node, "No findings", "empty-state");
    return;
  }
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const tbody = document.createElement("tbody");
  const header = document.createElement("tr");
  ["Severity", "Code", "Message"].forEach((name) => {
    const th = document.createElement("th");
    th.textContent = name;
    header.append(th);
  });
  thead.append(header);
  rows.forEach((finding) => {
    const row = document.createElement("tr");
    [finding.severity, finding.code, finding.message].forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value || "unknown";
      row.append(td);
    });
    tbody.append(row);
  });
  table.append(thead, tbody);
  node.append(table);
}

function renderPanelMessage(node, message, className) {
  clear(node);
  const empty = document.createElement("div");
  empty.className = className;
  empty.textContent = message;
  node.append(empty);
}

function replaceDetails(node, rows) {
  clear(node);
  rows.forEach(([name, value]) => node.append(detailItem(name, value)));
}

function detailItem(name, value) {
  const item = document.createElement("div");
  item.className = "detail-item";
  const label = document.createElement("span");
  label.textContent = name;
  const strong = document.createElement("strong");
  strong.textContent = value == null || value === "" ? "unknown" : String(value);
  item.append(label, strong);
  return item;
}

function clear(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function setConnection(text, kind) {
  nodes.connectionState.textContent = text;
  nodes.connectionState.className = `state-pill state-${kind}`;
}

async function fetchConsoleReport(path) {
  const response = await fetch(path, {
    method: "GET",
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${state.token}`,
    },
    cache: "no-store",
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body?.error?.message || `HTTP ${response.status}`);
  }
  return body;
}

function errorMessage(error, fallback) {
  return error instanceof Error ? error.message : fallback;
}

function restorePillClass(value) {
  if (value === "verified") {
    return "state-good";
  }
  if (value === "unavailable") {
    return "state-warn";
  }
  return "state-neutral";
}

function stateContext(backend, anchor) {
  const parts = [];
  if (backend.kind) {
    parts.push(`backend ${backend.kind}`);
  }
  if (backend.retention_capability) {
    parts.push(`retention ${backend.retention_capability}`);
  }
  if (anchor.kind) {
    parts.push(`anchor ${anchor.kind}${anchor.external ? "" : " local"}`);
  }
  return parts.length > 0
    ? `Current posture: ${parts.join(", ")}.`
    : "Current posture is unknown.";
}

function yesNo(value) {
  if (value === true) {
    return "yes";
  }
  if (value === false) {
    return "no";
  }
  return "unknown";
}

function bytes(value) {
  if (typeof value !== "number") {
    return "unknown";
  }
  return `${value} B`;
}

function millis(value) {
  if (typeof value !== "number") {
    return "unknown";
  }
  return `${value} ms`;
}

function checkpointAge(checkpoint) {
  const publishedAt = checkpoint?.published_at_ms;
  if (typeof publishedAt !== "number" || publishedAt <= 0) {
    return null;
  }
  const ageMs = Math.max(0, Date.now() - publishedAt);
  const kind = ageMs > CHECKPOINT_BAD_AGE_MS
    ? "bad"
    : ageMs > CHECKPOINT_WARN_AGE_MS
      ? "warn"
      : "good";
  return { label: relativeAge(ageMs), kind };
}

function relativeAge(ageMs) {
  const minute = 60 * 1000;
  const hour = 60 * minute;
  const day = 24 * hour;
  if (ageMs < minute) {
    return "just now";
  }
  if (ageMs < hour) {
    return `${Math.floor(ageMs / minute)} min ago`;
  }
  if (ageMs < day) {
    return `${Math.floor(ageMs / hour)} h ago`;
  }
  return `${Math.floor(ageMs / day)} d ago`;
}

function summaryKind(age, findings) {
  if (age?.kind === "bad") {
    return "bad";
  }
  if (age?.kind === "warn" || findings.length > 0) {
    return "warn";
  }
  return "good";
}

function formatTimestamp(value) {
  if (typeof value !== "number" || value <= 0) {
    return "none";
  }
  return new Date(value).toLocaleString();
}

function formatNow() {
  return new Date().toLocaleTimeString();
}

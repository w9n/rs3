const tokenKey = "rs3-console-token";

const state = {
  token: sessionStorage.getItem(tokenKey) || "",
  status: null,
  lastError: null,
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
  sessionStorage.removeItem(tokenKey);
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
  try {
    const response = await fetch("/api/status", {
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
    state.status = body;
    state.lastError = null;
    setConnection("Connected", "good");
  } catch (error) {
    state.lastError = error instanceof Error ? error.message : "Refresh failed";
    setConnection("Error", "bad");
  }
  render();
}

function render() {
  const status = state.status;
  renderMetrics(status);
  renderSummary(status);
  renderDetails(status);
  renderFindings(status?.findings || []);
  nodes.lastRefresh.textContent = state.lastError
    ? state.lastError
    : status
      ? `Updated ${formatNow()}`
      : "Never refreshed";
}

function renderSummary(status) {
  const restore = status?.restore || {};
  const backend = status?.backend || {};
  const anchor = status?.anchor || {};
  const findings = status?.findings || [];
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
      kind = findings.length === 0 ? "good" : "warn";
      primary = `Restore trust is verified at checkpoint ${restore.checkpoint?.sequence ?? "unknown"}.`;
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

function renderMetrics(status) {
  const restore = status?.restore || {};
  const runtime = status?.runtime || {};
  const repository = status?.repository || {};
  const checkpoint = restore.checkpoint;
  const envelope = restore.keyring_envelope;
  nodes.metrics.restore.textContent = restore.state || "unknown";
  nodes.metrics.mode.textContent = runtime.gateway_mode || "unknown";
  nodes.metrics.checkpoint.textContent = checkpoint
    ? `seq ${checkpoint.sequence}`
    : "none";
  nodes.metrics.envelope.textContent = envelope
    ? `gen ${envelope.generation}`
    : "none";
  nodes.metrics.retention.textContent =
    repository.retention_mode && repository.retention_mode !== "none"
      ? `${repository.retention_mode} ${repository.retention_days}d`
      : repository.retention_mode || "unknown";
  nodes.metrics.findings.textContent = String((status?.findings || []).length);

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
    ["Path browsing", enabledDisabled(security.path_browsing_enabled)],
    ["Secrets exposed", yesNo(security.secrets_exposed)],
    ["Action posture", security.action_posture || "unknown"],
    ["Batch max items", repository.commit_max_batch_items ?? "unknown"],
    ["Batch delay", millis(repository.commit_max_batch_delay_ms)],
    ["Pending limit", repository.commit_max_pending_items ?? "unknown"],
  ]);
}

function renderFindings(findings) {
  clear(nodes.findingsTable);
  if (findings.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No findings";
    nodes.findingsTable.append(empty);
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
  findings.forEach((finding) => {
    const row = document.createElement("tr");
    [finding.severity, finding.code, finding.message].forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value || "unknown";
      row.append(td);
    });
    tbody.append(row);
  });
  table.append(thead, tbody);
  nodes.findingsTable.append(table);
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

function enabledDisabled(value) {
  if (value === true) {
    return "enabled";
  }
  if (value === false) {
    return "disabled";
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

function formatTimestamp(value) {
  if (typeof value !== "number" || value <= 0) {
    return "none";
  }
  return new Date(value).toLocaleString();
}

function formatNow() {
  return new Date().toLocaleTimeString();
}

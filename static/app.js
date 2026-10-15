const PATH_QUERY = `MATCH path = (source:Principal {id: 'internet'})-[:CAN_ACCESS*1..8]->(asset:DataAsset {classification: 'restricted'})
WHERE all(access IN relationships(path) WHERE access.active = true)
RETURN [node IN nodes(path) | {id: node.id, name: node.name, kind: node.kind}] AS path_nodes,
       [access IN relationships(path) | {id: access.id, mechanism: access.mechanism, evidence: access.evidence}] AS path_edges,
       length(path) AS hops
ORDER BY hops ASC
LIMIT 50`;

const els = {
  statusDot: document.querySelector("#sidebar-status-dot"),
  status: document.querySelector("#sidebar-status"),
  nodeCount: document.querySelector("#node-count"),
  edgeCount: document.querySelector("#edge-count"),
  question: document.querySelector("#question-input"),
  analyze: document.querySelector("#analyze-button"),
  reset: document.querySelector("#reset-button"),
  refresh: document.querySelector("#refresh-button"),
  risk: document.querySelector("#risk-value"),
  riskIcon: document.querySelector("#risk-icon"),
  riskCaption: document.querySelector("#risk-caption"),
  pathCount: document.querySelector("#path-count"),
  pathBadge: document.querySelector("#path-badge"),
  summary: document.querySelector("#summary-text"),
  paths: document.querySelector("#paths-container"),
  fixes: document.querySelector("#fixes-container"),
  fixCount: document.querySelector("#fix-count"),
  evidence: document.querySelector("#evidence-list"),
  graphName: document.querySelector("#graph-name"),
  updated: document.querySelector("#last-updated"),
  offline: document.querySelector("#offline-banner"),
  toast: document.querySelector("#toast"),
  dialog: document.querySelector("#query-dialog"),
};

let toastTimer;
let busy = false;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[char]));
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
  return body;
}

function showToast(message, isError = false) {
  els.toast.textContent = message;
  els.toast.style.borderColor = isError ? "#73433f" : "#315349";
  els.toast.style.background = isError ? "#2a1a1c" : "#10241f";
  els.toast.style.color = isError ? "#ffaaa0" : "#b5eed5";
  els.toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => els.toast.classList.remove("show"), 3000);
}

function setBusy(value) {
  busy = value;
  els.analyze.disabled = value;
  els.analyze.querySelector("span:first-child").textContent = value ? "Querying graph…" : "Analyze paths";
}

function updateStatus(connected, data = {}) {
  els.statusDot.className = `status-dot ${connected ? "connected" : "disconnected"}`;
  els.status.textContent = connected ? "FalkorDB connected" : "FalkorDB offline";
  els.nodeCount.textContent = connected ? `${data.nodes ?? "—"} nodes` : "— nodes";
  els.edgeCount.textContent = connected ? `${data.relationships ?? "—"} edges` : "— edges";
  els.offline.classList.toggle("hidden", connected);
}

function nodeTone(kind = "") {
  const value = kind.toLowerCase();
  if (value.includes("external") || value.includes("internet")) return "node-external";
  if (value.includes("identity")) return "node-identity";
  if (value.includes("data") || value.includes("secret")) return "node-sensitive";
  return "";
}

function nodeGlyph(kind = "") {
  const value = kind.toLowerCase();
  if (value.includes("external")) return "◎";
  if (value.includes("endpoint")) return "↗";
  if (value.includes("workload")) return "▣";
  if (value.includes("identity")) return "♙";
  if (value.includes("secret")) return "◇";
  if (value.includes("data")) return "◈";
  return "●";
}

function renderPaths(paths) {
  if (!paths.length) {
    els.paths.innerHTML = `<div class="empty-state"><span class="safe-icon">✓</span>No active path reaches restricted data in the current graph state.</div>`;
    return;
  }
  els.paths.innerHTML = paths.map((path, index) => {
    const nodes = path.nodes || [];
    const edges = path.edges || [];
    const flow = nodes.map((node, i) => {
      const nodeHtml = `<div class="path-node ${nodeTone(node.kind)}"><span class="path-node-icon">${nodeGlyph(node.kind)}</span><span class="path-node-copy"><strong title="${escapeHtml(node.name)}">${escapeHtml(node.name)}</strong><small>${escapeHtml(node.kind)}</small></span></div>`;
      if (i >= edges.length) return nodeHtml;
      const edge = edges[i];
      return `${nodeHtml}<div class="path-edge" title="${escapeHtml(edge.evidence)}">›<span>${escapeHtml(edge.mechanism)}</span></div>`;
    }).join("");
    const evidence = edges.map((edge) => edge.evidence).filter(Boolean);
    return `<article class="path-card"><div class="path-card-header"><span><b>ROUTE ${String(index + 1).padStart(2, "0")}</b> · ${nodes.length} NODES</span><span>${path.hops} HOPS</span></div><div class="path-flow">${flow}</div><div class="path-evidence">Evidence: <b>${escapeHtml([...new Set(evidence)].join(" · "))}</b></div></article>`;
  }).join("");
}

function renderFixes(fixes) {
  els.fixCount.textContent = String(fixes.length).padStart(2, "0");
  if (!fixes.length) {
    els.fixes.innerHTML = `<div class="fix-empty">No active route remains in the modeled graph. Reset the scenario to replay the investigation.</div>`;
    return;
  }
  els.fixes.innerHTML = fixes.map((fix) => `<article class="fix-card">
    <div class="fix-card-title">${escapeHtml(fix.title)}</div>
    <div class="fix-card-target">${escapeHtml(fix.target)}</div>
    <div class="fix-card-detail">${escapeHtml(fix.detail)}</div>
    <button class="button" data-fix="${escapeHtml(fix.edge_id)}">Simulate fix <span>↗</span></button>
  </article>`).join("");
  els.fixes.querySelectorAll("[data-fix]").forEach((button) => {
    button.addEventListener("click", () => simulateFix(button.dataset.fix, button));
  });
}

function renderEvidence(paths) {
  const seen = new Set();
  const edges = paths.flatMap((path) => path.edges || []).filter((edge) => {
    if (seen.has(edge.id)) return false;
    seen.add(edge.id);
    return true;
  });
  if (!edges.length) {
    els.evidence.innerHTML = `<div class="evidence-empty">No active edge evidence in the current result.</div>`;
    return;
  }
  els.evidence.innerHTML = edges.slice(0, 8).map((edge) => `<div class="evidence-row"><span class="evidence-bullet"></span><span class="evidence-copy"><strong>${escapeHtml(edge.mechanism)}</strong><small>${escapeHtml(edge.evidence)} · ${escapeHtml(edge.id)}</small></span></div>`).join("");
}

function renderResult(data) {
  const count = data.path_count ?? data.paths?.length ?? 0;
  const safe = count === 0;
  updateStatus(true, data.graph || {});
  els.risk.textContent = safe ? "NO ACTIVE PATH" : "CRITICAL EXPOSURE";
  els.risk.classList.toggle("safe", safe);
  els.riskIcon.classList.toggle("safe", safe);
  els.riskIcon.textContent = safe ? "✓" : "!";
  els.riskCaption.textContent = safe ? "No route in modeled graph" : "Restricted data is reachable";
  els.pathCount.textContent = String(count).padStart(2, "0");
  els.pathBadge.textContent = String(count).padStart(2, "0");
  els.summary.textContent = data.summary || "Graph query completed.";
  els.graphName.textContent = `GRAPH · ${data.graph?.name || "pathguard"}`;
  els.updated.textContent = `Queried ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  renderPaths(data.paths || []);
  renderFixes(data.recommendations || []);
  renderEvidence(data.paths || []);
}

async function investigate() {
  if (busy) return;
  setBusy(true);
  els.paths.innerHTML = `<div class="empty-state"><span class="spinner"></span>Traversing FalkorDB relationships…</div>`;
  try {
    const result = await request("/api/investigate", {
      method: "POST",
      body: JSON.stringify({ question: els.question.value.trim() || "Can the public internet reach customer PII?", source_id: "internet" }),
    });
    renderResult(result);
  } catch (error) {
    updateStatus(false);
    els.paths.innerHTML = `<div class="empty-state"><span class="risk-icon">!</span>${escapeHtml(error.message)}</div>`;
    els.summary.textContent = "Analysis is blocked until the FalkorDB graph is available.";
    els.updated.textContent = "Graph query failed";
    showToast(error.message, true);
  } finally {
    setBusy(false);
  }
}

async function simulateFix(edgeId, button) {
  button.disabled = true;
  button.textContent = "Updating graph…";
  try {
    const result = await request("/api/remediate", { method: "POST", body: JSON.stringify({ edge_id: edgeId }) });
    renderResult(result);
    const remaining = result.path_count;
    showToast(remaining ? `Fix simulated. ${remaining} route remains in FalkorDB.` : "Fix simulated. No active route remains in FalkorDB.");
  } catch (error) {
    button.disabled = false;
    button.textContent = "Simulate fix ↗";
    showToast(error.message, true);
  }
}

async function resetScenario() {
  if (busy) return;
  els.reset.disabled = true;
  try {
    renderResult(await request("/api/reset", { method: "POST", body: "{}" }));
    showToast("Synthetic graph reset. Both attack paths are active again.");
  } catch (error) {
    showToast(error.message, true);
  } finally {
    els.reset.disabled = false;
  }
}

async function checkHealth() {
  try {
    const status = await request("/api/health");
    updateStatus(status.status === "connected", status);
    if (status.status === "connected") await investigate();
  } catch {
    updateStatus(false);
  }
}

document.querySelector("#view-query").addEventListener("click", () => {
  document.querySelector("#query-code").textContent = PATH_QUERY;
  els.dialog.showModal();
});
document.querySelector("#close-dialog").addEventListener("click", () => els.dialog.close());
els.dialog.addEventListener("click", (event) => {
  if (event.target === els.dialog) els.dialog.close();
});
els.analyze.addEventListener("click", investigate);
els.refresh.addEventListener("click", investigate);
els.reset.addEventListener("click", resetScenario);
els.question.addEventListener("keydown", (event) => {
  if (event.key === "Enter") investigate();
});
checkHealth();
setInterval(async () => {
  try {
    const status = await request("/api/health");
    updateStatus(status.status === "connected", status);
  } catch {
    updateStatus(false);
  }
}, 12000);

import { Fragment, useCallback, useEffect, useRef, useState } from "react";

const DEFAULT_QUESTION = "Can the public internet reach customer PII?";
const PATH_QUERY = `MATCH path = (source:Principal {id: 'internet'})-[:CAN_ACCESS*1..8]->(asset:DataAsset {classification: 'restricted'})
WHERE all(access IN relationships(path) WHERE access.active = true)
RETURN [node IN nodes(path) | {id: node.id, name: node.name, kind: node.kind}] AS path_nodes,
       [access IN relationships(path) | {id: access.id, mechanism: access.mechanism, evidence: access.evidence}] AS path_edges,
       length(path) AS hops
ORDER BY hops ASC
LIMIT 50`;

async function request(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
  return body;
}

function ServiceStep({ title, label, state }) {
  const connected = state === "connected";
  const pending = state === "checking" || state === "unknown";
  return (
    <div className={`architecture-step ${connected ? "is-connected" : "is-disconnected"}`}>
      <span className={`architecture-dot ${pending ? "is-pending" : ""}`} />
      <div><small>{title}</small><b>{label}</b></div>
    </div>
  );
}

function Sidebar({ health }) {
  return (
    <aside className="sidebar">
      <a className="brand" href="/" aria-label="Pathguard home">
        <span className="brand-mark"><span /><span /><span /><span /></span>
        <span>pathguard<span className="brand-period">.</span></span>
      </a>
      <div className="workspace-label">WORKSPACE</div>
      <div className="workspace-switch"><span className="workspace-icon">S</span><span><b>Sentinel Labs</b><small>Demo environment</small></span><span className="chevron">⌄</span></div>
      <nav className="nav-list" aria-label="Main navigation">
        <div className="nav-caption">ANALYZE</div>
        <a className="nav-item active" href="#investigation"><span className="nav-icon">⌕</span>Attack paths <span className="nav-count">{String(health.path_count ?? 2).padStart(2, "0")}</span></a>
        <a className="nav-item" href="#graph-panel"><span className="nav-icon">⌘</span>Access graph</a>
        <div className="nav-caption nav-caption-spaced">ENVIRONMENT</div>
        <a className="nav-item" href="#assets"><span className="nav-icon">▣</span>Sensitive assets <span className="tiny-dot" /></a>
        <a className="nav-item" href="#activity"><span className="nav-icon">◷</span>Activity log</a>
      </nav>
      <div className="sidebar-bottom">
        <div className="sidebar-db-card">
          <div className="db-card-title"><span className={`status-dot ${health.falkordb === "connected" ? "connected" : health.falkordb === "checking" ? "pending" : "disconnected"}`} />GRAPH STATUS</div>
          <div className="db-status">{health.falkordb === "connected" ? "FalkorDB connected" : health.falkordb === "checking" ? "Connecting to graph…" : "FalkorDB offline"}</div>
          <div className="db-meta"><span>{health.nodes ?? "—"} nodes</span><span>{health.relationships ?? "—"} edges</span></div>
          <div className="sidebar-services">
            <span>Graph API <b className={health.graph_api === "connected" ? "service-up" : "service-down"}>{health.graph_api || "checking"}</b></span>
            <span>FalkorDB <b className={health.falkordb === "connected" ? "service-up" : "service-down"}>{health.falkordb || "checking"}</b></span>
          </div>
        </div>
        <div className="profile"><div className="avatar">AR</div><div><b>Analyst</b><small>Security team</small></div><button className="more-button" aria-label="More options">···</button></div>
      </div>
    </aside>
  );
}

function PathCard({ path, index }) {
  const nodes = path.nodes || [];
  const edges = path.edges || [];
  return (
    <article className="path-card">
      <div className="path-card-header"><span><b>ROUTE {String(index + 1).padStart(2, "0")}</b> · {nodes.length} NODES</span><span>{path.hops} HOPS</span></div>
      <div className="path-flow">
        {nodes.map((node, nodeIndex) => (
          <Fragment key={`${node.id}-${nodeIndex}`}>
            <div className={`path-node ${nodeTone(node.kind)}`}>
              <span className="path-node-icon">{nodeGlyph(node.kind)}</span>
              <span className="path-node-copy"><strong title={node.name}>{node.name}</strong><small>{node.kind}</small></span>
            </div>
            {edges[nodeIndex] && <div className="path-edge" title={edges[nodeIndex].evidence}>›<span>{edges[nodeIndex].mechanism}</span></div>}
          </Fragment>
        ))}
      </div>
      <div className="path-evidence">Evidence: <b>{[...new Set(edges.map((edge) => edge.evidence).filter(Boolean))].join(" · ")}</b></div>
    </article>
  );
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

function App() {
  const [health, setHealth] = useState({ graph_api: "checking", falkordb: "checking", nodes: null, relationships: null });
  const [data, setData] = useState(null);
  const [question, setQuestion] = useState(DEFAULT_QUESTION);
  const [loading, setLoading] = useState(false);
  const [busyEdge, setBusyEdge] = useState(null);
  const [toast, setToast] = useState(null);
  const [queryOpen, setQueryOpen] = useState(false);
  const queryDialog = useRef(null);
  const hasAnalysis = useRef(false);
  const analyzeRef = useRef(null);
  const toastTimer = useRef(null);

  const showToast = useCallback((message, isError = false) => {
    setToast({ message, isError });
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 3200);
  }, []);

  const analyze = useCallback(async (query = question) => {
    if (loading) return null;
    setLoading(true);
    try {
      const result = await request("/api/investigate", {
        method: "POST",
        body: JSON.stringify({ question: query.trim() || DEFAULT_QUESTION, source_id: "internet" }),
      });
      setData(result);
      hasAnalysis.current = true;
      setHealth((current) => ({ ...current, ...result.graph, graph_api: "connected", falkordb: "connected", status: "connected" }));
      return result;
    } catch (error) {
      setData(null);
      hasAnalysis.current = false;
      setHealth((current) => ({ ...current, status: "disconnected" }));
      showToast(error.message, true);
      return null;
    } finally {
      setLoading(false);
    }
  }, [question, loading, showToast]);
  analyzeRef.current = analyze;

  useEffect(() => {
    let alive = true;
    let checking = false;
    const checkHealth = async () => {
      if (checking) return;
      checking = true;
      try {
        const status = await request("/api/health");
        if (!alive) return;
        setHealth(status);
        if (status.falkordb === "connected" && !hasAnalysis.current) {
          await analyzeRef.current?.(DEFAULT_QUESTION);
        }
        if (status.falkordb !== "connected") {
          hasAnalysis.current = false;
          setData(null);
        }
      } catch {
        if (alive) {
          setHealth({ graph_api: "disconnected", falkordb: "unknown", status: "disconnected", nodes: 0, relationships: 0 });
          hasAnalysis.current = false;
          setData(null);
        }
      } finally {
        checking = false;
      }
    };
    checkHealth();
    const timer = setInterval(checkHealth, 5000);
    return () => { alive = false; clearInterval(timer); clearTimeout(toastTimer.current); };
  }, []);

  useEffect(() => {
    if (queryOpen) queryDialog.current?.showModal();
    else if (queryDialog.current?.open) queryDialog.current.close();
  }, [queryOpen]);

  const simulateFix = async (edgeId) => {
    setBusyEdge(edgeId);
    try {
      const result = await request("/api/remediate", { method: "POST", body: JSON.stringify({ edge_id: edgeId }) });
      setData(result);
      hasAnalysis.current = true;
      setHealth((current) => ({ ...current, ...result.graph, graph_api: "connected", falkordb: "connected", status: "connected" }));
      showToast(result.path_count ? `Fix simulated. ${result.path_count} route remains in FalkorDB.` : "Fix simulated. No active route remains in FalkorDB.");
    } catch (error) {
      showToast(error.message, true);
    } finally {
      setBusyEdge(null);
    }
  };

  const resetScenario = async () => {
    setLoading(true);
    try {
      const result = await request("/api/reset", { method: "POST", body: "{}" });
      setData(result);
      hasAnalysis.current = true;
      setHealth((current) => ({ ...current, ...result.graph, graph_api: "connected", falkordb: "connected", status: "connected" }));
      showToast("Synthetic graph reset. Both attack paths are active again.");
    } catch (error) {
      showToast(error.message, true);
    } finally {
      setLoading(false);
    }
  };

  const connected = health.falkordb === "connected";
  // Never render an old response while health reports FalkorDB as unavailable.
  const visibleData = connected ? data : null;
  const paths = visibleData?.paths || [];
  const count = visibleData?.path_count ?? paths.length;
  const safe = visibleData && count === 0;

  return (
    <div className="shell">
      <Sidebar health={{ ...health, path_count: count }} />
      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumbs"><span>Sentinel Labs</span><span className="slash">/</span><b>Attack path analysis</b></div>
          <div className="topbar-actions"><div className="synthetic-label"><span className="synthetic-dot" /> SYNTHETIC ENVIRONMENT</div><button id="reset-button" className="button button-quiet" onClick={resetScenario} disabled={loading || !connected}>↺ <span>Reset scenario</span></button><div className="top-avatar">AR</div></div>
        </header>

        <section className="intro" id="investigation">
          <div className="eyebrow"><span className="eyebrow-line" />GRAPH-POWERED SECURITY ANALYSIS</div>
          <h1>Prove what’s <em>reachable.</em></h1>
          <p className="intro-copy">Trace attack paths through identities, workloads, and secrets. Test a fix against the graph before risk reaches your data.</p>
        </section>

        <form className="query-card" aria-label="Ask Pathguard" onSubmit={(event) => { event.preventDefault(); analyze(); }}>
          <div className="query-icon">✳</div>
          <div className="query-input-wrap"><label htmlFor="question-input">INVESTIGATION</label><input id="question-input" value={question} onChange={(event) => setQuestion(event.target.value)} maxLength={240} /></div>
          <button id="analyze-button" className="button button-primary" disabled={loading || !connected}><span>{loading ? "Querying graph…" : "Analyze paths"}</span><span aria-hidden="true">↗</span></button>
          <div className="query-footer"><span className="query-hint"><kbd>↵</kbd> Press enter to investigate</span><span className="query-source">SOURCE <b>Public Internet</b><span className="source-chevron">⌄</span></span><span className="query-target">TARGET <b>Restricted data</b><span className="target-chip">1 asset</span></span></div>
        </form>

        <section className="architecture-strip" aria-label="Live service architecture">
          <ServiceStep title="CLIENT" label="React UI" state="connected" /><span className="pipeline-arrow">→</span>
          <ServiceStep title="APP SERVICE" label="Pathguard API" state="connected" /><span className="pipeline-arrow">→</span>
          <ServiceStep title="GRAPH SERVICE" label="Graph API" state={health.graph_api} /><span className="pipeline-arrow">→</span>
          <ServiceStep title="DATABASE" label="FalkorDB" state={health.falkordb} />
          <a className="graph-api-link" href="/graph-api/docs" target="_blank" rel="noreferrer">Graph API docs ↗</a>
        </section>

        <section id="result-section" className="results-section">
          <div className="section-heading">
            <div><div className="eyebrow section-eyebrow"><span className="live-indicator" />LIVE GRAPH ANALYSIS</div><h2>Reachability report</h2></div>
            <div className="result-tools"><span id="last-updated" className="updated-label">{visibleData ? `Queried ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}` : "Waiting for graph"}</span><button className="icon-button" id="refresh-button" title="Run analysis again" aria-label="Refresh" onClick={() => analyze()} disabled={loading || !connected}>↻</button></div>
          </div>

          {!connected && <div className="offline-banner"><span>!</span><div><b>FalkorDB is required for analysis.</b><small>{health.graph_api === "connected" ? "The Graph API is running, but it cannot reach FalkorDB. No cached answer is shown." : "Start the Graph API and FalkorDB services. Pathguard does not use a cached or in-memory answer."}</small></div></div>}

          <div className="summary-grid">
            <article className="summary-card risk-card"><div className="card-label">RISK STATUS <span className="help-dot">?</span></div><div className="risk-row"><span className={`risk-icon ${safe ? "safe" : ""}`}>{safe ? "✓" : connected ? "!" : "×"}</span><div><strong className={safe ? "safe" : ""}>{safe ? "NO ACTIVE PATH" : connected && visibleData ? "CRITICAL EXPOSURE" : "GRAPH OFFLINE"}</strong><small>{safe ? "No route in modeled graph" : connected && visibleData ? "Restricted data is reachable" : "Analysis requires FalkorDB"}</small></div></div></article>
            <article className="summary-card"><div className="card-label">ACTIVE ROUTES <span className="card-detail">FROM INTERNET</span></div><div className="metric-row"><strong>{visibleData ? String(count).padStart(2, "0") : "—"}</strong><span className="metric-note">FalkorDB query</span></div></article>
            <article className="summary-card"><div className="card-label">PROTECTED TARGET <span className="card-detail">DATA CLASS</span></div><div className="asset-row"><span className="asset-icon">◈</span><div><strong>Customer PII</strong><small>Restricted · payments database</small></div></div></article>
          </div>

          <div className="content-grid">
            <section className="panel graph-panel" id="graph-panel">
              <div className="panel-heading"><div><div className="panel-title">Attack paths <span className="count-badge">{visibleData ? String(count).padStart(2, "0") : "—"}</span></div><div className="panel-subtitle">Each route is returned by a bounded Cypher traversal in FalkorDB.</div></div><button id="view-query" className="text-button" onClick={() => setQueryOpen(true)}>View Cypher <span>↗</span></button></div>
              <div className="paths-container">
                {!visibleData ? <div className="empty-state">{connected ? <><span className="spinner" />Traversing FalkorDB relationships…</> : "No graph result is available."}</div> : paths.length === 0 ? <div className="empty-state"><span className="safe-icon">✓</span>No active path reaches restricted data in the current graph state.</div> : paths.map((path, index) => <PathCard key={`${index}-${path.hops}`} path={path} index={index} />)}
              </div>
              <div className="graph-legend"><span><i className="legend-node legend-external" />External</span><span><i className="legend-node legend-workload" />Workload</span><span><i className="legend-node legend-identity" />Identity</span><span><i className="legend-node legend-sensitive" />Sensitive asset</span><span className="legend-explainer">Connected paths are the evidence</span></div>
            </section>

            <aside className="panel agent-panel">
              <div className="agent-header"><div className="agent-avatar">✳</div><div><div className="agent-title">Pathguard agent <span className="agent-live">LIVE</span></div><div className="agent-subtitle">Graph-backed reasoning</div></div></div>
              <div className="agent-rule"><span className="rule-icon">⌘</span><span>Every finding is grounded in the current FalkorDB path set.</span></div>
              <div className="agent-response"><div className="response-label"><span className="response-dot" />ANALYSIS</div><p>{visibleData?.summary || (connected ? "Waiting for graph results…" : "Analysis is blocked until FalkorDB is available.")}</p></div>
              <div className="recommendations-head"><span>RECOMMENDED FIXES</span><span className="count-badge">{String(visibleData?.recommendations?.length ?? 0).padStart(2, "0")}</span></div>
              <div className="fixes-container">
                {!visibleData ? <div className="fix-empty">Recommendations appear after a graph query.</div> : visibleData.recommendations.length === 0 ? <div className="fix-empty">No active route remains in the modeled graph. Reset the scenario to replay the investigation.</div> : visibleData.recommendations.map((fix) => <article className="fix-card" key={fix.edge_id}><div className="fix-card-title">{fix.title}</div><div className="fix-card-target">{fix.target}</div><div className="fix-card-detail">{fix.detail}</div><button className="button" onClick={() => simulateFix(fix.edge_id)} disabled={Boolean(busyEdge) || !connected}>{busyEdge === fix.edge_id ? "Updating graph…" : <>Simulate fix <span>↗</span></>}</button></article>)}
              </div>
              <div className="agent-footnote">Fixes run in the synthetic graph only. No cloud permissions are changed.</div>
            </aside>
          </div>

          <section className="panel evidence-panel" id="activity">
            <div className="panel-heading"><div><div className="panel-title">Evidence trail <span className="evidence-mark">↗</span></div><div className="panel-subtitle">The relationships behind the current result.</div></div><span className="graph-name">GRAPH · {visibleData?.graph?.name || "pathguard"}</span></div>
            <div className="evidence-list">
              {paths.flatMap((path) => path.edges || []).filter((edge, index, all) => all.findIndex((candidate) => candidate.id === edge.id) === index).slice(0, 12).map((edge) => <div className="evidence-row" key={edge.id}><span className="evidence-bullet" /><span className="evidence-copy"><strong>{edge.mechanism}</strong><small>{edge.evidence} · {edge.id}</small></span></div>)}
              {visibleData && paths.length === 0 && <div className="evidence-empty">No active edge evidence in the current result.</div>}
              {!visibleData && <div className="evidence-empty">Graph evidence will appear here after a successful query.</div>}
            </div>
          </section>
          <footer className="page-footer"><span>PATHGUARD <b>0.2.0</b></span><span>Powered by <b>FalkorDB</b> · Relationships first, answers second.</span><a href="https://www.wemakedevs.org/hackathons/falkordb" target="_blank" rel="noreferrer">Graph Hacks 2026 ↗</a></footer>
        </section>
      </main>

      <dialog ref={queryDialog} className="query-dialog" onClose={() => setQueryOpen(false)}><div className="dialog-head"><div><span className="eyebrow">CORE GRAPH OPERATION</span><h3>Cypher used for reachability</h3></div><button className="icon-button" aria-label="Close" onClick={() => setQueryOpen(false)}>×</button></div><pre><code>{PATH_QUERY}</code></pre><p>This bounded variable-length traversal runs in the separate FalkorDB Graph API. The application has no direct database connection.</p></dialog>
      <div className={`toast ${toast ? "show" : ""} ${toast?.isError ? "toast-error" : ""}`} role="status">{toast?.message || ""}</div>
    </div>
  );
}

export default App;

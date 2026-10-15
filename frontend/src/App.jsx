import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";

const DEFAULT_QUESTION = "Can the public internet reach customer PII?";
const PATH_QUERY = `MATCH path = (source:Principal {id: 'internet'})-[:CAN_ACCESS*1..8]->(asset:DataAsset {classification: 'restricted'})
WHERE all(access IN relationships(path) WHERE access.active = true)
RETURN [node IN nodes(path) | {id: node.id, name: node.name, kind: node.kind}] AS path_nodes,
       [access IN relationships(path) | {id: access.id, mechanism: access.mechanism, evidence: access.evidence}] AS path_edges,
       length(path) AS hops
ORDER BY hops ASC
LIMIT 50`;

const VIEWS = [
  { id: "paths", label: "Attack paths", icon: "⌕" },
  { id: "graph", label: "Access graph", icon: "⌘" },
  { id: "assets", label: "Sensitive assets", icon: "▣" },
  { id: "activity", label: "Evidence trail", icon: "◷" },
];

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

function Sidebar({ health, pathCount, nodeCount, view, onNavigate }) {
  const counts = { paths: pathCount, graph: nodeCount, assets: null, activity: null };
  return (
    <aside className="sidebar">
      <a className="brand" href="/" aria-label="Pathguard home" onClick={(event) => { event.preventDefault(); onNavigate("paths"); }}>
        <span className="brand-mark"><span /><span /><span /><span /></span>
        <span>pathguard<span className="brand-period">.</span></span>
      </a>
      <div className="workspace-label">WORKSPACE</div>
      <div className="workspace-switch"><span className="workspace-icon">S</span><span><b>Sentinel Labs</b><small>Demo environment</small></span><span className="chevron">⌄</span></div>
      <nav className="nav-list" aria-label="Main navigation">
        <div className="nav-caption">INVESTIGATE</div>
        {VIEWS.map((item, index) => (
          <Fragment key={item.id}>
            {index === 2 && <div className="nav-caption nav-caption-spaced">ENVIRONMENT</div>}
            <button type="button" className={`nav-item ${view === item.id ? "active" : ""}`} aria-current={view === item.id ? "page" : undefined} onClick={() => onNavigate(item.id)}>
              <span className="nav-icon">{item.icon}</span><span className="nav-label">{item.label}</span>
              {counts[item.id] != null && <span className="nav-count">{String(counts[item.id]).padStart(2, "0")}</span>}
            </button>
          </Fragment>
        ))}
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

function nodeTone(kind = "") {
  const value = kind.toLowerCase();
  if (value.includes("external") || value.includes("internet")) return "node-external";
  if (value.includes("identity")) return "node-identity";
  if (value.includes("data") || value.includes("secret") || value.includes("store")) return "node-sensitive";
  if (value.includes("endpoint")) return "node-endpoint";
  return "node-workload";
}

function nodeGlyph(kind = "") {
  const value = kind.toLowerCase();
  if (value.includes("external") || value.includes("internet")) return "◎";
  if (value.includes("endpoint")) return "↗";
  if (value.includes("workload")) return "▣";
  if (value.includes("identity")) return "♙";
  if (value.includes("secret")) return "◇";
  if (value.includes("data") || value.includes("store")) return "◈";
  return "●";
}

function buildSubgraph(paths) {
  const nodes = new Map();
  const edges = new Map();
  paths.forEach((path, pathIndex) => {
    (path.nodes || []).forEach((node, depth) => {
      const current = nodes.get(node.id) || { ...node, depth, pathIndexes: new Set() };
      current.depth = Math.min(current.depth, depth);
      current.pathIndexes.add(pathIndex);
      nodes.set(node.id, current);
      const target = path.nodes?.[depth + 1];
      const edge = path.edges?.[depth];
      if (target && edge) {
        const currentEdge = edges.get(edge.id) || { ...edge, sourceId: node.id, targetId: target.id, pathIndexes: new Set() };
        currentEdge.pathIndexes.add(pathIndex);
        edges.set(edge.id, currentEdge);
      }
    });
  });

  const layers = new Map();
  [...nodes.values()].forEach((node) => {
    if (!layers.has(node.depth)) layers.set(node.depth, []);
    layers.get(node.depth).push(node);
  });
  const layerKeys = [...layers.keys()].sort((a, b) => a - b);
  const maxRows = Math.max(1, ...layerKeys.map((key) => layers.get(key).length));
  const height = Math.max(430, 90 + maxRows * 112);
  const positions = new Map();
  const maxDepth = Math.max(1, ...layerKeys);
  layerKeys.forEach((depth) => {
    const layerNodes = layers.get(depth).sort((a, b) => a.name.localeCompare(b.name));
    layerNodes.forEach((node, index) => {
      positions.set(node.id, {
        x: 26 + depth * (970 / maxDepth),
        y: (height / (layerNodes.length + 1)) * (index + 1),
      });
    });
  });
  return { nodes: [...nodes.values()], edges: [...edges.values()], positions, height, width: 1110 };
}

function GraphView({ paths, selectedNodeId, onSelectNode, selectedEdgeId, onSelectEdge }) {
  const graph = useMemo(() => buildSubgraph(paths), [paths]);
  const selectedNode = graph.nodes.find((node) => node.id === selectedNodeId);
  const selectedEdge = graph.edges.find((edge) => edge.id === selectedEdgeId);
  const selectedEdgeSource = graph.nodes.find((node) => node.id === selectedEdge?.sourceId);
  const selectedEdgeTarget = graph.nodes.find((node) => node.id === selectedEdge?.targetId);
  const handleKey = (event, callback) => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); callback(); }
  };
  return (
    <div className="graph-view-layout">
      <section className="panel graph-canvas-panel">
        <div className="panel-heading"><div><div className="panel-title">Reachability subgraph <span className="count-badge">{graph.nodes.length} NODES</span></div><div className="panel-subtitle">Every node and relationship below came from the active FalkorDB traversal.</div></div><span className="graph-name">{graph.edges.length} ACTIVE EDGES</span></div>
        {!paths.length ? <div className="graph-empty">{graph.nodes.length ? "No active attack path remains in this graph." : "The graph canvas appears when FalkorDB returns an active path."}</div> : (
          <div className="graph-scroll" role="region" aria-label="Interactive attack path graph. Scroll horizontally to see all nodes.">
            <svg className="attack-graph" viewBox={`0 0 ${graph.width} ${graph.height}`} style={{ height: graph.height }} role="img" aria-label={`${graph.nodes.length} nodes and ${graph.edges.length} active relationships across ${paths.length} attack paths`}>
              <defs><marker id="graph-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#65e3ba" /></marker></defs>
              <g className="graph-guides">{[...new Set(graph.nodes.map((node) => node.depth))].map((depth) => {
                const x = 26 + depth * (970 / Math.max(1, ...graph.nodes.map((node) => node.depth)));
                return <line key={depth} x1={x} y1="22" x2={x} y2={graph.height - 22} />;
              })}</g>
              <g className="graph-edges">
                {graph.edges.map((edge) => {
                  const from = graph.positions.get(edge.sourceId);
                  const to = graph.positions.get(edge.targetId);
                  if (!from || !to) return null;
                  const startX = from.x + 106;
                  const endX = to.x - 4;
                  const controlX = (startX + endX) / 2;
                  const active = selectedEdgeId === edge.id;
                  return <g key={edge.id} className={`graph-edge ${active ? "is-selected" : ""}`} onClick={() => onSelectEdge(edge.id)} role="button" tabIndex="0" aria-label={`${edge.mechanism}: ${edge.evidence}`} onKeyDown={(event) => handleKey(event, () => onSelectEdge(edge.id))}>
                    <path d={`M ${startX} ${from.y} C ${controlX} ${from.y}, ${controlX} ${to.y}, ${endX} ${to.y}`} markerEnd="url(#graph-arrow)" />
                    <text x={controlX} y={(from.y + to.y) / 2 - 7} textAnchor="middle">{edge.mechanism}</text>
                    <title>{edge.evidence} · {edge.id}</title>
                  </g>;
                })}
              </g>
              <g className="graph-nodes">
                {graph.nodes.map((node) => {
                  const point = graph.positions.get(node.id);
                  const active = selectedNodeId === node.id;
                  return <g key={node.id} className={`graph-node ${nodeTone(node.kind)} ${active ? "is-selected" : ""}`} transform={`translate(${point.x}, ${point.y - 31})`} role="button" tabIndex="0" aria-pressed={active} aria-label={`${node.name}, ${node.kind}, on ${node.pathIndexes.size} attack path${node.pathIndexes.size === 1 ? "" : "s"}`} onClick={() => onSelectNode(node.id)} onKeyDown={(event) => handleKey(event, () => onSelectNode(node.id))}>
                    <rect width="106" height="62" rx="9" />
                    <text className="graph-node-glyph" x="13" y="25">{nodeGlyph(node.kind)}</text>
                    <text className="graph-node-name" x="31" y="25" textLength={Math.min(68, Math.max(20, node.name.length * 4))} lengthAdjust="spacingAndGlyphs">{node.name}</text>
                    <text className="graph-node-kind" x="12" y="46">{node.kind}</text>
                    <title>{node.name} · {node.kind}</title>
                  </g>;
                })}
              </g>
            </svg>
          </div>
        )}
        <div className="graph-legend"><span><i className="legend-node legend-external" />External</span><span><i className="legend-node legend-workload" />Workload / endpoint</span><span><i className="legend-node legend-identity" />Identity</span><span><i className="legend-node legend-sensitive" />Sensitive resource</span><span className="legend-explainer">Select a node or edge for evidence</span></div>
      </section>
      <aside className="panel graph-inspector">
        <div className="inspector-label">GRAPH INSPECTOR</div>
        {selectedNode ? <>
          <div className={`inspector-glyph ${nodeTone(selectedNode.kind)}`}>{nodeGlyph(selectedNode.kind)}</div>
          <h3>{selectedNode.name}</h3><p className="inspector-kind">{selectedNode.kind}</p>
          <div className="inspector-stat"><span>On active paths</span><b>{selectedNode.pathIndexes.size}</b></div>
          <div className="inspector-stat"><span>Node ID</span><code>{selectedNode.id}</code></div>
        </> : <div className="inspector-placeholder"><span>⌖</span><b>Select a graph node</b><small>Details will update from the current FalkorDB result.</small></div>}
        {selectedEdge ? <div className="inspector-edge">
          <div className="inspector-edge-title">SELECTED RELATIONSHIP</div>
          <div className="inspector-edge-flow"><b>{selectedEdgeSource?.name || selectedEdge.sourceId}</b><i>{selectedEdge.mechanism}</i><b>{selectedEdgeTarget?.name || selectedEdge.targetId}</b></div>
          <p>{selectedEdge.evidence || "No evidence text returned for this relationship."}</p>
          <div className="inspector-stat"><span>Relationship ID</span><code>{selectedEdge.id}</code></div>
          <div className="inspector-stat"><span>On active paths</span><b>{selectedEdge.pathIndexes.size}</b></div>
        </div> : <div className="inspector-hint">Select a relationship to see its mechanism, evidence, and active path count.</div>}
      </aside>
    </div>
  );
}

function PathCard({ path, index, onOpenGraph }) {
  const nodes = path.nodes || [];
  const edges = path.edges || [];
  return (
    <article className="path-card">
      <button type="button" className="path-card-open" onClick={() => onOpenGraph(nodes[0]?.id)} aria-label={`Inspect route ${index + 1} in access graph`}>
        <span className="path-card-header"><span><b>ROUTE {String(index + 1).padStart(2, "0")}</b> · {nodes.length} NODES</span><span>{path.hops} HOPS <i>↗</i></span></span>
        <span className="path-flow">
          {nodes.map((node, nodeIndex) => <Fragment key={`${node.id}-${nodeIndex}`}>
            <span className={`path-node ${nodeTone(node.kind)}`}><span className="path-node-icon">{nodeGlyph(node.kind)}</span><span className="path-node-copy"><strong title={node.name}>{node.name}</strong><small>{node.kind}</small></span></span>
            {edges[nodeIndex] && <span className="path-edge" title={edges[nodeIndex].evidence}>›<span>{edges[nodeIndex].mechanism}</span></span>}
          </Fragment>)}
        </span>
      </button>
      <div className="path-evidence">Evidence: <b>{[...new Set(edges.map((edge) => edge.evidence).filter(Boolean))].join(" · ")}</b></div>
    </article>
  );
}

function ViewHeading({ eyebrow, title, detail, updatedAt, onRefresh, loading, connected, action }) {
  return <div className="section-heading view-heading">
    <div><div className="eyebrow section-eyebrow"><span className="live-indicator" />{eyebrow}</div><h2>{title}</h2>{detail && <p className="view-detail">{detail}</p>}</div>
    <div className="result-tools"><span className="updated-label">{updatedAt ? `Updated ${updatedAt}` : connected ? "Awaiting graph query" : "Waiting for graph"}</span>{action}{onRefresh && <button className="icon-button" title="Run analysis again" aria-label="Refresh graph analysis" onClick={onRefresh} disabled={loading || !connected}>↻</button>}</div>
  </div>;
}

function SummaryCards({ paths, visibleData, health, nodeCount, edgeCount }) {
  const safe = Boolean(visibleData) && paths.length === 0;
  const uniqueAssetCount = new Set(paths.flatMap((path) => path.nodes || []).filter((node) => /secret|data|store|database/i.test(node.kind)).map((node) => node.id)).size;
  return <div className="summary-grid">
    <article className="summary-card risk-card"><div className="card-label">GRAPH ASSESSMENT <span className="help-dot" title="Based only on the active FalkorDB paths">?</span></div><div className="risk-row"><span className={`risk-icon ${safe ? "safe" : ""}`}>{safe ? "✓" : health.falkordb === "connected" ? "!" : "×"}</span><div><strong className={safe ? "safe" : ""}>{safe ? "NO ACTIVE PATH" : visibleData ? "EXPOSURE FOUND" : "GRAPH OFFLINE"}</strong><small>{safe ? "No active modeled route to restricted data" : visibleData ? "Internet can reach restricted data" : "FalkorDB is required for analysis"}</small></div></div></article>
    <article className="summary-card"><div className="card-label">ACTIVE ROUTES <span className="card-detail">FALKORDB RESULT</span></div><div className="metric-row"><strong>{visibleData ? String(paths.length).padStart(2, "0") : "—"}</strong><span className="metric-note">across graph</span></div></article>
    <article className="summary-card"><div className="card-label">PATH SUBGRAPH <span className="card-detail">LIVE RESULT</span></div><div className="metric-row"><strong>{visibleData ? nodeCount : "—"}</strong><span className="metric-note">nodes · {visibleData ? edgeCount : "—"} edges · {visibleData ? uniqueAssetCount : "—"} resources</span></div></article>
  </div>;
}

function EmptyGraphState({ connected, loading, zeroResults = false }) {
  if (loading) return <div className="empty-state"><span className="spinner" />Traversing FalkorDB relationships…</div>;
  if (!connected) return <div className="empty-state">No graph result is available. FalkorDB is required for this view.</div>;
  if (zeroResults) return <div className="empty-state"><span className="safe-icon">✓</span>No active path reaches restricted data in the current graph state.</div>;
  return <div className="empty-state">Run an investigation to load the current FalkorDB graph result.</div>;
}

function App() {
  const [health, setHealth] = useState({ graph_api: "checking", falkordb: "checking", nodes: null, relationships: null });
  const [data, setData] = useState(null);
  const [question, setQuestion] = useState(DEFAULT_QUESTION);
  const [loading, setLoading] = useState(false);
  const [busyEdge, setBusyEdge] = useState(null);
  const [toast, setToast] = useState(null);
  const [queryOpen, setQueryOpen] = useState(false);
  const [view, setView] = useState("paths");
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState(null);
  const [evidenceFilter, setEvidenceFilter] = useState("");
  const [updatedAt, setUpdatedAt] = useState(null);
  const queryDialog = useRef(null);
  const hasAnalysis = useRef(false);
  const analyzeRef = useRef(null);
  const toastTimer = useRef(null);

  const showToast = useCallback((message, isError = false) => {
    setToast({ message, isError });
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 3200);
  }, []);

  const acceptGraphResult = (result) => {
    setData(result);
    hasAnalysis.current = true;
    setUpdatedAt(new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }));
    setHealth((current) => ({ ...current, ...result.graph, graph_api: "connected", falkordb: "connected", status: "connected" }));
    setSelectedNodeId(null);
    setSelectedEdgeId(null);
  };

  const analyze = useCallback(async (query = question) => {
    if (loading) return null;
    setLoading(true);
    try {
      const result = await request("/api/investigate", {
        method: "POST",
        body: JSON.stringify({ question: query.trim() || DEFAULT_QUESTION, source_id: "internet" }),
      });
      acceptGraphResult(result);
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
        if (status.falkordb === "connected" && !hasAnalysis.current) await analyzeRef.current?.(DEFAULT_QUESTION);
        if (status.falkordb !== "connected") {
          hasAnalysis.current = false;
          setData(null);
          setUpdatedAt(null);
        }
      } catch {
        if (alive) {
          setHealth({ graph_api: "disconnected", falkordb: "unknown", status: "disconnected", nodes: 0, relationships: 0 });
          hasAnalysis.current = false;
          setData(null);
          setUpdatedAt(null);
        }
      } finally { checking = false; }
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
      acceptGraphResult(result);
      showToast(result.path_count ? `Fix simulated. ${result.path_count} route remains in FalkorDB.` : "Fix simulated. No active route remains in FalkorDB.");
    } catch (error) { showToast(error.message, true); }
    finally { setBusyEdge(null); }
  };

  const resetScenario = async () => {
    setLoading(true);
    try {
      const result = await request("/api/reset", { method: "POST", body: "{}" });
      acceptGraphResult(result);
      showToast("Synthetic graph reset. Both attack paths are active again.");
    } catch (error) { showToast(error.message, true); }
    finally { setLoading(false); }
  };

  const connected = health.falkordb === "connected";
  // Do not render a previous graph response after health reports FalkorDB as unavailable.
  const visibleData = connected ? data : null;
  const paths = visibleData?.paths || [];
  const graph = useMemo(() => buildSubgraph(paths), [paths]);
  const assets = useMemo(() => graph.nodes.filter((node) => /secret|data|store|database/i.test(node.kind)), [graph.nodes]);
  const evidence = useMemo(() => graph.edges.map((edge) => ({
    ...edge,
    source: graph.nodes.find((node) => node.id === edge.sourceId),
    target: graph.nodes.find((node) => node.id === edge.targetId),
  })), [graph.edges, graph.nodes]);
  const filteredEvidence = evidence.filter((edge) => `${edge.mechanism} ${edge.evidence} ${edge.source?.name} ${edge.target?.name} ${edge.id}`.toLowerCase().includes(evidenceFilter.toLowerCase()));
  const viewTitle = VIEWS.find((item) => item.id === view)?.label || "Attack paths";

  const openGraph = (nodeId) => { setSelectedNodeId(nodeId || null); setView("graph"); };
  const pickEvidence = (edge) => { setSelectedEdgeId(edge.id); setSelectedNodeId(edge.targetId); setView("graph"); };

  return (
    <div className="shell">
      <Sidebar health={health} pathCount={visibleData ? paths.length : 0} nodeCount={visibleData ? graph.nodes.length : 0} view={view} onNavigate={setView} />
      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumbs"><span>Sentinel Labs</span><span className="slash">/</span><b>{viewTitle}</b></div>
          <div className="topbar-actions"><div className="synthetic-label"><span className="synthetic-dot" /> SYNTHETIC ENVIRONMENT</div><button id="reset-button" className="button button-quiet" onClick={resetScenario} disabled={loading || !connected}>↺ <span>Reset scenario</span></button><div className="top-avatar">AR</div></div>
        </header>

        <section className="intro" id="investigation">
          <div className="eyebrow"><span className="eyebrow-line" />FALKORDB-POWERED SECURITY ANALYSIS</div>
          <h1>Prove what’s <em>reachable.</em></h1>
          <p className="intro-copy">Trace real modeled relationships from an internet principal to sensitive data. Change the graph, then see which routes remain.</p>
        </section>

        <form className="query-card" aria-label="Ask Pathguard" onSubmit={(event) => { event.preventDefault(); analyze(); }}>
          <div className="query-icon">✳</div>
          <div className="query-input-wrap"><label htmlFor="question-input">INVESTIGATION QUESTION</label><input id="question-input" value={question} onChange={(event) => setQuestion(event.target.value)} maxLength={240} /></div>
          <button id="analyze-button" className="button button-primary" disabled={loading || !connected}><span>{loading ? "Querying graph…" : "Analyze paths"}</span><span aria-hidden="true">↗</span></button>
          <div className="query-footer"><span className="query-hint"><kbd>↵</kbd> Press enter to investigate</span><span className="query-source">SOURCE <b>Public Internet</b><span className="source-chevron">⌄</span></span><span className="query-target">TARGET <b>Restricted data</b><span className="target-chip">FalkorDB traversal</span></span></div>
        </form>

        <section className="architecture-strip" aria-label="Live service architecture">
          <ServiceStep title="CLIENT" label="React UI" state="connected" /><span className="pipeline-arrow">→</span>
          <ServiceStep title="APP SERVICE" label="Pathguard API" state="connected" /><span className="pipeline-arrow">→</span>
          <ServiceStep title="GRAPH SERVICE" label="Graph API" state={health.graph_api} /><span className="pipeline-arrow">→</span>
          <ServiceStep title="DATABASE" label="FalkorDB" state={health.falkordb} />
          <a className="graph-api-link" href="/graph-api/docs" target="_blank" rel="noreferrer">Graph API docs ↗</a>
        </section>

        <section className="results-section" aria-live="polite">
          {!connected && <div className="offline-banner"><span>!</span><div><b>FalkorDB is required for analysis.</b><small>{health.graph_api === "connected" ? "The Graph API is running, but it cannot reach FalkorDB. No cached answer is shown." : "Pathguard does not use a cached or in-memory graph answer."}</small></div></div>}

          {view === "paths" && <>
            <ViewHeading eyebrow="LIVE GRAPH ANALYSIS" title="Attack paths to restricted data" detail="Each route is returned by a bounded variable-length Cypher traversal in FalkorDB." updatedAt={updatedAt} onRefresh={() => analyze()} loading={loading} connected={connected} action={<button id="view-query" className="text-button" onClick={() => setQueryOpen(true)}>View Cypher ↗</button>} />
            <SummaryCards paths={paths} visibleData={visibleData} health={health} nodeCount={graph.nodes.length} edgeCount={graph.edges.length} />
            <div className="content-grid">
              <section className="panel graph-panel">
                <div className="panel-heading"><div><div className="panel-title">Active routes <span className="count-badge">{visibleData ? String(paths.length).padStart(2, "0") : "—"}</span></div><div className="panel-subtitle">Select a route to inspect its full subgraph.</div></div><button className="text-button" onClick={() => setView("graph")}>Open graph ↗</button></div>
                <div className="paths-container">{!visibleData || paths.length === 0 ? <EmptyGraphState connected={connected} loading={loading} zeroResults={Boolean(visibleData)} /> : paths.map((path, index) => <PathCard key={`${path.nodes?.[0]?.id}-${index}-${path.hops}`} path={path} index={index} onOpenGraph={openGraph} />)}</div>
              </section>
              <aside className="panel agent-panel">
                <div className="agent-header"><div className="agent-avatar">✳</div><div><div className="agent-title">Graph-backed analysis <span className="agent-live">LIVE</span></div><div className="agent-subtitle">Grounded in the current path set</div></div></div>
                <div className="agent-rule"><span className="rule-icon">⌘</span><span>Every finding is calculated from FalkorDB relationships. Removing the database blocks this view.</span></div>
                <div className="agent-response"><div className="response-label"><span className="response-dot" />ANALYSIS</div><p>{visibleData?.summary || (connected ? "Waiting for graph results…" : "Analysis is blocked until FalkorDB is available.")}</p></div>
                <div className="recommendations-head"><span>RECOMMENDED FIXES</span><span className="count-badge">{String(visibleData?.recommendations?.length ?? 0).padStart(2, "0")}</span></div>
                <div className="fixes-container">{!visibleData ? <div className="fix-empty">Recommendations appear after a graph query.</div> : visibleData.recommendations.length === 0 ? <div className="fix-empty">No active route remains. Reset the scenario to replay the investigation.</div> : visibleData.recommendations.map((fix) => <article className="fix-card" key={fix.edge_id}><div className="fix-card-title">{fix.title}</div><div className="fix-card-target">{fix.target}</div><div className="fix-card-detail">{fix.detail}</div><button className="button" onClick={() => simulateFix(fix.edge_id)} disabled={Boolean(busyEdge) || !connected}>{busyEdge === fix.edge_id ? "Updating graph…" : <>Simulate fix <span>↗</span></>}</button></article>)}</div>
                <div className="agent-footnote">Fixes run in the synthetic graph only. No cloud permissions are changed.</div>
              </aside>
            </div>
          </>}

          {view === "graph" && <>
            <ViewHeading eyebrow="INTERACTIVE TOPOLOGY" title="Access graph" detail="Explore nodes and active relationships returned by the current FalkorDB query." updatedAt={updatedAt} onRefresh={() => analyze()} loading={loading} connected={connected} action={<button className="text-button" onClick={() => setQueryOpen(true)}>Cypher ↗</button>} />
            <SummaryCards paths={paths} visibleData={visibleData} health={health} nodeCount={graph.nodes.length} edgeCount={graph.edges.length} />
            {visibleData ? <GraphView paths={paths} selectedNodeId={selectedNodeId} onSelectNode={setSelectedNodeId} selectedEdgeId={selectedEdgeId} onSelectEdge={setSelectedEdgeId} /> : <section className="panel graph-unavailable"><EmptyGraphState connected={connected} loading={loading} />{connected && <button className="button button-primary" onClick={() => analyze()} disabled={loading}>Load graph from FalkorDB ↗</button>}</section>}
          </>}

          {view === "assets" && <>
            <ViewHeading eyebrow="REACHABLE RESOURCES" title="Sensitive assets" detail="Resources are discovered from the active attack paths, not a frontend fixture." updatedAt={updatedAt} onRefresh={() => analyze()} loading={loading} connected={connected} />
            <SummaryCards paths={paths} visibleData={visibleData} health={health} nodeCount={graph.nodes.length} edgeCount={graph.edges.length} />
            {!visibleData ? <section className="panel section-empty"><EmptyGraphState connected={connected} loading={loading} /></section> : assets.length === 0 ? <section className="panel section-empty"><div className="safe-icon">✓</div><h3>No sensitive resource is on an active path</h3><p>FalkorDB returned no secret, data store, or data asset in the current attack path set.</p></section> : <div className="asset-grid">{assets.map((asset) => {
              const incidentEdges = evidence.filter((edge) => edge.sourceId === asset.id || edge.targetId === asset.id);
              return <article className="panel resource-card" key={asset.id}>
                <div className={`resource-glyph ${nodeTone(asset.kind)}`}>{nodeGlyph(asset.kind)}</div>
                <div className="resource-overline">GRAPH RESOURCE <span className="resource-exposure">REACHABLE</span></div>
                <h3>{asset.name}</h3><p className="resource-kind">{asset.kind}</p>
                <div className="resource-meta"><span>Active paths</span><b>{asset.pathIndexes.size}</b></div>
                <div className="resource-meta"><span>Adjacent evidence</span><b>{incidentEdges.length} relationships</b></div>
                <div className="resource-connections">{incidentEdges.map((edge) => <button key={edge.id} onClick={() => pickEvidence(edge)}><span>{edge.source?.name}</span><i>→</i><span>{edge.target?.name}</span></button>)}</div>
                <button className="text-button resource-inspect" onClick={() => openGraph(asset.id)}>Inspect in graph ↗</button>
              </article>;
            })}</div>}
          </>}

          {view === "activity" && <>
            <ViewHeading eyebrow="CURRENT GRAPH EVIDENCE" title="Evidence trail" detail="Relationships and evidence strings attached to the active FalkorDB paths." updatedAt={updatedAt} onRefresh={() => analyze()} loading={loading} connected={connected} />
            <SummaryCards paths={paths} visibleData={visibleData} health={health} nodeCount={graph.nodes.length} edgeCount={graph.edges.length} />
            <section className="panel evidence-panel evidence-view">
              <div className="panel-heading"><div><div className="panel-title">Relationship evidence <span className="count-badge">{visibleData ? evidence.length : "—"}</span></div><div className="panel-subtitle">Select a relationship to focus it in the access graph.</div></div><span className="graph-name">GRAPH · {visibleData?.graph?.name || "pathguard"}</span></div>
              <label className="evidence-search"><span>⌕</span><input value={evidenceFilter} onChange={(event) => setEvidenceFilter(event.target.value)} placeholder="Filter by node, mechanism, evidence, or ID" aria-label="Filter graph evidence" /><kbd>{filteredEvidence.length} / {evidence.length}</kbd></label>
              {!visibleData ? <EmptyGraphState connected={connected} loading={loading} /> : <div className="evidence-table">{filteredEvidence.map((edge, index) => <button type="button" className={`evidence-record ${selectedEdgeId === edge.id ? "is-selected" : ""}`} key={edge.id} onClick={() => pickEvidence(edge)}>
                <span className="evidence-index">{String(index + 1).padStart(2, "0")}</span><span className="evidence-relationship"><b>{edge.source?.name}</b><i>{edge.mechanism}</i><b>{edge.target?.name}</b></span><span className="evidence-record-copy"><strong>{edge.evidence}</strong><small>{edge.id} · present on {edge.pathIndexes.size} active path{edge.pathIndexes.size === 1 ? "" : "s"}</small></span><span className="evidence-open">↗</span>
              </button>)}{filteredEvidence.length === 0 && <div className="evidence-empty">No relationships match “{evidenceFilter}”.</div>}</div>}
            </section>
          </>}

          <footer className="page-footer"><span>PATHGUARD <b>0.2.0</b></span><span>Powered by <b>FalkorDB</b> · Relationships first, answers second.</span><a href="https://www.wemakedevs.org/hackathons/falkordb" target="_blank" rel="noreferrer">Graph Hacks 2026 ↗</a></footer>
        </section>
      </main>

      <dialog ref={queryDialog} className="query-dialog" onClose={() => setQueryOpen(false)}><div className="dialog-head"><div><span className="eyebrow">CORE GRAPH OPERATION</span><h3>Cypher used for reachability</h3></div><button className="icon-button" aria-label="Close" onClick={() => setQueryOpen(false)}>×</button></div><pre><code>{PATH_QUERY}</code></pre><p>This bounded traversal runs in the separate FalkorDB Graph API. The application has no direct database connection.</p></dialog>
      <div className={`toast ${toast ? "show" : ""} ${toast?.isError ? "toast-error" : ""}`} role="status">{toast?.message || ""}</div>
    </div>
  );
}

export default App;

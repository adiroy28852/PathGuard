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
  { id: "scan", label: "Website scan", icon: "◎" },
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

function Sidebar({ health, pathCount, nodeCount, graphNodes, graphEdges, view, onNavigate, siteMode, siteHost }) {
  const counts = { paths: pathCount, graph: nodeCount, assets: null, activity: null };
  const viewLabel = (item) => item.id === "paths" && siteMode ? "Observed paths" : item.id === "assets" && siteMode ? "Discovered entities" : item.label;
  return (
    <aside className="sidebar">
      <a className="brand" href="/" aria-label="Pathguard home" onClick={(event) => { event.preventDefault(); onNavigate("paths"); }}>
        <span className="brand-mark"><span /><span /><span /><span /></span>
        <span>pathguard<span className="brand-period">.</span></span>
      </a>
      <div className="workspace-label">PROJECT</div>
      <div className="workspace-switch"><span className="workspace-icon">P</span><span><b>Pathguard</b><small>{siteMode ? siteHost : "Synthetic demo graph"}</small></span></div>
      <nav className="nav-list" aria-label="Main navigation">
        <div className="nav-caption">INVESTIGATE</div>
        {VIEWS.map((item, index) => (
          <Fragment key={item.id}>
            {index === 3 && <div className="nav-caption nav-caption-spaced">ENVIRONMENT</div>}
            <button type="button" className={`nav-item ${view === item.id ? "active" : ""}`} aria-current={view === item.id ? "page" : undefined} onClick={() => onNavigate(item.id)}>
              <span className="nav-icon">{item.icon}</span><span className="nav-label">{viewLabel(item)}</span>
              {counts[item.id] != null && <span className="nav-count">{String(counts[item.id]).padStart(2, "0")}</span>}
            </button>
          </Fragment>
        ))}
      </nav>
      <div className="sidebar-bottom">
        <div className="sidebar-db-card">
          <div className="db-card-title"><span className={`status-dot ${health.falkordb === "connected" ? "connected" : health.falkordb === "checking" ? "pending" : "disconnected"}`} />GRAPH STATUS</div>
          <div className="db-status">{health.falkordb === "connected" ? "FalkorDB connected" : health.falkordb === "checking" ? "Connecting to graph…" : "FalkorDB offline"}</div>
          <div className="db-meta"><span>{graphNodes ?? "—"} nodes</span><span>{graphEdges ?? "—"} edges</span></div>
          <div className="sidebar-services">
            <span>Graph API <b className={health.graph_api === "connected" ? "service-up" : "service-down"}>{health.graph_api || "checking"}</b></span>
            <span>FalkorDB <b className={health.falkordb === "connected" ? "service-up" : "service-down"}>{health.falkordb || "checking"}</b></span>
          </div>
        </div>
        <div className="profile"><div className="avatar">P</div><div><b>Pathguard</b><small>Local workspace</small></div></div>
      </div>
    </aside>
  );
}

function nodeTone(kind = "") {
  const value = kind.toLowerCase();
  if (value.includes("external") || value.includes("internet")) return "node-external";
  if (value.includes("interaction")) return "node-interaction";
  if (value.includes("identity")) return "node-identity";
  if (value.includes("finding") || value.includes("data") || value.includes("secret") || value.includes("store")) return "node-sensitive";
  if (value.includes("endpoint")) return "node-endpoint";
  return "node-workload";
}

function nodeGlyph(kind = "") {
  const value = kind.toLowerCase();
  if (value.includes("external") || value.includes("internet")) return "◎";
  if (value.includes("interaction")) return "↗";
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

function GraphView({ paths, selectedNodeId, onSelectNode, selectedEdgeId, onSelectEdge, siteGraph = false }) {
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
        <div className="panel-heading"><div><div className="panel-title">{siteGraph ? "Website evidence graph" : "Reachability subgraph"} <span className="count-badge">{graph.nodes.length} NODES</span></div><div className="panel-subtitle">{siteGraph ? "Every node and relationship below came from the selected scan in FalkorDB." : "Every node and relationship below came from the active FalkorDB traversal."}</div></div><span className="graph-name">{graph.edges.length} {siteGraph ? "RELATIONSHIPS" : "ACTIVE EDGES"}</span></div>
        {!paths.length ? <div className="graph-empty">{graph.nodes.length ? (siteGraph ? "No matching observations are in this scan result." : "No active attack path remains in this graph.") : "The graph canvas appears when FalkorDB returns an active path."}</div> : (
          <div className="graph-scroll" role="region" aria-label={`Interactive ${siteGraph ? "website evidence" : "attack path"} graph. Scroll horizontally to see all nodes.`}>
            <svg className="attack-graph" viewBox={`0 0 ${graph.width} ${graph.height}`} style={{ height: graph.height }} role="img" aria-label={`${graph.nodes.length} nodes and ${graph.edges.length} relationships across ${paths.length} ${siteGraph ? "evidence paths" : "attack paths"}`}>
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
                  return <g key={node.id} className={`graph-node ${nodeTone(node.kind)} ${active ? "is-selected" : ""}`} transform={`translate(${point.x}, ${point.y - 31})`} role="button" tabIndex="0" aria-pressed={active} aria-label={`${node.name}, ${node.kind}, on ${node.pathIndexes.size} ${siteGraph ? "evidence path" : "attack path"}${node.pathIndexes.size === 1 ? "" : "s"}`} onClick={() => onSelectNode(node.id)} onKeyDown={(event) => handleKey(event, () => onSelectNode(node.id))}>
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
        <div className="graph-legend">{siteGraph ? <><span><i className="legend-node legend-external" />Public origin</span><span><i className="legend-node legend-workload" />Website route</span><span><i className="legend-node legend-identity" />API / dependency</span><span><i className="legend-node legend-interaction" />Traffic signal</span><span><i className="legend-node legend-sensitive" />Finding</span></> : <><span><i className="legend-node legend-external" />External</span><span><i className="legend-node legend-workload" />Workload / endpoint</span><span><i className="legend-node legend-identity" />Identity</span><span><i className="legend-node legend-sensitive" />Sensitive resource</span></>}<span className="legend-explainer">Select a node or edge for evidence</span></div>
      </section>
      <aside className="panel graph-inspector">
        <div className="inspector-label">GRAPH INSPECTOR</div>
        {selectedNode ? <>
          <div className={`inspector-glyph ${nodeTone(selectedNode.kind)}`}>{nodeGlyph(selectedNode.kind)}</div>
          <h3>{selectedNode.name}</h3><p className="inspector-kind">{selectedNode.kind}</p>
          <div className="inspector-stat"><span>{siteGraph ? "On evidence paths" : "On active paths"}</span><b>{selectedNode.pathIndexes.size}</b></div>
          <div className="inspector-stat"><span>Node ID</span><code>{selectedNode.id}</code></div>
          {siteGraph && selectedNode.interaction_type && <>
            <div className="inspector-stat"><span>Signal type</span><b>{selectedNode.interaction_type.replaceAll("_", " ")}</b></div>
            <div className="inspector-stat"><span>Likely role</span><b>{selectedNode.role_category?.replaceAll("_", " ") || "unknown"}</b></div>
            <div className="inspector-stat"><span>Domain relation</span><b>{selectedNode.domain_relation?.replaceAll("_", " ") || "unknown"}</b></div>
            <div className="inspector-stat"><span>Confidence</span><b>{selectedNode.confidence || "low"}</b></div>
            <p className="inspector-hint">{selectedNode.classification_reason || "No role pattern matched."}{selectedNode.noise_candidate ? " Review candidate only." : ""}</p>
          </>}
        </> : <div className="inspector-placeholder"><span>⌖</span><b>Select a graph node</b><small>Details will update from the current FalkorDB result.</small></div>}
        {selectedEdge ? <div className="inspector-edge">
          <div className="inspector-edge-title">SELECTED RELATIONSHIP</div>
          <div className="inspector-edge-flow"><b>{selectedEdgeSource?.name || selectedEdge.sourceId}</b><i>{selectedEdge.mechanism}</i><b>{selectedEdgeTarget?.name || selectedEdge.targetId}</b></div>
          <p>{selectedEdge.evidence || "No evidence text returned for this relationship."}</p>
          <div className="inspector-stat"><span>Relationship ID</span><code>{selectedEdge.id}</code></div>
          <div className="inspector-stat"><span>{siteGraph ? "On evidence paths" : "On active paths"}</span><b>{selectedEdge.pathIndexes.size}</b></div>
        </div> : <div className="inspector-hint">Select a relationship to see its mechanism, evidence, and active path count.</div>}
      </aside>
    </div>
  );
}

function PathCard({ path, index, onOpenGraph, siteGraph = false }) {
  const nodes = path.nodes || [];
  const edges = path.edges || [];
  return (
    <article className="path-card">
      <button type="button" className="path-card-open" onClick={() => onOpenGraph(nodes[siteGraph ? 1 : 0]?.id)} aria-label={`Inspect route ${index + 1} in access graph`}>
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

function TrafficSignals({ paths }) {
  const [filter, setFilter] = useState("all");
  const signals = paths
    .filter((path) => path.category === "interaction" && path.nodes?.length)
    .map((path) => ({ signal: path.nodes.at(-1), page: path.nodes.at(-2), edge: path.edges?.at(-1) }));
  const visibleSignals = signals.filter(({ signal }) => {
    if (filter === "review") return signal.noise_candidate;
    if (filter === "redirects") return ["http_redirect", "script_redirect_intent", "meta_refresh_intent", "http_refresh_intent", "runtime_navigation"].includes(signal.interaction_type);
    if (filter === "popups") return ["popup_intent", "popup_navigation"].includes(signal.interaction_type);
    return true;
  });
  const filters = [["all", "All signals"], ["redirects", "Redirects"], ["popups", "Popup intent"], ["review", "Review candidates"]];
  return <section className="traffic-signals">
    <div className="traffic-filter-row" role="tablist" aria-label="Filter traffic signals">
      {filters.map(([id, label]) => <button key={id} type="button" className={filter === id ? "active" : ""} aria-selected={filter === id} onClick={() => setFilter(id)}>{label}{id === "all" ? ` (${signals.length})` : id === "review" ? ` (${signals.filter(({ signal }) => signal.noise_candidate).length})` : ""}</button>)}
    </div>
    <p className="traffic-explainer">Host and URL patterns only suggest a role. “Review candidate” is a heuristic match for ads, analytics, or tracking, not a maliciousness verdict. Popup intent is static evidence; popup navigation is observed during the short page-load browser pass. That pass blocks third-party requests, API/background calls, WebSockets, clicks, and mutating requests.</p>
    {visibleSignals.length ? <div className="traffic-card-list">{visibleSignals.map(({ signal, page, edge }) => <article className="panel traffic-card" key={signal.id}>
      <div className="traffic-card-top"><div><span className={`traffic-type traffic-type-${signal.interaction_type}`}>{signal.interaction_type?.replaceAll("_", " ") || "interaction"}</span><span className="traffic-role">{signal.role_category?.replaceAll("_", " ") || "unknown role"}</span></div><div className="traffic-badges"><span>{signal.confidence || "low"} confidence</span>{signal.noise_candidate && <span className="traffic-review">review candidate</span>}</div></div>
      <a className="traffic-url" href={signal.url} target="_blank" rel="noreferrer">{signal.url} ↗</a>
      <div className="traffic-meta"><span>HOST <b>{signal.host || "unknown"}</b></span><span>ORIGIN RELATION <b>{signal.domain_relation?.replaceAll("_", " ") || "unknown"}</b></span>{signal.status > 0 && <span>HTTP <b>{signal.status}</b></span>}{signal.redirect_scope && <span>SCOPE <b>{signal.redirect_scope.replaceAll("_", " ")}</b></span>}</div>
      <p className="traffic-evidence">{edge?.evidence || signal.evidence}</p>
      <p className="traffic-reason">{signal.classification_reason}</p>
      <small className="traffic-source">SOURCE PAGE · {page?.url || "unknown"}</small>
    </article>)}</div> : <div className="empty-state">No traffic signals match this filter in the selected FalkorDB scan.</div>}
  </section>;
}

function ViewHeading({ eyebrow, title, detail, updatedAt, onRefresh, loading, connected, action }) {
  return <div className="section-heading view-heading">
    <div><div className="eyebrow section-eyebrow"><span className="live-indicator" />{eyebrow}</div><h2>{title}</h2>{detail && <p className="view-detail">{detail}</p>}</div>
    <div className="result-tools"><span className="updated-label">{updatedAt ? `Updated ${updatedAt}` : connected ? "Awaiting graph query" : "Waiting for graph"}</span>{action}{onRefresh && <button className="icon-button" title="Run analysis again" aria-label="Refresh graph analysis" onClick={onRefresh} disabled={loading || !connected}>↻</button>}</div>
  </div>;
}

function SummaryCards({ paths, visibleData, health, nodeCount, edgeCount, siteMode = false, siteRouteCount = 0 }) {
  const safe = siteMode || (Boolean(visibleData) && paths.length === 0);
  const uniqueAssetCount = new Set(paths.flatMap((path) => path.nodes || []).filter((node) => siteMode ? !/external principal|website route/i.test(node.kind) : /secret|data|store|database/i.test(node.kind)).map((node) => node.id)).size;
  return <div className="summary-grid">
    <article className="summary-card risk-card"><div className="card-label">{siteMode ? "SCAN EVIDENCE" : "GRAPH ASSESSMENT"} <span className="help-dot" title="Based only on the active FalkorDB result">?</span></div><div className="risk-row"><span className={`risk-icon ${safe ? "safe" : ""}`}>{safe ? "✓" : health.falkordb === "connected" ? "!" : "×"}</span><div><strong className={safe ? "safe" : ""}>{siteMode ? (visibleData ? "OBSERVATIONS LOADED" : "NO SCAN SELECTED") : safe ? "NO ACTIVE PATH" : visibleData ? "EXPOSURE FOUND" : "GRAPH OFFLINE"}</strong><small>{siteMode ? `${siteRouteCount} route${siteRouteCount === 1 ? "" : "s"} saved for this target` : safe ? "No active modeled route to restricted data" : visibleData ? "Internet can reach restricted data" : "FalkorDB is required for analysis"}</small></div></div></article>
    <article className="summary-card"><div className="card-label">{siteMode ? "OBSERVED PATHS" : "ACTIVE ROUTES"} <span className="card-detail">FALKORDB RESULT</span></div><div className="metric-row"><strong>{visibleData ? String(paths.length).padStart(2, "0") : "—"}</strong><span className="metric-note">across graph</span></div></article>
    <article className="summary-card"><div className="card-label">{siteMode ? "EVIDENCE SUBGRAPH" : "PATH SUBGRAPH"} <span className="card-detail">LIVE RESULT</span></div><div className="metric-row"><strong>{visibleData ? nodeCount : "—"}</strong><span className="metric-note">nodes · {visibleData ? edgeCount : "—"} edges · {visibleData ? uniqueAssetCount : "—"} resources</span></div></article>
  </div>;
}

function EmptyGraphState({ connected, loading, zeroResults = false, siteMode = false }) {
  if (loading) return <div className="empty-state"><span className="spinner" />Traversing FalkorDB relationships…</div>;
  if (!connected) return <div className="empty-state">No graph result is available. FalkorDB is required for this view.</div>;
  if (zeroResults) return <div className="empty-state"><span className="safe-icon">✓</span>{siteMode ? "No observations match this graph question." : "No active path reaches restricted data in the current graph state."}</div>;
  return <div className="empty-state">Run an investigation to load the current FalkorDB graph result.</div>;
}

function WebsiteScanView({ connected, showToast, onScanChange }) {
  const [targetUrl, setTargetUrl] = useState("https://moviemx.netlify.app/");
  const [artifactType, setArtifactType] = useState("har");
  const [artifactContent, setArtifactContent] = useState("");
  const [artifactName, setArtifactName] = useState("");
  const [scan, setScan] = useState(null);
  const [answer, setAnswer] = useState(null);
  const [question, setQuestion] = useState("Which API endpoints did pages call?");
  const [busy, setBusy] = useState(false);
  const [questionBusy, setQuestionBusy] = useState(false);
  const [activePanel, setActivePanel] = useState("paths");
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState(null);
  const [busyFinding, setBusyFinding] = useState(null);

  useEffect(() => {
    let alive = true;
    const restoreLatest = async () => {
      try {
        const host = new URL(targetUrl).hostname;
        const history = await request(`/api/sites/history?site_host=${encodeURIComponent(host)}`);
        const latest = history.scans?.[0];
        if (!latest || !alive) return;
        const saved = await request(`/api/sites/scan?site_host=${encodeURIComponent(host)}&scan_id=${encodeURIComponent(latest.scan_id)}`);
        if (alive) { setScan(saved); onScanChange(saved); }
      } catch { /* An empty history is the normal first-visit state. */ }
    };
    restoreLatest();
    return () => { alive = false; };
  }, []);

  const runScan = async (event) => {
    event?.preventDefault();
    if (busy || !connected) return;
    setBusy(true);
    setAnswer(null);
    try {
      const payload = { target_url: targetUrl.trim() };
      if (artifactContent) Object.assign(payload, { artifact_type: artifactType, artifact_content: artifactContent });
      const result = await request("/api/sites/scan", { method: "POST", body: JSON.stringify(payload) });
      setScan(result);
      onScanChange(result);
      setSelectedNodeId(null);
      setSelectedEdgeId(null);
      setActivePanel("paths");
      showToast(`Scan saved in FalkorDB · ${result.route_count} routes, ${result.endpoint_count} API endpoints.`);
    } catch (error) { showToast(error.message, true); }
    finally { setBusy(false); }
  };

  const askQuestion = async (event) => {
    event.preventDefault();
    if (!scan || questionBusy) return;
    setQuestionBusy(true);
    try {
      const result = await request("/api/sites/question", {
        method: "POST",
        body: JSON.stringify({ site_host: scan.site_host, scan_id: scan.scan_id, question: question.trim() }),
      });
      setAnswer(result);
      setActivePanel("answer");
    } catch (error) { showToast(error.message, true); }
    finally { setQuestionBusy(false); }
  };

  const importFile = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > 2_000_000) { showToast("Evidence files must be smaller than 2 MB.", true); event.target.value = ""; return; }
    const extension = file.name.split(".").pop().toLowerCase();
    const kind = extension === "har" ? "har" : extension === "sarif" ? "sarif" : artifactType;
    try {
      setArtifactContent(await file.text());
      setArtifactName(file.name);
      setArtifactType(kind);
    } catch { showToast("Could not read that evidence file.", true); }
  };

  const loadSavedScan = async (item) => {
    setBusy(true);
    try {
      const result = await request(`/api/sites/scan?site_host=${encodeURIComponent(scan.site_host)}&scan_id=${encodeURIComponent(item.scan_id)}`);
      result.summary = `Loaded saved FalkorDB evidence for ${result.site_host}: ${result.route_count} routes, ${result.endpoint_count} API endpoints, ${result.dependency_count} loaded external resources, ${result.interaction_count || 0} traffic signals, and ${result.finding_count} findings.`;
      setTargetUrl(result.target_url);
      setScan(result);
      onScanChange(result);
      setAnswer(null);
      setActivePanel("paths");
      showToast("Saved scan snapshot loaded from FalkorDB.");
    } catch (error) { showToast(error.message, true); }
    finally { setBusy(false); }
  };

  const simulateFinding = async (findingId) => {
    setBusyFinding(findingId);
    try {
      const result = await request("/api/sites/remediate", { method: "POST", body: JSON.stringify({ site_host: scan.site_host, scan_id: scan.scan_id, finding_id: findingId }) });
      setScan((current) => {
        const next = { ...current, paths: result.paths };
        onScanChange(next);
        return next;
      });
      setAnswer(null);
      showToast("Finding dismissed in the FalkorDB what-if graph. The website was not changed.");
    } catch (error) { showToast(error.message, true); }
    finally { setBusyFinding(null); }
  };

  const currentPaths = answer?.paths || scan?.paths || [];
  return <>
    <ViewHeading eyebrow="TARGET WEBSITE DISCOVERY" title="Scan a website" detail="Create a sourced, persistent graph from public routes and imported evidence, then ask questions across its relationships." updatedAt={scan?.created_at ? new Date(scan.created_at).toLocaleTimeString() : null} loading={busy || questionBusy} connected={connected} action={scan && <button className="text-button" onClick={() => runScan()} disabled={busy || !connected}>↻ Rescan target</button>} />
    <form className="panel website-scan-form" onSubmit={runScan}>
      <div className="scan-form-copy"><div className="panel-title">TARGET <span className="count-badge">READ ONLY</span></div><div className="panel-subtitle">A static crawl is followed by a short isolated page-load browser pass. It can observe first-party popup/navigation behavior while blocking third-party requests, API calls, WebSockets, and mutations.</div></div>
      <div className="scan-input-row"><label className="scan-target-input"><span>↗</span><input type="url" required value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} placeholder="https://staging.example.com" aria-label="Target website URL" /></label><button className="button button-primary" type="submit" disabled={busy || !connected}>{busy ? <><span className="spinner" /> Discovering…</> : <>Start discovery <span>↗</span></>}</button></div>
      <div className="scan-import-row"><label className="scan-file-label"><span>Enrich with evidence</span><select value={artifactType} onChange={(event) => setArtifactType(event.target.value)} aria-label="Evidence file type"><option value="har">Browser HAR</option><option value="openapi">OpenAPI JSON</option><option value="sarif">SARIF findings</option></select></label><label className="button button-quiet scan-file-button">{artifactName ? `✓ ${artifactName}` : "Choose evidence file"}<input type="file" accept=".har,.json,.sarif,application/json" onChange={importFile} /></label>{artifactName && <button type="button" className="text-button" onClick={() => { setArtifactContent(""); setArtifactName(""); }}>Remove</button>}<span className="scan-import-hint">Optional · JSON up to 2 MB</span></div>
      <div className="scan-scope-note"><span>i</span><span>Max 12 routes · bounded page-load JS run · same-origin static GET/HEAD only · API/XHR, WebSockets, external requests, and mutations blocked · no forms submitted or controls clicked</span></div>
    </form>

    {!scan ? <section className="panel scan-placeholder"><span>◎</span><h3>Start with a website URL</h3><p>Pathguard will collect observable routes, first-party API references, external dependencies, and basic response-header evidence. FalkorDB will retain the scan as a graph.</p><div className="scan-placeholder-foot">FalkorDB connected · No target scan loaded yet</div></section> : <>
      <div className="scan-metrics">
        <article className="panel scan-metric"><small>TARGET GRAPH</small><b>{scan.site_host}</b><span>{scan.graph?.name}</span></article>
        <article className="panel scan-metric"><small>PUBLIC ROUTES</small><b>{scan.route_count}</b><span>observed in this scan</span></article>
        <article className="panel scan-metric"><small>APIS + LOADED RESOURCES</small><b>{scan.endpoint_count + scan.dependency_count}</b><span>{scan.endpoint_count} API · {scan.dependency_count} external loads</span></article>
        <article className="panel scan-metric"><small>TRAFFIC SIGNALS</small><b>{scan.interaction_count || 0}</b><span>redirects · outbound links · popup hints</span></article>
        <article className="panel scan-metric"><small>FINDINGS</small><b>{scan.finding_count}</b><span>{scan.artifact ? `Includes ${scan.artifact.type.toUpperCase()}` : "passive headers + imports"}</span></article>
      </div>
      <section className="panel scan-overview"><div><div className="panel-title">GRAPH-BACKED SCAN <span className="agent-live">FALKORDB</span></div><p>{scan.summary}</p><small>{scan.scope}</small><small className="scan-runtime-state">BEHAVIOR PASS · {(scan.browser_runtime?.status || "not recorded").toUpperCase()} · {scan.browser_runtime?.requests_seen || 0} requests observed · {scan.browser_runtime?.requests_blocked || 0} blocked</small></div><div className="scan-change"><b>{scan.changes?.baseline_scan_id ? "SCAN DIFF" : "FIRST SNAPSHOT"}</b>{scan.changes?.baseline_scan_id ? <span>Routes +{scan.changes.routes.added.length} / −{scan.changes.routes.removed.length} · APIs +{scan.changes.apis.added.length} / −{scan.changes.apis.removed.length} · signals +{scan.changes.interactions?.added.length || 0} / −{scan.changes.interactions?.removed.length || 0}</span> : <span>New scans are compared with this saved graph.</span>}</div></section>
      <form className="panel scan-question" onSubmit={askQuestion}>
        <div className="panel-heading"><div><div className="panel-title">ASK THE GRAPH</div><div className="panel-subtitle">Questions select a bounded FalkorDB traversal; the LLM only explains returned evidence.</div></div><span className="graph-name">{scan.scan_id}</span></div>
        <div className="scan-question-row"><input value={question} onChange={(event) => setQuestion(event.target.value)} maxLength={500} aria-label="Question about this website scan" placeholder="Ask what connects across this scan…" /><button className="button button-primary" disabled={questionBusy}>{questionBusy ? "Traversing…" : "Ask Pathguard ↗"}</button></div>
        <div className="scan-prompt-chips">{["Which API endpoints did pages call?", "Which external dependencies are loaded?", "Which redirects and popup hints were observed?", "What findings affect public routes?"].map((prompt) => <button type="button" key={prompt} onClick={() => setQuestion(prompt)}>{prompt}</button>)}</div>
      </form>
      {(answer || scan) && <>
        {answer && <section className="panel scan-answer"><div className="response-label"><span className="response-dot" />ANSWER FROM FALKORDB · {answer.category.toUpperCase()}</div><p>{answer.summary}</p>{answer.model_summary && <small>LLM explanation grounded in the returned graph paths</small>}</section>}
        <div className="scan-result-toolbar"><div className="scan-tabs" role="tablist" aria-label="Scan result panels">{[["paths", "Evidence paths"], ["traffic", `Traffic signals (${scan.interaction_count || 0})`], ["graph", "Graph view"], ["history", `Scan history (${scan.history?.length || 1})`]].map(([id, label]) => <button role="tab" aria-selected={activePanel === id} className={activePanel === id ? "active" : ""} key={id} onClick={() => setActivePanel(id)}>{label}</button>)}{answer && <button role="tab" aria-selected={activePanel === "answer"} className={activePanel === "answer" ? "active" : ""} onClick={() => setActivePanel("answer")}>Answer paths</button>}</div><span>{activePanel === "traffic" ? (scan.interaction_count || 0) : currentPaths.length} {activePanel === "traffic" ? "signals" : `FalkorDB path${currentPaths.length === 1 ? "" : "s"}`}</span></div>
        {activePanel === "paths" && <div className="paths-container site-paths">{(scan.paths || []).length ? scan.paths.map((path, index) => <div key={`${path.category}-${path.nodes.at(-1)?.id}-${index}`}><PathCard path={path} index={index} siteGraph onOpenGraph={(nodeId) => { setSelectedNodeId(nodeId || null); setActivePanel("graph"); }} />{path.category === "finding" && <button className="text-button site-simulate" onClick={() => simulateFinding(path.nodes.at(-1).id)} disabled={Boolean(busyFinding)}>{busyFinding === path.nodes.at(-1).id ? "Updating graph…" : "Simulate dismiss in graph ↗"}</button>}</div>) : <div className="empty-state">No evidence paths were returned for this scan.</div>}</div>}
        {activePanel === "answer" && <div className="paths-container site-paths">{answer?.paths?.length ? answer.paths.map((path, index) => <PathCard key={`${path.category}-${path.nodes.at(-1)?.id}-${index}`} path={path} index={index} siteGraph onOpenGraph={(nodeId) => { setSelectedNodeId(nodeId || null); setActivePanel("graph"); }} />) : <div className="empty-state">No paths matched that graph question. Try one of the suggested questions.</div>}</div>}
        {activePanel === "traffic" && <TrafficSignals paths={scan.paths || []} />}
        {activePanel === "graph" && <GraphView paths={scan.paths || []} selectedNodeId={selectedNodeId} onSelectNode={setSelectedNodeId} selectedEdgeId={selectedEdgeId} onSelectEdge={setSelectedEdgeId} siteGraph />}
        {activePanel === "history" && <section className="panel scan-history">{(scan.history || []).map((item) => <article key={item.scan_id}><div><b>{new Date(item.created_at).toLocaleString()}</b><small>{item.target_url}</small></div><span>{item.route_count} routes · {item.interaction_count || 0} traffic signals · {item.finding_count} findings</span><button type="button" className="text-button" onClick={() => loadSavedScan(item)} disabled={busy}>{item.scan_id === scan.scan_id ? "Current snapshot" : "Load snapshot ↗"}</button><code>{item.scan_id}</code></article>)}</section>}
      </>}
    </>}
  </>;
}

function App() {
  const [health, setHealth] = useState({ graph_api: "checking", falkordb: "checking", nodes: null, relationships: null });
  const [data, setData] = useState(null);
  const [question, setQuestion] = useState(DEFAULT_QUESTION);
  const [loading, setLoading] = useState(false);
  const [busyEdge, setBusyEdge] = useState(null);
  const [toast, setToast] = useState(null);
  const [queryOpen, setQueryOpen] = useState(false);
  const [view, setView] = useState("scan");
  const [activeSiteScan, setActiveSiteScan] = useState(null);
  const [dataMode, setDataMode] = useState("site");
  const [siteQuestion, setSiteQuestion] = useState("What API endpoints are referenced by this site?");
  const [siteQuestionResult, setSiteQuestionResult] = useState(null);
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

  const acceptSiteScan = useCallback((scan) => {
    setActiveSiteScan(scan);
    setDataMode("site");
    setSiteQuestionResult(null);
    setUpdatedAt(new Date(scan.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }));
    setSelectedNodeId(null);
    setSelectedEdgeId(null);
    if (scan.graph) setHealth((current) => ({ ...current, ...scan.graph, graph_api: "connected", falkordb: "connected", status: "connected" }));
  }, []);

  const askSiteQuestion = useCallback(async (query = siteQuestion) => {
    if (!activeSiteScan || loading) return null;
    setLoading(true);
    try {
      const result = await request("/api/sites/question", {
        method: "POST",
        body: JSON.stringify({ site_host: activeSiteScan.site_host, scan_id: activeSiteScan.scan_id, question: query.trim() || siteQuestion }),
      });
      setSiteQuestionResult(result);
      setUpdatedAt(new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }));
      setSelectedNodeId(null);
      setSelectedEdgeId(null);
      showToast(`FalkorDB found ${result.paths.length} matching evidence path${result.paths.length === 1 ? "" : "s"}.`);
      return result;
    } catch (error) {
      showToast(error.message, true);
      return null;
    } finally { setLoading(false); }
  }, [activeSiteScan, loading, siteQuestion, showToast]);

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
  const siteMode = Boolean(activeSiteScan) && dataMode === "site";
  // Do not render a previous graph response after health reports FalkorDB as unavailable.
  const visibleData = connected ? (siteMode ? activeSiteScan : data) : null;
  const paths = siteMode ? (siteQuestionResult?.paths || activeSiteScan?.paths || []) : (visibleData?.paths || []);
  const graph = useMemo(() => buildSubgraph(paths), [paths]);
  const assets = useMemo(() => siteMode
    ? graph.nodes.filter((node) => !/external principal|website route/i.test(node.kind))
    : graph.nodes.filter((node) => /secret|data|store|database/i.test(node.kind)), [graph.nodes, siteMode]);
  const evidence = useMemo(() => graph.edges.map((edge) => ({
    ...edge,
    source: graph.nodes.find((node) => node.id === edge.sourceId),
    target: graph.nodes.find((node) => node.id === edge.targetId),
  })), [graph.edges, graph.nodes]);
  const filteredEvidence = evidence.filter((edge) => `${edge.mechanism} ${edge.evidence} ${edge.source?.name} ${edge.target?.name} ${edge.id}`.toLowerCase().includes(evidenceFilter.toLowerCase()));
  const activeView = VIEWS.find((item) => item.id === view);
  const viewTitle = activeView ? (activeView.id === "paths" && siteMode ? "Observed paths" : activeView.id === "assets" && siteMode ? "Discovered entities" : activeView.label) : "Observed paths";

  const openGraph = (nodeId) => { setSelectedNodeId(nodeId || null); setView("graph"); };
  const pickEvidence = (edge) => { setSelectedEdgeId(edge.id); setSelectedNodeId(edge.targetId); setView("graph"); };
  const refreshGraph = () => siteMode ? askSiteQuestion() : analyze();

  return (
    <div className="shell">
      <Sidebar health={health} pathCount={visibleData ? paths.length : 0} nodeCount={visibleData ? graph.nodes.length : 0} graphNodes={siteMode ? activeSiteScan?.graph?.nodes : health.nodes} graphEdges={siteMode ? activeSiteScan?.graph?.relationships : health.relationships} view={view} onNavigate={setView} siteMode={siteMode} siteHost={activeSiteScan?.site_host} />
      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumbs"><span>Pathguard</span>{siteMode && <><span className="slash">/</span><span>{activeSiteScan.site_host}</span></>}<span className="slash">/</span><b>{viewTitle}</b></div>
          <div className="topbar-actions"><div className={`synthetic-label ${siteMode ? "site-source-label" : ""}`}><span className="synthetic-dot" /> {siteMode ? `SITE GRAPH · ${activeSiteScan.site_host}` : "SYNTHETIC DEMO GRAPH"}</div>{activeSiteScan && <button className="button button-quiet" onClick={() => { setDataMode(siteMode ? "synthetic" : "site"); setSiteQuestionResult(null); }} disabled={!connected}>{siteMode ? "Open synthetic demo" : "Use site graph"}</button>}{!siteMode && view !== "scan" && <button id="reset-button" className="button button-quiet" onClick={resetScenario} disabled={loading || !connected}>↺ <span>Reset demo</span></button>}</div>
        </header>

        <section className="intro" id="investigation">
          <div className="eyebrow"><span className="eyebrow-line" />{siteMode ? "TARGET-SPECIFIC FALKORDB GRAPH" : "SYNTHETIC FALKORDB DEMO"}</div>
          <h1>{siteMode ? <>Explore the site’s <em>observed graph.</em></> : <>Prove what’s <em>reachable.</em></>}</h1>
          <p className="intro-copy">{siteMode ? "Every route, API reference, loaded resource, traffic signal, and evidence path below belongs to the selected website scan. Observations do not prove exploitability." : "This sample models public access through payment and deployment services to restricted data. Switch to Website scan to investigate a real target."}</p>
        </section>

        {view !== "scan" && <form className="query-card" aria-label="Ask Pathguard" onSubmit={(event) => { event.preventDefault(); siteMode ? askSiteQuestion(siteQuestion) : analyze(); }}>
          <div className="query-icon">✳</div>
          <div className="query-input-wrap"><label htmlFor="question-input">{siteMode ? "ASK ABOUT THIS WEBSITE" : "SYNTHETIC DEMO QUESTION"}</label><input id="question-input" value={siteMode ? siteQuestion : question} onChange={(event) => siteMode ? setSiteQuestion(event.target.value) : setQuestion(event.target.value)} maxLength={siteMode ? 500 : 240} /></div>
          <button id="analyze-button" className="button button-primary" disabled={loading || !connected || (siteMode && !activeSiteScan)}><span>{loading ? "Querying graph…" : siteMode ? "Ask Pathguard" : "Analyze paths"}</span><span aria-hidden="true">↗</span></button>
          <div className="query-footer"><span className="query-hint"><kbd>↵</kbd> {siteMode ? "Search this saved scan" : "Investigate the sample graph"}</span><span className="query-source">SOURCE <b>{siteMode ? activeSiteScan.site_host : "Public Internet"}</b></span><span className="query-target">TARGET <b>{siteMode ? "Observed evidence" : "Restricted data"}</b><span className="target-chip">FalkorDB traversal</span></span></div>
        </form>}
        {siteMode && siteQuestionResult && view !== "scan" && <section className="panel site-query-result"><div className="response-label"><span className="response-dot" />PATHGUARD ANSWER · FALKORDB {siteQuestionResult.category.toUpperCase()}</div><p>{siteQuestionResult.summary}</p><small>Snapshot {siteQuestionResult.scan_id}</small></section>}

        <section className="architecture-strip" aria-label="Live service architecture">
          <ServiceStep title="CLIENT" label="React UI" state="connected" /><span className="pipeline-arrow">→</span>
          <ServiceStep title="APP SERVICE" label="Pathguard API" state="connected" /><span className="pipeline-arrow">→</span>
          <ServiceStep title="GRAPH SERVICE" label="Graph API" state={health.graph_api} /><span className="pipeline-arrow">→</span>
          <ServiceStep title="DATABASE" label="FalkorDB" state={health.falkordb} />
          <a className="graph-api-link" href="/graph-api/docs" target="_blank" rel="noreferrer">Graph API docs ↗</a>
        </section>

        <section className="results-section" aria-live="polite">
          {!connected && <div className="offline-banner"><span>!</span><div><b>FalkorDB is required for analysis.</b><small>{health.graph_api === "connected" ? "The Graph API is running, but it cannot reach FalkorDB. No cached answer is shown." : "Pathguard does not use a cached or in-memory graph answer."}</small></div></div>}

          <div className={view === "scan" ? "" : "hidden"}><WebsiteScanView connected={connected} showToast={showToast} onScanChange={acceptSiteScan} /></div>

          {view === "paths" && <>
            <ViewHeading eyebrow={siteMode ? "SCANNED WEBSITE GRAPH" : "SYNTHETIC DEMO GRAPH"} title={siteMode ? "Observed website paths" : "Attack paths to restricted data"} detail={siteMode ? "Routes connect the public origin to APIs, external dependencies, or imported findings observed in this saved scan." : "Each route is returned by a bounded variable-length Cypher traversal in FalkorDB."} updatedAt={updatedAt} onRefresh={refreshGraph} loading={loading} connected={connected} action={siteMode ? <button className="text-button" onClick={() => setView("scan")}>Open scan details ↗</button> : <button id="view-query" className="text-button" onClick={() => setQueryOpen(true)}>View Cypher ↗</button>} />
            <SummaryCards paths={paths} visibleData={visibleData} health={health} nodeCount={graph.nodes.length} edgeCount={graph.edges.length} siteMode={siteMode} siteRouteCount={activeSiteScan?.route_count} />
            <div className="content-grid">
              <section className="panel graph-panel">
                <div className="panel-heading"><div><div className="panel-title">{siteMode ? "Observed evidence paths" : "Active routes"} <span className="count-badge">{visibleData ? String(paths.length).padStart(2, "0") : "—"}</span></div><div className="panel-subtitle">Select a path to inspect its graph relationships and source evidence.</div></div><button className="text-button" onClick={() => setView("graph")}>Open graph ↗</button></div>
                <div className="paths-container">{!visibleData || paths.length === 0 ? <EmptyGraphState connected={connected} loading={loading} zeroResults={Boolean(visibleData)} siteMode={siteMode} /> : paths.map((path, index) => <PathCard key={`${path.nodes?.[0]?.id}-${index}-${path.hops}`} path={path} index={index} onOpenGraph={openGraph} siteGraph={siteMode} />)}</div>
              </section>
              {siteMode ? <aside className="panel agent-panel site-observation-panel">
                <div className="agent-header"><div className="agent-avatar">◎</div><div><div className="agent-title">Scan observations <span className="agent-live">FALKORDB</span></div><div className="agent-subtitle">{activeSiteScan.site_host}</div></div></div>
                <div className="agent-rule"><span className="rule-icon">i</span><span>These paths describe discovered references and imported evidence; they do not establish that any endpoint is vulnerable.</span></div>
                <div className="agent-response"><div className="response-label"><span className="response-dot" />{siteQuestionResult ? "GRAPH ANSWER" : "LATEST SCAN"}</div><p>{siteQuestionResult?.summary || activeSiteScan.summary}</p></div>
                <div className="recommendations-head"><span>THIS SNAPSHOT</span><span className="count-badge">{activeSiteScan.scan_id.slice(-6)}</span></div>
                <div className="site-snapshot-stats"><span>{activeSiteScan.route_count} routes</span><span>{activeSiteScan.endpoint_count} APIs</span><span>{activeSiteScan.dependency_count} dependencies</span><span>{activeSiteScan.finding_count} findings</span></div>
                <button className="button button-quiet site-open-scan" onClick={() => setView("scan")}>Open scan and history ↗</button>
              </aside> : <aside className="panel agent-panel">
                <div className="agent-header"><div className="agent-avatar">✳</div><div><div className="agent-title">Graph-backed analysis <span className="agent-live">LIVE</span></div><div className="agent-subtitle">Grounded in the current path set</div></div></div>
                <div className="agent-rule"><span className="rule-icon">⌘</span><span>Every finding is calculated from FalkorDB relationships. Removing the database blocks this view.</span></div>
                <div className="agent-response"><div className="response-label"><span className="response-dot" />ANALYSIS</div><p>{visibleData?.summary || (connected ? "Waiting for graph results…" : "Analysis is blocked until FalkorDB is available.")}</p></div>
                <div className="recommendations-head"><span>RECOMMENDED FIXES</span><span className="count-badge">{String(visibleData?.recommendations?.length ?? 0).padStart(2, "0")}</span></div>
                <div className="fixes-container">{!visibleData ? <div className="fix-empty">Recommendations appear after a graph query.</div> : visibleData.recommendations.length === 0 ? <div className="fix-empty">No active route remains. Reset the scenario to replay the investigation.</div> : visibleData.recommendations.map((fix) => <article className="fix-card" key={fix.edge_id}><div className="fix-card-title">{fix.title}</div><div className="fix-card-target">{fix.target}</div><div className="fix-card-detail">{fix.detail}</div><button className="button" onClick={() => simulateFix(fix.edge_id)} disabled={Boolean(busyEdge) || !connected}>{busyEdge === fix.edge_id ? "Updating graph…" : <>Simulate fix <span>↗</span></>}</button></article>)}</div>
                <div className="agent-footnote">Fixes run in the synthetic graph only. No cloud permissions are changed.</div>
              </aside>}
            </div>
          </>}

          {view === "graph" && <>
            <ViewHeading eyebrow={siteMode ? "TARGET-SPECIFIC TOPOLOGY" : "SYNTHETIC DEMO TOPOLOGY"} title={siteMode ? "Website graph" : "Access graph"} detail={siteMode ? `FalkorDB relationships discovered for ${activeSiteScan.site_host}. Select a node or edge to inspect its evidence.` : "Explore the sample nodes and active relationships returned by FalkorDB."} updatedAt={updatedAt} onRefresh={refreshGraph} loading={loading} connected={connected} action={siteMode ? <button className="text-button" onClick={() => setView("scan")}>Scan history ↗</button> : <button className="text-button" onClick={() => setQueryOpen(true)}>Cypher ↗</button>} />
            <SummaryCards paths={paths} visibleData={visibleData} health={health} nodeCount={graph.nodes.length} edgeCount={graph.edges.length} siteMode={siteMode} siteRouteCount={activeSiteScan?.route_count} />
            {visibleData ? <GraphView paths={paths} selectedNodeId={selectedNodeId} onSelectNode={setSelectedNodeId} selectedEdgeId={selectedEdgeId} onSelectEdge={setSelectedEdgeId} siteGraph={siteMode} /> : <section className="panel graph-unavailable"><EmptyGraphState connected={connected} loading={loading} />{connected && <button className="button button-primary" onClick={() => analyze()} disabled={loading}>Load demo graph from FalkorDB ↗</button>}</section>}
          </>}

          {view === "assets" && <>
            <ViewHeading eyebrow={siteMode ? "SITE-DISCOVERED ENTITIES" : "REACHABLE RESOURCES"} title={siteMode ? "Discovered entities" : "Sensitive assets"} detail={siteMode ? "Browse API endpoints, loaded resources, classified traffic signals, and imported findings from the selected website scan." : "Resources are discovered from the synthetic access paths in FalkorDB."} updatedAt={updatedAt} onRefresh={refreshGraph} loading={loading} connected={connected} />
            <SummaryCards paths={paths} visibleData={visibleData} health={health} nodeCount={graph.nodes.length} edgeCount={graph.edges.length} siteMode={siteMode} siteRouteCount={activeSiteScan?.route_count} />
            {!visibleData ? <section className="panel section-empty"><EmptyGraphState connected={connected} loading={loading} /></section> : assets.length === 0 ? <section className="panel section-empty"><div className="safe-icon">✓</div><h3>{siteMode ? "No discovered entities in this result" : "No sensitive resource is on an active path"}</h3><p>{siteMode ? "Run a scan or ask a broader question to load site entities from FalkorDB." : "FalkorDB returned no secret, data store, or data asset in the current attack path set."}</p></section> : <div className="asset-grid">{assets.map((asset) => {
              const incidentEdges = evidence.filter((edge) => edge.sourceId === asset.id || edge.targetId === asset.id);
              const relationship = incidentEdges.find((edge) => edge.targetId === asset.id) || incidentEdges[0];
              return <article className="panel resource-card" key={asset.id}>
                <div className={`resource-glyph ${nodeTone(asset.kind)}`}>{nodeGlyph(asset.kind)}</div>
                <div className="resource-overline">{siteMode ? "SITE OBSERVATION" : "GRAPH RESOURCE"} <span className="resource-exposure">{siteMode ? (asset.noise_candidate ? "REVIEW CANDIDATE" : asset.severity || "OBSERVED") : "REACHABLE"}</span></div>
                <h3>{asset.name}</h3><p className="resource-kind">{asset.kind}</p>
                {siteMode && asset.url && (asset.url.includes("${") ? <code className="site-entity-url">{asset.url}</code> : <a className="site-entity-url" href={asset.url} target="_blank" rel="noreferrer">{asset.url} ↗</a>)}
                {siteMode && asset.evidence && <p className="site-entity-evidence">{asset.evidence}</p>}
                <div className="resource-meta"><span>{siteMode ? "Observed paths" : "Active paths"}</span><b>{asset.pathIndexes.size}</b></div>
                <div className="resource-meta"><span>Adjacent evidence</span><b>{incidentEdges.length} relationships</b></div>
                {siteMode && relationship && <div className="resource-meta"><span>Evidence type</span><b>{relationship.mechanism}</b></div>}
                {siteMode && asset.interaction_type && <><div className="resource-meta"><span>Signal role</span><b>{asset.role_category?.replaceAll("_", " ") || "unknown"}</b></div><div className="resource-meta"><span>Classifier confidence</span><b>{asset.confidence || "low"}</b></div></>}
                <div className="resource-connections">{incidentEdges.map((edge) => <button key={edge.id} onClick={() => pickEvidence(edge)}><span>{edge.source?.name}</span><i>→</i><span>{edge.target?.name}</span></button>)}</div>
                <button className="text-button resource-inspect" onClick={() => openGraph(asset.id)}>Inspect in graph ↗</button>
              </article>;
            })}</div>}
          </>}

          {view === "activity" && <>
            <ViewHeading eyebrow={siteMode ? "SELECTED SITE EVIDENCE" : "SYNTHETIC DEMO EVIDENCE"} title="Evidence trail" detail={siteMode ? `Source strings and graph relationships collected for ${activeSiteScan.site_host}.` : "Relationship evidence attached to the synthetic graph paths."} updatedAt={updatedAt} onRefresh={refreshGraph} loading={loading} connected={connected} />
            <SummaryCards paths={paths} visibleData={visibleData} health={health} nodeCount={graph.nodes.length} edgeCount={graph.edges.length} siteMode={siteMode} siteRouteCount={activeSiteScan?.route_count} />
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

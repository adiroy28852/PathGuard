"""FalkorDB access and the synthetic cloud access graph."""

from __future__ import annotations

import os
import hashlib
import json
import re
import threading
from typing import Any

from falkordb import FalkorDB


GRAPH_NAME = os.getenv("FALKORDB_GRAPH", "pathguard")
SEED_CYPHER = """
CREATE
  (internet:Principal {id: 'internet', name: 'Public Internet', kind: 'External principal'}),
  (checkoutGateway:Endpoint {id: 'checkout-gateway', name: 'Checkout Gateway', kind: 'Public endpoint'}),
  (checkout:Workload {id: 'checkout-api', name: 'Checkout API', kind: 'Workload'}),
  (checkoutRole:Identity {id: 'checkout-role', name: 'Checkout Runtime Role', kind: 'Cloud identity'}),
  (adminGateway:Endpoint {id: 'admin-gateway', name: 'Admin Gateway', kind: 'Public endpoint'}),
  (adminConsole:Workload {id: 'admin-console', name: 'Admin Console', kind: 'Workload'}),
  (deployRunner:Workload {id: 'deploy-runner', name: 'Deploy Runner', kind: 'Workload'}),
  (deployRole:Identity {id: 'deploy-role', name: 'Deployment Role', kind: 'Cloud identity'}),
  (paymentSecret:Secret {id: 'payment-secret', name: 'Payments Production Secret', kind: 'Secret'}),
  (paymentsDb:DataStore {id: 'payments-db', name: 'Payments Database', kind: 'Data store'}),
  (pii:DataAsset {id: 'customer-pii', name: 'Customer PII', kind: 'Sensitive data', classification: 'restricted'}),

  (internet)-[:CAN_ACCESS {id: 'internet-checkout', mechanism: 'public route', evidence: 'Internet-facing load balancer', active: true}]->(checkoutGateway),
  (checkoutGateway)-[:CAN_ACCESS {id: 'checkout-route', mechanism: 'routes to', evidence: 'Gateway route configuration', active: true}]->(checkout),
  (checkout)-[:CAN_ACCESS {id: 'checkout-identity', mechanism: 'runs as', evidence: 'Workload identity binding', active: true}]->(checkoutRole),
  (checkoutRole)-[:CAN_ACCESS {id: 'checkout-secret-read', mechanism: 'reads secret', evidence: 'Secret access policy', active: true}]->(paymentSecret),

  (internet)-[:CAN_ACCESS {id: 'internet-admin', mechanism: 'public route', evidence: 'Exposed admin endpoint', active: true}]->(adminGateway),
  (adminGateway)-[:CAN_ACCESS {id: 'admin-route', mechanism: 'routes to', evidence: 'Gateway route configuration', active: true}]->(adminConsole),
  (adminConsole)-[:CAN_ACCESS {id: 'admin-deploy', mechanism: 'delegates to', evidence: 'Deployment integration', active: true}]->(deployRunner),
  (deployRunner)-[:CAN_ACCESS {id: 'deploy-identity', mechanism: 'runs as', evidence: 'Workload identity binding', active: true}]->(deployRole),
  (deployRole)-[:CAN_ACCESS {id: 'deploy-secret-read', mechanism: 'reads secret', evidence: 'Secret access policy', active: true}]->(paymentSecret),

  (paymentSecret)-[:CAN_ACCESS {id: 'secret-unlocks-db', mechanism: 'unlocks', evidence: 'Database credential in secret', active: true}]->(paymentsDb),
  (paymentsDb)-[:CAN_ACCESS {id: 'db-contains-pii', mechanism: 'contains', evidence: 'Synthetic data inventory', active: true}]->(pii)
"""

PATH_QUERY = """
MATCH path = (source:Principal {id: 'internet'})-[:CAN_ACCESS*1..8]->(asset:DataAsset {classification: 'restricted'})
WHERE all(access IN relationships(path) WHERE access.active = true)
RETURN
  [node IN nodes(path) | {id: node.id, name: node.name, kind: node.kind}] AS path_nodes,
  [access IN relationships(path) | {id: access.id, mechanism: access.mechanism, evidence: access.evidence}] AS path_edges,
  length(path) AS hops
ORDER BY hops ASC
LIMIT 50
"""

REMEDIATION_EDGE_IDS = {
    "checkout-secret-read",
    "deploy-secret-read",
}


class GraphUnavailable(RuntimeError):
    """Raised when FalkorDB cannot answer a required graph operation."""


class GraphStore:
    """The application's source of truth. There is deliberately no local fallback."""

    def __init__(self) -> None:
        self.url = os.getenv("FALKORDB_URL", "").strip()
        self.host = os.getenv("FALKORDB_HOST", "localhost")
        self.port = int(os.getenv("FALKORDB_PORT", "6379"))
        self.username = os.getenv("FALKORDB_USERNAME") or None
        self.password = os.getenv("FALKORDB_PASSWORD") or None
        self.ssl = os.getenv("FALKORDB_TLS", "false").casefold() in {"1", "true", "yes"}
        self._client: FalkorDB | None = None
        self._graph: Any | None = None
        self._seed_lock = threading.Lock()

    def graph(self) -> Any:
        if self._graph is None:
            try:
                if self.url:
                    self._client = FalkorDB.from_url(self.url)
                else:
                    self._client = FalkorDB(
                        host=self.host,
                        port=self.port,
                        username=self.username,
                        password=self.password,
                        ssl=self.ssl,
                    )
                self._graph = self._client.select_graph(GRAPH_NAME)
            except Exception as exc:  # connection errors vary by redis-py version
                self._client = None
                self._graph = None
                endpoint = "configured remote endpoint" if self.url else f"{self.host}:{self.port}"
                raise GraphUnavailable(f"Cannot connect to FalkorDB at {endpoint}") from exc
        return self._graph

    def _query(self, cypher: str) -> list[list[Any]]:
        try:
            return self.graph().query(cypher).result_set
        except GraphUnavailable:
            raise
        except Exception as exc:
            # Drop the cached connection so the next request can reconnect.
            self._client = None
            self._graph = None
            raise GraphUnavailable("FalkorDB query failed; Pathguard cannot answer without its graph") from exc

    @staticmethod
    def _literal(value: Any) -> str:
        """Encode values as Cypher string literals; never accept Cypher from a scan payload."""
        return json.dumps(str(value), ensure_ascii=False).replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")

    def _site_graph(self, graph_name: str) -> Any:
        # Initialize the shared connection through the demo graph, then select an isolated graph.
        self.graph()
        try:
            return self._client.select_graph(graph_name)
        except Exception as exc:
            self._client = None
            self._graph = None
            raise GraphUnavailable("Could not select the FalkorDB site graph") from exc

    def _site_query(self, graph_name: str, cypher: str) -> list[list[Any]]:
        try:
            return self._site_graph(graph_name).query(cypher).result_set
        except GraphUnavailable:
            raise
        except Exception as exc:
            self._client = None
            self._graph = None
            raise GraphUnavailable("FalkorDB could not answer the website graph query") from exc

    @staticmethod
    def site_graph_name(site_host: str) -> str:
        digest = hashlib.sha256(site_host.lower().encode("utf-8")).hexdigest()[:20]
        return f"pathguard_site_{digest}"

    @staticmethod
    def _route_key(scan_id: str, url: str) -> str:
        return hashlib.sha256(f"{scan_id}|{url}".encode("utf-8")).hexdigest()[:24]

    def ingest_site_scan(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        site_host = snapshot["site_host"].lower()
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", site_host):
            raise ValueError("Invalid target hostname")
        graph_name = self.site_graph_name(site_host)
        scan_id = snapshot["scan_id"]
        q = lambda value: self._literal(value)
        browser_runtime = snapshot.get("browser_runtime") or {}
        runtime_limit_hit = "true" if browser_runtime.get("request_limit_hit") else "false"
        previous = self._site_query(
            graph_name,
            f"MATCH (:Site {{id: {q(site_host)}}})-[:HAS_SCAN]->(s:Scan) "
            "RETURN s.id, s.created_at ORDER BY s.created_at DESC LIMIT 1",
        )
        previous_id = str(previous[0][0]) if previous else None
        root_url = snapshot["target_url"]
        self._site_query(graph_name, "MERGE (p:Principal {id: \"public-internet\"}) SET p.name = \"Public Internet\", p.kind = \"External principal\"")
        self._site_query(
            graph_name,
            f"MERGE (site:Site {{id: {q(site_host)}}}) SET site.name = {q(site_host)}, site.url = {q(root_url)}, site.kind = \"Website\" "
            f"MERGE (scan:Scan {{id: {q(scan_id)}}}) SET scan.target_url = {q(root_url)}, scan.created_at = {q(snapshot['created_at'])}, "
            f"scan.route_count = {len(snapshot['pages'])}, scan.finding_count = {len(snapshot['findings'])}, "
            f"scan.interaction_count = {len(snapshot.get('interactions', []))}, "
            f"scan.runtime_status = {q(browser_runtime.get('status', 'not_recorded'))}, "
            f"scan.runtime_duration_ms = {int(browser_runtime.get('duration_ms', 0))}, "
            f"scan.runtime_requests_seen = {int(browser_runtime.get('requests_seen', 0))}, "
            f"scan.runtime_requests_blocked = {int(browser_runtime.get('requests_blocked', 0))}, "
            f"scan.runtime_popup_pages_seen = {int(browser_runtime.get('popup_pages_seen', 0))}, "
            f"scan.runtime_error_type = {q(browser_runtime.get('error_type') or '')}, "
            f"scan.browser_sandbox = {q(browser_runtime.get('browser_sandbox', 'not_recorded'))}, "
            f"scan.runtime_request_limit_hit = {runtime_limit_hit}, "
            f"scan.artifact_type = {q((snapshot.get('artifact') or {}).get('type', ''))}, scan.artifact_records = {int((snapshot.get('artifact') or {}).get('records', 0))}, scan.kind = \"Website scan\" "
            f"MERGE (site)-[:HAS_SCAN {{id: {q(f'{scan_id}:site-scan')}}}]->(scan) "
            + (f"WITH site, scan MATCH (old:Scan {{id: {q(previous_id)}}}) MERGE (old)-[:PRECEDES {{id: {q(f'{previous_id}:{scan_id}:precedes')}}}]->(scan) " if previous_id else "")
            + "RETURN site.id",
        )
        self._site_query(
            graph_name,
            f"MATCH (p:Principal {{id: \"public-internet\"}}) MERGE (site:Site {{id: {q(site_host)}}}) "
            f"MERGE (p)-[:CAN_REACH {{id: {q(f'{scan_id}:public-site')}, scan_id: {q(scan_id)}, active: true, mechanism: \"public HTTPS/HTTP origin\", evidence: {q(root_url)}}}]->(site)",
        )

        page_by_url: dict[str, str] = {}
        for page in snapshot["pages"]:
            route_id = self._route_key(scan_id, page["url"])
            # Preserve SPA fragments: /#/home and /#/admin are separate graph routes.
            page_by_url[page["url"]] = route_id
            route_name = page.get("title") or page["url"].split("#", 1)[-1] or "/"
            self._site_query(
                graph_name,
                f"MATCH (scan:Scan {{id: {q(scan_id)}}}) "
                f"MERGE (route:Route {{id: {q(route_id)}}}) SET route.scan_id = {q(scan_id)}, route.url = {q(page['url'])}, "
                f"route.name = {q(route_name)}, route.kind = \"Website route\", route.status = {int(page.get('status') or 0)}, "
                f"route.content_type = {q(page.get('content_type', ''))} "
                f"MERGE (scan)-[:HAS_ROUTE {{id: {q(f'{scan_id}:route:{route_id}')}}}]->(route) "
                f"MERGE (site:Site {{id: {q(site_host)}}}) "
                f"MERGE (site)-[:CONTAINS {{id: {q(f'{scan_id}:contains:{route_id}')}}}]->(route)",
            )
            self._site_query(
                graph_name,
                f"MATCH (p:Principal {{id: \"public-internet\"}}), (route:Route {{id: {q(route_id)}}}) "
                f"MERGE (p)-[:OBSERVED_PUBLIC {{id: {q(f'{scan_id}:public:{route_id}')}, scan_id: {q(scan_id)}, active: true, "
                f"mechanism: \"public route observed\", evidence: {q(page['url'])}}}]->(route)",
            )

        # Attach observations to the exact route that produced them, retaining evidence and scan IDs.
        for endpoint in snapshot["api_endpoints"]:
            source_url = endpoint.get("source_url", root_url)
            route_id = page_by_url.get(source_url)
            if not route_id:
                route_id = next(iter(page_by_url.values()), None)
            if not route_id:
                continue
            endpoint_id = self._route_key(scan_id, f"{endpoint['method']}|{endpoint['url']}")
            self._site_query(
                graph_name,
                f"MERGE (api:ApiEndpoint {{id: {q(endpoint_id)}}}) SET api.scan_id = {q(scan_id)}, api.url = {q(endpoint['url'])}, "
                f"api.name = {q(endpoint['method'] + ' ' + endpoint['url'])}, api.method = {q(endpoint['method'])}, api.kind = \"API endpoint\", "
                f"api.status = {int(endpoint['status']) if endpoint.get('status') is not None else 0} "
                f"WITH api MATCH (route:Route {{id: {q(route_id)}}}) "
                f"MERGE (route)-[:CALLS {{id: {q(f'{scan_id}:calls:{endpoint_id}')}, scan_id: {q(scan_id)}, active: true, "
                f"mechanism: {q(endpoint['method'] + ' request')}, evidence: {q(endpoint.get('evidence', 'Observed API request'))}}}]->(api)",
            )

        for dependency in snapshot["dependencies"]:
            source_url = dependency.get("source_url", root_url)
            route_id = page_by_url.get(source_url) or next(iter(page_by_url.values()), None)
            if not route_id:
                continue
            dependency_id = self._route_key(scan_id, f"{dependency['host']}|{dependency['kind']}")
            self._site_query(
                graph_name,
                f"MERGE (dep:Dependency {{id: {q(dependency_id)}}}) SET dep.scan_id = {q(scan_id)}, dep.url = {q(dependency['url'])}, "
                f"dep.name = {q(dependency['host'])}, dep.host = {q(dependency['host'])}, dep.kind = \"External dependency\" "
                f"WITH dep MATCH (route:Route {{id: {q(route_id)}}}) "
                f"MERGE (route)-[:LOADS {{id: {q(f'{scan_id}:loads:{dependency_id}')}, scan_id: {q(scan_id)}, active: true, "
                f"mechanism: {q(dependency.get('kind', 'external reference'))}, evidence: {q(dependency.get('evidence', 'Observed external origin'))}}}]->(dep)",
            )

        # Keep navigation and redirect behavior separate from page routes and
        # external resources. These signals explain how the site behaves; they
        # do not create pages or imply that a destination is malicious.
        for interaction in snapshot.get("interactions", []):
            source_url = interaction.get("source_url", root_url)
            route_id = page_by_url.get(source_url) or next(iter(page_by_url.values()), None)
            if not route_id:
                continue
            target_url = interaction.get("url", "")
            interaction_type = interaction.get("interaction_type", "unknown")
            interaction_id = self._route_key(scan_id, f"interaction|{source_url}|{interaction_type}|{target_url}")
            noise_candidate = "true" if interaction.get("noise_candidate") else "false"
            status = int(interaction["status"]) if interaction.get("status") is not None else 0
            relationship_evidence = f"{interaction.get('evidence', 'Observed interaction')} Classification: {interaction.get('classification_reason', 'Unknown role; review evidence.')}"
            self._site_query(
                graph_name,
                f"MERGE (signal:Interaction {{id: {q(interaction_id)}}}) SET signal.scan_id = {q(scan_id)}, signal.url = {q(target_url)}, "
                f"signal.name = {q(interaction.get('host', 'unknown') + ' · ' + interaction_type)}, signal.host = {q(interaction.get('host', 'unknown'))}, "
                f"signal.kind = \"Observed interaction\", signal.interaction_type = {q(interaction_type)}, "
                f"signal.domain_relation = {q(interaction.get('domain_relation', 'unknown'))}, signal.role_category = {q(interaction.get('role_category', 'unknown'))}, "
                f"signal.confidence = {q(interaction.get('confidence', 'low'))}, signal.noise_candidate = {noise_candidate}, "
                f"signal.classification_reason = {q(interaction.get('classification_reason', ''))}, signal.evidence = {q(interaction.get('evidence', ''))}, "
                f"signal.redirect_scope = {q(interaction.get('redirect_scope', ''))}, signal.status = {status} "
                f"WITH signal MATCH (route:Route {{id: {q(route_id)}}}) "
                f"MERGE (route)-[:OBSERVED_INTERACTION {{id: {q(f'{scan_id}:interaction:{interaction_id}')}, scan_id: {q(scan_id)}, active: true, "
                f"mechanism: {q(interaction_type)}, evidence: {q(relationship_evidence)}}}]->(signal)",
            )

        for finding in snapshot["findings"]:
            uri = finding.get("uri", root_url)
            route_id = page_by_url.get(uri)
            if not route_id:
                route_id = next(iter(page_by_url.values()), None)
            if not route_id:
                continue
            finding_id = self._route_key(scan_id, f"finding|{finding['id']}")
            self._site_query(
                graph_name,
                f"MERGE (f:Finding {{id: {q(finding_id)}}}) SET f.scan_id = {q(scan_id)}, f.name = {q(finding['title'])}, "
                f"f.source_finding_id = {q(finding['id'])}, f.title = {q(finding['title'])}, f.severity = {q(finding['severity'])}, f.rule_id = {q(finding.get('rule_id', ''))}, "
                f"f.evidence = {q(finding['evidence'])}, f.source = {q(finding.get('source', 'Imported evidence'))}, f.kind = \"Finding\", f.active = true "
                f"WITH f MATCH (route:Route {{id: {q(route_id)}}}) "
                f"MERGE (route)-[:HAS_FINDING {{id: {q(f'{scan_id}:finding:{finding_id}')}, scan_id: {q(scan_id)}, active: true, "
                f"mechanism: {q(finding['severity'] + ' finding')}, evidence: {q(finding['evidence'])}}}]->(f)",
            )

        paths = self._site_paths(graph_name, scan_id)
        route_count = len(snapshot["pages"])
        endpoint_count = len(snapshot["api_endpoints"])
        dependency_count = len(snapshot["dependencies"])
        finding_count = len(snapshot["findings"])
        history = self.site_history(site_host)
        previous_snapshot = self._site_inventory(graph_name, previous_id) if previous_id else {"routes": set(), "apis": set(), "findings": set(), "interactions": set()}
        current_snapshot = {
            "routes": {page["url"] for page in snapshot["pages"]},
            "apis": {f"{item['method']} {item['url']}" for item in snapshot["api_endpoints"]},
            "findings": {f"{item['id']} {item['title']}" for item in snapshot["findings"]},
            "interactions": {f"{item.get('interaction_type')} {item.get('url')}" for item in snapshot.get("interactions", [])},
        }
        changes = {key: {"added": sorted(current_snapshot[key] - previous_snapshot[key]), "removed": sorted(previous_snapshot[key] - current_snapshot[key])} for key in current_snapshot}
        changes["baseline_scan_id"] = previous_id
        stats = self._site_query(graph_name, f"MATCH (n {{scan_id: {q(scan_id)}}}) RETURN count(n)")
        relation_stats = self._site_query(graph_name, f"MATCH ()-[r {{scan_id: {q(scan_id)}}}]->() RETURN count(r)")
        return {
            "database": "FalkorDB",
            "graph": {"name": graph_name, "nodes": int(stats[0][0]) if stats else 0, "relationships": int(relation_stats[0][0]) if relation_stats else 0},
            "site_host": site_host,
            "scan_id": scan_id,
            "target_url": root_url,
            "created_at": snapshot["created_at"],
            "scope": snapshot["scope"],
            "route_count": route_count,
            "endpoint_count": endpoint_count,
            "dependency_count": dependency_count,
            "finding_count": finding_count,
            "interaction_count": len(snapshot.get("interactions", [])),
            "browser_runtime": browser_runtime,
            "artifact": snapshot.get("artifact"),
            "limits": snapshot["limits"],
            "paths": paths,
            "changes": changes,
            "history": history,
        }

    def _site_paths(self, graph_name: str, scan_id: str, category: str = "all") -> list[dict[str, Any]]:
        q = self._literal
        root_rows = self._site_query(
            graph_name,
            f"MATCH (p:Principal {{id: \"public-internet\"}})-[e:OBSERVED_PUBLIC {{scan_id: {q(scan_id)}, active: true}}]->(r:Route {{scan_id: {q(scan_id)}}}) "
            "RETURN r.id, r.url, r.name, r.kind, e.id, e.mechanism, e.evidence",
        )
        routes: dict[str, dict[str, Any]] = {}
        root_edges: dict[str, dict[str, Any]] = {}
        paths: list[dict[str, Any]] = []
        for row in root_rows:
            rid = str(row[0])
            route = {"id": rid, "name": str(row[2]), "kind": str(row[3]), "url": str(row[1])}
            routes[rid] = route
            root_edges[rid] = {"id": str(row[4]), "mechanism": str(row[5]), "evidence": str(row[6])}
            if category == "all":
                paths.append({"nodes": [{"id": "public-internet", "name": "Public Internet", "kind": "External principal"}, route], "edges": [root_edges[rid]], "hops": 1, "category": "route"})
        relation_types = {"api": "CALLS", "dependency": "LOADS", "finding": "HAS_FINDING", "interaction": "OBSERVED_INTERACTION"}
        selected = [category] if category in relation_types else list(relation_types)
        for kind in selected:
            rel_type = relation_types[kind]
            rows = self._site_query(
                graph_name,
                f"MATCH (r:Route {{scan_id: {q(scan_id)}}})-[e:{rel_type} {{scan_id: {q(scan_id)}, active: true}}]->(t) "
                "RETURN r.id, r.url, r.name, r.kind, e.id, e.mechanism, e.evidence, t.id, t.name, t.kind, t.url, t.severity, t.title, t.evidence, "
                "t.interaction_type, t.domain_relation, t.role_category, t.confidence, t.noise_candidate, t.classification_reason, t.host, t.redirect_scope, t.status",
            )
            for row in rows:
                if str(row[0]) not in routes:
                    continue
                target = {"id": str(row[7]), "name": str(row[8]), "kind": str(row[9])}
                if row[10]:
                    target["url"] = str(row[10])
                if row[11]:
                    target["severity"] = str(row[11])
                if row[12]:
                    target["title"] = str(row[12])
                if row[13]:
                    target["evidence"] = str(row[13])
                if row[14]:
                    target["interaction_type"] = str(row[14])
                    target["domain_relation"] = str(row[15] or "unknown")
                    target["role_category"] = str(row[16] or "unknown")
                    target["confidence"] = str(row[17] or "low")
                    target["noise_candidate"] = row[18] is True or row[18] == 1 or str(row[18]).casefold() == "true"
                    target["classification_reason"] = str(row[19] or "")
                    target["host"] = str(row[20] or "")
                    target["redirect_scope"] = str(row[21] or "")
                    if row[22] is not None:
                        target["status"] = int(row[22])
                route = routes[str(row[0])]
                paths.append({
                    "nodes": [{"id": "public-internet", "name": "Public Internet", "kind": "External principal"}, route, target],
                    "edges": [root_edges[str(row[0])], {"id": str(row[4]), "mechanism": str(row[5]), "evidence": str(row[6])}],
                    "hops": 2,
                    "category": kind,
                })
        return paths

    def answer_site_question(self, site_host: str, scan_id: str, question: str) -> dict[str, Any]:
        normalized = question.casefold()
        category = "all"
        if any(word in normalized for word in ("finding", "vulnerability", "header", "sarif", "issue")):
            category = "finding"
        elif any(word in normalized for word in ("popup", "pop-up", "redirect", "traffic", "noise", "tracking", "advert", "outbound link", "external navigation", "external link")):
            category = "interaction"
        elif any(word in normalized for word in ("third", "external", "dependency", "script", "domain")):
            category = "dependency"
        elif any(word in normalized for word in ("api", "endpoint", "request", "call")):
            category = "api"
        graph_name = self.site_graph_name(site_host)
        paths = self._site_paths(graph_name, scan_id, category)
        stats = self._site_query(graph_name, f"MATCH (n {{scan_id: {self._literal(scan_id)}}}) RETURN count(n)")
        target = self._site_query(graph_name, f"MATCH (s:Scan {{id: {self._literal(scan_id)}}}) RETURN s.target_url, s.runtime_status, s.runtime_duration_ms, s.runtime_requests_seen, s.runtime_requests_blocked, s.runtime_request_limit_hit, s.runtime_popup_pages_seen, s.runtime_error_type, s.browser_sandbox")
        runtime = target[0] if target else []
        browser_runtime = {
            "status": str(runtime[1] or "not_recorded") if runtime else "not_recorded",
            "duration_ms": int(runtime[2] or 0) if runtime else 0,
            "requests_seen": int(runtime[3] or 0) if runtime else 0,
            "requests_blocked": int(runtime[4] or 0) if runtime else 0,
            "request_limit_hit": (runtime[5] is True or runtime[5] == 1 or str(runtime[5]).casefold() == "true") if runtime else False,
            "popup_pages_seen": int(runtime[6] or 0) if runtime else 0,
            "error_type": str(runtime[7] or "") if runtime else "",
            "browser_sandbox": str(runtime[8] or "not_recorded") if runtime else "not_recorded",
        }
        return {"database": "FalkorDB", "graph": {"name": graph_name, "nodes": int(stats[0][0]) if stats else 0}, "site_host": site_host, "target_url": str(runtime[0]) if runtime else site_host, "browser_runtime": browser_runtime, "scan_id": scan_id, "question": question, "category": category, "paths": paths}

    def simulate_site_remediation(self, site_host: str, scan_id: str, finding_id: str) -> dict[str, Any]:
        graph_name = self.site_graph_name(site_host)
        q = self._literal
        changed = self._site_query(
            graph_name,
            f"MATCH (f:Finding {{id: {q(finding_id)}, scan_id: {q(scan_id)}}}) "
            "SET f.active = false WITH f "
            f"MATCH (r:Route {{scan_id: {q(scan_id)}}})-[e:HAS_FINDING {{scan_id: {q(scan_id)}}}]->(f) "
            "SET e.active = false RETURN f.id",
        )
        if not changed:
            raise ValueError("That finding is not part of this scan.")
        return {
            "database": "FalkorDB",
            "site_host": site_host,
            "scan_id": scan_id,
            "finding_id": finding_id,
            "paths": self._site_paths(graph_name, scan_id),
            "notice": "Simulation changed only this scan's FalkorDB graph; the target website was not modified.",
        }

    def site_history(self, site_host: str) -> list[dict[str, Any]]:
        graph_name = self.site_graph_name(site_host)
        rows = self._site_query(
            graph_name,
            f"MATCH (:Site {{id: {self._literal(site_host.lower())}}})-[:HAS_SCAN]->(s:Scan) "
            "RETURN s.id, s.target_url, s.created_at, s.route_count, s.finding_count, s.interaction_count ORDER BY s.created_at DESC LIMIT 10",
        )
        return [{"scan_id": str(row[0]), "target_url": str(row[1]), "created_at": str(row[2]), "route_count": int(row[3] or 0), "finding_count": int(row[4] or 0), "interaction_count": int(row[5] or 0)} for row in rows]

    def load_site_scan(self, site_host: str, scan_id: str) -> dict[str, Any]:
        site_host = site_host.lower()
        graph_name = self.site_graph_name(site_host)
        q = self._literal
        rows = self._site_query(
            graph_name,
            f"MATCH (s:Scan {{id: {q(scan_id)}}}) RETURN s.target_url, s.created_at, s.route_count, s.finding_count, s.artifact_type, s.artifact_records, "
            "s.runtime_status, s.runtime_duration_ms, s.runtime_requests_seen, s.runtime_requests_blocked, s.runtime_request_limit_hit, s.runtime_popup_pages_seen, s.runtime_error_type, s.browser_sandbox",
        )
        if not rows:
            raise ValueError("That scan was not found in FalkorDB.")
        previous = self._site_query(
            graph_name,
            f"MATCH (old:Scan)-[:PRECEDES]->(:Scan {{id: {q(scan_id)}}}) RETURN old.id ORDER BY old.created_at DESC LIMIT 1",
        )
        previous_id = str(previous[0][0]) if previous else None
        inventory = self._site_inventory(graph_name, previous_id)
        current = self._site_inventory(graph_name, scan_id)
        changes = {key: {"added": sorted(current[key] - inventory[key]), "removed": sorted(inventory[key] - current[key])} for key in current}
        changes["baseline_scan_id"] = previous_id
        counts = {}
        for key, label in (("route_count", "Route"), ("endpoint_count", "ApiEndpoint"), ("dependency_count", "Dependency"), ("finding_count", "Finding"), ("interaction_count", "Interaction")):
            result = self._site_query(graph_name, f"MATCH (n:{label} {{scan_id: {q(scan_id)}}}) RETURN count(n)")
            counts[key] = int(result[0][0]) if result else 0
        stats = self._site_query(graph_name, f"MATCH (n {{scan_id: {q(scan_id)}}}) RETURN count(n)")
        relationships = self._site_query(graph_name, f"MATCH ()-[r {{scan_id: {q(scan_id)}}}]->() RETURN count(r)")
        target_url = str(rows[0][0])
        artifact_type = str(rows[0][4] or "")
        return {
            "database": "FalkorDB",
            "graph": {"name": graph_name, "nodes": int(stats[0][0]) if stats else 0, "relationships": int(relationships[0][0]) if relationships else 0},
            "site_host": site_host,
            "scan_id": scan_id,
            "target_url": target_url,
            "created_at": str(rows[0][1]),
            "scope": "Persisted read-only website observations, classified traffic signals, and imported evidence.",
            **counts,
            "browser_runtime": {
                "status": str(rows[0][6] or "not_recorded"),
                "duration_ms": int(rows[0][7] or 0),
                "requests_seen": int(rows[0][8] or 0),
                "requests_blocked": int(rows[0][9] or 0),
                "request_limit_hit": rows[0][10] is True or rows[0][10] == 1 or str(rows[0][10]).casefold() == "true",
                "popup_pages_seen": int(rows[0][11] or 0),
                "error_type": str(rows[0][12] or ""),
                "browser_sandbox": str(rows[0][13] or "not_recorded"),
                "off_origin_requests_fetched": False,
                "non_get_requests_sent": False,
                "cookies_persisted": False,
            },
            "artifact": {"type": artifact_type, "records": int(rows[0][5] or 0)} if artifact_type else None,
            "limits": {"max_pages": 12, "max_page_bytes": 1_000_000, "max_first_party_scripts": 20, "runtime_browser_ms": 13_500, "max_browser_requests": 100, "runtime_popup_detection": str(rows[0][6] or "") == "completed"},
            "paths": self._site_paths(graph_name, scan_id),
            "changes": changes,
            "history": self.site_history(site_host),
        }

    def _site_inventory(self, graph_name: str, scan_id: str | None) -> dict[str, set[str]]:
        if not scan_id:
            return {"routes": set(), "apis": set(), "findings": set(), "interactions": set()}
        q = self._literal
        routes = self._site_query(graph_name, f"MATCH (r:Route {{scan_id: {q(scan_id)}}}) RETURN r.url")
        apis = self._site_query(graph_name, f"MATCH (e:ApiEndpoint {{scan_id: {q(scan_id)}}}) RETURN e.method, e.url")
        findings = self._site_query(graph_name, f"MATCH (f:Finding {{scan_id: {q(scan_id)}}}) RETURN f.source_finding_id, f.title, f.id")
        interactions = self._site_query(graph_name, f"MATCH (i:Interaction {{scan_id: {q(scan_id)}}}) RETURN i.interaction_type, i.url")
        # Compare findings by title so snapshots created before source IDs were saved remain comparable.
        return {"routes": {str(row[0]) for row in routes}, "apis": {f"{row[0]} {row[1]}" for row in apis}, "findings": {str(row[1]) for row in findings}, "interactions": {f"{row[0]} {row[1]}" for row in interactions}}

    def ping(self) -> bool:
        result = self._query("RETURN 1 AS ok")
        return bool(result and result[0][0] == 1)

    def ensure_seeded(self) -> None:
        with self._seed_lock:
            result = self._query("MATCH (source:Principal {id: 'internet'}) RETURN source.id LIMIT 1")
            if not result:
                self._query(SEED_CYPHER)

    def attack_paths(self) -> list[dict[str, Any]]:
        self.ensure_seeded()
        rows = self._query(PATH_QUERY)
        paths: list[dict[str, Any]] = []
        for row in rows:
            paths.append(
                {
                    "nodes": row[0] or [],
                    "edges": row[1] or [],
                    "hops": int(row[2]),
                }
            )
        return paths

    def simulate_revocation(self, edge_id: str) -> None:
        if edge_id not in REMEDIATION_EDGE_IDS:
            raise ValueError("Only the two modeled secret-reader permissions can be simulated")
        # edge_id is selected from a closed allowlist above, never accepted as Cypher from the user.
        self._query(
            f"MATCH ()-[edge:CAN_ACCESS {{id: '{edge_id}'}}]->() "
            "SET edge.active = false RETURN edge.id"
        )

    def reset_scenario(self) -> None:
        self.ensure_seeded()
        self._query("MATCH ()-[edge:CAN_ACCESS]->() SET edge.active = true RETURN count(edge)")

    def graph_stats(self) -> dict[str, int]:
        self.ensure_seeded()
        nodes = self._query("MATCH (node) RETURN count(node) AS total")
        edges = self._query("MATCH ()-[edge:CAN_ACCESS]->() RETURN count(edge) AS total")
        return {
            "nodes": int(nodes[0][0]) if nodes else 0,
            "relationships": int(edges[0][0]) if edges else 0,
        }


graph_store = GraphStore()

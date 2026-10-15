"""FalkorDB access and the synthetic cloud access graph."""

from __future__ import annotations

import os
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

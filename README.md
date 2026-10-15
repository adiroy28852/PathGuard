# Pathguard

**A graph-first security agent that proves whether an exposed identity can reach sensitive data, then checks whether a proposed fix removes every route.**

Pathguard is built for the Graph Hacks challenge. Its React console calls the Pathguard application API. The application backend calls a separately deployed Graph API over HTTP. Only that Graph API imports the FalkorDB client, runs Cypher, seeds the graph, and changes graph edges. There is no FalkorDB driver in the application backend and no cached or in-memory fallback.

```text
React console → Pathguard API → FalkorDB Graph API → FalkorDB
```

Every reachability query and remediation check runs in FalkorDB. If the database is removed or stopped, the app remains available but reports the graph as offline and analysis returns HTTP 503.

## Demo flow

1. Ask whether the public Internet can reach customer PII.
2. Pathguard traverses the current FalkorDB graph and shows two independent paths with their evidence.
3. Simulate removing the Checkout API's secret-read permission. One route remains.
4. Simulate removing the deployment role's secret-read permission. No active route remains.
5. Reset the synthetic graph to restore both routes.

The graph is synthetic. The demo does not connect to or change a real cloud account.

## Run with Docker Compose

```sh
docker-compose up --build
```

Open [http://localhost:8000](http://localhost:8000) for the React app, [http://localhost:8000/graph-api/docs](http://localhost:8000/graph-api/docs) for the Graph API docs through the app, and [http://localhost:3000](http://localhost:3000) for FalkorDB Browser. The direct Graph API and database ports bind to localhost; only the app port is published for the demo. The Graph API seeds the `pathguard` graph on first use. The Browser is useful for inspecting the same nodes and relationships the API queries.

The frontend is React 19 built by Vite. Docker performs the frontend build, so a local Node installation is not required.

### Deploy with FalkorDB Cloud

The default Compose file runs a local FalkorDB container. For a managed FalkorDB endpoint, put its connection URL in `.env` and use the cloud Compose file:

```sh
# Add FALKORDB_URL=falkors://username:password@host:port to .env
# URL-encode special characters in the credentials.
docker-compose -f docker-compose.cloud.yml up --build -d
```

This mode omits the local database container and keeps the Graph API on the private Compose network; the React app is the only published service. It uses the same graph API and Cypher traversal as the local setup.

To enable optional model summaries, copy `.env.example` to `.env` and add an `OPENAI_API_KEY`. The core analysis and graph-backed summary work without it.

To stop the demo:

```sh
docker-compose down
```

## Optional LLM summary

The app works without an API key. If `OPENAI_API_KEY` is present in the app environment, an OpenAI model can summarize the evidence returned by FalkorDB. The model never writes Cypher, selects arbitrary graph data, or substitutes for the reachability query. Set `OPENAI_MODEL` to change the summary model.

## Graph model

| Label | Purpose | Key properties |
| --- | --- | --- |
| `Principal` | External or cloud identity starting point | `id`, `name`, `kind` |
| `Endpoint` | Reachable ingress point | `id`, `name`, `kind` |
| `Workload` | Service, console, or deployment runner | `id`, `name`, `kind` |
| `Identity` | Cloud role attached to a workload | `id`, `name`, `kind` |
| `Secret` | Credential or secret that can unlock a resource | `id`, `name`, `kind` |
| `DataStore` | Database or storage system | `id`, `name`, `kind` |
| `DataAsset` | Classified information inside a store | `id`, `name`, `kind`, `classification` |

Directed `CAN_ACCESS` relationships carry an `id`, `mechanism`, `evidence`, and `active` flag. This models effective access as a path through distinct entities. `active` is changed by the remediation simulator and read by the Cypher path filter.

## Core Cypher

```cypher
MATCH path = (source:Principal {id: 'internet'})
  -[:CAN_ACCESS*1..8]->(asset:DataAsset {classification: 'restricted'})
WHERE all(access IN relationships(path) WHERE access.active = true)
RETURN
  [node IN nodes(path) | {id: node.id, name: node.name, kind: node.kind}] AS path_nodes,
  [access IN relationships(path) | {
    id: access.id,
    mechanism: access.mechanism,
    evidence: access.evidence
  }] AS path_edges,
  length(path) AS hops
ORDER BY hops ASC
LIMIT 50
```

This variable-length traversal is the central product operation. Every displayed route and remediation check comes from FalkorDB. The source is a graph property model, not an LLM-generated answer or a decorative visualization.

## Backend

- **Pathguard API**: Python 3.12 and FastAPI. `POST /api/investigate`, `POST /api/remediate`, `POST /api/reset`, and `GET /api/health` serve the console.
- **FalkorDB Graph API**: a separate Python/FastAPI container. `GET /v1/analysis` runs the path traversal, `POST /v1/remediate` updates an allowlisted edge, `POST /v1/reset` restores the scenario, and `GET /v1/health` reports database readiness. Interactive OpenAPI docs are available through the app at `/graph-api/docs`; the Graph API container also serves them at `/docs` in local Compose mode.
- The app container does not install the FalkorDB client. Its `GraphAPIClient` uses HTTP and fails closed if the Graph API or database is unavailable.

## Hackathon resource use

The supplied [resource list](https://www.wemakedevs.org/hackathons/falkordb/resources) is a menu, so the project uses the pieces that support its graph-first demo:

- The [FalkorDB Python client](https://github.com/FalkorDB/falkordb-py) is installed only in the Graph API service.
- Docker Compose runs local FalkorDB and its Browser; the optional Cloud Compose file connects to a managed endpoint.
- Cypher expresses the bounded reachability query and the remediation re-check. The Browser at port `3000` can inspect the same graph.

The GraphRAG SDK, graph algorithm catalog, other integrations, community projects, and videos are not current runtime dependencies. The demo centers on a directly verifiable path query and edge revocation, which keeps FalkorDB as the required source of truth.

### Prove the database is required

With the stack running, stop only FalkorDB:

```sh
docker-compose stop falkordb
curl http://localhost:8000/api/health
curl -i http://localhost:8000/api/overview
```

Health reports `falkordb: disconnected`, the UI clears its prior result, and `/api/overview` returns HTTP 503. Restore it with `docker-compose start falkordb`; Pathguard reconnects and queries FalkorDB again.

The API is intentionally limited to the synthetic sample. It is a hackathon demo, not a production cloud security scanner.

## Hackathon submission notes

- Track: **Agents That Act on Connected Data**
- Required graph technology: FalkorDB
- AI coding assistant disclosure: built with OpenAI Codex; all generated code must be reviewed and understood by the team before submission.
- Demo video and public repository still need to be prepared before submitting.

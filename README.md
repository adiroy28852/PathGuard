# Pathguard

**A graph-first security agent that proves whether an exposed identity can reach sensitive data, then checks whether a proposed fix removes every route.**

Pathguard is built for the Graph Hacks challenge. FalkorDB stores the synthetic cloud access model and performs every reachability query. Remediation simulation updates an edge in FalkorDB, then reruns the traversal and reports residual paths. If FalkorDB is unavailable, analysis returns an error; there is no cached or in-memory fallback.

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

Open [http://localhost:8000](http://localhost:8000) for the app and [http://localhost:3000](http://localhost:3000) for FalkorDB Browser. The graph and browser ports bind to localhost so the unauthenticated database is not exposed to the network. The app seeds the `pathguard` graph on first use. The Browser is useful for inspecting the same nodes and relationships the application queries.

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

- Python 3.12, FastAPI, and the official FalkorDB Python client.
- `POST /api/investigate` queries active paths.
- `POST /api/remediate` disables one allowlisted synthetic permission and reruns reachability.
- `POST /api/reset` restores the synthetic scenario.
- `GET /api/health` exposes graph connectivity and graph counts.

The API is intentionally limited to the synthetic sample. It is a hackathon demo, not a production cloud security scanner.

## Hackathon submission notes

- Track: **Agents That Act on Connected Data**
- Required graph technology: FalkorDB
- AI coding assistant disclosure: built with OpenAI Codex; all generated code must be reviewed and understood by the team before submission.
- Demo video and public repository still need to be prepared before submitting.

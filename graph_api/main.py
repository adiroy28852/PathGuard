"""HTTP boundary for every operation that reads or changes FalkorDB."""

from __future__ import annotations

from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .store import GRAPH_NAME, PATH_QUERY, GraphUnavailable, graph_store

app = FastAPI(
    title="Pathguard Graph API",
    description="The only service allowed to query or mutate the FalkorDB graph.",
    version="0.1.0",
)


class RemediateRequest(BaseModel):
    edge_id: Literal["checkout-secret-read", "deploy-secret-read"]


def graph_call(operation):
    try:
        return operation()
    except GraphUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail="FalkorDB is unavailable. The Graph API has no fallback store.",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/")
def root() -> dict[str, str]:
    return {
        "service": "pathguard-graph-api",
        "database": "FalkorDB",
        "docs": "/docs",
        "health": "/v1/health",
    }


@app.get("/v1/health")
def health() -> dict:
    """Report API liveness separately from FalkorDB readiness."""
    try:
        graph_store.ping()
        stats = graph_store.graph_stats()
        return {
            "graph_api": "connected",
            "falkordb": "connected",
            "graph": GRAPH_NAME,
            **stats,
        }
    except GraphUnavailable:
        return {
            "graph_api": "connected",
            "falkordb": "disconnected",
            "graph": GRAPH_NAME,
            "nodes": 0,
            "relationships": 0,
        }


@app.get("/v1/analysis")
def analysis() -> dict:
    """Return the active paths and counts as one graph-backed snapshot."""
    def query_graph() -> dict:
        paths = graph_store.attack_paths()
        stats = graph_store.graph_stats()
        return {"paths": paths, "graph": {"name": GRAPH_NAME, **stats}}

    return graph_call(query_graph)


@app.get("/v1/query")
def query() -> dict[str, str]:
    return {"database": "FalkorDB", "cypher": PATH_QUERY.strip()}


@app.post("/v1/remediate")
def remediate(body: RemediateRequest) -> dict[str, str]:
    return graph_call(lambda: _revoke(body.edge_id))


def _revoke(edge_id: str) -> dict[str, str]:
    graph_store.simulate_revocation(edge_id)
    return {"database": "FalkorDB", "revoked_edge": edge_id}


@app.post("/v1/reset")
def reset() -> dict[str, str]:
    def restore() -> dict[str, str]:
        graph_store.reset_scenario()
        return {"database": "FalkorDB", "status": "reset", "graph": GRAPH_NAME}

    return graph_call(restore)

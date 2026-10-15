"""HTTP boundary for every operation that reads or changes FalkorDB."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from .store import GRAPH_NAME, PATH_QUERY, GraphUnavailable, graph_store

app = FastAPI(
    title="Pathguard Graph API",
    description="The only service allowed to query or mutate the FalkorDB graph.",
    version="0.1.0",
)


class RemediateRequest(BaseModel):
    edge_id: Literal["checkout-secret-read", "deploy-secret-read"]


class SiteQuestionRequest(BaseModel):
    site_host: str
    scan_id: str
    question: str


class SiteRemediateRequest(BaseModel):
    site_host: str
    scan_id: str
    finding_id: str


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


@app.post("/v1/sites/scan")
def ingest_site_scan(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Persist an observed website snapshot as a separate FalkorDB graph."""
    return graph_call(lambda: graph_store.ingest_site_scan(snapshot))


@app.post("/v1/sites/question")
def answer_site_question(body: SiteQuestionRequest) -> dict[str, Any]:
    if len(body.question) > 500:
        raise HTTPException(status_code=400, detail="Question must be 500 characters or fewer.")
    return graph_call(lambda: graph_store.answer_site_question(body.site_host, body.scan_id, body.question))


@app.get("/v1/sites/history")
def site_history(site_host: str = Query(min_length=1, max_length=253)) -> dict[str, Any]:
    return graph_call(lambda: {"site_host": site_host, "scans": graph_store.site_history(site_host)})


@app.get("/v1/sites/scan")
def load_site_scan(site_host: str = Query(min_length=1, max_length=253), scan_id: str = Query(min_length=1, max_length=64)) -> dict[str, Any]:
    return graph_call(lambda: graph_store.load_site_scan(site_host, scan_id))


@app.post("/v1/sites/remediate")
def simulate_site_remediation(body: SiteRemediateRequest) -> dict[str, Any]:
    return graph_call(lambda: graph_store.simulate_site_remediation(body.site_host, body.scan_id, body.finding_id))

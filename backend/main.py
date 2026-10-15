"""Pathguard FastAPI application."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .agent import PathguardAgent
from .graph_store import GraphUnavailable, graph_store


BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
agent = PathguardAgent(graph_store)

app = FastAPI(
    title="Pathguard",
    description="A graph-first agent that finds and verifies attack paths in FalkorDB.",
    version="0.1.0",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class InvestigateRequest(BaseModel):
    question: str = Field(default="Can the public internet reach customer PII?", min_length=3, max_length=240)
    source_id: Literal["internet"] = "internet"


class RemediateRequest(BaseModel):
    edge_id: Literal["checkout-secret-read", "deploy-secret-read"]


def graph_call(operation):
    try:
        return operation()
    except GraphUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail="FalkorDB is unavailable. Pathguard cannot analyze reachability without its graph.",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/")
def home() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> dict:
    try:
        graph_store.ping()
        stats = graph_store.graph_stats()
        return {"status": "connected", "graph": "pathguard", **stats}
    except GraphUnavailable:
        return {"status": "disconnected", "graph": "pathguard", "message": "Graph required for analysis"}


@app.get("/api/overview")
def overview() -> dict:
    return graph_call(lambda: agent.investigate())


@app.post("/api/investigate")
def investigate(body: InvestigateRequest) -> dict:
    # source_id is a Literal so the user cannot inject Cypher through the query planner.
    return graph_call(lambda: agent.investigate(body.question.strip()))


@app.post("/api/remediate")
def remediate(body: RemediateRequest) -> dict:
    return graph_call(lambda: agent.simulate(body.edge_id))


@app.post("/api/reset")
def reset() -> dict:
    return graph_call(agent.reset)

"""Pathguard HTTP backend and React static asset host."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .agent import PathguardAgent
from .graph_client import GraphUnavailable, graph_api


BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend" / "dist"
ASSETS_DIR = FRONTEND_DIR / "assets"
agent = PathguardAgent(graph_api)

app = FastAPI(
    title="Pathguard API",
    description="Application API for the React Pathguard console.",
    version="0.2.0",
)
app.mount("/assets", StaticFiles(directory=ASSETS_DIR, check_dir=False), name="assets")


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
            detail="Graph API/FalkorDB is unavailable. Pathguard cannot analyze without the graph.",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/", include_in_schema=False)
def home() -> FileResponse:
    index = FRONTEND_DIR / "index.html"
    if not index.is_file():
        raise HTTPException(status_code=503, detail="React frontend has not been built")
    return FileResponse(index)


@app.get("/graph-api/docs", include_in_schema=False)
def graph_api_docs():
    return get_swagger_ui_html(
        openapi_url="/graph-api/openapi.json",
        title="Pathguard Graph API",
    )


@app.get("/graph-api/openapi.json", include_in_schema=False)
def graph_api_openapi() -> dict:
    return graph_call(graph_api.openapi_schema)


@app.get("/api/health")
def health() -> dict:
    status = graph_api.health()
    status["status"] = "connected" if status.get("falkordb") == "connected" else "disconnected"
    return status


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

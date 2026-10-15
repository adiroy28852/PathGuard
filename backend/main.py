"""Pathguard HTTP backend and React static asset host."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .agent import PathguardAgent
from .graph_client import GraphUnavailable, graph_api
from .scanner import ScanInputError, scan_website


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


class WebsiteScanRequest(BaseModel):
    target_url: str = Field(min_length=8, max_length=2048)
    artifact_type: Literal["har", "openapi", "sarif"] | None = None
    artifact_content: str | None = Field(default=None, max_length=2_000_000)


class WebsiteQuestionRequest(BaseModel):
    site_host: str = Field(min_length=1, max_length=253)
    scan_id: str = Field(min_length=1, max_length=64)
    question: str = Field(min_length=3, max_length=500)


class WebsiteRemediateRequest(BaseModel):
    site_host: str = Field(min_length=1, max_length=253)
    scan_id: str = Field(min_length=1, max_length=64)
    finding_id: str = Field(min_length=1, max_length=64)


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


@app.post("/api/sites/scan")
def scan_site(body: WebsiteScanRequest) -> dict[str, Any]:
    try:
        snapshot = scan_website(body.target_url, body.artifact_type, body.artifact_content)
    except ScanInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = graph_call(lambda: graph_api.ingest_site_scan(snapshot))
    result["summary"] = (
        f"FalkorDB saved {result['route_count']} observed route(s), {result['endpoint_count']} API endpoint(s), "
        f"{result['dependency_count']} loaded external resource(s), {result.get('interaction_count', 0)} traffic signal(s), "
        f"and {result['finding_count']} evidence finding(s) for {result['site_host']}. "
        f"Page-load behavior pass: {(result.get('browser_runtime') or {}).get('status', 'not recorded')}. "
        "These are observations from this scan, not proof of exploitability."
    )
    result["model_summary"] = False
    return result


@app.post("/api/sites/question")
def ask_about_site(body: WebsiteQuestionRequest) -> dict[str, Any]:
    return graph_call(lambda: agent.answer_site_question(body.site_host, body.scan_id, body.question.strip()))


@app.get("/api/sites/history")
def site_scan_history(site_host: str = Query(min_length=1, max_length=253)) -> dict[str, Any]:
    return graph_call(lambda: graph_api.site_history(site_host))


@app.get("/api/sites/scan")
def load_site_scan(site_host: str = Query(min_length=1, max_length=253), scan_id: str = Query(min_length=1, max_length=64)) -> dict[str, Any]:
    result = graph_call(lambda: graph_api.load_site_scan(site_host, scan_id))
    result["summary"] = (
        f"Loaded the saved FalkorDB snapshot for {result['site_host']}: {result['route_count']} routes, "
        f"{result['endpoint_count']} API endpoints, {result['dependency_count']} loaded external resources, "
        f"{result.get('interaction_count', 0)} traffic signals, and {result['finding_count']} evidence findings; "
        f"page-load behavior pass: {(result.get('browser_runtime') or {}).get('status', 'not recorded')}."
    )
    result["model_summary"] = False
    return result


@app.post("/api/sites/remediate")
def remediate_site_finding(body: WebsiteRemediateRequest) -> dict[str, Any]:
    return graph_call(lambda: graph_api.simulate_site_remediation(body.site_host, body.scan_id, body.finding_id))

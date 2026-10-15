"""HTTP client for the separate FalkorDB Graph API service."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


class GraphUnavailable(RuntimeError):
    """Raised when the graph service or its required FalkorDB is unavailable."""


class GraphAPIClient:
    """Backend-to-graph-service client; the backend never opens a FalkorDB socket."""

    def __init__(self) -> None:
        self.base_url = os.getenv("GRAPH_API_URL", "http://graph-api:8100").rstrip("/")
        self.timeout = float(os.getenv("GRAPH_API_TIMEOUT_SECONDS", "5"))

    def _request(self, path: str, method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers={"Content-Type": "application/json"},
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                response_body = json.loads(exc.read().decode("utf-8"))
                detail = response_body.get("detail", "Graph API request failed")
            except (ValueError, AttributeError):
                detail = "Graph API request failed"
            raise GraphUnavailable(f"{detail} (HTTP {exc.code})") from exc
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise GraphUnavailable(
                "Pathguard Graph API is unavailable. FalkorDB is required for analysis."
            ) from exc

    def analysis(self) -> dict[str, Any]:
        return self._request("/v1/analysis")

    def openapi_schema(self) -> dict[str, Any]:
        return self._request("/openapi.json")

    def health(self) -> dict[str, Any]:
        try:
            return self._request("/v1/health")
        except GraphUnavailable as exc:
            return {
                "graph_api": "disconnected",
                "falkordb": "unknown",
                "graph": "pathguard",
                "nodes": 0,
                "relationships": 0,
                "message": str(exc),
            }

    def revoke_edge(self, edge_id: str) -> None:
        self._request("/v1/remediate", "POST", {"edge_id": edge_id})

    def reset_scenario(self) -> None:
        self._request("/v1/reset", "POST", {})

    def ingest_site_scan(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        return self._request("/v1/sites/scan", "POST", snapshot)

    def answer_site_question(self, site_host: str, scan_id: str, question: str) -> dict[str, Any]:
        return self._request("/v1/sites/question", "POST", {"site_host": site_host, "scan_id": scan_id, "question": question})

    def site_history(self, site_host: str) -> dict[str, Any]:
        from urllib.parse import urlencode

        return self._request(f"/v1/sites/history?{urlencode({'site_host': site_host})}")

    def load_site_scan(self, site_host: str, scan_id: str) -> dict[str, Any]:
        from urllib.parse import urlencode

        return self._request(f"/v1/sites/scan?{urlencode({'site_host': site_host, 'scan_id': scan_id})}")

    def simulate_site_remediation(self, site_host: str, scan_id: str, finding_id: str) -> dict[str, Any]:
        return self._request("/v1/sites/remediate", "POST", {"site_host": site_host, "scan_id": scan_id, "finding_id": finding_id})


graph_api = GraphAPIClient()

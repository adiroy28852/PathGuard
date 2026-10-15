"""Graph-first security agent: query paths, recommend controls, verify residual risk."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from .graph_store import GraphStore


FIXES = {
    "checkout-secret-read": {
        "title": "Remove the Checkout API's direct secret access",
        "detail": "Replace the broad read permission with the narrow credential access the checkout flow needs.",
        "target": "Checkout Runtime Role → Payments Production Secret",
    },
    "deploy-secret-read": {
        "title": "Remove the deployment role's standing secret access",
        "detail": "Use a short-lived deployment credential and keep production secret reads out of the runner role.",
        "target": "Deployment Role → Payments Production Secret",
    },
}


class PathguardAgent:
    """A constrained tool-using agent whose findings are always derived from FalkorDB."""

    def __init__(self, store: GraphStore) -> None:
        self.store = store

    def investigate(self, question: str = "Can the public internet reach customer PII?") -> dict[str, Any]:
        normalized = question.casefold()
        if not any(term in normalized for term in ("internet", "public", "external", "outside", "attacker")):
            raise ValueError("This demo currently traces access from the public Internet.")
        if not any(term in normalized for term in ("pii", "customer", "restricted", "sensitive", "personal", "data")):
            raise ValueError("This demo currently checks reachability to restricted customer data.")
        paths = self.store.attack_paths()
        recommendations = self._recommend(paths)
        stats = self.store.graph_stats()
        summary = self._grounded_summary(paths, question)
        model_used = False
        ai_summary = self._optional_model_summary(question, paths)
        if ai_summary:
            summary = ai_summary
            model_used = True

        return {
            "question": question,
            "summary": summary,
            "risk": "CRITICAL" if paths else "NO ACTIVE PATH FOUND",
            "path_count": len(paths),
            "paths": paths,
            "recommendations": recommendations,
            "graph": {"name": "pathguard", **stats},
            "model_summary": model_used,
            "notice": "Synthetic demo graph. No live cloud account is connected.",
        }

    def simulate(self, edge_id: str) -> dict[str, Any]:
        if edge_id not in FIXES:
            raise ValueError("Unknown remediation")
        self.store.simulate_revocation(edge_id)
        result = self.investigate()
        result["simulated_fix"] = FIXES[edge_id]
        result["residual_risk"] = "CRITICAL" if result["path_count"] else "NO ACTIVE PATH FOUND"
        return result

    def reset(self) -> dict[str, Any]:
        self.store.reset_scenario()
        return self.investigate()

    @staticmethod
    def _recommend(paths: list[dict[str, Any]]) -> list[dict[str, str]]:
        active_edges = {edge.get("id") for path in paths for edge in path["edges"]}
        return [
            {"edge_id": edge_id, **fix}
            for edge_id, fix in FIXES.items()
            if edge_id in active_edges
        ]

    @staticmethod
    def _grounded_summary(paths: list[dict[str, Any]], question: str) -> str:
        if not paths:
            return (
                "FalkorDB found no active path from the public Internet to restricted data "
                "in this synthetic graph. This describes the modeled graph only."
            )
        shortest = min(paths, key=lambda path: path["hops"])
        chain = " → ".join(node["name"] for node in shortest["nodes"])
        return (
            f"FalkorDB found {len(paths)} active route(s) from the public Internet to restricted data. "
            f"The shortest is {shortest['hops']} relationships: {chain}. "
            "Every remaining route passes through the production secret and database, so revoke each exposed identity's "
            "secret-reader edge and re-check for residual routes."
        )

    @staticmethod
    def _optional_model_summary(question: str, paths: list[dict[str, Any]]) -> str | None:
        """Summarize graph evidence when a key exists; never query the model without graph results."""
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return None

        evidence = {
            "question": question,
            "active_path_count": len(paths),
            "paths": [
                {
                    "nodes": [node["name"] for node in path["nodes"]],
                    "edges": [edge["mechanism"] for edge in path["edges"]],
                    "hops": path["hops"],
                }
                for path in paths
            ],
            "available_remediation_ids": list(FIXES),
        }
        body = {
            "model": os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
            "instructions": (
                "You are Pathguard, a defensive security analyst. Use only the supplied FalkorDB result. "
                "Do not claim the real cloud is safe or compromised; this is a synthetic graph snapshot. "
                "Explain the strongest path and remaining risk in at most 3 short sentences. "
                "If the path count is zero, say only that no active route exists in the modeled graph."
            ),
            "input": json.dumps(evidence),
            "max_output_tokens": 180,
        }
        request = urllib.request.Request(
            "https://api.openai.com/v1/responses",
            data=json.dumps(body).encode("utf-8"),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                payload = json.loads(response.read().decode("utf-8"))
            for item in payload.get("output", []):
                if item.get("type") != "message":
                    continue
                for content in item.get("content", []):
                    if content.get("type") == "output_text" and content.get("text"):
                        return content["text"].strip()
        except (OSError, ValueError, urllib.error.URLError, KeyError, TypeError):
            # Graph evidence remains usable when the optional model service is unavailable.
            return None
        return None


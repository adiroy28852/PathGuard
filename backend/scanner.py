"""Bounded, read-only website discovery for graph ingestion."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any


MAX_PAGES = 12
MAX_BODY_BYTES = 1_000_000
MAX_SCRIPT_BYTES = 1_000_000
USER_AGENT = "Pathguard-ReadOnly-Discovery/0.1"


class ScanInputError(ValueError):
    pass


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScanInputError("Enter a complete http:// or https:// website URL.")
    if parsed.username or parsed.password:
        raise ScanInputError("URLs containing embedded credentials are not supported.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ScanInputError("The target URL has an invalid port.") from exc
    if port not in {80, 443}:
        raise ScanInputError("Only standard HTTP and HTTPS ports are allowed.")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ScanInputError("The target hostname is invalid.") from exc
    return parsed.scheme, host, port


def _assert_public_host(host: str) -> None:
    if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local")):
        raise ScanInputError("The target must be a publicly resolvable website.")
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ScanInputError("The target hostname could not be resolved.") from exc
    addresses = {answer[4][0].split("%", 1)[0] for answer in answers}
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ScanInputError("The target must resolve only to public IP addresses.")


def _normalize_url(url: str, base: str) -> str | None:
    absolute = urllib.parse.urljoin(base, url.strip())
    parsed = urllib.parse.urlsplit(absolute)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return urllib.parse.urlunsplit(parsed)


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.in_title = False
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, str]] = []
        self.form: dict[str, str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "title":
            self.in_title = True
        elif tag.lower() == "a" and values.get("href"):
            self.links.append(values["href"])
        elif tag.lower() == "script" and values.get("src"):
            self.scripts.append(values["src"])
        elif tag.lower() == "form":
            self.form = {"action": values.get("action", ""), "method": values.get("method", "GET").upper()}
            self.forms.append(self.form)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False
        elif tag.lower() == "form":
            self.form = None

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data.strip())


class _ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, expected_origin: tuple[str, str, int]) -> None:
        super().__init__()
        self.expected_origin = expected_origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urljoin(req.full_url, newurl)
        if _origin(target) != self.expected_origin:
            raise ScanInputError("Discovery stopped at a redirect outside the target origin.")
        return super().redirect_request(req, fp, code, msg, headers, target)


def _fetch(url: str, expected_origin: tuple[str, str, int], limit: int = MAX_BODY_BYTES) -> tuple[str, int, str, dict[str, str], bytes] | None:
    current = url
    for _ in range(4):
        if _origin(current) != expected_origin:
            raise ScanInputError("Discovery stopped at a redirect outside the target origin.")
        _assert_public_host(expected_origin[1])
        request = urllib.request.Request(current, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/javascript,*/*;q=0.5"})
        opener = urllib.request.build_opener(urllib.request.HTTPHandler(), urllib.request.HTTPSHandler(), _ScopedRedirectHandler(expected_origin))
        try:
            response = opener.open(request, timeout=5)
        except urllib.error.HTTPError as exc:
            if exc.code in {301, 302, 303, 307, 308}:
                location = exc.headers.get("Location")
                if not location:
                    return None
                current = urllib.parse.urljoin(current, location)
                continue
            return (current, exc.code, exc.headers.get("Content-Type", ""), {k.lower(): v for k, v in exc.headers.items()}, b"")
        except (urllib.error.URLError, TimeoutError, OSError):
            return None
        with response:
            final_url = response.geturl()
            if _origin(final_url) != expected_origin:
                raise ScanInputError("Discovery stopped at a redirect outside the target origin.")
            body = response.read(limit + 1)
            if len(body) > limit:
                body = body[:limit]
            return (
                final_url,
                int(response.status),
                response.headers.get("Content-Type", ""),
                {k.lower(): v for k, v in response.headers.items()},
                body,
            )
    raise ScanInputError("The target redirected too many times.")


def _endpoint(url: str, method: str, source_url: str, evidence: str, status: int | None = None) -> dict[str, Any]:
    return {"url": url, "method": method.upper(), "source_url": source_url, "evidence": evidence, "status": status}


def _parse_artifact(kind: str, content: str, base_url: str) -> dict[str, list[dict[str, Any]]]:
    if len(content.encode("utf-8")) > 2_000_000:
        raise ScanInputError("Evidence files must be smaller than 2 MB.")
    try:
        artifact = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ScanInputError("Evidence import must be valid JSON (HAR, OpenAPI JSON, or SARIF).") from exc
    result: dict[str, list[dict[str, Any]]] = {"api_endpoints": [], "dependencies": [], "findings": []}
    kind = kind.lower()
    if kind == "har":
        entries = artifact.get("log", {}).get("entries", [])
        for entry in entries[:5000]:
            request = entry.get("request", {})
            url = request.get("url", "")
            parsed = urllib.parse.urlsplit(url)
            if not parsed.hostname:
                continue
            if parsed.hostname.lower() == urllib.parse.urlsplit(base_url).hostname.lower():
                result["api_endpoints"].append(_endpoint(url, request.get("method", "GET"), _header(request, "referer") or base_url, "Imported from browser HAR", entry.get("response", {}).get("status")))
            else:
                result["dependencies"].append({"url": f"{parsed.scheme}://{parsed.netloc}", "host": parsed.hostname.lower(), "source_url": _header(request, "referer") or base_url, "kind": "HAR request", "evidence": f"Observed {request.get('method', 'GET')} request"})
    elif kind == "openapi":
        servers = artifact.get("servers", [])
        server = urllib.parse.urljoin(base_url, servers[0].get("url", "")) if servers else base_url
        for path, operations in artifact.get("paths", {}).items():
            if not isinstance(operations, dict):
                continue
            for method, operation in operations.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"}:
                    continue
                url = urllib.parse.urljoin(server.rstrip("/") + "/", path.lstrip("/"))
                result["api_endpoints"].append(_endpoint(url, method.upper(), base_url, f"OpenAPI operation: {operation.get('summary') or operation.get('operationId') or path}"))
    elif kind == "sarif":
        rules = {}
        for run in artifact.get("runs", []):
            rules.update({rule.get("id"): rule for rule in run.get("tool", {}).get("driver", {}).get("rules", [])})
            for finding in run.get("results", []):
                rule_id = finding.get("ruleId", "unknown")
                rule = rules.get(rule_id, {})
                location = next(iter(finding.get("locations", [])), {}).get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                message = finding.get("message", {}).get("text", rule.get("shortDescription", {}).get("text", rule_id))
                result["findings"].append({"id": hashlib.sha256(f"{rule_id}|{location}|{message}".encode()).hexdigest()[:20], "title": rule.get("name") or rule_id, "severity": finding.get("level", "warning").upper(), "uri": urllib.parse.urljoin(base_url, location), "evidence": message, "rule_id": rule_id, "source": "SARIF import"})
    else:
        raise ScanInputError("Choose a supported JSON evidence type: HAR, OpenAPI, or SARIF.")
    return result


def _header(request: dict[str, Any], name: str) -> str:
    for header in request.get("headers", []):
        if header.get("name", "").lower() == name:
            return header.get("value", "")
    return ""


def _source_observations(source: str, source_url: str, target_url: str, origin: tuple[str, str, int], endpoint_map: dict, dependency_map: dict) -> list[str]:
    """Extract likely app routes and API client references from first-party source."""
    api_bases: set[str] = set()
    api_base_vars: dict[str, str] = {}
    api_clients: dict[str, str] = {}
    for match in re.finditer(r"(?:^|[,;])([A-Za-z_$][\w$]*)\s*=\s*['\"](https?://[^'\"]+)['\"]", source):
        raw = match.group(2).rstrip("/")
        parsed = urllib.parse.urlsplit(raw)
        if parsed.hostname and parsed.hostname.lower().startswith("api."):
            api_base_vars[match.group(1)] = raw
    for match in re.finditer(r"(?:^|[,;])([A-Za-z_$][\w$]*)\s*=\s*[A-Za-z_$][\w$]*\.create\(\{.{0,500}?baseURL\s*:\s*([A-Za-z_$][\w$]*)", source, re.DOTALL):
        base = api_base_vars.get(match.group(2))
        if base:
            api_clients[match.group(1)] = base
    for match in re.finditer(r"https?://[^\s\"'`<>]+", source, re.IGNORECASE):
        raw = match.group(0).rstrip(".,);}")
        try:
            parsed = urllib.parse.urlsplit(raw)
        except ValueError:
            continue
        if not parsed.hostname or parsed.hostname.lower() == origin[1]:
            continue
        host = parsed.hostname.lower()
        if host.startswith("api."):
            if "${" not in raw:
                api_bases.add(raw.rstrip("/"))
                endpoint_map.setdefault(("GET", raw.rstrip("/")), _endpoint(raw.rstrip("/"), "GET", source_url, "External API base URL referenced in first-party source"))
            continue
        context = source[max(0, match.start() - 60):match.start()]
        if re.search(r"(?:src|href)\s*:\s*(?:`|['\"])?$", context, re.IGNORECASE):
            dependency_map[(host, "runtime asset")] = {"url": f"{parsed.scheme}://{parsed.netloc}", "host": host, "source_url": source_url, "kind": "runtime asset", "evidence": "External asset URL referenced in first-party source"}

    for client, base in api_clients.items():
        pattern = re.compile(rf"\b{re.escape(client)}\.(get|post|put|patch|delete|options|head)\(\s*([`\"'])([^`\"']{{1,240}})\2", re.IGNORECASE)
        for call in pattern.finditer(source):
            request_path = call.group(3)
            if not request_path.startswith("/"):
                continue
            full_url = base.rstrip("/") + request_path
            method = call.group(1).upper()
            endpoint_map.setdefault((method, full_url), _endpoint(full_url, method, source_url, "API client request path in first-party source"))

    route_paths = re.findall(r"(?:to|linkTo)\s*:\s*['\"](/[^'\"?#]{1,120})['\"]", source)
    hash_router = bool(re.search(r"hashchange|location\.hash|HashRouter|createHashRouter", source, re.IGNORECASE))
    routes: list[str] = []
    seen: set[str] = set()
    for route_path in route_paths:
        if route_path.startswith(("/api/", "/assets/", "/node_modules/")) or route_path in seen:
            continue
        seen.add(route_path)
        if hash_router:
            root = urllib.parse.urlsplit(target_url)
            routes.append(urllib.parse.urlunsplit((root.scheme, root.netloc, root.path or "/", "", route_path)))
        else:
            routes.append(urllib.parse.urljoin(source_url, route_path))
    return routes


def scan_website(target_url: str, artifact_type: str | None = None, artifact_content: str | None = None) -> dict[str, Any]:
    target_url = target_url.strip()
    if len(target_url) > 2048:
        raise ScanInputError("Target URL is too long.")
    origin = _origin(target_url)
    _assert_public_host(origin[1])
    parsed_target = urllib.parse.urlsplit(target_url)
    target_url = urllib.parse.urlunsplit((origin[0], parsed_target.netloc, parsed_target.path or "/", parsed_target.query, parsed_target.fragment))
    scan_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    pages: dict[str, dict[str, Any]] = {}
    endpoint_map: dict[tuple[str, str], dict[str, Any]] = {}
    dependency_map: dict[tuple[str, str], dict[str, Any]] = {}
    queue = deque([target_url])
    visited: set[str] = set()
    script_urls: set[str] = set()
    while queue and len(pages) < MAX_PAGES:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        if _origin(url) != origin:
            continue
        fetched = _fetch(urllib.parse.urldefrag(url)[0], origin)
        if not fetched:
            continue
        final_url, status, content_type, headers, body = fetched
        if "html" not in content_type.lower() and not body.lstrip().startswith(b"<!DOCTYPE html") and b"<html" not in body[:1000].lower():
            continue
        parser = _PageParser()
        source = body.decode("utf-8", errors="replace")
        parser.feed(source)
        page_url = urllib.parse.urldefrag(url)[0]
        title = " ".join(" ".join(parser.title_parts).split())
        anchors: list[str] = []
        forms: list[dict[str, str]] = []
        for candidate in parser.links:
            normalized = _normalize_url(candidate, page_url)
            if not normalized:
                continue
            if _origin(normalized) == origin:
                anchors.append(normalized)
            else:
                ext = urllib.parse.urlsplit(normalized)
                dependency_map[(ext.hostname.lower(), "link")] = {"url": f"{ext.scheme}://{ext.netloc}", "host": ext.hostname.lower(), "source_url": page_url, "kind": "link", "evidence": "External link observed in page"}
        for form in parser.forms:
            action = _normalize_url(form["action"] or page_url, page_url)
            if action:
                forms.append({"action": action, "method": form["method"]})
                if _origin(action) == origin:
                    endpoint_map[(form["method"], action)] = _endpoint(action, form["method"], page_url, "HTML form action")
        page = {"url": page_url, "title": title, "status": status, "content_type": content_type, "headers": headers, "scripts": [], "forms": forms, "links": anchors}
        pages[page_url] = page
        for candidate in anchors:
            if urllib.parse.urlsplit(candidate).fragment:
                if len(pages) < MAX_PAGES:
                    pages.setdefault(candidate, {"url": candidate, "title": title, "status": status, "content_type": "client-side route", "headers": headers, "scripts": [], "forms": [], "links": []})
            else:
                queue.append(candidate)
        for script in parser.scripts:
            normalized = _normalize_url(script, page_url)
            if not normalized:
                continue
            if _origin(normalized) == origin:
                script_urls.add(urllib.parse.urldefrag(normalized)[0])
                page["scripts"].append(normalized)
            else:
                ext = urllib.parse.urlsplit(normalized)
                dependency_map[(ext.hostname.lower(), "script")] = {"url": f"{ext.scheme}://{ext.netloc}", "host": ext.hostname.lower(), "source_url": page_url, "kind": "script", "evidence": "External script source observed in page"}
        # Keep passively observed security-header findings and exact source evidence.
        required_headers = [("content-security-policy", "Content Security Policy"), ("x-content-type-options", "X-Content-Type-Options"), ("referrer-policy", "Referrer Policy")]
        if origin[0] == "https":
            required_headers.append(("strict-transport-security", "Strict-Transport-Security"))
        for header, label in required_headers:
            if header not in headers:
                fid = hashlib.sha256(f"{page_url}|{header}".encode()).hexdigest()[:20]
                page.setdefault("findings", []).append({"id": fid, "title": f"{label} header not observed", "severity": "INFO", "uri": page_url, "evidence": f"The response did not include the {label} header.", "rule_id": f"headers/{header}", "source": "Passive response-header observation"})
        for discovered_route in _source_observations(source, page_url, target_url, origin, endpoint_map, dependency_map):
            if len(pages) < MAX_PAGES:
                pages.setdefault(discovered_route, {"url": discovered_route, "title": "Client-side route", "status": 200, "content_type": "client-side route", "headers": {}, "scripts": [], "forms": [], "links": []})

    # Fetch a bounded number of first-party scripts only; no external code is executed.
    for script_url in list(script_urls)[:20]:
        fetched = _fetch(script_url, origin, MAX_SCRIPT_BYTES)
        if not fetched:
            continue
        final_url, _, _, _, body = fetched
        source = body.decode("utf-8", errors="replace")
        for discovered_route in _source_observations(source, final_url, target_url, origin, endpoint_map, dependency_map):
            if len(pages) < MAX_PAGES:
                pages.setdefault(discovered_route, {"url": discovered_route, "title": "Client-side route", "status": 200, "content_type": "client-side route", "headers": {}, "scripts": [], "forms": [], "links": []})

    combined: dict[str, list[dict[str, Any]]] = {"api_endpoints": list(endpoint_map.values()), "dependencies": list(dependency_map.values()), "findings": [finding for page in pages.values() for finding in page.get("findings", [])]}
    artifact_info = None
    if artifact_type and artifact_content:
        imported = _parse_artifact(artifact_type, artifact_content, target_url)
        combined["api_endpoints"].extend(imported["api_endpoints"])
        combined["dependencies"].extend(imported["dependencies"])
        combined["findings"].extend(imported["findings"])
        artifact_info = {"type": artifact_type, "records": sum(len(items) for items in imported.values())}
    # Stable de-duplication keeps repeated page references from creating duplicate nodes.
    combined["api_endpoints"] = list({(item["method"], item["url"]): item for item in combined["api_endpoints"]}.values())
    combined["dependencies"] = list({(item["host"], item["kind"]): item for item in combined["dependencies"]}.values())
    combined["findings"] = list({item["id"]: item for item in combined["findings"]}.values())
    return {
        "scan_id": scan_id,
        "target_url": target_url,
        "site_host": origin[1],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "scope": "Same-origin, read-only discovery; no forms submitted and no external hosts fetched.",
        "pages": list(pages.values())[:MAX_PAGES],
        **combined,
        "artifact": artifact_info,
        "limits": {"max_pages": MAX_PAGES, "max_page_bytes": MAX_BODY_BYTES, "max_first_party_scripts": 20},
    }

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
from time import monotonic
from typing import Any


MAX_PAGES = 12
MAX_INTERACTIONS = 250
MAX_BODY_BYTES = 1_000_000
MAX_SCRIPT_BYTES = 1_000_000
MAX_BROWSER_REQUESTS = 100
MAX_POPUP_PAGES = 10
RUNTIME_SETTLE_MS = 1500
RUNTIME_TIMEOUT_MS = 12000
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
    try:
        absolute = urllib.parse.urljoin(base, url.strip())
        parsed = urllib.parse.urlsplit(absolute)
        # Do not crawl destinations with embedded usernames or passwords.
        if parsed.username or parsed.password:
            return None
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return urllib.parse.urlunsplit(parsed)


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.in_title = False
        self.links: list[dict[str, str]] = []
        self.scripts: list[str] = []
        self.inline_scripts: list[str] = []
        self._script_parts: list[str] | None = None
        self.iframes: list[str] = []
        self.refreshes: list[str] = []
        self.forms: list[dict[str, str]] = []
        self.form: dict[str, str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "title":
            self.in_title = True
        elif tag.lower() in {"a", "area"} and values.get("href"):
            self.links.append({"url": values["href"], "target": values.get("target", ""), "onclick": values.get("onclick", ""), "element": tag.lower()})
        elif tag.lower() == "script":
            if values.get("src"):
                self.scripts.append(values["src"])
            else:
                self._script_parts = []
        elif tag.lower() == "iframe" and values.get("src"):
            self.iframes.append(values["src"])
        elif tag.lower() == "meta" and values.get("http-equiv", "").casefold() == "refresh":
            match = re.search(r"(?:^|;)\s*url\s*=\s*['\"]?(.+?)['\"]?\s*$", values.get("content", ""), re.IGNORECASE)
            if match:
                self.refreshes.append(match.group(1).strip())
        elif tag.lower() == "form":
            self.form = {"action": values.get("action", ""), "method": values.get("method", "GET").upper()}
            self.forms.append(self.form)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False
        elif tag.lower() == "form":
            self.form = None
        elif tag.lower() == "script" and self._script_parts is not None:
            self.inline_scripts.append("".join(self._script_parts))
            self._script_parts = None

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data.strip())
        if self._script_parts is not None:
            self._script_parts.append(data)


class _NoFollowRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Redirects are followed manually so every hop is recorded and off-origin
        # destinations are never fetched.
        return None


def _same_origin(url: str, expected_origin: tuple[str, str, int]) -> bool:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".") if parsed.hostname else ""
        return (parsed.scheme, host, port) == expected_origin and not parsed.username and not parsed.password
    except (ValueError, UnicodeError):
        return False


def _fetch(url: str, expected_origin: tuple[str, str, int], limit: int = MAX_BODY_BYTES) -> tuple[str, int, str, dict[str, str], bytes, list[dict[str, Any]]] | None:
    current = url
    redirects: list[dict[str, Any]] = []
    for _ in range(6):
        if not _same_origin(current, expected_origin):
            break
        _assert_public_host(expected_origin[1])
        request = urllib.request.Request(current, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/javascript,*/*;q=0.5"})
        opener = urllib.request.build_opener(urllib.request.HTTPHandler(), urllib.request.HTTPSHandler(), _NoFollowRedirectHandler())
        try:
            response = opener.open(request, timeout=5)
        except urllib.error.HTTPError as exc:
            if exc.code in {301, 302, 303, 307, 308}:
                location = exc.headers.get("Location")
                if not location:
                    return (current, exc.code, exc.headers.get("Content-Type", ""), {k.lower(): v for k, v in exc.headers.items()}, b"", redirects)
                target = _normalize_url(location, current)
                if not target:
                    return (current, exc.code, "redirect", {k.lower(): v for k, v in exc.headers.items()}, b"", redirects)
                same_origin = _same_origin(target, expected_origin)
                redirects.append({"source_url": current, "target_url": target, "status": exc.code, "same_origin": same_origin, "evidence": f"HTTP {exc.code} Location response"})
                if not same_origin:
                    return (current, exc.code, "redirect", {k.lower(): v for k, v in exc.headers.items()}, b"", redirects)
                current = target
                continue
            return (current, exc.code, exc.headers.get("Content-Type", ""), {k.lower(): v for k, v in exc.headers.items()}, b"", redirects)
        except (urllib.error.URLError, TimeoutError, OSError):
            return None
        with response:
            final_url = response.geturl()
            if not _same_origin(final_url, expected_origin):
                return (current, int(response.status), "redirect", {k.lower(): v for k, v in response.headers.items()}, b"", redirects)
            body = response.read(limit + 1)
            if len(body) > limit:
                body = body[:limit]
            return (
                final_url,
                int(response.status),
                response.headers.get("Content-Type", ""),
                {k.lower(): v for k, v in response.headers.items()},
                body,
                redirects,
            )
    return (current, 310, "redirect loop/limit", {}, b"", redirects)


def _registrable_domain(host: str) -> str:
    labels = host.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return host.lower()
    compound_suffixes = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.in", "com.br", "co.jp", "com.sg", "co.nz"}
    suffix = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if suffix in compound_suffixes and len(labels) >= 3 else suffix


_ROLE_PATTERNS = (
    ("advertising", ("doubleclick", "googlesyndication", "adservice", "taboola", "outbrain", "criteo", "adroll", "adsystem", "adserver")),
    ("analytics", ("google-analytics", "googletagmanager", "segment", "amplitude", "mixpanel", "hotjar", "clarity", "fullstory", "plausible", "matomo", "analytics")),
    ("identity", ("auth0", "okta", "cognito", "clerk", "identity", "login", "accounts.google", "microsoftonline")),
    ("payment", ("stripe", "paypal", "razorpay", "checkout", "adyen", "braintree")),
    ("content_delivery", ("cloudfront", "fastly", "jsdelivr", "unpkg", "cloudflare", "gstatic", "fonts.googleapis", "akamai")),
    ("social", ("facebook", "instagram", "linkedin", "twitter", "tiktok", "youtube", "pinterest")),
    ("link_shortener", ("bit.ly", "t.co", "tinyurl", "rb.gy", "short.io")),
    ("api_service", ("api.", "/api/", "graphql")),
)


def _redact_url_secrets(url: str) -> str:
    """Hide common credential query parameters before evidence is persisted or shown."""
    try:
        parsed = urllib.parse.urlsplit(url)
        sensitive_names = {
            "key", "api_key", "apikey", "token", "access_token", "refresh_token", "id_token",
            "client_secret", "secret", "password", "passwd", "authorization", "auth",
            "session", "sessionid", "signature", "sig", "credential", "code",
        }
        query = []
        for name, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            normalized = name.casefold()
            sensitive = normalized in sensitive_names or normalized.endswith(("_token", "-token", "_key", "-key", "_secret", "-secret", "_signature", "-signature", "_credential", "-credential"))
            query.append((name, "REDACTED" if sensitive and value else value))
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), parsed.fragment))
    except ValueError:
        return url


def _classify_interaction(url: str, source_url: str, origin: tuple[str, str, int], interaction_type: str, evidence: str) -> dict[str, Any]:
    url = _redact_url_secrets(url)
    try:
        parsed = urllib.parse.urlsplit(url)
        host = (parsed.hostname or "unknown").lower().rstrip(".")
    except ValueError:
        parsed = urllib.parse.urlsplit("")
        host = "unknown"
    try:
        source_host = urllib.parse.urlsplit(source_url).hostname or origin[1]
    except ValueError:
        source_host = origin[1]
    if _same_origin(url, origin):
        domain_relation = "same_origin"
    elif _registrable_domain(host) == _registrable_domain(source_host):
        domain_relation = "related_domain"
    else:
        domain_relation = "external_domain"

    role = "unknown"
    confidence = "low"
    matched_pattern = ""
    searchable = f"{host}{parsed.path}".lower()
    for candidate, patterns in _ROLE_PATTERNS:
        matched_pattern = next((pattern for pattern in patterns if pattern in searchable), "")
        if matched_pattern:
            role = candidate
            confidence = "medium"
            break
    tracking_parameter = next((key for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True) if key.lower().startswith(("utm_", "gclid", "fbclid", "msclkid", "dclid", "_ga"))), "")
    if role == "unknown" and tracking_parameter:
        role = "tracking_metadata"
        confidence = "low"
    noise_candidate = role in {"advertising", "analytics", "tracking_metadata"}
    if matched_pattern:
        reason = f"Host/path matched the heuristic pattern '{matched_pattern}'; this suggests a likely {role.replace('_', ' ')} role, not proof."
    elif tracking_parameter:
        reason = f"URL contains tracking-style parameter '{tracking_parameter}'; this alone does not establish intent."
    else:
        reason = "No known host or URL pattern matched; kept as unknown rather than guessing from domain alone."
    return {
        "url": url,
        "host": host,
        "source_url": source_url,
        "interaction_type": interaction_type,
        "domain_relation": domain_relation,
        "role_category": role,
        "confidence": confidence,
        "noise_candidate": noise_candidate,
        "classification_reason": reason,
        "evidence": evidence,
    }


def _runtime_observations(target_url: str, origin: tuple[str, str, int]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Observe a bounded page-load session; all off-origin and mutating requests are blocked."""
    started = monotonic()
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return [], {"status": "unavailable", "reason": "Playwright is not installed."}

    observed: dict[tuple[str, str, str], dict[str, Any]] = {}
    requests_seen = 0
    requests_blocked = 0
    popup_pages_seen = 0
    request_limit_hit = False
    browser = None
    context = None
    root_page = None
    runtime_error_type = None
    browser_sandbox = "not_started"

    def record(url: str, source_url: str, interaction_type: str, evidence: str, status: int | None = None, redirect_scope: str = "") -> None:
        normalized = _normalize_url(url, source_url)
        if not normalized:
            return
        signal = _classify_interaction(normalized, source_url, origin, interaction_type, evidence)
        if status is not None:
            signal["status"] = status
        if redirect_scope:
            signal["redirect_scope"] = redirect_scope
        observed[(source_url, interaction_type, normalized)] = signal

    def page_source(page) -> str:
        try:
            current = page.url
            return current if current.startswith(("http://", "https://")) else target_url
        except Exception:
            return target_url

    def handle_request(route) -> None:
        nonlocal requests_seen, requests_blocked, request_limit_hit
        request = route.request
        requests_seen += 1
        frame_unavailable = False
        try:
            page = request.frame.page
        except Exception:
            # A popup's first document request can arrive before Playwright has
            # attached its initial frame, so Request.frame is unavailable here.
            page = None
            frame_unavailable = True
        source_url = page_source(page) if page is not None else target_url
        is_popup = (
            (page is not None and root_page is not None and page != root_page)
            or (frame_unavailable and request.is_navigation_request() and request.resource_type == "document")
        )
        is_document = request.resource_type == "document"

        if requests_seen > MAX_BROWSER_REQUESTS:
            request_limit_hit = True
            requests_blocked += 1
            route.abort()
            return

        if not _same_origin(request.url, origin):
            requests_blocked += 1
            interaction_type = "popup_navigation" if is_popup and is_document else "runtime_navigation" if is_document else "runtime_external_request"
            source_for_signal = target_url if is_popup or page is root_page else source_url
            record(
                request.url,
                source_for_signal,
                interaction_type,
                f"Page-load browser observed an off-origin {request.resource_type} request; it was blocked before reaching the destination.",
            )
            route.abort()
            return

        if request.method.upper() not in {"GET", "HEAD"}:
            requests_blocked += 1
            record(
                request.url,
                source_url,
                "blocked_mutation",
                f"Page-load browser attempted a {request.method.upper()} request; non-GET/HEAD requests are blocked and forms are never submitted.",
            )
            route.abort()
            return

        if request.resource_type in {"fetch", "xhr"}:
            requests_blocked += 1
            record(
                request.url,
                source_url,
                "blocked_api_request",
                f"Page-load browser attempted a same-origin {request.resource_type} request; API/background requests are blocked during behavior observation.",
            )
            route.abort()
            return

        if is_popup and is_document:
            record(request.url, target_url, "popup_navigation", "Page-load browser observed a same-origin popup page navigation.")
        elif page is root_page and is_document and request.url.rstrip("/") != target_url.rstrip("/"):
            record(request.url, target_url, "runtime_navigation", "Page-load browser observed a same-origin document navigation triggered by page code.")

        try:
            route.continue_()
        except Exception:
            requests_blocked += 1

    def handle_response(response) -> None:
        status = response.status
        if status not in {301, 302, 303, 307, 308}:
            return
        location = response.headers.get("location", "")
        if not location:
            return
        destination = _normalize_url(location, response.url)
        if not destination:
            return
        request = response.request
        try:
            page = request.frame.page
        except Exception:
            page = None
        source_url = page_source(page) if page is not None else target_url
        same_origin = _same_origin(destination, origin)
        record(
            destination,
            source_url,
            "http_redirect",
            f"Page-load browser observed an HTTP {status} Location response. " + ("The next hop stays within the scanned origin." if same_origin else "The next hop was blocked before reaching the off-origin destination."),
            status=status,
            redirect_scope="same_origin" if same_origin else "out_of_scope",
        )

    def handle_new_page(page) -> None:
        nonlocal popup_pages_seen
        if root_page is None or page == root_page:
            return
        popup_pages_seen += 1
        if popup_pages_seen > MAX_POPUP_PAGES:
            try:
                page.close()
            except Exception:
                pass

    status = "completed"
    try:
        _assert_public_host(origin[1])
        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(headless=True, chromium_sandbox=True, args=["--disable-dev-shm-usage"])
                browser_sandbox = "enabled"
            except Exception as launch_error:
                message = str(launch_error).casefold()
                if "sandboxing failed" not in message and "no usable sandbox" not in message:
                    raise
                # Some Docker hosts block Chromium user namespaces. Fall back only
                # for that specific host limitation; Compose still contains the
                # browser as a non-root process with dropped capabilities.
                browser_sandbox = "disabled; isolated by non-root Docker container"
                browser = playwright.chromium.launch(headless=True, chromium_sandbox=False, args=["--disable-dev-shm-usage"])
            context = browser.new_context(service_workers="block", accept_downloads=False)
            context.route("**/*", handle_request)
            context.route_web_socket("**/*", lambda websocket: websocket.close(code=1000, reason="Passive scan"))
            context.on("response", handle_response)
            context.on("page", handle_new_page)
            root_page = context.new_page()
            try:
                root_page.goto(target_url, wait_until="domcontentloaded", timeout=RUNTIME_TIMEOUT_MS)
            except PlaywrightTimeoutError:
                status = "timed_out"
            try:
                root_page.wait_for_timeout(RUNTIME_SETTLE_MS)
            except Exception:
                pass
    except Exception as exc:
        status = "failed"
        runtime_error_type = type(exc).__name__
    finally:
        try:
            if context is not None:
                context.close()
        except Exception:
            pass
        try:
            if browser is not None:
                browser.close()
        except Exception:
            pass

    return list(observed.values()), {
        "status": status,
        "error_type": runtime_error_type,
        "browser_sandbox": browser_sandbox,
        "duration_ms": int((monotonic() - started) * 1000),
        "requests_seen": requests_seen,
        "requests_blocked": requests_blocked,
        "popup_pages_seen": popup_pages_seen,
        "popup_page_limit": MAX_POPUP_PAGES,
        "request_limit": MAX_BROWSER_REQUESTS,
        "request_limit_hit": request_limit_hit,
        "settle_ms": RUNTIME_SETTLE_MS,
        "off_origin_requests_fetched": False,
        "non_get_requests_sent": False,
        "cookies_persisted": False,
    }


def _endpoint(url: str, method: str, source_url: str, evidence: str, status: int | None = None) -> dict[str, Any]:
    return {"url": url, "method": method.upper(), "source_url": source_url, "evidence": evidence, "status": status}


def _parse_artifact(kind: str, content: str, base_url: str) -> dict[str, list[dict[str, Any]]]:
    if len(content.encode("utf-8")) > 2_000_000:
        raise ScanInputError("Evidence files must be smaller than 2 MB.")
    try:
        artifact = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ScanInputError("Evidence import must be valid JSON (HAR, OpenAPI JSON, or SARIF).") from exc
    result: dict[str, list[dict[str, Any]]] = {"api_endpoints": [], "dependencies": [], "interactions": [], "findings": []}
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
            response = entry.get("response", {})
            status = response.get("status")
            location = next((header.get("value", "") for header in response.get("headers", []) if header.get("name", "").lower() == "location"), "")
            if status in {301, 302, 303, 307, 308} and location:
                source_url = _header(request, "referer") or base_url
                destination = _normalize_url(location, url)
                if destination:
                    interaction = _classify_interaction(destination, source_url, _origin(base_url), "http_redirect", f"Imported HAR records an HTTP {status} Location response for this request.")
                    interaction["status"] = int(status)
                    interaction["redirect_scope"] = "same_origin" if _same_origin(destination, _origin(base_url)) else "out_of_scope"
                    result["interactions"].append(interaction)
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


def _source_observations(source: str, source_url: str, target_url: str, origin: tuple[str, str, int], endpoint_map: dict, dependency_map: dict, interactions: dict, source_page_url: str | None = None) -> list[str]:
    """Extract likely app routes and API client references from first-party source."""
    evidence_source_url = source_page_url or source_url
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
                endpoint_map.setdefault(("GET", raw.rstrip("/")), _endpoint(raw.rstrip("/"), "GET", evidence_source_url, "External API base URL referenced in first-party source"))
            continue
        context = source[max(0, match.start() - 60):match.start()]
        if re.search(r"(?:src|href)\s*:\s*(?:`|['\"])?$", context, re.IGNORECASE):
            dependency_map[(host, "runtime asset")] = {"url": f"{parsed.scheme}://{parsed.netloc}", "host": host, "source_url": evidence_source_url, "kind": "runtime asset", "evidence": "External asset URL referenced in first-party source"}

    # Static source inspection can identify popup and redirect intents without
    # executing untrusted JavaScript. These records are explicitly marked as
    # source hints; a browser session is needed to confirm runtime behavior.
    popup_pattern = re.compile(r"\bwindow\s*\.\s*open\s*\(\s*(['\"])(https?://[^'\"]+|/[^'\"]*)\1", re.IGNORECASE)
    for match in popup_pattern.finditer(source):
        candidate = _normalize_url(match.group(2), source_url)
        if candidate:
            evidence = "Static first-party source contains a window.open URL literal; runtime popup not confirmed."
            item = _classify_interaction(candidate, evidence_source_url, origin, "popup_intent", evidence)
            interactions[(evidence_source_url, "popup_intent", candidate)] = item
    redirect_pattern = re.compile(
        r"(?:window\s*\.\s*location(?:\s*\.\s*(?:href|assign|replace))?|document\s*\.\s*location(?:\s*\.\s*(?:href|assign|replace))?|location\s*\.\s*(?:href|assign|replace))\s*(?:=|\()\s*(['\"])(https?://[^'\"]+|/[^'\"]*)\1",
        re.IGNORECASE,
    )
    for match in redirect_pattern.finditer(source):
        candidate = _normalize_url(match.group(2), source_url)
        if candidate:
            evidence = "Static first-party source contains a location redirect URL literal; runtime redirect not confirmed."
            item = _classify_interaction(candidate, evidence_source_url, origin, "script_redirect_intent", evidence)
            interactions[(evidence_source_url, "script_redirect_intent", candidate)] = item

    for client, base in api_clients.items():
        pattern = re.compile(rf"\b{re.escape(client)}\.(get|post|put|patch|delete|options|head)\(\s*([`\"'])([^`\"']{{1,240}})\2", re.IGNORECASE)
        for call in pattern.finditer(source):
            request_path = call.group(3)
            if not request_path.startswith("/"):
                continue
            full_url = base.rstrip("/") + request_path
            method = call.group(1).upper()
            endpoint_map.setdefault((method, full_url), _endpoint(full_url, method, evidence_source_url, "API client request path in first-party source"))

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
    interaction_map: dict[tuple[str, str, str], dict[str, Any]] = {}
    queue = deque([target_url])
    visited: set[str] = set()
    script_urls: set[str] = set()
    script_sources: dict[str, str] = {}
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
        final_url, status, content_type, headers, body, redirect_hops = fetched
        for hop in redirect_hops:
            source_url = hop["source_url"]
            target = hop["target_url"]
            item = _classify_interaction(
                target,
                source_url,
                origin,
                "http_redirect",
                f"Observed HTTP {hop['status']} redirect response. " + ("Target remains within the scanned origin." if hop["same_origin"] else "Target is outside the scanned origin and was not fetched."),
            )
            item["status"] = hop["status"]
            item["redirect_scope"] = "same_origin" if hop["same_origin"] else "out_of_scope"
            interaction_map[(source_url, "http_redirect", target)] = item
        waf_action = headers.get("x-amzn-waf-action", "").strip().lower()
        if waf_action == "challenge":
            raise ScanInputError(
                "This website's AWS WAF returned a browser challenge to the read-only scanner. "
                "No site content was scanned. Choose a target that permits automated read-only requests."
            )
        is_html = "html" in content_type.lower() or body.lstrip().startswith(b"<!DOCTYPE html") or b"<html" in body[:1000].lower()
        if not is_html:
            # A redirecting source URL is still a real route observation. Keep
            # it as a stub so each HTTP hop has a route endpoint in FalkorDB.
            if redirect_hops and len(pages) < MAX_PAGES:
                pages.setdefault(url, {"url": url, "title": "Redirect response", "status": status, "content_type": "redirect", "headers": headers, "scripts": [], "forms": [], "links": []})
            continue
        parser = _PageParser()
        source = body.decode("utf-8", errors="replace")
        parser.feed(source)
        page_url = urllib.parse.urldefrag(final_url)[0]
        # Preserve the requested redirecting route as its own route, while
        # attributing the fetched HTML to its final same-origin URL.
        for hop in redirect_hops:
            if len(pages) >= MAX_PAGES:
                break
            pages.setdefault(hop["source_url"], {"url": hop["source_url"], "title": "Redirect response", "status": hop["status"], "content_type": "redirect", "headers": {}, "scripts": [], "forms": [], "links": []})
        title = " ".join(" ".join(parser.title_parts).split())
        anchors: list[str] = []
        forms: list[dict[str, str]] = []
        for link in parser.links:
            normalized = _normalize_url(link["url"], page_url)
            if not normalized:
                continue
            popup = link.get("target", "").casefold() == "_blank" or "window.open" in link.get("onclick", "").casefold()
            same_origin = _same_origin(normalized, origin)
            if popup or not same_origin:
                interaction_type = "popup_intent" if popup else "external_navigation"
                evidence = "Anchor uses target=_blank; this indicates new-tab intent, not a confirmed popup." if popup else f"External {link['element']} link observed in page; destination was not fetched."
                if "window.open" in link.get("onclick", "").casefold():
                    evidence = "Anchor onclick contains window.open; runtime popup not confirmed."
                item = _classify_interaction(normalized, page_url, origin, interaction_type, evidence)
                interaction_map[(page_url, interaction_type, normalized)] = item
            if same_origin and not popup:
                anchors.append(normalized)
        for form in parser.forms:
            action = _normalize_url(form["action"] or page_url, page_url)
            if action:
                forms.append({"action": action, "method": form["method"]})
                if _same_origin(action, origin):
                    endpoint_map[(form["method"], action)] = _endpoint(action, form["method"], page_url, "HTML form action")
                else:
                    evidence = f"External HTML form action observed; the form was not submitted ({form['method']})."
                    item = _classify_interaction(action, page_url, origin, "external_form_action", evidence)
                    interaction_map[(page_url, "external_form_action", action)] = item
        for refresh in parser.refreshes:
            normalized = _normalize_url(refresh, page_url)
            if normalized:
                item = _classify_interaction(normalized, page_url, origin, "meta_refresh_intent", "HTML meta refresh target observed; automatic navigation was not triggered by the crawler.")
                interaction_map[(page_url, "meta_refresh_intent", normalized)] = item
        refresh_header = headers.get("refresh", "")
        header_refresh = re.search(r"(?:^|;)\s*url\s*=\s*['\"]?(.+?)['\"]?\s*$", refresh_header, re.IGNORECASE)
        if header_refresh:
            normalized = _normalize_url(header_refresh.group(1).strip(), page_url)
            if normalized:
                item = _classify_interaction(normalized, page_url, origin, "http_refresh_intent", "HTTP Refresh header target observed; automatic navigation was not triggered by the crawler.")
                interaction_map[(page_url, "http_refresh_intent", normalized)] = item
        page = {"url": page_url, "title": title, "status": status, "content_type": content_type, "headers": headers, "scripts": [], "forms": forms, "links": anchors}
        if len(pages) < MAX_PAGES or page_url in pages:
            pages.setdefault(page_url, page)
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
            if _same_origin(normalized, origin):
                script_url = urllib.parse.urldefrag(normalized)[0]
                script_urls.add(script_url)
                script_sources.setdefault(script_url, page_url)
                page["scripts"].append(normalized)
            else:
                ext = urllib.parse.urlsplit(normalized)
                host = (ext.hostname or "unknown").lower()
                dependency_map[(host, "script")] = {"url": f"{ext.scheme}://{ext.netloc}", "host": host, "source_url": page_url, "kind": "script", "evidence": "External script source observed in page"}
                item = _classify_interaction(normalized, page_url, origin, "external_script_load", "External script source observed in page; the script was not fetched or executed.")
                interaction_map[(page_url, "external_script_load", normalized)] = item
        for iframe in parser.iframes:
            normalized = _normalize_url(iframe, page_url)
            if normalized:
                item = _classify_interaction(normalized, page_url, origin, "iframe_embed", "Iframe source observed in page; iframe content was not fetched or executed.")
                interaction_map[(page_url, "iframe_embed", normalized)] = item
            if normalized and not _same_origin(normalized, origin):
                ext = urllib.parse.urlsplit(normalized)
                host = (ext.hostname or "unknown").lower()
                dependency_map[(host, "iframe")] = {"url": f"{ext.scheme}://{ext.netloc}", "host": host, "source_url": page_url, "kind": "iframe", "evidence": "External iframe source observed; iframe content was not fetched."}
        # Keep passively observed security-header findings and exact source evidence.
        required_headers = [("content-security-policy", "Content Security Policy"), ("x-content-type-options", "X-Content-Type-Options"), ("referrer-policy", "Referrer Policy")]
        if origin[0] == "https":
            required_headers.append(("strict-transport-security", "Strict-Transport-Security"))
        for header, label in required_headers:
            if header not in headers:
                fid = hashlib.sha256(f"{page_url}|{header}".encode()).hexdigest()[:20]
                page.setdefault("findings", []).append({"id": fid, "title": f"{label} header not observed", "severity": "INFO", "uri": page_url, "evidence": f"The response did not include the {label} header.", "rule_id": f"headers/{header}", "source": "Passive response-header observation"})
        for discovered_route in _source_observations(source, page_url, target_url, origin, endpoint_map, dependency_map, interaction_map):
            if len(pages) < MAX_PAGES:
                pages.setdefault(discovered_route, {"url": discovered_route, "title": "Client-side route", "status": 200, "content_type": "client-side route", "headers": {}, "scripts": [], "forms": [], "links": []})

    # Fetch a bounded number of first-party scripts only; no external code is executed.
    for script_url in list(script_urls)[:20]:
        fetched = _fetch(script_url, origin, MAX_SCRIPT_BYTES)
        if not fetched:
            continue
        final_url, _, _, _, body, redirect_hops = fetched
        source = body.decode("utf-8", errors="replace")
        source_page_url = script_sources.get(script_url, target_url)
        for hop in redirect_hops:
            target = hop["target_url"]
            item = _classify_interaction(target, source_page_url, origin, "http_redirect", f"Observed HTTP {hop['status']} redirect while fetching first-party script {hop['source_url']}. " + ("Target remains within the scanned origin." if hop["same_origin"] else "Target is outside the scanned origin and was not fetched."))
            item["status"] = hop["status"]
            item["redirect_scope"] = "same_origin" if hop["same_origin"] else "out_of_scope"
            item["resource_url"] = hop["source_url"]
            interaction_map[(source_page_url, "http_redirect", target)] = item
        for discovered_route in _source_observations(source, final_url, target_url, origin, endpoint_map, dependency_map, interaction_map, source_page_url):
            if len(pages) < MAX_PAGES:
                pages.setdefault(discovered_route, {"url": discovered_route, "title": "Client-side route", "status": 200, "content_type": "client-side route", "headers": {}, "scripts": [], "forms": [], "links": []})

    runtime_interactions, browser_runtime = _runtime_observations(target_url, origin)
    for item in runtime_interactions:
        interaction_map[(item["source_url"], item["interaction_type"], item["url"])] = item

    combined: dict[str, list[dict[str, Any]]] = {"api_endpoints": list(endpoint_map.values()), "dependencies": list(dependency_map.values()), "interactions": list(interaction_map.values()), "findings": [finding for page in pages.values() for finding in page.get("findings", [])]}
    artifact_info = None
    if artifact_type and artifact_content:
        imported = _parse_artifact(artifact_type, artifact_content, target_url)
        combined["api_endpoints"].extend(imported["api_endpoints"])
        combined["dependencies"].extend(imported["dependencies"])
        combined["interactions"].extend(imported.get("interactions", []))
        combined["findings"].extend(imported["findings"])
        artifact_info = {"type": artifact_type, "records": sum(len(items) for items in imported.values())}
    # Stable de-duplication keeps repeated page references from creating duplicate nodes.
    combined["api_endpoints"] = list({(item["method"], item["url"]): item for item in combined["api_endpoints"]}.values())
    combined["dependencies"] = list({(item["host"], item["kind"]): item for item in combined["dependencies"]}.values())
    combined["interactions"] = list({(item["source_url"], item["interaction_type"], item["url"]): item for item in combined["interactions"]}.values())[:MAX_INTERACTIONS]
    combined["findings"] = list({item["id"]: item for item in combined["findings"]}.values())
    return {
        "scan_id": scan_id,
        "target_url": target_url,
        "site_host": origin[1],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "scope": "Bounded same-origin discovery plus an isolated page-load behavior pass. First-party JavaScript runs briefly in a fresh browser context; off-origin requests, API/XHR, WebSockets, and non-GET/HEAD requests are blocked. No forms are submitted, controls clicked, cookies persisted, or third-party hosts fetched.",
        "pages": list(pages.values())[:MAX_PAGES],
        **combined,
        "artifact": artifact_info,
        "browser_runtime": browser_runtime,
        "interaction_count": len(combined["interactions"]),
        "limits": {"max_pages": MAX_PAGES, "max_page_bytes": MAX_BODY_BYTES, "max_first_party_scripts": 20, "max_interactions": MAX_INTERACTIONS, "runtime_browser_ms": RUNTIME_TIMEOUT_MS + RUNTIME_SETTLE_MS, "max_browser_requests": MAX_BROWSER_REQUESTS, "runtime_popup_detection": browser_runtime.get("status") == "completed"},
    }

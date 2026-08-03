"""Derive non-mutating HTTP API probe targets from live control-plane data.

The live fixture runner must never guess a stage, API mapping, or route.  This
module contains no environment identifiers and emits no identifiers: callers
provide complete, paginated API Gateway collections and retain any sensitive
evidence in the protected fixture journal.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass


class ApiProbeSafetyError(ValueError):
    """A safe probe cannot be constructed from complete, unambiguous data."""


@dataclass(frozen=True)
class InvocationBase:
    kind: str
    url: str


def _nonempty_string(value: object, code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ApiProbeSafetyError(code)
    return value.strip()


def _route_parts(route_key: object) -> tuple[str, str] | None:
    if not isinstance(route_key, str) or " " not in route_key:
        return None
    method, path = route_key.split(" ", 1)
    if not method or not path.startswith("/"):
        return None
    return method.upper(), path


def _is_static_get(route_key: object) -> bool:
    parts = _route_parts(route_key)
    return bool(parts and parts[0] == "GET" and "{" not in parts[1] and "$default" not in parts[1])


def require_complete_collection(*, items: Iterable[Mapping[str, object]], complete: bool, name: str) -> list[Mapping[str, object]]:
    """Reject a partial API Gateway result before it can affect a probe."""
    if not complete:
        raise ApiProbeSafetyError(f"INCOMPLETE_{name.upper()}_PAGINATION")
    return list(items)


def derive_invocation_bases(
    *,
    api_endpoint: str,
    execute_endpoint_enabled: bool,
    stages: Iterable[Mapping[str, object]],
    stages_complete: bool,
    domains_with_mappings: Iterable[tuple[Mapping[str, object], Iterable[Mapping[str, object]]]],
    domains_complete: bool,
    mappings_complete: bool,
    api_id: str,
) -> tuple[InvocationBase, ...]:
    """Return only exact execute-api or custom-domain bases for this API."""
    endpoint = _nonempty_string(api_endpoint, "API_ENDPOINT_MISSING").rstrip("/")
    current_api_id = _nonempty_string(api_id, "API_ID_MISSING")
    live_stages = require_complete_collection(items=stages, complete=stages_complete, name="stages")
    domain_pairs = list(domains_with_mappings)
    if not domains_complete:
        raise ApiProbeSafetyError("INCOMPLETE_DOMAINS_PAGINATION")
    if not mappings_complete:
        raise ApiProbeSafetyError("INCOMPLETE_MAPPINGS_PAGINATION")
    if not live_stages:
        raise ApiProbeSafetyError("API_STAGE_MISSING")

    bases: list[InvocationBase] = []
    if execute_endpoint_enabled:
        for stage in live_stages:
            name = _nonempty_string(stage.get("StageName"), "STAGE_NAME_MISSING")
            bases.append(
                InvocationBase(
                    "execute-default" if name == "$default" else "execute-named",
                    endpoint if name == "$default" else f"{endpoint}/{name}",
                )
            )

    for domain, mappings in domain_pairs:
        domain_name = _nonempty_string(domain.get("DomainName"), "DOMAIN_NAME_MISSING")
        for mapping in mappings:
            if mapping.get("ApiId") != current_api_id:
                continue
            key = mapping.get("ApiMappingKey")
            if key is not None and not isinstance(key, str):
                raise ApiProbeSafetyError("API_MAPPING_KEY_INVALID")
            suffix = (key or "").strip("/")
            bases.append(InvocationBase("custom-domain", f"https://{domain_name}" + (f"/{suffix}" if suffix else "")))

    unique: dict[str, InvocationBase] = {base.url.rstrip("/"): base for base in bases}
    if not unique:
        raise ApiProbeSafetyError("NO_VALID_INVOCATION_BASE")
    return tuple(unique.values())


def classify_route(*, route: Mapping[str, object], canonical_public_reads: set[str], canonical_protected_reads: set[str]) -> str:
    """Classify a route without treating an arbitrary GET as safe to invoke."""
    key = route.get("RouteKey")
    parts = _route_parts(key)
    if parts is None or key == "$default" or not _is_static_get(key):
        return "UNKNOWN"
    authorization = route.get("AuthorizationType") or "NONE"
    if key in canonical_public_reads and authorization == "NONE":
        return "PUBLIC_SAFE_READ"
    if key in canonical_protected_reads and authorization not in ("NONE", None):
        return "PROTECTED_SAFE_READ"
    return "UNKNOWN"


def select_safe_read(
    *,
    routes: Iterable[Mapping[str, object]],
    routes_complete: bool,
    canonical_route_key: str,
    required_classification: str,
) -> Mapping[str, object]:
    """Select one canonical static GET route and verify its live auth type."""
    live_routes = require_complete_collection(items=routes, complete=routes_complete, name="routes")
    if required_classification not in {"PUBLIC_SAFE_READ", "PROTECTED_SAFE_READ"}:
        raise ApiProbeSafetyError("SAFE_ROUTE_CLASSIFICATION_INVALID")
    candidates = [route for route in live_routes if route.get("RouteKey") == canonical_route_key]
    if len(candidates) != 1:
        raise ApiProbeSafetyError("CANONICAL_SAFE_ROUTE_MISSING_OR_AMBIGUOUS")
    route = candidates[0]
    classification = classify_route(
        route=route,
        canonical_public_reads={canonical_route_key} if required_classification == "PUBLIC_SAFE_READ" else set(),
        canonical_protected_reads={canonical_route_key} if required_classification == "PROTECTED_SAFE_READ" else set(),
    )
    if classification != required_classification:
        raise ApiProbeSafetyError("CANONICAL_SAFE_ROUTE_AUTH_OR_SHAPE_MISMATCH")
    return route


def cors_probe_allowed(*, cors_configuration: object, route: Mapping[str, object]) -> bool:
    """CORS is probed only with live CORS configuration and a real static route."""
    return bool(cors_configuration) and _is_static_get(route.get("RouteKey"))


def cors_headers_present(*, headers: Mapping[str, object]) -> bool:
    """Accept a CORS probe only when the gateway returned the required header."""
    normalized = {str(key).lower(): value for key, value in headers.items()}
    return bool(normalized.get("access-control-allow-origin"))


def redact_identifier(_value: object) -> str:
    """Keep diagnostic renderers from accidentally exposing an AWS identifier."""
    return "<redacted>"

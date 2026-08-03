from __future__ import annotations

import pytest

from scripts.household_join_live.api_safe_probe import (
    ApiProbeSafetyError,
    classify_route,
    cors_probe_allowed,
    cors_headers_present,
    derive_invocation_bases,
    redact_identifier,
    select_safe_read,
)


API_ID = "api-opaque"
ENDPOINT = "https://execute.example"
PROTECTED = "GET /safe-status"
PUBLIC = "GET /public-status"


def bases(*, stages, enabled=True, mappings=(), domains_complete=True, mappings_complete=True):
    return derive_invocation_bases(
        api_endpoint=ENDPOINT,
        execute_endpoint_enabled=enabled,
        stages=stages,
        stages_complete=True,
        domains_with_mappings=mappings,
        domains_complete=domains_complete,
        mappings_complete=mappings_complete,
        api_id=API_ID,
    )


def test_derives_default_and_named_execute_stage_without_bad_prefixes():
    default = bases(stages=[{"StageName": "$default"}])
    named = bases(stages=[{"StageName": "dev"}])
    assert default[0].url == ENDPOINT
    assert named[0].url == f"{ENDPOINT}/dev"


def test_disabled_execute_endpoint_requires_a_custom_mapping():
    with pytest.raises(ApiProbeSafetyError, match="NO_VALID"):
        bases(stages=[{"StageName": "$default"}], enabled=False)


@pytest.mark.parametrize("mapping_key,expected_suffix", [(None, ""), ("", ""), ("dev", "/dev"), ("v3/dev", "/v3/dev")])
def test_derives_empty_and_multilevel_custom_mappings(mapping_key, expected_suffix):
    result = bases(
        stages=[{"StageName": "dev"}],
        mappings=[({"DomainName": "api.example"}, [{"ApiId": API_ID, "ApiMappingKey": mapping_key}])],
    )
    assert any(base.kind == "custom-domain" and base.url.endswith(expected_suffix) for base in result)


def test_wrong_mapping_prefix_is_not_used_for_this_api():
    result = bases(
        stages=[{"StageName": "dev"}],
        mappings=[({"DomainName": "api.example"}, [{"ApiId": "different-api", "ApiMappingKey": "wrong"}])],
    )
    assert all(base.kind != "custom-domain" for base in result)


def test_rejects_incomplete_stage_domain_or_mapping_pagination():
    with pytest.raises(ApiProbeSafetyError, match="INCOMPLETE_STAGES"):
        derive_invocation_bases(api_endpoint=ENDPOINT, execute_endpoint_enabled=True, stages=[], stages_complete=False, domains_with_mappings=[], domains_complete=True, mappings_complete=True, api_id=API_ID)
    with pytest.raises(ApiProbeSafetyError, match="INCOMPLETE_DOMAINS"):
        bases(stages=[{"StageName": "dev"}], domains_complete=False)
    with pytest.raises(ApiProbeSafetyError, match="INCOMPLETE_MAPPINGS"):
        bases(stages=[{"StageName": "dev"}], mappings_complete=False)


@pytest.mark.parametrize("key", ["GET /static", "GET /{id}", "ANY /{proxy+}", "$default", "POST /safe-status"])
def test_route_classification_handles_static_parameterized_greedy_default_and_method_mismatch(key):
    route = {"RouteKey": key, "AuthorizationType": "JWT"}
    result = classify_route(route=route, canonical_public_reads={PUBLIC}, canonical_protected_reads={PROTECTED})
    assert result == ("PROTECTED_SAFE_READ" if key == PROTECTED else "UNKNOWN")


def test_public_and_protected_routes_require_exact_method_and_authentication():
    assert classify_route(route={"RouteKey": PUBLIC, "AuthorizationType": "NONE"}, canonical_public_reads={PUBLIC}, canonical_protected_reads=set()) == "PUBLIC_SAFE_READ"
    assert classify_route(route={"RouteKey": PROTECTED, "AuthorizationType": "JWT"}, canonical_public_reads=set(), canonical_protected_reads={PROTECTED}) == "PROTECTED_SAFE_READ"
    assert classify_route(route={"RouteKey": PUBLIC, "AuthorizationType": "JWT"}, canonical_public_reads={PUBLIC}, canonical_protected_reads=set()) == "UNKNOWN"


def test_health_or_protected_route_absence_fails_closed():
    with pytest.raises(ApiProbeSafetyError, match="CANONICAL_SAFE_ROUTE"):
        select_safe_read(routes=[], routes_complete=True, canonical_route_key="GET /health", required_classification="PUBLIC_SAFE_READ")
    with pytest.raises(ApiProbeSafetyError, match="CANONICAL_SAFE_ROUTE"):
        select_safe_read(routes=[{"RouteKey": PUBLIC, "AuthorizationType": "NONE"}], routes_complete=True, canonical_route_key=PROTECTED, required_classification="PROTECTED_SAFE_READ")


def test_authorized_default_route_cannot_be_safe_and_stale_route_is_rejected():
    assert classify_route(route={"RouteKey": "$default", "AuthorizationType": "JWT"}, canonical_public_reads=set(), canonical_protected_reads={PROTECTED}) == "UNKNOWN"
    with pytest.raises(ApiProbeSafetyError, match="MISSING_OR_AMBIGUOUS"):
        select_safe_read(routes=[{"RouteKey": PROTECTED, "AuthorizationType": "JWT"}, {"RouteKey": PROTECTED, "AuthorizationType": "JWT"}], routes_complete=True, canonical_route_key=PROTECTED, required_classification="PROTECTED_SAFE_READ")


def test_cors_probe_needs_configuration_and_real_static_route():
    route = {"RouteKey": PROTECTED, "AuthorizationType": "JWT"}
    assert not cors_probe_allowed(cors_configuration=None, route=route)
    assert cors_probe_allowed(cors_configuration={"AllowMethods": ["GET"]}, route=route)
    assert not cors_probe_allowed(cors_configuration={"AllowMethods": ["GET"]}, route={"RouteKey": "ANY /{proxy+}"})
    assert cors_headers_present(headers={"Access-Control-Allow-Origin": "https://app.example"})
    assert not cors_headers_present(headers={})


def test_identifier_redaction_is_constant():
    assert redact_identifier("sensitive-resource-identifier") == "<redacted>"

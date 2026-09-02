from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "prepare-http-api-route-drift-repair-template.py"
SPEC = importlib.util.spec_from_file_location("http_api_route_drift_repair", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def integration(name: str) -> dict:
    return {
        "Type": "AWS::ApiGatewayV2::Integration",
        "Properties": {
            "ApiId": {"Ref": MODULE.API},
            "IntegrationType": "AWS_PROXY",
            "IntegrationUri": {"Fn::GetAtt": [name, "Arn"]},
        },
    }


def route(index: int, route_key: str, integration_name: str) -> tuple[str, dict]:
    return (
        f"AffectedRoute{index}",
        {
            "Type": "AWS::ApiGatewayV2::Route",
            "Properties": {
                "ApiId": {"Ref": MODULE.API},
                "AuthorizationType": "NONE",
                "RouteKey": route_key,
                "Target": {
                    "Fn::Join": [
                        "/",
                        ["integrations", {"Ref": integration_name}],
                    ]
                },
            },
        },
    )


def wrapper(*, include_new_routes: bool) -> dict:
    resources = {
        MODULE.API: {
            "Type": "AWS::ApiGatewayV2::Api",
            "Properties": {"Body": {"paths": {"/health": {"get": {}}}}},
        },
        "KaevoHouseholdJoinIntegration": integration("JoinFunction"),
        "KaevoIdentityV3ApiIntegration": integration("IdentityFunction"),
        MODULE.EXPECTED_AUTHORIZER: {
            "Type": "AWS::ApiGatewayV2::Authorizer",
            "Properties": {
                "ApiId": {"Ref": MODULE.API},
                "AuthorizerType": "JWT",
                "Name": "HouseholdJoinAuthorizer",
            },
        },
        "Unrelated": {"Type": "AWS::S3::Bucket"},
    }
    for index, route_key in enumerate(sorted(MODULE.EXPECTED_ROUTE_KEYS)):
        if route_key in MODULE.EXPECTED_NEW_ROUTE_KEYS and not include_new_routes:
            continue
        integration_name = (
            "KaevoHouseholdJoinIntegration"
            if "/household-joins/" in route_key
            else "KaevoIdentityV3ApiIntegration"
        )
        name, resource = route(index, route_key, integration_name)
        resources[name] = resource
    return {"TemplateBody": {"Resources": resources}}


def test_prepares_exact_detach_and_restore_candidates_without_api_body_changes():
    deployed = wrapper(include_new_routes=False)
    candidate = wrapper(include_new_routes=True)
    detached, restored, removed = MODULE.prepare(deployed, candidate)

    assert len(removed) == len(MODULE.EXPECTED_ROUTE_KEYS) - len(MODULE.EXPECTED_NEW_ROUTE_KEYS) + 3
    assert (
        detached["Resources"][MODULE.API]
        == deployed["TemplateBody"]["Resources"][MODULE.API]
    )
    assert (
        restored["Resources"][MODULE.API]
        == deployed["TemplateBody"]["Resources"][MODULE.API]
    )
    assert detached["Resources"]["Unrelated"] == {"Type": "AWS::S3::Bucket"}
    assert restored["Resources"]["Unrelated"] == {"Type": "AWS::S3::Bucket"}
    assert len(MODULE.EXPECTED_ROUTE_KEYS) == 34
    assert "GET /v3/identity/me" in MODULE.EXPECTED_ROUTE_KEYS
    assert "GET /v3/identity/profile-mappings" in MODULE.EXPECTED_ROUTE_KEYS
    assert "POST /v3/identity/account-deletion" in MODULE.EXPECTED_ROUTE_KEYS
    assert (
        "PUT /v3/identity/profiles/{profileId}/jellyfin-binding"
        in MODULE.EXPECTED_ROUTE_KEYS
    )
    assert (
        "POST /v3/identity/profiles/{profileId}/jellyfin-binding-operations"
        in MODULE.EXPECTED_ROUTE_KEYS
    )
    assert (
        "GET /v3/identity/jellyfin-binding-operations/{operationId}"
        in MODULE.EXPECTED_ROUTE_KEYS
    )
    assert all(name not in detached["Resources"] for name in removed)
    assert all(name in restored["Resources"] for name in removed)
    restored_keys = {
        resource["Properties"]["RouteKey"]
        for resource in restored["Resources"].values()
        if resource.get("Type") == "AWS::ApiGatewayV2::Route"
    }
    assert restored_keys == MODULE.EXPECTED_ROUTE_KEYS


def test_repairs_when_some_new_routes_are_already_in_the_deployed_template():
    deployed = wrapper(include_new_routes=False)
    candidate = wrapper(include_new_routes=True)
    deployed_resources = deployed["TemplateBody"]["Resources"]
    candidate_resources = candidate["TemplateBody"]["Resources"]
    existing_new_routes = [
        name
        for name, resource in candidate_resources.items()
        if resource.get("Type") == "AWS::ApiGatewayV2::Route"
        and resource["Properties"]["RouteKey"] in MODULE.EXPECTED_NEW_ROUTE_KEYS
    ][:2]
    for name in existing_new_routes:
        deployed_resources[name] = candidate_resources[name]

    detached, restored, removed = MODULE.prepare(deployed, candidate)

    assert all(name in removed for name in existing_new_routes)
    assert all(name not in detached["Resources"] for name in removed)
    restored_keys = {
        resource["Properties"]["RouteKey"]
        for resource in restored["Resources"].values()
        if resource.get("Type") == "AWS::ApiGatewayV2::Route"
    }
    assert restored_keys == MODULE.EXPECTED_ROUTE_KEYS


def test_fails_closed_when_any_expected_route_is_missing():
    deployed = wrapper(include_new_routes=False)
    candidate = wrapper(include_new_routes=True)
    resources = deployed["TemplateBody"]["Resources"]
    first_route = next(
        name
        for name, resource in resources.items()
        if resource.get("Type") == "AWS::ApiGatewayV2::Route"
        and resource["Properties"]["RouteKey"] not in MODULE.EXPECTED_NEW_ROUTE_KEYS
    )
    resources.pop(first_route)

    try:
        MODULE.prepare(deployed, candidate)
    except ValueError as error:
        assert "route set differs" in str(error)
    else:
        raise AssertionError("missing route must be rejected")


def test_fails_closed_when_new_candidate_route_is_missing():
    deployed = wrapper(include_new_routes=False)
    candidate = wrapper(include_new_routes=True)
    resources = candidate["TemplateBody"]["Resources"]
    missing = next(
        name
        for name, resource in resources.items()
        if resource.get("Type") == "AWS::ApiGatewayV2::Route"
        and resource["Properties"]["RouteKey"] in MODULE.EXPECTED_NEW_ROUTE_KEYS
    )
    resources.pop(missing)

    try:
        MODULE.prepare(deployed, candidate)
    except ValueError as error:
        assert "candidate affected route set differs" in str(error)
    else:
        raise AssertionError("missing candidate route must be rejected")

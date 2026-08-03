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


def wrapper() -> dict:
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
        integration_name = (
            "KaevoHouseholdJoinIntegration"
            if "/household-joins/" in route_key
            else "KaevoIdentityV3ApiIntegration"
        )
        name, resource = route(index, route_key, integration_name)
        resources[name] = resource
    return {"TemplateBody": {"Resources": resources}}


def test_prepares_exact_detach_and_restore_candidates_without_api_body_changes():
    deployed = wrapper()
    detached, restored, removed = MODULE.prepare(deployed)

    assert len(removed) == len(MODULE.EXPECTED_ROUTE_KEYS) + 3
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
    assert all(name not in detached["Resources"] for name in removed)
    assert all(name in restored["Resources"] for name in removed)


def test_fails_closed_when_any_expected_route_is_missing():
    deployed = wrapper()
    resources = deployed["TemplateBody"]["Resources"]
    first_route = next(
        name
        for name, resource in resources.items()
        if resource.get("Type") == "AWS::ApiGatewayV2::Route"
    )
    resources.pop(first_route)

    try:
        MODULE.prepare(deployed)
    except ValueError as error:
        assert "route set differs" in str(error)
    else:
        raise AssertionError("missing route must be rejected")

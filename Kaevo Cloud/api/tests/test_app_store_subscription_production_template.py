from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "prepare-app-store-subscription-production-template.py"
SPEC = importlib.util.spec_from_file_location("app_store_production_template", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def api_function(code_key: str) -> dict:
    return {
        "Type": "AWS::Lambda::Function",
        "Properties": {
            "Handler": "handler.lambda_handler",
            "Runtime": "python3.12",
            "Code": {"S3Bucket": "bucket", "S3Key": code_key},
            "Environment": {"Variables": {"EXISTING": "value"}},
        },
    }


def role() -> dict:
    return {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "Policies": [
                {
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Sid": "KaevoCloudApiDynamoDBCrud",
                                "Resource": [{"Fn::GetAtt": ["ExistingTable", "Arn"]}],
                            }
                        ]
                    }
                }
            ]
        },
    }


def route(route_key: str) -> dict:
    return {
        "Type": "AWS::ApiGatewayV2::Route",
        "Properties": {
            "RouteKey": route_key,
            "Target": {
                "Fn::Join": ["/", ["integrations", {"Ref": MODULE.INTEGRATION}]]
            },
        },
    }


def templates() -> tuple[dict, dict]:
    deployed = {
        "Resources": {
            "KaevoCloudApiFunction": api_function("old.zip"),
            "KaevoCloudApiFunctionRole": role(),
            "KaevoCloudHttpApi": {
                "Type": "AWS::ApiGatewayV2::Api",
                "Properties": {"Body": {"paths": {"/health": {}}}},
            },
            "KaevoCloudHttpApiStage": {
                "Type": "AWS::ApiGatewayV2::Stage",
                "Properties": {"RouteSettings": {"POST /existing": {}}},
            },
        }
    }
    candidate = {
        "Resources": {
            **deployed["Resources"],
            MODULE.TRANSACTIONS_TABLE: {"Type": "AWS::DynamoDB::Table"},
            MODULE.ACCESS_POLICY: {"Type": "AWS::IAM::Policy"},
            MODULE.INTEGRATION: {"Type": "AWS::ApiGatewayV2::Integration"},
            **{
                logical_id: route(route_key)
                for logical_id, route_key in MODULE.ROUTES.items()
            },
            **{
                logical_id: {"Type": "AWS::Lambda::Permission"}
                for logical_id in MODULE.PERMISSIONS
            },
        }
    }
    return deployed, candidate


def test_first_phase_adds_explicit_routes_without_touching_api_body_or_stage():
    deployed, candidate = templates()

    prepared = MODULE.prepare_template(deployed, candidate)

    resources = prepared["Resources"]
    assert resources["KaevoCloudHttpApi"] == deployed["Resources"]["KaevoCloudHttpApi"]
    assert resources["KaevoCloudHttpApiStage"] == deployed["Resources"]["KaevoCloudHttpApiStage"]
    assert set(resources) == set(deployed["Resources"]) | {
        MODULE.TRANSACTIONS_TABLE,
        MODULE.ACCESS_POLICY,
        MODULE.INTEGRATION,
        *MODULE.PERMISSIONS,
        *MODULE.ROUTES,
    }
    assert resources["KaevoCloudApiFunction"] == deployed["Resources"]["KaevoCloudApiFunction"]
    assert resources["KaevoCloudApiFunctionRole"] == deployed["Resources"]["KaevoCloudApiFunctionRole"]


def test_fails_closed_when_an_explicit_route_is_missing():
    deployed, candidate = templates()
    candidate["Resources"].pop("KaevoAppStoreSyncRoute")

    try:
        MODULE.prepare_template(deployed, candidate)
    except MODULE.ScopeError as error:
        assert "incomplete" in str(error)
    else:
        raise AssertionError("missing App Store route must be rejected")

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "prepare-household-invitation-delete-transformed-template.py"
SPEC = importlib.util.spec_from_file_location("invitation_delete_template", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def wrapper() -> dict:
    operation = {
        "parameters": [{"in": "path", "name": "invitationId", "required": True}],
        "responses": {},
        "x-amazon-apigateway-integration": {
            "httpMethod": "POST",
            "payloadFormatVersion": "2.0",
            "type": "aws_proxy",
            "uri": {"Fn::GetAtt": ["KaevoCloudApiFunction", "Arn"]},
        },
    }
    return {
        "TemplateBody": {
            "Resources": {
                "KaevoCloudHttpApi": {
                    "Type": "AWS::ApiGatewayV2::Api",
                    "Properties": {
                        "Body": {
                            "paths": {
                                "/v2/household/invitations/{invitationId}/revoke": {
                                    "post": operation,
                                },
                            },
                        },
                    },
                },
                "KaevoCloudApiFunctionRevokeHouseholdInvitationPermission": {
                    "Type": "AWS::Lambda::Permission",
                    "Properties": {
                        "Action": "lambda:InvokeFunction",
                        "FunctionName": {"Ref": "KaevoCloudApiFunction"},
                        "Principal": "apigateway.amazonaws.com",
                        "SourceArn": {
                            "Fn::Sub": [
                                "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${__ApiId__}/${__Stage__}/POST/v2/household/invitations/*/revoke",
                                {
                                    "__ApiId__": {"Ref": "KaevoCloudHttpApi"},
                                    "__Stage__": "*",
                                },
                            ],
                        },
                    },
                },
                "Unrelated": {"Type": "AWS::S3::Bucket"},
            },
        },
    }


def test_adds_only_exact_delete_path_using_existing_lambda_integration():
    deployed = wrapper()
    prepared = MODULE.prepare_template(deployed)
    before = deployed["TemplateBody"]["Resources"]
    after = prepared["Resources"]
    target = after["KaevoCloudHttpApi"]["Properties"]["Body"]["paths"][
        "/v2/household/invitations/{invitationId}"
    ]["delete"]
    source = before["KaevoCloudHttpApi"]["Properties"]["Body"]["paths"][
        "/v2/household/invitations/{invitationId}/revoke"
    ]["post"]

    assert target == source
    assert after["Unrelated"] == before["Unrelated"]
    permission = after[
        "KaevoCloudApiFunctionDeleteHouseholdInvitationPermission"
    ]
    assert permission["Properties"]["SourceArn"]["Fn::Sub"][0].endswith(
        "/DELETE/v2/household/invitations/*"
    )
    assert "/v2/household/invitations/{invitationId}" not in (
        before["KaevoCloudHttpApi"]["Properties"]["Body"]["paths"]
    )


def test_refuses_inline_body_update_when_external_routes_exist():
    deployed = wrapper()
    deployed["TemplateBody"]["Resources"]["ProtectedIdentityRoute"] = {
        "Type": "AWS::ApiGatewayV2::Route",
        "Properties": {
            "ApiId": {"Ref": "KaevoCloudHttpApi"},
            "AuthorizationType": "NONE",
            "RouteKey": "GET /v3/identity/me",
            "Target": {
                "Fn::Join": [
                    "/",
                    ["integrations", {"Ref": "ProtectedIdentityIntegration"}],
                ]
            },
        },
    }

    try:
        MODULE.prepare_template(deployed)
    except ValueError as error:
        assert "refusing to update the inline HTTP API body" in str(error)
    else:
        raise AssertionError("unsafe inline API body update must be rejected")

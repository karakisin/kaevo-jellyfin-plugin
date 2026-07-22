from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PREPARE = load_script("prepare-v3-api-only-template.py")
SCOPE = load_script("assert-pairing-v3-change-set-scope.py")


def template(*, include_v2: bool, v1_method: str = "POST") -> str:
    v2 = "" if not include_v2 else """        MintHomeConnectorPairingGrant:
          Type: HttpApi
          Properties:
            ApiId:
              Ref: KaevoCloudHttpApi
            Path: /v2/home-connectors/pairing/grants
            Method: POST
        StartHomeConnectorPairingWithGrant:
          Type: HttpApi
          Properties:
            ApiId:
              Ref: KaevoCloudHttpApi
            Path: /v2/home-connectors/pairing/start
            Method: POST
"""
    return f"""Resources:
  KaevoIdentityClaimIssuerFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: s3://candidate/identity
  KaevoOwnerEnrollmentFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: s3://candidate/owner
  KaevoCloudApiFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: s3://candidate/api
      Events:
        StartHomeConnectorPairing:
          Type: HttpApi
          Properties:
            ApiId:
              Ref: KaevoCloudHttpApi
            Path: /v1/home-connectors/pairing/start
            Method: {v1_method}
            Auth:
              Authorizer: KaevoOwnerAuthorizer
{v2}        IssueHomeConnectorPairingAuthorizationV3:
          Type: HttpApi
          Properties:
            ApiId:
              Ref: KaevoCloudHttpApi
            Path: /v3/home-connectors/pairing/authorizations
            Method: POST
    Metadata:
      SamResourceId: KaevoCloudApiFunction
  KaevoCloudHttpApi:
    Type: AWS::Serverless::HttpApi
    Metadata:
      SamResourceId: KaevoCloudHttpApi
"""


def test_api_only_preparation_copies_missing_deployed_v2_events_and_pins_identity_artifacts():
    deployed = template(include_v2=True).replace("s3://candidate/identity", "s3://live/identity").replace("s3://candidate/owner", "s3://live/owner")
    prepared = PREPARE.prepare_template(template(include_v2=False), deployed)
    assert "MintHomeConnectorPairingGrant:" in prepared
    assert "StartHomeConnectorPairingWithGrant:" in prepared
    assert "Path: /v2/home-connectors/pairing/grants" in prepared
    assert "Path: /v2/home-connectors/pairing/start" in prepared
    assert "Path: /v3/home-connectors/pairing/authorizations" in prepared
    assert "CodeUri: s3://live/identity" in prepared
    assert "CodeUri: s3://live/owner" in prepared
    assert "KaevoCloudHttpApi:\n    Type: AWS::Serverless::HttpApi\n    Metadata:\n      SamResourceId: KaevoCloudHttpApi" in prepared


def test_connector_control_preparation_pins_complete_existing_api_resource():
    deployed = template(include_v2=True)
    candidate = deployed.replace("CodeUri: s3://candidate/api", "CodeUri: s3://candidate/new-api")
    candidate = candidate.replace("      Events:\n", "      Environment:\n        Variables:\n          FORBIDDEN_DRIFT: true\n      Events:\n", 1)
    prepared = PREPARE.prepare_template(candidate, deployed)
    assert PREPARE.resource_section(prepared, "KaevoCloudApiFunction") == PREPARE.resource_section(deployed, "KaevoCloudApiFunction")
    assert "FORBIDDEN_DRIFT" not in PREPARE.resource_section(prepared, "KaevoCloudApiFunction")


def test_pinning_last_deployed_resource_does_not_swallow_new_candidate_resources():
    deployed = template(include_v2=True).replace(
        "  KaevoCloudHttpApi:\n    Type: AWS::Serverless::HttpApi\n    Metadata:\n      SamResourceId: KaevoCloudHttpApi\n",
        "  KaevoCloudHttpApi:\n    Type: AWS::Serverless::HttpApi\n    Metadata:\n      SamResourceId: KaevoCloudHttpApi\nOutputs:\n  ApiUrl:\n    Value: deployed\n",
    )
    candidate = template(include_v2=True).replace(
        "  KaevoCloudHttpApi:\n    Type: AWS::Serverless::HttpApi\n    Metadata:\n      SamResourceId: KaevoCloudHttpApi\n",
        "  KaevoCloudHttpApi:\n    Type: AWS::Serverless::HttpApi\n    Metadata:\n      SamResourceId: KaevoCloudHttpApi\n  KaevoV3ConnectorControlFunction:\n    Type: AWS::Serverless::Function\n    Properties:\n      CodeUri: dedicated.zip\nOutputs:\n  ApiUrl:\n    Value: candidate\n",
    )
    prepared = PREPARE.prepare_template(candidate, deployed)
    assert "  KaevoV3ConnectorControlFunction:\n" in prepared
    assert prepared.count("Outputs:\n") == 1


def test_api_only_preparation_restores_deployed_http_api_metadata():
    deployed = template(include_v2=True)
    candidate = deployed.replace("    Metadata:\n      SamResourceId: KaevoCloudHttpApi\n", "")
    prepared = PREPARE.prepare_template(candidate, deployed)
    assert "KaevoCloudHttpApi:\n    Type: AWS::Serverless::HttpApi\n    Metadata:\n      SamResourceId: KaevoCloudHttpApi" in prepared


def test_api_only_preparation_restores_a_changed_deployed_legacy_event():
    deployed = template(include_v2=True)
    prepared = PREPARE.prepare_template(template(include_v2=True, v1_method="GET"), deployed)
    assert PREPARE.resource_section(prepared, "KaevoCloudApiFunction") == PREPARE.resource_section(deployed, "KaevoCloudApiFunction")
    assert "Method: GET" not in PREPARE.resource_section(prepared, "KaevoCloudApiFunction")


def test_v3_change_set_scope_allowlist_rejects_legacy_permission_removal():
    rejected = {"Changes": [{"ResourceChange": {
        "LogicalResourceId": "KaevoCloudApiFunctionMintHomeConnectorPairingGrantPermission",
        "Action": "Remove", "Replacement": "False",
    }}]}
    assert SCOPE.scope_errors(rejected) == [
        "forbidden removal: KaevoCloudApiFunctionMintHomeConnectorPairingGrantPermission"
    ]


def test_v3_change_set_scope_allowlist_accepts_only_reviewed_resources():
    reviewed = {"Changes": [
        {"ResourceChange": {"LogicalResourceId": logical_id, "Action": "Add", "Replacement": "False"}}
        for logical_id in sorted(SCOPE.ALLOWED_ADDS)
    ] + [
        {"ResourceChange": {"LogicalResourceId": logical_id, "Action": "Modify", "Replacement": "False"}}
        for logical_id in sorted(SCOPE.ALLOWED_MODIFIES)
    ]}
    assert SCOPE.scope_errors(json.loads(json.dumps(reviewed))) == []


def test_v3_change_set_scope_rejects_existing_api_function_or_role_change():
    for logical_id in ("KaevoCloudApiFunction", "KaevoCloudApiFunctionRole"):
        rejected = {"Changes": [{"ResourceChange": {
            "LogicalResourceId": logical_id, "Action": "Modify", "Replacement": "False",
        }}]}
        assert SCOPE.scope_errors(rejected) == [f"unexpected modification: {logical_id}"]


def test_dedicated_control_lambda_has_exact_routes_and_least_privilege_boundary():
    source = (ROOT / "infra" / "template.yaml").read_text()
    control = PREPARE.resource_section(source, "KaevoV3ConnectorControlFunction")
    role = PREPARE.resource_section(source, "KaevoV3ConnectorControlFunctionRole")
    api = PREPARE.resource_section(source, "KaevoCloudApiFunction")
    expected = {
        "/v3/home-connectors/register",
        "/v3/home-connectors/{connectorId}/heartbeat",
        "/v3/home-connectors/{connectorId}/relay-ticket",
        "/v3/remote-requests/claim",
        "/v3/remote-requests/{requestId}/complete",
        "/v3/remote-requests/{requestId}/fail",
    }
    assert set(PREPARE.PATH_LINE.findall(control)) == expected
    assert all(path not in PREPARE.PATH_LINE.findall(api) for path in expected)
    assert "CodeUri: ../api/" in control
    assert "Handler: connector_control_handler.lambda_handler" in control
    assert "PAIRING_V3_AUTHORIZATION_SIGNING_SEED" not in control
    assert "KaevoPairingV3AuthorizationSigningSecret" not in control + role
    assert "secretsmanager:" not in role
    assert "kms:" not in role
    assert 'Resource: "*"' not in role
    actions = set(re.findall(r"^                  - ([a-z0-9-]+:[A-Za-z0-9*]+)$", role, re.MULTILINE))
    assert actions == {
        "logs:CreateLogStream", "logs:PutLogEvents", "dynamodb:GetItem",
        "dynamodb:UpdateItem", "dynamodb:PutItem", "dynamodb:Query", "s3:PutObject",
    }
    assert "ReadAndTransitionRemoteRequestRecords" in role
    assert "QueryPendingRemoteRequestsByConnector" in role

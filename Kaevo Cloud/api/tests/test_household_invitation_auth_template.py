from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PREPARE = load_script("prepare-household-invitation-auth-template.py")
SCOPE = load_script("assert-household-invitation-auth-change-set-scope.py")


def template(
    *,
    household_authorizer: bool,
    unrelated_method: str = "POST",
    include_deployed_only_route: bool = False,
) -> str:
    auth = "" if not household_authorizer else """            Auth:
              Authorizer: KaevoOwnerAuthorizer
"""
    deployed_only = "" if not include_deployed_only_route else """        DeployedOnlyV2Route:
          Type: HttpApi
          Properties:
            ApiId:
              Ref: KaevoCloudHttpApi
            Path: /v2/deployed-only
            Method: POST
"""
    return f"""Resources:
  KaevoCloudApiFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: s3://immutable/api
      Events:
        ExistingRoute:
          Type: HttpApi
          Properties:
            ApiId:
              Ref: KaevoCloudHttpApi
            Path: /v1/existing
            Method: {unrelated_method}
{deployed_only}        HouseholdInvitations:
          Type: HttpApi
          Properties:
            ApiId:
              Ref: KaevoCloudHttpApi
            Path: /v2/household/invitations
            Method: ANY
{auth}        RevokeHouseholdInvitation:
          Type: HttpApi
          Properties:
            ApiId:
              Ref: KaevoCloudHttpApi
            Path: /v2/household/invitations/{{invitationId}}/revoke
            Method: POST
{auth}    Metadata:
      SamResourceId: KaevoCloudApiFunction
  KaevoCloudHttpApi:
    Type: AWS::Serverless::HttpApi
    Metadata:
      SamResourceId: KaevoCloudHttpApi
"""


def test_source_household_routes_rely_on_lambda_dpop_validation_not_gateway_jwt():
    source = (ROOT / "infra" / "template.yaml").read_text()
    events = PREPARE.HELPER.api_events(source)[0]
    assert "Authorizer:" not in events["HouseholdInvitations"].text
    assert "Authorizer:" not in events["RevokeHouseholdInvitation"].text


def test_preparation_changes_only_two_household_event_blocks():
    deployed = template(household_authorizer=True)
    candidate = template(household_authorizer=False)
    prepared = PREPARE.prepare_template(candidate, deployed)
    actual = PREPARE.HELPER.api_events(prepared)[0]
    before = PREPARE.HELPER.api_events(deployed)[0]
    wanted = PREPARE.HELPER.api_events(candidate)[0]

    assert actual["HouseholdInvitations"] == wanted["HouseholdInvitations"]
    assert actual["RevokeHouseholdInvitation"] == wanted["RevokeHouseholdInvitation"]
    assert actual["ExistingRoute"] == before["ExistingRoute"]
    assert PREPARE.HELPER.resource_section(prepared, "KaevoCloudApiFunction").count("CodeUri: s3://immutable/api") == 1


def test_preparation_preserves_deployed_legacy_events_missing_from_clean_checkout():
    deployed = template(household_authorizer=True, include_deployed_only_route=True)
    candidate = template(household_authorizer=False)

    prepared = PREPARE.prepare_template(candidate, deployed)
    actual = PREPARE.HELPER.api_events(prepared)[0]
    before = PREPARE.HELPER.api_events(deployed)[0]

    assert actual["DeployedOnlyV2Route"] == before["DeployedOnlyV2Route"]
    assert "Authorizer:" not in actual["HouseholdInvitations"].text
    assert "Authorizer:" not in actual["RevokeHouseholdInvitation"].text


def test_preparation_rejects_any_unrelated_event_drift():
    deployed = template(household_authorizer=True)
    candidate = template(household_authorizer=False, unrelated_method="GET")
    prepared = PREPARE.prepare_template(candidate, deployed)
    actual = PREPARE.HELPER.api_events(prepared)[0]
    assert "Method: POST" in actual["ExistingRoute"].text
    assert "Method: GET" not in actual["ExistingRoute"].text


def test_scope_accepts_only_in_place_http_api_modification():
    approved = {"Changes": [{"ResourceChange": {
        "LogicalResourceId": "KaevoCloudHttpApi",
        "ResourceType": "AWS::ApiGatewayV2::Api",
        "Action": "Modify",
        "Replacement": "False",
    }}]}
    assert SCOPE.scope_errors(json.loads(json.dumps(approved))) == []


def test_scope_rejects_lambda_iam_add_remove_and_replacement():
    rejected = {"Changes": [
        {"ResourceChange": {"LogicalResourceId": "KaevoCloudApiFunction", "Action": "Modify", "Replacement": "False"}},
        {"ResourceChange": {"LogicalResourceId": "UnexpectedPermission", "Action": "Add", "Replacement": "False"}},
        {"ResourceChange": {"LogicalResourceId": "LegacyRoutePermission", "Action": "Remove", "Replacement": "False"}},
        {"ResourceChange": {"LogicalResourceId": "KaevoCloudHttpApi", "Action": "Modify", "Replacement": "Conditional"}},
    ]}
    assert SCOPE.scope_errors(rejected) == [
        "unexpected modify: KaevoCloudApiFunction",
        "unexpected add: UnexpectedPermission",
        "unexpected remove: LegacyRoutePermission",
        "forbidden replacement: KaevoCloudHttpApi (Conditional)",
    ]

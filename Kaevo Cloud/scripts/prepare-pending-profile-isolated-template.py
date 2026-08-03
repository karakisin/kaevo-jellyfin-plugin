#!/usr/bin/env python3
"""Prepare a dedicated Household Join-only candidate from the live template."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import subprocess
from urllib.parse import urlparse


UPDATED = {"KaevoHouseholdJoinFunctionRole", "KaevoHouseholdJoinFunction"}
ADDED = {"KaevoHouseholdJoinOnboardingStatusRoute", "KaevoHouseholdJoinProfileSetupRoute"}


def ref(name: str) -> dict:
    return {"Ref": name}


def get_att(name: str) -> dict:
    return {"Fn::GetAtt": [name, "Arn"]}


def s3_code(uri: str) -> dict:
    parsed = urlparse(uri)
    if parsed.scheme != "s3" or not parsed.netloc or not parsed.path.strip("/"):
        raise ValueError("artifact URI must be a complete s3://bucket/key URI")
    return {"S3Bucket": parsed.netloc, "S3Key": parsed.path.lstrip("/")}


def join_policy() -> dict:
    reads = (
        "KaevoHouseholdInvitationsTable", "KaevoPrincipalsTable", "KaevoIdentityMembershipsTable",
        "KaevoIdentityProfilesTable", "KaevoEntitlementsTable", "KaevoAccountsTable",
        "KaevoAuthIdentitiesTable", "KaevoHouseholdMembershipsTable", "KaevoProfilesTable",
        "KaevoProfileBindingsTable", "KaevoProfileMappingsTable",
    )
    transactional = (
        "KaevoHouseholdJoinTransactionsTable", "KaevoHouseholdInvitationsTable", "KaevoPrincipalsTable",
        "KaevoIdentityMembershipsTable", "KaevoIdentityProfilesTable", "KaevoEntitlementsTable",
        "KaevoAccountsTable", "KaevoAuthIdentitiesTable", "KaevoHouseholdMembershipsTable",
        "KaevoProfilesTable", "KaevoProfileBindingsTable", "KaevoProfileMappingsTable",
    )
    return {"PolicyName": "KaevoHouseholdJoinLeastPrivilege", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                {"Sid": "WriteOwnLambdaLogs", "Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": {"Fn::Sub": "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/kaevo-cloud-${EnvironmentName}-household-join:*"}},
                {"Sid": "ReadAndTransitionJoinTransactions", "Effect": "Allow", "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"], "Resource": get_att("KaevoHouseholdJoinTransactionsTable")},
                {"Sid": "ReadInvitationAndOnboardingAuthority", "Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": [get_att(name) for name in reads]},
                {"Sid": "AtomicallyAdvanceHouseholdJoinOnboarding", "Effect": "Allow", "Action": ["dynamodb:TransactWriteItems"], "Resource": [get_att(name) for name in transactional]},
                {"Sid": "PutProfileSetupRecordsTransactionally", "Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": [get_att(name) for name in ("KaevoIdentityProfilesTable", "KaevoProfilesTable", "KaevoProfileBindingsTable", "KaevoProfileMappingsTable", "KaevoEntitlementsTable", "KaevoPrincipalsTable", "KaevoIdentityMembershipsTable")], "Condition": {"StringEquals": {"dynamodb:EnclosingOperation": "TransactWriteItems"}}},
                {"Sid": "ActivatePendingProfileMembershipTransactionally", "Effect": "Allow", "Action": ["dynamodb:UpdateItem"], "Resource": get_att("KaevoHouseholdMembershipsTable"), "Condition": {"StringEquals": {"dynamodb:EnclosingOperation": "TransactWriteItems"}}},
                {"Sid": "ResolveAuthenticatedSubjectOnly", "Effect": "Allow", "Action": ["cognito-idp:ListUsers"], "Resource": get_att("KaevoUserPool")},
            ]}}


def join_role(baseline_role: dict) -> dict:
    """Preserve every deployed role property except its reviewed inline policy."""
    candidate = copy.deepcopy(baseline_role)
    policies = candidate.get("Properties", {}).get("Policies")
    if not isinstance(policies, list):
        raise ValueError("dedicated role is missing inline policies")
    matches = [index for index, policy in enumerate(policies) if policy.get("PolicyName") == "KaevoHouseholdJoinLeastPrivilege"]
    if matches != [0] or len(policies) != 1:
        raise ValueError("dedicated role inline-policy shape changed unexpectedly")
    policies[0] = join_policy()
    return candidate


def join_environment() -> dict:
    values = {
        "HOUSEHOLD_JOIN_TRANSACTIONS_TABLE": ref("KaevoHouseholdJoinTransactionsTable"),
        "HOUSEHOLD_INVITATIONS_TABLE": ref("KaevoHouseholdInvitationsTable"),
        "PRINCIPALS_TABLE": ref("KaevoPrincipalsTable"),
        "IDENTITY_MEMBERSHIPS_TABLE": ref("KaevoIdentityMembershipsTable"),
        "IDENTITY_PROFILES_TABLE": ref("KaevoIdentityProfilesTable"),
        "ACCOUNTS_TABLE": ref("KaevoAccountsTable"),
        "AUTH_IDENTITIES_TABLE": ref("KaevoAuthIdentitiesTable"),
        "HOUSEHOLD_MEMBERSHIPS_TABLE": ref("KaevoHouseholdMembershipsTable"),
        "CLOUD_PROFILES_TABLE": ref("KaevoProfilesTable"),
        "PROFILE_BINDINGS_TABLE": ref("KaevoProfileBindingsTable"),
        "PROFILE_MAPPINGS_TABLE": ref("KaevoProfileMappingsTable"),
        "ENTITLEMENTS_TABLE": ref("KaevoEntitlementsTable"),
        "COGNITO_USER_POOL_ID": ref("KaevoUserPool"),
        "EXPECTED_COGNITO_ISSUER": {"Fn::Sub": "https://cognito-idp.${AWS::Region}.amazonaws.com/${KaevoUserPool}"},
        "EXPECTED_NATIVE_CLIENT_ID": {"Fn::If": ["HasNativeOidc", ref("KaevoSecurityStageNativeOidcClient"), ""]},
        "EXPECTED_NATIVE_CALLBACK_URI": "kaevo://oauth/callback",
        "NATIVE_OIDC_AUTHORIZATION_ENDPOINT": "https://auth.kaevo.watch/oauth2/authorize",
        "PUBLIC_API_BASE_URL": "https://api.kaevo.watch",
        "HOUSEHOLD_JOIN_AUTHORIZE_BASE_URL": "https://api.kaevo.watch/v3/identity/household-joins/authorize",
    }
    return {"Variables": values}


def route(key: str) -> dict:
    return {"Type": "AWS::ApiGatewayV2::Route", "Properties": {
        "ApiId": ref("KaevoCloudHttpApi"), "AuthorizationType": "JWT",
        "AuthorizerId": ref("KaevoHouseholdJoinAuthorizer"), "RouteKey": key,
        "Target": {"Fn::Join": ["/", ["integrations", ref("KaevoHouseholdJoinIntegration")]]},
    }}


def live_baseline(stack_name: str, region: str, profile: str) -> dict:
    command = ["aws", "cloudformation", "get-template", "--stack-name", stack_name, "--template-stage", "Original", "--region", region, "--output", "json"]
    if profile:
        command.extend(["--profile", profile])
    output = subprocess.run(command, check=True, capture_output=True, text=True).stdout
    body = json.loads(output)["TemplateBody"]
    return json.loads(body) if isinstance(body, str) else body


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--artifact-s3-uri", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    baseline = live_baseline(args.stack_name, args.region, args.profile)
    candidate = copy.deepcopy(baseline)
    resources = candidate["Resources"]
    required = UPDATED | {"KaevoHouseholdJoinAuthorizer", "KaevoHouseholdJoinIntegration"}
    missing = required - set(resources)
    if missing:
        raise ValueError(f"live template missing expected dedicated resource(s): {sorted(missing)}")
    resources["KaevoHouseholdJoinFunctionRole"] = join_role(resources["KaevoHouseholdJoinFunctionRole"])
    function = resources["KaevoHouseholdJoinFunction"]
    function["Properties"]["Code"] = s3_code(args.artifact_s3_uri)
    function["Properties"]["Environment"] = join_environment()
    resources["KaevoHouseholdJoinOnboardingStatusRoute"] = route("GET /v3/identity/household-joins/onboarding-status")
    resources["KaevoHouseholdJoinProfileSetupRoute"] = route("POST /v3/identity/household-joins/profile-setup")

    baseline_resources = baseline["Resources"]
    changed = {name for name in baseline_resources if resources[name] != baseline_resources[name]}
    added = set(resources) - set(baseline_resources)
    removed = set(baseline_resources) - set(resources)
    if changed != UPDATED or added != ADDED or removed:
        raise ValueError(f"candidate scope mismatch changed={sorted(changed)} added={sorted(added)} removed={sorted(removed)}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(candidate, indent=2) + "\n")
    print("PENDING_PROFILE_TEMPLATE_SCOPE=APPROVED")
    print("MODIFIED=KaevoHouseholdJoinFunctionRole,KaevoHouseholdJoinFunction")
    print("ADDED=KaevoHouseholdJoinOnboardingStatusRoute,KaevoHouseholdJoinProfileSetupRoute")


if __name__ == "__main__":
    main()

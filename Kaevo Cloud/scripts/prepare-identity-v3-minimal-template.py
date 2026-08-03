#!/usr/bin/env python3
"""Build an Identity V3-only CloudFormation candidate from a deployed baseline.

This intentionally consumes the deployed *processed* template instead of the
local SAM template.  Keeping every existing resource object unchanged avoids
SAM's regenerated OpenAPI body, Cognito trigger, domain metadata, and
unrelated function drift.  The output is plain CloudFormation JSON without a
Transform.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from urllib.parse import urlparse


TABLES = {
    "KaevoAccountsTable": {
        "name": "accounts",
        "attributes": [("account_id", "S")],
        "key_schema": [("account_id", "HASH")],
    },
    "KaevoAuthIdentitiesTable": {
        "name": "auth-identities",
        "attributes": [
            ("auth_identity_key", "S"),
            ("account_id", "S"),
            ("created_at_epoch", "N"),
        ],
        "key_schema": [("auth_identity_key", "HASH")],
        "indexes": [("account_id-created_at_epoch-index", [("account_id", "HASH"), ("created_at_epoch", "RANGE")])],
    },
    "KaevoHouseholdMembershipsTable": {
        "name": "household-memberships",
        "attributes": [
            ("household_id", "S"),
            ("membership_id", "S"),
            ("account_id", "S"),
            ("updated_at_epoch", "N"),
        ],
        "key_schema": [("household_id", "HASH"), ("membership_id", "RANGE")],
        "indexes": [("account_id-updated_at_epoch-index", [("account_id", "HASH"), ("updated_at_epoch", "RANGE")])],
    },
    "KaevoProfilesTable": {
        "name": "profiles",
        "attributes": [("profile_id", "S"), ("household_id", "S"), ("created_at_epoch", "N")],
        "key_schema": [("profile_id", "HASH")],
        "indexes": [("household_id-created_at_epoch-index", [("household_id", "HASH"), ("created_at_epoch", "RANGE")])],
    },
    "KaevoProfileBindingsTable": {
        "name": "profile-bindings",
        "attributes": [("account_id", "S"), ("profile_id", "S")],
        "key_schema": [("account_id", "HASH"), ("profile_id", "RANGE")],
    },
    "KaevoProfileMappingsTable": {
        "name": "profile-mappings",
        "attributes": [("installation_id", "S"), ("local_profile_source_id", "S")],
        "key_schema": [("installation_id", "HASH"), ("local_profile_source_id", "RANGE")],
    },
}

ROUTES = (
    ("KaevoIdentityV3GetContextRoute", "GET /v3/identity/me"),
    ("KaevoIdentityV3MigrateExistingAccountRoute", "POST /v3/identity/migrate-existing-account"),
    ("KaevoIdentityV3MigrateHouseholdMembershipRoute", "POST /v3/identity/migrate-household-membership"),
    ("KaevoIdentityV3CreateProfileRoute", "POST /v3/identity/profiles"),
    ("KaevoIdentityV3CreateProfileBindingRoute", "POST /v3/identity/profiles/{profileId}/bindings"),
    ("KaevoIdentityV3ListProfileMappingsRoute", "GET /v3/identity/profile-mappings"),
    ("KaevoIdentityV3PreviewProfileMappingRoute", "POST /v3/identity/profile-mappings/preview"),
    ("KaevoIdentityV3ConfirmProfileMappingRoute", "POST /v3/identity/profile-mappings/confirm"),
    ("KaevoIdentityV3CreateAndConfirmProfileMappingRoute", "POST /v3/identity/profile-mappings/create-and-confirm"),
)
UPDATED_RESOURCES = {"KaevoCloudApiFunction", "KaevoOwnerEnrollmentFunction"}


def ref(name: str) -> dict:
    return {"Ref": name}


def get_att(name: str) -> dict:
    return {"Fn::GetAtt": [name, "Arn"]}


def table_resource(spec: dict) -> dict:
    props = {
        "TableName": {"Fn::Sub": f"kaevo-cloud-${{EnvironmentName}}-{spec['name']}"},
        "BillingMode": "PAY_PER_REQUEST",
        "SSESpecification": {"SSEEnabled": True},
        "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
        "AttributeDefinitions": [{"AttributeName": name, "AttributeType": kind} for name, kind in spec["attributes"]],
        "KeySchema": [{"AttributeName": name, "KeyType": kind} for name, kind in spec["key_schema"]],
        "Tags": [{"Key": "KaevoDataClass", "Value": "identity-authority"}],
    }
    if indexes := spec.get("indexes"):
        props["GlobalSecondaryIndexes"] = [
            {
                "IndexName": name,
                "KeySchema": [{"AttributeName": attribute, "KeyType": kind} for attribute, kind in schema],
                "Projection": {"ProjectionType": "ALL"},
            }
            for name, schema in indexes
        ]
    return {"Type": "AWS::DynamoDB::Table", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "Properties": props}


def s3_code(uri: str) -> dict:
    parsed = urlparse(uri)
    if parsed.scheme != "s3" or not parsed.netloc or not parsed.path.strip("/"):
        raise ValueError("identity code URI must be a complete s3://bucket/key URI")
    return {"S3Bucket": parsed.netloc, "S3Key": parsed.path.lstrip("/")}


def table_arns(names: tuple[str, ...]) -> list[dict]:
    resources: list[dict] = []
    for name in names:
        resources.append(get_att(name))
        resources.append({"Fn::Sub": f"${{{name}.Arn}}/index/*"})
    return resources


def iam_policy(role: str, actions: list[str], tables: tuple[str, ...]) -> dict:
    return {
        "Type": "AWS::IAM::Policy",
        "Properties": {
            "PolicyName": "KaevoIdentityV3DataAccess",
            "Roles": [ref(role)],
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{"Sid": "IdentityV3DataAccess", "Effect": "Allow", "Action": actions, "Resource": table_arns(tables)}],
            },
        },
    }


def identity_v3_environment() -> dict:
    """Only configuration evaluated by the nine Identity V3 code paths."""
    return {
        "KAEVO_ENV": ref("EnvironmentName"),
        "PUBLIC_API_BASE_URL": "https://api.kaevo.watch",
        "EXPECTED_COGNITO_ISSUER": {"Fn::Sub": "https://cognito-idp.${AWS::Region}.amazonaws.com/${KaevoUserPool}"},
        "AUDIT_REFERENCE_SECRET_ARN": ref("KaevoAuditReferenceSecret"),
        "APP_SESSIONS_TABLE": ref("KaevoAppSessionsTable"),
        "INSTALLATIONS_TABLE": ref("KaevoInstallationsTable"),
        "SECURITY_AUDIT_TABLE": ref("KaevoSecurityAuditTable"),
        "PRINCIPALS_TABLE": ref("KaevoPrincipalsTable"),
        "IDENTITY_MEMBERSHIPS_TABLE": ref("KaevoIdentityMembershipsTable"),
        "IDENTITY_HOUSEHOLDS_TABLE": ref("KaevoIdentityHouseholdsTable"),
        "IDENTITY_PROFILES_TABLE": ref("KaevoIdentityProfilesTable"),
        "ACCOUNTS_TABLE": ref("KaevoAccountsTable"),
        "AUTH_IDENTITIES_TABLE": ref("KaevoAuthIdentitiesTable"),
        "HOUSEHOLD_MEMBERSHIPS_TABLE": ref("KaevoHouseholdMembershipsTable"),
        "PROFILES_TABLE": ref("KaevoProfilesTable"),
        "PROFILE_BINDINGS_TABLE": ref("KaevoProfileBindingsTable"),
        "PROFILE_MAPPINGS_TABLE": ref("KaevoProfileMappingsTable"),
    }


def identity_v3_role() -> dict:
    return {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "RoleName": {"Fn::Sub": "kaevo-cloud-${EnvironmentName}-identity-v3-api"},
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            },
            "Tags": [{"Key": "KaevoSecurityBoundary", "Value": "identity-v3-api"}],
        },
    }


def identity_v3_data_policy() -> dict:
    """Exact service actions used by the dedicated Identity V3 handler paths."""
    read_identity_graph = [
        get_att("KaevoPrincipalsTable"), get_att("KaevoIdentityMembershipsTable"),
        get_att("KaevoIdentityHouseholdsTable"), get_att("KaevoIdentityProfilesTable"),
    ]
    read_normalized = [
        get_att("KaevoAccountsTable"), get_att("KaevoAuthIdentitiesTable"),
        get_att("KaevoHouseholdMembershipsTable"), get_att("KaevoProfilesTable"),
        get_att("KaevoProfileBindingsTable"), get_att("KaevoProfileMappingsTable"),
    ]
    query_resources = [
        get_att("KaevoAuthIdentitiesTable"), {"Fn::Sub": "${KaevoAuthIdentitiesTable.Arn}/index/*"},
        get_att("KaevoProfileBindingsTable"), get_att("KaevoProfileMappingsTable"),
    ]
    # DynamoDB authorizes every item operation embedded in a transaction.  The
    # existing-account migration writes only these two normalized records; its
    # audit record is covered by WriteIdentitySecurityAudit below.
    existing_account_migration_records = [
        get_att("KaevoAccountsTable"), get_att("KaevoAuthIdentitiesTable"),
    ]
    # The household migration writes only its deterministic membership and
    # guards to this table; its completion audit remains separately scoped.
    household_membership_migration_records = [get_att("KaevoHouseholdMembershipsTable")]
    # Create-and-confirm writes these three records in one transaction. The
    # audit write remains under the existing audit-only statement below.
    profile_bootstrap_records = [
        get_att("KaevoProfilesTable"), get_att("KaevoProfileBindingsTable"),
        get_att("KaevoProfileMappingsTable"),
    ]
    transaction_resources = read_normalized + [get_att("KaevoSecurityAuditTable")]
    log_group_arn = {"Fn::Sub": "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/kaevo-cloud-${EnvironmentName}-identity-v3-api:*"}
    return {
        "Type": "AWS::IAM::Policy",
        "Properties": {
            "PolicyName": "KaevoIdentityV3LeastPrivilege",
            "Roles": [ref("KaevoIdentityV3ApiRole")],
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Sid": "ReadProtectedSessionAndInstallation", "Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": [get_att("KaevoAppSessionsTable"), get_att("KaevoInstallationsTable")]},
                    {"Sid": "RecordDpopReplay", "Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": get_att("KaevoAppSessionsTable")},
                    {"Sid": "ReadExistingIdentityGraph", "Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": read_identity_graph},
                    {"Sid": "ReadNormalizedIdentity", "Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": read_normalized},
                    {"Sid": "QueryAuthorizedIdentityIndexes", "Effect": "Allow", "Action": ["dynamodb:Query"], "Resource": query_resources},
                    {"Sid": "WriteExistingAccountMigrationRecords", "Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": existing_account_migration_records},
                    {"Sid": "WriteHouseholdMembershipMigrationRecords", "Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": household_membership_migration_records},
                    {"Sid": "WriteProfileBootstrapRecords", "Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": profile_bootstrap_records},
                    {"Sid": "WriteIdentityTransitionsAtomically", "Effect": "Allow", "Action": ["dynamodb:TransactWriteItems"], "Resource": transaction_resources},
                    {"Sid": "WriteIdentitySecurityAudit", "Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": get_att("KaevoSecurityAuditTable")},
                    {"Sid": "ReadAuditReferenceKey", "Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": ref("KaevoAuditReferenceSecret")},
                    {"Sid": "CreateOwnLogGroup", "Effect": "Allow", "Action": ["logs:CreateLogGroup"], "Resource": "*"},
                    {"Sid": "WriteOwnLambdaLogs", "Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": log_group_arn},
                ],
            },
        },
    }


def ensure_scope(baseline: dict, candidate: dict) -> None:
    baseline_resources = baseline["Resources"]
    candidate_resources = candidate["Resources"]
    unexpected_removed = set(baseline_resources) - set(candidate_resources)
    if unexpected_removed:
        raise ValueError(f"candidate removed baseline resources: {sorted(unexpected_removed)}")
    changed = {
        name
        for name in baseline_resources
        if candidate_resources[name] != baseline_resources[name]
    }
    if changed != UPDATED_RESOURCES:
        raise ValueError(f"unexpected baseline resource modifications: {sorted(changed)}")
    expected_added = set(TABLES) | {"KaevoIdentityV3ApiIntegration", "KaevoIdentityV3InvokePermission", "KaevoIdentityV3ApiDataPolicy", "KaevoIdentityV3OwnerEnrollmentDataPolicy"} | {name for name, _ in ROUTES}
    actual_added = set(candidate_resources) - set(baseline_resources)
    if actual_added != expected_added:
        raise ValueError(f"unexpected resource additions: {sorted(actual_added ^ expected_added)}")


def prepare(baseline: dict, identity_code_uri: str) -> dict:
    candidate = copy.deepcopy(baseline)
    resources = candidate["Resources"]
    code = s3_code(identity_code_uri)
    for function in UPDATED_RESOURCES:
        resources[function]["Properties"]["Code"] = code

    api_variables = resources["KaevoCloudApiFunction"]["Properties"]["Environment"]["Variables"]
    api_variables.update({
        "ACCOUNTS_TABLE": ref("KaevoAccountsTable"),
        "AUTH_IDENTITIES_TABLE": ref("KaevoAuthIdentitiesTable"),
        "HOUSEHOLD_MEMBERSHIPS_TABLE": ref("KaevoHouseholdMembershipsTable"),
        "PROFILES_TABLE": ref("KaevoProfilesTable"),
        "PROFILE_BINDINGS_TABLE": ref("KaevoProfileBindingsTable"),
        "PROFILE_MAPPINGS_TABLE": ref("KaevoProfileMappingsTable"),
    })
    owner_variables = resources["KaevoOwnerEnrollmentFunction"]["Properties"]["Environment"]["Variables"]
    owner_variables.update({"ACCOUNTS_TABLE": ref("KaevoAccountsTable"), "AUTH_IDENTITIES_TABLE": ref("KaevoAuthIdentitiesTable")})

    resources.update({name: table_resource(spec) for name, spec in TABLES.items()})
    resources["KaevoIdentityV3ApiIntegration"] = {
        "Type": "AWS::ApiGatewayV2::Integration",
        "Properties": {
            "ApiId": ref("KaevoCloudHttpApi"),
            "IntegrationType": "AWS_PROXY",
            "IntegrationMethod": "POST",
            "PayloadFormatVersion": "2.0",
            "IntegrationUri": {"Fn::Sub": [
                "arn:${AWS::Partition}:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${FunctionArn}/invocations",
                {"FunctionArn": get_att("KaevoCloudApiFunction")},
            ]},
        },
    }
    resources["KaevoIdentityV3InvokePermission"] = {
        "Type": "AWS::Lambda::Permission",
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": ref("KaevoCloudApiFunction"),
            "Principal": "apigateway.amazonaws.com",
            "SourceArn": {"Fn::Sub": "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${KaevoCloudHttpApi}/*/*/v3/identity/*"},
        },
    }
    for name, route_key in ROUTES:
        resources[name] = {
            "Type": "AWS::ApiGatewayV2::Route",
            "Properties": {
                "ApiId": ref("KaevoCloudHttpApi"),
                "AuthorizationType": "NONE",
                "RouteKey": route_key,
                "Target": {"Fn::Join": ["/", ["integrations", ref("KaevoIdentityV3ApiIntegration")]]},
            },
        }

    all_tables = tuple(TABLES)
    resources["KaevoIdentityV3ApiDataPolicy"] = iam_policy(
        "KaevoCloudApiFunctionRole",
        ["dynamodb:BatchGetItem", "dynamodb:BatchWriteItem", "dynamodb:ConditionCheckItem", "dynamodb:DeleteItem", "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:TransactGetItems", "dynamodb:TransactWriteItems", "dynamodb:UpdateItem"],
        all_tables,
    )
    resources["KaevoIdentityV3OwnerEnrollmentDataPolicy"] = iam_policy(
        "KaevoOwnerEnrollmentFunctionRole",
        ["dynamodb:ConditionCheckItem", "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:TransactWriteItems", "dynamodb:UpdateItem"],
        ("KaevoAccountsTable", "KaevoAuthIdentitiesTable"),
    )
    ensure_scope(baseline, candidate)
    return candidate


def prepare_isolated(baseline: dict, identity_code_uri: str) -> dict:
    """Add a dedicated Identity V3 Lambda without mutating any baseline ARN.

    CloudFormation treats consumers of an updated Lambda's ``GetAtt Arn`` as
    dynamic, even when a code-only update cannot replace the function.  The
    deployed HTTP API Body and social dispatcher both consume the main API
    Lambda ARN.  A dedicated function avoids those unrelated change-set rows.
    """
    candidate = copy.deepcopy(baseline)
    resources = candidate["Resources"]
    resources.update({name: table_resource(spec) for name, spec in TABLES.items()})

    existing_api = resources["KaevoCloudApiFunction"]["Properties"]
    api_properties = {
        "FunctionName": {"Fn::Sub": "kaevo-cloud-${EnvironmentName}-identity-v3-api"},
        "Code": s3_code(identity_code_uri),
        "Handler": existing_api["Handler"],
        "Runtime": existing_api["Runtime"],
        "Timeout": existing_api["Timeout"],
        "MemorySize": existing_api["MemorySize"],
        "Architectures": existing_api["Architectures"],
        "Role": get_att("KaevoIdentityV3ApiRole"),
        "Environment": {"Variables": identity_v3_environment()},
    }
    # The deployed processed template represents Lambda tags as a list.  Keep
    # that accepted CloudFormation shape for the dedicated function too.
    api_properties["Tags"] = [
        {"Key": "lambda:createdBy", "Value": "SAM"},
        {"Key": "KaevoSecurityBoundary", "Value": "identity-v3-api"},
    ]
    resources["KaevoIdentityV3ApiRole"] = identity_v3_role()
    resources["KaevoIdentityV3ApiFunction"] = {
        "Type": "AWS::Lambda::Function",
        "Properties": api_properties,
    }
    resources["KaevoIdentityV3ApiIntegration"] = {
        "Type": "AWS::ApiGatewayV2::Integration",
        "Properties": {
            "ApiId": ref("KaevoCloudHttpApi"),
            "IntegrationType": "AWS_PROXY",
            "IntegrationMethod": "POST",
            "PayloadFormatVersion": "2.0",
            "IntegrationUri": {"Fn::Sub": [
                "arn:${AWS::Partition}:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${FunctionArn}/invocations",
                {"FunctionArn": get_att("KaevoIdentityV3ApiFunction")},
            ]},
        },
    }
    resources["KaevoIdentityV3InvokePermission"] = {
        "Type": "AWS::Lambda::Permission",
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": ref("KaevoIdentityV3ApiFunction"),
            "Principal": "apigateway.amazonaws.com",
            "SourceArn": {"Fn::Sub": "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${KaevoCloudHttpApi}/*/*/v3/identity/*"},
        },
    }
    for name, route_key in ROUTES:
        resources[name] = {
            "Type": "AWS::ApiGatewayV2::Route",
            "Properties": {
                "ApiId": ref("KaevoCloudHttpApi"),
                "AuthorizationType": "NONE",
                "RouteKey": route_key,
                "Target": {"Fn::Join": ["/", ["integrations", ref("KaevoIdentityV3ApiIntegration")]]},
            },
        }
    resources["KaevoIdentityV3ApiDataPolicy"] = identity_v3_data_policy()

    baseline_resources = baseline["Resources"]
    changed = [name for name in baseline_resources if resources[name] != baseline_resources[name]]
    expected_added = set(TABLES) | {"KaevoIdentityV3ApiRole", "KaevoIdentityV3ApiFunction", "KaevoIdentityV3ApiIntegration", "KaevoIdentityV3InvokePermission", "KaevoIdentityV3ApiDataPolicy"} | {name for name, _ in ROUTES}
    actual_added = set(resources) - set(baseline_resources)
    if changed:
        raise ValueError(f"isolated candidate modified baseline resources: {changed}")
    if actual_added != expected_added:
        raise ValueError(f"isolated candidate added unexpected resources: {sorted(actual_added ^ expected_added)}")
    return candidate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-processed-template", required=True, type=Path)
    parser.add_argument("--identity-code-s3-uri", required=True)
    parser.add_argument("--isolated", action="store_true", help="add a dedicated Identity V3 Lambda and preserve every baseline resource")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.deployed_processed_template.is_file():
        raise ValueError("deployed processed template must exist")
    if args.output.resolve() == args.deployed_processed_template.resolve():
        raise ValueError("output must differ from deployed processed template")
    baseline = json.loads(args.deployed_processed_template.read_text())
    candidate = prepare_isolated(baseline, args.identity_code_s3_uri) if args.isolated else prepare(baseline, args.identity_code_s3_uri)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(candidate, indent=2) + "\n")


if __name__ == "__main__":
    main()

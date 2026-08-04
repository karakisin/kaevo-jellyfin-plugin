#!/usr/bin/env python3
"""Prepare an exact-scope Identity V3 profile-deletion deployment template."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from urllib.parse import urlparse



FUNCTION = "KaevoIdentityV3ApiFunction"
POLICY = "KaevoIdentityV3ApiDataPolicy"
DELETION_SID = "ManageExactProfileDeletionGraph"

ENVIRONMENT_BINDINGS = {
    "PROFILE_EVENTS_TABLE": "KaevoProfileEventsTable",
    "PROFILE_SETTINGS_TABLE": "KaevoProfileSettingsTable",
    "DEVICES_TABLE": "KaevoDevicesTable",
    "ENTITLEMENTS_TABLE": "KaevoEntitlementsTable",
    "PROFILE_AVATARS_BUCKET": "KaevoProfileAvatarsBucket",
    "HOUSEHOLD_INVITATIONS_TABLE": "KaevoHouseholdInvitationsTable",
    "HOUSEHOLD_JOIN_TRANSACTIONS_TABLE": "KaevoHouseholdJoinTransactionsTable",
}

DELETION_TABLES = (
    "KaevoProfileEventsTable",
    "KaevoProfileSettingsTable",
    "KaevoDevicesTable",
    "KaevoEntitlementsTable",
    "KaevoAppSessionsTable",
    "KaevoHouseholdMembershipsTable",
    "KaevoProfilesTable",
    "KaevoProfileBindingsTable",
    "KaevoProfileMappingsTable",
    "KaevoPrincipalsTable",
    "KaevoIdentityMembershipsTable",
    "KaevoIdentityProfilesTable",
    "KaevoHouseholdInvitationsTable",
    "KaevoHouseholdJoinTransactionsTable",
    "KaevoInstallationsTable",
)


def ref(name: str) -> dict:
    return {"Ref": name}


def get_att(name: str) -> dict:
    return {"Fn::GetAtt": [name, "Arn"]}


def s3_code(uri: str) -> dict:
    parsed = urlparse(uri)
    if parsed.scheme != "s3" or not parsed.netloc or not parsed.path.strip("/"):
        raise ValueError("identity code URI must be a complete s3://bucket/key URI")
    return {"S3Bucket": parsed.netloc, "S3Key": parsed.path.lstrip("/")}


def deletion_statement() -> dict:
    table_resources = []
    for name in DELETION_TABLES:
        table_resources.extend((
            get_att(name),
            {"Fn::Sub": f"${{{name}.Arn}}/index/*"},
        ))
    return {
        "Sid": DELETION_SID,
        "Effect": "Allow",
        "Action": [
            "dynamodb:GetItem",
            "dynamodb:Query",
            "dynamodb:UpdateItem",
            "dynamodb:DeleteItem",
        ],
        "Resource": table_resources,
    }


def avatar_statement() -> dict:
    return {
        "Sid": "DeleteExactProfileAvatar",
        "Effect": "Allow",
        "Action": ["s3:DeleteObject"],
        # Profile avatars are stored beneath this exact prefix.  Keep the
        # deletion grant prefix-bound: the function must never gain access to
        # unrelated objects in the private bucket.
        "Resource": {"Fn::Sub": "${KaevoProfileAvatarsBucket.Arn}/profile-avatars/*"},
    }


def _statement_with_sid(statements: list[object], sid: str) -> tuple[int, dict] | None:
    matches = [
        (index, statement)
        for index, statement in enumerate(statements)
        if isinstance(statement, dict) and statement.get("Sid") == sid
    ]
    if len(matches) > 1:
        raise ValueError(f"duplicate identity policy statement: {sid}")
    return matches[0] if matches else None


def prepare(baseline: dict, identity_code_uri: str | None = None) -> dict:
    candidate = copy.deepcopy(baseline)
    resources = candidate.get("Resources") or {}
    required = {FUNCTION, POLICY, *ENVIRONMENT_BINDINGS.values(), *DELETION_TABLES}
    missing = sorted(required - set(resources))
    if missing:
        raise ValueError(f"missing expected deployed resources: {missing}")

    function = resources[FUNCTION].get("Properties") or {}
    if identity_code_uri is not None:
        function["Code"] = s3_code(identity_code_uri)
    variables = (
        function.setdefault("Environment", {})
        .setdefault("Variables", {})
    )
    for variable, logical_id in ENVIRONMENT_BINDINGS.items():
        current = variables.get(variable)
        expected = ref(logical_id)
        if current not in (None, expected):
            raise ValueError(f"environment binding conflicts with live state: {variable}")
        variables[variable] = expected

    statements = (
        resources[POLICY]
        .get("Properties", {})
        .get("PolicyDocument", {})
        .get("Statement")
    )
    if not isinstance(statements, list):
        raise ValueError("Identity V3 data policy has no statement list")
    deletion = _statement_with_sid(statements, DELETION_SID)
    if deletion is None:
        statements.append(deletion_statement())
    elif deletion[1] != deletion_statement():
        raise ValueError("exact profile-deletion graph policy conflicts with the reviewed scope")

    avatar = _statement_with_sid(statements, "DeleteExactProfileAvatar")
    expected_avatar = avatar_statement()
    if avatar is None:
        statements.append(expected_avatar)
    elif avatar[1] != expected_avatar:
        legacy_avatar = {
            **expected_avatar,
            "Action": ["s3:GetObject", "s3:DeleteObject"],
        }
        legacy_avatar_wrong_prefix = {
            **legacy_avatar,
            "Resource": {"Fn::Sub": "${KaevoProfileAvatarsBucket.Arn}/profiles/*"},
        }
        if avatar[1] not in (legacy_avatar, legacy_avatar_wrong_prefix):
            raise ValueError("exact profile-avatar deletion policy conflicts with the reviewed scope")
        statements[avatar[0]] = expected_avatar

    baseline_resources = baseline["Resources"]
    modified = [
        name for name in baseline_resources
        if resources[name] != baseline_resources[name]
    ]
    if set(modified) not in ({POLICY}, {FUNCTION, POLICY}):
        raise ValueError(f"unexpected baseline resource modifications: {modified}")
    if set(resources) != set(baseline_resources):
        raise ValueError("profile-deletion candidate must not add or remove resources")
    return candidate


def main() -> None:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--deployed-processed-template", type=Path)
    source.add_argument("--deployed-stack-name")
    parser.add_argument("--identity-code-s3-uri")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.deployed_processed_template is not None:
        baseline = json.loads(args.deployed_processed_template.read_text(encoding="utf-8"))
    else:
        import boto3

        template = boto3.client("cloudformation").get_template(
            StackName=args.deployed_stack_name,
            TemplateStage="Processed",
        )["TemplateBody"]
        baseline = json.loads(template if isinstance(template, str) else json.dumps(template))
    candidate = prepare(baseline, args.identity_code_s3_uri)
    if args.deployed_processed_template is not None and args.output.resolve() == args.deployed_processed_template.resolve():
        raise ValueError("output must differ from deployed processed template")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
    print("IDENTITY_V3_PROFILE_DELETION_TEMPLATE=APPROVED")
    print("MODIFIED_RESOURCES=KaevoIdentityV3ApiDataPolicy_OR_IDENTITY_CODE_AND_POLICY")


if __name__ == "__main__":
    main()

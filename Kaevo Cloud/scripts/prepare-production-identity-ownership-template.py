#!/usr/bin/env python3
"""Import source-owned Production identity contracts into the deployed template.

This preparer is deliberately narrow. It starts from the processed Production
template and changes only the native OIDC expectations on the isolated claim
issuer and the owner-enrollment IAM contract already declared in
``infra/template.yaml``. This brings formerly out-of-band live configuration
under CloudFormation ownership without packaging unrelated dirty-tree work.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import subprocess


CLAIM_FUNCTION = "KaevoIdentityClaimIssuerFunction"
OWNER_ROLE = "KaevoOwnerEnrollmentFunctionRole"


class ScopeError(RuntimeError):
    pass


def _production_value(security: str, production: str, development: str) -> dict:
    return {
        "Fn::If": [
            "IsSecurityStage",
            security,
            {
                "Fn::If": [
                    "IsProduction",
                    production,
                    {"Fn::If": ["IsDevelopment", development, ""]},
                ]
            },
        ]
    }


def prepare_template(deployed: dict) -> dict:
    prepared = copy.deepcopy(deployed)
    resources = prepared.get("Resources") or {}
    try:
        variables = resources[CLAIM_FUNCTION]["Properties"]["Environment"]["Variables"]
        policies = resources[OWNER_ROLE]["Properties"]["Policies"]
    except (KeyError, TypeError) as exc:
        raise ScopeError("deployed identity ownership boundary is incomplete") from exc

    required_variables = {
        "EXPECTED_NATIVE_CLIENT_NAME",
        "EXPECTED_NATIVE_CALLBACK_URI",
        "EXPECTED_NATIVE_LOGOUT_URI",
    }
    if not required_variables.issubset(variables):
        raise ScopeError("claim issuer native expectation boundary is incomplete")

    variables["EXPECTED_NATIVE_CLIENT_NAME"] = _production_value(
        "kaevo-security-stage-native-oidc",
        "kaevo-cloud-production-native-oidc",
        "kaevo-cloud-dev-native-oidc",
    )
    variables["EXPECTED_NATIVE_CALLBACK_URI"] = _production_value(
        "kaevo-security-stage://oauth/callback",
        "kaevo://oauth/callback",
        "kaevo://oauth/callback",
    )
    variables["EXPECTED_NATIVE_LOGOUT_URI"] = _production_value(
        "kaevo-security-stage://oauth/logout",
        "kaevo://oauth/logout",
        "kaevo://oauth/logout",
    )

    statements = [
        statement
        for policy in policies
        for statement in (policy.get("PolicyDocument") or {}).get("Statement", [])
    ]
    bootstrap = next(
        (s for s in statements if s.get("Sid") == "BootstrapAuthoritativeIdentityGraph"),
        None,
    )
    if bootstrap is None:
        raise ScopeError("owner bootstrap policy is missing")

    actions = bootstrap.get("Action")
    targets = bootstrap.get("Resource")
    if not isinstance(actions, list) or not isinstance(targets, list):
        raise ScopeError("owner bootstrap policy has an unexpected shape")
    if "dynamodb:UpdateItem" not in actions:
        insert_at = actions.index("dynamodb:TransactWriteItems")
        actions.insert(insert_at, "dynamodb:UpdateItem")
    membership_target = {"Fn::GetAtt": ["KaevoHouseholdMembershipsTable", "Arn"]}
    if membership_target not in targets:
        targets.append(membership_target)

    if not any(s.get("Sid") == "ReadExactEnrollingCognitoUser" for s in statements):
        owner_policy = next(
            policy
            for policy in policies
            if bootstrap in (policy.get("PolicyDocument") or {}).get("Statement", [])
        )
        owner_policy["PolicyDocument"]["Statement"].append(
            {
                "Sid": "ReadExactEnrollingCognitoUser",
                "Effect": "Allow",
                "Action": ["cognito-idp:AdminGetUser"],
                "Resource": {
                    "Fn::Sub": (
                        "arn:${AWS::Partition}:cognito-idp:${AWS::Region}:"
                        "${AWS::AccountId}:userpool/${KaevoUserPool}"
                    )
                },
            }
        )

    changed = sorted(
        name
        for name, resource in resources.items()
        if resource != (deployed.get("Resources") or {}).get(name)
    )
    expected = sorted([CLAIM_FUNCTION, OWNER_ROLE])
    if changed != expected:
        raise ScopeError(f"identity ownership candidate changed unexpected resources: {changed}")
    return prepared


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    result = subprocess.run(
        [
            "aws",
            "cloudformation",
            "get-template",
            "--stack-name",
            args.stack_name,
            "--template-stage",
            "Processed",
            "--region",
            args.region,
            "--output",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    body = json.loads(result.stdout)["TemplateBody"]
    deployed = json.loads(body) if isinstance(body, str) else body
    prepared = prepare_template(deployed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(prepared, indent=2) + "\n")
    print(
        "PRODUCTION_IDENTITY_OWNERSHIP_TEMPLATE_APPROVED "
        f"resources={CLAIM_FUNCTION},{OWNER_ROLE}"
    )


if __name__ == "__main__":
    main()

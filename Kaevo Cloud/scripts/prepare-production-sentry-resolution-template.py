#!/usr/bin/env python3
"""Prepare a production change set scoped to Kaevo's Sentry resolver."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import subprocess
from typing import Any


API_FUNCTION = "KaevoCloudApiFunction"
API_ROLE = "KaevoCloudApiFunctionRole"
ACCESS_POLICY = "KaevoSentryIssueResolverAccessPolicy"
EXPECTED_HANDLER = "handler.lambda_handler"
EXPECTED_RUNTIME = "python3.12"


class ScopeError(RuntimeError):
    pass


def prepare_template(
    deployed: dict[str, Any], *, code_bucket: str, code_key: str, secret_arn: str,
) -> dict[str, Any]:
    if not code_bucket or not code_key or not secret_arn.startswith("arn:aws:secretsmanager:"):
        raise ScopeError("exact code location and Secrets Manager ARN are required")
    resources = deployed.get("Resources")
    if not isinstance(resources, dict):
        raise ScopeError("deployed template is missing Resources")
    if ACCESS_POLICY in resources:
        raise ScopeError("Sentry resolver access policy already exists")
    function = resources.get(API_FUNCTION)
    role = resources.get(API_ROLE)
    if not isinstance(function, dict) or function.get("Type") != "AWS::Lambda::Function":
        raise ScopeError("deployed Production API function is missing")
    if not isinstance(role, dict) or role.get("Type") != "AWS::IAM::Role":
        raise ScopeError("deployed Production API role is missing")
    properties = function.get("Properties")
    if not isinstance(properties, dict):
        raise ScopeError("deployed Production API properties are missing")
    if properties.get("Handler") != EXPECTED_HANDLER or properties.get("Runtime") != EXPECTED_RUNTIME:
        raise ScopeError("deployed Production API runtime ownership changed")
    environment = properties.get("Environment", {}).get("Variables")
    if not isinstance(environment, dict):
        raise ScopeError("deployed Production API environment is missing")
    if environment.get("SENTRY_ISSUE_RESOLVER_SECRET_ARN") not in {None, ""}:
        raise ScopeError("Sentry resolver environment is already configured")

    prepared = copy.deepcopy(deployed)
    prepared_function = prepared["Resources"][API_FUNCTION]["Properties"]
    prepared_function["Code"] = {"S3Bucket": code_bucket, "S3Key": code_key}
    prepared_function["Environment"]["Variables"]["SENTRY_ISSUE_RESOLVER_SECRET_ARN"] = secret_arn
    prepared["Resources"][ACCESS_POLICY] = {
        "Type": "AWS::IAM::Policy",
        "Properties": {
            "PolicyName": "kaevo-cloud-production-sentry-issue-resolver",
            "Roles": [{"Ref": API_ROLE}],
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "ReadExactSentryIssueResolverCredential",
                    "Effect": "Allow",
                    "Action": ["secretsmanager:GetSecretValue"],
                    "Resource": secret_arn,
                }],
            },
        },
    }

    changed = sorted(
        logical_id
        for logical_id, resource in prepared["Resources"].items()
        if resource != resources.get(logical_id)
    )
    if changed != sorted([ACCESS_POLICY, API_FUNCTION]):
        raise ScopeError(f"candidate changed unexpected resources: {changed}")
    if set(prepared["Resources"]) - set(resources) != {ACCESS_POLICY}:
        raise ScopeError("candidate changed the resource set unexpectedly")
    return prepared


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--code-bucket", required=True)
    parser.add_argument("--code-key", required=True)
    parser.add_argument("--secret-arn", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ScopeError("output already exists; refusing to overwrite")
    result = subprocess.run(
        [
            "aws", "cloudformation", "get-template",
            "--stack-name", args.stack_name,
            "--template-stage", "Processed",
            "--region", args.region,
            "--output", "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    body = json.loads(result.stdout)["TemplateBody"]
    deployed = json.loads(body) if isinstance(body, str) else body
    prepared = prepare_template(
        deployed,
        code_bucket=args.code_bucket,
        code_key=args.code_key,
        secret_arn=args.secret_arn,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(prepared, indent=2, sort_keys=True) + "\n")
    print(
        "PRODUCTION_SENTRY_RESOLUTION_TEMPLATE_APPROVED "
        f"resources={API_FUNCTION},{ACCESS_POLICY}"
    )


if __name__ == "__main__":
    main()

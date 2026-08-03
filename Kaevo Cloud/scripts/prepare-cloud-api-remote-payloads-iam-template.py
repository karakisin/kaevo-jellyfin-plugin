#!/usr/bin/env python3
"""Prepare an IAM-only CloudFormation reconciliation candidate from live state."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import subprocess


FUNCTION = "KaevoCloudApiFunction"
FUNCTION_ROLE = "KaevoCloudApiFunctionRole"
BUCKET = "KaevoRemotePayloadsBucket"
GSI_TABLE = "KaevoHouseholdJoinTransactionsTable"


def live_template(*, stack_name: str, region: str, profile: str) -> dict:
    result = subprocess.run(
        ["aws", "cloudformation", "get-template", "--stack-name", stack_name,
         "--template-stage", "Original", "--region", region, "--profile", profile,
         "--output", "json"],
        check=True, capture_output=True, text=True,
    )
    body = json.loads(result.stdout)["TemplateBody"]
    return json.loads(body) if isinstance(body, str) else body


def remote_payloads_policy(*, policy_name: str) -> dict:
    return {
        "PolicyName": policy_name,
        "PolicyDocument": {"Statement": [{
            "Sid": "ReadAndStoreBoundedRemoteResponses",
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": {"Fn::Sub": f"${{{BUCKET}.Arn}}/remote-responses/*"},
        }]},
    }


def is_remote_payloads_policy(policy: object) -> bool:
    if not isinstance(policy, dict):
        return False
    return BUCKET in json.dumps(policy.get("PolicyDocument") or {}, sort_keys=True)


def prepare(baseline: dict) -> dict:
    candidate = copy.deepcopy(baseline)
    resources = candidate.get("Resources") or {}
    function = resources.get(FUNCTION)
    role = resources.get(FUNCTION_ROLE)
    if not isinstance(function, dict) or not isinstance(role, dict) or not isinstance(resources.get(BUCKET), dict):
        raise ValueError("live_template_missing_api_role_or_remote_payloads_bucket")
    properties = role.get("Properties")
    if not isinstance(properties, dict) or not isinstance(properties.get("Policies"), list):
        raise ValueError("live_template_missing_api_role_policy_list")
    matches = [index for index, entry in enumerate(properties["Policies"]) if is_remote_payloads_policy(entry)]
    if len(matches) != 1:
        raise ValueError("live_template_remote_payloads_policy_not_unique")
    index = matches[0]
    previous = properties["Policies"][index]
    if not isinstance(previous, dict) or not isinstance(previous.get("PolicyName"), str):
        raise ValueError("live_template_remote_payloads_policy_name_missing")
    policy = remote_payloads_policy(policy_name=previous["PolicyName"])
    if previous == policy:
        raise ValueError("remote_payloads_policy_already_least_privilege")
    if not isinstance(resources.get(GSI_TABLE), dict):
        raise ValueError("live_template_missing_join_transactions_table")
    properties["Policies"][index] = policy
    return candidate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    baseline = live_template(stack_name=args.stack_name, region=args.region, profile=args.profile)
    candidate = prepare(baseline)
    before, after = baseline["Resources"], candidate["Resources"]
    changed = {name for name in before if before[name] != after[name]}
    if changed != {FUNCTION_ROLE} or set(before) != set(after):
        raise ValueError("iam_candidate_scope_unexpected")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(candidate, sort_keys=True, indent=2) + "\n")
    print("IAM_RECONCILIATION_TEMPLATE_SCOPE=APPROVED")
    print("MODIFIED_RESOURCE_COUNT=1")
    print("GSI_PRESENT=false")


if __name__ == "__main__":
    main()

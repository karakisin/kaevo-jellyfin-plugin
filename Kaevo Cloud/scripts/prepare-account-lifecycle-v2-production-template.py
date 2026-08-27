#!/usr/bin/env python3
"""Prepare a fail-closed Account Lifecycle V2 production change template.

The working SAM template intentionally contains other in-progress Kaevo work.
This tool starts from the currently deployed, processed CloudFormation template
and copies only the reviewed V2 resources, V4 routes, and Household Join
membership-registry integration from a non-executed candidate change set.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any


V2_RESOURCE_PREFIX = "KaevoAccountLifecycleV2"
V4_PATH_PREFIX = "/v4/account-lifecycle/"
V4_ROUTE_MARKER = "/v4/account-lifecycle/"
HOUSEHOLD_JOIN_FUNCTION = "KaevoHouseholdJoinFunction"
HOUSEHOLD_JOIN_ROLE = "KaevoHouseholdJoinFunctionRole"
HTTP_API = "KaevoCloudHttpApi"
HTTP_API_STAGE = "KaevoCloudHttpApiStage"


class ScopeError(RuntimeError):
    """Raised when the candidate cannot be narrowed without guessing."""


def _resources(template: dict[str, Any]) -> dict[str, Any]:
    resources = template.get("Resources")
    if not isinstance(resources, dict):
        raise ScopeError("template is missing Resources")
    return resources


def _policy_statements(role: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    policies = role.get("Properties", {}).get("Policies", [])
    for policy in policies:
        for statement in policy.get("PolicyDocument", {}).get("Statement", []):
            sid = str(statement.get("Sid") or "")
            if not sid or sid in result:
                raise ScopeError("Household Join role has missing or duplicate statement Sid")
            result[sid] = statement
    return result


def _merge_household_join_role(
    deployed_role: dict[str, Any], candidate_role: dict[str, Any]
) -> None:
    deployed = _policy_statements(deployed_role)
    candidate = _policy_statements(candidate_role)
    expected_updates = {
        "ReadInvitationAndOnboardingAuthority",
        "AtomicallyAdvanceHouseholdJoinOnboarding",
        "PutProfileSetupRecordsTransactionally",
    }
    for sid in expected_updates:
        if sid not in deployed or sid not in candidate:
            raise ScopeError(f"missing reviewed Household Join policy statement: {sid}")
        deployed[sid].clear()
        deployed[sid].update(copy.deepcopy(candidate[sid]))

    new_sid = "UpdateLifecycleV2OwnershipGuardTransactionally"
    if new_sid in deployed or new_sid not in candidate:
        raise ScopeError("unexpected Household Join lifecycle guard policy state")
    policies = deployed_role["Properties"]["Policies"]
    if len(policies) != 1:
        raise ScopeError("Household Join role policy layout changed")
    policies[0]["PolicyDocument"]["Statement"].append(copy.deepcopy(candidate[new_sid]))


def prepare_template(
    deployed_template: dict[str, Any], candidate_template: dict[str, Any]
) -> dict[str, Any]:
    prepared = copy.deepcopy(deployed_template)
    deployed_resources = _resources(deployed_template)
    candidate_resources = _resources(candidate_template)
    prepared_resources = _resources(prepared)

    v2_ids = sorted(
        logical_id
        for logical_id in candidate_resources
        if logical_id.startswith(V2_RESOURCE_PREFIX)
    )
    if not v2_ids:
        raise ScopeError("candidate contains no Account Lifecycle V2 resources")
    conflicts = sorted(set(v2_ids) & set(deployed_resources))
    if conflicts:
        raise ScopeError(f"Account Lifecycle V2 resources already exist: {conflicts}")
    for logical_id in v2_ids:
        prepared_resources[logical_id] = copy.deepcopy(candidate_resources[logical_id])

    deployed_paths = prepared_resources[HTTP_API]["Properties"]["Body"]["paths"]
    candidate_paths = candidate_resources[HTTP_API]["Properties"]["Body"]["paths"]
    v4_paths = sorted(path for path in candidate_paths if path.startswith(V4_PATH_PREFIX))
    if len(v4_paths) != 4 or any(path in deployed_paths for path in v4_paths):
        raise ScopeError("candidate V4 route set is incomplete or already deployed")
    for path in v4_paths:
        deployed_paths[path] = copy.deepcopy(candidate_paths[path])

    deployed_route_settings = prepared_resources[HTTP_API_STAGE]["Properties"].setdefault(
        "RouteSettings", {}
    )
    candidate_route_settings = candidate_resources[HTTP_API_STAGE]["Properties"].get(
        "RouteSettings", {}
    )
    v4_route_settings = {
        route: settings
        for route, settings in candidate_route_settings.items()
        if V4_ROUTE_MARKER in route
    }
    if set(v4_route_settings) != {"POST /v4/account-lifecycle/enroll-owner"}:
        raise ScopeError("candidate V4 throttling contract changed")
    for route, settings in v4_route_settings.items():
        if route in deployed_route_settings:
            raise ScopeError("V4 route throttling is already deployed")
        deployed_route_settings[route] = copy.deepcopy(settings)

    deployed_join = prepared_resources[HOUSEHOLD_JOIN_FUNCTION]
    candidate_join = candidate_resources[HOUSEHOLD_JOIN_FUNCTION]
    deployed_join["Properties"]["Code"] = copy.deepcopy(candidate_join["Properties"]["Code"])
    candidate_lifecycle_table = candidate_join["Properties"]["Environment"]["Variables"].get(
        "ACCOUNT_LIFECYCLE_V2_TABLE"
    )
    if candidate_lifecycle_table != {"Ref": "KaevoAccountLifecycleV2Table"}:
        raise ScopeError("Household Join lifecycle table binding changed")
    deployed_join["Properties"]["Environment"]["Variables"][
        "ACCOUNT_LIFECYCLE_V2_TABLE"
    ] = copy.deepcopy(candidate_lifecycle_table)

    _merge_household_join_role(
        prepared_resources[HOUSEHOLD_JOIN_ROLE],
        candidate_resources[HOUSEHOLD_JOIN_ROLE],
    )

    allowed_existing = {
        HTTP_API,
        HTTP_API_STAGE,
        HOUSEHOLD_JOIN_FUNCTION,
        HOUSEHOLD_JOIN_ROLE,
    }
    changed_existing = {
        logical_id
        for logical_id in deployed_resources
        if prepared_resources[logical_id] != deployed_resources[logical_id]
    }
    if changed_existing != allowed_existing:
        raise ScopeError(
            f"prepared template changed unexpected deployed resources: {sorted(changed_existing)}"
        )
    if set(prepared_resources) != set(deployed_resources) | set(v2_ids):
        raise ScopeError("prepared resource set escaped the V2 boundary")
    return prepared


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--candidate-change-set", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ScopeError("output already exists; refusing to overwrite")

    import boto3

    cloudformation = boto3.client("cloudformation", region_name=args.region)
    deployed = cloudformation.get_template(
        StackName=args.stack_name, TemplateStage="Processed"
    )["TemplateBody"]
    candidate = cloudformation.get_template(
        ChangeSetName=args.candidate_change_set, TemplateStage="Processed"
    )["TemplateBody"]
    prepared = prepare_template(deployed, candidate)
    args.output.write_text(json.dumps(prepared, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()

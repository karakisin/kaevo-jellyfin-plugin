#!/usr/bin/env python3
"""Prepare a production change set containing only App Store subscriptions.

The working SAM template intentionally contains other in-progress resources and
resources owned by separate stacks. Start from the processed live Production
template and copy only the reviewed subscription table, explicit routes,
permissions, and standalone least-privilege table policy. This phase is
strictly additive: it cannot modify the Lambda, its generated role, the inline
API body, or the stage. Runtime code and route throttles are separate gates.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

import boto3


TRANSACTIONS_TABLE = "KaevoAppStoreTransactionsTable"
ACCESS_POLICY = "KaevoAppStoreTransactionsAccessPolicy"
PERMISSIONS = {
    "KaevoAppStoreSyncInvokePermission",
    "KaevoAppStoreNotificationsInvokePermission",
}
ROUTES = {
    "KaevoAppStoreSyncRoute": "POST /v1/subscriptions/app-store/sync",
    "KaevoAppStoreNotificationsProductionRoute": (
        "POST /v1/app-store-server-notifications/production"
    ),
    "KaevoAppStoreNotificationsSandboxRoute": (
        "POST /v1/app-store-server-notifications/sandbox"
    ),
}
INTEGRATION = "KaevoAppStoreApiIntegration"


class ScopeError(RuntimeError):
    """Raised when the candidate cannot be narrowed without guessing."""


def _resources(template: dict[str, Any]) -> dict[str, Any]:
    resources = template.get("Resources")
    if not isinstance(resources, dict):
        raise ScopeError("template is missing Resources")
    return resources


def prepare_template(
    deployed_template: dict[str, Any], candidate_template: dict[str, Any]
) -> dict[str, Any]:
    deployed = _resources(deployed_template)
    candidate = _resources(candidate_template)
    prepared_template = copy.deepcopy(deployed_template)
    prepared = _resources(prepared_template)

    subscription_resources = {
        TRANSACTIONS_TABLE,
        ACCESS_POLICY,
        INTEGRATION,
        *PERMISSIONS,
        *ROUTES,
    }
    if not subscription_resources <= candidate.keys():
        raise ScopeError("candidate subscription resource set is incomplete")
    for logical_id in subscription_resources & deployed.keys():
        if deployed[logical_id] != candidate[logical_id]:
            raise ScopeError(f"deployed subscription resource changed: {logical_id}")
    additions = subscription_resources - deployed.keys()
    for logical_id in additions:
        prepared[logical_id] = copy.deepcopy(candidate[logical_id])

    for logical_id, route_key in ROUTES.items():
        route = prepared[logical_id]
        if route.get("Type") != "AWS::ApiGatewayV2::Route":
            raise ScopeError(f"candidate route type changed: {logical_id}")
        if route.get("Properties", {}).get("RouteKey") != route_key:
            raise ScopeError(f"candidate route key changed: {logical_id}")
        target = route.get("Properties", {}).get("Target", {})
        if {"Ref": INTEGRATION} not in target.get("Fn::Join", [None, []])[1]:
            raise ScopeError(f"candidate route integration changed: {logical_id}")

    changed_existing = {
        logical_id
        for logical_id in deployed
        if prepared[logical_id] != deployed[logical_id]
    }
    if changed_existing:
        raise ScopeError(
            f"prepared template changed unexpected resources: {sorted(changed_existing)}"
        )
    if set(prepared) != set(deployed) | additions:
        raise ScopeError("prepared resource set escaped the subscription boundary")
    return prepared_template


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--candidate-change-set", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ScopeError("output already exists; refusing to overwrite")

    cloudformation = boto3.client("cloudformation", region_name=args.region)
    deployed = cloudformation.get_template(
        StackName=args.stack_name, TemplateStage="Processed"
    )["TemplateBody"]
    candidate = cloudformation.get_template(
        StackName=args.stack_name,
        ChangeSetName=args.candidate_change_set,
        TemplateStage="Processed",
    )["TemplateBody"]
    prepared = prepare_template(deployed, candidate)
    args.output.write_text(json.dumps(prepared, indent=2, sort_keys=True) + "\n")
    print(
        "APP_STORE_SUBSCRIPTION_PRODUCTION_TEMPLATE_APPROVED "
        f"existing_changes=0 additions={len(set(prepared['Resources']) - set(deployed))} "
        "api_body_changes=0 stage_changes=0 lambda_changes=0 role_changes=0"
    )


if __name__ == "__main__":
    main()

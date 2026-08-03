#!/usr/bin/env python3
"""Fail-closed, aggregate-only rollback gate for pending-profile Household Join.

This is not a snapshot-consistent transaction.  An operator must first quiesce
all Household Join writes; the guard then validates its AWS target, makes two
fully paginated passes separated by a documented interval, and accepts only
matching zero-count results.  It never writes data or prints record contents.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import re
import sys
import time
from typing import Any, Mapping

import boto3


EXPECTED_ACCOUNT = "295055514343"
EXPECTED_REGION = "us-west-2"
EXPECTED_STACK = "kaevo-cloud-dev"
HEALTHY_STACK_STATUSES = frozenset({
    "CREATE_COMPLETE", "UPDATE_COMPLETE", "IMPORT_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
})
EXPECTED_TABLES = {
    # Table selection always starts from these CloudFormation logical IDs. The
    # physical names below are assertions about the resolved stack resource,
    # never operator-selectable scan targets.
    "accounts": {
        "logical_id": "KaevoAccountsTable",
        "expected_name": "kaevo-cloud-dev-accounts",
    },
    "auth_identities": {
        "logical_id": "KaevoAuthIdentitiesTable",
        "expected_name": "kaevo-cloud-dev-auth-identities",
    },
    "identity_memberships": {
        "logical_id": "KaevoIdentityMembershipsTable",
        "expected_name": "kaevo-cloud-dev-identity-memberships",
        "key_schema": (("principal_id", "HASH"),),
        "state_key": "state",
        "allowed_states": frozenset({"active", "pending_profile"}),
        "pending_state": "pending_profile",
    },
    "household_memberships": {
        "logical_id": "KaevoHouseholdMembershipsTable",
        "expected_name": "kaevo-cloud-dev-household-memberships",
        "key_schema": (("household_id", "HASH"), ("membership_id", "RANGE")),
        "state_key": "status",
        "allowed_states": frozenset({"active", "pending_profile"}),
        "pending_state": "pending_profile",
    },
    "join_transactions": {
        "logical_id": "KaevoHouseholdJoinTransactionsTable",
        "expected_name": "kaevo-cloud-dev-household-join-transactions",
        "key_schema": (("join_resume_hash", "HASH"),),
        "ttl": ("ENABLED", "cleanup_at"),
    },
    "profiles": {
        "logical_id": "KaevoProfilesTable",
        "expected_name": "kaevo-cloud-dev-profiles",
    },
    "profile_bindings": {
        "logical_id": "KaevoProfileBindingsTable",
        "expected_name": "kaevo-cloud-dev-profile-bindings",
    },
    "profile_mappings": {
        "logical_id": "KaevoProfileMappingsTable",
        "expected_name": "kaevo-cloud-dev-profile-mappings",
    },
    "entitlements": {
        "logical_id": "KaevoEntitlementsTable",
        "expected_name": "kaevo-cloud-dev-entitlements",
    },
    "household_invitations": {
        "logical_id": "KaevoHouseholdInvitationsTable",
        "expected_name": "kaevo-cloud-dev-household-invitations",
    },
    "principals": {
        "logical_id": "KaevoPrincipalsTable",
        "expected_name": "kaevo-cloud-dev-principals",
    },
    "identity_profiles": {
        "logical_id": "KaevoIdentityProfilesTable",
        "expected_name": "kaevo-cloud-dev-identity-profiles",
    },
}


class UnsafeRollback(RuntimeError):
    """Any target, read, or consistency concern blocks rollback."""


@dataclass(frozen=True)
class Counts:
    pending_identity_memberships: int
    pending_normalized_memberships: int
    profile_setup_transactions: int


def fail(reason: str) -> None:
    raise UnsafeRollback(reason)


def exact_schema(value: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list):
        fail("malformed_key_schema")
    result = tuple((str(entry.get("AttributeName") or ""), str(entry.get("KeyType") or "")) for entry in value if isinstance(entry, Mapping))
    if len(result) != len(value):
        fail("malformed_key_schema")
    return result


def expected_arn(table_name: str) -> str:
    return f"arn:aws:dynamodb:{EXPECTED_REGION}:{EXPECTED_ACCOUNT}:table/{table_name}"


def validate_stack(cloudformation: Any) -> dict[str, str]:
    response = cloudformation.describe_stacks(StackName=EXPECTED_STACK)
    stacks = response.get("Stacks") if isinstance(response, Mapping) else None
    if not isinstance(stacks, list) or len(stacks) != 1:
        fail("stack_not_found_or_malformed")
    if str(stacks[0].get("StackStatus") or "") not in HEALTHY_STACK_STATUSES:
        fail("stack_not_healthy")
    resources: dict[str, str] = {}
    expected_by_logical = {str(spec["logical_id"]): spec for spec in EXPECTED_TABLES.values()}
    token: str | None = None
    seen_tokens: set[str] = set()
    while True:
        kwargs = {"StackName": EXPECTED_STACK}
        if token:
            kwargs["NextToken"] = token
        page = cloudformation.list_stack_resources(**kwargs)
        summaries = page.get("StackResourceSummaries") if isinstance(page, Mapping) else None
        if not isinstance(summaries, list):
            fail("malformed_stack_resources")
        for resource in summaries:
            if not isinstance(resource, Mapping):
                fail("malformed_stack_resources")
            logical_id = str(resource.get("LogicalResourceId") or "")
            if logical_id in expected_by_logical:
                physical = str(resource.get("PhysicalResourceId") or "")
                if (not physical
                    or str(resource.get("ResourceType") or "") != "AWS::DynamoDB::Table"
                    or str(resource.get("ResourceStatus") or "") not in HEALTHY_STACK_STATUSES):
                    fail("missing_expected_resource")
                resources[logical_id] = physical
        token_value = page.get("NextToken") if isinstance(page, Mapping) else None
        if token_value is None:
            break
        if not isinstance(token_value, str) or not token_value:
            fail("malformed_stack_pagination")
        if token_value in seen_tokens:
            fail("stack_pagination_cycle_detected")
        seen_tokens.add(token_value)
        token = token_value
    for spec in EXPECTED_TABLES.values():
        if resources.get(spec["logical_id"]) != spec["expected_name"]:
            fail("stack_table_name_mismatch")
    return resources


def validate_table(dynamodb_client: Any, spec: Mapping[str, Any], table_name: str) -> None:
    try:
        response = dynamodb_client.describe_table(TableName=table_name)
    except Exception:
        fail("describe_table_failed")
    table = response.get("Table") if isinstance(response, Mapping) else None
    if not isinstance(table, Mapping):
        fail("malformed_describe_table")
    if str(table.get("TableName") or "") != table_name:
        fail("table_name_mismatch")
    if str(table.get("TableArn") or "") != expected_arn(table_name):
        fail("table_arn_mismatch")
    if str(table.get("TableStatus") or "") != "ACTIVE":
        fail("table_not_active")
    if "key_schema" in spec and exact_schema(table.get("KeySchema")) != tuple(spec["key_schema"]):
        fail("table_key_schema_mismatch")
    if "ttl" in spec:
        try:
            ttl_response = dynamodb_client.describe_time_to_live(TableName=table_name)
        except Exception:
            fail("describe_ttl_failed")
        ttl = ttl_response.get("TimeToLiveDescription") if isinstance(ttl_response, Mapping) else None
        if not isinstance(ttl, Mapping) or (str(ttl.get("TimeToLiveStatus") or ""), str(ttl.get("AttributeName") or "")) != tuple(spec["ttl"]):
            fail("table_ttl_mismatch")


def validate_target(session: Any, *, region: str) -> tuple[Any, Any, dict[str, str]]:
    if region != EXPECTED_REGION:
        fail("unexpected_region")
    sts = session.client("sts")
    try:
        caller = sts.get_caller_identity()
    except Exception:
        fail("sts_failed")
    if not isinstance(caller, Mapping) or str(caller.get("Account") or "") != EXPECTED_ACCOUNT:
        fail("unexpected_account")
    cloudformation = session.client("cloudformation")
    dynamodb_client = session.client("dynamodb")
    try:
        resolved = validate_stack(cloudformation)
    except UnsafeRollback:
        raise
    except Exception:
        fail("stack_validation_failed")
    for spec in EXPECTED_TABLES.values():
        validate_table(dynamodb_client, spec, resolved[str(spec["logical_id"])])
    return caller, session.resource("dynamodb"), resolved


def scan_states(table: Any, *, state_key: str, allowed_states: frozenset[str], pending_state: str) -> int:
    total = 0
    start_key: dict[str, Any] | None = None
    seen_keys: set[str] = set()
    while True:
        kwargs: dict[str, Any] = {
            "ProjectionExpression": "#state",
            "ExpressionAttributeNames": {"#state": state_key},
        }
        if start_key is not None:
            kwargs["ExclusiveStartKey"] = start_key
        response = table.scan(**kwargs)
        items = response.get("Items") if isinstance(response, Mapping) else None
        if not isinstance(items, list):
            fail("malformed_scan_response")
        for item in items:
            if not isinstance(item, Mapping):
                fail("malformed_scan_item")
            state = str(item.get(state_key) or "")
            if state not in allowed_states:
                fail("unknown_membership_state")
            if state == pending_state:
                total += 1
        key = response.get("LastEvaluatedKey") if isinstance(response, Mapping) else None
        if key is None:
            return total
        if not isinstance(key, Mapping) or not key:
            fail("malformed_pagination_key")
        fingerprint = repr(sorted(key.items()))
        if fingerprint in seen_keys:
            fail("pagination_cycle_detected")
        seen_keys.add(fingerprint)
        start_key = dict(key)


def scan_join_transactions(table: Any) -> int:
    pending = 0
    start_key: dict[str, Any] | None = None
    seen_keys: set[str] = set()
    accepted = frozenset({"initiated", "awaiting_authorization", "membership_accepted", "completed"})
    lookup_states = frozenset({"profile_setup_required", "completed"})
    ignored_entities = frozenset({"HouseholdJoinRateLimit", "HouseholdJoinDpopReplay"})
    while True:
        kwargs: dict[str, Any] = {
            "ProjectionExpression": "#entity, #state",
            "ExpressionAttributeNames": {"#entity": "entity_type", "#state": "state"},
        }
        if start_key is not None:
            kwargs["ExclusiveStartKey"] = start_key
        response = table.scan(**kwargs)
        items = response.get("Items") if isinstance(response, Mapping) else None
        if not isinstance(items, list):
            fail("malformed_scan_response")
        for item in items:
            if not isinstance(item, Mapping):
                fail("malformed_scan_item")
            entity = str(item.get("entity_type") or "")
            state = str(item.get("state") or "")
            if entity == "HouseholdJoinResume":
                if state not in accepted:
                    fail("unknown_transaction_state")
                if state == "membership_accepted":
                    pending += 1
            elif entity == "HouseholdJoinPendingLookup":
                if state not in lookup_states:
                    fail("unknown_transaction_state")
                if state == "profile_setup_required":
                    pending += 1
            elif entity not in ignored_entities:
                fail("unknown_transaction_entity")
        key = response.get("LastEvaluatedKey") if isinstance(response, Mapping) else None
        if key is None:
            return pending
        if not isinstance(key, Mapping) or not key:
            fail("malformed_pagination_key")
        fingerprint = repr(sorted(key.items()))
        if fingerprint in seen_keys:
            fail("pagination_cycle_detected")
        seen_keys.add(fingerprint)
        start_key = dict(key)


def run_pass(resource: Any, resolved: Mapping[str, str]) -> Counts:
    return Counts(
        pending_identity_memberships=scan_states(resource.Table(resolved[EXPECTED_TABLES["identity_memberships"]["logical_id"]]), state_key="state", allowed_states=EXPECTED_TABLES["identity_memberships"]["allowed_states"], pending_state="pending_profile"),
        pending_normalized_memberships=scan_states(resource.Table(resolved[EXPECTED_TABLES["household_memberships"]["logical_id"]]), state_key="status", allowed_states=EXPECTED_TABLES["household_memberships"]["allowed_states"], pending_state="pending_profile"),
        profile_setup_transactions=scan_join_transactions(resource.Table(resolved[EXPECTED_TABLES["join_transactions"]["logical_id"]])),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fail-closed pending-profile rollback gate")
    parser.add_argument("--profile", required=True, help="AWS profile; STS account identity is validated before reads")
    parser.add_argument("--region", required=True, help="must be us-west-2")
    parser.add_argument("--stack-name", default=EXPECTED_STACK, help="must be kaevo-cloud-dev")
    parser.add_argument("--interval-seconds", type=int, default=30, help="quiesced interval between fully paginated passes (1-60)")
    parser.add_argument("--quiesce-confirmation", required=True, help="must be pending-profile-writes-quiesced")
    return parser.parse_args()


def print_counts(label: str, counts: Counts) -> None:
    print(f"{label}_pending_identity_memberships={counts.pending_identity_memberships}")
    print(f"{label}_pending_normalized_memberships={counts.pending_normalized_memberships}")
    print(f"{label}_profile_setup_transactions={counts.profile_setup_transactions}")


def main() -> int:
    args = parse_args()
    if args.quiesce_confirmation != "pending-profile-writes-quiesced":
        print("result=UNSAFE_FOR_ROLLBACK reason=quiescence_not_confirmed")
        return 2
    if args.stack_name != EXPECTED_STACK:
        print("result=UNSAFE_FOR_ROLLBACK reason=unexpected_stack")
        return 2
    if not 1 <= args.interval_seconds <= 60:
        print("result=UNSAFE_FOR_ROLLBACK reason=invalid_interval")
        return 2
    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        caller, resource, resolved = validate_target(session, region=args.region)
        first = run_pass(resource, resolved)
        time.sleep(args.interval_seconds)
        second = run_pass(resource, resolved)
        if first != second:
            fail("pass_disagreement")
        if any((first.pending_identity_memberships, first.pending_normalized_memberships, first.profile_setup_transactions)):
            fail("pending_onboarding_records")
    except Exception as error:
        reason = error.args[0] if isinstance(error, UnsafeRollback) and error.args else type(error).__name__
        print(f"result=UNSAFE_FOR_ROLLBACK reason={reason}")
        return 3
    print(f"caller_account={caller['Account']}")
    print(f"region={EXPECTED_REGION}")
    print(f"stack={EXPECTED_STACK}")
    for spec in EXPECTED_TABLES.values():
        table_name = resolved[str(spec["logical_id"])]
        print(f"table_name={table_name}")
        print(f"table_arn={expected_arn(table_name)}")
    print("quiescence_acknowledged=true")
    print(f"interval_seconds={args.interval_seconds}")
    print_counts("first_pass", first)
    print_counts("second_pass", second)
    print("result=SAFE_FOR_ROLLBACK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

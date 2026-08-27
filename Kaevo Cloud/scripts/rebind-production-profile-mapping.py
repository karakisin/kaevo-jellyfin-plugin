#!/usr/bin/env python3
"""Rebind one Production installation to one exact local profile source.

This is a one-time repair for records created before the per-installation Cloud
profile guard existed. It is fail-closed, snapshots the strongly read records,
and uses one conditional transaction for the replacement mapping, revocations,
guard, and privacy-safe security audit event.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any

import boto3


SOURCE_ROOT = Path(__file__).parents[1] / "api" / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from profile_mapping import (  # noqa: E402
    build_confirmed_mapping,
    build_mapping_guard,
    mapping_guard_source_id,
)
from security_audit import load_audit_key, prepare_audit_item  # noqa: E402


SAFE_SOURCE = re.compile(r"^lps1_[0-9a-f]{64}$")


class RepairError(RuntimeError):
    """Raised when immutable Production evidence does not match the plan."""


def _assert_source(value: str) -> str:
    if not SAFE_SOURCE.fullmatch(value):
        raise RepairError("invalid local profile source")
    return value


def build_rebind_transaction(
    records: list[dict[str, Any]],
    *,
    profile_mappings_table: str,
    security_audit_table: str,
    installation_id: str,
    account_id: str,
    household_id: str,
    cloud_profile_id: str,
    new_source: str,
    expected_old_sources: set[str],
    audit_item: dict[str, Any],
    now_iso: str,
    now_epoch: int,
) -> list[dict[str, Any]]:
    if not all((profile_mappings_table, security_audit_table, installation_id,
                account_id, household_id, cloud_profile_id)):
        raise RepairError("incomplete immutable repair scope")
    new_source = _assert_source(new_source)
    expected = {_assert_source(value) for value in expected_old_sources}
    if not expected or new_source in expected:
        raise RepairError("invalid replacement source scope")

    by_source = {
        str(record.get("local_profile_source_id") or ""): record
        for record in records
        if isinstance(record, dict)
    }
    if len(by_source) != len(records):
        raise RepairError("duplicate or malformed mapping keys")
    guard_source = mapping_guard_source_id(cloud_profile_id)
    if guard_source in by_source:
        raise RepairError("mapping guard already exists; use the protected API")
    if new_source in by_source:
        raise RepairError("replacement source already exists")

    exact_confirmed_sources = {
        source
        for source, record in by_source.items()
        if record.get("entity_type") == "LocalProfileMapping"
        and record.get("mapping_state") == "confirmed"
        and record.get("account_id") == account_id
        and record.get("household_id") == household_id
        and record.get("cloud_profile_id") == cloud_profile_id
    }
    if exact_confirmed_sources != expected:
        raise RepairError("confirmed source set does not match the frozen plan")

    for source in sorted(expected):
        record = by_source.get(source)
        if not isinstance(record, dict) or not str(record.get("mapping_id") or ""):
            raise RepairError("expected mapping record is incomplete")
        if str(record.get("installation_id") or "") != installation_id:
            raise RepairError("installation mapping mismatch")

    mapping = build_confirmed_mapping(
        installation_id=installation_id,
        local_source_id=new_source,
        account_id=account_id,
        household_id=household_id,
        cloud_profile_id=cloud_profile_id,
        now_iso=now_iso,
        now_epoch=now_epoch,
    )
    guard = build_mapping_guard(
        installation_id=installation_id,
        account_id=account_id,
        household_id=household_id,
        cloud_profile_id=cloud_profile_id,
        local_source_id=new_source,
        now_iso=now_iso,
        now_epoch=now_epoch,
    )
    transaction: list[dict[str, Any]] = [{"Put": {
        "TableName": profile_mappings_table,
        "Item": mapping,
        "ConditionExpression": (
            "attribute_not_exists(installation_id) "
            "AND attribute_not_exists(local_profile_source_id)"
        ),
    }}]
    for source in sorted(expected):
        record = by_source[source]
        transaction.append({"Update": {
            "TableName": profile_mappings_table,
            "Key": {
                "installation_id": installation_id,
                "local_profile_source_id": source,
            },
            "ConditionExpression": (
                "entity_type = :entity AND mapping_id = :mapping_id "
                "AND account_id = :account_id AND household_id = :household_id "
                "AND cloud_profile_id = :cloud_profile_id AND mapping_state = :confirmed"
            ),
            "UpdateExpression": (
                "SET mapping_state = :revoked, updated_at = :updated_at, "
                "updated_at_epoch = :updated_epoch, revoked_at = :updated_at, "
                "revocation_reason = :reason"
            ),
            "ExpressionAttributeValues": {
                ":entity": "LocalProfileMapping",
                ":mapping_id": record["mapping_id"],
                ":account_id": account_id,
                ":household_id": household_id,
                ":cloud_profile_id": cloud_profile_id,
                ":confirmed": "confirmed",
                ":revoked": "revoked",
                ":updated_at": now_iso,
                ":updated_epoch": now_epoch,
                ":reason": "account_lifecycle_v2_duplicate_profile_repair",
            },
        }})
    transaction.extend([
        {"Put": {
            "TableName": profile_mappings_table,
            "Item": guard,
            "ConditionExpression": (
                "attribute_not_exists(installation_id) "
                "AND attribute_not_exists(local_profile_source_id)"
            ),
        }},
        {"Put": {
            "TableName": security_audit_table,
            "Item": audit_item,
            "ConditionExpression": "attribute_not_exists(event_id)",
        }},
    ])
    return transaction


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", required=True)
    parser.add_argument("--api-function", required=True)
    parser.add_argument("--profile-mappings-table", required=True)
    parser.add_argument("--security-audit-table", required=True)
    parser.add_argument("--installation-id", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--household-id", required=True)
    parser.add_argument("--cloud-profile-id", required=True)
    parser.add_argument("--new-local-profile-source-id", required=True)
    parser.add_argument(
        "--expected-old-local-profile-source-id", action="append", required=True,
    )
    parser.add_argument("--actor-subject", required=True)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if args.snapshot.exists():
        raise RepairError("snapshot already exists; refusing to overwrite")

    dynamodb = boto3.resource("dynamodb", region_name=args.region)
    table = dynamodb.Table(args.profile_mappings_table)
    records = table.query(
        KeyConditionExpression=boto3.dynamodb.conditions.Key("installation_id").eq(
            args.installation_id
        ),
        ConsistentRead=True,
    ).get("Items", [])
    args.snapshot.parent.mkdir(parents=True, exist_ok=True)
    args.snapshot.write_text(json.dumps(records, indent=2, sort_keys=True, default=str) + "\n")

    variables = boto3.client("lambda", region_name=args.region).get_function_configuration(
        FunctionName=args.api_function
    ).get("Environment", {}).get("Variables", {})
    for name in ("KAEVO_ENV", "EXPECTED_COGNITO_ISSUER", "AUDIT_REFERENCE_SECRET_ARN"):
        value = str(variables.get(name) or "")
        if not value:
            raise RepairError(f"missing audit environment: {name}")
        os.environ[name] = value
    audit_key = load_audit_key(
        client=boto3.client("secretsmanager", region_name=args.region)
    )
    now_epoch = int(time.time())
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch))
    audit_item = prepare_audit_item(
        scope_id=args.household_id,
        event_type="profile_mapping_admin_rebound",
        actor_subject=args.actor_subject,
        target_id=args.cloud_profile_id,
        target_type="local_profile_mapping",
        result="success",
        reason_code="account_lifecycle_v2_duplicate_profile_repair",
        request_id=f"{args.installation_id}:{args.new_local_profile_source_id}:{now_epoch}",
        now=now_epoch,
        key=audit_key,
    )
    transaction = build_rebind_transaction(
        records,
        profile_mappings_table=args.profile_mappings_table,
        security_audit_table=args.security_audit_table,
        installation_id=args.installation_id,
        account_id=args.account_id,
        household_id=args.household_id,
        cloud_profile_id=args.cloud_profile_id,
        new_source=args.new_local_profile_source_id,
        expected_old_sources=set(args.expected_old_local_profile_source_id),
        audit_item=audit_item,
        now_iso=now_iso,
        now_epoch=now_epoch,
    )
    print(
        "PROFILE_MAPPING_REBIND_PLAN_APPROVED "
        f"installation={args.installation_id} revoked={len(args.expected_old_local_profile_source_id)} "
        f"writes={len(transaction)} apply={str(args.apply).lower()}"
    )
    if args.apply:
        dynamodb.meta.client.transact_write_items(TransactItems=transaction)
        print("PROFILE_MAPPING_REBIND_APPLIED")


if __name__ == "__main__":
    main()

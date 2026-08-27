#!/usr/bin/env python3
"""Retire one fully-consolidated duplicate Production owner profile.

This is phase two of the split-owner-profile repair.  It moves one exact
installation mapping from the duplicate normalized Profile to the already
verified survivor, replaces the installation guard, and deletes only the
duplicate Profile/ProfileBinding plus their lifecycle registry resources.

The transaction is deliberately dry-run first and fail-closed.  It never
deletes IdentityProfile, account, household, installation, Jellyfin, Seerr,
connector, media, or survivor records.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Mapping, Sequence

import boto3
from boto3.dynamodb.conditions import Attr, Key
from boto3.dynamodb.types import TypeSerializer


SOURCE_ROOT = Path(__file__).parents[1] / "api" / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from profile_mapping import build_mapping_guard, mapping_guard_source_id  # noqa: E402
from security_audit import load_audit_key, prepare_audit_item  # noqa: E402


class RetirementError(RuntimeError):
    """Raised when Production authority differs from the approved scope."""


def _same(record: Mapping[str, Any] | None, expected: Mapping[str, Any], reason: str) -> None:
    if not isinstance(record, Mapping) or any(record.get(key) != value for key, value in expected.items()):
        raise RetirementError(reason)


def _resource_key(resource_type: str, resource_id: str) -> str:
    digest = hashlib.sha256(f"{resource_type}\x00{resource_id}".encode("utf-8")).hexdigest()
    return f"resource#{resource_type}#{digest}"


def build_retirement_transaction(
    *,
    survivor_profile: Mapping[str, Any] | None,
    survivor_binding: Mapping[str, Any] | None,
    survivor_identity_profile: Mapping[str, Any] | None,
    survivor_profile_registry: Mapping[str, Any] | None,
    survivor_binding_registry: Mapping[str, Any] | None,
    duplicate_profile: Mapping[str, Any] | None,
    duplicate_binding: Mapping[str, Any] | None,
    duplicate_identity_profile: Mapping[str, Any] | None,
    duplicate_profile_registry: Mapping[str, Any] | None,
    duplicate_binding_registry: Mapping[str, Any] | None,
    mapping: Mapping[str, Any] | None,
    old_guard: Mapping[str, Any] | None,
    new_guard: Mapping[str, Any] | None,
    duplicate_mapping_records: Sequence[Mapping[str, Any]],
    account_id: str,
    household_id: str,
    survivor_profile_id: str,
    survivor_binding_id: str,
    duplicate_profile_id: str,
    duplicate_binding_id: str,
    installation_id: str,
    local_profile_source_id: str,
    profiles_table: str,
    profile_bindings_table: str,
    profile_mappings_table: str,
    lifecycle_table: str,
    security_audit_table: str,
    audit_item: Mapping[str, Any],
    now_iso: str,
    now_epoch: int,
) -> list[dict[str, Any]]:
    if not all((
        account_id, household_id, survivor_profile_id, survivor_binding_id,
        duplicate_profile_id, duplicate_binding_id, installation_id,
        local_profile_source_id, profiles_table, profile_bindings_table,
        profile_mappings_table, lifecycle_table, security_audit_table,
    )) or survivor_profile_id == duplicate_profile_id:
        raise RetirementError("incomplete or overlapping retirement scope")

    _same(survivor_profile, {
        "profile_id": survivor_profile_id,
        "household_id": household_id,
        "entity_type": "Profile",
        "status": "active",
    }, "survivor profile changed")
    _same(survivor_binding, {
        "account_id": account_id,
        "profile_id": survivor_profile_id,
        "binding_id": survivor_binding_id,
        "household_id": household_id,
        "entity_type": "ProfileBinding",
        "status": "active",
    }, "survivor binding changed")
    _same(survivor_identity_profile, {
        "profile_id": survivor_profile_id,
        "account_id": account_id,
        "household_id": household_id,
        "state": "active",
        "jellyfin_binding_state": "active",
    }, "survivor provider authority changed")
    _same(duplicate_profile, {
        "profile_id": duplicate_profile_id,
        "household_id": household_id,
        "display_name": "My Profile",
        "entity_type": "Profile",
        "status": "active",
    }, "duplicate profile changed")
    _same(duplicate_binding, {
        "account_id": account_id,
        "profile_id": duplicate_profile_id,
        "binding_id": duplicate_binding_id,
        "household_id": household_id,
        "entity_type": "ProfileBinding",
        "status": "active",
    }, "duplicate binding changed")
    if duplicate_identity_profile is not None:
        raise RetirementError("duplicate unexpectedly owns provider authority")

    old_guard_source = mapping_guard_source_id(duplicate_profile_id)
    new_guard_source = mapping_guard_source_id(survivor_profile_id)
    _same(mapping, {
        "installation_id": installation_id,
        "local_profile_source_id": local_profile_source_id,
        "entity_type": "LocalProfileMapping",
        "account_id": account_id,
        "household_id": household_id,
        "cloud_profile_id": duplicate_profile_id,
        "mapping_state": "confirmed",
    }, "approved iPhone mapping changed")
    _same(old_guard, {
        "installation_id": installation_id,
        "local_profile_source_id": old_guard_source,
        "entity_type": "LocalProfileMappingGuard",
        "account_id": account_id,
        "household_id": household_id,
        "cloud_profile_id": duplicate_profile_id,
        "current_local_profile_source_id": local_profile_source_id,
        "mapping_state": "active",
    }, "duplicate mapping guard changed")
    if new_guard is not None:
        raise RetirementError("survivor mapping guard already exists")

    active_duplicate_keys = {
        (str(record.get("installation_id") or ""), str(record.get("local_profile_source_id") or ""))
        for record in duplicate_mapping_records
        if str(record.get("mapping_state") or "") in {"confirmed", "active"}
    }
    expected_active_keys = {
        (installation_id, local_profile_source_id),
        (installation_id, old_guard_source),
    }
    if active_duplicate_keys != expected_active_keys:
        raise RetirementError("duplicate still has another active installation mapping")

    _same(survivor_profile_registry, {
        "account_id": account_id,
        "record_key": _resource_key("cloud_profile", survivor_profile_id),
        "resource_type": "cloud_profile",
        "resource_id": survivor_profile_id,
        "state": "active",
    }, "survivor lifecycle profile changed")
    _same(survivor_binding_registry, {
        "account_id": account_id,
        "record_key": _resource_key("profile_binding", survivor_binding_id),
        "resource_type": "profile_binding",
        "resource_id": survivor_binding_id,
        "state": "active",
    }, "survivor lifecycle binding changed")
    _same(duplicate_profile_registry, {
        "account_id": account_id,
        "record_key": _resource_key("cloud_profile", duplicate_profile_id),
        "resource_type": "cloud_profile",
        "resource_id": duplicate_profile_id,
        "state": "active",
    }, "duplicate lifecycle profile changed")
    _same(duplicate_binding_registry, {
        "account_id": account_id,
        "record_key": _resource_key("profile_binding", duplicate_binding_id),
        "resource_type": "profile_binding",
        "resource_id": duplicate_binding_id,
        "state": "active",
    }, "duplicate lifecycle binding changed")
    if not str((mapping or {}).get("mapping_id") or "") or not str((old_guard or {}).get("mapping_id") or ""):
        raise RetirementError("mapping identifiers missing")
    if not str((audit_item or {}).get("event_id") or ""):
        raise RetirementError("audit item is incomplete")

    replacement_guard = build_mapping_guard(
        installation_id=installation_id,
        account_id=account_id,
        household_id=household_id,
        cloud_profile_id=survivor_profile_id,
        local_source_id=local_profile_source_id,
        now_iso=now_iso,
        now_epoch=now_epoch,
    )
    return [
        {"Update": {
            "TableName": profile_mappings_table,
            "Key": {
                "installation_id": installation_id,
                "local_profile_source_id": local_profile_source_id,
            },
            "UpdateExpression": (
                "SET cloud_profile_id = :survivor, updated_at = :updated_at, "
                "updated_at_epoch = :updated_epoch, confirmation_method = :method"
            ),
            "ConditionExpression": (
                "mapping_id = :mapping_id AND entity_type = :entity "
                "AND account_id = :account_id AND household_id = :household_id "
                "AND cloud_profile_id = :duplicate AND mapping_state = :confirmed"
            ),
            "ExpressionAttributeValues": {
                ":survivor": survivor_profile_id,
                ":updated_at": now_iso,
                ":updated_epoch": int(now_epoch),
                ":method": "production-duplicate-owner-profile-retirement-v1",
                ":mapping_id": mapping["mapping_id"],
                ":entity": "LocalProfileMapping",
                ":account_id": account_id,
                ":household_id": household_id,
                ":duplicate": duplicate_profile_id,
                ":confirmed": "confirmed",
            },
        }},
        {"Delete": {
            "TableName": profile_mappings_table,
            "Key": {
                "installation_id": installation_id,
                "local_profile_source_id": old_guard_source,
            },
            "ConditionExpression": (
                "mapping_id = :mapping_id AND entity_type = :entity "
                "AND cloud_profile_id = :duplicate "
                "AND current_local_profile_source_id = :source AND mapping_state = :active"
            ),
            "ExpressionAttributeValues": {
                ":mapping_id": old_guard["mapping_id"],
                ":entity": "LocalProfileMappingGuard",
                ":duplicate": duplicate_profile_id,
                ":source": local_profile_source_id,
                ":active": "active",
            },
        }},
        {"Put": {
            "TableName": profile_mappings_table,
            "Item": replacement_guard,
            "ConditionExpression": "attribute_not_exists(installation_id) AND attribute_not_exists(local_profile_source_id)",
        }},
        {"Delete": {
            "TableName": profiles_table,
            "Key": {"profile_id": duplicate_profile_id},
            "ConditionExpression": (
                "household_id = :household_id AND display_name = :display_name "
                "AND entity_type = :entity AND #status = :active"
            ),
            "ExpressionAttributeNames": {"#status": "status"},
            "ExpressionAttributeValues": {
                ":household_id": household_id,
                ":display_name": "My Profile",
                ":entity": "Profile",
                ":active": "active",
            },
        }},
        {"Delete": {
            "TableName": profile_bindings_table,
            "Key": {"account_id": account_id, "profile_id": duplicate_profile_id},
            "ConditionExpression": (
                "binding_id = :binding_id AND household_id = :household_id "
                "AND entity_type = :entity AND #status = :active"
            ),
            "ExpressionAttributeNames": {"#status": "status"},
            "ExpressionAttributeValues": {
                ":binding_id": duplicate_binding_id,
                ":household_id": household_id,
                ":entity": "ProfileBinding",
                ":active": "active",
            },
        }},
        {"Delete": {
            "TableName": lifecycle_table,
            "Key": {
                "account_id": account_id,
                "record_key": _resource_key("cloud_profile", duplicate_profile_id),
            },
            "ConditionExpression": "resource_type = :type AND resource_id = :id AND #state = :active",
            "ExpressionAttributeNames": {"#state": "state"},
            "ExpressionAttributeValues": {
                ":type": "cloud_profile", ":id": duplicate_profile_id, ":active": "active",
            },
        }},
        {"Delete": {
            "TableName": lifecycle_table,
            "Key": {
                "account_id": account_id,
                "record_key": _resource_key("profile_binding", duplicate_binding_id),
            },
            "ConditionExpression": "resource_type = :type AND resource_id = :id AND #state = :active",
            "ExpressionAttributeNames": {"#state": "state"},
            "ExpressionAttributeValues": {
                ":type": "profile_binding", ":id": duplicate_binding_id, ":active": "active",
            },
        }},
        {"Put": {
            "TableName": security_audit_table,
            "Item": dict(audit_item),
            "ConditionExpression": "attribute_not_exists(event_id)",
        }},
    ]


def _serialize_transaction(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    serializer = TypeSerializer()
    result: list[dict[str, Any]] = []
    for action in items:
        name, body = next(iter(action.items()))
        converted = dict(body)
        for field in ("Item", "Key", "ExpressionAttributeValues"):
            if field in converted:
                converted[field] = {
                    key: serializer.serialize(value) for key, value in converted[field].items()
                }
        result.append({name: converted})
    return result


def _get(table: Any, key: Mapping[str, Any]) -> Mapping[str, Any] | None:
    return table.get_item(Key=dict(key), ConsistentRead=True).get("Item")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", required=True)
    parser.add_argument("--api-function", required=True)
    parser.add_argument("--profiles-table", required=True)
    parser.add_argument("--profile-bindings-table", required=True)
    parser.add_argument("--identity-profiles-table", required=True)
    parser.add_argument("--profile-mappings-table", required=True)
    parser.add_argument("--lifecycle-table", required=True)
    parser.add_argument("--security-audit-table", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--household-id", required=True)
    parser.add_argument("--actor-subject", required=True)
    parser.add_argument("--survivor-profile-id", required=True)
    parser.add_argument("--survivor-binding-id", required=True)
    parser.add_argument("--duplicate-profile-id", required=True)
    parser.add_argument("--duplicate-binding-id", required=True)
    parser.add_argument("--installation-id", required=True)
    parser.add_argument("--local-profile-source-id", required=True)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if args.snapshot.exists():
        raise RetirementError("snapshot already exists; refusing to overwrite")

    dynamodb = boto3.resource("dynamodb", region_name=args.region)
    table = lambda name: dynamodb.Table(name)
    old_guard_source = mapping_guard_source_id(args.duplicate_profile_id)
    new_guard_source = mapping_guard_source_id(args.survivor_profile_id)
    duplicate_profile_registry_key = _resource_key("cloud_profile", args.duplicate_profile_id)
    duplicate_binding_registry_key = _resource_key("profile_binding", args.duplicate_binding_id)
    survivor_profile_registry_key = _resource_key("cloud_profile", args.survivor_profile_id)
    survivor_binding_registry_key = _resource_key("profile_binding", args.survivor_binding_id)
    exact = {
        "survivor_profile": _get(table(args.profiles_table), {"profile_id": args.survivor_profile_id}),
        "survivor_binding": _get(table(args.profile_bindings_table), {
            "account_id": args.account_id, "profile_id": args.survivor_profile_id,
        }),
        "survivor_identity_profile": _get(table(args.identity_profiles_table), {
            "profile_id": args.survivor_profile_id,
        }),
        "survivor_profile_registry": _get(table(args.lifecycle_table), {
            "account_id": args.account_id, "record_key": survivor_profile_registry_key,
        }),
        "survivor_binding_registry": _get(table(args.lifecycle_table), {
            "account_id": args.account_id, "record_key": survivor_binding_registry_key,
        }),
        "duplicate_profile": _get(table(args.profiles_table), {"profile_id": args.duplicate_profile_id}),
        "duplicate_binding": _get(table(args.profile_bindings_table), {
            "account_id": args.account_id, "profile_id": args.duplicate_profile_id,
        }),
        "duplicate_identity_profile": _get(table(args.identity_profiles_table), {
            "profile_id": args.duplicate_profile_id,
        }),
        "duplicate_profile_registry": _get(table(args.lifecycle_table), {
            "account_id": args.account_id, "record_key": duplicate_profile_registry_key,
        }),
        "duplicate_binding_registry": _get(table(args.lifecycle_table), {
            "account_id": args.account_id, "record_key": duplicate_binding_registry_key,
        }),
        "mapping": _get(table(args.profile_mappings_table), {
            "installation_id": args.installation_id,
            "local_profile_source_id": args.local_profile_source_id,
        }),
        "old_guard": _get(table(args.profile_mappings_table), {
            "installation_id": args.installation_id,
            "local_profile_source_id": old_guard_source,
        }),
        "new_guard": _get(table(args.profile_mappings_table), {
            "installation_id": args.installation_id,
            "local_profile_source_id": new_guard_source,
        }),
        "duplicate_mapping_records": table(args.profile_mappings_table).scan(
            FilterExpression=Attr("cloud_profile_id").eq(args.duplicate_profile_id),
            ConsistentRead=True,
        ).get("Items", []),
    }
    args.snapshot.parent.mkdir(parents=True, exist_ok=True)
    args.snapshot.write_text(json.dumps(exact, indent=2, sort_keys=True, default=str) + "\n")

    variables = boto3.client("lambda", region_name=args.region).get_function_configuration(
        FunctionName=args.api_function,
    ).get("Environment", {}).get("Variables", {})
    for name in ("KAEVO_ENV", "EXPECTED_COGNITO_ISSUER", "AUDIT_REFERENCE_SECRET_ARN"):
        value = str(variables.get(name) or "")
        if not value:
            raise RetirementError(f"missing audit environment: {name}")
        os.environ[name] = value
    audit_key = load_audit_key(client=boto3.client("secretsmanager", region_name=args.region))
    now_epoch = int(time.time())
    now_iso = datetime.now(timezone.utc).isoformat()
    audit_item = prepare_audit_item(
        scope_id=args.household_id,
        event_type="duplicate_owner_profile_retired",
        actor_subject=args.actor_subject,
        target_id=args.duplicate_profile_id,
        target_type="profile",
        result="success",
        reason_code="approved_duplicate_profile_retirement",
        request_id=f"duplicate-profile-retirement-{args.installation_id}-{now_epoch}",
        now=now_epoch,
        key=audit_key,
    )
    transaction = build_retirement_transaction(
        **exact,
        account_id=args.account_id,
        household_id=args.household_id,
        survivor_profile_id=args.survivor_profile_id,
        survivor_binding_id=args.survivor_binding_id,
        duplicate_profile_id=args.duplicate_profile_id,
        duplicate_binding_id=args.duplicate_binding_id,
        installation_id=args.installation_id,
        local_profile_source_id=args.local_profile_source_id,
        profiles_table=args.profiles_table,
        profile_bindings_table=args.profile_bindings_table,
        profile_mappings_table=args.profile_mappings_table,
        lifecycle_table=args.lifecycle_table,
        security_audit_table=args.security_audit_table,
        audit_item=audit_item,
        now_iso=now_iso,
        now_epoch=now_epoch,
    )
    print(json.dumps({
        "mode": "apply" if args.apply else "dry_run",
        "transaction_actions": len(transaction),
        "installation_id": args.installation_id,
        "local_profile_source_id": args.local_profile_source_id,
        "survivor_profile_id": args.survivor_profile_id,
        "duplicate_profile_id": args.duplicate_profile_id,
        "snapshot": str(args.snapshot),
    }, sort_keys=True))
    if args.apply:
        boto3.client("dynamodb", region_name=args.region).transact_write_items(
            TransactItems=_serialize_transaction(transaction),
        )
        print("DUPLICATE_OWNER_PROFILE_RETIREMENT_APPLIED")


if __name__ == "__main__":
    main()

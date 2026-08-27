#!/usr/bin/env python3
"""Dry-run-first consolidation of one split Production owner profile.

The repair preserves the historical identity/provider profile, materializes it
in the normalized Profile/ProfileBinding model, and repoints one exact local
profile mapping.  It deliberately leaves the duplicate profile in place until
post-migration readback and physical-device checks prove the survivor works.
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
from typing import Any, Mapping

import boto3
from boto3.dynamodb.types import TypeSerializer


SOURCE_ROOT = Path(__file__).parents[1] / "api" / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from profile_binding import build_profile_creation  # noqa: E402
from profile_mapping import build_mapping_guard, mapping_guard_source_id  # noqa: E402
from security_audit import load_audit_key, prepare_audit_item  # noqa: E402


class ConsolidationError(RuntimeError):
    """Raised when current authority differs from the explicitly approved plan."""


def _same(record: Mapping[str, Any] | None, expected: Mapping[str, Any], reason: str) -> None:
    if not isinstance(record, Mapping) or any(record.get(key) != value for key, value in expected.items()):
        raise ConsolidationError(reason)


def _resource_key(resource_type: str, resource_id: str) -> str:
    digest = hashlib.sha256(f"{resource_type}\x00{resource_id}".encode("utf-8")).hexdigest()
    return f"resource#{resource_type}#{digest}"


def _registry_resource(
    account_id: str,
    resource_type: str,
    resource_id: str,
    *,
    now_epoch: int,
    attributes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    key = _resource_key(resource_type, resource_id)
    record: dict[str, Any] = {
        "account_id": account_id,
        "record_key": key,
        "record_type": "account_lifecycle_resource",
        "schema_version": 2,
        "resource_key": key,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "state": "active",
        "created_at_epoch": int(now_epoch),
        "updated_at_epoch": int(now_epoch),
    }
    if attributes:
        record["attributes"] = dict(attributes)
    return record


def build_consolidation_transaction(
    *,
    identity_profile: Mapping[str, Any] | None,
    principal: Mapping[str, Any] | None,
    identity_membership: Mapping[str, Any] | None,
    identity_household: Mapping[str, Any] | None,
    connector: Mapping[str, Any] | None,
    duplicate_profile: Mapping[str, Any] | None,
    duplicate_binding: Mapping[str, Any] | None,
    mapping: Mapping[str, Any] | None,
    old_guard: Mapping[str, Any] | None,
    survivor_profile: Mapping[str, Any] | None,
    survivor_binding: Mapping[str, Any] | None,
    new_guard: Mapping[str, Any] | None,
    account_id: str,
    household_id: str,
    owner_subject: str,
    survivor_profile_id: str,
    duplicate_profile_id: str,
    connector_id: str,
    jellyfin_user_id: str,
    installation_id: str,
    local_profile_source_id: str,
    display_name: str,
    identity_profiles_table: str,
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
        account_id, household_id, owner_subject, survivor_profile_id,
        duplicate_profile_id, connector_id, jellyfin_user_id, installation_id,
        local_profile_source_id, display_name, identity_profiles_table,
        profiles_table, profile_bindings_table, profile_mappings_table,
        lifecycle_table, security_audit_table,
    )) or survivor_profile_id == duplicate_profile_id:
        raise ConsolidationError("incomplete or overlapping consolidation scope")

    _same(identity_profile, {
        "profile_id": survivor_profile_id,
        "account_id": account_id,
        "household_id": household_id,
        "display_name": "My Profile",
        "state": "active",
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": connector_id,
        "jellyfin_user_id": jellyfin_user_id,
    }, "historical provider authority changed")
    _same(principal, {
        "principal_id": owner_subject,
        "account_id": account_id,
        "household_id": household_id,
        "state": "active",
    }, "owner principal changed")
    if survivor_profile_id not in set((principal or {}).get("profile_ids") or []):
        raise ConsolidationError("owner principal no longer owns survivor")
    _same(identity_membership, {
        "principal_id": owner_subject,
        "account_id": account_id,
        "household_id": household_id,
        "profile_id": survivor_profile_id,
        "state": "active",
    }, "identity membership changed")
    _same(identity_household, {
        "household_id": household_id,
        "account_id": account_id,
        "owner_principal_id": owner_subject,
        "state": "active",
    }, "identity household changed")
    _same(connector, {
        "connector_id": connector_id,
        "profile_id": survivor_profile_id,
        "state": "active",
        "revoked": False,
    }, "Jellyfin connector authority changed")
    _same(duplicate_profile, {
        "profile_id": duplicate_profile_id,
        "household_id": household_id,
        "entity_type": "Profile",
        "status": "active",
    }, "duplicate profile changed")
    _same(duplicate_binding, {
        "account_id": account_id,
        "profile_id": duplicate_profile_id,
        "household_id": household_id,
        "entity_type": "ProfileBinding",
        "status": "active",
    }, "duplicate binding changed")
    _same(mapping, {
        "installation_id": installation_id,
        "local_profile_source_id": local_profile_source_id,
        "entity_type": "LocalProfileMapping",
        "account_id": account_id,
        "household_id": household_id,
        "cloud_profile_id": duplicate_profile_id,
        "mapping_state": "confirmed",
    }, "approved iPhone mapping changed")
    old_guard_source = mapping_guard_source_id(duplicate_profile_id)
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
    if any(record is not None for record in (survivor_profile, survivor_binding, new_guard)):
        raise ConsolidationError("survivor normalization already exists; use readback verification")
    if not str((audit_item or {}).get("event_id") or ""):
        raise ConsolidationError("audit item is incomplete")

    created_at = str(identity_profile.get("created_at") or "").strip()
    if not created_at:
        raise ConsolidationError("historical profile creation time missing")
    try:
        created_epoch = int(datetime.fromisoformat(created_at.replace("Z", "+00:00")).timestamp())
    except ValueError as error:
        raise ConsolidationError("historical profile creation time invalid") from error

    plan = build_profile_creation(
        household_id=household_id,
        account_id=account_id,
        display_name=display_name,
        profile_type="adult",
        age_classification="adult",
        now_iso=now_iso,
        now_epoch=now_epoch,
        reserved_profile_id=survivor_profile_id,
    )
    normalized_profile = {
        **plan.profile,
        "created_at": created_at,
        "created_at_epoch": created_epoch,
        "source_provenance": "legacy-identity-profile-consolidation-v1",
        "migration_state": "completed",
    }
    normalized_binding = {
        **plan.binding,
        "migration_provenance": "legacy-identity-profile-consolidation-v1",
    }
    replacement_guard = build_mapping_guard(
        installation_id=installation_id,
        account_id=account_id,
        household_id=household_id,
        cloud_profile_id=survivor_profile_id,
        local_source_id=local_profile_source_id,
        now_iso=now_iso,
        now_epoch=now_epoch,
    )
    cloud_registry = _registry_resource(
        account_id, "cloud_profile", survivor_profile_id, now_epoch=now_epoch,
    )
    binding_registry = _registry_resource(
        account_id, "profile_binding", str(normalized_binding["binding_id"]),
        now_epoch=now_epoch,
        attributes={"profile_id": survivor_profile_id, "household_id": household_id},
    )

    exact_mapping_id = str(mapping.get("mapping_id") or "")
    exact_old_guard_id = str(old_guard.get("mapping_id") or "")
    if not exact_mapping_id or not exact_old_guard_id:
        raise ConsolidationError("mapping identifiers missing")

    return [
        {"Put": {
            "TableName": profiles_table,
            "Item": normalized_profile,
            "ConditionExpression": "attribute_not_exists(profile_id)",
        }},
        {"Put": {
            "TableName": profile_bindings_table,
            "Item": normalized_binding,
            "ConditionExpression": "attribute_not_exists(account_id) AND attribute_not_exists(profile_id)",
        }},
        {"Update": {
            "TableName": identity_profiles_table,
            "Key": {"profile_id": survivor_profile_id},
            "UpdateExpression": "SET display_name = :display_name",
            "ConditionExpression": (
                "account_id = :account_id AND household_id = :household_id "
                "AND display_name = :old_display_name "
                "AND #state = :active AND jellyfin_binding_state = :active "
                "AND jellyfin_connector_id = :connector_id AND jellyfin_user_id = :jellyfin_user_id"
            ),
            "ExpressionAttributeNames": {"#state": "state"},
            "ExpressionAttributeValues": {
                ":display_name": display_name,
                ":account_id": account_id,
                ":household_id": household_id,
                ":old_display_name": "My Profile",
                ":active": "active",
                ":connector_id": connector_id,
                ":jellyfin_user_id": jellyfin_user_id,
            },
        }},
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
                ":method": "production-owner-profile-consolidation-v1",
                ":mapping_id": exact_mapping_id,
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
                ":mapping_id": exact_old_guard_id,
                ":entity": "LocalProfileMappingGuard",
                ":duplicate": duplicate_profile_id,
                ":source": local_profile_source_id,
                ":active": "active",
            },
        }},
        {"Put": {
            "TableName": profile_mappings_table,
            "Item": replacement_guard,
            "ConditionExpression": (
                "attribute_not_exists(installation_id) "
                "AND attribute_not_exists(local_profile_source_id)"
            ),
        }},
        {"Put": {
            "TableName": lifecycle_table,
            "Item": cloud_registry,
            "ConditionExpression": "attribute_not_exists(account_id) AND attribute_not_exists(record_key)",
        }},
        {"Put": {
            "TableName": lifecycle_table,
            "Item": binding_registry,
            "ConditionExpression": "attribute_not_exists(account_id) AND attribute_not_exists(record_key)",
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", required=True)
    parser.add_argument("--api-function", required=True)
    parser.add_argument("--identity-profiles-table", required=True)
    parser.add_argument("--profiles-table", required=True)
    parser.add_argument("--profile-bindings-table", required=True)
    parser.add_argument("--profile-mappings-table", required=True)
    parser.add_argument("--principals-table", required=True)
    parser.add_argument("--identity-memberships-table", required=True)
    parser.add_argument("--identity-households-table", required=True)
    parser.add_argument("--connectors-table", required=True)
    parser.add_argument("--lifecycle-table", required=True)
    parser.add_argument("--security-audit-table", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--household-id", required=True)
    parser.add_argument("--owner-subject", required=True)
    parser.add_argument("--survivor-profile-id", required=True)
    parser.add_argument("--duplicate-profile-id", required=True)
    parser.add_argument("--connector-id", required=True)
    parser.add_argument("--jellyfin-user-id", required=True)
    parser.add_argument("--installation-id", required=True)
    parser.add_argument("--local-profile-source-id", required=True)
    parser.add_argument("--display-name", required=True)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if args.snapshot.exists():
        raise ConsolidationError("snapshot already exists; refusing to overwrite")

    dynamodb = boto3.resource("dynamodb", region_name=args.region)
    table = lambda name: dynamodb.Table(name)
    old_guard_source = mapping_guard_source_id(args.duplicate_profile_id)
    new_guard_source = mapping_guard_source_id(args.survivor_profile_id)
    exact = {
        "identity_profile": table(args.identity_profiles_table).get_item(
            Key={"profile_id": args.survivor_profile_id}, ConsistentRead=True,
        ).get("Item"),
        "principal": table(args.principals_table).get_item(
            Key={"principal_id": args.owner_subject}, ConsistentRead=True,
        ).get("Item"),
        "identity_membership": table(args.identity_memberships_table).get_item(
            Key={"principal_id": args.owner_subject}, ConsistentRead=True,
        ).get("Item"),
        "identity_household": table(args.identity_households_table).get_item(
            Key={"household_id": args.household_id}, ConsistentRead=True,
        ).get("Item"),
        "connector": table(args.connectors_table).get_item(
            Key={"connector_id": args.connector_id}, ConsistentRead=True,
        ).get("Item"),
        "duplicate_profile": table(args.profiles_table).get_item(
            Key={"profile_id": args.duplicate_profile_id}, ConsistentRead=True,
        ).get("Item"),
        "duplicate_binding": table(args.profile_bindings_table).get_item(Key={
            "account_id": args.account_id, "profile_id": args.duplicate_profile_id,
        }, ConsistentRead=True).get("Item"),
        "mapping": table(args.profile_mappings_table).get_item(Key={
            "installation_id": args.installation_id,
            "local_profile_source_id": args.local_profile_source_id,
        }, ConsistentRead=True).get("Item"),
        "old_guard": table(args.profile_mappings_table).get_item(Key={
            "installation_id": args.installation_id,
            "local_profile_source_id": old_guard_source,
        }, ConsistentRead=True).get("Item"),
        "survivor_profile": table(args.profiles_table).get_item(
            Key={"profile_id": args.survivor_profile_id}, ConsistentRead=True,
        ).get("Item"),
        "survivor_binding": table(args.profile_bindings_table).get_item(Key={
            "account_id": args.account_id, "profile_id": args.survivor_profile_id,
        }, ConsistentRead=True).get("Item"),
        "new_guard": table(args.profile_mappings_table).get_item(Key={
            "installation_id": args.installation_id,
            "local_profile_source_id": new_guard_source,
        }, ConsistentRead=True).get("Item"),
    }
    args.snapshot.parent.mkdir(parents=True, exist_ok=True)
    args.snapshot.write_text(json.dumps(exact, indent=2, sort_keys=True, default=str) + "\n")

    variables = boto3.client("lambda", region_name=args.region).get_function_configuration(
        FunctionName=args.api_function,
    ).get("Environment", {}).get("Variables", {})
    for name in ("KAEVO_ENV", "EXPECTED_COGNITO_ISSUER", "AUDIT_REFERENCE_SECRET_ARN"):
        value = str(variables.get(name) or "")
        if not value:
            raise ConsolidationError(f"missing audit environment: {name}")
        os.environ[name] = value
    audit_key = load_audit_key(client=boto3.client("secretsmanager", region_name=args.region))
    now_epoch = int(time.time())
    now_iso = datetime.now(timezone.utc).isoformat()
    audit_item = prepare_audit_item(
        scope_id=args.household_id,
        event_type="owner_profile_authority_consolidated",
        actor_subject=args.owner_subject,
        actor_type="cognito_subject",
        target_id=args.survivor_profile_id,
        target_type="profile",
        result="success",
        reason_code="approved_duplicate_profile_repair",
        request_id=f"profile-consolidation-{now_epoch}",
        now=now_epoch,
        key=audit_key,
    )
    transaction = build_consolidation_transaction(
        **exact,
        account_id=args.account_id,
        household_id=args.household_id,
        owner_subject=args.owner_subject,
        survivor_profile_id=args.survivor_profile_id,
        duplicate_profile_id=args.duplicate_profile_id,
        connector_id=args.connector_id,
        jellyfin_user_id=args.jellyfin_user_id,
        installation_id=args.installation_id,
        local_profile_source_id=args.local_profile_source_id,
        display_name=args.display_name,
        identity_profiles_table=args.identity_profiles_table,
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
        "survivor_profile_id": args.survivor_profile_id,
        "duplicate_profile_retired": False,
        "snapshot": str(args.snapshot),
    }, sort_keys=True))
    if args.apply:
        boto3.client("dynamodb", region_name=args.region).transact_write_items(
            TransactItems=_serialize_transaction(transaction),
        )
        print("OWNER_PROFILE_CONSOLIDATION_PHASE_ONE_APPLIED")


if __name__ == "__main__":
    main()

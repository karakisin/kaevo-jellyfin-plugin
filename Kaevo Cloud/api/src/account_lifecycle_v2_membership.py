"""Lifecycle V2 registry writes for an accepted household member.

These builders return DynamoDB transaction actions only.  Household Join adds
them to the same transaction that activates the member's canonical profile,
so neither the business graph nor its deletion registry can exist alone.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping


def _resource_key(resource_type: str, resource_id: str) -> str:
    digest = hashlib.sha256(
        f"{resource_type}\x00{resource_id}".encode("utf-8")
    ).hexdigest()
    return f"resource#{resource_type}#{digest}"


def _resource(
    account_id: str,
    resource_type: str,
    resource_id: str,
    *,
    now: int,
    attributes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    key = _resource_key(resource_type, resource_id)
    result: dict[str, Any] = {
        "account_id": account_id,
        "record_key": key,
        "record_type": "account_lifecycle_resource",
        "schema_version": 2,
        "resource_key": key,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "state": "active",
        "created_at_epoch": int(now),
        "updated_at_epoch": int(now),
    }
    if attributes:
        result["attributes"] = dict(attributes)
    return result


def member_registry_records(
    *,
    account_id: str,
    subject: str,
    auth_identity_key: str,
    household_id: str,
    membership_id: str,
    profile_id: str,
    profile_binding_id: str,
    owner_account_id: str | None,
    now: int,
) -> list[dict[str, Any]]:
    """Build only resources owned by the member account.

    The shared Household is deliberately absent. A member can remove their
    own membership and profiles but can never delete the Owner's household.
    """
    records = [
        {
            "account_id": account_id,
            "record_key": "root",
            "record_type": "account_lifecycle_root",
            "schema_version": 2,
            "revision": 1,
            "state": "active",
            "account_role": "member",
            "owner_deletion_state": "member",
            "created_at_epoch": int(now),
            "updated_at_epoch": int(now),
        },
        _resource(account_id, "account", account_id, now=now),
        _resource(account_id, "auth_identity", auth_identity_key, now=now),
        _resource(account_id, "cognito_subject", subject, now=now),
        _resource(account_id, "principal", subject, now=now),
        _resource(account_id, "identity_membership", subject, now=now),
        _resource(
            account_id,
            "household_membership",
            membership_id,
            now=now,
            attributes={"household_id": household_id, "profile_id": profile_id},
        ),
        _resource(account_id, "identity_profile", profile_id, now=now),
        _resource(account_id, "cloud_profile", profile_id, now=now),
        _resource(
            account_id,
            "profile_binding",
            profile_binding_id,
            now=now,
            attributes={"profile_id": profile_id, "household_id": household_id},
        ),
    ]
    if owner_account_id:
        records.append(_resource(
            account_id,
            "owner_lifecycle_guard",
            owner_account_id,
            now=now,
            attributes={
                "household_id": household_id,
                "owner_account_id": owner_account_id,
            },
        ))
    return records


def member_registry_transaction_actions(
    *,
    table_name: str,
    **record_arguments: Any,
) -> list[dict[str, Any]]:
    return [
        {"Put": {
            "TableName": table_name,
            "Item": record,
            "ConditionExpression": "attribute_not_exists(record_key)",
        }}
        for record in member_registry_records(**record_arguments)
    ]


def owner_shared_guard_transaction_action(
    *,
    table_name: str,
    owner_account_id: str,
    expected_revision: int,
    now: int,
) -> dict[str, Any]:
    if expected_revision < 1:
        raise ValueError("lifecycle_owner_revision_invalid")
    return {"Update": {
        "TableName": table_name,
        "Key": {"account_id": owner_account_id, "record_key": "root"},
        "UpdateExpression": (
            "SET owner_deletion_state = :shared, revision = :next, "
            "updated_at_epoch = :now"
        ),
        "ConditionExpression": (
            "record_type = :root_type AND #state = :active "
            "AND account_role = :owner AND revision = :current "
            "AND owner_deletion_state IN (:sole, :shared)"
        ),
        "ExpressionAttributeNames": {"#state": "state"},
        "ExpressionAttributeValues": {
            ":root_type": "account_lifecycle_root",
            ":active": "active",
            ":owner": "owner",
            ":current": int(expected_revision),
            ":next": int(expected_revision) + 1,
            ":sole": "sole_member",
            ":shared": "ownership_transfer_required",
            ":now": int(now),
        },
    }}

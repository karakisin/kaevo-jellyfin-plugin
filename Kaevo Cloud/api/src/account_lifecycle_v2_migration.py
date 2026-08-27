"""Explicit protected migration from the canonical V1 graph to Lifecycle V2.

This endpoint exists only for accounts created before Lifecycle V2 enrollment.
It never searches by email, display name, device cache, or provider username.
The DPoP-bound app session selects one account and Cognito subject; every
registry resource must then be proven by immutable keys in that account's
canonical Cloud graph before one conditional transaction may create the root.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any, Iterable, Mapping, Sequence

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from account_foundation import provider_subject_key
from account_lifecycle_v2_session import (
    LifecycleV2SessionError,
    ProtectedLifecycleV2SessionAuthenticator,
)
from security_audit import AuditReferenceError, prepare_audit_item


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


class LifecycleV2MigrationError(RuntimeError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _response(status: int, body: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": json.dumps(body, separators=(",", ":"), sort_keys=True),
    }


def _name(key: str) -> str:
    value = os.environ.get(key, "").strip()
    if not value:
        raise LifecycleV2MigrationError("migration_configuration_missing")
    return value


def _text(value: Any, reason: str) -> str:
    result = str(value or "").strip()
    if not result or len(result) > 512 or any(ord(character) < 32 for character in result):
        raise LifecycleV2MigrationError(reason)
    return result


def _active(
    record: Mapping[str, Any] | None,
    *,
    entity_type: str | None = None,
    state_field: str = "state",
) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        raise LifecycleV2MigrationError("legacy_graph_incomplete")
    result = dict(record)
    if entity_type is not None and result.get("entity_type") != entity_type:
        raise LifecycleV2MigrationError("legacy_graph_conflict")
    if result.get(state_field) != "active":
        raise LifecycleV2MigrationError("legacy_graph_inactive")
    return result


def _resource_key(resource_type: str, resource_id: str) -> str:
    digest = hashlib.sha256(f"{resource_type}\x00{resource_id}".encode("utf-8")).hexdigest()
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


def _unique(records: Iterable[Mapping[str, Any]], key: str) -> list[dict[str, Any]]:
    material = [dict(record) for record in records]
    values = [_text(record.get(key), "legacy_graph_identifier_missing") for record in material]
    if len(values) != len(set(values)):
        raise LifecycleV2MigrationError("legacy_graph_ambiguous")
    return material


def _snapshot_check(
    table: str,
    key: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> dict[str, Any]:
    """Condition one exact source item inside the migration transaction."""
    names = {f"#f{index}": field for index, field in enumerate(expected)}
    values = {f":v{index}": value for index, value in enumerate(expected.values())}
    return {"ConditionCheck": {
        "TableName": table,
        "Key": dict(key),
        "ConditionExpression": " AND ".join(
            f"#f{index} = :v{index}" for index in range(len(expected))
        ),
        "ExpressionAttributeNames": names,
        "ExpressionAttributeValues": values,
    }}


def build_registry(
    *,
    account_id: str,
    subject: str,
    account: Mapping[str, Any],
    auth_identity: Mapping[str, Any],
    principal: Mapping[str, Any],
    identity_membership: Mapping[str, Any],
    household: Mapping[str, Any],
    account_memberships: Sequence[Mapping[str, Any]],
    household_memberships: Sequence[Mapping[str, Any]],
    identity_profiles: Sequence[Mapping[str, Any]],
    cloud_profiles: Sequence[Mapping[str, Any]],
    profile_bindings: Sequence[Mapping[str, Any]],
    now: int,
) -> list[dict[str, Any]]:
    account_id = _text(account_id, "account_id_invalid")
    subject = _text(subject, "subject_invalid")
    account = _active(account, entity_type="Account", state_field="status")
    if account.get("account_id") != account_id:
        raise LifecycleV2MigrationError("account_binding_conflict")

    expected_auth_key = provider_subject_key("cognito", subject)
    auth_identity = _active(auth_identity, entity_type="AuthIdentity", state_field="status")
    if (
        auth_identity.get("auth_identity_key") != expected_auth_key
        or auth_identity.get("account_id") != account_id
        or auth_identity.get("provider") != "cognito"
    ):
        raise LifecycleV2MigrationError("auth_identity_binding_conflict")

    principal = _active(principal)
    identity_membership = _active(identity_membership)
    household_id = _text(principal.get("household_id"), "household_id_invalid")
    if any(
        record.get("account_id") != account_id
        or record.get("principal_id") != subject
        or record.get("household_id") != household_id
        for record in (principal, identity_membership)
    ):
        raise LifecycleV2MigrationError("principal_binding_conflict")

    household = _active(household)
    if household.get("household_id") != household_id:
        raise LifecycleV2MigrationError("household_binding_conflict")

    own_memberships = [
        _active(record, state_field="status") for record in account_memberships
        if record.get("entity_type") == "HouseholdMembership"
    ]
    if len(own_memberships) != 1:
        raise LifecycleV2MigrationError("household_membership_ambiguous")
    membership = own_memberships[0]
    if membership.get("account_id") != account_id or membership.get("household_id") != household_id:
        raise LifecycleV2MigrationError("household_membership_conflict")
    access_role = _text(membership.get("household_access_role"), "household_role_invalid")
    account_role = "owner" if access_role == "owner" else "member"
    if account_role == "owner":
        if (
            household.get("account_id") != account_id
            or household.get("owner_principal_id") != subject
        ):
            raise LifecycleV2MigrationError("household_owner_conflict")
        other_adult = any(
            record.get("entity_type") == "HouseholdMembership"
            and record.get("status") == "active"
            and record.get("account_id") != account_id
            and record.get("canonical_role") in {"owner", "adult"}
            for record in household_memberships
        )
        owner_deletion_state = "transfer_required" if other_adult else "sole_member"
    else:
        owner_deletion_state = "member"

    identity_profiles = _unique(
        (_active(record) for record in identity_profiles), "profile_id",
    )
    principal_profile_ids = {
        _text(value, "identity_profile_id_invalid")
        for value in (principal.get("profile_ids") or [])
    }
    membership_profile_id = _text(
        identity_membership.get("profile_id"), "identity_membership_profile_missing",
    )
    principal_profile_ids.add(membership_profile_id)
    if {record.get("profile_id") for record in identity_profiles} != principal_profile_ids:
        raise LifecycleV2MigrationError("identity_profile_set_conflict")
    if any(
        record.get("account_id") != account_id
        or record.get("household_id") != household_id
        or record.get("owner_principal_id") != subject
        for record in identity_profiles
    ):
        raise LifecycleV2MigrationError("identity_profile_binding_conflict")

    profile_bindings = _unique(
        (_active(record, entity_type="ProfileBinding", state_field="status")
         for record in profile_bindings),
        "binding_id",
    )
    if not profile_bindings:
        raise LifecycleV2MigrationError("profile_binding_required")
    if any(
        record.get("account_id") != account_id or record.get("household_id") != household_id
        for record in profile_bindings
    ):
        raise LifecycleV2MigrationError("profile_binding_conflict")
    binding_profile_ids = {
        _text(record.get("profile_id"), "cloud_profile_id_invalid")
        for record in profile_bindings
    }
    cloud_profiles = _unique(
        (_active(record, entity_type="Profile", state_field="status")
         for record in cloud_profiles),
        "profile_id",
    )
    if {record.get("profile_id") for record in cloud_profiles} != binding_profile_ids:
        raise LifecycleV2MigrationError("cloud_profile_set_conflict")
    if any(record.get("household_id") != household_id for record in cloud_profiles):
        raise LifecycleV2MigrationError("cloud_profile_binding_conflict")

    root = {
        "account_id": account_id,
        "record_key": "root",
        "record_type": "account_lifecycle_root",
        "schema_version": 2,
        "revision": 1,
        "state": "active",
        "account_role": account_role,
        "owner_deletion_state": owner_deletion_state,
        "migration_provenance": "protected-exact-v1-to-v2",
        "created_at_epoch": int(now),
        "updated_at_epoch": int(now),
    }
    resources = [
        _resource(account_id, "account", account_id, now=now),
        _resource(account_id, "auth_identity", expected_auth_key, now=now),
        _resource(account_id, "cognito_subject", subject, now=now),
        _resource(account_id, "principal", subject, now=now),
        _resource(account_id, "identity_membership", subject, now=now),
        _resource(
            account_id, "household_membership", _text(membership.get("membership_id"), "membership_id_invalid"),
            now=now, attributes={"household_id": household_id, "profile_id": membership_profile_id},
        ),
    ]
    if account_role == "owner":
        resources.append(_resource(account_id, "household", household_id, now=now))
    for guard in _unique(
        (record for record in account_memberships
         if record.get("entity_type") in {
             "HouseholdMembershipAccountGuard", "HouseholdMembershipOwnerGuard",
         }),
        "membership_id",
    ):
        if (
            guard.get("status") != "active"
            or guard.get("account_id") != account_id
            or guard.get("household_id") != household_id
        ):
            raise LifecycleV2MigrationError("household_membership_guard_conflict")
        resources.append(_resource(
            account_id, "household_membership_guard",
            _text(guard.get("membership_id"), "membership_guard_id_invalid"),
            now=now, attributes={"household_id": household_id},
        ))
    resources.extend(
        _resource(account_id, "identity_profile", str(record["profile_id"]), now=now)
        for record in identity_profiles
    )
    resources.extend(
        _resource(account_id, "cloud_profile", str(record["profile_id"]), now=now)
        for record in cloud_profiles
    )
    resources.extend(
        _resource(
            account_id, "profile_binding", str(record["binding_id"]), now=now,
            attributes={"profile_id": str(record["profile_id"]), "household_id": household_id},
        )
        for record in profile_bindings
    )
    if len({record["record_key"] for record in resources}) != len(resources):
        raise LifecycleV2MigrationError("lifecycle_resource_ambiguous")
    return [root, *sorted(resources, key=lambda record: str(record["record_key"]))]


def _ready(records: Sequence[Mapping[str, Any]], *, created: bool) -> dict[str, Any]:
    root = next(record for record in records if record.get("record_key") == "root")
    identity_profiles = sorted(
        str(record.get("resource_id") or "") for record in records
        if record.get("resource_type") == "identity_profile"
    )
    household = next((
        str(record.get("resource_id") or "") for record in records
        if record.get("resource_type") == "household"
    ), "")
    if not household:
        household = next((
            str((record.get("attributes") or {}).get("household_id") or "")
            for record in records
            if record.get("resource_type") == "household_membership"
        ), "")
    return {
        "state": "ready",
        "created": bool(created),
        "account_id": str(root["account_id"]),
        "household_id": household,
        "profile_id": identity_profiles[0] if identity_profiles else "",
        "lifecycle_revision": int(root["revision"]),
    }


def migrate_existing_account_v2(
    event: Mapping[str, Any],
    *,
    session: Mapping[str, Any],
    dynamodb: Any,
    now: int | None = None,
) -> dict[str, Any]:
    try:
        body = json.loads(event.get("body") or "{}")
    except (TypeError, ValueError) as error:
        raise LifecycleV2MigrationError("migration_request_invalid") from error
    if not isinstance(body, Mapping) or body.get("explicit_confirmation") is not True:
        raise LifecycleV2MigrationError("migration_confirmation_required")
    current = int(time.time()) if now is None else int(now)
    account_id = _text(session.get("account_id"), "session_account_invalid")
    subject = _text(session.get("principal_id"), "session_principal_invalid")
    lifecycle = dynamodb.Table(_name("ACCOUNT_LIFECYCLE_V2_TABLE"))
    existing = lifecycle.query(
        KeyConditionExpression=Key("account_id").eq(account_id), ConsistentRead=True,
    ).get("Items") or []
    if any(record.get("record_key") == "root" for record in existing):
        return _response(200, _ready(existing, created=False))

    account = dynamodb.Table(_name("ACCOUNTS_TABLE")).get_item(
        Key={"account_id": account_id}, ConsistentRead=True,
    ).get("Item")
    auth_key = provider_subject_key("cognito", subject)
    auth = dynamodb.Table(_name("AUTH_IDENTITIES_TABLE")).get_item(
        Key={"auth_identity_key": auth_key}, ConsistentRead=True,
    ).get("Item")
    principal = dynamodb.Table(_name("PRINCIPALS_TABLE")).get_item(
        Key={"principal_id": subject}, ConsistentRead=True,
    ).get("Item")
    identity_membership = dynamodb.Table(_name("IDENTITY_MEMBERSHIPS_TABLE")).get_item(
        Key={"principal_id": subject}, ConsistentRead=True,
    ).get("Item")
    household_id = _text((principal or {}).get("household_id"), "household_id_invalid")
    household = dynamodb.Table(_name("IDENTITY_HOUSEHOLDS_TABLE")).get_item(
        Key={"household_id": household_id}, ConsistentRead=True,
    ).get("Item")
    memberships_table = dynamodb.Table(_name("HOUSEHOLD_MEMBERSHIPS_TABLE"))
    account_memberships = memberships_table.query(
        IndexName="account_id-updated_at_epoch-index",
        KeyConditionExpression=Key("account_id").eq(account_id),
        ConsistentRead=False,
    ).get("Items") or []
    household_memberships = memberships_table.query(
        KeyConditionExpression=Key("household_id").eq(household_id),
        ConsistentRead=True,
    ).get("Items") or []

    profile_ids = {
        _text(value, "identity_profile_id_invalid")
        for value in ((principal or {}).get("profile_ids") or [])
    }
    profile_ids.add(_text(
        (identity_membership or {}).get("profile_id"),
        "identity_membership_profile_missing",
    ))
    identity_profiles_table = dynamodb.Table(_name("IDENTITY_PROFILES_TABLE"))
    identity_profiles = [
        identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        for profile_id in sorted(profile_ids)
    ]
    bindings = dynamodb.Table(_name("PROFILE_BINDINGS_TABLE")).query(
        KeyConditionExpression=Key("account_id").eq(account_id),
        ConsistentRead=True,
    ).get("Items") or []
    profiles_table = dynamodb.Table(_name("PROFILES_TABLE"))
    cloud_profiles = [
        profiles_table.get_item(
            Key={"profile_id": _text(binding.get("profile_id"), "cloud_profile_id_invalid")},
            ConsistentRead=True,
        ).get("Item")
        for binding in bindings
    ]
    registry = build_registry(
        account_id=account_id,
        subject=subject,
        account=account,
        auth_identity=auth,
        principal=principal,
        identity_membership=identity_membership,
        household=household,
        account_memberships=account_memberships,
        household_memberships=household_memberships,
        identity_profiles=identity_profiles,
        cloud_profiles=cloud_profiles,
        profile_bindings=bindings,
        now=current,
    )
    try:
        audit = prepare_audit_item(
            scope_id=account_id,
            event_type="account_lifecycle_v2_existing_account_migrated",
            actor_subject=subject,
            actor_type="protected_cognito_subject",
            target_id=account_id,
            target_type="account",
            result="success",
            request_id=str((event.get("requestContext") or {}).get("requestId") or "")[:128],
            now=current,
        )
    except AuditReferenceError as error:
        raise LifecycleV2MigrationError("audit_unavailable") from error
    transaction = [{"Put": {
        "TableName": _name("ACCOUNT_LIFECYCLE_V2_TABLE"),
        "Item": record,
        "ConditionExpression": "attribute_not_exists(record_key)",
    }} for record in registry]
    transaction.append({"Put": {
        "TableName": _name("SECURITY_AUDIT_TABLE"),
        "Item": audit,
        "ConditionExpression": "attribute_not_exists(event_id)",
    }})
    snapshot_checks = [
        _snapshot_check(_name("ACCOUNTS_TABLE"), {"account_id": account_id}, {
            "entity_type": "Account", "status": "active",
        }),
        _snapshot_check(_name("AUTH_IDENTITIES_TABLE"), {"auth_identity_key": auth_key}, {
            "account_id": account_id, "provider": "cognito",
            "entity_type": "AuthIdentity", "status": "active",
        }),
        _snapshot_check(_name("PRINCIPALS_TABLE"), {"principal_id": subject}, {
            "account_id": account_id, "household_id": household_id,
            "profile_ids": list((principal or {}).get("profile_ids") or []), "state": "active",
        }),
        _snapshot_check(_name("IDENTITY_MEMBERSHIPS_TABLE"), {"principal_id": subject}, {
            "account_id": account_id, "household_id": household_id,
            "profile_id": str((identity_membership or {}).get("profile_id") or ""),
            "state": "active",
        }),
        _snapshot_check(_name("IDENTITY_HOUSEHOLDS_TABLE"), {"household_id": household_id}, {
            "account_id": str((household or {}).get("account_id") or ""),
            "owner_principal_id": str((household or {}).get("owner_principal_id") or ""),
            "state": "active",
        }),
    ]
    checked_memberships: set[tuple[str, str]] = set()
    for record in [*account_memberships, *household_memberships]:
        key = (
            str(record.get("household_id") or ""),
            str(record.get("membership_id") or ""),
        )
        if not all(key) or key in checked_memberships:
            continue
        checked_memberships.add(key)
        snapshot_checks.append(_snapshot_check(
            _name("HOUSEHOLD_MEMBERSHIPS_TABLE"),
            {"household_id": key[0], "membership_id": key[1]},
            {
                "entity_type": str(record.get("entity_type") or ""),
                "account_id": str(record.get("account_id") or ""),
                "status": str(record.get("status") or ""),
            },
        ))
    for record in identity_profiles:
        snapshot_checks.append(_snapshot_check(
            _name("IDENTITY_PROFILES_TABLE"),
            {"profile_id": str(record.get("profile_id") or "")},
            {
                "account_id": str(record.get("account_id") or ""),
                "household_id": str(record.get("household_id") or ""),
                "owner_principal_id": str(record.get("owner_principal_id") or ""),
                "state": str(record.get("state") or ""),
            },
        ))
    for record in cloud_profiles:
        snapshot_checks.append(_snapshot_check(
            _name("PROFILES_TABLE"),
            {"profile_id": str(record.get("profile_id") or "")},
            {
                "household_id": str(record.get("household_id") or ""),
                "entity_type": str(record.get("entity_type") or ""),
                "status": str(record.get("status") or ""),
            },
        ))
    for record in bindings:
        snapshot_checks.append(_snapshot_check(
            _name("PROFILE_BINDINGS_TABLE"),
            {
                "account_id": str(record.get("account_id") or ""),
                "profile_id": str(record.get("profile_id") or ""),
            },
            {
                "binding_id": str(record.get("binding_id") or ""),
                "household_id": str(record.get("household_id") or ""),
                "entity_type": str(record.get("entity_type") or ""),
                "status": str(record.get("status") or ""),
            },
        ))
    transaction.extend(snapshot_checks)
    if len(transaction) > 100:
        raise LifecycleV2MigrationError("legacy_graph_ambiguous")
    try:
        dynamodb.meta.client.transact_write_items(TransactItems=transaction)
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") == "TransactionCanceledException":
            existing = lifecycle.query(
                KeyConditionExpression=Key("account_id").eq(account_id), ConsistentRead=True,
            ).get("Items") or []
            if any(record.get("record_key") == "root" for record in existing):
                return _response(200, _ready(existing, created=False))
            raise LifecycleV2MigrationError("migration_graph_changed") from error
        raise LifecycleV2MigrationError("migration_transaction_failed") from error
    return _response(201, _ready(registry, created=True))


def _authenticator() -> ProtectedLifecycleV2SessionAuthenticator:
    dynamodb = boto3.resource("dynamodb")
    return ProtectedLifecycleV2SessionAuthenticator(
        app_sessions_table=dynamodb.Table(_name("APP_SESSIONS_TABLE")),
        installations_table=dynamodb.Table(_name("INSTALLATIONS_TABLE")),
        public_base_url=_name("PUBLIC_API_BASE_URL"),
    )


def lambda_handler(event: Mapping[str, Any], _context: Any) -> dict[str, Any]:
    try:
        return migrate_existing_account_v2(
            event,
            session=_authenticator().authenticate(event),
            dynamodb=boto3.resource("dynamodb"),
        )
    except LifecycleV2SessionError as error:
        LOGGER.info(
            "account_lifecycle_v2_migration_session_rejected reason=%s",
            error.reason,
        )
        return _response(401, {"state": "not_authorized"})
    except LifecycleV2MigrationError as error:
        LOGGER.warning("account_lifecycle_v2_migration_failed reason=%s", error.reason)
        status = 409 if error.reason in {
            "legacy_graph_ambiguous", "legacy_graph_conflict", "legacy_graph_incomplete",
            "migration_graph_changed", "household_membership_ambiguous",
            "identity_profile_set_conflict", "cloud_profile_set_conflict",
        } else 400
        return _response(status, {"state": error.reason})
    except Exception:
        LOGGER.exception("account_lifecycle_v2_migration_unhandled")
        return _response(503, {"state": "temporarily_unavailable"})

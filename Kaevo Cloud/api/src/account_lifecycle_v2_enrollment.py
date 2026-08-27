"""Fresh Owner enrollment for Account Lifecycle V2.

The entire account graph and lifecycle registry are created in one DynamoDB
transaction.  Existing V1 accounts are never inferred or silently backfilled
through this endpoint.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
from typing import Any, Mapping

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from account_foundation import (
    CanonicalRole,
    build_account_record,
    build_auth_identity_record,
    normalized_email,
    provider_subject_key,
)
from household_membership import (
    build_account_household_guard,
    build_household_membership_record,
    build_household_owner_guard,
    household_membership_id,
)
from identity_authority import AuthorityError, AuthoritativeClaims, validate_access_token_claims
from profile_binding import build_profile_creation
from security_audit import AuditReferenceError, prepare_audit_item


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


class LifecycleV2EnrollmentError(RuntimeError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _response(status: int, body: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": json.dumps(body, separators=(",", ":"), sort_keys=True),
    }


def _claims(event: Mapping[str, Any]) -> Mapping[str, Any]:
    authorizer = (((event.get("requestContext") or {}).get("authorizer") or {}).get("jwt") or {})
    claims = authorizer.get("claims")
    return claims if isinstance(claims, Mapping) else {}


def _name(key: str) -> str:
    value = os.environ.get(key, "").strip()
    if not value:
        raise LifecycleV2EnrollmentError("enrollment_configuration_missing")
    return value


def _identifier(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(24)}"


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
    result = {
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


def _registry_records(
    *,
    account_id: str,
    subject: str,
    auth_identity_key: str,
    household_id: str,
    membership_id: str,
    account_guard_id: str,
    owner_guard_id: str,
    profile_id: str,
    binding_id: str,
    now: int,
) -> list[dict[str, Any]]:
    return [
        {
            "account_id": account_id,
            "record_key": "root",
            "record_type": "account_lifecycle_root",
            "schema_version": 2,
            "revision": 1,
            "state": "active",
            "account_role": "owner",
            "owner_deletion_state": "sole_member",
            "created_at_epoch": int(now),
            "updated_at_epoch": int(now),
        },
        _resource(account_id, "account", account_id, now=now),
        _resource(account_id, "auth_identity", auth_identity_key, now=now),
        _resource(account_id, "cognito_subject", subject, now=now),
        _resource(account_id, "principal", subject, now=now),
        _resource(account_id, "identity_membership", subject, now=now),
        _resource(account_id, "household", household_id, now=now),
        _resource(
            account_id, "household_membership", membership_id, now=now,
            attributes={"household_id": household_id, "profile_id": profile_id},
        ),
        _resource(
            account_id, "household_membership_guard", account_guard_id, now=now,
            attributes={"household_id": household_id},
        ),
        _resource(
            account_id, "household_membership_guard", owner_guard_id, now=now,
            attributes={"household_id": household_id},
        ),
        _resource(account_id, "identity_profile", profile_id, now=now),
        _resource(account_id, "cloud_profile", profile_id, now=now),
        _resource(
            account_id, "profile_binding", binding_id, now=now,
            attributes={"profile_id": profile_id, "household_id": household_id},
        ),
    ]


def _verified_email(claims: Mapping[str, Any], *, cognito: Any) -> tuple[str | None, bool]:
    if str(claims.get("email_verified") or "").lower() == "true":
        try:
            return normalized_email(claims.get("email")), True
        except Exception:
            pass
    username = str(claims.get("username") or claims.get("cognito:username") or "").strip()
    if not username:
        return None, False
    try:
        result = cognito.admin_get_user(
            UserPoolId=_name("COGNITO_USER_POOL_ID"), Username=username,
        )
    except ClientError:
        return None, False
    attributes = {
        str(item.get("Name") or ""): str(item.get("Value") or "")
        for item in result.get("UserAttributes", [])
        if isinstance(item, Mapping)
    }
    if attributes.get("email_verified", "").lower() != "true":
        return None, False
    try:
        return normalized_email(attributes.get("email")), True
    except Exception:
        return None, False


def _ready_receipt(account_id: str, household_id: str, profile_id: str, *, created: bool) -> dict[str, Any]:
    return {
        "state": "ready",
        "created": bool(created),
        "account_id": account_id,
        "household_id": household_id,
        "profile_id": profile_id,
        "lifecycle_revision": 1,
    }


def _existing_receipt(dynamodb: Any, subject: str) -> dict[str, Any] | None:
    auth = dynamodb.Table(_name("AUTH_IDENTITIES_TABLE")).get_item(
        Key={"auth_identity_key": provider_subject_key("cognito", subject)},
        ConsistentRead=True,
    ).get("Item")
    if not isinstance(auth, Mapping):
        return None
    if auth.get("status") != "active" or auth.get("entity_type") != "AuthIdentity":
        raise LifecycleV2EnrollmentError("auth_identity_not_active")
    account_id = str(auth.get("account_id") or "")
    root = dynamodb.Table(_name("ACCOUNT_LIFECYCLE_V2_TABLE")).get_item(
        Key={"account_id": account_id, "record_key": "root"},
        ConsistentRead=True,
    ).get("Item")
    if not isinstance(root, Mapping) or int(root.get("schema_version") or 0) != 2:
        raise LifecycleV2EnrollmentError("legacy_account_requires_separate_migration")
    membership = dynamodb.Table(_name("IDENTITY_MEMBERSHIPS_TABLE")).get_item(
        Key={"principal_id": subject},
        ConsistentRead=True,
    ).get("Item")
    if not isinstance(membership, Mapping) or any((
        str(membership.get("account_id") or "") != account_id,
        str(membership.get("state") or "") != "active",
    )):
        raise LifecycleV2EnrollmentError("lifecycle_registry_incomplete")
    household_id = str(membership.get("household_id") or "")
    profile_id = str(membership.get("profile_id") or "")
    if not household_id or not profile_id:
        raise LifecycleV2EnrollmentError("lifecycle_registry_incomplete")
    resources = dynamodb.Table(_name("ACCOUNT_LIFECYCLE_V2_TABLE")).query(
        KeyConditionExpression=Key("account_id").eq(account_id),
        ConsistentRead=True,
    ).get("Items") or []
    active_by_type: dict[str, set[str]] = {}
    for item in resources:
        if (
            item.get("record_type") != "account_lifecycle_resource"
            or item.get("state") != "active"
        ):
            continue
        active_by_type.setdefault(str(item.get("resource_type") or ""), set()).add(
            str(item.get("resource_id") or ""),
        )
    if (
        household_id not in active_by_type.get("household", set())
        or profile_id not in active_by_type.get("identity_profile", set())
    ):
        raise LifecycleV2EnrollmentError("lifecycle_registry_incomplete")
    return _ready_receipt(account_id, household_id, profile_id, created=False)


def enroll_owner_v2(
    event: Mapping[str, Any],
    *,
    dynamodb: Any,
    cognito: Any,
    now: int | None = None,
) -> dict[str, Any]:
    current = int(time.time()) if now is None else int(now)
    claims = _claims(event)
    standard = validate_access_token_claims(
        claims,
        expected_issuer=_name("EXPECTED_COGNITO_ISSUER"),
        expected_client_id=_name("EXPECTED_ENROLLMENT_CLIENT_ID"),
        additional_expected_client_ids=(os.environ.get("EXPECTED_NATIVE_CLIENT_ID", ""),),
        now=current,
    )
    subject = standard["sub"]
    if existing := _existing_receipt(dynamodb, subject):
        return _response(200, existing)

    account_id = _identifier("acct")
    household_id = _identifier("hh")
    profile_id = _identifier("profile")
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(current))
    email, email_verified = _verified_email(claims, cognito=cognito)
    account = build_account_record(account_id, now_iso=now_iso, now_epoch=current)
    auth = build_auth_identity_record(
        account_id=account_id,
        provider="cognito",
        provider_subject=subject,
        now_iso=now_iso,
        now_epoch=current,
        email=email,
        email_verified=email_verified,
    )
    principal = {
        "principal_id": subject,
        "account_id": account_id,
        "household_id": household_id,
        "role": "owner",
        "authz_version": 1,
        "profile_ids": [profile_id],
        "state": "active",
        "revoked": False,
        "created_at": now_iso,
    }
    identity_membership = {
        "principal_id": subject,
        "account_id": account_id,
        "household_id": household_id,
        "profile_id": profile_id,
        "role": "owner",
        "authz_version": 1,
        "state": "active",
        "created_at": now_iso,
    }
    household = {
        "household_id": household_id,
        "account_id": account_id,
        "owner_principal_id": subject,
        "state": "active",
        "created_at": now_iso,
    }
    identity_profile = {
        "profile_id": profile_id,
        "account_id": account_id,
        "household_id": household_id,
        "owner_principal_id": subject,
        "display_name": "My Profile",
        "profile_type": "adult",
        "state": "active",
        "created_at": now_iso,
    }
    authority = AuthoritativeClaims(account_id, household_id, profile_id, "owner", 1)
    membership_id = household_membership_id(account_id, household_id)
    normalized_membership = {
        **build_household_membership_record(
            authority, CanonicalRole.OWNER, now_iso=now_iso, now_epoch=current,
        ),
        "profile_id": profile_id,
        "migration_provenance": "account-lifecycle-v2",
    }
    account_guard = build_account_household_guard(
        authority, membership_id=membership_id, now_iso=now_iso, now_epoch=current,
    )
    owner_guard = build_household_owner_guard(
        authority, membership_id=membership_id, now_iso=now_iso, now_epoch=current,
    )
    profile_creation = build_profile_creation(
        household_id=household_id,
        account_id=account_id,
        display_name="My Profile",
        profile_type="adult",
        age_classification="adult",
        now_iso=now_iso,
        now_epoch=current,
        reserved_profile_id=profile_id,
    )
    cloud_profile = {
        **profile_creation.profile,
        "source_provenance": "account-lifecycle-v2",
    }
    profile_binding = {
        **profile_creation.binding,
        "migration_provenance": "account-lifecycle-v2",
    }
    registry = _registry_records(
        account_id=account_id,
        subject=subject,
        auth_identity_key=str(auth["auth_identity_key"]),
        household_id=household_id,
        membership_id=membership_id,
        account_guard_id=str(account_guard["membership_id"]),
        owner_guard_id=str(owner_guard["membership_id"]),
        profile_id=profile_id,
        binding_id=str(profile_binding["binding_id"]),
        now=current,
    )
    try:
        audit = prepare_audit_item(
            scope_id=household_id,
            event_type="account_lifecycle_v2_owner_enrolled",
            actor_subject=subject,
            actor_type="cognito_subject",
            target_id=account_id,
            target_type="account",
            result="success",
            request_id=str((event.get("requestContext") or {}).get("requestId") or "")[:128],
            now=current,
        )
    except AuditReferenceError as error:
        raise LifecycleV2EnrollmentError("audit_unavailable") from error

    records = [
        (_name("ACCOUNTS_TABLE"), "account_id", account),
        (_name("AUTH_IDENTITIES_TABLE"), "auth_identity_key", auth),
        (_name("PRINCIPALS_TABLE"), "principal_id", principal),
        (_name("IDENTITY_MEMBERSHIPS_TABLE"), "principal_id", identity_membership),
        (_name("IDENTITY_HOUSEHOLDS_TABLE"), "household_id", household),
        (_name("IDENTITY_PROFILES_TABLE"), "profile_id", identity_profile),
        (_name("HOUSEHOLD_MEMBERSHIPS_TABLE"), "membership_id", normalized_membership),
        (_name("HOUSEHOLD_MEMBERSHIPS_TABLE"), "membership_id", account_guard),
        (_name("HOUSEHOLD_MEMBERSHIPS_TABLE"), "membership_id", owner_guard),
        (_name("PROFILES_TABLE"), "profile_id", cloud_profile),
        (_name("PROFILE_BINDINGS_TABLE"), "profile_id", profile_binding),
        *[(
            _name("ACCOUNT_LIFECYCLE_V2_TABLE"), "record_key", record,
        ) for record in registry],
        (_name("SECURITY_AUDIT_TABLE"), "event_id", audit),
    ]
    transaction = [{"Put": {
        "TableName": table,
        "Item": item,
        "ConditionExpression": f"attribute_not_exists({key})",
    }} for table, key, item in records]
    try:
        dynamodb.meta.client.transact_write_items(TransactItems=transaction)
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") == "TransactionCanceledException":
            existing = _existing_receipt(dynamodb, subject)
            if existing:
                return _response(200, existing)
        raise LifecycleV2EnrollmentError("enrollment_transaction_failed") from error
    return _response(201, _ready_receipt(account_id, household_id, profile_id, created=True))


def lambda_handler(event: Mapping[str, Any], _context: Any) -> dict[str, Any]:
    try:
        return enroll_owner_v2(
            event,
            dynamodb=boto3.resource("dynamodb"),
            cognito=boto3.client("cognito-idp"),
        )
    except AuthorityError:
        return _response(401, {"state": "not_authorized"})
    except LifecycleV2EnrollmentError as error:
        if error.reason == "legacy_account_requires_separate_migration":
            return _response(409, {"state": error.reason})
        LOGGER.warning("account_lifecycle_v2_enrollment_failed reason=%s", error.reason)
        return _response(503, {"state": "temporarily_unavailable"})
    except Exception:
        LOGGER.exception("account_lifecycle_v2_enrollment_unhandled")
        return _response(503, {"state": "temporarily_unavailable"})

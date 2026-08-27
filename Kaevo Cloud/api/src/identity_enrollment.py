"""One-time, owner-only identity bootstrap for a Cognito human subject.

This function is intentionally separate from the main API and claim issuer. It
accepts only an API-Gateway-verified enrollment access token, generates all
authority identifiers server-side, and commits the identity graph atomically.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from typing import Any, Mapping

import boto3
from botocore.exceptions import ClientError

from identity_authority import AuthorityError, derive_authoritative_claims, validate_access_token_claims
from security_audit import AuditReferenceError, prepare_audit_item
from account_foundation import (
    build_account_record,
    build_auth_identity_record,
    normalized_email,
    plan_existing_account_backfill,
    provider_subject_key,
)
from household_membership import (
    account_household_guard_id,
    household_membership_id,
    household_owner_guard_id,
    plan_household_membership_normalization,
)


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


def _response(status_code: int, body: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": json.dumps(body, separators=(",", ":"), sort_keys=True),
    }


def _claims(event: Mapping[str, Any]) -> Mapping[str, Any]:
    authorizer = (((event.get("requestContext") or {}).get("authorizer") or {}).get("jwt") or {})
    claims = authorizer.get("claims")
    return claims if isinstance(claims, Mapping) else {}


def _request_id(event: Mapping[str, Any]) -> str:
    return str((event.get("requestContext") or {}).get("requestId") or "")[:128]


def _name(environment_name: str) -> str:
    value = os.environ.get(environment_name, "")
    if not value:
        raise AuthorityError("enrollment_configuration")
    return value


def _identifier(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(24)}"


def _verified_cognito_email(claims: Mapping[str, Any]) -> tuple[str | None, bool]:
    """Resolve the signed-in account email from Cognito, never profile data.

    Cognito access tokens do not consistently include ``email`` for federated
    users.  The verified token does include the exact Cognito username, so a
    single AdminGetUser lookup can persist the account email during one-time
    enrollment without matching or merging users by email.
    """
    claim_email = claims.get("email")
    claim_verified = str(claims.get("email_verified") or "").lower() == "true"
    if claim_verified:
        try:
            if email := normalized_email(claim_email):
                return email, True
        except Exception:
            pass

    user_pool_id = os.environ.get("COGNITO_USER_POOL_ID", "").strip()
    username = str(
        claims.get("username") or claims.get("cognito:username") or ""
    ).strip()
    if not user_pool_id or not username or len(username) > 128:
        return None, False
    if any(ord(character) < 32 for character in username):
        return None, False

    try:
        response = boto3.client("cognito-idp").admin_get_user(
            UserPoolId=user_pool_id,
            Username=username,
        )
    except ClientError as error:
        LOGGER.warning(
            "owner_enrollment_email_lookup_deferred code=%s",
            str((error.response or {}).get("Error", {}).get("Code") or "unknown"),
        )
        return None, False

    attributes = {
        str(item.get("Name") or ""): str(item.get("Value") or "")
        for item in response.get("UserAttributes", [])
        if isinstance(item, Mapping)
    }
    if attributes.get("email_verified", "").lower() != "true":
        return None, False
    try:
        return normalized_email(attributes.get("email")), True
    except Exception:
        return None, False


def _get_graph(dynamodb: Any, subject: str):
    principal = dynamodb.Table(_name("PRINCIPALS_TABLE")).get_item(
        Key={"principal_id": subject}, ConsistentRead=True,
    ).get("Item")
    if not principal:
        return None
    membership = dynamodb.Table(_name("IDENTITY_MEMBERSHIPS_TABLE")).get_item(
        Key={"principal_id": subject}, ConsistentRead=True,
    ).get("Item")
    household_id = str(principal.get("household_id") or "")
    profile_id = str((membership or {}).get("profile_id") or "")
    household = dynamodb.Table(_name("IDENTITY_HOUSEHOLDS_TABLE")).get_item(
        Key={"household_id": household_id}, ConsistentRead=True,
    ).get("Item") if household_id else None
    profile = dynamodb.Table(_name("IDENTITY_PROFILES_TABLE")).get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item") if profile_id else None
    claims = derive_authoritative_claims(subject, principal, membership, household, profile)
    if str(principal.get("role") or "") != "owner":
        raise AuthorityError("invalid_existing_enrollment")
    return {
        "principal": principal,
        "membership": membership,
        "household": household,
        "profile": profile,
        "claims": claims,
    }


def _foundation_puts(dynamodb: Any, subject: str, graph: Mapping[str, Any], *, now: int):
    """Return missing owner-foundation records derived only from stored authority."""
    claims = graph["claims"]
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    account = dynamodb.Table(_name("ACCOUNTS_TABLE")).get_item(
        Key={"account_id": claims.account_id}, ConsistentRead=True,
    ).get("Item")
    auth_identity_key = provider_subject_key("cognito", subject)
    auth_identity = dynamodb.Table(_name("AUTH_IDENTITIES_TABLE")).get_item(
        Key={"auth_identity_key": auth_identity_key}, ConsistentRead=True,
    ).get("Item")
    account_plan = plan_existing_account_backfill(
        subject=subject,
        principal=graph["principal"],
        membership=graph["membership"],
        household=graph["household"],
        profile=graph["profile"],
        existing_account=account,
        existing_auth_identity=auth_identity,
        now_iso=created_at,
        now_epoch=now,
    )

    memberships = dynamodb.Table(_name("HOUSEHOLD_MEMBERSHIPS_TABLE"))
    membership_id = household_membership_id(claims.account_id, claims.household_id)
    existing_membership = memberships.get_item(Key={
        "household_id": claims.household_id,
        "membership_id": membership_id,
    }, ConsistentRead=True).get("Item")
    account_guard_id = account_household_guard_id(claims.account_id, claims.household_id)
    existing_account_guard = memberships.get_item(Key={
        "household_id": claims.household_id,
        "membership_id": account_guard_id,
    }, ConsistentRead=True).get("Item")
    owner_guard_id = household_owner_guard_id(claims.household_id)
    existing_owner_guard = memberships.get_item(Key={
        "household_id": claims.household_id,
        "membership_id": owner_guard_id,
    }, ConsistentRead=True).get("Item")
    membership_plan = plan_household_membership_normalization(
        subject=subject,
        principal=graph["principal"],
        legacy_membership=graph["membership"],
        household=graph["household"],
        profile=graph["profile"],
        existing_membership=existing_membership,
        existing_account_guard=existing_account_guard,
        existing_owner_guard=existing_owner_guard,
        now_iso=created_at,
        now_epoch=now,
    )

    normalized_membership = membership_plan.membership_record
    if normalized_membership is not None:
        normalized_membership = {
            **normalized_membership,
            "profile_id": claims.profile_id,
            "migration_provenance": "owner-enrollment-v1",
        }
    records = (
        (_name("ACCOUNTS_TABLE"), "account_id", account_plan.account_record),
        (_name("AUTH_IDENTITIES_TABLE"), "auth_identity_key", account_plan.auth_identity_record),
        (_name("HOUSEHOLD_MEMBERSHIPS_TABLE"), "membership_id", normalized_membership),
        (_name("HOUSEHOLD_MEMBERSHIPS_TABLE"), "membership_id", membership_plan.uniqueness_guard_record),
        (_name("HOUSEHOLD_MEMBERSHIPS_TABLE"), "membership_id", membership_plan.owner_guard_record),
    )
    writes = [
        {"Put": {
            "TableName": table,
            "Item": item,
            "ConditionExpression": f"attribute_not_exists({key})",
        }}
        for table, key, item in records
        if item is not None
    ]
    if (
        isinstance(existing_membership, dict)
        and existing_membership.get("entity_type") == "HouseholdMembership"
        and existing_membership.get("status") == "active"
        and int(existing_membership.get("schema_version") or 0) == 1
        and str(existing_membership.get("membership_id") or "") == membership_id
        and str(existing_membership.get("account_id") or "") == claims.account_id
        and str(existing_membership.get("household_id") or "") == claims.household_id
        and str(existing_membership.get("canonical_role") or "") == claims.role
        and not str(existing_membership.get("profile_id") or "").strip()
    ):
        writes.append({"Update": {
            "TableName": _name("HOUSEHOLD_MEMBERSHIPS_TABLE"),
            "Key": {
                "household_id": claims.household_id,
                "membership_id": membership_id,
            },
            "UpdateExpression": (
                "SET profile_id = :profile_id, updated_at = :updated_at, "
                "updated_at_epoch = :updated_at_epoch, migration_provenance = :provenance"
            ),
            "ConditionExpression": (
                "entity_type = :entity_type AND #status = :active "
                "AND schema_version = :schema_version AND account_id = :account_id "
                "AND household_id = :household_id AND membership_id = :membership_id "
                "AND canonical_role = :canonical_role AND attribute_not_exists(profile_id)"
            ),
            "ExpressionAttributeNames": {"#status": "status"},
            "ExpressionAttributeValues": {
                ":profile_id": claims.profile_id,
                ":updated_at": created_at,
                ":updated_at_epoch": now,
                ":provenance": "owner-enrollment-repair-v1",
                ":entity_type": "HouseholdMembership",
                ":active": "active",
                ":schema_version": 1,
                ":account_id": claims.account_id,
                ":household_id": claims.household_id,
                ":membership_id": membership_id,
                ":canonical_role": claims.role,
            },
        }})
    return writes


def _foundation_puts_for_new_graph(
    graph: Mapping[str, Any], *, created_at: str, now: int,
):
    """Build the normalized membership records committed with a fresh graph."""
    plan = plan_household_membership_normalization(
        subject=graph["principal"]["principal_id"],
        principal=graph["principal"],
        legacy_membership=graph["membership"],
        household=graph["household"],
        profile=graph["profile"],
        existing_membership=None,
        existing_account_guard=None,
        existing_owner_guard=None,
        now_iso=created_at,
        now_epoch=now,
    )
    normalized_membership = plan.membership_record
    if normalized_membership is not None:
        normalized_membership = {
            **normalized_membership,
            "profile_id": graph["claims"].profile_id,
            "migration_provenance": "owner-enrollment-v1",
        }
    records = (
        normalized_membership,
        plan.uniqueness_guard_record,
        plan.owner_guard_record,
    )
    return [
        {"Put": {
            "TableName": _name("HOUSEHOLD_MEMBERSHIPS_TABLE"),
            "Item": item,
            "ConditionExpression": "attribute_not_exists(membership_id)",
        }}
        for item in records
        if item is not None
    ]


def _repair_existing_owner_foundation(
    event: Mapping[str, Any], *, dynamodb: Any, subject: str,
    graph: Mapping[str, Any], now: int,
) -> bool:
    """Add only missing normalized records for a valid existing owner graph."""
    puts = _foundation_puts(dynamodb, subject, graph, now=now)
    if not puts:
        return False
    try:
        audit = prepare_audit_item(
            scope_id=graph["claims"].household_id,
            event_type="identity_owner_enrollment_repaired",
            actor_subject=subject,
            actor_type="cognito_subject",
            target_id=graph["claims"].profile_id,
            target_type="profile",
            result="success",
            request_id=_request_id(event),
            now=now,
        )
    except AuditReferenceError as error:
        raise AuthorityError("audit_unavailable") from error
    puts.append({"Put": {
        "TableName": _name("SECURITY_AUDIT_TABLE"),
        "Item": audit,
        "ConditionExpression": "attribute_not_exists(event_id)",
    }})
    try:
        dynamodb.meta.client.transact_write_items(TransactItems=puts)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "TransactionCanceledException":
            refreshed = _get_graph(dynamodb, subject)
            if refreshed and not _foundation_puts(dynamodb, subject, refreshed, now=now):
                return False
        raise AuthorityError("enrollment_failed") from error
    return True


def enroll_owner(event: Mapping[str, Any], *, dynamodb: Any, now: int | None = None) -> dict[str, Any]:
    current = int(time.time()) if now is None else int(now)
    standard = validate_access_token_claims(
        _claims(event),
        expected_issuer=_name("EXPECTED_COGNITO_ISSUER"),
        expected_client_id=_name("EXPECTED_ENROLLMENT_CLIENT_ID"),
        additional_expected_client_ids=(os.environ.get("EXPECTED_NATIVE_CLIENT_ID", ""),),
        now=current,
    )
    subject = standard["sub"]
    account_email, account_email_verified = _verified_cognito_email(_claims(event))
    existing_graph = _get_graph(dynamodb, subject)
    if existing_graph:
        _repair_existing_owner_foundation(
            event, dynamodb=dynamodb, subject=subject, graph=existing_graph, now=current,
        )
        return _response(200, {"state": "already_enrolled", "next": "authenticate_with_main_client"})

    account_id = _identifier("acct")
    household_id = _identifier("hh")
    profile_id = _identifier("profile")
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(current))
    account = build_account_record(account_id, now_iso=created_at, now_epoch=current)
    auth_identity = build_auth_identity_record(
        account_id=account_id,
        provider="cognito",
        provider_subject=subject,
        now_iso=created_at,
        now_epoch=current,
        email=account_email,
        email_verified=account_email_verified,
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
        "created_at": created_at,
    }
    membership = {
        "principal_id": subject,
        "account_id": account_id,
        "household_id": household_id,
        "profile_id": profile_id,
        "role": "owner",
        "authz_version": 1,
        "state": "active",
        "created_at": created_at,
    }
    household = {
        "household_id": household_id,
        "account_id": account_id,
        "owner_principal_id": subject,
        "state": "active",
        "created_at": created_at,
    }
    profile = {
        "profile_id": profile_id,
        "account_id": account_id,
        "household_id": household_id,
        "owner_principal_id": subject,
        # A fresh Owner graph must already be presentable through
        # /v3/identity/me.  Leaving this field absent makes the protected
        # identity resolver reject the otherwise-valid self profile and sends
        # a brand-new account into the legacy profile-recovery flow.
        "display_name": "My Profile",
        "profile_type": "adult",
        "state": "active",
        "created_at": created_at,
    }
    graph = {
        "principal": principal,
        "membership": membership,
        "household": household,
        "profile": profile,
        "claims": derive_authoritative_claims(subject, principal, membership, household, profile),
    }
    try:
        audit = prepare_audit_item(
            scope_id=household_id,
            event_type="identity_owner_enrolled",
            actor_subject=subject,
            actor_type="cognito_subject",
            target_id=profile_id,
            target_type="profile",
            result="success",
            request_id=_request_id(event),
            now=current,
        )
    except AuditReferenceError as error:
        raise AuthorityError("audit_unavailable") from error
    entries = [
        (_name("ACCOUNTS_TABLE"), "account_id", account),
        (_name("AUTH_IDENTITIES_TABLE"), "auth_identity_key", auth_identity),
        (_name("PRINCIPALS_TABLE"), "principal_id", principal),
        (_name("IDENTITY_MEMBERSHIPS_TABLE"), "principal_id", membership),
        (_name("IDENTITY_HOUSEHOLDS_TABLE"), "household_id", household),
        (_name("IDENTITY_PROFILES_TABLE"), "profile_id", profile),
    ]
    transaction = [
        {"Put": {
            "TableName": table,
            "Item": item,
            "ConditionExpression": f"attribute_not_exists({key})",
        }}
        for table, key, item in entries
    ]
    transaction.extend(_foundation_puts_for_new_graph(graph, created_at=created_at, now=current))
    transaction.append({"Put": {
        "TableName": _name("SECURITY_AUDIT_TABLE"),
        "Item": audit,
        "ConditionExpression": "attribute_not_exists(event_id)",
    }})
    try:
        dynamodb.meta.client.transact_write_items(TransactItems=transaction)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "TransactionCanceledException":
            try:
                existing_graph = _get_graph(dynamodb, subject)
                if existing_graph:
                    _repair_existing_owner_foundation(
                        event, dynamodb=dynamodb, subject=subject,
                        graph=existing_graph, now=current,
                    )
                    return _response(200, {"state": "already_enrolled", "next": "authenticate_with_main_client"})
            except AuthorityError:
                pass
        raise AuthorityError("enrollment_failed") from error
    return _response(201, {"state": "enrolled", "next": "authenticate_with_main_client"})


def lambda_handler(event, _context):
    try:
        return enroll_owner(event, dynamodb=boto3.resource("dynamodb"))
    except AuthorityError as error:
        LOGGER.warning("identity_enrollment_denied reason=%s", error.reason)
        return _response(401, {"state": "not_authorized"})
    except Exception:
        LOGGER.error("identity_enrollment_failed")
        return _response(503, {"state": "temporarily_unavailable"})

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


def _name(environment_name: str) -> str:
    value = os.environ.get(environment_name, "")
    if not value:
        raise AuthorityError("enrollment_configuration")
    return value


def _identifier(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(24)}"


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
    derive_authoritative_claims(subject, principal, membership, household, profile)
    if str(principal.get("role") or "") != "owner":
        raise AuthorityError("invalid_existing_enrollment")
    return principal


def enroll_owner(event: Mapping[str, Any], *, dynamodb: Any, now: int | None = None) -> dict[str, Any]:
    current = int(time.time()) if now is None else int(now)
    standard = validate_access_token_claims(
        _claims(event),
        expected_issuer=_name("EXPECTED_COGNITO_ISSUER"),
        expected_client_id=_name("EXPECTED_ENROLLMENT_CLIENT_ID"),
        now=current,
    )
    subject = standard["sub"]
    if _get_graph(dynamodb, subject):
        return _response(200, {"state": "already_enrolled", "next": "authenticate_with_main_client"})

    account_id = _identifier("acct")
    household_id = _identifier("hh")
    profile_id = _identifier("profile")
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(current))
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
        "profile_type": "adult",
        "state": "active",
        "created_at": created_at,
    }
    audit = {
        "household_id": household_id,
        "event_id": f"{current:010d}#{_identifier('event')}",
        "event_type": "identity_owner_enrolled",
        "subject_hash": __import__("hashlib").sha256(subject.encode("utf-8")).hexdigest(),
        "created_at": created_at,
        "expires_at": current + (400 * 24 * 60 * 60),
    }
    entries = [
        (_name("PRINCIPALS_TABLE"), "principal_id", principal),
        (_name("IDENTITY_MEMBERSHIPS_TABLE"), "principal_id", membership),
        (_name("IDENTITY_HOUSEHOLDS_TABLE"), "household_id", household),
        (_name("IDENTITY_PROFILES_TABLE"), "profile_id", profile),
        (_name("SECURITY_AUDIT_TABLE"), "event_id", audit),
    ]
    transaction = [
        {"Put": {
            "TableName": table,
            "Item": item,
            "ConditionExpression": f"attribute_not_exists({key})",
        }}
        for table, key, item in entries
    ]
    try:
        dynamodb.meta.client.transact_write_items(TransactItems=transaction)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "TransactionCanceledException":
            try:
                if _get_graph(dynamodb, subject):
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

"""Cognito V2 pre-token-generation issuer for authoritative Kaevo claims."""

from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import Any, Mapping

import boto3

from identity_authority import AuthorityError, derive_authoritative_claims, require_identifier


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)
SUPPORTED_TRIGGERS = frozenset({
    "TokenGeneration_HostedAuth",
    "TokenGeneration_Authentication",
    "TokenGeneration_NewPasswordChallenge",
    "TokenGeneration_AuthenticateDevice",
    "TokenGeneration_RefreshTokens",
})
KAEVO_CLAIMS = [
    "account_id", "household_id", "profile_id", "role",
    "authz_version", "identity_schema_version",
]


def _safe_subject(subject: str) -> str:
    return hashlib.sha256(subject.encode("utf-8")).hexdigest()[:12]


def _deny(reason: str, event: Mapping[str, Any], started: float) -> None:
    request_id = str(event.get("requestId") or "")[:64]
    raw_subject = str(((event.get("request") or {}).get("userAttributes") or {}).get("sub") or "")
    LOGGER.warning(
        "identity_claim_denied reason=%s request=%s subject_hash=%s duration_ms=%d",
        reason,
        request_id,
        _safe_subject(raw_subject) if raw_subject else "missing",
        int((time.monotonic() - started) * 1000),
    )
    raise RuntimeError("Not authorized")


def _table(resource: Any, environment_name: str):
    name = os.environ.get(environment_name, "")
    if not name:
        raise AuthorityError("issuer_configuration")
    return resource.Table(name)


def _client_kind(event: Mapping[str, Any], cognito: Any) -> str:
    pool_id = require_identifier(event.get("userPoolId"), "user_pool_id")
    client_id = require_identifier((event.get("callerContext") or {}).get("clientId"), "client_id")
    pool = cognito.describe_user_pool(UserPoolId=pool_id).get("UserPool") or {}
    if str(pool.get("Name") or "") != os.environ.get("EXPECTED_USER_POOL_NAME", ""):
        raise AuthorityError("unexpected_user_pool")
    client = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id).get("UserPoolClient") or {}
    client_name = str(client.get("ClientName") or "")
    if client_name == os.environ.get("EXPECTED_MAIN_CLIENT_NAME", ""):
        return "main"
    if client_name == os.environ.get("EXPECTED_ENROLLMENT_CLIENT_NAME", ""):
        return "enrollment"
    raise AuthorityError("unexpected_user_pool_client")


def issue_claims(event: Mapping[str, Any], *, dynamodb: Any, cognito: Any) -> dict[str, Any]:
    if str(event.get("version") or "") != "2" or event.get("triggerSource") not in SUPPORTED_TRIGGERS:
        raise AuthorityError("unsupported_token_event")
    kind = _client_kind(event, cognito)
    response = dict(event)
    response["response"] = dict(response.get("response") or {})
    overrides: dict[str, Any] = {
        "idTokenGeneration": {"claimsToSuppress": KAEVO_CLAIMS},
        "accessTokenGeneration": {"claimsToSuppress": KAEVO_CLAIMS},
    }
    if kind == "enrollment":
        response["response"]["claimsAndScopeOverrideDetails"] = overrides
        return response

    subject = require_identifier(
        ((event.get("request") or {}).get("userAttributes") or {}).get("sub"),
        "subject",
        opaque=True,
    )
    principals = _table(dynamodb, "PRINCIPALS_TABLE")
    memberships = _table(dynamodb, "IDENTITY_MEMBERSHIPS_TABLE")
    households = _table(dynamodb, "IDENTITY_HOUSEHOLDS_TABLE")
    profiles = _table(dynamodb, "IDENTITY_PROFILES_TABLE")
    principal = principals.get_item(Key={"principal_id": subject}, ConsistentRead=True).get("Item")
    membership = memberships.get_item(Key={"principal_id": subject}, ConsistentRead=True).get("Item")
    household_id = str((principal or {}).get("household_id") or "")
    profile_id = str((membership or {}).get("profile_id") or "")
    household = households.get_item(Key={"household_id": household_id}, ConsistentRead=True).get("Item") if household_id else None
    profile = profiles.get_item(Key={"profile_id": profile_id}, ConsistentRead=True).get("Item") if profile_id else None
    claims = derive_authoritative_claims(subject, principal, membership, household, profile)
    overrides["accessTokenGeneration"] = {
        "claimsToAddOrOverride": claims.as_token_claims(),
        "claimsToSuppress": [],
    }
    response["response"]["claimsAndScopeOverrideDetails"] = overrides
    return response


def lambda_handler(event, _context):
    started = time.monotonic()
    try:
        return issue_claims(
            event,
            dynamodb=boto3.resource("dynamodb"),
            cognito=boto3.client("cognito-idp"),
        )
    except AuthorityError as error:
        _deny(error.reason, event, started)
    except Exception:
        LOGGER.error("identity_claim_denied reason=dependency_failure")
        _deny("dependency_failure", event, started)

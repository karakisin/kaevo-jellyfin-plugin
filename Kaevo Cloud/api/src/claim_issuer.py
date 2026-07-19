"""Cognito V2 pre-token-generation issuer for authoritative Kaevo claims."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
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
NATIVE_TRIGGERS = frozenset({"TokenGeneration_HostedAuth"})
KAEVO_CLAIMS = [
    "account_id", "household_id", "profile_id", "role",
    "authz_version", "identity_schema_version",
]


@dataclass(frozen=True)
class ClientPolicy:
    kind: str
    expected_name: str
    permitted_triggers: frozenset[str]
    authentication_purpose: str
    issues_human_claims: bool
    permits_refresh_claims: bool
    stage_only: bool


def _configured_policies() -> tuple[ClientPolicy, ...]:
    return (
        ClientPolicy(
            kind="main",
            expected_name=os.environ.get("EXPECTED_MAIN_CLIENT_NAME", ""),
            permitted_triggers=SUPPORTED_TRIGGERS,
            authentication_purpose="existing_human_authentication",
            issues_human_claims=True,
            permits_refresh_claims=True,
            stage_only=False,
        ),
        ClientPolicy(
            kind="enrollment",
            expected_name=os.environ.get("EXPECTED_ENROLLMENT_CLIENT_NAME", ""),
            permitted_triggers=SUPPORTED_TRIGGERS,
            authentication_purpose="owner_enrollment",
            issues_human_claims=False,
            permits_refresh_claims=True,
            stage_only=False,
        ),
        ClientPolicy(
            kind="native",
            expected_name=os.environ.get("EXPECTED_NATIVE_CLIENT_NAME", ""),
            permitted_triggers=NATIVE_TRIGGERS,
            authentication_purpose="security_stage_managed_login",
            issues_human_claims=True,
            permits_refresh_claims=False,
            stage_only=True,
        ),
    )


def _deny(reason: str, event: Mapping[str, Any], started: float) -> None:
    request_id = str(event.get("requestId") or "")[:64]
    subject_present = bool(((event.get("request") or {}).get("userAttributes") or {}).get("sub"))
    LOGGER.warning(
        "identity_claim_denied reason=%s request=%s subject_state=%s duration_ms=%d",
        reason,
        request_id,
        "present" if subject_present else "missing",
        int((time.monotonic() - started) * 1000),
    )
    raise RuntimeError("Not authorized")


def _table(resource: Any, environment_name: str):
    name = os.environ.get(environment_name, "")
    if not name:
        raise AuthorityError("issuer_configuration")
    return resource.Table(name)


def _validate_native_configuration(client: Mapping[str, Any]) -> None:
    required = {
        "AllowedOAuthFlowsUserPoolClient": True,
        "EnableTokenRevocation": True,
    }
    if "ClientSecret" in client or any(client.get(key) is not value for key, value in required.items()):
        raise AuthorityError("unexpected_native_client_configuration")
    exact_lists = {
        "AllowedOAuthFlows": ["code"],
        "AllowedOAuthScopes": ["openid"],
        "SupportedIdentityProviders": ["COGNITO"],
        "CallbackURLs": ["kaevo-security-stage://oauth/callback"],
        "LogoutURLs": ["kaevo-security-stage://oauth/logout"],
        "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
    }
    if any(client.get(key) != value for key, value in exact_lists.items()):
        raise AuthorityError("unexpected_native_client_configuration")
    if client.get("DefaultRedirectURI") != "kaevo-security-stage://oauth/callback":
        raise AuthorityError("unexpected_native_client_configuration")


def _client_policy(event: Mapping[str, Any], cognito: Any) -> ClientPolicy:
    pool_id = require_identifier(event.get("userPoolId"), "user_pool_id")
    client_id = require_identifier((event.get("callerContext") or {}).get("clientId"), "client_id")
    pool = cognito.describe_user_pool(UserPoolId=pool_id).get("UserPool") or {}
    if pool.get("Id") != pool_id or str(pool.get("Name") or "") != os.environ.get("EXPECTED_USER_POOL_NAME", ""):
        raise AuthorityError("unexpected_user_pool")
    client = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id).get("UserPoolClient") or {}
    if client.get("ClientId") != client_id or client.get("UserPoolId") != pool_id:
        raise AuthorityError("unexpected_user_pool_client")
    client_name = str(client.get("ClientName") or "")
    trigger = str(event.get("triggerSource") or "")
    for policy in _configured_policies():
        if policy.expected_name and client_name == policy.expected_name:
            if trigger not in policy.permitted_triggers:
                raise AuthorityError("unsupported_client_trigger")
            if policy.stage_only:
                _validate_native_configuration(client)
            return policy
    raise AuthorityError("unexpected_user_pool_client")


def issue_claims(event: Mapping[str, Any], *, dynamodb: Any, cognito: Any) -> dict[str, Any]:
    if str(event.get("version") or "") != "2":
        raise AuthorityError("unsupported_token_event")
    policy = _client_policy(event, cognito)
    response = dict(event)
    response["response"] = dict(response.get("response") or {})
    overrides: dict[str, Any] = {
        "idTokenGeneration": {"claimsToSuppress": KAEVO_CLAIMS},
        "accessTokenGeneration": {"claimsToSuppress": KAEVO_CLAIMS},
    }
    if not policy.issues_human_claims:
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

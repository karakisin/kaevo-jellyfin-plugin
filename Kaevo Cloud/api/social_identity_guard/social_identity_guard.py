"""Pre-sign-up collision guard for Google and Sign in with Apple.

This trigger never links by email. It only prevents Cognito from creating a
second federated profile when a provider-authenticated email already belongs to
a user in the pool. Existing owners must use the explicit DPoP-bound pre-link
flow first.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Mapping

import boto3


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


def guard_external_provider_signup(event: Mapping[str, Any], *, cognito: Any):
    if event.get("triggerSource") != "PreSignUp_ExternalProvider":
        return event
    pool_id = str(event.get("userPoolId") or "")
    expected_pool_id = str(os.environ.get("EXPECTED_USER_POOL_ID") or "")
    username = str(event.get("userName") or "")
    attributes = ((event.get("request") or {}).get("userAttributes") or {})
    email = str(attributes.get("email") or "").strip().lower()
    provider = username.split("_", 1)[0]
    if not pool_id or not expected_pool_id or pool_id != expected_pool_id:
        raise ValueError("unexpected_user_pool")
    if provider not in {"Google", "SignInWithApple"}:
        raise ValueError("unsupported_external_identity")
    if not email:
        raise ValueError("verified_email_required")
    # Cognito invokes this trigger only after the configured upstream provider
    # has authenticated the user.  Its PreSignUp event does not reliably carry
    # the provider's email_verified mapping, even when the user-pool mapping is
    # configured.  The trusted provider identity, required mapped email, and
    # collision check below are the stable security boundary here.
    escaped = email.replace("\\", "\\\\").replace('"', '\\"')
    matches = cognito.list_users(UserPoolId=pool_id, Filter=f'email = "{escaped}"', Limit=2).get("Users") or []
    if matches:
        LOGGER.warning("social_identity_signup_denied reason=existing_account_link_required provider=%s", provider)
        raise ValueError("existing_account_link_required")
    LOGGER.info("social_identity_signup_allowed provider=%s", provider)
    return event


def lambda_handler(event, _context):
    return guard_external_provider_signup(event, cognito=boto3.client("cognito-idp"))

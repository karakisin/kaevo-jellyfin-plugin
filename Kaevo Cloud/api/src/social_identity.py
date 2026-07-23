"""Conflict-safe social identity linking for an existing Kaevo owner.

The caller is already authorized by the device-bound owner session in
``handler.py``.  This module owns only the provider OAuth transaction and the
Cognito link.  Email is validation/collision evidence, never link authority.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key


LINK_TTL_SECONDS = 5 * 60
PROVIDERS = frozenset({"google", "apple"})
GOOGLE_ISSUERS = frozenset({"accounts.google.com", "https://accounts.google.com"})
APPLE_ISSUER = "https://appleid.apple.com"


class SocialIdentityError(Exception):
    """A stable, non-sensitive social-link failure."""

    def __init__(self, reason: str, status_code: int = 400):
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


@dataclass(frozen=True)
class ProviderIdentity:
    provider: str
    subject: str
    email_present: bool
    email_verified: bool


def canonical_provider(value: Any) -> str:
    provider = str(value or "").strip().lower()
    if provider not in PROVIDERS:
        raise SocialIdentityError("unsupported_identity_provider")
    return provider


def provider_name(provider: str) -> str:
    return "Google" if canonical_provider(provider) == "google" else "SignInWithApple"


def state_key(state: str) -> str:
    return f"social-link#{hashlib.sha256(state.encode('ascii')).hexdigest()}"


def new_attempt(*, provider: str, session: Mapping[str, Any], callback_url: str, now: int | None = None):
    current = int(time.time()) if now is None else int(now)
    canonical = canonical_provider(provider)
    if not callback_url.startswith("https://"):
        raise SocialIdentityError("invalid_social_link_callback", 503)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    attempt_id = secrets.token_urlsafe(24)
    item = {
        "token_hash": state_key(state),
        "record_type": "social_identity_link",
        "state": "pending",
        "provider": canonical,
        "attempt_id": attempt_id,
        "principal_id": str(session.get("principal_id") or ""),
        "account_id": str(session.get("account_id") or ""),
        "household_id": str(session.get("household_id") or ""),
        "installation_id": str(session.get("installation_id") or ""),
        "oauth_nonce": nonce,
        "callback_url": callback_url,
        "created_at_epoch": current,
        "expires_at": current + LINK_TTL_SECONDS,
    }
    if not all(item[key] for key in ("principal_id", "account_id", "household_id", "installation_id")):
        raise SocialIdentityError("invalid_owner_session", 401)
    return item, state


def authorization_url(provider: str, credentials: Mapping[str, Any], *, callback_url: str, state: str, nonce: str) -> str:
    canonical = canonical_provider(provider)
    client_id = str(credentials.get("client_id") or "").strip()
    if not client_id:
        raise SocialIdentityError("identity_provider_unavailable", 503)
    if canonical == "google":
        base = "https://accounts.google.com/o/oauth2/v2/auth"
        query = {
            "client_id": client_id,
            "redirect_uri": callback_url,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            "prompt": "select_account",
        }
    else:
        base = "https://appleid.apple.com/auth/authorize"
        query = {
            "client_id": client_id,
            "redirect_uri": callback_url,
            "response_type": "code",
            "response_mode": "form_post",
            "scope": "name email",
            "state": state,
            "nonce": nonce,
        }
    return f"{base}?{urllib.parse.urlencode(query)}"


def _post_form(url: str, values: Mapping[str, str]) -> Mapping[str, Any]:
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(values).encode("ascii"),
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # nosec B310 -- fixed provider URL
            payload = response.read(64 * 1024)
    except Exception as error:
        raise SocialIdentityError("identity_provider_unavailable", 503) from error
    try:
        result = json.loads(payload)
    except (TypeError, ValueError) as error:
        raise SocialIdentityError("invalid_identity_provider_response", 502) from error
    if not isinstance(result, Mapping):
        raise SocialIdentityError("invalid_identity_provider_response", 502)
    return result


def _apple_client_secret(credentials: Mapping[str, Any], *, now: int) -> str:
    try:
        key = load_pem_private_key(str(credentials["private_key"]).encode("utf-8"), password=None)
        return jwt.encode(
            {
                "iss": str(credentials["team_id"]),
                "iat": now,
                "exp": now + 300,
                "aud": APPLE_ISSUER,
                "sub": str(credentials["client_id"]),
            },
            key,
            algorithm="ES256",
            headers={"kid": str(credentials["key_id"]), "typ": "JWT"},
        )
    except Exception as error:
        raise SocialIdentityError("identity_provider_unavailable", 503) from error


def exchange_code(provider: str, credentials: Mapping[str, Any], *, code: str, callback_url: str, now: int | None = None) -> str:
    canonical = canonical_provider(provider)
    current = int(time.time()) if now is None else int(now)
    values = {
        "grant_type": "authorization_code",
        "client_id": str(credentials.get("client_id") or ""),
        "code": code,
        "redirect_uri": callback_url,
    }
    if canonical == "google":
        values["client_secret"] = str(credentials.get("client_secret") or "")
        endpoint = "https://oauth2.googleapis.com/token"
    else:
        values["client_secret"] = _apple_client_secret(credentials, now=current)
        endpoint = "https://appleid.apple.com/auth/token"
    if not code or not all(values.values()):
        raise SocialIdentityError("invalid_identity_provider_response")
    result = _post_form(endpoint, values)
    identity_token = str(result.get("id_token") or "")
    if not identity_token:
        raise SocialIdentityError("invalid_identity_provider_response", 502)
    return identity_token


def validate_identity_token(
    provider: str,
    identity_token: str,
    credentials: Mapping[str, Any],
    *,
    expected_nonce: str,
    key_resolver: Callable[[str, str], Any],
    now: int | None = None,
) -> ProviderIdentity:
    canonical = canonical_provider(provider)
    current = int(time.time()) if now is None else int(now)
    try:
        header = jwt.get_unverified_header(identity_token)
        kid = str(header.get("kid") or "")
        if header.get("alg") != "RS256" or not kid:
            raise SocialIdentityError("invalid_identity_provider_token", 401)
        key = key_resolver(canonical, kid)
        claims = jwt.decode(
            identity_token,
            key,
            algorithms=["RS256"],
            audience=str(credentials.get("client_id") or ""),
            options={
                "require": ["sub", "iss", "aud", "iat", "exp", "nonce"],
                "verify_iss": False,
                # PyJWT validates against wall time.  We validate against the
                # injected/current time immediately below to keep tests and
                # clock-skew handling deterministic.
                "verify_exp": False,
                "verify_iat": False,
            },
        )
    except SocialIdentityError:
        raise
    except Exception as error:
        raise SocialIdentityError("invalid_identity_provider_token", 401) from error
    actual_issuer = str(claims.get("iss") or "")
    if canonical == "google" and actual_issuer not in GOOGLE_ISSUERS:
        raise SocialIdentityError("invalid_identity_provider_token", 401)
    if canonical == "apple" and not hmac.compare_digest(actual_issuer, APPLE_ISSUER):
        raise SocialIdentityError("invalid_identity_provider_token", 401)
    if not hmac.compare_digest(str(claims.get("nonce") or ""), expected_nonce):
        raise SocialIdentityError("identity_provider_nonce_mismatch", 401)
    issued_at = int(claims.get("iat") or 0)
    expires_at = int(claims.get("exp") or 0)
    if issued_at > current + 60 or expires_at < current:
        raise SocialIdentityError("invalid_identity_provider_token", 401)
    subject = str(claims.get("sub") or "").strip()
    if not subject or len(subject) > 256:
        raise SocialIdentityError("invalid_identity_provider_token", 401)
    email_present = bool(str(claims.get("email") or "").strip())
    verified_value = claims.get("email_verified")
    email_verified = verified_value is True or str(verified_value).lower() == "true"
    if email_present and not email_verified:
        raise SocialIdentityError("identity_provider_email_unverified", 403)
    return ProviderIdentity(canonical, subject, email_present, email_verified)


def resolve_signing_key(provider: str, kid: str):
    endpoint = (
        "https://www.googleapis.com/oauth2/v3/certs"
        if canonical_provider(provider) == "google"
        else "https://appleid.apple.com/auth/keys"
    )
    try:
        with urllib.request.urlopen(endpoint, timeout=10) as response:  # nosec B310 -- fixed provider URL
            document = json.loads(response.read(256 * 1024))
        for candidate in document.get("keys") or []:
            if hmac.compare_digest(str(candidate.get("kid") or ""), kid):
                return jwt.PyJWK.from_dict(candidate).key
    except Exception as error:
        raise SocialIdentityError("identity_provider_unavailable", 503) from error
    raise SocialIdentityError("invalid_identity_provider_token", 401)


def parse_cognito_identities(attributes: list[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    raw = next((str(value.get("Value") or "") for value in attributes if value.get("Name") == "identities"), "")
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except ValueError:
        return []
    return parsed if isinstance(parsed, list) else []


def identity_is_linked(attributes: list[Mapping[str, Any]], identity: ProviderIdentity) -> bool:
    expected_provider = provider_name(identity.provider)
    return any(
        hmac.compare_digest(str(item.get("providerName") or ""), expected_provider)
        and hmac.compare_digest(str(item.get("userId") or ""), identity.subject)
        for item in parse_cognito_identities(attributes)
    )


def resolve_cognito_username(cognito: Any, *, user_pool_id: str, subject: str) -> str:
    escaped = subject.replace("\\", "\\\\").replace('"', '\\"')
    result = cognito.list_users(UserPoolId=user_pool_id, Filter=f'sub = "{escaped}"', Limit=2)
    users = result.get("Users") or []
    if len(users) != 1:
        raise SocialIdentityError("existing_account_not_found", 409)
    return str(users[0].get("Username") or "")


def link_provider_identity(cognito: Any, *, user_pool_id: str, destination_subject: str, identity: ProviderIdentity) -> str:
    username = resolve_cognito_username(cognito, user_pool_id=user_pool_id, subject=destination_subject)
    existing = cognito.admin_get_user(UserPoolId=user_pool_id, Username=username)
    if identity_is_linked(existing.get("UserAttributes") or [], identity):
        return "already_linked"
    try:
        cognito.admin_link_provider_for_user(
            UserPoolId=user_pool_id,
            DestinationUser={
                "ProviderName": "Cognito",
                "ProviderAttributeValue": username,
            },
            SourceUser={
                "ProviderName": provider_name(identity.provider),
                "ProviderAttributeName": "Cognito_Subject",
                "ProviderAttributeValue": identity.subject,
            },
        )
    except Exception as error:
        # Resolve an ambiguous response by reading the destination. Never retry
        # the mutation blindly and never move a provider identity.
        current = cognito.admin_get_user(UserPoolId=user_pool_id, Username=username)
        if identity_is_linked(current.get("UserAttributes") or [], identity):
            return "linked"
        raise SocialIdentityError("identity_provider_link_conflict", 409) from error
    verified = cognito.admin_get_user(UserPoolId=user_pool_id, Username=username)
    if not identity_is_linked(verified.get("UserAttributes") or [], identity):
        raise SocialIdentityError("identity_provider_link_ambiguous", 503)
    return "linked"


def decode_form_body(body: str, *, is_base64: bool) -> Mapping[str, str]:
    try:
        raw = base64.b64decode(body).decode("utf-8") if is_base64 else body
    except Exception as error:
        raise SocialIdentityError("invalid_identity_provider_response") from error
    parsed = urllib.parse.parse_qs(raw, keep_blank_values=True, strict_parsing=False)
    return {key: values[-1] for key, values in parsed.items() if values}

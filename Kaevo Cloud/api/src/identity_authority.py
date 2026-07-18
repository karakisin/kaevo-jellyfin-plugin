"""Authoritative human-identity validation for Kaevo Cloud.

The Cognito subject is an opaque identifier.  All tenant, profile, role and
authorization-version claims are derived from server-owned DynamoDB records.
"""

from __future__ import annotations

import hmac
import re
import time
from dataclasses import dataclass
from typing import Any, Mapping


IDENTITY_SCHEMA_VERSION = 1
HUMAN_ROLES = frozenset({"owner", "adult", "child"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class AuthorityError(Exception):
    """A deliberately non-sensitive, fail-closed authority error."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _same(left: Any, right: Any) -> bool:
    return hmac.compare_digest(str(left or ""), str(right or ""))


def require_identifier(value: Any, name: str, *, opaque: bool = False) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 128 or any(ord(character) < 32 for character in text):
        raise AuthorityError(f"invalid_{name}")
    if not opaque and not _IDENTIFIER.fullmatch(text):
        raise AuthorityError(f"invalid_{name}")
    return text


def require_positive_integer(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise AuthorityError(f"invalid_{name}")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise AuthorityError(f"invalid_{name}") from error
    if parsed < 1 or str(value).strip() not in {str(parsed), f"{parsed}.0"}:
        raise AuthorityError(f"invalid_{name}")
    return parsed


def require_active(record: Mapping[str, Any] | None, record_name: str) -> Mapping[str, Any]:
    if not isinstance(record, Mapping):
        raise AuthorityError(f"missing_{record_name}")
    revoked = record.get("revoked")
    if revoked not in (None, False, 0, "false", "False") or str(record.get("state") or "") != "active":
        raise AuthorityError(f"inactive_{record_name}")
    return record


@dataclass(frozen=True)
class AuthoritativeClaims:
    account_id: str
    household_id: str
    profile_id: str
    role: str
    authz_version: int
    identity_schema_version: int = IDENTITY_SCHEMA_VERSION

    def as_token_claims(self) -> dict[str, str]:
        return {
            "account_id": self.account_id,
            "household_id": self.household_id,
            "profile_id": self.profile_id,
            "role": self.role,
            "authz_version": str(self.authz_version),
            "identity_schema_version": str(self.identity_schema_version),
        }


def derive_authoritative_claims(
    subject: Any,
    principal: Mapping[str, Any] | None,
    membership: Mapping[str, Any] | None,
    household: Mapping[str, Any] | None,
    profile: Mapping[str, Any] | None,
) -> AuthoritativeClaims:
    """Validate the complete identity graph before issuing any Kaevo claim."""
    subject_id = require_identifier(subject, "subject", opaque=True)
    principal = require_active(principal, "principal")
    membership = require_active(membership, "membership")
    household = require_active(household, "household")
    profile = require_active(profile, "profile")

    account_id = require_identifier(principal.get("account_id"), "account_id")
    household_id = require_identifier(principal.get("household_id"), "household_id")
    profile_id = require_identifier(membership.get("profile_id"), "profile_id")
    role = str(principal.get("role") or "")
    if role not in HUMAN_ROLES:
        raise AuthorityError("unsupported_human_role")
    authz_version = require_positive_integer(principal.get("authz_version"), "authz_version")

    profile_ids = principal.get("profile_ids")
    if not isinstance(profile_ids, list) or not profile_ids:
        raise AuthorityError("invalid_profile_membership")
    normalized_profiles = [require_identifier(item, "profile_id") for item in profile_ids]
    if len(normalized_profiles) != len(set(normalized_profiles)) or profile_id not in normalized_profiles:
        raise AuthorityError("invalid_profile_membership")

    expected = {
        "principal_id": subject_id,
        "account_id": account_id,
        "household_id": household_id,
        "profile_id": profile_id,
        "role": role,
    }
    for record, keys in (
        (principal, ("principal_id", "account_id", "household_id", "role")),
        (membership, tuple(expected)),
        (profile, ("profile_id", "account_id", "household_id")),
        (household, ("account_id", "household_id")),
    ):
        for key in keys:
            if not _same(record.get(key), expected[key]):
                raise AuthorityError("identity_relationship_mismatch")

    if role == "owner":
        if not _same(household.get("owner_principal_id"), subject_id):
            raise AuthorityError("identity_relationship_mismatch")
        if not _same(profile.get("owner_principal_id"), subject_id):
            raise AuthorityError("identity_relationship_mismatch")
    elif _same(household.get("owner_principal_id"), subject_id):
        raise AuthorityError("identity_relationship_mismatch")

    membership_version = require_positive_integer(membership.get("authz_version"), "authz_version")
    if membership_version != authz_version:
        raise AuthorityError("identity_relationship_mismatch")
    return AuthoritativeClaims(account_id, household_id, profile_id, role, authz_version)


def validate_access_token_claims(
    claims: Mapping[str, Any],
    *,
    expected_issuer: str,
    expected_client_id: str,
    now: int | None = None,
) -> dict[str, Any]:
    """Validate standard claims after API Gateway has verified the JWT."""
    if not isinstance(claims, Mapping):
        raise AuthorityError("invalid_access_token")
    subject = require_identifier(claims.get("sub"), "subject", opaque=True)
    issuer = str(claims.get("iss") or "")
    client_id = str(claims.get("client_id") or "")
    token_use = str(claims.get("token_use") or "")
    if not expected_issuer or not _same(issuer, expected_issuer):
        raise AuthorityError("invalid_access_token")
    if not expected_client_id or not _same(client_id, expected_client_id):
        raise AuthorityError("invalid_access_token")
    # This is the OAuth token-type discriminator, not a password or credential.
    if token_use != "access":  # nosec B105
        raise AuthorityError("invalid_access_token")
    current = int(time.time()) if now is None else int(now)
    try:
        expires_at = int(claims.get("exp"))
        issued_at = int(claims.get("iat"))
        authenticated_at = int(claims.get("auth_time"))
    except (TypeError, ValueError) as error:
        raise AuthorityError("invalid_access_token") from error
    if expires_at <= current or issued_at > current + 60 or authenticated_at > issued_at + 60:
        raise AuthorityError("invalid_access_token")
    return {
        "sub": subject,
        "iss": issuer,
        "client_id": client_id,
        "token_use": token_use,
        "exp": expires_at,
        "iat": issued_at,
        "auth_time": authenticated_at,
    }

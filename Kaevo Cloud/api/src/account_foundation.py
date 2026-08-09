"""Account Foundation primitives for Kaevo Cloud identity APIs.

This module is deliberately additive.  It defines the canonical household
roles used by new identity surfaces and the normalized Account/AuthIdentity
records without changing legacy media, pairing, or protected-session policy.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from identity_authority import AuthorityError, AuthoritativeClaims, derive_authoritative_claims


ACCOUNT_SCHEMA_VERSION = 1
AUTH_IDENTITY_SCHEMA_VERSION = 1
IDENTITY_CONTEXT_SCHEMA_VERSION = 1
_PROVIDER = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


class AccountFoundationError(Exception):
    """A fail-closed error that is safe to convert into a public state."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ExistingAccountBackfillPlan:
    """The server-derived, additive work required for one legacy identity."""

    claims: AuthoritativeClaims
    role: "CanonicalRole"
    account_record: dict[str, Any] | None
    auth_identity_record: dict[str, Any] | None

    @property
    def is_already_migrated(self) -> bool:
        return self.account_record is None and self.auth_identity_record is None


class CanonicalRole(str, Enum):
    OWNER = "owner"
    ADULT = "adult"
    TEEN = "teen"
    CHILD = "child"


class HouseholdAccessRole(str, Enum):
    """Server-owned authority inside a household.

    This is intentionally separate from ``CanonicalRole``.  Adult/teen/child
    describes the person; Owner/Admin/Member describes what that person may
    administer for the household.
    """

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


class Capability(str, Enum):
    HOUSEHOLD_MANAGE = "household.manage"
    HOUSEHOLD_INVITE = "household.invite"
    HOUSEHOLD_REMOVE_MEMBER = "household.remove_member"
    BILLING_MANAGE = "billing.manage"
    PROFILE_MANAGE_SELF = "profile.manage_self"
    PROFILE_MANAGE_CHILD = "profile.manage_child"
    PROFILE_SWITCH = "profile.switch"
    RECOMMENDATION_SEND = "recommendation.send"
    RECOMMENDATION_SEND_TO_CHILD = "recommendation.send_to_child"
    DEVICE_MANAGE_SELF = "device.manage_self"
    CLOUD_SYNC_MANAGE_SELF = "cloud_sync.manage_self"
    PROFILE_MANAGE_HOUSEHOLD = "profile.manage_household"
    PROFILE_DELETE_HOUSEHOLD = "profile.delete_household"
    PROFILE_SWITCH_GRANT = "profile.switch_grant"
    MEDIA_SERVICES_MANAGE = "media_services.manage"
    REQUESTS_VIEW_HOUSEHOLD = "requests.view_household"
    DOWNLOADS_VIEW_HOUSEHOLD = "downloads.view_household"
    STREAMS_VIEW_HOUSEHOLD = "streams.view_household"
    HOUSEHOLD_TRANSFER_OWNERSHIP = "household.transfer_ownership"


# The only role-to-capability authority for Account Foundation.  New identity
# APIs consume this mapping rather than spread role-name comparisons through
# request handlers.
ROLE_CAPABILITIES: dict[CanonicalRole, frozenset[Capability]] = {
    CanonicalRole.OWNER: frozenset(Capability),
    CanonicalRole.ADULT: frozenset({
        Capability.PROFILE_MANAGE_SELF,
        Capability.PROFILE_SWITCH,
        Capability.RECOMMENDATION_SEND,
        Capability.RECOMMENDATION_SEND_TO_CHILD,
        Capability.DEVICE_MANAGE_SELF,
        Capability.CLOUD_SYNC_MANAGE_SELF,
    }),
    CanonicalRole.TEEN: frozenset({
        Capability.PROFILE_MANAGE_SELF,
        Capability.RECOMMENDATION_SEND,
        Capability.DEVICE_MANAGE_SELF,
        Capability.CLOUD_SYNC_MANAGE_SELF,
    }),
    CanonicalRole.CHILD: frozenset({Capability.PROFILE_MANAGE_SELF}),
}

ACCESS_ROLE_CAPABILITIES: dict[HouseholdAccessRole, frozenset[Capability]] = {
    HouseholdAccessRole.OWNER: frozenset({
        Capability.HOUSEHOLD_MANAGE,
        Capability.HOUSEHOLD_INVITE,
        Capability.HOUSEHOLD_REMOVE_MEMBER,
        Capability.BILLING_MANAGE,
        Capability.PROFILE_MANAGE_HOUSEHOLD,
        Capability.PROFILE_DELETE_HOUSEHOLD,
        Capability.PROFILE_SWITCH,
        Capability.PROFILE_SWITCH_GRANT,
        Capability.MEDIA_SERVICES_MANAGE,
        Capability.REQUESTS_VIEW_HOUSEHOLD,
        Capability.DOWNLOADS_VIEW_HOUSEHOLD,
        Capability.STREAMS_VIEW_HOUSEHOLD,
        Capability.HOUSEHOLD_TRANSFER_OWNERSHIP,
    }),
    HouseholdAccessRole.ADMIN: frozenset({
        Capability.HOUSEHOLD_INVITE,
        Capability.PROFILE_MANAGE_HOUSEHOLD,
        Capability.PROFILE_SWITCH,
        Capability.PROFILE_SWITCH_GRANT,
        Capability.MEDIA_SERVICES_MANAGE,
        Capability.STREAMS_VIEW_HOUSEHOLD,
    }),
    HouseholdAccessRole.MEMBER: frozenset(),
}


@dataclass(frozen=True)
class LegacyRoleResolution:
    source_role: str
    canonical_role: CanonicalRole | None
    requires_owner_resolution: bool


def resolve_legacy_role(value: Any) -> LegacyRoleResolution:
    """Resolve only unambiguous historical names.

    ``kid`` is the historical, unambiguous spelling of ``child``. ``admin``
    and ``member`` are iOS-local legacy labels with no safe,
    permanent Account Foundation equivalent.  A later, owner-confirmed
    migration must choose their canonical role; callers must not infer it.
    """
    source_role = str(value or "").strip().lower()
    direct = {
        "owner": CanonicalRole.OWNER,
        "adult": CanonicalRole.ADULT,
        "child": CanonicalRole.CHILD,
        "kid": CanonicalRole.CHILD,
        "teen": CanonicalRole.TEEN,
    }.get(source_role)
    if direct is not None:
        return LegacyRoleResolution(source_role, direct, False)
    if source_role in {"admin", "member"}:
        return LegacyRoleResolution(source_role, None, True)
    raise AccountFoundationError("unsupported_household_role")


def canonical_role(value: Any) -> CanonicalRole:
    resolution = resolve_legacy_role(value)
    if resolution.canonical_role is None:
        raise AccountFoundationError("legacy_role_requires_owner_resolution")
    return resolution.canonical_role


def capabilities_for(role: CanonicalRole) -> frozenset[str]:
    return frozenset(capability.value for capability in ROLE_CAPABILITIES[role])


def household_access_role(
    value: Any, *, canonical: CanonicalRole | None = None,
) -> HouseholdAccessRole:
    """Resolve household authority without inferring Admin.

    Existing owner records remain Owner.  Every other record that predates the
    additive field fails safely to Member.
    """

    if isinstance(value, HouseholdAccessRole):
        resolved = value
    else:
        text = str(value or "").strip().lower()
        if not text:
            resolved = (
                HouseholdAccessRole.OWNER
                if canonical is CanonicalRole.OWNER
                else HouseholdAccessRole.MEMBER
            )
        else:
            try:
                resolved = HouseholdAccessRole(text)
            except ValueError as error:
                raise AccountFoundationError("unsupported_household_access_role") from error
    if canonical is CanonicalRole.OWNER and resolved is not HouseholdAccessRole.OWNER:
        raise AccountFoundationError("owner_access_role_conflict")
    if canonical is not None and canonical is not CanonicalRole.OWNER and resolved is HouseholdAccessRole.OWNER:
        raise AccountFoundationError("owner_access_role_conflict")
    return resolved


def household_capabilities_for(
    role: CanonicalRole, access_role: HouseholdAccessRole,
) -> frozenset[str]:
    """Return self capabilities plus server-owned household authority.

    ``profile.switch`` is household authority, so the legacy adult grant is
    removed unless Owner/Admin authority explicitly restores it.
    """

    values = set(capabilities_for(role))
    values.discard(Capability.PROFILE_SWITCH.value)
    values.update(capability.value for capability in ACCESS_ROLE_CAPABILITIES[access_role])
    return frozenset(values)


def _identifier(value: Any, name: str, *, maximum: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or any(ord(character) < 32 for character in text):
        raise AccountFoundationError(f"invalid_{name}")
    return text


def normalized_provider(value: Any) -> str:
    provider = _identifier(value, "provider", maximum=32).lower()
    if not _PROVIDER.fullmatch(provider):
        raise AccountFoundationError("invalid_provider")
    return provider


def provider_subject_key(provider: Any, provider_subject: Any) -> str:
    """Return the globally unique, non-reversible DynamoDB key.

    Provider subjects are intentionally never returned by Account Foundation
    APIs.  Hashing the opaque provider/subject tuple gives a stable unique key
    without retaining it as an application-visible attribute.
    """
    canonical_provider = normalized_provider(provider)
    subject = _identifier(provider_subject, "provider_subject", maximum=512)
    digest = hashlib.sha256(f"{canonical_provider}\x00{subject}".encode("utf-8")).hexdigest()
    return f"v{AUTH_IDENTITY_SCHEMA_VERSION}#{canonical_provider}#{digest}"


def normalized_email(value: Any) -> str | None:
    if value is None:
        return None
    email = str(value).strip().lower()
    if not email:
        return None
    if len(email) > 320 or "@" not in email or any(ord(character) < 32 for character in email):
        raise AccountFoundationError("invalid_email")
    return email


def build_account_record(account_id: Any, *, now_iso: str, now_epoch: int) -> dict[str, Any]:
    return {
        "account_id": _identifier(account_id, "account_id"),
        "entity_type": "Account",
        "status": "active",
        "schema_version": ACCOUNT_SCHEMA_VERSION,
        "created_at": now_iso,
        "updated_at": now_iso,
        "created_at_epoch": int(now_epoch),
    }


def build_auth_identity_record(
    *,
    account_id: Any,
    provider: Any,
    provider_subject: Any,
    now_iso: str,
    now_epoch: int,
    email: Any = None,
    email_verified: bool = False,
) -> dict[str, Any]:
    canonical_provider = normalized_provider(provider)
    record = {
        "auth_identity_key": provider_subject_key(canonical_provider, provider_subject),
        "entity_type": "AuthIdentity",
        "account_id": _identifier(account_id, "account_id"),
        "provider": canonical_provider,
        "status": "active",
        "schema_version": AUTH_IDENTITY_SCHEMA_VERSION,
        "email_verified": bool(email_verified),
        "created_at": now_iso,
        "updated_at": now_iso,
        "created_at_epoch": int(now_epoch),
    }
    if (email_value := normalized_email(email)) is not None:
        record["normalized_email"] = email_value
    return record


def assert_auth_identity_binding(
    record: Mapping[str, Any] | None,
    *,
    account_id: Any,
    provider: Any,
    provider_subject: Any,
) -> Mapping[str, Any]:
    if not isinstance(record, Mapping):
        raise AccountFoundationError("auth_identity_binding_required")
    expected = {
        "auth_identity_key": provider_subject_key(provider, provider_subject),
        "account_id": _identifier(account_id, "account_id"),
        "provider": normalized_provider(provider),
    }
    if any(str(record.get(key) or "") != value for key, value in expected.items()):
        raise AccountFoundationError("auth_identity_binding_conflict")
    if record.get("entity_type") != "AuthIdentity" or record.get("status") != "active":
        raise AccountFoundationError("auth_identity_inactive")
    if int(record.get("schema_version") or 0) != AUTH_IDENTITY_SCHEMA_VERSION:
        raise AccountFoundationError("unsupported_auth_identity_schema")
    return record


def public_auth_identity(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return only account-safe metadata; never a provider subject or token."""
    result = {
        "provider": str(record.get("provider") or ""),
        "email_verified": bool(record.get("email_verified")),
        "status": str(record.get("status") or ""),
    }
    if isinstance(record.get("normalized_email"), str):
        result["email"] = record["normalized_email"]
    return result


def plan_existing_account_backfill(
    *,
    subject: Any,
    principal: Mapping[str, Any] | None,
    membership: Mapping[str, Any] | None,
    household: Mapping[str, Any] | None,
    profile: Mapping[str, Any] | None,
    existing_account: Mapping[str, Any] | None,
    existing_auth_identity: Mapping[str, Any] | None,
    now_iso: str,
    now_epoch: int,
) -> ExistingAccountBackfillPlan:
    """Return the only safe additive backfill for an authority graph.

    The existing principal's server-owned ``account_id`` is retained as the
    durable Account identifier.  This avoids a second account namespace and
    makes the operation idempotent without consulting email or local profiles.
    """
    # Resolve historical iOS-only labels before the legacy authority validator
    # rejects them generically, so the migration can explicitly stop for an
    # owner-confirmed decision instead of treating them as absent records.
    if isinstance(principal, Mapping):
        legacy_role = resolve_legacy_role(principal.get("role"))
        if legacy_role.requires_owner_resolution:
            raise AccountFoundationError("manual_review_required")
    try:
        claims = derive_authoritative_claims(subject, principal, membership, household, profile)
    except AuthorityError as error:
        raise AccountFoundationError("authority_record_missing") from error
    role = canonical_role(claims.role)

    account_record: dict[str, Any] | None = None
    if existing_account is None:
        account_record = build_account_record(claims.account_id, now_iso=now_iso, now_epoch=now_epoch)
    elif (
        existing_account.get("account_id") != claims.account_id
        or existing_account.get("entity_type") != "Account"
        or existing_account.get("status") != "active"
        or int(existing_account.get("schema_version") or 0) != ACCOUNT_SCHEMA_VERSION
    ):
        raise AccountFoundationError("manual_review_required")

    auth_identity_record: dict[str, Any] | None = None
    if existing_auth_identity is None:
        auth_identity_record = build_auth_identity_record(
            account_id=claims.account_id,
            provider="cognito",
            provider_subject=subject,
            now_iso=now_iso,
            now_epoch=now_epoch,
        )
    else:
        try:
            assert_auth_identity_binding(
                existing_auth_identity,
                account_id=claims.account_id,
                provider="cognito",
                provider_subject=subject,
            )
        except AccountFoundationError as error:
            if error.reason == "auth_identity_binding_conflict":
                raise AccountFoundationError("provider_identity_conflict") from error
            raise AccountFoundationError("manual_review_required") from error

    return ExistingAccountBackfillPlan(
        claims=claims,
        role=role,
        account_record=account_record,
        auth_identity_record=auth_identity_record,
    )

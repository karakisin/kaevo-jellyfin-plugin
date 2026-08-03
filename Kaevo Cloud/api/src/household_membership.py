"""Additive normalized HouseholdMembership primitives for Kaevo Cloud.

Legacy principal/membership/household/profile records remain the authority
source during migration.  This module creates only a normalized projection of
that authority and deliberately has no client-input based resolution path.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from account_foundation import (
    AccountFoundationError,
    CanonicalRole,
    HouseholdAccessRole,
    canonical_role,
    household_access_role,
    household_capabilities_for,
    resolve_legacy_role,
)
from identity_authority import AuthorityError, AuthoritativeClaims, derive_authoritative_claims


HOUSEHOLD_MEMBERSHIP_SCHEMA_VERSION = 1
PROFILE_ACCESS_POLICY_REF = "profile-binding-required-v1"


@dataclass(frozen=True)
class HouseholdMembershipPlan:
    """Server-derived, transaction-safe projection for one account-household."""

    claims: AuthoritativeClaims
    role: CanonicalRole
    membership_id: str
    membership_record: dict[str, Any] | None
    uniqueness_guard_record: dict[str, Any] | None
    owner_guard_record: dict[str, Any] | None

    @property
    def is_already_normalized(self) -> bool:
        return (
            self.membership_record is None
            and self.uniqueness_guard_record is None
            and self.owner_guard_record is None
        )


def _identifier(value: Any, name: str) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 256 or any(ord(character) < 32 for character in text):
        raise AccountFoundationError(f"invalid_{name}")
    return text


def _key(prefix: str, *parts: Any) -> str:
    source = "\x00".join(_identifier(part, "membership_key_part") for part in parts)
    return f"{prefix}#{hashlib.sha256(source.encode('utf-8')).hexdigest()}"


def household_membership_id(account_id: Any, household_id: Any) -> str:
    """Stable membership identity for exactly one account-household pair."""
    return _key("hm1", account_id, household_id)


def account_household_guard_id(account_id: Any, household_id: Any) -> str:
    return _key("ahu1", account_id, household_id)


def household_owner_guard_id(household_id: Any) -> str:
    return _key("hog1", household_id)


def _assert_unambiguous_household(principal: Mapping[str, Any], claims: AuthoritativeClaims) -> None:
    """Reject optional legacy multi-household hints rather than choosing one."""
    household_ids = principal.get("household_ids")
    if household_ids is None:
        return
    if not isinstance(household_ids, list):
        raise AccountFoundationError("household_authority_ambiguous")
    normalized = {_identifier(value, "household_id") for value in household_ids}
    if normalized != {claims.household_id}:
        raise AccountFoundationError("household_authority_ambiguous")


def _validate_membership(
    record: Mapping[str, Any], *, claims: AuthoritativeClaims, role: CanonicalRole, membership_id: str,
) -> None:
    expected = {
        "entity_type": "HouseholdMembership",
        "membership_id": membership_id,
        "account_id": claims.account_id,
        "household_id": claims.household_id,
        "canonical_role": role.value,
        "schema_version": HOUSEHOLD_MEMBERSHIP_SCHEMA_VERSION,
    }
    if any(record.get(key) != value for key, value in expected.items()):
        raise AccountFoundationError("membership_conflict")
    if record.get("status") != "active":
        # An inactive record is historical state, not a request to reactivate.
        raise AccountFoundationError("membership_migration_not_required")
    household_access_role(record.get("household_access_role"), canonical=role)


def _validate_guard(
    record: Mapping[str, Any], *, household_id: str, guard_id: str, entity_type: str,
    membership_id: str, account_id: str | None = None,
) -> None:
    expected = {
        "entity_type": entity_type,
        "household_id": household_id,
        "membership_id": guard_id,
        "normalized_membership_id": membership_id,
        "status": "active",
        "schema_version": HOUSEHOLD_MEMBERSHIP_SCHEMA_VERSION,
    }
    if account_id is not None:
        expected["account_id"] = account_id
    if any(record.get(key) != value for key, value in expected.items()):
        raise AccountFoundationError("membership_conflict")


def build_household_membership_record(
    claims: AuthoritativeClaims, role: CanonicalRole, *, now_iso: str, now_epoch: int,
    access_role: HouseholdAccessRole | None = None,
) -> dict[str, Any]:
    membership_id = household_membership_id(claims.account_id, claims.household_id)
    resolved_access_role = household_access_role(access_role, canonical=role)
    return {
        "household_id": claims.household_id,
        "membership_id": membership_id,
        "entity_type": "HouseholdMembership",
        "account_id": claims.account_id,
        "canonical_role": role.value,
        "household_access_role": resolved_access_role.value,
        "status": "active",
        "joined_at": now_iso,
        "updated_at": now_iso,
        "updated_at_epoch": int(now_epoch),
        "schema_version": HOUSEHOLD_MEMBERSHIP_SCHEMA_VERSION,
        "migration_provenance": "legacy-authority-graph-v1",
        # No profile mapping is claimed until a later server-authorized binding.
        "profile_access_policy_ref": PROFILE_ACCESS_POLICY_REF,
    }


def _build_guard(
    *, household_id: str, guard_id: str, entity_type: str, membership_id: str,
    account_id: str | None, now_iso: str, now_epoch: int,
) -> dict[str, Any]:
    record = {
        "household_id": household_id,
        "membership_id": guard_id,
        "entity_type": entity_type,
        "normalized_membership_id": membership_id,
        "status": "active",
        "updated_at": now_iso,
        "updated_at_epoch": int(now_epoch),
        "schema_version": HOUSEHOLD_MEMBERSHIP_SCHEMA_VERSION,
    }
    if account_id is not None:
        record["account_id"] = account_id
    return record


def build_account_household_guard(
    claims: AuthoritativeClaims, *, membership_id: str, now_iso: str, now_epoch: int,
) -> dict[str, Any]:
    return _build_guard(
        household_id=claims.household_id,
        guard_id=account_household_guard_id(claims.account_id, claims.household_id),
        entity_type="HouseholdMembershipAccountGuard",
        membership_id=membership_id,
        account_id=claims.account_id,
        now_iso=now_iso,
        now_epoch=now_epoch,
    )


def build_household_owner_guard(
    claims: AuthoritativeClaims, *, membership_id: str, now_iso: str, now_epoch: int,
) -> dict[str, Any]:
    return _build_guard(
        household_id=claims.household_id,
        guard_id=household_owner_guard_id(claims.household_id),
        entity_type="HouseholdMembershipOwnerGuard",
        membership_id=membership_id,
        account_id=claims.account_id,
        now_iso=now_iso,
        now_epoch=now_epoch,
    )


def resolve_household_membership(
    *, subject: Any, principal: Mapping[str, Any] | None, legacy_membership: Mapping[str, Any] | None,
    household: Mapping[str, Any] | None, profile: Mapping[str, Any] | None,
    normalized_membership: Mapping[str, Any] | None,
) -> tuple[AuthoritativeClaims, CanonicalRole, Mapping[str, Any]]:
    """Resolve normalized membership only after validating the legacy graph."""
    if isinstance(principal, Mapping):
        legacy = resolve_legacy_role(principal.get("role"))
        if legacy.requires_owner_resolution:
            raise AccountFoundationError("legacy_role_unresolved")
    try:
        claims = derive_authoritative_claims(subject, principal, legacy_membership, household, profile)
    except AuthorityError as error:
        raise AccountFoundationError("household_authority_missing") from error
    if not isinstance(principal, Mapping):
        raise AccountFoundationError("household_authority_missing")
    _assert_unambiguous_household(principal, claims)
    role = canonical_role(claims.role)
    if not isinstance(normalized_membership, Mapping):
        raise AccountFoundationError("household_membership_migration_required")
    _validate_membership(
        normalized_membership,
        claims=claims,
        role=role,
        membership_id=household_membership_id(claims.account_id, claims.household_id),
    )
    return claims, role, normalized_membership


def plan_household_membership_normalization(
    *, subject: Any, principal: Mapping[str, Any] | None, legacy_membership: Mapping[str, Any] | None,
    household: Mapping[str, Any] | None, profile: Mapping[str, Any] | None,
    existing_membership: Mapping[str, Any] | None, existing_account_guard: Mapping[str, Any] | None,
    existing_owner_guard: Mapping[str, Any] | None, now_iso: str, now_epoch: int,
) -> HouseholdMembershipPlan:
    """Plan the only safe additive membership normalization for one session."""
    if isinstance(principal, Mapping):
        legacy = resolve_legacy_role(principal.get("role"))
        if legacy.requires_owner_resolution:
            raise AccountFoundationError("legacy_role_unresolved")
    try:
        claims = derive_authoritative_claims(subject, principal, legacy_membership, household, profile)
    except AuthorityError as error:
        raise AccountFoundationError("household_authority_missing") from error
    if not isinstance(principal, Mapping):
        raise AccountFoundationError("household_authority_missing")
    _assert_unambiguous_household(principal, claims)
    role = canonical_role(claims.role)
    membership_id = household_membership_id(claims.account_id, claims.household_id)

    membership_record = None
    if existing_membership is not None:
        _validate_membership(existing_membership, claims=claims, role=role, membership_id=membership_id)
    else:
        membership_record = build_household_membership_record(claims, role, now_iso=now_iso, now_epoch=now_epoch)

    account_guard_id = account_household_guard_id(claims.account_id, claims.household_id)
    uniqueness_guard_record = None
    if existing_account_guard is not None:
        _validate_guard(
            existing_account_guard, household_id=claims.household_id, guard_id=account_guard_id,
            entity_type="HouseholdMembershipAccountGuard", membership_id=membership_id,
            account_id=claims.account_id,
        )
        if existing_membership is None:
            raise AccountFoundationError("membership_conflict")
    elif existing_membership is not None:
        raise AccountFoundationError("membership_conflict")
    else:
        uniqueness_guard_record = build_account_household_guard(
            claims, membership_id=membership_id, now_iso=now_iso, now_epoch=now_epoch,
        )

    owner_guard_record = None
    if role is CanonicalRole.OWNER:
        owner_guard_id = household_owner_guard_id(claims.household_id)
        if existing_owner_guard is not None:
            try:
                _validate_guard(
                    existing_owner_guard, household_id=claims.household_id, guard_id=owner_guard_id,
                    entity_type="HouseholdMembershipOwnerGuard", membership_id=membership_id,
                    account_id=claims.account_id,
                )
            except AccountFoundationError as error:
                if isinstance(existing_owner_guard, Mapping) and existing_owner_guard.get("entity_type") == "HouseholdMembershipOwnerGuard":
                    raise AccountFoundationError("ownership_conflict") from error
                raise
            if existing_membership is None:
                raise AccountFoundationError("membership_conflict")
        elif existing_membership is not None:
            raise AccountFoundationError("membership_conflict")
        else:
            owner_guard_record = build_household_owner_guard(
                claims, membership_id=membership_id, now_iso=now_iso, now_epoch=now_epoch,
            )

    return HouseholdMembershipPlan(
        claims=claims,
        role=role,
        membership_id=membership_id,
        membership_record=membership_record,
        uniqueness_guard_record=uniqueness_guard_record,
        owner_guard_record=owner_guard_record,
    )


def public_membership_context(
    claims: AuthoritativeClaims, role: CanonicalRole, membership: Mapping[str, Any], *,
    profile_access: list[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    access_role = household_access_role(membership.get("household_access_role"), canonical=role)
    # Profile switching is meaningful only with two explicit active bindings.
    capabilities = household_capabilities_for(role, access_role)
    switchable = [
        item for item in (profile_access or [])
        if item.get("access_level") in {"switch", "manage"}
    ]
    if len(switchable) < 2:
        capabilities = frozenset(value for value in capabilities if value != "profile.switch")
    return {
        "membership_id": str(membership.get("membership_id") or ""),
        "household_id": claims.household_id,
        "role": access_role.value,
        "canonical_role": role.value,
        "capabilities": sorted(capabilities),
        "status": "active",
    }

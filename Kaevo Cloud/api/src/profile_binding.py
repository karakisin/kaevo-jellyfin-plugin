"""Authoritative Cloud Profile and ProfileBinding records.

The module never reads local profile data.  It validates explicit Cloud
records, keeps identifiers server-issued/deterministic as appropriate, and
provides the single profile-access resolver used by identity surfaces.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from account_foundation import AccountFoundationError


PROFILE_SCHEMA_VERSION = 1
PROFILE_BINDING_SCHEMA_VERSION = 1
PROFILE_TYPES = frozenset({"adult", "teen", "child"})
AGE_CLASSIFICATIONS = frozenset({"adult", "teen", "child", "unresolved"})
ACCESS_LEVELS = frozenset({"view", "switch", "manage"})
_DISPLAY_NAME = re.compile(r"^[^\x00-\x1f]{1,80}$")


@dataclass(frozen=True)
class ProfileCreationPlan:
    profile: dict[str, Any]
    binding: dict[str, Any]


def _identifier(value: Any, name: str, maximum: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or any(ord(character) < 32 for character in text):
        raise AccountFoundationError(f"invalid_{name}")
    return text


def server_issued_profile_id() -> str:
    return f"prf1_{uuid.uuid4()}"


def profile_binding_id(account_id: Any, profile_id: Any) -> str:
    source = f"{_identifier(account_id, 'account_id')}\x00{_identifier(profile_id, 'profile_id')}"
    return "pbd1_" + hashlib.sha256(source.encode("utf-8")).hexdigest()


def _profile_type(value: Any) -> str:
    result = str(value or "").strip().lower()
    if result not in PROFILE_TYPES:
        raise AccountFoundationError("profile_type_required")
    return result


def _age_classification(value: Any, profile_type: str) -> str:
    result = str(value or "").strip().lower()
    if result not in AGE_CLASSIFICATIONS:
        raise AccountFoundationError("age_classification_required")
    if result == "unresolved" or result != profile_type:
        raise AccountFoundationError("profile_classification_unresolved")
    return result


def _display_name(value: Any) -> str:
    result = str(value or "").strip()
    if not _DISPLAY_NAME.fullmatch(result):
        raise AccountFoundationError("invalid_profile_display_name")
    return result


def _access_level(value: Any) -> str:
    result = str(value or "").strip().lower()
    if result not in ACCESS_LEVELS:
        raise AccountFoundationError("invalid_profile_access_level")
    return result


def build_profile_creation(
    *, household_id: Any, account_id: Any, display_name: Any, profile_type: Any,
    age_classification: Any, now_iso: str, now_epoch: int,
    reserved_profile_id: Any | None = None,
) -> ProfileCreationPlan:
    household = _identifier(household_id, "household_id")
    account = _identifier(account_id, "account_id")
    kind = _profile_type(profile_type)
    age = _age_classification(age_classification, kind)
    # Household invitations reserve the canonical profile identity before
    # provider accounts are bound.  Activation must reuse that exact identity
    # or the member's Jellyfin/Seerr bindings would remain attached to an
    # unreachable invitation placeholder.
    profile_id = (
        _identifier(reserved_profile_id, "profile_id")
        if reserved_profile_id is not None
        else server_issued_profile_id()
    )
    profile = {
        "profile_id": profile_id,
        "entity_type": "Profile",
        "household_id": household,
        "profile_type": kind,
        "display_name": _display_name(display_name),
        "age_classification": age,
        "status": "active",
        "created_at": now_iso,
        "updated_at": now_iso,
        "created_at_epoch": int(now_epoch),
        "updated_at_epoch": int(now_epoch),
        "schema_version": PROFILE_SCHEMA_VERSION,
        "source_provenance": "cloud-profile-creation-v1",
        "migration_state": "not_applicable",
        # Placeholder only; no PIN or biometric material is stored.
        "protection_policy_ref": "profile-protection-unconfigured-v1",
    }
    binding = build_profile_binding(
        account_id=account, profile=profile, access_level="manage", granted_by_account_id=account,
        now_iso=now_iso, now_epoch=now_epoch, provenance="profile-creation-v1",
    )
    return ProfileCreationPlan(profile=profile, binding=binding)


def build_profile_binding(
    *, account_id: Any, profile: Mapping[str, Any], access_level: Any,
    granted_by_account_id: Any, now_iso: str, now_epoch: int, provenance: str,
) -> dict[str, Any]:
    account = _identifier(account_id, "account_id")
    profile_id = _identifier(profile.get("profile_id"), "profile_id")
    household_id = _identifier(profile.get("household_id"), "household_id")
    return {
        "account_id": account,
        "profile_id": profile_id,
        "binding_id": profile_binding_id(account, profile_id),
        "entity_type": "ProfileBinding",
        "household_id": household_id,
        "access_level": _access_level(access_level),
        "status": "active",
        "granted_by_account_id": _identifier(granted_by_account_id, "granted_by_account_id"),
        "granted_at": now_iso,
        "updated_at": now_iso,
        "updated_at_epoch": int(now_epoch),
        "schema_version": PROFILE_BINDING_SCHEMA_VERSION,
        "migration_provenance": provenance,
    }


def validate_profile(profile: Mapping[str, Any] | None, *, household_id: Any | None = None) -> Mapping[str, Any]:
    if not isinstance(profile, Mapping) or profile.get("entity_type") != "Profile":
        raise AccountFoundationError("profile_not_found")
    if profile.get("status") != "active" or int(profile.get("schema_version") or 0) != PROFILE_SCHEMA_VERSION:
        raise AccountFoundationError("profile_inactive")
    profile_household = _identifier(profile.get("household_id"), "household_id")
    if household_id is not None and profile_household != _identifier(household_id, "household_id"):
        raise AccountFoundationError("cross_household_binding_rejected")
    kind = _profile_type(profile.get("profile_type"))
    _age_classification(profile.get("age_classification"), kind)
    _display_name(profile.get("display_name"))
    return profile


def validate_binding(
    binding: Mapping[str, Any], *, account_id: Any, profile: Mapping[str, Any], household_id: Any,
) -> Mapping[str, Any]:
    account = _identifier(account_id, "account_id")
    profile_id = _identifier(profile.get("profile_id"), "profile_id")
    household = _identifier(household_id, "household_id")
    expected = {
        "entity_type": "ProfileBinding",
        "account_id": account,
        "profile_id": profile_id,
        "binding_id": profile_binding_id(account, profile_id),
        "household_id": household,
        "schema_version": PROFILE_BINDING_SCHEMA_VERSION,
    }
    if any(binding.get(key) != value for key, value in expected.items()):
        raise AccountFoundationError("profile_binding_conflict")
    if binding.get("status") != "active":
        raise AccountFoundationError("profile_binding_not_reactivated")
    _access_level(binding.get("access_level"))
    return binding


def resolve_profile_access(
    *, account_id: Any, household_id: Any, bindings: Iterable[Mapping[str, Any]],
    profiles_by_id: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, str]]:
    """Return only active, same-household, explicit bindings for one account."""
    account = _identifier(account_id, "account_id")
    household = _identifier(household_id, "household_id")
    resolved: list[dict[str, str]] = []
    for binding in bindings:
        if not isinstance(binding, Mapping) or binding.get("status") != "active":
            continue
        profile_id = str(binding.get("profile_id") or "")
        profile = profiles_by_id.get(profile_id)
        try:
            validate_profile(profile, household_id=household)
            validate_binding(binding, account_id=account, profile=profile, household_id=household)
        except AccountFoundationError:
            continue
        resolved.append({
            "profile_id": profile_id,
            "profile_type": str(profile.get("profile_type") or ""),
            "display_name": str(profile.get("display_name") or ""),
            "access_level": str(binding.get("access_level") or ""),
            "status": "active",
        })
    return sorted(resolved, key=lambda item: item["profile_id"])

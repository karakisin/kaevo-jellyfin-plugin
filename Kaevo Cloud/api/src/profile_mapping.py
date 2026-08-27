"""Explicit installation-scoped local-to-Cloud Profile mapping records."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

from account_foundation import AccountFoundationError


PROFILE_MAPPING_SCHEMA_VERSION = 1
_SOURCE = re.compile(r"^lps1_[a-f0-9]{64}$")


def local_profile_source_id(value: Any) -> str:
    source = str(value or "").strip()
    if not _SOURCE.fullmatch(source):
        raise AccountFoundationError("invalid_local_profile_source")
    return source


def mapping_id(installation_id: Any, source_id: Any) -> str:
    installation = str(installation_id or "").strip()
    source = local_profile_source_id(source_id)
    if not installation:
        raise AccountFoundationError("invalid_installation_id")
    return "pmp1_" + hashlib.sha256(f"{installation}\x00{source}".encode("utf-8")).hexdigest()


def mapping_guard_source_id(cloud_profile_id: Any) -> str:
    """Return the reserved per-installation uniqueness key for a Cloud Profile.

    The guard shares the mapping table's partition so DynamoDB can conditionally
    claim one local source for a Cloud Profile in the same transaction as the
    mapping write. Its sort key deliberately remains in the table's validated
    opaque-source namespace; callers distinguish it by ``entity_type`` and it
    can never be inferred from a display name or email address.
    """
    profile = str(cloud_profile_id or "").strip()
    if not profile:
        raise AccountFoundationError("invalid_cloud_profile_id")
    digest = hashlib.sha256(f"cloud-profile-guard-v1\x00{profile}".encode("utf-8")).hexdigest()
    return f"lps1_{digest}"


def build_mapping_guard(
    *, installation_id: Any, account_id: Any, household_id: Any,
    cloud_profile_id: Any, local_source_id: Any, now_iso: str, now_epoch: int,
) -> dict[str, Any]:
    installation = str(installation_id or "").strip()
    account = str(account_id or "").strip()
    household = str(household_id or "").strip()
    profile = str(cloud_profile_id or "").strip()
    source = local_profile_source_id(local_source_id)
    guard_source = mapping_guard_source_id(profile)
    if not all((installation, account, household)):
        raise AccountFoundationError("invalid_mapping_context")
    return {
        "installation_id": installation,
        "local_profile_source_id": guard_source,
        "mapping_id": "pmg1_" + hashlib.sha256(
            f"{installation}\x00{profile}".encode("utf-8")
        ).hexdigest(),
        "entity_type": "LocalProfileMappingGuard",
        "account_id": account,
        "household_id": household,
        "cloud_profile_id": profile,
        "current_local_profile_source_id": source,
        "mapping_state": "active",
        "created_at": now_iso,
        "updated_at": now_iso,
        "updated_at_epoch": int(now_epoch),
        "schema_version": PROFILE_MAPPING_SCHEMA_VERSION,
    }


def build_confirmed_mapping(
    *, installation_id: Any, local_source_id: Any, account_id: Any, household_id: Any,
    cloud_profile_id: Any, now_iso: str, now_epoch: int,
) -> dict[str, Any]:
    installation = str(installation_id or "").strip()
    source = local_profile_source_id(local_source_id)
    account = str(account_id or "").strip()
    household = str(household_id or "").strip()
    profile = str(cloud_profile_id or "").strip()
    if not all((installation, account, household, profile)):
        raise AccountFoundationError("invalid_mapping_context")
    return {
        "installation_id": installation,
        "local_profile_source_id": source,
        "mapping_id": mapping_id(installation, source),
        "entity_type": "LocalProfileMapping",
        "account_id": account,
        "household_id": household,
        "cloud_profile_id": profile,
        "mapping_state": "confirmed",
        "confirmation_method": "explicit_user_confirmation_v1",
        "confirmed_by_account_id": account,
        "created_at": now_iso,
        "updated_at": now_iso,
        "updated_at_epoch": int(now_epoch),
        "schema_version": PROFILE_MAPPING_SCHEMA_VERSION,
    }


def validate_confirmed_mapping(
    record: Mapping[str, Any], *, installation_id: str, source_id: str,
    account_id: str, household_id: str,
) -> Mapping[str, Any]:
    expected = {
        "installation_id": installation_id,
        "local_profile_source_id": source_id,
        "mapping_id": mapping_id(installation_id, source_id),
        "entity_type": "LocalProfileMapping",
        "account_id": account_id,
        "household_id": household_id,
        "mapping_state": "confirmed",
        "schema_version": PROFILE_MAPPING_SCHEMA_VERSION,
    }
    if any(record.get(key) != value for key, value in expected.items()):
        raise AccountFoundationError("mapping_conflict")
    return record


def public_mapping(record: Mapping[str, Any], *, usable_profile_ids: set[str]) -> dict[str, str]:
    cloud_profile_id = str(record.get("cloud_profile_id") or "")
    state = "confirmed" if cloud_profile_id in usable_profile_ids else "unresolved"
    return {
        "mapping_id": str(record.get("mapping_id") or ""),
        "local_profile_source_id": str(record.get("local_profile_source_id") or ""),
        "cloud_profile_id": cloud_profile_id,
        "mapping_state": state,
    }

"""Pure Account Lifecycle V2 authority and deletion-plan contract.

This module deliberately imports no V1 handler, identity projection, profile
mapping, or account-deletion planner. Persistence and provider executors are
adapters around this contract, never alternative sources of ownership.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = 2
_ACCOUNT_ID = re.compile(r"^acct_[A-Za-z0-9_-]{16,96}$")
_OPERATION_ID = re.compile(r"^ald2_[A-Za-z0-9_-]{24,96}$")


class LifecycleV2Error(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class DeletionScope(str, Enum):
    KAEVO_ONLY = "kaevo_only"
    EVERYTHING = "everything"


class ProviderCapability(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


class OperationPhase(str, Enum):
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    QUEUED = "queued"
    DELETING_SEERR = "deleting_seerr"
    VERIFYING_SEERR_ABSENCE = "verifying_seerr_absence"
    DELETING_JELLYFIN = "deleting_jellyfin"
    VERIFYING_JELLYFIN_ABSENCE = "verifying_jellyfin_absence"
    DELETING_COGNITO = "deleting_cognito"
    VERIFYING_COGNITO_ABSENCE = "verifying_cognito_absence"
    DELETING_KAEVO_GRAPH = "deleting_kaevo_graph"
    VERIFYING_KAEVO_ABSENCE = "verifying_kaevo_absence"
    COMPLETED = "completed"
    RETRY_REQUIRED = "retry_required"


RESOURCE_TYPES = frozenset({
    "account",
    "auth_identity",
    "cognito_subject",
    "principal",
    "identity_membership",
    "household",
    "household_membership",
    "household_membership_guard",
    "identity_profile",
    "cloud_profile",
    "profile_binding",
    "installation",
    "app_session_family",
    "app_session_access",
    "app_session_refresh",
    "profile_mapping",
    "provider_binding",
    "owner_lifecycle_guard",
})

FORBIDDEN_AUTHORITY_FIELDS = frozenset({
    "display_name", "email", "avatar", "local_profile_id", "profile_name",
})

ALLOWED_RESOURCE_ATTRIBUTES = frozenset({
    "household_id",
    "profile_id",
    "two_way_profile_deletion",
    "connector_id",
    "jellyfin_user_id",
    "seerr_user_id",
    "owner_account_id",
    "installation_id",
    "local_profile_source_id",
})


@dataclass(frozen=True)
class LifecycleResource:
    resource_key: str
    resource_type: str
    resource_id: str
    state: str
    attributes: Mapping[str, Any]


@dataclass(frozen=True)
class FrozenDeletionPlan:
    operation_id: str
    account_id: str
    scope: DeletionScope
    lifecycle_revision: int
    resources: tuple[LifecycleResource, ...]
    resource_keys: tuple[str, ...]
    profile_ids: tuple[str, ...]
    provider_binding_ids: tuple[str, ...]
    provider_capability: ProviderCapability
    plan_digest: str

    def public_summary(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "account_id": self.account_id,
            "scope": self.scope.value,
            "lifecycle_revision": self.lifecycle_revision,
            "profile_count": len(self.profile_ids),
            "provider_binding_count": len(self.provider_binding_ids),
            "provider_capability": self.provider_capability.value,
            "can_confirm": self.provider_capability in {
                ProviderCapability.ENABLED,
                ProviderCapability.NOT_APPLICABLE,
            },
            "plan_digest": self.plan_digest,
        }


def _required_text(value: Any, reason: str) -> str:
    result = str(value or "").strip()
    if not result or len(result) > 256 or any(ord(character) < 32 for character in result):
        raise LifecycleV2Error(reason)
    return result


def _canonical_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return "aldp2_" + hashlib.sha256(encoded).hexdigest()


def parse_registry(records: Iterable[Mapping[str, Any]]) -> tuple[dict[str, Any], tuple[LifecycleResource, ...]]:
    material = [dict(record) for record in records]
    roots = [record for record in material if record.get("record_type") == "account_lifecycle_root"]
    if len(roots) != 1:
        raise LifecycleV2Error("lifecycle_root_ambiguous")
    root = roots[0]
    account_id = _required_text(root.get("account_id"), "account_id_invalid")
    if not _ACCOUNT_ID.fullmatch(account_id):
        raise LifecycleV2Error("account_id_invalid")
    if int(root.get("schema_version") or 0) != SCHEMA_VERSION:
        raise LifecycleV2Error("lifecycle_schema_unsupported")
    if root.get("state") != "active":
        raise LifecycleV2Error("lifecycle_not_active")
    if int(root.get("revision") or 0) < 1:
        raise LifecycleV2Error("lifecycle_revision_invalid")
    account_role = str(root.get("account_role") or "")
    owner_deletion_state = str(root.get("owner_deletion_state") or "")
    if account_role == "owner":
        if owner_deletion_state != "sole_member":
            # A household membership mutation must update this root in the
            # same transaction. Missing or shared-owner state is never
            # inferred away.
            raise LifecycleV2Error("ownership_transfer_required")
    elif account_role == "member":
        if owner_deletion_state != "member":
            raise LifecycleV2Error("lifecycle_membership_state_invalid")
    else:
        raise LifecycleV2Error("lifecycle_account_role_invalid")

    resources: list[LifecycleResource] = []
    seen_keys: set[str] = set()
    for record in material:
        if record.get("record_type") != "account_lifecycle_resource":
            continue
        if any(field in record for field in FORBIDDEN_AUTHORITY_FIELDS):
            raise LifecycleV2Error("presentation_field_used_as_authority")
        if _required_text(record.get("account_id"), "resource_account_invalid") != account_id:
            raise LifecycleV2Error("cross_account_resource")
        resource_key = _required_text(record.get("resource_key"), "resource_key_invalid")
        if resource_key in seen_keys:
            raise LifecycleV2Error("resource_key_ambiguous")
        seen_keys.add(resource_key)
        resource_type = _required_text(record.get("resource_type"), "resource_type_invalid")
        if resource_type not in RESOURCE_TYPES:
            raise LifecycleV2Error("resource_type_invalid")
        attributes = dict(record.get("attributes") or {})
        if any(field not in ALLOWED_RESOURCE_ATTRIBUTES for field in attributes):
            raise LifecycleV2Error("resource_attribute_not_allowed")
        if any(field in FORBIDDEN_AUTHORITY_FIELDS for field in attributes):
            raise LifecycleV2Error("presentation_field_used_as_authority")
        resources.append(LifecycleResource(
            resource_key=resource_key,
            resource_type=resource_type,
            resource_id=_required_text(record.get("resource_id"), "resource_id_invalid"),
            state=_required_text(record.get("state"), "resource_state_invalid"),
            attributes=attributes,
        ))
    if not resources:
        raise LifecycleV2Error("lifecycle_resources_missing")
    if account_role == "member" and any(
        resource.resource_type == "household" for resource in resources
    ):
        raise LifecycleV2Error("member_cannot_own_household_resource")
    return root, tuple(sorted(resources, key=lambda resource: resource.resource_key))


def _provider_capability(resources: Sequence[LifecycleResource]) -> ProviderCapability:
    providers = [resource for resource in resources if resource.resource_type == "provider_binding"]
    if not providers:
        return ProviderCapability.NOT_APPLICABLE
    states = {
        str(resource.attributes.get("two_way_profile_deletion") or "unavailable")
        for resource in providers
    }
    if states == {"enabled"}:
        return ProviderCapability.ENABLED
    if "disabled" in states:
        return ProviderCapability.DISABLED
    return ProviderCapability.UNAVAILABLE


def freeze_deletion_plan(
    *,
    operation_id: str,
    authenticated_account_id: str,
    requested_scope: str,
    registry_records: Iterable[Mapping[str, Any]],
) -> FrozenDeletionPlan:
    """Freeze a deletion plan solely from one server-owned registry partition."""
    if not _OPERATION_ID.fullmatch(str(operation_id or "")):
        raise LifecycleV2Error("operation_id_invalid")
    try:
        scope = DeletionScope(requested_scope)
    except ValueError as error:
        raise LifecycleV2Error("deletion_scope_invalid") from error
    if scope is not DeletionScope.EVERYTHING:
        # Kaevo-only deletion is retained in the enum solely so historical
        # receipts and already-running operations remain decodable. Every new
        # account deletion must include the exact linked provider identities.
        raise LifecycleV2Error("deletion_scope_retired")
    root, resources = parse_registry(registry_records)
    account_id = str(root["account_id"])
    if account_id != str(authenticated_account_id or ""):
        raise LifecycleV2Error("authenticated_account_mismatch")
    if any(resource.state not in {"active", "revoked"} for resource in resources):
        raise LifecycleV2Error("resource_state_not_deletable")
    if len([resource for resource in resources if resource.resource_type == "account"]) != 1:
        raise LifecycleV2Error("account_resource_ambiguous")
    if len([resource for resource in resources if resource.resource_type == "cognito_subject"]) != 1:
        raise LifecycleV2Error("cognito_resource_ambiguous")

    provider_capability = _provider_capability(resources)
    resource_keys = tuple(resource.resource_key for resource in resources)
    profile_ids = tuple(sorted({
        resource.resource_id for resource in resources
        if resource.resource_type in {"identity_profile", "cloud_profile"}
    }))
    provider_binding_ids = tuple(sorted({
        resource.resource_id for resource in resources
        if resource.resource_type == "provider_binding"
    }))
    # The operation ID identifies the persisted confirmation envelope, but it
    # is not part of the frozen account graph. Reissuing an operation for the
    # same semantic plan must preserve the digest so a protected-session
    # revalidation can distinguish an unchanged graph from a changed one.
    digest_payload = {
        "schema_version": SCHEMA_VERSION,
        "account_id": account_id,
        "scope": scope.value,
        "lifecycle_revision": int(root["revision"]),
        "resources": [
            {
                "resource_key": resource.resource_key,
                "resource_type": resource.resource_type,
                "resource_id": resource.resource_id,
                "state": resource.state,
                "attributes": dict(resource.attributes),
            }
            for resource in resources
        ],
        "resource_keys": resource_keys,
        "profile_ids": profile_ids,
        "provider_binding_ids": provider_binding_ids,
        "provider_capability": provider_capability.value,
    }
    return FrozenDeletionPlan(
        operation_id=operation_id,
        account_id=account_id,
        scope=scope,
        lifecycle_revision=int(root["revision"]),
        resources=resources,
        resource_keys=resource_keys,
        profile_ids=profile_ids,
        provider_binding_ids=provider_binding_ids,
        provider_capability=provider_capability,
        plan_digest=_canonical_digest(digest_payload),
    )


_ALLOWED_PHASE_TRANSITIONS = {
    OperationPhase.AWAITING_CONFIRMATION: {OperationPhase.QUEUED},
    OperationPhase.QUEUED: {
        OperationPhase.DELETING_SEERR,
        OperationPhase.DELETING_COGNITO,
    },
    OperationPhase.DELETING_SEERR: {OperationPhase.VERIFYING_SEERR_ABSENCE, OperationPhase.RETRY_REQUIRED},
    OperationPhase.VERIFYING_SEERR_ABSENCE: {OperationPhase.DELETING_JELLYFIN, OperationPhase.RETRY_REQUIRED},
    OperationPhase.DELETING_JELLYFIN: {OperationPhase.VERIFYING_JELLYFIN_ABSENCE, OperationPhase.RETRY_REQUIRED},
    OperationPhase.VERIFYING_JELLYFIN_ABSENCE: {OperationPhase.DELETING_COGNITO, OperationPhase.RETRY_REQUIRED},
    OperationPhase.DELETING_COGNITO: {OperationPhase.VERIFYING_COGNITO_ABSENCE, OperationPhase.RETRY_REQUIRED},
    OperationPhase.VERIFYING_COGNITO_ABSENCE: {OperationPhase.DELETING_KAEVO_GRAPH, OperationPhase.RETRY_REQUIRED},
    OperationPhase.DELETING_KAEVO_GRAPH: {OperationPhase.VERIFYING_KAEVO_ABSENCE, OperationPhase.RETRY_REQUIRED},
    OperationPhase.VERIFYING_KAEVO_ABSENCE: {OperationPhase.COMPLETED, OperationPhase.RETRY_REQUIRED},
    # A retry resumes the last durably recorded step. Rewinding every failure
    # to ``queued`` would repeat already-proved provider/Cognito work and can
    # become impossible after the exact AuthIdentity has been deleted.
    OperationPhase.RETRY_REQUIRED: {
        OperationPhase.QUEUED,
        OperationPhase.DELETING_SEERR,
        OperationPhase.VERIFYING_SEERR_ABSENCE,
        OperationPhase.DELETING_JELLYFIN,
        OperationPhase.VERIFYING_JELLYFIN_ABSENCE,
        OperationPhase.DELETING_COGNITO,
        OperationPhase.VERIFYING_COGNITO_ABSENCE,
        OperationPhase.DELETING_KAEVO_GRAPH,
        OperationPhase.VERIFYING_KAEVO_ABSENCE,
    },
    OperationPhase.COMPLETED: set(),
}


def require_phase_transition(current: str, proposed: str) -> OperationPhase:
    try:
        current_phase = OperationPhase(current)
        proposed_phase = OperationPhase(proposed)
    except ValueError as error:
        raise LifecycleV2Error("operation_phase_invalid") from error
    if proposed_phase not in _ALLOWED_PHASE_TRANSITIONS[current_phase]:
        raise LifecycleV2Error("operation_phase_transition_invalid")
    return proposed_phase

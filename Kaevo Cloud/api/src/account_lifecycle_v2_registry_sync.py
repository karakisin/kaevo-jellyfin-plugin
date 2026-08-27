"""Exact provider-edge projection into Account Lifecycle V2.

Only canonical profile and connector keys already owned by the lifecycle
registry are read. Presentation data and client mappings are never inputs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

from botocore.exceptions import ClientError

from account_lifecycle_v2_service import LifecycleV2StorageError


def _text(value: Any, *, maximum: int = 256) -> str:
    result = str(value or "").strip()
    if len(result) > maximum or any(ord(character) < 32 for character in result):
        raise LifecycleV2StorageError("provider_registry_value_invalid")
    return result


def _resource_key(resource_type: str, resource_id: str) -> str:
    digest = hashlib.sha256(f"{resource_type}\x00{resource_id}".encode()).hexdigest()
    return f"resource#{resource_type}#{digest}"


class ExactLifecycleV2ProviderRegistrySync:
    def __init__(
        self, *, lifecycle_table: Any, identity_profiles_table: Any,
        home_connectors_table: Any, clock,
    ):
        self.lifecycle_table = lifecycle_table
        self.identity_profiles_table = identity_profiles_table
        self.home_connectors_table = home_connectors_table
        self.clock = clock

    @staticmethod
    def _capability(connector: Mapping[str, Any] | None, now: int) -> str:
        if not isinstance(connector, Mapping) or not (
            connector.get("protocol_version") == "kaevo-pairing-v3"
            and connector.get("state") == "active"
            and connector.get("auth_state") == "v3_active"
            and not bool(connector.get("revoked", False))
            and int(connector.get("last_seen_epoch") or 0) >= now - 120
        ):
            return "unavailable"
        try:
            status = json.loads(str(connector.get("provider_status_json") or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            return "unavailable"
        deletion = status.get("profile_deletion") if isinstance(status, Mapping) else None
        if not isinstance(deletion, Mapping) or deletion.get("configured") is not True:
            return "unavailable"
        if deletion.get("ok") is True and deletion.get("reason") in {None, ""}:
            return "enabled"
        if deletion.get("ok") is False and deletion.get("reason") == "disabled":
            return "disabled"
        return "unavailable"

    def _desired(self, *, account_id: str, records: Sequence[Mapping[str, Any]], now: int):
        profile_ids = sorted({
            _text(item.get("resource_id")) for item in records
            if item.get("record_type") == "account_lifecycle_resource"
            and item.get("resource_type") == "identity_profile"
            and item.get("state") == "active"
        })
        bindings = []
        for profile_id in profile_ids:
            profile = self.identity_profiles_table.get_item(
                Key={"profile_id": profile_id}, ConsistentRead=True,
            ).get("Item")
            if not isinstance(profile, Mapping) or not (
                _text(profile.get("profile_id")) == profile_id
                and _text(profile.get("account_id")) == account_id
                and profile.get("state") == "active"
            ):
                raise LifecycleV2StorageError("provider_profile_conflict")
            jellyfin_state = _text(profile.get("jellyfin_binding_state"))
            connector_id = _text(profile.get("jellyfin_connector_id"))
            jellyfin_user_id = _text(profile.get("jellyfin_user_id"), maximum=64)
            seerr_user_id = _text(profile.get("seerr_user_id"), maximum=32)
            seerr_connector_id = _text(profile.get("seerr_connector_id"))
            seerr_jellyfin_id = _text(profile.get("seerr_jellyfin_user_id"), maximum=64)
            if not any((jellyfin_state, connector_id, jellyfin_user_id, seerr_user_id,
                        seerr_connector_id, seerr_jellyfin_id)):
                continue
            complete = (
                jellyfin_state == "active" and bool(connector_id) and bool(jellyfin_user_id)
                and (not seerr_user_id or (
                    _text(profile.get("seerr_binding_state")) == "active"
                    and seerr_connector_id == connector_id
                    and seerr_jellyfin_id == jellyfin_user_id
                ))
            )
            connector = self.home_connectors_table.get_item(
                Key={"connector_id": connector_id}, ConsistentRead=True,
            ).get("Item") if connector_id else None
            capability = self._capability(connector, now) if complete else "unavailable"
            identity = "\x00".join((account_id, profile_id, connector_id,
                                     jellyfin_user_id, seerr_user_id))
            binding_id = "alpb2_" + hashlib.sha256(identity.encode()).hexdigest()
            attributes = {
                "profile_id": profile_id,
                "connector_id": connector_id,
                "jellyfin_user_id": jellyfin_user_id,
                "two_way_profile_deletion": capability,
            }
            if seerr_user_id:
                attributes["seerr_user_id"] = seerr_user_id
            key = _resource_key("provider_binding", binding_id)
            bindings.append({
                "account_id": account_id, "record_key": key,
                "record_type": "account_lifecycle_resource", "schema_version": 2,
                "resource_key": key, "resource_type": "provider_binding",
                "resource_id": binding_id, "state": "active",
                "attributes": attributes, "created_at_epoch": now,
                "updated_at_epoch": now,
            })
        if len(bindings) > 1:
            raise LifecycleV2StorageError("provider_registry_household_unsupported")
        return bindings[0] if bindings else None

    def synchronize(self, *, account_id: str, registry_records: Sequence[Mapping[str, Any]]):
        now = int(self.clock())
        desired = self._desired(account_id=account_id, records=registry_records, now=now)
        existing = [item for item in registry_records
                    if item.get("record_type") == "account_lifecycle_resource"
                    and item.get("resource_type") == "provider_binding"
                    and item.get("state") == "active"]
        if desired is None:
            if existing:
                raise LifecycleV2StorageError("provider_registry_stale")
            return
        if len(existing) > 1 or (existing and existing[0].get("resource_id") != desired["resource_id"]):
            raise LifecycleV2StorageError("provider_registry_conflict")
        if existing and existing[0].get("attributes") == desired["attributes"]:
            return
        root = next((item for item in registry_records if item.get("record_key") == "root"), None)
        if not isinstance(root, Mapping):
            raise LifecycleV2StorageError("lifecycle_root_missing")
        revision = int(root.get("revision") or 0)
        put = {
            "TableName": self.lifecycle_table.name,
            "Item": desired,
            "ConditionExpression": (
                "attribute_not_exists(record_key)" if not existing else
                "record_type = :resource_type AND resource_id = :resource_id"
            ),
        }
        if existing:
            put["ExpressionAttributeValues"] = {
                ":resource_type": "account_lifecycle_resource",
                ":resource_id": desired["resource_id"],
            }
        try:
            self.lifecycle_table.meta.client.transact_write_items(TransactItems=[
                {"Put": put},
                {"Update": {
                    "TableName": self.lifecycle_table.name,
                    "Key": {"account_id": account_id, "record_key": "root"},
                    "UpdateExpression": "SET revision = :next, updated_at_epoch = :now",
                    "ConditionExpression": "revision = :current AND #state = :active",
                    "ExpressionAttributeNames": {"#state": "state"},
                    "ExpressionAttributeValues": {
                        ":next": revision + 1, ":now": now,
                        ":current": revision, ":active": "active",
                    },
                }},
            ])
        except ClientError as error:
            raise LifecycleV2StorageError("provider_registry_persist_failed") from error

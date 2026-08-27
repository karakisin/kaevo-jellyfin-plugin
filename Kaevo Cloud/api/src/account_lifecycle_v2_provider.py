"""Exact provider-command transport for Account Lifecycle V2.

The existing connector relay is used only as a transport.  Authority comes
from the immutable provider-binding snapshot frozen into the V2 operation;
the adapter never discovers a user from an email, display name, avatar, or a
device-local mapping.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from botocore.exceptions import ClientError

from account_lifecycle_v2_executor import LifecycleV2ExecutionError


SEERR_DELETE = "account_lifecycle_v2.seerr.delete_exact_identity"
SEERR_VERIFY = "account_lifecycle_v2.seerr.verify_exact_identity_absence"
JELLYFIN_DELETE = "account_lifecycle_v2.jellyfin.delete_exact_identity"
JELLYFIN_VERIFY = "account_lifecycle_v2.jellyfin.verify_exact_identity_absence"
_OPERATIONS = {SEERR_DELETE, SEERR_VERIFY, JELLYFIN_DELETE, JELLYFIN_VERIFY}
_REQUEST_NAMESPACE = uuid.UUID("4b0e54de-564c-41d4-b5bb-e5802f3c367c")


def _text(value: Any, reason: str, *, maximum: int = 256) -> str:
    result = str(value or "")
    if (
        not result
        or len(result) > maximum
        or any(ord(character) < 32 for character in result)
    ):
        raise LifecycleV2ExecutionError(reason)
    return result


def _binding_context(binding: Mapping[str, Any]) -> dict[str, Any]:
    if str(binding.get("resource_type") or "") != "provider_binding":
        raise LifecycleV2ExecutionError("provider_binding_snapshot_invalid")
    attributes = binding.get("attributes")
    if not isinstance(attributes, Mapping):
        raise LifecycleV2ExecutionError("provider_binding_snapshot_invalid")
    if str(attributes.get("two_way_profile_deletion") or "") != "enabled":
        raise LifecycleV2ExecutionError("provider_deletion_not_enabled")
    seerr_raw = attributes.get("seerr_user_id")
    seerr_user_id = None
    if seerr_raw not in {None, ""}:
        try:
            seerr_user_id = int(str(seerr_raw))
        except ValueError as error:
            raise LifecycleV2ExecutionError("provider_binding_snapshot_invalid") from error
        if seerr_user_id <= 0:
            raise LifecycleV2ExecutionError("provider_binding_snapshot_invalid")
    return {
        "lifecycle_binding_id": _text(
            binding.get("resource_id"), "provider_binding_snapshot_invalid",
        ),
        "profile_id": _text(
            attributes.get("profile_id"), "provider_binding_snapshot_invalid",
        ),
        "connector_id": _text(
            attributes.get("connector_id"), "provider_binding_snapshot_invalid",
        ),
        "jellyfin_user_id": _text(
            attributes.get("jellyfin_user_id"), "provider_binding_snapshot_invalid",
            maximum=64,
        ),
        "seerr_user_id": seerr_user_id,
    }


def frozen_profile_provider_binding(item: Mapping[str, Any]) -> dict[str, str] | None:
    """Return a validated frozen binding only for a lifecycle V2 request."""
    try:
        request = json.loads(str(item.get("request_json") or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    operation = str(request.get("path") or "").removeprefix("/commands/")
    if operation not in _OPERATIONS:
        return None
    try:
        frozen = json.loads(str(item.get("profile_provider_binding_json") or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        raise LifecycleV2ExecutionError("frozen_provider_binding_invalid")
    if not isinstance(frozen, Mapping):
        raise LifecycleV2ExecutionError("frozen_provider_binding_invalid")
    provider = _text(frozen.get("provider"), "frozen_provider_binding_invalid")
    connector_id = _text(frozen.get("connector_id"), "frozen_provider_binding_invalid")
    provider_user_id = _text(
        frozen.get("provider_user_id"), "frozen_provider_binding_invalid", maximum=64,
    )
    if (
        provider != "jellyfin"
        or connector_id != str(item.get("connector_id") or "")
        or str(item.get("profile_id") or "") != str(request.get("body", {}).get("profile_id") or item.get("profile_id") or "")
    ):
        raise LifecycleV2ExecutionError("frozen_provider_binding_invalid")
    return {
        "provider": provider,
        "connector_id": connector_id,
        "provider_user_id": provider_user_id,
    }


class RemoteExactProviderDeletionV2:
    def __init__(
        self,
        table: Any,
        *,
        clock: Callable[[], int] | None = None,
        request_ttl_seconds: int = 15 * 60,
        poll_timeout_seconds: float = 0,
        poll_interval_seconds: float = 0.5,
        sleeper=time.sleep,
    ):
        self.table = table
        self.clock = clock or (lambda: int(time.time()))
        self.request_ttl_seconds = request_ttl_seconds
        self.poll_timeout_seconds = max(0.0, float(poll_timeout_seconds))
        self.poll_interval_seconds = max(0.05, float(poll_interval_seconds))
        self.sleeper = sleeper

    def delete_seerr(self, *, operation_id: str, binding: Mapping[str, Any]) -> None:
        self._dispatch(operation_id, binding, SEERR_DELETE, require_seerr=True)

    def seerr_absent(self, *, operation_id: str, binding: Mapping[str, Any]) -> bool:
        return self._dispatch(operation_id, binding, SEERR_VERIFY, require_seerr=True)

    def delete_jellyfin(self, *, operation_id: str, binding: Mapping[str, Any]) -> None:
        self._dispatch(operation_id, binding, JELLYFIN_DELETE, require_seerr=False)

    def jellyfin_absent(self, *, operation_id: str, binding: Mapping[str, Any]) -> bool:
        return self._dispatch(operation_id, binding, JELLYFIN_VERIFY, require_seerr=False)

    def _dispatch(
        self,
        operation_id: str,
        binding: Mapping[str, Any],
        command: str,
        *,
        require_seerr: bool,
    ) -> bool:
        operation_id = _text(operation_id, "operation_identity_invalid", maximum=128)
        context = _binding_context(binding)
        if require_seerr and context["seerr_user_id"] is None:
            raise LifecycleV2ExecutionError("provider_binding_snapshot_invalid")
        request_id = str(uuid.uuid5(
            _REQUEST_NAMESPACE,
            "\x00".join((operation_id, context["lifecycle_binding_id"], command)),
        ))
        parameters = {
            "operation_id": operation_id,
            "lifecycle_binding_id": context["lifecycle_binding_id"],
            "profile_id": context["profile_id"],
            "jellyfin_user_id": context["jellyfin_user_id"],
        }
        if context["seerr_user_id"] is not None:
            parameters["seerr_user_id"] = context["seerr_user_id"]
        request_payload = {
            "provider": "home_server",
            "method": "COMMAND",
            "path": f"/commands/{command}",
            "query": {},
            "body": parameters,
        }
        canonical_request = json.dumps(request_payload, sort_keys=True, separators=(",", ":"))
        request_digest = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        now_epoch = int(self.clock())
        now = datetime.fromtimestamp(now_epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        item = {
            "request_id": request_id,
            "profile_id": context["profile_id"],
            "connector_id": context["connector_id"],
            "status": "pending",
            "status_created_at": f"pending#020#{now}#{request_id}",
            "priority": 20,
            "request_json": canonical_request,
            "request_digest": request_digest,
            "profile_provider_binding_json": json.dumps({
                "provider": "jellyfin",
                "connector_id": context["connector_id"],
                "provider_user_id": context["jellyfin_user_id"],
            }, sort_keys=True, separators=(",", ":")),
            "lifecycle_version": 2,
            "lifecycle_operation_id": operation_id,
            "lifecycle_binding_id": context["lifecycle_binding_id"],
            "created_at": now,
            "updated_at": now,
            "expires_at": now_epoch + self.request_ttl_seconds,
        }
        try:
            self.table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(request_id)",
            )
            current = item
        except ClientError as error:
            if str((error.response or {}).get("Error", {}).get("Code") or "") != "ConditionalCheckFailedException":
                raise LifecycleV2ExecutionError("provider_request_persist_failed") from error
            current = self.table.get_item(
                Key={"request_id": request_id}, ConsistentRead=True,
            ).get("Item")
            if not isinstance(current, Mapping):
                raise LifecycleV2ExecutionError("provider_request_missing")
            if (
                str(current.get("request_digest") or "") != request_digest
                or str(current.get("lifecycle_operation_id") or "") != operation_id
                or str(current.get("lifecycle_binding_id") or "") != context["lifecycle_binding_id"]
            ):
                raise LifecycleV2ExecutionError("provider_request_identity_conflict")

        status = str(current.get("status") or "")
        deadline = time.monotonic() + self.poll_timeout_seconds
        while status in {"pending", "in_progress", "completing"} and time.monotonic() < deadline:
            self.sleeper(min(
                self.poll_interval_seconds,
                max(0.0, deadline - time.monotonic()),
            ))
            current = self.table.get_item(
                Key={"request_id": request_id}, ConsistentRead=True,
            ).get("Item")
            if not isinstance(current, Mapping):
                raise LifecycleV2ExecutionError("provider_request_missing")
            status = str(current.get("status") or "")
        if status in {"pending", "in_progress", "completing"}:
            raise LifecycleV2ExecutionError("provider_request_pending")
        if status != "completed":
            raise LifecycleV2ExecutionError("provider_request_failed")
        try:
            response = json.loads(str(current.get("response_json") or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise LifecycleV2ExecutionError("provider_response_invalid") from error
        result = response.get("result") if isinstance(response, Mapping) else None
        if (
            not isinstance(result, Mapping)
            or int(result.get("lifecycle_version") or 0) != 2
            or str(response.get("operation") or "") != command
            or str(result.get("operation_id") or "") != operation_id
            or str(result.get("lifecycle_binding_id") or "") != context["lifecycle_binding_id"]
            or str(result.get("connector_id") or "") != context["connector_id"]
            or str(result.get("profile_id") or "") != context["profile_id"]
            or str(result.get("jellyfin_user_id") or "") != context["jellyfin_user_id"]
        ):
            raise LifecycleV2ExecutionError("provider_response_identity_mismatch")
        if require_seerr and int(result.get("seerr_user_id") or 0) != context["seerr_user_id"]:
            raise LifecycleV2ExecutionError("provider_response_identity_mismatch")
        is_verification = command in {SEERR_VERIFY, JELLYFIN_VERIFY}
        if is_verification and result.get("absence_confirmed") is not True:
            raise LifecycleV2ExecutionError("provider_absence_unconfirmed")
        if not is_verification and result.get("absence_confirmed") is not False:
            raise LifecycleV2ExecutionError("provider_response_invalid")
        return True

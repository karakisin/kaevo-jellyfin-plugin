"""Account Lifecycle V2 application service and DynamoDB adapter.

The authenticated Cognito subject is resolved through the canonical
AuthIdentity record.  Profile projections and device mappings are never read
to decide account ownership or deletion scope.
"""

from __future__ import annotations

import hmac
import hashlib
import secrets
import time
from typing import Any, Callable, Mapping, Protocol

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from account_foundation import provider_subject_key
from account_lifecycle_v2 import (
    DeletionScope,
    FrozenDeletionPlan,
    LifecycleV2Error,
    OperationPhase,
    freeze_deletion_plan,
)


class LifecycleV2StorageError(RuntimeError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class LifecycleV2Repository(Protocol):
    def account_id_for_subject(self, subject: str) -> str: ...
    def registry_records(self, account_id: str) -> list[dict[str, Any]]: ...
    def put_preflight(self, plan: FrozenDeletionPlan, now: int) -> None: ...
    def queue_operation(
        self, account_id: str, operation_id: str, plan_digest: str, now: int,
    ) -> dict[str, Any]: ...
    def operation(self, account_id: str, operation_id: str) -> dict[str, Any] | None: ...
    def operation_for_subject(self, operation_id: str, subject: str) -> dict[str, Any] | None: ...
    def ensure_session_resources(
        self, account_id: str, *, subject: str, family_id: str, installation_id: str,
        access_record_id: str, now: int,
    ) -> None: ...


def _operation_key(operation_id: str) -> str:
    return f"operation#{operation_id}"


def _public_operation(item: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        "operation_id": str(item.get("operation_id") or ""),
        "account_id": str(item.get("account_id") or ""),
        "scope": str(item.get("scope") or ""),
        "phase": str(item.get("phase") or ""),
        "retryable": bool(item.get("retryable", False)),
        "proof": None,
    }
    proof = item.get("proof")
    if isinstance(proof, Mapping):
        result["proof"] = {
            "cognito_identity_absent": bool(proof.get("cognito_identity_absent", False)),
            "cognito_email_absent": bool(proof.get("cognito_email_absent", False)),
            "kaevo_graph_absent": bool(proof.get("kaevo_graph_absent", False)),
            "jellyfin_identity_absent": proof.get("jellyfin_identity_absent"),
            "seerr_identity_absent": proof.get("seerr_identity_absent"),
        }
    return result


class DynamoLifecycleV2Repository:
    def __init__(
        self,
        *,
        lifecycle_table: Any,
        auth_identities_table: Any,
        installations_table: Any | None = None,
        app_sessions_table: Any | None = None,
        profile_mappings_table: Any | None = None,
    ):
        self.lifecycle_table = lifecycle_table
        self.auth_identities_table = auth_identities_table
        self.installations_table = installations_table
        self.app_sessions_table = app_sessions_table
        self.profile_mappings_table = profile_mappings_table

    def account_id_for_subject(self, subject: str) -> str:
        item = self.auth_identities_table.get_item(
            Key={"auth_identity_key": provider_subject_key("cognito", subject)},
            ConsistentRead=True,
        ).get("Item")
        if (
            not isinstance(item, Mapping)
            or item.get("entity_type") != "AuthIdentity"
            or item.get("provider") != "cognito"
            or item.get("status") != "active"
        ):
            raise LifecycleV2StorageError("auth_identity_not_active")
        account_id = str(item.get("account_id") or "")
        if not account_id:
            raise LifecycleV2StorageError("auth_identity_account_missing")
        return account_id

    def registry_records(self, account_id: str) -> list[dict[str, Any]]:
        response = self.lifecycle_table.query(
            KeyConditionExpression=Key("account_id").eq(account_id),
            ConsistentRead=True,
        )
        records = list(response.get("Items") or [])
        while response.get("LastEvaluatedKey"):
            response = self.lifecycle_table.query(
                KeyConditionExpression=Key("account_id").eq(account_id),
                ConsistentRead=True,
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            records.extend(response.get("Items") or [])
        # An account that predates Lifecycle V2 has no registry partition yet.
        # Surface that exact state to the API boundary so the protected client
        # can invoke the explicit immutable-ID migration path. Passing an empty
        # list into plan validation instead strands an otherwise valid account.
        if not records:
            raise LifecycleV2StorageError("lifecycle_root_missing")
        return records

    @staticmethod
    def _runtime_resource(
        account_id: str, resource_type: str, resource_id: str, now: int,
        *, attributes: Mapping[str, Any] | None = None,
    ):
        if (
            not resource_id or len(resource_id) > 256
            or any(ord(character) < 32 for character in resource_id)
        ):
            raise LifecycleV2StorageError("runtime_resource_invalid")
        digest = hashlib.sha256(
            f"{resource_type}\x00{resource_id}".encode("utf-8")
        ).hexdigest()
        key = f"resource#{resource_type}#{digest}"
        resource = {
            "account_id": account_id,
            "record_key": key,
            "record_type": "account_lifecycle_resource",
            "schema_version": 2,
            "resource_key": key,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "state": "active",
            "created_at_epoch": int(now),
            "updated_at_epoch": int(now),
        }
        if attributes:
            resource["attributes"] = dict(attributes)
        return resource

    def ensure_session_resources(
        self, account_id: str, *, subject: str, family_id: str, installation_id: str,
        access_record_id: str, now: int,
    ) -> None:
        if (
            self.installations_table is None
            or self.app_sessions_table is None
            or self.profile_mappings_table is None
        ):
            raise LifecycleV2StorageError("runtime_resource_configuration_missing")

        def exact_account_items(table: Any) -> list[dict[str, Any]]:
            response = table.scan(
                ConsistentRead=True,
                FilterExpression="#account_id = :account_id",
                ExpressionAttributeNames={"#account_id": "account_id"},
                ExpressionAttributeValues={":account_id": account_id},
            )
            items = list(response.get("Items") or [])
            while response.get("LastEvaluatedKey"):
                response = table.scan(
                    ConsistentRead=True,
                    FilterExpression="#account_id = :account_id",
                    ExpressionAttributeNames={"#account_id": "account_id"},
                    ExpressionAttributeValues={":account_id": account_id},
                    ExclusiveStartKey=response["LastEvaluatedKey"],
                )
                items.extend(response.get("Items") or [])
            if any(str(item.get("account_id") or "") != account_id for item in items):
                raise LifecycleV2StorageError("runtime_resource_account_conflict")
            return [dict(item) for item in items]

        desired_by_key: dict[str, dict[str, Any]] = {}

        def include(
            resource_type: str, resource_id: str,
            *, attributes: Mapping[str, Any] | None = None,
        ) -> None:
            resource = self._runtime_resource(
                account_id, resource_type, resource_id, now, attributes=attributes,
            )
            desired_by_key[resource["record_key"]] = resource

        # Session-family authority is stable across access/refresh rotation.
        # The graph executor deletes and verifies every token dynamically by
        # family, so persisting individual token hashes here is redundant and
        # would make a reviewed deletion plan invalidate itself whenever the
        # protected session rotates between review and confirmation.
        include("app_session_family", family_id)
        include("installation", installation_id)

        for item in exact_account_items(self.installations_table):
            include(
                "installation",
                str(item.get("installation_id") or ""),
            )

        for item in exact_account_items(self.app_sessions_table):
            record_type = str(item.get("record_type") or "")
            token_hash = str(item.get("token_hash") or "")
            family = str(item.get("family_id") or "")
            if record_type not in {"access", "refresh"}:
                raise LifecycleV2StorageError("runtime_session_type_unsupported")
            if family:
                include("app_session_family", family)
            if not token_hash:
                raise LifecycleV2StorageError("runtime_session_token_invalid")

        for item in exact_account_items(self.profile_mappings_table):
            mapping_id = str(item.get("mapping_id") or "")
            installation = str(item.get("installation_id") or "")
            local_source = str(item.get("local_profile_source_id") or "")
            if not mapping_id or not installation or not local_source:
                raise LifecycleV2StorageError("runtime_profile_mapping_invalid")
            include(
                "profile_mapping",
                mapping_id,
                attributes={
                    "installation_id": installation,
                    "local_profile_source_id": local_source,
                },
            )

        desired = sorted(desired_by_key.values(), key=lambda item: item["record_key"])
        # One transaction can carry 99 resource puts plus the root revision
        # update. Re-read after every batch so concurrent preflights either
        # converge on the same exact graph or fail closed.
        for _ in range(32):
            records = self.registry_records(account_id)
            root = next(
                (item for item in records if item.get("record_key") == "root"), None,
            )
            if not isinstance(root, Mapping):
                raise LifecycleV2StorageError("lifecycle_root_missing")
            revision = int(root.get("revision") or 0)
            existing = {
                str(item.get("record_key") or ""): item for item in records
                if item.get("record_type") == "account_lifecycle_resource"
            }
            obsolete_session_token_keys = sorted(
                key for key, item in existing.items()
                if item.get("resource_type") in {
                    "app_session_access", "app_session_refresh",
                }
            )
            missing = []
            for resource in desired:
                current = existing.get(resource["record_key"])
                if current is None:
                    missing.append(resource)
                    continue
                if (
                    current.get("resource_type") != resource["resource_type"]
                    or current.get("resource_id") != resource["resource_id"]
                    or current.get("state") != "active"
                ):
                    raise LifecycleV2StorageError("runtime_resource_conflict")
            if not missing and not obsolete_session_token_keys:
                return
            changes = [
                {"Delete": {
                    "TableName": self.lifecycle_table.name,
                    "Key": {"account_id": account_id, "record_key": key},
                    "ConditionExpression": (
                        "record_type = :resource_type AND "
                        "(resource_type = :access OR resource_type = :refresh)"
                    ),
                    "ExpressionAttributeValues": {
                        ":resource_type": "account_lifecycle_resource",
                        ":access": "app_session_access",
                        ":refresh": "app_session_refresh",
                    },
                }}
                for key in obsolete_session_token_keys
            ]
            changes.extend({"Put": {
                "TableName": self.lifecycle_table.name,
                "Item": resource,
                "ConditionExpression": "attribute_not_exists(record_key)",
            }} for resource in missing)
            transaction = changes[:99]
            transaction.append({"Update": {
                "TableName": self.lifecycle_table.name,
                "Key": {"account_id": account_id, "record_key": "root"},
                "UpdateExpression": "SET revision = :next, updated_at_epoch = :now",
                "ConditionExpression": (
                    "record_type = :root_type AND #state = :active AND revision = :current"
                ),
                "ExpressionAttributeNames": {"#state": "state"},
                "ExpressionAttributeValues": {
                    ":next": revision + 1,
                    ":now": int(now),
                    ":root_type": "account_lifecycle_root",
                    ":active": "active",
                    ":current": revision,
                },
            }})
            try:
                self.lifecycle_table.meta.client.transact_write_items(
                    TransactItems=transaction,
                )
                if len(changes) <= 99:
                    return
            except ClientError as error:
                code = str((error.response or {}).get("Error", {}).get("Code") or "")
                if code != "TransactionCanceledException":
                    raise LifecycleV2StorageError("runtime_resource_persist_failed") from error
        raise LifecycleV2StorageError("runtime_resource_limit_exceeded")

    def put_preflight(self, plan: FrozenDeletionPlan, now: int) -> None:
        item = {
            "account_id": plan.account_id,
            "record_key": _operation_key(plan.operation_id),
            "record_type": "account_lifecycle_operation",
            "schema_version": 2,
            "operation_id": plan.operation_id,
            "scope": plan.scope.value,
            "phase": OperationPhase.AWAITING_CONFIRMATION.value,
            "retryable": False,
            "plan_digest": plan.plan_digest,
            "lifecycle_revision": plan.lifecycle_revision,
            "resource_snapshots": [
                {
                    "resource_key": resource.resource_key,
                    "resource_type": resource.resource_type,
                    "resource_id": resource.resource_id,
                    "state": resource.state,
                    "attributes": dict(resource.attributes),
                }
                for resource in plan.resources
            ],
            "resource_keys": list(plan.resource_keys),
            "profile_ids": list(plan.profile_ids),
            "provider_binding_ids": list(plan.provider_binding_ids),
            "provider_capability": plan.provider_capability.value,
            "created_at_epoch": int(now),
            "updated_at_epoch": int(now),
        }
        try:
            self.lifecycle_table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(record_key)",
            )
        except ClientError as error:
            raise LifecycleV2StorageError("preflight_persist_failed") from error

    def queue_operation(
        self, account_id: str, operation_id: str, plan_digest: str, now: int,
    ) -> dict[str, Any]:
        existing = self.operation(account_id, operation_id)
        if not existing:
            raise LifecycleV2StorageError("operation_not_found")
        if str(existing.get("plan_digest") or "") != plan_digest:
            raise LifecycleV2StorageError("operation_confirmation_conflict")
        if str(existing.get("phase") or "") != OperationPhase.AWAITING_CONFIRMATION.value:
            return existing
        revision = int(existing.get("lifecycle_revision") or 0)
        if revision < 1:
            raise LifecycleV2StorageError("operation_confirmation_conflict")
        try:
            self.lifecycle_table.meta.client.transact_write_items(TransactItems=[
                {"ConditionCheck": {
                    "TableName": self.lifecycle_table.name,
                    "Key": {"account_id": account_id, "record_key": "root"},
                    "ConditionExpression": (
                        "record_type = :root_type AND #state = :active "
                        "AND revision = :revision AND ("
                        "(account_role = :owner AND owner_deletion_state = :sole) OR "
                        "(account_role = :member AND owner_deletion_state = :member))"
                    ),
                    "ExpressionAttributeNames": {"#state": "state"},
                    "ExpressionAttributeValues": {
                        ":root_type": "account_lifecycle_root",
                        ":active": "active",
                        ":revision": revision,
                        ":owner": "owner",
                        ":sole": "sole_member",
                        ":member": "member",
                    },
                }},
                {"Update": {
                    "TableName": self.lifecycle_table.name,
                    "Key": {"account_id": account_id, "record_key": _operation_key(operation_id)},
                    "UpdateExpression": (
                        "SET #phase = :queued, retryable = :retryable, "
                        "updated_at_epoch = :now, confirmed_at_epoch = if_not_exists(confirmed_at_epoch, :now)"
                    ),
                    "ConditionExpression": (
                        "record_type = :record_type AND operation_id = :operation_id "
                        "AND plan_digest = :plan_digest AND lifecycle_revision = :revision "
                        "AND #phase = :awaiting AND #scope = :everything "
                        "AND provider_capability IN (:enabled, :not_applicable)"
                    ),
                    "ExpressionAttributeNames": {
                        "#phase": "phase",
                        "#scope": "scope",
                    },
                    "ExpressionAttributeValues": {
                        ":queued": OperationPhase.QUEUED.value,
                        ":retryable": True,
                        ":now": int(now),
                        ":record_type": "account_lifecycle_operation",
                        ":operation_id": operation_id,
                        ":plan_digest": plan_digest,
                        ":revision": revision,
                        ":awaiting": OperationPhase.AWAITING_CONFIRMATION.value,
                        ":everything": DeletionScope.EVERYTHING.value,
                        ":enabled": "enabled",
                        ":not_applicable": "not_applicable",
                    },
                }},
            ])
            queued = self.operation(account_id, operation_id)
            if not queued or str(queued.get("phase") or "") != OperationPhase.QUEUED.value:
                raise LifecycleV2StorageError("operation_confirmation_conflict")
            return queued
        except ClientError as error:
            code = str((error.response or {}).get("Error", {}).get("Code") or "")
            if code != "TransactionCanceledException":
                raise LifecycleV2StorageError("operation_queue_failed") from error
            existing = self.operation(account_id, operation_id)
            if (
                existing
                and str(existing.get("plan_digest") or "") == plan_digest
                and str(existing.get("phase") or "") != OperationPhase.AWAITING_CONFIRMATION.value
            ):
                return existing
            raise LifecycleV2StorageError("operation_confirmation_conflict") from error

    def operation(self, account_id: str, operation_id: str) -> dict[str, Any] | None:
        item = self.lifecycle_table.get_item(
            Key={"account_id": account_id, "record_key": _operation_key(operation_id)},
            ConsistentRead=True,
        ).get("Item")
        return dict(item) if isinstance(item, Mapping) else None

    def operation_for_subject(self, operation_id: str, subject: str) -> dict[str, Any] | None:
        response = self.lifecycle_table.query(
            IndexName="operation_id-index",
            KeyConditionExpression=Key("operation_id").eq(operation_id),
            ConsistentRead=False,
        )
        items = [
            dict(item) for item in response.get("Items") or []
            if item.get("record_type") == "account_lifecycle_operation"
        ]
        if len(items) != 1:
            return None
        subjects = {
            str(resource.get("resource_id") or "")
            for resource in items[0].get("resource_snapshots") or []
            if isinstance(resource, Mapping)
            and resource.get("resource_type") == "cognito_subject"
        }
        if len(subjects) != 1 or not hmac.compare_digest(next(iter(subjects)), subject):
            return None
        return items[0]


class AccountLifecycleV2Service:
    def __init__(
        self,
        repository: LifecycleV2Repository,
        *,
        operation_id_factory: Callable[[], str] | None = None,
        clock: Callable[[], int] | None = None,
    ):
        self.repository = repository
        self.operation_id_factory = operation_id_factory or (
            lambda: f"ald2_{secrets.token_urlsafe(24)}"
        )
        self.clock = clock or (lambda: int(time.time()))

    def preflight(self, *, subject: str, requested_scope: str) -> dict[str, Any]:
        account_id = self.repository.account_id_for_subject(subject)
        plan = freeze_deletion_plan(
            operation_id=self.operation_id_factory(),
            authenticated_account_id=account_id,
            requested_scope=requested_scope,
            registry_records=self.repository.registry_records(account_id),
        )
        self.repository.put_preflight(plan, self.clock())
        return plan.public_summary()

    def register_session_resources(
        self, *, subject: str, session: Mapping[str, Any], now: int | None = None,
    ) -> str:
        account_id = self.repository.account_id_for_subject(subject)
        if account_id != str(session.get("account_id") or ""):
            raise LifecycleV2Error("protected_session_account_mismatch")
        self.repository.ensure_session_resources(
            account_id,
            subject=subject,
            family_id=str(session.get("family_id") or ""),
            installation_id=str(session.get("installation_id") or ""),
            access_record_id=str(session.get("token_hash") or ""),
            now=int(self.clock() if now is None else now),
        )
        return account_id

    def confirm(
        self,
        *,
        subject: str,
        operation_id: str,
        plan_digest: str,
        confirmation: str,
    ) -> dict[str, Any]:
        if confirmation != "DELETE":
            raise LifecycleV2Error("deletion_confirmation_invalid")
        account_id = self.repository.account_id_for_subject(subject)
        existing = self.repository.operation(account_id, operation_id)
        if (
            not existing
            or str(existing.get("plan_digest") or "") != plan_digest
            or str(existing.get("account_id") or "") != account_id
        ):
            raise LifecycleV2StorageError("operation_confirmation_conflict")
        if str(existing.get("scope") or "") != DeletionScope.EVERYTHING.value:
            raise LifecycleV2Error("deletion_scope_retired")
        if str(existing.get("provider_capability") or "") not in {
            "enabled", "not_applicable",
        }:
            raise LifecycleV2Error("provider_deletion_not_enabled")
        item = self.repository.queue_operation(
            account_id, operation_id, plan_digest, self.clock(),
        )
        return _public_operation(item)

    def status(self, *, subject: str, operation_id: str) -> dict[str, Any]:
        try:
            account_id = self.repository.account_id_for_subject(subject)
            item = self.repository.operation(account_id, operation_id)
        except LifecycleV2StorageError as error:
            if error.reason not in {"auth_identity_not_active", "auth_identity_account_missing"}:
                raise
            item = self.repository.operation_for_subject(operation_id, subject)
        if not item:
            raise LifecycleV2StorageError("operation_not_found")
        return _public_operation(item)

    def status_for_account(self, *, account_id: str, operation_id: str) -> dict[str, Any]:
        item = self.repository.operation(account_id, operation_id)
        if not item:
            raise LifecycleV2StorageError("operation_not_found")
        return _public_operation(item)

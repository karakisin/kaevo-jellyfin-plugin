"""SQS worker for durable Account Lifecycle V2 deletion operations."""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Mapping

import boto3

from account_lifecycle_v2 import OperationPhase
from account_lifecycle_v2_aws import (
    CognitoSubjectDeletion,
    DynamoKaevoGraphDeletion,
    DynamoOperationJournal,
)
from account_lifecycle_v2_executor import AccountLifecycleV2Executor, EXECUTABLE_PHASES
from account_lifecycle_v2_provider import RemoteExactProviderDeletionV2
from account_lifecycle_v2_service import DynamoLifecycleV2Repository, LifecycleV2StorageError


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise LifecycleV2StorageError("lifecycle_worker_configuration_missing")
    return value


def _message(record: Mapping[str, Any]) -> tuple[str, str]:
    raw = record.get("body")
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 4096:
        raise LifecycleV2StorageError("lifecycle_worker_message_invalid")
    try:
        body = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise LifecycleV2StorageError("lifecycle_worker_message_invalid") from error
    if not isinstance(body, Mapping) or int(body.get("schema_version") or 0) != 2:
        raise LifecycleV2StorageError("lifecycle_worker_message_invalid")
    account_id = str(body.get("account_id") or "")
    operation_id = str(body.get("operation_id") or "")
    if not account_id or not operation_id.startswith("ald2_"):
        raise LifecycleV2StorageError("lifecycle_worker_message_invalid")
    return account_id, operation_id


def _runtime():
    dynamodb = boto3.resource("dynamodb")
    lifecycle = dynamodb.Table(_required_environment("ACCOUNT_LIFECYCLE_V2_TABLE"))
    auth = dynamodb.Table(_required_environment("AUTH_IDENTITIES_TABLE"))
    remote = dynamodb.Table(_required_environment("REMOTE_REQUESTS_TABLE"))
    repository = DynamoLifecycleV2Repository(
        lifecycle_table=lifecycle,
        auth_identities_table=auth,
    )
    graph = DynamoKaevoGraphDeletion(
        lifecycle_table=lifecycle,
        app_sessions_table=dynamodb.Table(_required_environment("APP_SESSIONS_TABLE")),
        household_invitations_table=dynamodb.Table(
            _required_environment("HOUSEHOLD_INVITATIONS_TABLE")
        ),
        tables={
            "accounts": dynamodb.Table(_required_environment("ACCOUNTS_TABLE")),
            "auth_identities": auth,
            "principals": dynamodb.Table(_required_environment("PRINCIPALS_TABLE")),
            "identity_memberships": dynamodb.Table(_required_environment("IDENTITY_MEMBERSHIPS_TABLE")),
            "household_memberships": dynamodb.Table(_required_environment("HOUSEHOLD_MEMBERSHIPS_TABLE")),
            "identity_households": dynamodb.Table(_required_environment("IDENTITY_HOUSEHOLDS_TABLE")),
            "identity_profiles": dynamodb.Table(_required_environment("IDENTITY_PROFILES_TABLE")),
            "profiles": dynamodb.Table(_required_environment("PROFILES_TABLE")),
            "profile_bindings": dynamodb.Table(_required_environment("PROFILE_BINDINGS_TABLE")),
            "profile_mappings": dynamodb.Table(_required_environment("PROFILE_MAPPINGS_TABLE")),
            "installations": dynamodb.Table(_required_environment("INSTALLATIONS_TABLE")),
            "app_sessions": dynamodb.Table(_required_environment("APP_SESSIONS_TABLE")),
        },
    )
    executor = AccountLifecycleV2Executor(
        journal=DynamoOperationJournal(lifecycle, clock=lambda: int(time.time())),
        providers=RemoteExactProviderDeletionV2(
            remote, poll_timeout_seconds=8, poll_interval_seconds=0.5,
        ),
        cognito=CognitoSubjectDeletion(
            boto3.client("cognito-idp"),
            user_pool_id=_required_environment("COGNITO_USER_POOL_ID"),
            auth_identities_table=auth,
        ),
        kaevo_graph=graph,
    )
    return repository, executor


def process_record(
    record: Mapping[str, Any],
    *,
    repository: DynamoLifecycleV2Repository,
    executor: AccountLifecycleV2Executor,
) -> dict[str, Any]:
    account_id, operation_id = _message(record)
    operation = repository.operation(account_id, operation_id)
    if not operation:
        raise LifecycleV2StorageError("operation_not_found")
    phase = str(operation.get("phase") or "")
    if phase == OperationPhase.COMPLETED.value:
        return operation
    executable = {item.value for item in EXECUTABLE_PHASES}
    executable.add(OperationPhase.RETRY_REQUIRED.value)
    if phase not in executable:
        raise LifecycleV2StorageError("operation_not_executable")
    result = executor.execute(operation)
    if str(result.get("phase") or "") == OperationPhase.RETRY_REQUIRED.value:
        # Raising returns the same SQS message after its visibility timeout.
        # Every provider command uses a deterministic request ID, so delivery
        # is at-least-once without duplicating provider authority.
        raise LifecycleV2StorageError(str(result.get("failure_reason") or result.get("reason") or "retry_required"))
    if str(result.get("phase") or "") != OperationPhase.COMPLETED.value:
        raise LifecycleV2StorageError("operation_terminal_proof_missing")
    return result


def lambda_handler(event: Mapping[str, Any], _context: Any) -> dict[str, Any]:
    records = event.get("Records")
    if not isinstance(records, list) or not records:
        raise LifecycleV2StorageError("lifecycle_worker_message_invalid")
    repository, executor = _runtime()
    failures = []
    completed = 0
    for record in records:
        message_id = str((record or {}).get("messageId") or "")
        try:
            process_record(record, repository=repository, executor=executor)
            completed += 1
        except Exception:
            LOGGER.exception(
                "account_lifecycle_v2_worker_failure message_id=%s", message_id,
            )
            failures.append({"itemIdentifier": message_id})
    return {"batchItemFailures": failures, "completed": completed}

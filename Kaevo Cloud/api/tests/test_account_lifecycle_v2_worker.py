import json

import pytest

from account_lifecycle_v2_service import LifecycleV2StorageError
from account_lifecycle_v2_worker import process_record


ACCOUNT_ID = "acct_0123456789abcdef01234567"
OPERATION_ID = "ald2_0123456789abcdef0123456789abcdef"


def record():
    return {"body": json.dumps({
        "schema_version": 2,
        "account_id": ACCOUNT_ID,
        "operation_id": OPERATION_ID,
    })}


class Repository:
    def __init__(self, operation):
        self.value = operation

    def operation(self, account_id, operation_id):
        assert account_id == ACCOUNT_ID
        assert operation_id == OPERATION_ID
        return self.value


class Executor:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def execute(self, operation):
        self.calls.append(operation)
        return self.result


def operation(phase):
    return {
        "account_id": ACCOUNT_ID,
        "operation_id": OPERATION_ID,
        "phase": phase,
    }


def test_worker_accepts_only_terminal_proof_completion():
    executor = Executor(operation("completed"))

    result = process_record(
        record(), repository=Repository(operation("queued")), executor=executor,
    )

    assert result["phase"] == "completed"
    assert len(executor.calls) == 1


def test_retry_required_fails_message_for_delayed_sqs_redelivery():
    executor = Executor({**operation("retry_required"), "failure_reason": "provider_request_pending"})

    with pytest.raises(LifecycleV2StorageError, match="provider_request_pending"):
        process_record(
            record(), repository=Repository(operation("queued")), executor=executor,
        )


def test_completed_operation_is_idempotent_and_does_not_execute_again():
    executor = Executor(operation("should_not_execute"))

    result = process_record(
        record(), repository=Repository(operation("completed")), executor=executor,
    )

    assert result["phase"] == "completed"
    assert executor.calls == []


@pytest.mark.parametrize("phase", [
    "deleting_seerr",
    "verifying_seerr_absence",
    "deleting_jellyfin",
    "verifying_jellyfin_absence",
    "deleting_cognito",
    "verifying_cognito_absence",
    "deleting_kaevo_graph",
    "verifying_kaevo_absence",
])
def test_worker_redelivery_resumes_every_durable_execution_phase(phase):
    executor = Executor(operation("completed"))

    result = process_record(
        record(), repository=Repository(operation(phase)), executor=executor,
    )

    assert result["phase"] == "completed"
    assert executor.calls == [operation(phase)]


def test_worker_rejects_client_shaped_or_legacy_messages():
    with pytest.raises(LifecycleV2StorageError, match="lifecycle_worker_message_invalid"):
        process_record(
            {"body": json.dumps({"account_id": ACCOUNT_ID, "operation_id": OPERATION_ID})},
            repository=Repository(None),
            executor=Executor({}),
        )

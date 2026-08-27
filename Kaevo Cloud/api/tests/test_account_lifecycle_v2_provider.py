import json

import pytest
from botocore.exceptions import ClientError

from account_lifecycle_v2_executor import LifecycleV2ExecutionError
from account_lifecycle_v2_provider import (
    JELLYFIN_DELETE,
    JELLYFIN_VERIFY,
    RemoteExactProviderDeletionV2,
    frozen_profile_provider_binding,
)


OPERATION_ID = "ald2_0123456789abcdef0123456789abcdef"


def binding():
    return {
        "resource_type": "provider_binding",
        "resource_id": "provider_binding_0123456789abcdef",
        "attributes": {
            "profile_id": "profile_0123456789abcdef",
            "connector_id": "connector-1",
            "jellyfin_user_id": "0123456789abcdef0123456789abcdef",
            "seerr_user_id": "42",
            "two_way_profile_deletion": "enabled",
        },
    }


class Table:
    def __init__(self):
        self.item = None

    def put_item(self, *, Item, ConditionExpression):
        assert ConditionExpression == "attribute_not_exists(request_id)"
        if self.item is not None:
            raise ClientError({
                "Error": {"Code": "ConditionalCheckFailedException"},
            }, "PutItem")
        self.item = dict(Item)

    def get_item(self, *, Key, ConsistentRead):
        assert ConsistentRead is True
        return {"Item": dict(self.item)} if self.item else {}


def completed_response(table, *, command, absence):
    request = json.loads(table.item["request_json"])
    parameters = request["body"]
    table.item.update({
        "status": "completed",
        "response_json": json.dumps({
            "requestId": table.item["request_id"],
            "state": "complete",
            "operation": command,
            "result": {
                "lifecycle_version": 2,
                "operation_id": OPERATION_ID,
                "lifecycle_binding_id": parameters["lifecycle_binding_id"],
                "provider": "jellyfin",
                "state": "absence_confirmed" if absence else "delete_dispatched",
                "connector_id": table.item["connector_id"],
                "profile_id": table.item["profile_id"],
                "jellyfin_user_id": parameters["jellyfin_user_id"],
                "seerr_user_id": parameters.get("seerr_user_id"),
                "absence_confirmed": absence,
            },
        }),
    })


def test_first_dispatch_is_durable_and_reports_pending():
    table = Table()
    provider = RemoteExactProviderDeletionV2(table, clock=lambda: 1_700_000_000)

    with pytest.raises(LifecycleV2ExecutionError, match="provider_request_pending"):
        provider.delete_jellyfin(operation_id=OPERATION_ID, binding=binding())

    assert table.item["lifecycle_version"] == 2
    assert table.item["request_digest"]
    assert json.loads(table.item["request_json"])["path"] == f"/commands/{JELLYFIN_DELETE}"
    assert frozen_profile_provider_binding(table.item) == {
        "provider": "jellyfin",
        "connector_id": "connector-1",
        "provider_user_id": "0123456789abcdef0123456789abcdef",
    }


def test_retry_uses_same_request_and_accepts_exact_delete_receipt():
    table = Table()
    provider = RemoteExactProviderDeletionV2(table, clock=lambda: 1_700_000_000)
    with pytest.raises(LifecycleV2ExecutionError):
        provider.delete_jellyfin(operation_id=OPERATION_ID, binding=binding())
    request_id = table.item["request_id"]
    completed_response(table, command=JELLYFIN_DELETE, absence=False)

    provider.delete_jellyfin(operation_id=OPERATION_ID, binding=binding())

    assert table.item["request_id"] == request_id


def test_worker_poll_accepts_plugin_receipt_without_waiting_for_sqs_redelivery():
    table = Table()
    calls = 0

    def complete_once(_seconds):
        nonlocal calls
        calls += 1
        if calls == 1:
            completed_response(table, command=JELLYFIN_DELETE, absence=False)

    provider = RemoteExactProviderDeletionV2(
        table,
        clock=lambda: 1_700_000_000,
        poll_timeout_seconds=0.1,
        poll_interval_seconds=0.05,
        sleeper=complete_once,
    )

    provider.delete_jellyfin(operation_id=OPERATION_ID, binding=binding())

    assert calls == 1


def test_absence_requires_a_separate_exact_verification_receipt():
    table = Table()
    provider = RemoteExactProviderDeletionV2(table, clock=lambda: 1_700_000_000)
    with pytest.raises(LifecycleV2ExecutionError):
        provider.jellyfin_absent(operation_id=OPERATION_ID, binding=binding())
    completed_response(table, command=JELLYFIN_VERIFY, absence=False)

    with pytest.raises(LifecycleV2ExecutionError, match="provider_absence_unconfirmed"):
        provider.jellyfin_absent(operation_id=OPERATION_ID, binding=binding())


def test_frozen_binding_rejects_connector_drift():
    item = {
        "connector_id": "connector-1",
        "profile_id": "profile-1",
        "request_json": json.dumps({
            "path": f"/commands/{JELLYFIN_DELETE}",
            "body": {"profile_id": "profile-1"},
        }),
        "profile_provider_binding_json": json.dumps({
            "provider": "jellyfin",
            "connector_id": "connector-2",
            "provider_user_id": "0123456789abcdef0123456789abcdef",
        }),
    }

    with pytest.raises(LifecycleV2ExecutionError, match="frozen_provider_binding_invalid"):
        frozen_profile_provider_binding(item)

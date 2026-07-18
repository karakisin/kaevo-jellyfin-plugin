from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError


os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

HANDLER_PATH = Path(__file__).resolve().parents[1] / "src" / "handler.py"
SPEC = importlib.util.spec_from_file_location("kaevo_remote_state_handler", HANDLER_PATH)
assert SPEC is not None and SPEC.loader is not None
handler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handler)


class FakeRemoteRequests:
    def __init__(self, items):
        self.items = {item["request_id"]: dict(item) for item in items}

    def get_item(self, *, Key):
        item = self.items.get(Key["request_id"])
        return {"Item": dict(item)} if item else {}

    def query(self, **_):
        return {"Items": [dict(item) for item in self.items.values() if item["status"] == "pending"]}

    def update_item(self, *, Key, ExpressionAttributeValues, ReturnValues, **_):
        item = self.items.get(Key["request_id"])
        expected = ExpressionAttributeValues.get(":pending", ExpressionAttributeValues.get(":in_progress"))
        if not item or item.get("status") != expected:
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem")
        if ":now_epoch" in ExpressionAttributeValues and int(item.get("expires_at") or 0) < ExpressionAttributeValues[":now_epoch"]:
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem")
        if ":completing" in ExpressionAttributeValues:
            item["status"] = ExpressionAttributeValues[":completing"]
        elif ":failed" in ExpressionAttributeValues:
            item.update({
                "status": ExpressionAttributeValues[":failed"],
                "failed_at": ExpressionAttributeValues[":now"],
                "error_json": ExpressionAttributeValues[":error_json"],
            })
        else:
            item["status"] = ExpressionAttributeValues[":in_progress"]
        return {"Attributes": dict(item)}

    def put_item(self, *, Item, ExpressionAttributeValues=None, **_):
        existing = self.items.get(Item["request_id"])
        if ExpressionAttributeValues and (not existing or existing.get("status") != ExpressionAttributeValues[":completing"]):
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "PutItem")
        self.items[Item["request_id"]] = dict(Item)


def event(body):
    return {"headers": {"authorization": "Bearer connector-token"}, "body": json.dumps(body)}


def request_item(request_id, status, expires_at=None):
    now = handler.utc_now_iso()
    return {
        "request_id": request_id,
        "connector_id": "connector-1",
        "profile_id": "profile-1",
        "status": status,
        "status_created_at": handler.status_sort_key(status, now, request_id),
        "created_at": now,
        "expires_at": expires_at if expires_at is not None else handler.epoch_now() + 300,
    }


def test_expired_pending_request_cannot_be_claimed(monkeypatch):
    table = FakeRemoteRequests([request_item("expired", "pending", handler.epoch_now() - 1)])
    monkeypatch.setattr(handler, "remote_requests_table", table)
    monkeypatch.setattr(handler, "require_connector_auth", lambda _event, connector_id: connector_id == "connector-1")
    result = handler.claim_remote_request(event({"connector_id": "connector-1"}))
    assert result["statusCode"] == 200
    assert json.loads(result["body"])["state"] == "empty"
    assert table.items["expired"]["status"] == "pending"


def test_completion_and_failure_replays_cannot_overwrite_terminal_state(monkeypatch):
    complete_id = "complete-once"
    fail_id = "fail-once"
    table = FakeRemoteRequests([
        request_item(complete_id, "in_progress"),
        request_item(fail_id, "in_progress"),
    ])
    monkeypatch.setattr(handler, "remote_requests_table", table)
    monkeypatch.setattr(handler, "require_connector_auth", lambda _event, connector_id: connector_id == "connector-1")

    completed = handler.complete_remote_request(event({"connector_id": "connector-1", "response": {"ok": True}}), f"/v1/remote-requests/{complete_id}/complete")
    assert completed["statusCode"] == 200
    replayed_completion = handler.complete_remote_request(event({"connector_id": "connector-1", "response": {"ok": False}}), f"/v1/remote-requests/{complete_id}/complete")
    assert replayed_completion["statusCode"] == 409
    assert json.loads(table.items[complete_id]["response_json"])["ok"] is True

    failed = handler.fail_remote_request(event({"connector_id": "connector-1", "message": "first"}), f"/v1/remote-requests/{fail_id}/fail")
    assert failed["statusCode"] == 200
    replayed_failure = handler.fail_remote_request(event({"connector_id": "connector-1", "message": "second"}), f"/v1/remote-requests/{fail_id}/fail")
    assert replayed_failure["statusCode"] == 409
    assert json.loads(table.items[fail_id]["error_json"])["message"] == "first"

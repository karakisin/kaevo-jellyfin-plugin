from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path


os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

HANDLER_PATH = Path(__file__).resolve().parents[1] / "src" / "handler.py"
SPEC = importlib.util.spec_from_file_location("kaevo_cloud_pairing_handler", HANDLER_PATH)
assert SPEC is not None and SPEC.loader is not None
handler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handler)


class FakeTable:
    def __init__(self):
        self.items = {}

    def put_item(self, *, Item):
        self.items[Item["connector_id"]] = dict(Item)

    def get_item(self, *, Key):
        item = self.items.get(Key["connector_id"])
        return {"Item": dict(item)} if item else {}


def event(body: dict, *, dev_key: str | None = None, connector_token: str | None = None):
    headers = {}
    if dev_key:
        headers["x-kaevo-dev-key"] = dev_key
    if connector_token:
        headers["authorization"] = f"Bearer {connector_token}"
    return {"headers": headers, "body": json.dumps(body)}


def test_pairing_token_is_returned_once_and_only_hash_is_stored(monkeypatch):
    table = FakeTable()
    monkeypatch.setattr(handler, "home_connectors_table", table)
    monkeypatch.setattr(handler, "DEV_API_KEY", "development-user-key")

    started = handler.start_connector_pairing(event({"profile_id": "profile-1"}, dev_key="development-user-key"))
    started_body = json.loads(started["body"])
    assert started["statusCode"] == 201

    paired = handler.exchange_connector_pairing(
        event({"connector_id": started_body["connector_id"], "pairing_code": started_body["pairing_code"]})
    )
    paired_body = json.loads(paired["body"])
    assert paired["statusCode"] == 200
    assert len(paired_body["connector_token"]) >= 40
    assert len(paired_body["playback_grant_key"]) >= 40

    stored = table.items[started_body["connector_id"]]
    assert paired_body["connector_token"] not in str(stored)
    assert stored["playback_grant_key"] == paired_body["playback_grant_key"]
    assert "pairing_code_hash" not in stored
    assert handler.require_connector_auth(
        event({}, connector_token=paired_body["connector_token"]), started_body["connector_id"]
    )

    replay = handler.exchange_connector_pairing(
        event({"connector_id": started_body["connector_id"], "pairing_code": started_body["pairing_code"]})
    )
    assert replay["statusCode"] == 401


def test_wrong_token_and_revoked_connector_are_rejected(monkeypatch):
    table = FakeTable()
    monkeypatch.setattr(handler, "home_connectors_table", table)
    monkeypatch.setattr(handler, "DEV_API_KEY", "development-user-key")
    connector_id = "connector-1"
    table.put_item(Item={
        "connector_id": connector_id,
        "profile_id": "profile-1",
        "auth_state": "active",
        "revoked": False,
        "connector_token_hash": handler.secret_hash("correct-token"),
    })
    assert not handler.require_connector_auth(event({}, connector_token="wrong-token"), connector_id)
    revoked = handler.revoke_home_connector(
        event({}, dev_key="development-user-key"), f"/v1/home-connectors/{connector_id}/revoke"
    )
    assert revoked["statusCode"] == 200
    assert not handler.require_connector_auth(event({}, connector_token="correct-token"), connector_id)

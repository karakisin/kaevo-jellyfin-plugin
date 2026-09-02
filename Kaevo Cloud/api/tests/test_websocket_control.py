from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from boto3.dynamodb.types import TypeSerializer
from botocore.exceptions import ClientError

from websocket_control import common, notification_handler, socket_handler, ticket_handler


CONNECTOR_ID = "connector-control-v2"
HOUSEHOLD_BINDING = "household-binding-hash"
CONNECTION_ID = "connection-1"
SERIALIZER = TypeSerializer()


def conditional_failure(operation):
    return ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, operation)


class FakeConnectionsTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item, ConditionExpression=None, **_kwargs):
        key = Item["record_key"]
        if ConditionExpression and key in self.items:
            raise conditional_failure("PutItem")
        self.items[key] = dict(Item)
        return {}

    def get_item(self, Key, **_kwargs):
        item = self.items.get(Key["record_key"])
        return {"Item": dict(item)} if item else {}

    def update_item(self, Key, ConditionExpression=None, ExpressionAttributeValues=None, ReturnValues=None, **_kwargs):
        key = Key["record_key"]
        item = self.items.get(key)
        values = ExpressionAttributeValues or {}
        if item is None:
            raise conditional_failure("UpdateItem")
        if key.startswith("ticket#"):
            if item.get("used_at") is not None or item.get("expires_at", 0) < values[":now"]:
                raise conditional_failure("UpdateItem")
            if item.get("environment") != values[":environment"]:
                raise conditional_failure("UpdateItem")
            item.update({"used_at": values[":now"], "connection_id": values[":connection_id"]})
        else:
            if values.get(":connection_id") and item.get("connection_id") != values[":connection_id"]:
                raise conditional_failure("UpdateItem")
            if values.get(":connector_id") and item.get("connector_id") != values[":connector_id"]:
                raise conditional_failure("UpdateItem")
            item.update({
                "last_seen_at": values.get(":now", item.get("last_seen_at")),
                "expires_at": values.get(":expires_at", item.get("expires_at")),
            })
        self.items[key] = item
        return {"Attributes": dict(item)} if ReturnValues else {}

    def delete_item(self, Key, ConditionExpression=None, ExpressionAttributeValues=None, **_kwargs):
        key = Key["record_key"]
        item = self.items.get(key)
        if ConditionExpression and item and item.get("connection_id") != ExpressionAttributeValues[":connection_id"]:
            raise conditional_failure("DeleteItem")
        self.items.pop(key, None)
        return {}


class FakeConnectorTable:
    def __init__(self, family_binding=HOUSEHOLD_BINDING):
        self.item = {
            "connector_id": CONNECTOR_ID,
            "family_binding": family_binding,
            "state": "active",
            "auth_state": "v3_active",
            "revoked": False,
        }

    def get_item(self, Key, **_kwargs):
        return {"Item": dict(self.item)} if Key.get("connector_id") == CONNECTOR_ID else {}


class FakeRemoteRequestsTable:
    def __init__(self, item=None):
        self.item = item or {
            "request_id": "request-1",
            "connector_id": CONNECTOR_ID,
            "status": "pending",
            "expires_at": 10_000,
            "request_json": json.dumps({"provider": "jellyfin", "method": "GET", "path": "/System/Info"}),
        }
        self.claimed = False

    def get_item(self, Key, **_kwargs):
        return {"Item": dict(self.item)} if Key.get("request_id") == self.item["request_id"] else {}

    def update_item(self, **_kwargs):
        if self.claimed:
            raise conditional_failure("UpdateItem")
        self.claimed = True
        self.item["status"] = "in_progress"
        return {"Attributes": dict(self.item)}

    def query(self, **_kwargs):
        return {"Items": [dict(self.item)] if self.item.get("status") == "pending" else []}


class FakeManagementClient:
    class exceptions:
        class GoneException(Exception):
            pass

    def __init__(self, gone=False):
        self.messages = []
        self.gone = gone

    def post_to_connection(self, ConnectionId, Data):
        if self.gone:
            raise self.exceptions.GoneException()
        self.messages.append((ConnectionId, json.loads(Data)))


@pytest.fixture
def tables(monkeypatch):
    connections = FakeConnectionsTable()
    connectors = FakeConnectorTable()
    remotes = FakeRemoteRequestsTable()
    monkeypatch.setattr(common, "connections_table", connections)
    monkeypatch.setattr(common, "home_connectors_table", connectors)
    monkeypatch.setattr(common, "remote_requests_table", remotes)
    monkeypatch.setattr(common, "CONTROL_WEBSOCKET_URL", "wss://control.example/dev")
    monkeypatch.setattr(common, "KAEVO_ENV", "dev")
    monkeypatch.setattr(common, "epoch_now", lambda: 1_000)
    monkeypatch.setattr(ticket_handler.connector_control, "remote_requests_table", remotes)
    monkeypatch.setattr(ticket_handler.connector_control, "epoch_now", lambda: 1_000)
    monkeypatch.setattr(ticket_handler.connector_control, "utc_now_iso", lambda: "2026-09-02T00:00:00Z")
    monkeypatch.setattr(ticket_handler.connector_control, "_mirror_binding_operation", lambda *_args: None)
    return connections, connectors, remotes


def http_event(path, body):
    return {
        "rawPath": path,
        "requestContext": {"http": {"method": "POST"}},
        "body": json.dumps(body),
    }


def websocket_event(route_key, *, connection_id=CONNECTION_ID, headers=None, body=None):
    return {
        "headers": headers or {},
        "body": json.dumps(body or {}),
        "requestContext": {
            "routeKey": route_key,
            "connectionId": connection_id,
            "domainName": "control.example",
            "stage": "dev",
        },
    }


def test_signed_ticket_is_short_lived_bound_and_never_logged(tables, monkeypatch, caplog):
    monkeypatch.setattr(
        ticket_handler.connector_control,
        "authenticate_connector",
        lambda *_args: {
            "connector_id": CONNECTOR_ID,
            "family_binding": HOUSEHOLD_BINDING,
        },
    )
    caplog.set_level(logging.INFO)
    response = ticket_handler.issue_ticket(
        http_event("ignored", {
            "connector_id": CONNECTOR_ID,
            "connector_control_protocol": 2,
        }),
        CONNECTOR_ID,
    )
    payload = json.loads(response["body"])
    assert response["statusCode"] == 201
    assert payload["control_websocket_url"] == "wss://control.example/dev"
    assert payload["expires_at"] == 1_090
    ticket = payload["connection_ticket"]
    stored = tables[0].items[f"ticket#{common.ticket_digest(ticket)}"]
    assert stored["connector_id"] == CONNECTOR_ID
    assert stored["household_binding"] == HOUSEHOLD_BINDING
    assert ticket not in caplog.text


def test_old_protocol_is_authenticated_then_requires_upgrade(tables, monkeypatch):
    calls = []
    monkeypatch.setattr(
        ticket_handler.connector_control,
        "authenticate_connector",
        lambda *_args: calls.append(True) or {
            "connector_id": CONNECTOR_ID,
            "family_binding": HOUSEHOLD_BINDING,
        },
    )
    response = ticket_handler.issue_ticket(
        http_event("ignored", {"connector_id": CONNECTOR_ID}), CONNECTOR_ID,
    )
    assert calls == [True]
    assert response["statusCode"] == 426
    assert response["headers"]["Retry-After"] == "60"


def test_connection_ticket_is_one_time_and_replay_fails(tables):
    ticket = "one-time-ticket"
    tables[0].items[f"ticket#{common.ticket_digest(ticket)}"] = {
        "record_key": f"ticket#{common.ticket_digest(ticket)}",
        "record_type": "connector_control_ticket",
        "connector_id": CONNECTOR_ID,
        "household_binding": HOUSEHOLD_BINDING,
        "environment": "dev",
        "connector_control_protocol": 2,
        "expires_at": 1_090,
    }
    event = websocket_event("$connect", headers={"Authorization": f"Bearer {ticket}"})
    assert socket_handler.connect(event)["statusCode"] == 200
    assert socket_handler.connect(event)["statusCode"] == 401
    assert tables[0].items[f"connector#{CONNECTOR_ID}"]["connection_id"] == CONNECTION_ID


def test_expired_or_wrong_environment_ticket_fails_closed(tables):
    for suffix, environment, expires_at in (("expired", "dev", 999), ("wrong-env", "production", 1_090)):
        ticket = f"ticket-{suffix}"
        tables[0].items[f"ticket#{common.ticket_digest(ticket)}"] = {
            "record_key": f"ticket#{common.ticket_digest(ticket)}",
            "record_type": "connector_control_ticket",
            "connector_id": CONNECTOR_ID,
            "household_binding": HOUSEHOLD_BINDING,
            "environment": environment,
            "connector_control_protocol": 2,
            "expires_at": expires_at,
        }
        event = websocket_event("$connect", headers={"Authorization": f"Bearer {ticket}"})
        assert socket_handler.connect(event)["statusCode"] == 401


def test_connection_rechecks_current_household_before_accepting_ticket(tables):
    ticket = "stale-household-ticket"
    tables[0].items[f"ticket#{common.ticket_digest(ticket)}"] = {
        "record_key": f"ticket#{common.ticket_digest(ticket)}",
        "record_type": "connector_control_ticket",
        "connector_id": CONNECTOR_ID,
        "household_binding": "former-household",
        "environment": "dev",
        "connector_control_protocol": 2,
        "expires_at": 1_090,
    }
    event = websocket_event("$connect", headers={"Authorization": f"Bearer {ticket}"})
    assert socket_handler.connect(event)["statusCode"] == 401
    assert f"connector#{CONNECTOR_ID}" not in tables[0].items


def test_exact_claim_is_connector_bound_and_duplicate_safe(tables, monkeypatch):
    monkeypatch.setattr(ticket_handler.connector_control, "authenticate_connector", lambda *_args: {"connector_id": CONNECTOR_ID})
    event = http_event("ignored", {
        "connector_id": CONNECTOR_ID,
        "connector_control_protocol": 2,
    })
    first = ticket_handler.claim_exact(event, "request-1")
    second = ticket_handler.claim_exact(event, "request-1")
    assert first["statusCode"] == 200
    assert second["statusCode"] == 409


def test_exact_claim_rejects_expired_request_without_transition(tables, monkeypatch):
    tables[2].item["expires_at"] = 999
    monkeypatch.setattr(ticket_handler.connector_control, "authenticate_connector", lambda *_args: {"connector_id": CONNECTOR_ID})
    response = ticket_handler.claim_exact(http_event("ignored", {
        "connector_id": CONNECTOR_ID,
        "connector_control_protocol": 2,
    }), "request-1")
    assert response["statusCode"] == 410
    assert tables[2].claimed is False


def test_notification_checks_current_household_binding(tables, monkeypatch):
    tables[0].items[f"connector#{CONNECTOR_ID}"] = {
        "record_key": f"connector#{CONNECTOR_ID}",
        "connection_id": CONNECTION_ID,
        "environment": "dev",
        "household_binding": HOUSEHOLD_BINDING,
        "expires_at": 2_000,
    }
    client = FakeManagementClient()
    monkeypatch.setattr(common.boto3, "client", lambda *_args, **_kwargs: client)
    image = {key: SERIALIZER.serialize(value) for key, value in tables[2].item.items()}
    record = {"eventName": "INSERT", "dynamodb": {"NewImage": image, "SequenceNumber": "1"}}
    notification_handler.notify_pending_request(record)
    assert client.messages[0][0] == CONNECTION_ID
    assert client.messages[0][1] == {
        "type": "remote_request_available",
        "request_id": "request-1",
        "connector_control_protocol": 2,
    }

    client.messages.clear()
    tables[1].item["family_binding"] = "different-household"
    notification_handler.notify_pending_request(record)
    assert client.messages == []


def test_stale_gateway_connection_is_removed_after_gone_response(tables, monkeypatch):
    tables[0].items[f"connector#{CONNECTOR_ID}"] = {
        "record_key": f"connector#{CONNECTOR_ID}",
        "connector_id": CONNECTOR_ID,
        "connection_id": CONNECTION_ID,
        "environment": "dev",
        "household_binding": HOUSEHOLD_BINDING,
        "expires_at": 2_000,
    }
    tables[0].items[f"connection#{CONNECTION_ID}"] = {
        "record_key": f"connection#{CONNECTION_ID}",
        "connector_id": CONNECTOR_ID,
        "connection_id": CONNECTION_ID,
        "expires_at": 2_000,
    }
    monkeypatch.setattr(common.boto3, "client", lambda *_args, **_kwargs: FakeManagementClient(gone=True))
    image = {key: SERIALIZER.serialize(value) for key, value in tables[2].item.items()}
    notification_handler.notify_pending_request({"eventName": "INSERT", "dynamodb": {"NewImage": image}})
    assert f"connector#{CONNECTOR_ID}" not in tables[0].items
    assert f"connection#{CONNECTION_ID}" not in tables[0].items


def test_disconnect_removes_only_the_current_connection(tables):
    tables[0].items[f"connector#{CONNECTOR_ID}"] = {
        "record_key": f"connector#{CONNECTOR_ID}",
        "connector_id": CONNECTOR_ID,
        "connection_id": CONNECTION_ID,
    }
    tables[0].items[f"connection#{CONNECTION_ID}"] = {
        "record_key": f"connection#{CONNECTION_ID}",
        "connector_id": CONNECTOR_ID,
        "connection_id": CONNECTION_ID,
    }
    assert socket_handler.disconnect(websocket_event("$disconnect"))["statusCode"] == 200
    assert f"connector#{CONNECTOR_ID}" not in tables[0].items
    assert f"connection#{CONNECTION_ID}" not in tables[0].items


def test_recover_sends_only_opaque_pending_identifiers(tables, monkeypatch):
    tables[0].items[f"connector#{CONNECTOR_ID}"] = {
        "record_key": f"connector#{CONNECTOR_ID}",
        "record_type": "active_connector_control_connection",
        "connector_id": CONNECTOR_ID,
        "connection_id": CONNECTION_ID,
        "environment": "dev",
        "household_binding": HOUSEHOLD_BINDING,
        "expires_at": 2_000,
    }
    tables[0].items[f"connection#{CONNECTION_ID}"] = {
        **tables[0].items[f"connector#{CONNECTOR_ID}"],
        "record_key": f"connection#{CONNECTION_ID}",
    }
    client = FakeManagementClient()
    monkeypatch.setattr(common, "management_client", lambda _event: client)
    response = socket_handler.ping_or_recover(websocket_event("recover", body={
        "action": "recover",
        "connector_control_protocol": 2,
    }))
    assert response["statusCode"] == 200
    assert client.messages == [(CONNECTION_ID, {
        "type": "remote_request_available",
        "request_id": "request-1",
        "connector_control_protocol": 2,
    })]


def test_plugin_source_has_no_healthy_empty_poll_loop_and_marks_recovery_explicitly():
    repository = Path(__file__).resolve().parents[3]
    source = (repository / "Kaevo Jellyfin Plugin/src/Kaevo.Plugin.KaevoForJellyfin/Services/KaevoCloudConnectorService.cs").read_text()
    assert "TimeSpan.FromMilliseconds(250)" not in source
    assert source.count('"/v1/remote-requests/claim"') == 2  # recovery call plus error-category mapping
    assert "recovery = true" in source
    assert "DisconnectedRecoveryMinimumSeconds = 60" in source

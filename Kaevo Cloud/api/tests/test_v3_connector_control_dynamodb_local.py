from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor

import boto3
import pytest

import pairing_v3
from connector_control import connector_control_handler as control


ENDPOINT = os.environ.get("KAEVO_DYNAMODB_LOCAL_ENDPOINT")
pytestmark = pytest.mark.skipif(not ENDPOINT, reason="DynamoDB Local endpoint not configured")
SEED = b"C" * 32
CONNECTOR_ID = "ddb-control-connector"
PROFILE_ID = "ddb-control-profile"


class RecordingS3:
    def __init__(self):
        self.objects = []

    def put_object(self, **kwargs):
        self.objects.append(kwargs)
        return {}


def resource():
    return boto3.resource(
        "dynamodb", endpoint_url=ENDPOINT, region_name="us-west-2",
        aws_access_key_id="testing", aws_secret_access_key="testing",
    )


@pytest.fixture
def control_tables(monkeypatch):
    ddb = resource()
    client = ddb.meta.client
    definitions = {
        "v3-control-connectors": ({"AttributeName": "connector_id", "AttributeType": "S"},),
        "v3-control-sessions": ({"AttributeName": "token_hash", "AttributeType": "S"},),
        "v3-control-profiles": ({"AttributeName": "profile_id", "AttributeType": "S"},),
    }
    tables = {}
    for name, attributes in definitions.items():
        key = attributes[0]["AttributeName"]
        try:
            client.delete_table(TableName=name)
            client.get_waiter("table_not_exists").wait(TableName=name)
        except client.exceptions.ResourceNotFoundException:
            pass
        client.create_table(
            TableName=name, BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": key, "KeyType": "HASH"}], AttributeDefinitions=list(attributes),
        )
        client.get_waiter("table_exists").wait(TableName=name)
        tables[name] = ddb.Table(name)
    remote_name = "v3-control-remotes"
    try:
        client.delete_table(TableName=remote_name)
        client.get_waiter("table_not_exists").wait(TableName=remote_name)
    except client.exceptions.ResourceNotFoundException:
        pass
    client.create_table(
        TableName=remote_name, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "request_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "request_id", "AttributeType": "S"},
            {"AttributeName": "connector_id", "AttributeType": "S"},
            {"AttributeName": "status_created_at", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "connector_id-status_created_at-index",
            "KeySchema": [
                {"AttributeName": "connector_id", "KeyType": "HASH"},
                {"AttributeName": "status_created_at", "KeyType": "RANGE"},
            ], "Projection": {"ProjectionType": "ALL"},
        }],
    )
    client.get_waiter("table_exists").wait(TableName=remote_name)
    tables[remote_name] = ddb.Table(remote_name)
    public = pairing_v3.ed25519_public_key_from_seed(SEED)
    tables["v3-control-connectors"].put_item(Item={
        "connector_id": CONNECTOR_ID, "protocol_version": pairing_v3.PROTOCOL,
        "auth_state": "v3_active", "state": "active", "revoked": False,
        "plugin_public_key": pairing_v3.b64url_encode(public),
        "plugin_public_key_fingerprint": pairing_v3.plugin_fingerprint(public),
        "plugin_instance_id": "ddb-control-plugin", "plugin_key_id": "1", "server_id": "ddb-control-server",
        "account_binding": pairing_v3.sha256_b64url(b"ddb-control-account"),
        "family_binding": pairing_v3.sha256_b64url(b"ddb-control-family"),
    })
    tables["v3-control-profiles"].put_item(Item={
        "profile_id": PROFILE_ID, "account_id": "ddb-control-account", "household_id": "ddb-control-family",
    })
    monkeypatch.setattr(control, "dynamodb", ddb)
    monkeypatch.setattr(control, "home_connectors_table", tables["v3-control-connectors"])
    monkeypatch.setattr(control, "app_sessions_table", tables["v3-control-sessions"])
    monkeypatch.setattr(control, "identity_profiles_table", tables["v3-control-profiles"])
    monkeypatch.setattr(control, "remote_requests_table", tables[remote_name])
    monkeypatch.setattr(control, "PLAYBACK_GRANT_SIGNING_KEY", "R" * 32)
    yield tables
    for table in tables.values():
        table.delete()


def event(route, body, nonce):
    timestamp = str(control.epoch_now() * 1000)
    transcript = pairing_v3.canonical_transcript("connector-request", (
        ("httpMethod", "POST"), ("canonicalRoute", route),
        ("bodyDigest", pairing_v3.canonical_json_digest(body)), ("timestamp", timestamp),
        ("nonce", nonce), ("connectorId", CONNECTOR_ID), ("pluginInstanceId", "ddb-control-plugin"),
        ("pluginKeyId", "1"),
        ("pluginPublicKeyFingerprint", pairing_v3.plugin_fingerprint(pairing_v3.ed25519_public_key_from_seed(SEED))),
    ))
    return {
        "rawPath": route, "requestContext": {"http": {"method": "POST"}}, "body": json.dumps(body),
        "headers": {
            "X-Kaevo-Plugin-Key-Id": "1", "X-Kaevo-Plugin-Timestamp": timestamp,
            "X-Kaevo-Plugin-Nonce": nonce, "X-Kaevo-Plugin-Signature": pairing_v3.sign_ed25519(SEED, transcript),
        },
    }


def test_dynamodb_connector_control_concurrency_replay_and_transitions(control_tables):
    connectors = control_tables["v3-control-connectors"]
    remotes = control_tables["v3-control-remotes"]
    register_route = "/v3/home-connectors/register"
    register_body = {"connector_id": CONNECTOR_ID, "profile_id": PROFILE_ID, "provider_status": {}}
    requests = [event(register_route, register_body, f"ddbcontrolregistrationnonce00000{index}") for index in range(2)]
    with ThreadPoolExecutor(max_workers=2) as executor:
        registration = list(executor.map(lambda request: control.lambda_handler(request, None), requests))
    assert [result["statusCode"] for result in registration] == [200, 200]
    connector_items = connectors.scan().get("Items", [])
    assert len(connector_items) == 1
    assert connector_items[0]["connector_id"] == CONNECTOR_ID
    assert connector_items[0]["profile_id"] == PROFILE_ID

    # Idempotent retry returns the same connector; a conflicting profile never overwrites it.
    retry = control.lambda_handler(event(register_route, register_body, "ddbcontrolregistrationnonce000003"), None)
    assert json.loads(retry["body"])["connector"]["connector_id"] == CONNECTOR_ID
    conflict = control.lambda_handler(event(register_route, {**register_body, "profile_id": "conflict"}, "ddbcontrolregistrationnonce000004"), None)
    assert conflict["statusCode"] == 403
    assert connectors.get_item(Key={"connector_id": CONNECTOR_ID}, ConsistentRead=True)["Item"]["profile_id"] == PROFILE_ID

    heartbeat_route = f"/v3/home-connectors/{CONNECTOR_ID}/heartbeat"
    heartbeat = event(heartbeat_route, register_body, "ddbcontrolheartbeatnonce00000001")
    assert control.lambda_handler(heartbeat, None)["statusCode"] == 200
    assert control.lambda_handler(heartbeat, None)["statusCode"] == 401
    relay_route = f"/v3/home-connectors/{CONNECTOR_ID}/relay-ticket"
    relay = event(relay_route, {"connector_id": CONNECTOR_ID}, "ddbcontrolrelayticketnonce000001")
    assert control.lambda_handler(relay, None)["statusCode"] == 201
    assert control.lambda_handler(relay, None)["statusCode"] == 401

    remotes.put_item(Item={
        "request_id": "ddb-remote-claim", "connector_id": CONNECTOR_ID, "profile_id": PROFILE_ID,
        "status": "pending", "status_created_at": "pending#050#2026-01-01T00:00:00Z#ddb-remote-claim",
        "expires_at": control.epoch_now() + 60, "request_json": "{}",
    })
    claims = [event("/v3/remote-requests/claim", {"connector_id": CONNECTOR_ID}, f"ddbcontrolclaimnonce0000000000{index}") for index in range(2)]
    with ThreadPoolExecutor(max_workers=2) as executor:
        claim_results = list(executor.map(lambda request: control.lambda_handler(request, None), claims))
    assert sorted(json.loads(result["body"])["state"] for result in claim_results) == ["claimed", "empty"]

    remotes.put_item(Item={
        "request_id": "ddb-remote-complete", "connector_id": CONNECTOR_ID, "profile_id": PROFILE_ID,
        "status": "in_progress", "status_created_at": "in_progress#1", "expires_at": control.epoch_now() + 60,
        "request_json": "{}",
    })
    complete_route = "/v3/remote-requests/ddb-remote-complete/complete"
    complete = control.lambda_handler(event(complete_route, {"connector_id": CONNECTOR_ID, "response": {"ok": True}}, "ddbcontrolcompletenonce00000001"), None)
    assert json.loads(complete["body"])["state"] == "completed"
    remotes.put_item(Item={
        "request_id": "ddb-remote-fail", "connector_id": CONNECTOR_ID, "profile_id": PROFILE_ID,
        "status": "in_progress", "status_created_at": "in_progress#2", "expires_at": control.epoch_now() + 60,
        "request_json": "{}",
    })
    fail_route = "/v3/remote-requests/ddb-remote-fail/fail"
    failed = control.lambda_handler(event(fail_route, {"connector_id": CONNECTOR_ID, "message": "bounded"}, "ddbcontrolfailnonce00000000001"), None)
    assert json.loads(failed["body"])["state"] == "failed"
    final = remotes.scan().get("Items", [])
    assert len(final) == 3
    assert len({item["request_id"] for item in final}) == 3


def test_dynamodb_s3_backed_completion_uses_disjoint_response_attributes(control_tables, monkeypatch):
    remotes = control_tables["v3-control-remotes"]
    request_id = "ddb-remote-s3-complete"
    remotes.put_item(Item={
        "request_id": request_id, "connector_id": CONNECTOR_ID, "profile_id": PROFILE_ID,
        "status": "in_progress", "status_created_at": "in_progress#3", "expires_at": control.epoch_now() + 60,
        "request_json": "{}", "response_json": "stale", "response_gzip_base64": "stale",
    })
    storage = RecordingS3()
    monkeypatch.setattr(control, "REMOTE_RESPONSE_COMPRESS_THRESHOLD_BYTES", 1)
    monkeypatch.setattr(control, "REMOTE_PAYLOADS_BUCKET", "test-remote-payloads")
    monkeypatch.setattr(control, "s3_client", storage)

    route = f"/v3/remote-requests/{request_id}/complete"
    result = control.lambda_handler(
        event(route, {"connector_id": CONNECTOR_ID, "response": {"payload": "x" * 512}}, "ddbcontrols3completionnonce01"),
        None,
    )

    assert result["statusCode"] == 200
    assert json.loads(result["body"])["state"] == "completed"
    item = remotes.get_item(Key={"request_id": request_id}, ConsistentRead=True)["Item"]
    assert item["status"] == "completed"
    assert item["response_encoding"] == "s3+gzip"
    assert item["response_s3_key"].endswith(f"/{request_id}.json.gz")
    assert item["response_stored_bytes"] > 0
    assert "response_json" not in item
    assert "response_gzip_base64" not in item
    assert len(storage.objects) == 1

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor

import boto3
import pytest

import handler
import pairing_v3


ENDPOINT = os.environ.get("KAEVO_DYNAMODB_LOCAL_ENDPOINT")
pytestmark = pytest.mark.skipif(not ENDPOINT, reason="DynamoDB Local endpoint not configured")


def resource():
    return boto3.resource("dynamodb", endpoint_url=ENDPOINT, region_name="us-west-2", aws_access_key_id="testing", aws_secret_access_key="testing")


def event(route, body, headers=None):
    return {"rawPath": route, "requestContext": {"http": {"method": "POST"}}, "headers": headers or {}, "body": json.dumps(body)}


@pytest.fixture
def local_v3_tables(monkeypatch):
    dynamo = resource()
    client = dynamo.meta.client
    tables = {}
    for name, key in (("pairing-v3-sessions", "token_hash"), ("pairing-v3-connectors", "connector_id")):
        try:
            client.delete_table(TableName=name)
            client.get_waiter("table_not_exists").wait(TableName=name)
        except client.exceptions.ResourceNotFoundException:
            pass
        client.create_table(TableName=name, BillingMode="PAY_PER_REQUEST", KeySchema=[{"AttributeName": key, "KeyType": "HASH"}], AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}])
        client.get_waiter("table_exists").wait(TableName=name)
        tables[name] = dynamo.Table(name)
    monkeypatch.setattr(handler, "dynamodb", dynamo)
    monkeypatch.setattr(handler, "app_sessions_table", tables["pairing-v3-sessions"])
    monkeypatch.setattr(handler, "home_connectors_table", tables["pairing-v3-connectors"])
    monkeypatch.setattr(handler, "PAIRING_V3_AUTHORIZATION_SIGNING_SEED", pairing_v3.b64url_encode(b"A" * 32))
    monkeypatch.setattr(handler, "PAIRING_V3_AUTHORIZATION_KEY_ID", "dynamodb-local-vector")
    monkeypatch.setattr(handler, "KAEVO_ENV", "test")
    monkeypatch.setattr(handler, "pairing_v3_entitled", lambda _session: True)
    monkeypatch.setattr(handler, "owner_bound_session", lambda _event: ({"role": "owner", "principal_id": "owner-1", "account_id": "account-1", "household_id": "family-1", "family_id": "owner-session-1", "device_id": "ios-device-1", "profile_id": "profile-1"}, None))
    yield tables
    for table in tables.values():
        table.delete()


def bindings():
    public = pairing_v3.ed25519_public_key_from_seed(b"B" * 32)
    return {"protocol": pairing_v3.PROTOCOL, "pairingAttemptId": "123e4567-e89b-12d3-a456-426614174000", "ticketId": "ticket-v3-ddb-01", "pluginInstanceId": "plugin-v3-ddb-01", "pluginPublicKeyFingerprint": pairing_v3.plugin_fingerprint(public), "jellyfinServerId": "server-v3-ddb-01", "jellyfinUserId": "jellyfin-user-1", "iosDeviceId": "ios-device-1"}


def redemption(authorization, nonce):
    public = pairing_v3.ed25519_public_key_from_seed(b"B" * 32)
    claims = handler.pairing_v3_verify_authorization_claims(authorization, handler.epoch_now()).claims
    body = {**bindings(), "authorization": authorization, "pluginPublicKey": pairing_v3.b64url_encode(public), "pluginKeyId": "1"}
    timestamp = str(handler.epoch_now() * 1000)
    signature = pairing_v3.sign_ed25519(b"B" * 32, pairing_v3.redemption_transcript(method="POST", route="/v3/home-connectors/pairing/redemptions", body_digest=pairing_v3.canonical_json_digest(body), timestamp=timestamp, nonce=nonce, pairing_attempt_id=body["pairingAttemptId"], authorization_jti=claims["jti"], plugin_instance_id=body["pluginInstanceId"], plugin_public_key_fingerprint=body["pluginPublicKeyFingerprint"], jellyfin_server_id=body["jellyfinServerId"]))
    return event("/v3/home-connectors/pairing/redemptions", body, {"X-Kaevo-Plugin-Timestamp": timestamp, "X-Kaevo-Plugin-Nonce": nonce, "X-Kaevo-Plugin-Signature": signature})


def test_dynamodb_transaction_allows_one_enrollment_under_concurrent_redemption(local_v3_tables):
    issued = handler.issue_home_connector_pairing_authorization_v3(event("/v3/home-connectors/pairing/authorizations", bindings()))
    assert issued["statusCode"] == 201
    authorization = json.loads(issued["body"])["authorization"]
    requests = [redemption(authorization, f"abcdefghijklmnopqrstuvwxyz0123{i:02d}") for i in range(2)]
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(handler.redeem_home_connector_pairing_v3, requests))
    assert sorted(result["statusCode"] for result in results) == [201, 409]
    connectors = local_v3_tables["pairing-v3-connectors"].scan().get("Items", [])
    assert len([item for item in connectors if item.get("record_type") != "pairing_v3_plugin_binding"]) == 1
    records = local_v3_tables["pairing-v3-sessions"].scan().get("Items", [])
    assert len([item for item in records if item.get("record_type") == "pairing_v3_authorization" and item.get("state") == "redeemed"]) == 1

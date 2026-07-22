from __future__ import annotations

import base64
import json
import logging
import os
import uuid
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

# Keep unit tests independent from the workstation's SSO credential provider.
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

import pairing_v3
import handler


VECTOR_PATH = Path(__file__).resolve().parents[2] / "docs" / "PAIRING_V3_TEST_VECTORS.json"
SIGNING_SEED = b"A" * 32
PLUGIN_SEED = b"B" * 32


class FakeTable:
    def __init__(self, name, key):
        self.name = name
        self.key = key
        self.items = {}

    def put_item(self, *, Item, ConditionExpression=None, **_):
        key = Item[self.key]
        if ConditionExpression and "attribute_not_exists" in ConditionExpression and key in self.items:
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "PutItem")
        self.items[key] = dict(Item)

    def get_item(self, *, Key, **_):
        item = self.items.get(Key[self.key])
        return {"Item": dict(item)} if item else {}


def client_error(code):
    return ClientError({"Error": {"Code": code}}, "TransactWriteItems")


@pytest.fixture
def v3_tables(monkeypatch):
    sessions = FakeTable("sessions", "token_hash")
    connectors = FakeTable("connectors", "connector_id")
    monkeypatch.setattr(handler, "app_sessions_table", sessions)
    monkeypatch.setattr(handler, "home_connectors_table", connectors)
    monkeypatch.setattr(handler, "PAIRING_V3_AUTHORIZATION_SIGNING_SEED", pairing_v3.b64url_encode(SIGNING_SEED))
    monkeypatch.setattr(handler, "PAIRING_V3_AUTHORIZATION_KEY_ID", "vector-key-1")
    monkeypatch.setattr(handler, "KAEVO_ENV", "test")
    monkeypatch.setattr(handler, "pairing_v3_entitled", lambda _session: True)
    monkeypatch.setattr(handler, "owner_bound_session", lambda _event: ({
        "role": "owner", "principal_id": "owner-1", "account_id": "account-1", "household_id": "family-1",
        "family_id": "session-family-1", "device_id": "ios-device-1", "profile_id": "profile-1",
    }, None))

    def transact(writes):
        staged = {sessions.name: dict(sessions.items), connectors.name: dict(connectors.items)}
        tables = {sessions.name: sessions, connectors.name: connectors}
        for write in writes:
            table = tables[write["table"]]
            item = write.get("item") or write["key"]
            key = item[table.key]
            existing = staged[table.name].get(key)
            condition = write.get("condition") or ""
            if "attribute_not_exists" in condition and existing:
                raise client_error("TransactionCanceledException")
            if "#state = :active" in condition and (not existing or existing.get("state") != "active"):
                raise client_error("TransactionCanceledException")
            if write.get("kind") == "update":
                updated = dict(existing or {})
                updated.update({"state": "redeemed", "redeemed_at": write["values"][":redeemed_at"]})
                staged[table.name][key] = updated
            else:
                staged[table.name][key] = dict(item)
        sessions.items = staged[sessions.name]
        connectors.items = staged[connectors.name]

    monkeypatch.setattr(handler, "pairing_v3_transact_write", transact)
    return sessions, connectors


def event(route, body, headers=None):
    return {
        "rawPath": route,
        "requestContext": {"http": {"method": "POST"}},
        "headers": headers or {},
        "body": json.dumps(body),
    }


def bindings():
    return {
        "protocol": "kaevo-pairing-v3",
        "pairingAttemptId": "123e4567-e89b-12d3-a456-426614174000",
        "ticketId": "ticket-v3-test-01",
        "pluginInstanceId": "plugin-v3-test-01",
        "pluginPublicKeyFingerprint": pairing_v3.plugin_fingerprint(pairing_v3.ed25519_public_key_from_seed(PLUGIN_SEED)),
        "jellyfinServerId": "jellyfin-v3-test-01",
        "jellyfinUserId": "jellyfin-user-1",
        "iosDeviceId": "ios-device-1",
    }


def issue_authorization():
    issued = handler.issue_home_connector_pairing_authorization_v3(event("/v3/home-connectors/pairing/authorizations", bindings()))
    assert issued["statusCode"] == 201
    return json.loads(issued["body"])["authorization"]


def signed_redemption(authorization, *, nonce="abcdefghijklmnopqrstuvwxyz012345", jellyfin_user="jellyfin-user-1"):
    public = pairing_v3.ed25519_public_key_from_seed(PLUGIN_SEED)
    claims = handler.pairing_v3_verify_authorization_claims(authorization, handler.epoch_now()).claims
    body = {
        **bindings(), "authorization": authorization, "pluginPublicKey": pairing_v3.b64url_encode(public),
        "jellyfinUserId": jellyfin_user, "pluginKeyId": "1",
    }
    route = "/v3/home-connectors/pairing/redemptions"
    timestamp = str(handler.epoch_now() * 1000)
    transcript = pairing_v3.redemption_transcript(
        method="POST", route=route, body_digest=pairing_v3.canonical_json_digest(body), timestamp=timestamp,
        nonce=nonce, pairing_attempt_id=body["pairingAttemptId"], authorization_jti=claims["jti"],
        plugin_instance_id=body["pluginInstanceId"], plugin_public_key_fingerprint=body["pluginPublicKeyFingerprint"],
        jellyfin_server_id=body["jellyfinServerId"],
    )
    return event(route, body, {
        "X-Kaevo-Plugin-Timestamp": timestamp, "X-Kaevo-Plugin-Nonce": nonce,
        "X-Kaevo-Plugin-Signature": pairing_v3.sign_ed25519(PLUGIN_SEED, transcript),
    })


def signed_connector_request(route, body, *, nonce="connectorrequestnonce0123456789"):
    timestamp = str(handler.epoch_now() * 1000)
    connector_id = str(body["connector_id"])
    fingerprint = bindings()["pluginPublicKeyFingerprint"]
    transcript = pairing_v3.canonical_transcript("connector-request", (
        ("httpMethod", "POST"), ("canonicalRoute", route),
        ("bodyDigest", pairing_v3.canonical_json_digest(body)), ("timestamp", timestamp),
        ("nonce", nonce), ("connectorId", connector_id),
        ("pluginInstanceId", bindings()["pluginInstanceId"]), ("pluginKeyId", "1"),
        ("pluginPublicKeyFingerprint", fingerprint),
    ))
    return event(route, body, {
        "X-Kaevo-Plugin-Key-Id": "1", "X-Kaevo-Plugin-Timestamp": timestamp,
        "X-Kaevo-Plugin-Nonce": nonce,
        "X-Kaevo-Plugin-Signature": pairing_v3.sign_ed25519(PLUGIN_SEED, transcript),
    })


def test_fixed_vector_matches_hkdf_public_key_transcript_and_signature():
    vector = json.loads(VECTOR_PATH.read_text())
    kdf = vector["challengeSigningKdf"]
    seed = pairing_v3.derive_challenge_signing_seed(bytes.fromhex(kdf["ikmHex"]), kdf["ticketIdUtf8"])
    assert seed.hex() == kdf["expectedSeedHex"]
    public = pairing_v3.ed25519_public_key_from_seed(seed)
    assert pairing_v3.b64url_encode(public) == vector["ed25519"]["expectedPublicKeyBase64url"]
    assert pairing_v3.plugin_fingerprint(public) == vector["ed25519"]["expectedFingerprint"]
    transcript = pairing_v3.challenge_transcript(**{
        "ticket_id": vector["challengeTranscript"]["values"]["ticketId"],
        "challenge_id": vector["challengeTranscript"]["values"]["challengeId"],
        "challenge_nonce": vector["challengeTranscript"]["values"]["challengeNonce"],
        "pairing_attempt_id": vector["challengeTranscript"]["values"]["pairingAttemptId"],
        "plugin_instance_id": vector["challengeTranscript"]["values"]["pluginInstanceId"],
        "plugin_public_key_fingerprint": vector["challengeTranscript"]["values"]["pluginPublicKeyFingerprint"],
        "jellyfin_server_id": vector["challengeTranscript"]["values"]["jellyfinServerId"],
        "issued_at": vector["challengeTranscript"]["values"]["challengeIssuedAt"],
        "expires_at": vector["challengeTranscript"]["values"]["challengeExpiresAt"],
        "local_completion_route": vector["challengeTranscript"]["values"]["localCompletionRoute"],
        "pairing_authorization_hash": vector["challengeTranscript"]["values"]["pairingAuthorizationHash"],
    })
    signature = pairing_v3.sign_ed25519(seed, transcript)
    assert signature == vector["challengeTranscript"]["expectedSignatureBase64url"]
    pairing_v3.verify_ed25519(public, transcript, signature)


@pytest.mark.parametrize("value", ["ABC", "123e4567-e89b-12d3-a456-426614174000\\n", "123E4567-E89B-12D3-A456-426614174000"])
def test_correlation_values_are_canonical_or_replaced(value):
    correlation = handler.pairing_v3_correlation_id({"headers": {"X-Kaevo-Correlation-Id": value}})
    assert pairing_v3.canonical_uuid(correlation)
    assert correlation != value or value == "123e4567-e89b-12d3-a456-426614174000"


def test_authorization_redemption_is_single_use_and_idempotent(v3_tables):
    sessions, connectors = v3_tables
    authorization = issue_authorization()
    first = handler.redeem_home_connector_pairing_v3(signed_redemption(authorization))
    assert first["statusCode"] == 201
    body = json.loads(first["body"])
    assert body["code"] == "pairing_redeemed"
    assert len(connectors.items) == 2  # Connector plus server-level plugin binding.
    second = handler.redeem_home_connector_pairing_v3(signed_redemption(authorization, nonce="abcdefghijklmnopqrstuvwxyz012346"))
    assert second["statusCode"] == 200
    assert json.loads(second["body"])["idempotent"] is True
    assert len(connectors.items) == 2
    states = [item.get("state") for item in sessions.items.values() if item.get("record_type") == "pairing_v3_authorization"]
    assert states == ["redeemed"]


def test_v3_connector_registers_and_becomes_online_with_signed_control_request(v3_tables):
    _, connectors = v3_tables
    authorization = issue_authorization()
    redeemed = handler.redeem_home_connector_pairing_v3(signed_redemption(authorization))
    connector_id = json.loads(redeemed["body"])["connectorId"]
    enrolled = connectors.items[connector_id]
    assert enrolled["profile_id"] == "profile-1"
    assert enrolled["auth_state"] == "v3_active"

    body = {
        "connector_id": connector_id, "profile_id": "profile-1",
        "connector_name": "Kaevo Jellyfin Plugin", "host_type": "jellyfin_plugin",
        "app_version": "0.2.61", "capabilities": ["provider_status"],
        "provider_status": {"sonarr": {"ok": True, "configured": True, "version": "0.2.61"}},
    }
    result = handler.register_home_connector(
        signed_connector_request("/v3/home-connectors/register", body), pairing_v3=True,
    )
    assert result["statusCode"] == 200
    public = json.loads(result["body"])["connector"]
    assert public["online"] is True
    assert public["provider_status"]["sonarr"]["ok"] is True


def test_v3_connector_rejects_missing_signature_and_nonce_replay(v3_tables):
    authorization = issue_authorization()
    redeemed = handler.redeem_home_connector_pairing_v3(signed_redemption(authorization))
    connector_id = json.loads(redeemed["body"])["connectorId"]
    body = {"connector_id": connector_id, "profile_id": "profile-1", "provider_status": {}}
    unsigned = event("/v3/home-connectors/register", body)
    assert handler.register_home_connector(unsigned, pairing_v3=True)["statusCode"] == 401
    signed = signed_connector_request("/v3/home-connectors/register", body)
    assert handler.register_home_connector(signed, pairing_v3=True)["statusCode"] == 200
    assert handler.register_home_connector(signed, pairing_v3=True)["statusCode"] == 401


def test_v3_connector_signature_is_bound_to_route_and_body(v3_tables):
    authorization = issue_authorization()
    redeemed = handler.redeem_home_connector_pairing_v3(signed_redemption(authorization))
    connector_id = json.loads(redeemed["body"])["connectorId"]
    body = {"connector_id": connector_id, "profile_id": "profile-1", "provider_status": {}}
    request = signed_connector_request("/v3/home-connectors/register", body)
    request["rawPath"] = f"/v3/home-connectors/{connector_id}/heartbeat"
    assert handler.heartbeat_home_connector(request, request["rawPath"], pairing_v3=True)["statusCode"] == 401


def test_existing_v3_connector_profile_backfill_requires_matching_identity_graph(monkeypatch):
    profiles = FakeTable("profiles", "profile_id")
    profiles.put_item(Item={"profile_id": "profile-1", "account_id": "account-1", "household_id": "family-1"})
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    connector = {
        "account_binding": pairing_v3.sha256_b64url(b"account-1"),
        "family_binding": pairing_v3.sha256_b64url(b"family-1"),
    }
    assert handler.pairing_v3_profile_binding(connector, "profile-1") == "profile-1"
    profiles.put_item(Item={"profile_id": "profile-2", "account_id": "other-account", "household_id": "family-1"})
    assert handler.pairing_v3_profile_binding(connector, "profile-2") == ""


def test_reused_plugin_nonce_is_rejected_even_after_terminal_enrollment(v3_tables):
    authorization = issue_authorization()
    request = signed_redemption(authorization)
    assert handler.redeem_home_connector_pairing_v3(request)["statusCode"] == 201
    replay = handler.redeem_home_connector_pairing_v3(request)
    assert replay["statusCode"] == 409
    assert json.loads(replay["body"])["code"] == "plugin_nonce_replayed"


@pytest.mark.parametrize("status, code", [(401, "owner_session_required"), (403, "owner_required")])
def test_authorization_requires_a_valid_owner_session(monkeypatch, status, code):
    monkeypatch.setattr(handler, "owner_bound_session", lambda _event: (None, {"statusCode": status, "body": json.dumps({"state": code})}))
    result = handler.issue_home_connector_pairing_authorization_v3(event("/v3/home-connectors/pairing/authorizations", bindings()))
    body = json.loads(result["body"])
    assert result["statusCode"] == status
    assert body["code"] == code
    assert "authorization" not in body


def test_v3_owner_session_rejects_legacy_app_session_records(monkeypatch):
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: {
        "record_type": "app_session", "role": "owner",
    })
    session, error = handler.owner_bound_session({})
    assert session is None
    assert error["statusCode"] == 401
    assert json.loads(error["body"])["state"] == "owner_session_required"


def test_v3_owner_session_accepts_only_protected_owner_access_records(monkeypatch):
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: {
        "record_type": "access", "role": "owner",
    })
    session, error = handler.owner_bound_session({})
    assert error is None
    assert session["record_type"] == "access"


def test_missing_cloud_signing_key_fails_closed_without_issuing_an_artifact(v3_tables, monkeypatch):
    monkeypatch.setattr(handler, "PAIRING_V3_AUTHORIZATION_SIGNING_SEED", "")
    result = handler.issue_home_connector_pairing_authorization_v3(event("/v3/home-connectors/pairing/authorizations", bindings()))
    body = json.loads(result["body"])
    assert result["statusCode"] == 503
    assert body["code"] == "pairing_dependency_failure"
    assert "authorization" not in body


def test_iac_scopes_the_v3_authorization_signing_secret_to_only_the_api_lambda():
    template = (Path(__file__).resolve().parents[2] / "infra" / "template.yaml").read_text()
    owner = template.split("  KaevoOwnerEnrollmentFunction:", 1)[1].split("  KaevoOwnerEnrollmentLogGroup:", 1)[0]
    api = template.split("  KaevoCloudApiFunction:", 1)[1].split("      Events:", 1)[0]
    assert "PAIRING_V3_AUTHORIZATION_SIGNING_SEED" not in owner
    assert "ReadPairingV3AuthorizationSigningKey" not in owner
    assert "PAIRING_V3_AUTHORIZATION_SIGNING_SEED" in api
    assert "PAIRING_V3_AUTHORIZATION_KEY_ID: v3-dev-20260722-1" in api
    assert "ReadPairingV3AuthorizationSigningKey" in api
    assert "Resource: !Ref KaevoPairingV3AuthorizationSigningSecret" in api


def test_redemption_rejects_jellyfin_user_binding_mismatch(v3_tables):
    authorization = issue_authorization()
    result = handler.redeem_home_connector_pairing_v3(signed_redemption(authorization, jellyfin_user="jellyfin-user-2"))
    assert result["statusCode"] == 403
    assert json.loads(result["body"])["code"] == "binding_mismatch"


def test_bad_plugin_signature_does_not_consume_authorization(v3_tables):
    sessions, _ = v3_tables
    authorization = issue_authorization()
    request = signed_redemption(authorization)
    request["headers"]["X-Kaevo-Plugin-Signature"] = "A" * 86
    result = handler.redeem_home_connector_pairing_v3(request)
    assert result["statusCode"] == 422
    assert [item["state"] for item in sessions.items.values() if item.get("record_type") == "pairing_v3_authorization"] == ["active"]


def test_structured_logging_does_not_emit_authorization_or_identifiers(v3_tables, caplog):
    authorization = issue_authorization()
    with caplog.at_level(logging.INFO, logger=handler.LOGGER.name):
        result = handler.redeem_home_connector_pairing_v3(signed_redemption(authorization))
    assert result["statusCode"] == 201
    emitted = "\n".join(record.getMessage() for record in caplog.records)
    assert authorization not in emitted
    assert "jellyfin-user-1" not in emitted
    assert "jellyfin-v3-test-01" not in emitted
    assert "pairingAttemptId" not in emitted
    v3_records = [record for record in caplog.records if "kaevo_pairing_v3" in record.getMessage()]
    assert v3_records
    assert all(record.levelno == logging.WARNING for record in v3_records)

from __future__ import annotations

import json
import threading

import pytest
from botocore.exceptions import ClientError

import pairing_v3
from connector_control import connector_control_handler as control


PLUGIN_SEED = b"B" * 32
CONNECTOR_ID = "connector-v3-control-01"
PROFILE_ID = "profile-v3-control-01"


def conditional_failure(operation="UpdateItem"):
    return ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, operation)


class FakeTable:
    def __init__(self, key):
        self.key = key
        self.items = {}
        self.lock = threading.Lock()

    def get_item(self, Key, **_):
        with self.lock:
            item = self.items.get(Key[self.key])
            return {"Item": dict(item)} if item else {}

    def put_item(self, Item, ConditionExpression=None, **_):
        with self.lock:
            key = Item[self.key]
            if ConditionExpression and key in self.items:
                raise conditional_failure("PutItem")
            self.items[key] = dict(Item)
        return {}

    def query(self, **_):
        with self.lock:
            items = [dict(item) for item in self.items.values() if item.get("status") == "pending"]
        return {"Items": sorted(items, key=lambda item: item.get("status_created_at", ""))[:8]}

    def update_item(self, Key, ConditionExpression, UpdateExpression, ExpressionAttributeValues, ReturnValues=None, **_):
        with self.lock:
            key = Key[self.key]
            item = self.items.get(key)
            if not item:
                raise conditional_failure()
            values = ExpressionAttributeValues
            if self.key == "connector_id":
                if item.get("profile_id") not in {None, "", values[":profile"]}:
                    raise conditional_failure()
                for field, token in (
                    ("protocol_version", ":protocol"), ("auth_state", ":auth"), ("state", ":active"),
                    ("plugin_instance_id", ":plugin_instance"),
                    ("plugin_public_key_fingerprint", ":fingerprint"),
                    ("plugin_key_id", ":plugin_key_id"), ("server_id", ":server_id"),
                ):
                    if str(item.get(field) or "") != str(values[token]):
                        raise conditional_failure()
                item.update({
                    "profile_id": item.get("profile_id") or values[":profile"],
                    "connector_name": values[":connector_name"], "host_type": values[":host_type"],
                    "app_version": values[":app_version"], "created_at": item.get("created_at") or values[":now"],
                    "updated_at": values[":now"], "last_seen_at": values[":now"],
                    "last_seen_epoch": values[":now_epoch"], "capabilities_json": values[":capabilities"],
                    "provider_status_json": values[":provider_status"],
                })
            else:
                expected = values.get(":pending") or values.get(":in_progress") or values.get(":completing")
                if expected and item.get("status") != expected:
                    raise conditional_failure()
                if ":in_progress" in values and ":pending" in values:
                    item.update({"status": "in_progress", "claimed_at": values[":now"], "updated_at": values[":now"], "status_created_at": values[":sort"]})
                elif ":completing" in values and ":completed" not in values:
                    item.update({"status": "completing", "updated_at": values[":now"], "status_created_at": values[":sort"]})
                elif ":completed" in values:
                    item.update({"status": "completed", "completed_at": values[":now"], "updated_at": values[":now"], "status_created_at": values[":sort"], "http_status": values[":http_status"], "truncated": values[":truncated"]})
                    for field, token in (("response_json", ":response_json"), ("response_gzip_base64", ":response_gzip"), ("response_encoding", ":response_encoding")):
                        if token in values:
                            item[field] = values[token]
                elif ":failed" in values:
                    item.update({"status": "failed", "failed_at": values[":now"], "updated_at": values[":now"], "status_created_at": values[":sort"], "error_json": values[":error"]})
            self.items[key] = item
            return {"Attributes": dict(item)} if ReturnValues else {}


@pytest.fixture
def tables(monkeypatch):
    connectors = FakeTable("connector_id")
    sessions = FakeTable("token_hash")
    profiles = FakeTable("profile_id")
    remotes = FakeTable("request_id")
    public = pairing_v3.ed25519_public_key_from_seed(PLUGIN_SEED)
    fingerprint = pairing_v3.plugin_fingerprint(public)
    connectors.items[CONNECTOR_ID] = {
        "connector_id": CONNECTOR_ID, "protocol_version": pairing_v3.PROTOCOL,
        "auth_state": "v3_active", "state": "active", "revoked": False,
        "plugin_public_key": pairing_v3.b64url_encode(public),
        "plugin_public_key_fingerprint": fingerprint, "plugin_instance_id": "plugin-control-01",
        "plugin_key_id": "1", "server_id": "server-control-01",
        "account_binding": pairing_v3.sha256_b64url(b"account-control-01"),
        "family_binding": pairing_v3.sha256_b64url(b"family-control-01"),
    }
    profiles.items[PROFILE_ID] = {"profile_id": PROFILE_ID, "account_id": "account-control-01", "household_id": "family-control-01"}
    monkeypatch.setattr(control, "home_connectors_table", connectors)
    monkeypatch.setattr(control, "app_sessions_table", sessions)
    monkeypatch.setattr(control, "identity_profiles_table", profiles)
    monkeypatch.setattr(control, "remote_requests_table", remotes)
    monkeypatch.setattr(control, "PLAYBACK_GRANT_SIGNING_KEY", "K" * 32)
    return connectors, sessions, profiles, remotes


def event(route, body, headers=None):
    return {"rawPath": route, "requestContext": {"http": {"method": "POST"}}, "headers": headers or {}, "body": json.dumps(body)}


def signed(route, body, nonce="connectorcontrolnonce0123456789"):
    timestamp = str(control.epoch_now() * 1000)
    transcript = pairing_v3.canonical_transcript("connector-request", (
        ("httpMethod", "POST"), ("canonicalRoute", route),
        ("bodyDigest", pairing_v3.canonical_json_digest(body)), ("timestamp", timestamp),
        ("nonce", nonce), ("connectorId", CONNECTOR_ID),
        ("pluginInstanceId", "plugin-control-01"), ("pluginKeyId", "1"),
        ("pluginPublicKeyFingerprint", pairing_v3.plugin_fingerprint(pairing_v3.ed25519_public_key_from_seed(PLUGIN_SEED))),
    ))
    return event(route, body, {
        "X-Kaevo-Plugin-Key-Id": "1", "X-Kaevo-Plugin-Timestamp": timestamp,
        "X-Kaevo-Plugin-Nonce": nonce,
        "X-Kaevo-Plugin-Signature": pairing_v3.sign_ed25519(PLUGIN_SEED, transcript),
    })


def body(**extra):
    return {"connector_id": CONNECTOR_ID, "profile_id": PROFILE_ID, "provider_status": {}, **extra}


def test_signed_registration_is_idempotent_and_conditionally_backfills_profile(tables):
    first = control.lambda_handler(signed("/v3/home-connectors/register", body()), None)
    second = control.lambda_handler(signed("/v3/home-connectors/register", body(), "connectorcontrolnonce0123456790"), None)
    assert first["statusCode"] == second["statusCode"] == 200
    assert json.loads(first["body"])["connector"]["connector_id"] == CONNECTOR_ID
    assert tables[0].items[CONNECTOR_ID]["profile_id"] == PROFILE_ID
    assert len(tables[0].items) == 1


def test_missing_wrong_and_replayed_signatures_fail_closed(tables):
    route = "/v3/home-connectors/register"
    assert control.lambda_handler(event(route, body()), None)["statusCode"] == 401
    wrong_route = signed(route, body())
    wrong_route["rawPath"] = f"/v3/home-connectors/{CONNECTOR_ID}/heartbeat"
    assert control.lambda_handler(wrong_route, None)["statusCode"] == 401
    valid = signed(route, body(), "connectorcontrolnonce0123456791")
    assert control.lambda_handler(valid, None)["statusCode"] == 200
    assert control.lambda_handler(valid, None)["statusCode"] == 401


def test_profile_conflict_and_wrong_binding_are_rejected(tables):
    tables[0].items[CONNECTOR_ID]["profile_id"] = "other-profile"
    assert control.lambda_handler(signed("/v3/home-connectors/register", body(), "connectorcontrolnonce0123456792"), None)["statusCode"] == 403
    tables[0].items[CONNECTOR_ID].pop("profile_id")
    tables[0].items[CONNECTOR_ID]["account_binding"] = pairing_v3.sha256_b64url(b"wrong")
    assert control.lambda_handler(signed("/v3/home-connectors/register", body(), "connectorcontrolnonce0123456793"), None)["statusCode"] == 403


def test_heartbeat_and_relay_ticket_use_key_bound_auth_and_replay_guard(tables):
    tables[0].items[CONNECTOR_ID]["profile_id"] = PROFILE_ID
    heartbeat = f"/v3/home-connectors/{CONNECTOR_ID}/heartbeat"
    assert control.lambda_handler(signed(heartbeat, body(), "connectorcontrolnonce0123456794"), None)["statusCode"] == 200
    relay = f"/v3/home-connectors/{CONNECTOR_ID}/relay-ticket"
    request = signed(relay, {"connector_id": CONNECTOR_ID}, "connectorcontrolnonce0123456795")
    result = control.lambda_handler(request, None)
    assert result["statusCode"] == 201
    assert "relay_ticket" in json.loads(result["body"])
    assert control.lambda_handler(request, None)["statusCode"] == 401


def test_concurrent_claim_has_one_authoritative_winner_and_no_duplicate(tables):
    tables[0].items[CONNECTOR_ID]["profile_id"] = PROFILE_ID
    tables[3].items["remote-1"] = {
        "request_id": "remote-1", "connector_id": CONNECTOR_ID, "profile_id": PROFILE_ID,
        "status": "pending", "status_created_at": "pending#001", "expires_at": control.epoch_now() + 60,
        "request_json": json.dumps({"provider": "sonarr", "method": "GET", "path": "/api/v3/system/status"}),
    }
    results = []
    def run(index):
        results.append(control.lambda_handler(signed("/v3/remote-requests/claim", {"connector_id": CONNECTOR_ID}, f"connectorcontrolnonce01234568{index:02d}"), None))
    threads = [threading.Thread(target=run, args=(index,)) for index in range(2)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert sorted(json.loads(result["body"])["state"] for result in results) == ["claimed", "empty"]
    assert list(tables[3].items) == ["remote-1"]


def test_completion_and_failure_transitions_are_consistent(tables):
    tables[0].items[CONNECTOR_ID]["profile_id"] = PROFILE_ID
    for request_id in ("complete-1", "fail-1"):
        tables[3].items[request_id] = {
            "request_id": request_id, "connector_id": CONNECTOR_ID, "profile_id": PROFILE_ID,
            "status": "in_progress", "request_json": "{}", "expires_at": control.epoch_now() + 60,
        }
    complete_route = "/v3/remote-requests/complete-1/complete"
    complete = control.lambda_handler(signed(complete_route, {"connector_id": CONNECTOR_ID, "response": {"ok": True}}, "connectorcontrolnonce0123456801"), None)
    fail_route = "/v3/remote-requests/fail-1/fail"
    failed = control.lambda_handler(signed(fail_route, {"connector_id": CONNECTOR_ID, "message": "bounded"}, "connectorcontrolnonce0123456802"), None)
    assert json.loads(complete["body"])["state"] == "completed"
    assert json.loads(failed["body"])["state"] == "failed"
    assert tables[3].items["complete-1"]["status"] == "completed"
    assert tables[3].items["fail-1"]["status"] == "failed"


def test_handler_has_no_owner_cognito_or_pairing_authorization_secret_surface():
    source = __import__("pathlib").Path(control.__file__).read_text()
    forbidden = [
        "PAIRING_V3_AUTHORIZATION_SIGNING_SEED", "KaevoPairingV3AuthorizationSigningSecret",
        "secretsmanager", "cognito-idp", "owner_bound_session", 'header_value(event, "authorization")',
    ]
    assert all(value not in source for value in forbidden)
    assert "connector_unauthorized" in source

from __future__ import annotations

import json
import logging
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
        self.update_calls = []

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
            self.update_calls.append({
                "condition": ConditionExpression,
                "expression": UpdateExpression,
                "values": dict(ExpressionAttributeValues),
            })
            key = Key[self.key]
            item = self.items.get(key)
            if not item:
                raise conditional_failure()
            values = ExpressionAttributeValues
            if self.key == "connector_id":
                if ":revoked_state" in values:
                    for field, token in (
                        ("protocol_version", ":protocol"),
                        ("auth_state", ":active_auth"),
                        ("state", ":active_state"),
                        ("plugin_instance_id", ":plugin_instance"),
                        ("plugin_public_key_fingerprint", ":fingerprint"),
                        ("plugin_key_id", ":plugin_key_id"),
                    ):
                        if str(item.get(field) or "") != str(values[token]):
                            raise conditional_failure()
                    if bool(item.get("revoked")):
                        raise conditional_failure()
                    item.update({
                        "revoked": values[":true"],
                        "auth_state": values[":revoked_auth"],
                        "state": values[":revoked_state"],
                        "updated_at": values[":now"],
                        "revoked_at": values[":now"],
                    })
                    if " REMOVE " in UpdateExpression:
                        for field in UpdateExpression.split(" REMOVE ", 1)[1].split(","):
                            item.pop(field.strip(), None)
                else:
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
                    for field, token in (
                        ("response_json", ":response_json"),
                        ("response_gzip_base64", ":response_gzip"),
                        ("response_encoding", ":response_encoding"),
                        ("response_s3_key", ":response_s3_key"),
                        ("response_stored_bytes", ":response_stored_bytes"),
                    ):
                        if token in values:
                            item[field] = values[token]
                elif ":failed" in values:
                    item.update({"status": "failed", "failed_at": values[":now"], "updated_at": values[":now"], "status_created_at": values[":sort"], "error_json": values[":error"]})
                if " REMOVE " in UpdateExpression:
                    for field in UpdateExpression.split(" REMOVE ", 1)[1].split(","):
                        item.pop(field.strip(), None)
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


def signed_raw(route, raw_body, nonce="connectorrawnumbernonce0123456"):
    timestamp = str(control.epoch_now() * 1000)
    transcript = pairing_v3.canonical_transcript("connector-request", (
        ("httpMethod", "POST"), ("canonicalRoute", route),
        ("bodyDigest", pairing_v3.canonical_json_digest_preserving_number_lexemes(raw_body)),
        ("timestamp", timestamp), ("nonce", nonce), ("connectorId", CONNECTOR_ID),
        ("pluginInstanceId", "plugin-control-01"), ("pluginKeyId", "1"),
        ("pluginPublicKeyFingerprint", pairing_v3.plugin_fingerprint(pairing_v3.ed25519_public_key_from_seed(PLUGIN_SEED))),
    ))
    return {
        "rawPath": route,
        "requestContext": {"http": {"method": "POST"}},
        "headers": {
            "X-Kaevo-Plugin-Key-Id": "1", "X-Kaevo-Plugin-Timestamp": timestamp,
            "X-Kaevo-Plugin-Nonce": nonce,
            "X-Kaevo-Plugin-Signature": pairing_v3.sign_ed25519(PLUGIN_SEED, transcript),
        },
        "body": raw_body,
    }


def signed_v2(route, raw_body, nonce="connectorrawbytesnonce0123456"):
    timestamp = str(control.epoch_now() * 1000)
    transcript = pairing_v3.canonical_transcript("connector-request", (
        ("httpMethod", "POST"), ("canonicalRoute", route),
        ("bodyDigest", pairing_v3.sha256_b64url(raw_body.encode("utf-8"))),
        ("timestamp", timestamp), ("nonce", nonce), ("connectorId", CONNECTOR_ID),
        ("pluginInstanceId", "plugin-control-01"), ("pluginKeyId", "1"),
        ("pluginPublicKeyFingerprint", pairing_v3.plugin_fingerprint(pairing_v3.ed25519_public_key_from_seed(PLUGIN_SEED))),
    ))
    return {
        "rawPath": route,
        "requestContext": {"http": {"method": "POST"}},
        "headers": {
            "X-Kaevo-Plugin-Key-Id": "1", "X-Kaevo-Plugin-Timestamp": timestamp,
            "X-Kaevo-Plugin-Nonce": nonce, "X-Kaevo-Plugin-Signature-Version": "2",
            "X-Kaevo-Plugin-Signature": pairing_v3.sign_ed25519(PLUGIN_SEED, transcript),
        },
        "body": raw_body,
    }


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


def test_signature_v2_verifies_exact_serialized_body_bytes(tables):
    route = f"/v3/home-connectors/{CONNECTOR_ID}/heartbeat"
    raw_body = json.dumps(body(progress=0.000000000000000000123), separators=(",", ":"))
    request = signed_v2(route, raw_body)

    assert control.lambda_handler(request, None)["statusCode"] == 200


def test_signature_v2_rejects_changed_serialized_body_and_unknown_version(tables):
    route = f"/v3/home-connectors/{CONNECTOR_ID}/heartbeat"
    raw_body = json.dumps(body(), separators=(",", ":"))
    changed = signed_v2(route, raw_body, "connectorrawbytesnonce0123457")
    changed["body"] = json.dumps(body(), indent=1)
    assert control.lambda_handler(changed, None)["statusCode"] == 401

    unsupported = signed_v2(route, raw_body, "connectorrawbytesnonce0123458")
    unsupported["headers"]["X-Kaevo-Plugin-Signature-Version"] = "3"
    assert control.lambda_handler(unsupported, None)["statusCode"] == 401


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


def test_disconnect_revokes_exact_connector_and_is_idempotently_confirmable(tables):
    connector = tables[0].items[CONNECTOR_ID]
    connector.update({
        "profile_id": PROFILE_ID,
        "connector_name": "private-name",
        "host_type": "private-host",
        "app_version": "private-version",
        "last_seen_at": "private-time",
        "last_seen_epoch": control.epoch_now(),
        "capabilities_json": "[\"private\"]",
        "provider_status_json": "{\"private\":true}",
        "jellyfin_user_id": "private-user",
        "server_name": "private-server",
    })
    route = f"/v3/home-connectors/{CONNECTOR_ID}/disconnect"
    first = control.lambda_handler(
        signed(
            route,
            {"connector_id": CONNECTOR_ID},
            "connectorcontrolnonce0123456796",
        ),
        None,
    )

    assert first["statusCode"] == 200
    assert json.loads(first["body"]) == {
        "state": "disconnected",
        "idempotent": False,
    }
    retained = tables[0].items[CONNECTOR_ID]
    assert retained["revoked"] is True
    assert retained["auth_state"] == "v3_revoked"
    assert retained["state"] == "revoked"
    assert {
        "profile_id", "account_binding", "family_binding", "connector_name",
        "host_type", "app_version", "last_seen_at", "last_seen_epoch",
        "capabilities_json", "provider_status_json", "jellyfin_user_id",
        "server_name",
    }.isdisjoint(retained)

    second = control.lambda_handler(
        signed(
            route,
            {"connector_id": CONNECTOR_ID},
            "connectorcontrolnonce0123456797",
        ),
        None,
    )
    assert second["statusCode"] == 200
    assert json.loads(second["body"]) == {
        "state": "disconnected",
        "idempotent": True,
    }

    register = control.lambda_handler(
        signed(
            "/v3/home-connectors/register",
            body(),
            "connectorcontrolnonce0123456798",
        ),
        None,
    )
    assert register["statusCode"] == 401


def test_concurrent_claim_has_one_authoritative_winner_and_no_duplicate(tables):
    tables[0].items[CONNECTOR_ID]["profile_id"] = PROFILE_ID
    tables[3].items["remote-1"] = {
        "request_id": "remote-1", "connector_id": CONNECTOR_ID, "profile_id": PROFILE_ID,
        "status": "pending", "status_created_at": "pending#001", "expires_at": control.epoch_now() + 60,
        "request_json": json.dumps({"provider": "sonarr", "method": "GET", "path": "/api/v3/system/status"}),
    }
    results = []
    def run(index):
        results.append(control.lambda_handler(signed("/v3/remote-requests/claim", {
            "connector_id": CONNECTOR_ID,
            "connector_control_protocol": 2,
            "recovery": True,
        }, f"connectorcontrolnonce01234568{index:02d}"), None))
    threads = [threading.Thread(target=run, args=(index,)) for index in range(2)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert sorted(json.loads(result["body"])["state"] for result in results) == ["claimed", "empty"]
    assert list(tables[3].items) == ["remote-1"]


def test_legacy_poll_authenticates_then_requires_push_protocol(tables):
    nonce = "connectorcontrolnonce0123456801"
    result = control.lambda_handler(
        signed(
            "/v3/remote-requests/claim",
            {"connector_id": CONNECTOR_ID},
            nonce,
        ),
        None,
    )

    assert result["statusCode"] == 426
    assert result["headers"]["Retry-After"] == "60"
    assert json.loads(result["body"])["state"] == "upgrade_required"
    assert len(tables[1].items) == 1
    assert next(iter(tables[1].items.values()))["record_type"] == "pairing_v3_connector_nonce"


def test_push_protocol_cannot_use_legacy_claim_outside_recovery(tables):
    result = control.lambda_handler(
        signed(
            "/v3/remote-requests/claim",
            {"connector_id": CONNECTOR_ID, "connector_control_protocol": 2},
            "connectorcontrolnonce0123456802",
        ),
        None,
    )

    assert result["statusCode"] == 400
    assert json.loads(result["body"]) == {
        "state": "recovery_claim_required",
        "retry_after_seconds": 60,
    }


def test_command_claim_preserves_allowlisted_operation_and_parameters(tables):
    tables[0].items[CONNECTOR_ID]["profile_id"] = PROFILE_ID
    tables[3].items["provider-health-1"] = {
        "request_id": "provider-health-1", "connector_id": CONNECTOR_ID, "profile_id": PROFILE_ID,
        "status": "pending", "status_created_at": "pending#001", "expires_at": control.epoch_now() + 60,
        "request_json": json.dumps({
            "provider": "home_server", "method": "COMMAND", "path": "/commands/provider.health",
            "query": {}, "body": {"provider": "sonarr"},
        }),
    }

    result = control.lambda_handler(
        signed(
            "/v3/remote-requests/claim",
            {"connector_id": CONNECTOR_ID, "connector_control_protocol": 2, "recovery": True},
            "connectorcontrolnonce0123456899",
        ),
        None,
    )
    payload = json.loads(result["body"])

    assert result["statusCode"] == 200
    assert payload["state"] == "claimed"
    assert payload["request"]["operation"] == "provider.health"
    assert payload["request"]["parameters"] == {"provider": "sonarr"}
    encoded = json.dumps(payload)
    assert "authorization" not in encoded.lower()
    assert "token" not in encoded.lower()


def test_lifecycle_v2_claim_projects_only_the_frozen_exact_provider_binding(tables):
    tables[0].items[CONNECTOR_ID]["profile_id"] = PROFILE_ID
    jellyfin_user_id = "dbb85e8dd0844ee097a4c9fd8d358215"
    tables[3].items["lifecycle-v2-delete-1"] = {
        "request_id": "lifecycle-v2-delete-1",
        "connector_id": CONNECTOR_ID,
        "profile_id": PROFILE_ID,
        "status": "pending",
        "status_created_at": "pending#020#lifecycle-v2-delete-1",
        "expires_at": control.epoch_now() + 60,
        "request_json": json.dumps({
            "provider": "home_server",
            "method": "COMMAND",
            "path": "/commands/account_lifecycle_v2.seerr.delete_exact_identity",
            "query": {},
            "body": {
                "operation_id": "ald2-operation-1",
                "profile_id": PROFILE_ID,
                "jellyfin_user_id": jellyfin_user_id,
                "seerr_user_id": 20,
            },
        }),
        "profile_provider_binding_json": json.dumps({
            "provider": "jellyfin",
            "connector_id": CONNECTOR_ID,
            "provider_user_id": jellyfin_user_id,
        }),
    }

    result = control.lambda_handler(
        signed(
            "/v3/remote-requests/claim",
            {"connector_id": CONNECTOR_ID, "connector_control_protocol": 2, "recovery": True},
            "connectorcontrolnonce0123456877",
        ),
        None,
    )
    payload = json.loads(result["body"])

    assert result["statusCode"] == 200
    assert payload["state"] == "claimed"
    assert payload["request"]["profile_provider_binding"] == {
        "provider": "jellyfin",
        "connector_id": CONNECTOR_ID,
        "provider_user_id": jellyfin_user_id,
    }


def test_non_lifecycle_command_cannot_inject_a_provider_binding():
    projected = control.public_remote_request({
        "request_id": "ordinary-command-1",
        "connector_id": CONNECTOR_ID,
        "profile_id": PROFILE_ID,
        "status": "in_progress",
        "request_json": json.dumps({
            "provider": "home_server",
            "method": "COMMAND",
            "path": "/commands/provider.health",
            "body": {"profile_provider_binding": {
                "provider": "jellyfin",
                "connector_id": CONNECTOR_ID,
                "provider_user_id": "attacker-selected-user",
            }},
        }),
        "profile_provider_binding_json": json.dumps({
            "provider": "jellyfin",
            "connector_id": CONNECTOR_ID,
            "provider_user_id": "attacker-selected-user",
        }),
    })

    assert "profile_provider_binding" not in projected


def test_watched_command_claim_projects_only_canonical_exact_profile_binding(tables):
    jellyfin_user_id = "DBB85E8D-D084-4EE0-97A4-C9FD8D358215"
    tables[0].items[CONNECTOR_ID]["profile_id"] = PROFILE_ID
    tables[2].items[PROFILE_ID].update({
        "state": "active",
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": CONNECTOR_ID,
        "jellyfin_user_id": jellyfin_user_id,
    })
    tables[3].items["watched-1"] = {
        "request_id": "watched-1",
        "connector_id": CONNECTOR_ID,
        "profile_id": PROFILE_ID,
        "status": "pending",
        "status_created_at": "pending#020#watched-1",
        "expires_at": control.epoch_now() + 60,
        "request_json": json.dumps({
            "provider": "home_server",
            "method": "COMMAND",
            "path": "/commands/jellyfin.mark_played",
            "query": {},
            "body": {
                "item_id": "0123456789abcdef0123456789abcdef",
                "profile_provider_binding": {
                    "provider": "jellyfin",
                    "connector_id": "attacker-connector",
                    "provider_user_id": "ffffffffffffffffffffffffffffffff",
                },
            },
        }),
    }

    result = control.lambda_handler(
        signed(
            "/v3/remote-requests/claim",
            {"connector_id": CONNECTOR_ID, "connector_control_protocol": 2, "recovery": True},
            "connectorcontrolnonce0123456878",
        ),
        None,
    )
    payload = json.loads(result["body"])

    assert result["statusCode"] == 200
    assert payload["state"] == "claimed"
    assert payload["request"]["profile_provider_binding"] == {
        "provider": "jellyfin",
        "connector_id": CONNECTOR_ID,
        "provider_user_id": "dbb85e8dd0844ee097a4c9fd8d358215",
    }


@pytest.mark.parametrize("profile_update", [
    {"state": "inactive", "jellyfin_binding_state": "active"},
    {"state": "active", "jellyfin_binding_state": "missing"},
    {"state": "active", "jellyfin_binding_state": "active", "jellyfin_connector_id": "other-connector"},
    {"state": "active", "jellyfin_binding_state": "active", "jellyfin_user_id": "not-a-user-id"},
])
def test_watched_command_binding_projection_fails_closed(profile_update, tables):
    profile = tables[2].items[PROFILE_ID]
    profile.update({
        "state": "active",
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": CONNECTOR_ID,
        "jellyfin_user_id": "dbb85e8dd0844ee097a4c9fd8d358215",
    })
    profile.update(profile_update)
    projected = control.public_remote_request({
        "request_id": "watched-fail-closed-1",
        "connector_id": CONNECTOR_ID,
        "profile_id": PROFILE_ID,
        "status": "in_progress",
        "request_json": json.dumps({
            "provider": "home_server",
            "method": "COMMAND",
            "path": "/commands/jellyfin.mark_unplayed",
            "body": {"item_id": "0123456789abcdef0123456789abcdef"},
        }),
    })

    assert "profile_provider_binding" not in projected


def test_lifecycle_v2_binding_mismatch_fails_closed():
    with pytest.raises(ValueError, match="frozen_provider_binding_invalid"):
        control.public_remote_request({
            "request_id": "lifecycle-v2-invalid-1",
            "connector_id": CONNECTOR_ID,
            "profile_id": PROFILE_ID,
            "status": "in_progress",
            "request_json": json.dumps({
                "provider": "home_server",
                "method": "COMMAND",
                "path": "/commands/account_lifecycle_v2.jellyfin.delete_exact_identity",
                "body": {"profile_id": PROFILE_ID},
            }),
            "profile_provider_binding_json": json.dumps({
                "provider": "jellyfin",
                "connector_id": "different-connector",
                "provider_user_id": "dbb85e8dd0844ee097a4c9fd8d358215",
            }),
        })


def test_completion_and_failure_transitions_are_consistent(tables):
    tables[0].items[CONNECTOR_ID]["profile_id"] = PROFILE_ID
    for request_id in ("complete-1", "fail-1"):
        tables[3].items[request_id] = {
            "request_id": request_id, "connector_id": CONNECTOR_ID, "profile_id": PROFILE_ID,
            "status": "in_progress", "request_json": "{}", "expires_at": control.epoch_now() + 60,
        }
    tables[3].items["complete-1"].update({
        "response_gzip_base64": "stale", "response_s3_key": "stale",
        "response_encoding": "stale", "response_stored_bytes": 1,
    })
    complete_route = "/v3/remote-requests/complete-1/complete"
    complete = control.lambda_handler(signed(complete_route, {"connector_id": CONNECTOR_ID, "response": {"ok": True}}, "connectorcontrolnonce0123456801"), None)
    fail_route = "/v3/remote-requests/fail-1/fail"
    failed = control.lambda_handler(signed(fail_route, {"connector_id": CONNECTOR_ID, "message": "bounded"}, "connectorcontrolnonce0123456802"), None)
    assert json.loads(complete["body"])["state"] == "completed"
    assert json.loads(failed["body"])["state"] == "failed"
    assert tables[3].items["complete-1"]["status"] == "completed"
    assert tables[3].items["complete-1"]["response_json"] == '{"ok":true}'
    assert not {"response_gzip_base64", "response_s3_key", "response_encoding", "response_stored_bytes"} & tables[3].items["complete-1"].keys()
    assert tables[3].items["fail-1"]["status"] == "failed"
    completion_call = next(call for call in tables[3].update_calls if ":completed" in call["values"])
    assert completion_call["condition"] == "#status = :in_progress"
    assert ":completing" not in completion_call["values"]
    set_paths = {
        fragment.split("=", 1)[0].strip()
        for fragment in completion_call["expression"].split(" REMOVE ", 1)[0].removeprefix("SET ").split(",")
    }
    remove_paths = {path.strip() for path in completion_call["expression"].split(" REMOVE ", 1)[1].split(",")}
    assert {"response_json"} <= set_paths
    assert {"response_gzip_base64", "response_s3_key", "response_encoding", "response_stored_bytes"} <= remove_paths
    assert set_paths.isdisjoint(remove_paths)


def test_completion_accepts_plugin_digest_that_preserves_provider_number_lexemes(tables, caplog):
    tables[0].items[CONNECTOR_ID]["profile_id"] = PROFILE_ID
    tables[3].items["complete-number-1"] = {
        "request_id": "complete-number-1", "connector_id": CONNECTOR_ID, "profile_id": PROFILE_ID,
        "status": "in_progress", "request_json": "{}", "expires_at": control.epoch_now() + 60,
    }
    route = "/v3/remote-requests/complete-number-1/complete"
    raw_body = (
        '{"connector_id":' + json.dumps(CONNECTOR_ID)
        + ',"response":{"progress":1.2300,"rate":1e+30,"remaining":-0.0}}'
    )

    with caplog.at_level(logging.WARNING, logger=control.LOGGER.name):
        result = control.lambda_handler(signed_raw(route, raw_body), None)

    assert result["statusCode"] == 200
    assert tables[3].items["complete-number-1"]["status"] == "completed"
    assert any(control.CONNECTOR_AUTH_NUMBER_COMPATIBILITY_EVENT in record.message for record in caplog.records)


def test_completion_accepts_plugin_digest_that_escapes_provider_format_characters(tables, caplog):
    tables[0].items[CONNECTOR_ID]["profile_id"] = PROFILE_ID
    tables[3].items["complete-format-1"] = {
        "request_id": "complete-format-1", "connector_id": CONNECTOR_ID, "profile_id": PROFILE_ID,
        "status": "in_progress", "request_json": "{}", "expires_at": control.epoch_now() + 60,
    }
    route = "/v3/remote-requests/complete-format-1/complete"
    raw_body = (
        '{"connector_id":' + json.dumps(CONNECTOR_ID)
        + ',"response":{"credits":{"cast":[{"name":"cast member\\uFEFF"}]}}}'
    )

    with caplog.at_level(logging.WARNING, logger=control.LOGGER.name):
        result = control.lambda_handler(
            signed_raw(route, raw_body, "connectorformatnonce01234567890"),
            None,
        )

    assert result["statusCode"] == 200
    assert tables[3].items["complete-format-1"]["status"] == "completed"
    assert any(control.CONNECTOR_AUTH_NUMBER_COMPATIBILITY_EVENT in record.message for record in caplog.records)


def test_oversized_completion_does_not_leave_the_request_completing(tables, monkeypatch):
    tables[0].items[CONNECTOR_ID]["profile_id"] = PROFILE_ID
    tables[3].items["oversized-1"] = {
        "request_id": "oversized-1", "connector_id": CONNECTOR_ID, "profile_id": PROFILE_ID,
        "status": "in_progress", "request_json": "{}", "expires_at": control.epoch_now() + 60,
    }
    monkeypatch.setattr(control, "REMOTE_RESPONSE_COMPRESS_THRESHOLD_BYTES", 1)
    monkeypatch.setattr(control, "REMOTE_RESPONSE_MAX_STORED_BYTES", 1)
    monkeypatch.setattr(control, "REMOTE_PAYLOADS_BUCKET", "")
    monkeypatch.setattr(control, "s3_client", None)

    route = "/v3/remote-requests/oversized-1/complete"
    result = control.lambda_handler(
        signed(route, {"connector_id": CONNECTOR_ID, "response": {"payload": "x" * 512}}, "connectorcontrolnonce0123456803"),
        None,
    )

    assert result["statusCode"] == 413
    assert json.loads(result["body"])["state"] == "response_too_large"
    assert tables[3].items["oversized-1"]["status"] == "in_progress"


def test_handler_has_no_owner_cognito_or_pairing_authorization_secret_surface():
    source = __import__("pathlib").Path(control.__file__).read_text()
    forbidden = [
        "PAIRING_V3_AUTHORIZATION_SIGNING_SEED", "KaevoPairingV3AuthorizationSigningSecret",
        "secretsmanager", "cognito-idp", "owner_bound_session", 'header_value(event, "authorization")',
    ]
    assert all(value not in source for value in forbidden)
    assert "connector_unauthorized" in source

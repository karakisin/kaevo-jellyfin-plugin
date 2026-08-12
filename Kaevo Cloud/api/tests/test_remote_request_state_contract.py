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


class RecordingS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, *, Bucket, Key, Body, **_):
        self.objects[(Bucket, Key)] = Body


class ExactProfileTable:
    def __init__(self, item):
        self.item = dict(item)

    def get_item(self, *, Key, **_):
        if Key["profile_id"] != self.item["profile_id"]:
            return {}
        return {"Item": dict(self.item)}


class ExactConnectorTable:
    def __init__(self, item):
        self.item = dict(item)

    def get_item(self, *, Key, **_):
        if Key["connector_id"] != self.item["connector_id"]:
            return {}
        return {"Item": dict(self.item)}


class ExactHouseholdMembershipTable:
    def __init__(self, item):
        self.item = dict(item)

    def get_item(self, *, Key, **_):
        if (
            Key["household_id"] != self.item["household_id"]
            or Key["membership_id"] != self.item["membership_id"]
        ):
            return {}
        return {"Item": dict(self.item)}


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


def test_switch_auth_accepts_only_exact_source_grant_in_same_household(monkeypatch):
    class Profiles:
        records = {
            "profile-source": {
                "profile_id": "profile-source",
                "household_id": "household-1",
                "state": "active",
                "switch_profile_ids": ["profile-target"],
            },
            "profile-target": {
                "profile_id": "profile-target",
                "household_id": "household-1",
                "state": "active",
            },
            "profile-ungranted": {
                "profile_id": "profile-ungranted",
                "household_id": "household-1",
                "state": "active",
            },
            "profile-foreign": {
                "profile_id": "profile-foreign",
                "household_id": "household-2",
                "state": "active",
            },
        }

        def get_item(self, *, Key, ConsistentRead):
            assert ConsistentRead is True
            item = self.records.get(Key["profile_id"])
            return {"Item": dict(item)} if item else {}

    monkeypatch.setattr(handler, "identity_profiles_table", Profiles())
    authentication_count = 0

    def authenticate_once(_event):
        nonlocal authentication_count
        authentication_count += 1
        assert authentication_count == 1, "one DPoP proof must not be authenticated twice"
        return {
            "profile_id": "profile-source",
            "household_id": "household-1",
        }

    monkeypatch.setattr(handler, "authenticated_app_session", authenticate_once)

    assert handler.require_profile_switch_auth({}, "profile-target") is True
    assert authentication_count == 1


def test_switch_auth_rejects_ungranted_and_foreign_targets(monkeypatch):
    class Profiles:
        records = {
            "profile-source": {
                "profile_id": "profile-source",
                "household_id": "household-1",
                "state": "active",
                "switch_profile_ids": ["profile-target"],
            },
            "profile-ungranted": {
                "profile_id": "profile-ungranted",
                "household_id": "household-1",
                "state": "active",
            },
            "profile-foreign": {
                "profile_id": "profile-foreign",
                "household_id": "household-2",
                "state": "active",
            },
        }

        def get_item(self, *, Key, ConsistentRead):
            assert ConsistentRead is True
            item = self.records.get(Key["profile_id"])
            return {"Item": dict(item)} if item else {}

    monkeypatch.setattr(handler, "identity_profiles_table", Profiles())
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: {
        "profile_id": "profile-source",
        "household_id": "household-1",
    })

    assert handler.require_profile_switch_auth({}, "profile-ungranted") is False
    assert handler.require_profile_switch_auth({}, "profile-foreign") is False


def test_switch_auth_accepts_self_without_reading_profile_graph(monkeypatch):
    class UnreadableProfiles:
        def get_item(self, **_kwargs):
            raise AssertionError("self authorization must not read the switch graph")

    monkeypatch.setattr(handler, "identity_profiles_table", UnreadableProfiles())
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: {
        "profile_id": "profile-source",
        "household_id": "household-1",
    })

    assert handler.require_profile_switch_auth({}, "profile-source") is True


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


def test_large_completion_stores_only_under_the_bounded_remote_response_prefix(monkeypatch):
    request_id = "stored-once"
    table = FakeRemoteRequests([request_item(request_id, "in_progress")])
    storage = RecordingS3()
    monkeypatch.setattr(handler, "remote_requests_table", table)
    monkeypatch.setattr(handler, "require_connector_auth", lambda _event, connector_id: connector_id == "connector-1")
    monkeypatch.setattr(handler, "REMOTE_PAYLOADS_BUCKET", "bound-test-bucket")
    monkeypatch.setattr(handler, "s3_client", storage)
    monkeypatch.setattr(handler, "REMOTE_RESPONSE_COMPRESS_THRESHOLD_BYTES", 1)

    completed = handler.complete_remote_request(
        event({"connector_id": "connector-1", "response": {"large": "value"}}),
        f"/v1/remote-requests/{request_id}/complete",
    )

    expected_key = f"remote-responses/profile-1/{request_id}.json.gz"
    assert completed["statusCode"] == 200
    assert set(storage.objects) == {("bound-test-bucket", expected_key)}
    assert table.items[request_id]["response_s3_key"] == expected_key


def test_prepare_completion_embeds_one_exact_short_lived_playback_grant(monkeypatch):
    request_id = "prepare-playback"
    item = request_item(request_id, "in_progress")
    item["request_json"] = json.dumps({
        "provider": "home_server",
        "method": "COMMAND",
        "path": "/commands/jellyfin.prepare_playback",
        "query": {},
        "body": {
            "item_id": "a" * 32,
            "device_id": "ios-device-1",
            "max_bitrate": 20_000_000,
        },
    })
    table = FakeRemoteRequests([item])
    connector = {
        "connector_id": "connector-1",
        "auth_state": "active",
        "playback_grant_key": "h" * 48,
    }
    monkeypatch.setattr(handler, "remote_requests_table", table)
    monkeypatch.setattr(handler, "home_connectors_table", ExactConnectorTable(connector))
    monkeypatch.setattr(handler, "require_connector_auth", lambda _event, connector_id: connector_id == "connector-1")
    monkeypatch.setattr(handler, "PLAYBACK_GRANT_SIGNING_KEY", "x" * 48)
    monkeypatch.setattr(handler, "PLAYBACK_RELAY_PUBLIC_URL", "https://relay.test")
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _: ({
        "cloud_enabled": True,
        "subscription_state": "active",
    }, None))

    completed = handler.complete_remote_request(
        event({
            "connector_id": "connector-1",
            "response": {"result": {
                "item_id": "a" * 32,
                "media_source_id": "source-1",
                "playback_session_id": "session-1",
                "mode": "transcode",
                "max_bitrate": 20_000_000,
            }},
        }),
        f"/v1/remote-requests/{request_id}/complete",
    )

    assert completed["statusCode"] == 200
    stored = json.loads(table.items[request_id]["response_json"])
    grant = stored["result"]["playback_grant"]
    assert grant["state"] == "issued"
    assert grant["connector_id"] == "connector-1"
    assert grant["expires_at"] - handler.epoch_now() <= 120
    assert grant["relay_base_url"].startswith("https://relay.test/v1/playback/")
    assert "grant" not in grant


def test_prepare_completion_does_not_grant_mismatched_item_or_bitrate(monkeypatch):
    item = request_item("prepare-mismatch", "in_progress")
    item["request_json"] = json.dumps({
        "method": "COMMAND",
        "path": "/commands/jellyfin.prepare_playback",
        "body": {
            "item_id": "a" * 32,
            "device_id": "ios-device-1",
            "max_bitrate": 10_000_000,
        },
    })
    monkeypatch.setattr(handler, "home_connectors_table", ExactConnectorTable({
        "connector_id": "connector-1",
        "auth_state": "active",
        "playback_grant_key": "h" * 48,
    }))
    monkeypatch.setattr(handler, "PLAYBACK_GRANT_SIGNING_KEY", "x" * 48)
    monkeypatch.setattr(handler, "PLAYBACK_RELAY_PUBLIC_URL", "https://relay.test")
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _: ({
        "cloud_enabled": True,
        "subscription_state": "active",
    }, None))

    response_payload = {"result": {
        "item_id": "b" * 32,
        "media_source_id": "source-1",
        "playback_session_id": "session-1",
        "mode": "transcode",
        "max_bitrate": 20_000_000,
    }}

    assert handler._completion_with_embedded_playback_grant(item, response_payload) == response_payload


def test_admin_seerr_request_list_keeps_only_its_matching_exact_scope(monkeypatch):
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable({
        "profile_id": "profile-1",
        "state": "active",
        "seerr_binding_state": "active",
        "seerr_user_id": 42,
    }))

    query, reason = handler._authorized_seerr_request_query(
        "profile-1",
        {"take": 50, "skip": 0, "requestedBy": "42"},
    )

    assert reason == ""
    assert query == {"take": 50, "skip": 0, "requestedBy": "42"}


def test_admin_seerr_request_list_rejects_another_profiles_scope(monkeypatch):
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable({
        "profile_id": "profile-1",
        "state": "active",
        "seerr_binding_state": "active",
        "seerr_user_id": "42",
    }))

    query, reason = handler._authorized_seerr_request_query(
        "profile-1",
        {"requestedBy": "99"},
    )

    assert query is None
    assert reason == "profile_seerr_request_scope_conflict"


def test_admin_seerr_request_list_requires_an_active_exact_binding(monkeypatch):
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable({
        "profile_id": "profile-1",
        "state": "active",
        "seerr_binding_state": "pending",
        "seerr_user_id": "42",
    }))

    query, reason = handler._authorized_seerr_request_query("profile-1", {})

    assert query is None
    assert reason == "profile_seerr_binding_required"


def test_owner_seerr_request_list_is_household_wide_and_ignores_client_scope(monkeypatch):
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable({
        "profile_id": "profile-owner",
        "state": "active",
        "seerr_binding_state": "active",
        "seerr_user_id": "42",
        "household_access_role": "owner",
    }))

    query, reason = handler._authorized_seerr_request_query(
        "profile-owner",
        {"take": 50, "skip": 0, "requestedBy": "42"},
    )

    assert reason == ""
    assert query == {"take": 50, "skip": 0}


def test_owner_seerr_request_list_uses_exact_membership_without_personal_binding(monkeypatch):
    household_id = "household-1"
    account_id = "account-1"
    profile_id = "profile-owner"
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable({
        "profile_id": profile_id,
        "state": "active",
        "household_id": household_id,
        "account_id": account_id,
        # Intentionally no Seerr binding: an Owner's household-wide read is
        # authorized by the exact canonical membership, not a copied field.
    }))
    monkeypatch.setattr(handler, "household_memberships_table", ExactHouseholdMembershipTable({
        "household_id": household_id,
        "membership_id": handler.household_membership_id(account_id, household_id),
        "entity_type": "HouseholdMembership",
        "status": "active",
        "account_id": account_id,
        "profile_id": profile_id,
        "household_access_role": "owner",
    }))

    query, reason = handler._authorized_seerr_request_query(
        profile_id,
        {"take": 50, "requestedBy": "42"},
    )

    assert reason == ""
    assert query == {"take": 50}


def test_remote_metadata_request_enforces_admin_scope_before_queueing(monkeypatch):
    table = FakeRemoteRequests([])
    monkeypatch.setattr(handler, "remote_requests_table", table)
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable({
        "profile_id": "profile-admin",
        "state": "active",
        "seerr_binding_state": "active",
        "seerr_user_id": "42",
        "household_access_role": "admin",
    }))
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: {
        "profile_id": "profile-admin",
        "household_id": "household-1",
    })
    monkeypatch.setattr(handler, "latest_online_connector_for_profile", lambda profile_id: {"connector_id": "connector-1"})

    result = handler.create_remote_request(event({
        "profile_id": "profile-admin",
        "provider": "seerr",
        "method": "GET",
        "path": "/api/v1/request",
        "query": {"take": 50, "skip": 0},
    }))

    assert result["statusCode"] == 202
    queued = next(iter(table.items.values()))
    assert json.loads(queued["request_json"])["query"] == {"take": 50, "skip": 0, "requestedBy": "42"}


def test_remote_metadata_request_owner_receives_household_scope_before_queueing(monkeypatch):
    table = FakeRemoteRequests([])
    monkeypatch.setattr(handler, "remote_requests_table", table)
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable({
        "profile_id": "profile-owner",
        "state": "active",
        "seerr_binding_state": "active",
        "seerr_user_id": "42",
        "household_access_role": "owner",
    }))
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: {
        "profile_id": "profile-owner",
        "household_id": "household-1",
    })
    monkeypatch.setattr(handler, "latest_online_connector_for_profile", lambda profile_id: {"connector_id": "connector-1"})

    result = handler.create_remote_request(event({
        "profile_id": "profile-owner",
        "provider": "seerr",
        "method": "GET",
        "path": "/api/v1/request",
        "query": {"take": 50, "skip": 0, "requestedBy": "42"},
    }))

    assert result["statusCode"] == 202
    queued = next(iter(table.items.values()))
    assert json.loads(queued["request_json"])["query"] == {"take": 50, "skip": 0}


def test_remote_jellyfin_metadata_rewrites_client_identity_to_exact_profile_binding(monkeypatch):
    table = FakeRemoteRequests([])
    profile_id = "profile-member"
    bound_user_id = "0123456789abcdef0123456789abcdef"
    untrusted_user_id = "fedcba9876543210fedcba9876543210"
    monkeypatch.setattr(handler, "remote_requests_table", table)
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable({
        "profile_id": profile_id,
        "state": "active",
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": "connector-1",
        "jellyfin_user_id": bound_user_id,
    }))
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: {
        "profile_id": profile_id,
        "household_id": "household-1",
    })
    monkeypatch.setattr(handler, "latest_online_connector_for_profile", lambda _profile_id: {"connector_id": "connector-1"})

    result = handler.create_remote_request(event({
        "profile_id": profile_id,
        "provider": "jellyfin",
        "method": "GET",
        "path": f"/Shows/{'a' * 32}/Seasons",
        "query": {"userId": untrusted_user_id},
    }))

    assert result["statusCode"] == 202
    queued = json.loads(next(iter(table.items.values()))["request_json"])
    assert queued["query"] == {"userId": bound_user_id}


def test_remote_jellyfin_metadata_requires_exact_profile_binding(monkeypatch):
    table = FakeRemoteRequests([])
    monkeypatch.setattr(handler, "remote_requests_table", table)
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable({
        "profile_id": "profile-member",
        "state": "active",
        "jellyfin_binding_state": "inactive",
    }))
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: {
        "profile_id": "profile-member",
        "household_id": "household-1",
    })
    monkeypatch.setattr(handler, "latest_online_connector_for_profile", lambda _profile_id: {"connector_id": "connector-1"})

    result = handler.create_remote_request(event({
        "profile_id": "profile-member",
        "provider": "jellyfin",
        "method": "GET",
        "path": f"/Shows/{'a' * 32}/Episodes",
        "query": {"userId": "0" * 32},
    }))

    assert result["statusCode"] == 409
    assert json.loads(result["body"])["state"] == "profile_jellyfin_binding_required"
    assert not table.items

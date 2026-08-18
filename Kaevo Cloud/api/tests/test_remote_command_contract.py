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
SPEC = importlib.util.spec_from_file_location("kaevo_cloud_handler", HANDLER_PATH)
assert SPEC is not None and SPEC.loader is not None
handler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handler)


def command(operation: str, parameters: dict):
    return handler.normalize_remote_command(operation, parameters)


def test_jellyfin_user_actions_accept_only_item_ids():
    payload, error = command("jellyfin.favorite", {"item_id": "a" * 32})
    assert error == ""
    assert payload == {
        "provider": "home_server",
        "method": "COMMAND",
        "path": "/commands/jellyfin.favorite",
        "query": {},
        "body": {"item_id": "a" * 32},
    }


def test_jellyfin_user_actions_reject_paths_and_urls():
    payload, error = command("jellyfin.mark_played", {"item_id": "../../Media/Movies"})
    assert payload is None
    assert "Jellyfin id" in error


def test_seerr_request_body_is_bounded_and_normalized():
    payload, error = command(
        "seerr.create_request",
        {"media_type": "TV", "media_id": 42, "seasons": [3, 1, 3], "is_4k": False},
    )
    assert error == ""
    assert payload["body"] == {
        "media_type": "tv",
        "media_id": 42,
        "seasons": [1, 3],
        "is_4k": False,
    }


def test_downloader_queue_command_is_exact_id_bound_and_state_bounded():
    payload, error = command(
        "downloaders.set_queue_state",
        {
            "arr_kind": "SONARR",
            "arr_queue_id": 41,
            "arr_download_client_id": 8,
            "download_id": "SABnzbd_nzo_7f9c",
            "target_state": "PAUSED",
        },
    )
    assert error == ""
    assert payload == {
        "provider": "home_server",
        "method": "COMMAND",
        "path": "/commands/downloaders.set_queue_state",
        "query": {},
        "body": {
            "arr_kind": "sonarr",
            "arr_queue_id": 41,
            "arr_download_client_id": 8,
            "download_id": "SABnzbd_nzo_7f9c",
            "target_state": "paused",
        },
    }

    for invalid in (
        {"arr_kind": "sonarr", "arr_queue_id": 0, "arr_download_client_id": 8, "download_id": "safe", "target_state": "paused"},
        {"arr_kind": "sonarr", "arr_queue_id": 1, "arr_download_client_id": 0, "download_id": "safe", "target_state": "paused"},
        {"arr_kind": "sonarr", "arr_queue_id": 1, "arr_download_client_id": 8, "download_id": "../../unsafe", "target_state": "paused"},
        {"arr_kind": "lidarr", "arr_queue_id": 1, "arr_download_client_id": 8, "download_id": "safe", "target_state": "paused"},
        {"arr_kind": "sonarr", "arr_queue_id": 1, "arr_download_client_id": 8, "download_id": "safe", "target_state": "delete"},
    ):
        rejected, rejected_error = command("downloaders.set_queue_state", invalid)
        assert rejected is None
        assert rejected_error


def test_downloader_queue_command_requires_owner_capability(monkeypatch):
    class RemoteRequests:
        def __init__(self):
            self.items = {}

        def get_item(self, *, Key):
            item = self.items.get(Key["request_id"])
            return {"Item": dict(item)} if item else {}

        def put_item(self, *, Item, **_):
            self.items[Item["request_id"]] = dict(Item)

    monkeypatch.setattr(handler, "remote_requests_table", RemoteRequests())
    monkeypatch.setattr(handler, "require_dev_key", lambda _: False)
    monkeypatch.setattr(
        handler,
        "authorize_protected_owner_download_command",
        lambda _event, profile_id: (
            None
            if profile_id == "owner-profile"
            else handler.response(403, {"state": "unauthorized"})
        ),
    )
    monkeypatch.setattr(handler, "latest_online_connector_for_profile", lambda _: {"connector_id": "connector-1"})

    result = handler.create_remote_command({
        "body": json.dumps({
            "profile_id": "owner-profile",
            "operation": "downloaders.set_queue_state",
            "parameters": {
                "arr_kind": "radarr",
                "arr_queue_id": 9,
                "arr_download_client_id": 4,
                "download_id": "hash-9",
                "target_state": "running",
            },
            "idempotency_key": "owner-download-control-1",
        }),
    })
    assert result["statusCode"] == 202
    queued = next(iter(handler.remote_requests_table.items.values()))
    assert queued["priority"] == 1

    denied = handler.create_remote_command({
        "body": json.dumps({
            "profile_id": "member-profile",
            "operation": "downloaders.set_queue_state",
            "parameters": {
                "arr_kind": "radarr",
                "arr_queue_id": 9,
                "arr_download_client_id": 4,
                "download_id": "hash-9",
                "target_state": "running",
            },
            "idempotency_key": "member-download-control-1",
        }),
    })
    assert denied["statusCode"] == 403


def test_sonarr_episode_search_requires_owner_and_owner_can_poll(monkeypatch):
    class RemoteRequests:
        def __init__(self):
            self.items = {}

        def get_item(self, *, Key):
            item = self.items.get(Key["request_id"])
            return {"Item": dict(item)} if item else {}

        def put_item(self, *, Item, **_):
            self.items[Item["request_id"]] = dict(Item)

    requests = RemoteRequests()
    monkeypatch.setattr(handler, "remote_requests_table", requests)
    monkeypatch.setattr(handler, "require_dev_key", lambda _: False)
    monkeypatch.setattr(
        handler,
        "authorize_protected_owner_download_command",
        lambda _event, profile_id: (
            None
            if profile_id == "owner-profile"
            else handler.response(403, {"state": "owner_required"})
        ),
    )
    monkeypatch.setattr(
        handler,
        "latest_online_connector_for_profile",
        lambda _: {"connector_id": "connector-1"},
    )

    created = handler.create_remote_command({
        "body": json.dumps({
            "profile_id": "owner-profile",
            "operation": "sonarr.search_episodes",
            "parameters": {"episode_ids": [33, 22, 33]},
            "idempotency_key": "owner-sonarr-search-1",
        }),
    })
    assert created["statusCode"] == 202
    request_id, queued = next(iter(requests.items.items()))
    assert json.loads(queued["request_json"])["path"] == "/commands/sonarr.search_episodes"
    assert json.loads(queued["request_json"])["body"] == {"episode_ids": [22, 33]}

    denied = handler.create_remote_command({
        "body": json.dumps({
            "profile_id": "member-profile",
            "operation": "sonarr.search_episodes",
            "parameters": {"episode_ids": [22]},
            "idempotency_key": "member-sonarr-search-1",
        }),
    })
    assert denied["statusCode"] == 403

    monkeypatch.setattr(
        handler,
        "require_profile_auth",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("owner Sonarr polling must retain owner authorization")
        ),
    )
    polled = handler.get_remote_request({}, f"/v1/remote-requests/{request_id}")
    assert polled["statusCode"] == 200


def test_protected_owner_download_command_uses_exact_same_household_profiles(monkeypatch):
    class Profiles:
        def __init__(self):
            self.items = {
                "owner-profile": {
                    "profile_id": "owner-profile",
                    "household_id": "household-1",
                    "state": "active",
                },
                "member-profile": {
                    "profile_id": "member-profile",
                    "household_id": "household-1",
                    "state": "active",
                },
                "foreign-profile": {
                    "profile_id": "foreign-profile",
                    "household_id": "household-2",
                    "state": "active",
                },
            }

        def get_item(self, *, Key, ConsistentRead):
            assert ConsistentRead is True
            item = self.items.get(Key["profile_id"])
            return {"Item": dict(item)} if item else {}

    monkeypatch.setattr(handler, "require_dev_key", lambda _: False)
    monkeypatch.setattr(handler, "identity_profiles_table", Profiles())
    monkeypatch.setattr(
        handler,
        "household_manager_bound_session",
        lambda _event: ({
            "record_type": "access",
            "profile_id": "owner-profile",
            "household_id": "household-1",
            "household_access_role": "owner",
        }, None),
    )

    assert handler.authorize_protected_owner_download_command({}, "owner-profile") is None
    assert handler.authorize_protected_owner_download_command({}, "member-profile") is None
    denied = handler.authorize_protected_owner_download_command({}, "foreign-profile")
    assert denied["statusCode"] == 404
    assert json.loads(denied["body"])["state"] == "target_not_found"


def test_protected_download_command_rejects_non_owner_manager(monkeypatch):
    monkeypatch.setattr(handler, "require_dev_key", lambda _: False)
    monkeypatch.setattr(
        handler,
        "household_manager_bound_session",
        lambda _event: ({
            "record_type": "access",
            "profile_id": "admin-profile",
            "household_id": "household-1",
            "household_access_role": "admin",
        }, None),
    )

    denied = handler.authorize_protected_owner_download_command({}, "member-profile")
    assert denied["statusCode"] == 403
    assert json.loads(denied["body"])["state"] == "owner_required"


def test_protected_owner_can_poll_same_household_download_command(monkeypatch):
    class RemoteRequests:
        def get_item(self, *, Key):
            assert Key == {"request_id": "request-1"}
            return {"Item": {
                "request_id": "request-1",
                "profile_id": "member-profile",
                "status": "completed",
                "request_json": json.dumps({
                    "provider": "home_server",
                    "method": "COMMAND",
                    "path": "/commands/downloaders.set_queue_state",
                    "query": {},
                    "body": {
                        "arr_kind": "radarr",
                        "arr_queue_id": 9,
                        "arr_download_client_id": 4,
                        "download_id": "hash-9",
                        "target_state": "paused",
                    },
                }),
            }}

    monkeypatch.setattr(handler, "remote_requests_table", RemoteRequests())
    monkeypatch.setattr(
        handler,
        "authorize_protected_owner_download_command",
        lambda _event, profile_id: None if profile_id == "member-profile" else handler.response(403, {"state": "unauthorized"}),
    )
    monkeypatch.setattr(
        handler,
        "require_profile_auth",
        lambda *_args: (_ for _ in ()).throw(AssertionError("owner command polling must not consume profile auth first")),
    )

    result = handler.get_remote_request({}, "/v1/remote-requests/request-1")
    assert result["statusCode"] == 200
    assert json.loads(result["body"])["request_id"] == "request-1"


def test_seerr_create_command_derives_the_bound_requester_not_the_client(monkeypatch):
    class RemoteRequests:
        def __init__(self):
            self.items = {}

        def get_item(self, *, Key):
            item = self.items.get(Key["request_id"])
            return {"Item": dict(item)} if item else {}

        def put_item(self, *, Item):
            self.items[Item["request_id"]] = dict(Item)

    class Profiles:
        def get_item(self, *, Key, ConsistentRead):
            assert Key == {"profile_id": "profile-1"}
            assert ConsistentRead is True
            return {"Item": {
                "profile_id": "profile-1",
                "state": "active",
                "household_access_role": "member",
                "request_access_enabled": True,
                "seerr_binding_state": "active",
                "seerr_connector_id": "connector-1",
                "seerr_user_id": "14",
            }}

    remote_requests = RemoteRequests()
    monkeypatch.setattr(handler, "remote_requests_table", remote_requests)
    monkeypatch.setattr(handler, "identity_profiles_table", Profiles())
    monkeypatch.setattr(handler, "require_dev_key", lambda _: False)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: {
        "profile_id": "profile-1",
        "household_id": "household-1",
    })
    monkeypatch.setattr(handler, "latest_online_connector_for_profile", lambda _: {"connector_id": "connector-1"})

    result = handler.create_remote_command({
        "headers": {"authorization": "Bearer scoped-session"},
        "body": (
            '{"profile_id":"profile-1","operation":"seerr.create_request",'
            '"parameters":{"media_type":"movie","media_id":42,"requester_user_id":999},'
            '"idempotency_key":"seerr-create-derived-user-1"}'
        ),
    })

    assert result["statusCode"] == 202
    queued = next(iter(remote_requests.items.values()))
    assert json.loads(queued["request_json"])["body"]["requester_user_id"] == 14


def test_optimizer_execute_requires_plan_token_and_exact_confirmation():
    payload, error = command(
        "optimizer.execute_remux",
        {
            "plan_id": "1ed758af-f117-4a25-8cbb-e03c2cb67ed2",
            "approval_token": "a" * 32,
            "confirmation": "YES_REMUX_ONE_FILE",
        },
    )
    assert error == ""
    assert payload["body"]["confirmation"] == "YES_REMUX_ONE_FILE"

    rejected, rejected_error = command(
        "optimizer.execute_remux",
        {
            "plan_id": "1ed758af-f117-4a25-8cbb-e03c2cb67ed2",
            "approval_token": "a" * 32,
            "confirmation": "yes",
        },
    )
    assert rejected is None
    assert "confirmation" in rejected_error


def test_optimizer_job_status_requires_uuid():
    payload, error = command(
        "optimizer.job_status",
        {"job_id": "1ed758af-f117-4a25-8cbb-e03c2cb67ed2"},
    )
    assert error == ""
    assert payload["body"] == {"job_id": "1ed758af-f117-4a25-8cbb-e03c2cb67ed2"}

    rejected, rejected_error = command("optimizer.job_status", {"job_id": "nope"})
    assert rejected is None
    assert "UUID" in rejected_error


def test_optimizer_pause_and_resume_are_bounded():
    job_id = "1ed758af-f117-4a25-8cbb-e03c2cb67ed2"
    for duration in (0, 60, 360, 720):
        payload, error = command(
            "optimizer.pause_job",
            {"job_id": job_id, "duration_minutes": duration},
        )
        assert error == ""
        assert payload["path"] == "/commands/optimizer.pause_job"
        assert payload["body"] == {"job_id": job_id, "duration_minutes": duration}

    rejected, rejected_error = command(
        "optimizer.pause_job",
        {"job_id": job_id, "duration_minutes": 61},
    )
    assert rejected is None
    assert "0, 60, 360, or 720" in rejected_error

    resumed, error = command("optimizer.resume_job", {"job_id": job_id})
    assert error == ""
    assert resumed["path"] == "/commands/optimizer.resume_job"
    assert resumed["body"] == {"job_id": job_id}


def test_optimizer_interrupted_cleanup_is_item_bound_and_confirmed():
    item_id = "a" * 32
    payload, error = command(
        "optimizer.cleanup_interrupted",
        {"item_id": item_id, "confirmation": "YES_REMOVE_KAEVO_PARTIAL"},
    )
    assert error == ""
    assert payload["path"] == "/commands/optimizer.cleanup_interrupted"
    assert payload["body"] == {
        "item_id": item_id,
        "confirmation": "YES_REMOVE_KAEVO_PARTIAL",
    }

    rejected, rejected_error = command(
        "optimizer.cleanup_interrupted",
        {"item_id": item_id, "confirmation": "yes"},
    )
    assert rejected is None
    assert "confirmation" in rejected_error


def test_optimizer_scan_is_bounded_and_pageable():
    payload, error = command("optimizer.scan", {"limit": 100, "start_index": 200})
    assert error == ""
    assert payload == {
        "provider": "home_server",
        "method": "COMMAND",
        "path": "/commands/optimizer.scan",
        "query": {},
        "body": {"limit": 100, "start_index": 200},
    }

    for invalid_start in (-1, 1_000_001):
        rejected, rejected_error = command(
            "optimizer.scan", {"limit": 50, "start_index": invalid_start}
        )
        assert rejected is None
        assert "start_index" in rejected_error


def test_optimizer_scan_is_available_to_scoped_profile_sessions(monkeypatch):
    class RemoteRequests:
        def __init__(self):
            self.items = {}

        def get_item(self, *, Key):
            item = self.items.get(Key["request_id"])
            return {"Item": dict(item)} if item else {}

        def put_item(self, *, Item):
            self.items[Item["request_id"]] = dict(Item)

    monkeypatch.setattr(handler, "remote_requests_table", RemoteRequests())
    monkeypatch.setattr(handler, "require_dev_key", lambda _: False)
    monkeypatch.setattr(handler, "require_profile_auth", lambda _event, profile_id: profile_id == "profile-1")
    monkeypatch.setattr(handler, "latest_online_connector_for_profile", lambda _: {"connector_id": "connector-1"})

    result = handler.create_remote_command({
        "headers": {"authorization": "Bearer scoped-session"},
        "body": '{"profile_id":"profile-1","operation":"optimizer.scan","parameters":{"limit":100,"start_index":0},"idempotency_key":"optimizer-scan-session-1"}',
    })

    assert result["statusCode"] == 202


def test_optimizer_plan_is_available_to_scoped_profile_sessions(monkeypatch):
    class RemoteRequests:
        def __init__(self):
            self.items = {}

        def get_item(self, *, Key):
            item = self.items.get(Key["request_id"])
            return {"Item": dict(item)} if item else {}

        def put_item(self, *, Item):
            self.items[Item["request_id"]] = dict(Item)

    monkeypatch.setattr(handler, "remote_requests_table", RemoteRequests())
    monkeypatch.setattr(handler, "require_dev_key", lambda _: False)
    monkeypatch.setattr(handler, "require_profile_auth", lambda _event, profile_id: profile_id == "profile-1")
    monkeypatch.setattr(handler, "latest_online_connector_for_profile", lambda _: {"connector_id": "connector-1"})

    result = handler.create_remote_command({
        "headers": {"authorization": "Bearer scoped-session"},
        "body": '{"profile_id":"profile-1","operation":"optimizer.plan_remux","parameters":{"item_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"idempotency_key":"optimizer-plan-session-1"}',
    })

    assert result["statusCode"] == 202


def test_seerr_create_request_is_available_only_to_the_exact_scoped_profile_session(monkeypatch):
    class RemoteRequests:
        def __init__(self):
            self.items = {}
            self.put_count = 0

        def get_item(self, *, Key):
            item = self.items.get(Key["request_id"])
            return {"Item": dict(item)} if item else {}

        def put_item(self, *, Item):
            self.put_count += 1
            self.items[Item["request_id"]] = dict(Item)

    class Profiles:
        def get_item(self, *, Key, ConsistentRead):
            if Key["profile_id"] != "profile-1":
                return {}
            return {"Item": {
                "profile_id": "profile-1",
                "state": "active",
                "household_access_role": "member",
                "request_access_enabled": True,
                "seerr_binding_state": "active",
                "seerr_connector_id": "connector-1",
                "seerr_user_id": "14",
            }}

    remote_requests = RemoteRequests()
    monkeypatch.setattr(handler, "remote_requests_table", remote_requests)
    monkeypatch.setattr(handler, "identity_profiles_table", Profiles())
    monkeypatch.setattr(handler, "require_dev_key", lambda _: False)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: {
        "profile_id": "profile-1",
        "household_id": "household-1",
    })
    monkeypatch.setattr(
        handler,
        "latest_online_connector_for_profile",
        lambda profile_id: (
            {"connector_id": "connector-1"}
            if profile_id == "profile-1"
            else {"connector_id": "connector-2"}
        ),
    )

    body = (
        '{"profile_id":"profile-1","operation":"seerr.create_request",'
        '"parameters":{"media_type":"tv","media_id":42,"seasons":[3,1,3],"is_4k":false},'
        '"idempotency_key":"seerr-create-session-1"}'
    )
    created = handler.create_remote_command({
        "headers": {"authorization": "Bearer scoped-session"},
        "body": body,
    })
    duplicate = handler.create_remote_command({
        "headers": {"authorization": "Bearer scoped-session"},
        "body": body,
    })

    assert created["statusCode"] == 202
    assert duplicate["statusCode"] == 200
    assert remote_requests.put_count == 1

    cross_profile = handler.create_remote_command({
        "headers": {"authorization": "Bearer scoped-session"},
        "body": (
            '{"profile_id":"profile-2","operation":"seerr.create_request",'
            '"parameters":{"media_type":"movie","media_id":43},'
            '"idempotency_key":"seerr-create-session-2"}'
        ),
    })
    assert cross_profile["statusCode"] == 401
    assert remote_requests.put_count == 1


def test_jellyfin_watched_mutations_require_the_exact_scoped_profile_session(monkeypatch):
    class RemoteRequests:
        def __init__(self):
            self.items = {}

        def get_item(self, *, Key):
            item = self.items.get(Key["request_id"])
            return {"Item": dict(item)} if item else {}

        def put_item(self, *, Item):
            self.items[Item["request_id"]] = dict(Item)

    remote_requests = RemoteRequests()
    monkeypatch.setattr(handler, "remote_requests_table", remote_requests)
    monkeypatch.setattr(handler, "require_dev_key", lambda _: False)
    monkeypatch.setattr(
        handler,
        "authorize_profile_switch_session",
        lambda _event, profile_id: (
            (True, {"profile_id": "profile-1", "household_id": "household-1"})
            if profile_id == "profile-1"
            else (False, None)
        ),
    )
    monkeypatch.setattr(
        handler,
        "latest_online_connector_for_profile",
        lambda profile_id: (
            {"connector_id": "connector-1"}
            if profile_id == "profile-1"
            else {"connector_id": "connector-2"}
        ),
    )
    monkeypatch.setattr(
        handler,
        "require_profile_switch_auth",
        lambda _event, profile_id: profile_id == "profile-1",
    )
    monkeypatch.setattr(
        handler,
        "require_profile_auth",
        lambda _event, _profile_id: False,
    )

    for operation, suffix in (("jellyfin.mark_played", "played"), ("jellyfin.mark_unplayed", "unplayed")):
        result = handler.create_remote_command({
            "headers": {"authorization": "Bearer scoped-session"},
            "body": json.dumps({
                "profile_id": "profile-1",
                "operation": operation,
                "parameters": {"item_id": "a" * 32},
                "idempotency_key": f"watched-mutation-{suffix}-1",
            }),
        })

        assert result["statusCode"] == 202
        queued = next(
            item for item in remote_requests.items.values()
            if item["idempotency_key"] == f"watched-mutation-{suffix}-1"
        )
        assert json.loads(queued["request_json"])["path"] == f"/commands/{operation}"

        fetched = handler.get_remote_request(
            {"headers": {"authorization": "Bearer scoped-session"}},
            f"/v1/remote-requests/{queued['request_id']}",
        )
        assert fetched["statusCode"] == 200
        fetched_body = json.loads(fetched["body"])
        assert fetched_body["request_id"] == queued["request_id"]
        assert fetched_body["profile_id"] == "profile-1"
        assert fetched_body["operation"] == operation

    cross_profile = handler.create_remote_command({
        "headers": {"authorization": "Bearer scoped-session"},
        "body": json.dumps({
            "profile_id": "profile-2",
            "operation": "jellyfin.mark_played",
            "parameters": {"item_id": "b" * 32},
            "idempotency_key": "watched-mutation-cross-profile-1",
        }),
    })
    assert cross_profile["statusCode"] == 401

    foreign_request_id = "foreign-watched-mutation"
    remote_requests.items[foreign_request_id] = {
        "request_id": foreign_request_id,
        "profile_id": "profile-2",
        "status": "pending",
        "request_json": json.dumps({
            "provider": "home_server",
            "method": "COMMAND",
            "path": "/commands/jellyfin.mark_played",
            "query": {},
            "body": {"item_id": "b" * 32},
        }),
    }
    cross_profile_readback = handler.get_remote_request(
        {"headers": {"authorization": "Bearer scoped-session"}},
        f"/v1/remote-requests/{foreign_request_id}",
    )
    assert cross_profile_readback["statusCode"] == 401


def test_seerr_cancel_request_remains_denied_to_profile_sessions(monkeypatch):
    monkeypatch.setattr(handler, "remote_requests_table", object())
    monkeypatch.setattr(handler, "require_dev_key", lambda _: False)
    monkeypatch.setattr(handler, "require_profile_auth", lambda _event, _profile_id: True)

    result = handler.create_remote_command({
        "headers": {"authorization": "Bearer scoped-session"},
        "body": (
            '{"profile_id":"profile-1","operation":"seerr.cancel_request",'
            '"parameters":{"request_id":42},'
            '"idempotency_key":"seerr-cancel-session-1"}'
        ),
    })

    assert result["statusCode"] == 401


def test_arbitrary_commands_are_rejected():
    payload, error = command("jellyfin.delete_media", {"item_id": "a" * 32})
    assert payload is None
    assert error == "unsupported remote command"


def test_provider_health_is_allowlisted_and_bounded():
    for provider in ("sonarr", "radarr", "seerr", "lidarr", "readarr", "prowlarr", "bazarr", "tdarr"):
        payload, error = command("provider.health", {"provider": provider.upper()})
        assert error == ""
        assert payload == {
            "provider": "home_server",
            "method": "COMMAND",
            "path": "/commands/provider.health",
            "query": {},
            "body": {"provider": provider},
        }

    rejected, error = command("provider.health", {"provider": "http://lan/admin"})
    assert rejected is None
    assert error == "provider is not supported"


def test_plugin_backed_provider_reads_are_allowlisted_without_secrets():
    allowed = (
        ("seerr", "/api/v1/search", {"query": "dune", "page": "1"}),
        ("sonarr", "/api/v3/series", {}),
        ("radarr", "/api/v3/movie", {}),
        ("lidarr", "/api/v1/artist", {}),
        ("readarr", "/api/v1/author", {}),
        ("prowlarr", "/api/v1/indexerstatus", {}),
        ("bazarr", "/api/system/status", {}),
        ("tdarr", "/api/v2/status", {}),
    )
    for provider, path, query in allowed:
        accepted, error = handler.is_safe_remote_path(provider, path, query)
        assert accepted is True
        assert error == ""

    accepted, error = handler.is_safe_remote_path("seerr", "/api/v1/search", {"apikey": "secret"})
    assert accepted is False
    assert error == "query cannot include secrets"


def test_arr_identity_batches_are_exact_provider_path_bound_and_limited():
    assert handler.is_safe_remote_path("radarr", "/api/v3/movie", {"tmdbIds": "11,22"}) == (True, "")
    assert handler.is_safe_remote_path("sonarr", "/api/v3/series", {"tvdbIds": "33"}) == (True, "")

    rejected = (
        ("radarr", "/api/v3/movie", {"tvdbIds": "11"}),
        ("radarr", "/api/v3/queue", {"tmdbIds": "11"}),
        ("sonarr", "/api/v3/series", {"tvdbIds": "0"}),
        ("sonarr", "/api/v3/series", {"tvdbIds": "11,11"}),
        ("radarr", "/api/v3/movie", {"tmdbIds": ",".join(str(value) for value in range(1, 34))}),
    )
    for provider, path, query in rejected:
        accepted, _ = handler.is_safe_remote_path(provider, path, query)
        assert accepted is False


def test_sonarr_episode_commands_are_id_bounded():
    inventory, error = command("sonarr.episode_inventory", {"tvdb_id": 121361})
    assert error == ""
    assert inventory["body"] == {"tvdb_id": 121361}

    search, error = command("sonarr.search_episodes", {"episode_ids": [9, 4, 9]})
    assert error == ""
    assert search["body"] == {"episode_ids": [4, 9]}

    cancel, error = command("sonarr.cancel_episodes", {"series_id": 17, "episode_ids": [4, 9]})
    assert error == ""
    assert cancel["body"] == {"series_id": 17, "episode_ids": [4, 9]}

    cancel, error = command(
        "sonarr.cancel_episodes",
        {"series_id": 17, "episode_ids": [4], "command_ids": [18, 12, 18]},
    )
    assert error == ""
    assert cancel["body"]["command_ids"] == [12, 18]


def test_sonarr_episode_commands_reject_unbounded_or_invalid_ids():
    payload, error = command("sonarr.search_episodes", {"episode_ids": []})
    assert payload is None
    assert "between 1 and 500" in error

    payload, error = command("sonarr.remove_episode_files", {"series_id": 2, "episode_ids": ["../1"]})
    assert payload is None
    assert "positive integers" in error

    payload, error = command(
        "sonarr.cancel_episodes",
        {"series_id": 2, "episode_ids": [1], "command_ids": [0]},
    )
    assert payload is None
    assert "command_ids must contain positive integers" == error


def test_playback_preparation_is_item_device_and_bitrate_bound():
    payload, error = command("jellyfin.prepare_playback", {
        "item_id": "a" * 32, "device_id": "ios-device-1", "max_bitrate": 20_000_000,
    })
    assert error == ""
    assert payload["body"] == {"item_id": "a" * 32, "device_id": "ios-device-1", "max_bitrate": 20_000_000}
    rejected, _ = command("jellyfin.prepare_playback", {
        "item_id": "a" * 32, "device_id": "https://lan/admin", "max_bitrate": 20_000_000,
    })
    assert rejected is None


def test_playback_preparation_preserves_valid_track_selection():
    payload, error = command("jellyfin.prepare_playback", {
        "item_id": "a" * 32,
        "device_id": "ios-device-1",
        "max_bitrate": 12_000_000,
        "audio_stream_index": 4,
        "subtitle_stream_index": 7,
    })
    assert error == ""
    assert payload["body"]["audio_stream_index"] == 4
    assert payload["body"]["subtitle_stream_index"] == 7

    rejected, rejected_error = command("jellyfin.prepare_playback", {
        "item_id": "a" * 32,
        "device_id": "ios-device-1",
        "max_bitrate": 12_000_000,
        "audio_stream_index": -1,
    })
    assert rejected is None
    assert rejected_error == "audio_stream_index is invalid"


def test_playback_preparation_preserves_compatibility_player_request():
    payload, error = command("jellyfin.prepare_playback", {
        "item_id": "a" * 32,
        "device_id": "ios-device-1",
        "max_bitrate": 12_000_000,
        "compatibility_player": True,
    })
    assert error == ""
    assert payload["body"]["compatibility_player"] is True

    rejected, rejected_error = command("jellyfin.prepare_playback", {
        "item_id": "a" * 32,
        "device_id": "ios-device-1",
        "max_bitrate": 12_000_000,
        "compatibility_player": "true",
    })
    assert rejected is None
    assert rejected_error == "compatibility_player is invalid"


def test_playback_preparation_requires_boolean_media_segment_opt_in():
    payload, error = command("jellyfin.prepare_playback", {
        "item_id": "a" * 32,
        "device_id": "ios-device-1",
        "max_bitrate": 12_000_000,
        "media_segments_enabled": True,
    })
    assert error == ""
    assert payload["body"]["media_segments_enabled"] is True

    rejected, rejected_error = command("jellyfin.prepare_playback", {
        "item_id": "a" * 32,
        "device_id": "ios-device-1",
        "max_bitrate": 12_000_000,
        "media_segments_enabled": "true",
    })
    assert rejected is None
    assert rejected_error == "media_segments_enabled is invalid"


def test_delete_item_is_exact_item_bound():
    payload, error = command("jellyfin.delete_item", {"item_id": "b" * 32})
    assert error == ""
    assert payload["path"] == "/commands/jellyfin.delete_item"
    assert payload["body"] == {"item_id": "b" * 32}


def test_playback_progress_is_identifier_and_position_bound():
    payload, error = command("jellyfin.playback_progress", {
        "item_id": "a" * 32,
        "media_source_id": "media-source-1",
        "play_session_id": "play-session-1",
        "position_ticks": 123_000_000,
        "is_paused": True,
    })
    assert error == ""
    assert payload["path"] == "/commands/jellyfin.playback_progress"
    assert payload["body"]["position_ticks"] == 123_000_000
    assert payload["body"]["is_paused"] is True

    rejected, rejected_error = command("jellyfin.playback_progress", {
        "item_id": "a" * 32,
        "media_source_id": "https://lan/media",
        "play_session_id": "play-session-1",
        "position_ticks": -1,
    })
    assert rejected is None
    assert "media_source_id" in rejected_error


def test_remote_command_route_is_declared_in_sam_template():
    template = (HANDLER_PATH.parents[2] / "infra" / "template.yaml").read_text()
    assert 'DEV_API_KEY: !If [IsProduction, "", !Ref DevApiKey]' in template
    assert "KaevoOwnerAuthorizer:" in template
    assert "Path: /v1/remote-commands" in template
    route_block = template.split("Path: /v1/remote-commands", 1)[1].split("\n\n", 1)[0]
    assert "Method: POST" in route_block


def test_playback_is_prioritized_ahead_of_metadata_and_artwork():
    playback = {"method": "COMMAND", "path": "/commands/jellyfin.prepare_playback"}
    detail = {"method": "GET", "path": f"/Users/{'a' * 32}/Items/{'b' * 32}"}
    snapshot = {"method": "GET", "path": "/kaevo/internal/main-snapshot"}
    artwork = {"method": "GET", "path": "/kaevo/internal/image"}

    priorities = [handler.remote_request_priority(value) for value in (playback, detail, snapshot, artwork)]
    assert priorities == sorted(priorities)
    assert priorities == [0, 10, 30, 90]

    progress = {"method": "COMMAND", "path": "/commands/jellyfin.playback_progress"}
    assert handler.remote_request_priority(progress) == 1


def test_pending_sort_key_includes_zero_padded_priority():
    created_at = "2026-07-15T12:00:00+00:00"
    playback_key = handler.status_sort_key("pending", created_at, "playback", 0)
    artwork_key = handler.status_sort_key("pending", created_at, "artwork", 90)

    assert playback_key == "pending#000#2026-07-15T12:00:00+00:00#playback"
    assert playback_key < artwork_key

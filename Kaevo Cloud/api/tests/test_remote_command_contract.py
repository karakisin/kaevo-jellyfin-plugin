from __future__ import annotations

import importlib.util
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
    assert "DEV_API_KEY: !Ref DevApiKey" in template
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

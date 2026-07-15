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


def test_arbitrary_commands_are_rejected():
    payload, error = command("jellyfin.delete_media", {"item_id": "a" * 32})
    assert payload is None
    assert error == "unsupported remote command"


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


def test_pending_sort_key_includes_zero_padded_priority():
    created_at = "2026-07-15T12:00:00+00:00"
    playback_key = handler.status_sort_key("pending", created_at, "playback", 0)
    artwork_key = handler.status_sort_key("pending", created_at, "artwork", 90)

    assert playback_key == "pending#000#2026-07-15T12:00:00+00:00#playback"
    assert playback_key < artwork_key

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
SPEC = importlib.util.spec_from_file_location("kaevo_cloud_handler_images", HANDLER_PATH)
assert SPEC is not None and SPEC.loader is not None
handler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handler)


def test_remote_image_request_preserves_2160_tier_and_clamps_larger_values():
    item = handler.create_remote_image_request_item(
        profile_id="profile-1",
        connector_id="connector-1",
        provider="jellyfin",
        item_id="a" * 32,
        image_type="Backdrop",
        params={"max_width": "2160", "max_height": "9999", "quality": "99"},
    )

    payload = json.loads(item["request_json"])
    assert payload["path"] == "/kaevo/internal/image"
    assert item["priority"] == 90
    assert payload["query"]["max_width"] == "2160"
    assert payload["query"]["max_height"] == "2160"
    assert payload["query"]["quality"] == "95"


def test_remote_image_defaults_remain_bounded():
    item = handler.create_remote_image_request_item(
        profile_id="profile-1",
        connector_id="connector-1",
        provider="jellyfin",
        item_id="b" * 32,
        image_type="Primary",
        params={},
    )

    query = json.loads(item["request_json"])["query"]
    assert query["max_width"] == "600"
    assert query["max_height"] == "900"
    assert query["quality"] == "90"

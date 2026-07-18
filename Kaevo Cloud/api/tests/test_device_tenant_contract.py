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
SPEC = importlib.util.spec_from_file_location("kaevo_device_tenant_handler", HANDLER_PATH)
assert SPEC is not None and SPEC.loader is not None
handler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handler)


class FakeDevices:
    def __init__(self):
        self.items = {}

    def get_item(self, *, Key):
        item = self.items.get(Key["device_id"])
        return {"Item": dict(item)} if item else {}

    def put_item(self, *, Item):
        self.items[Item["device_id"]] = dict(Item)


def test_profile_cannot_take_over_another_profiles_device(monkeypatch):
    table = FakeDevices()
    table.put_item(Item={"device_id": "shared-device-id", "profile_id": "profile-1"})
    monkeypatch.setattr(handler, "devices_table", table)
    monkeypatch.setattr(handler, "require_profile_auth", lambda _event, profile_id: profile_id == "profile-2")
    result = handler.register_device({
        "headers": {"authorization": "Bearer profile-2-session"},
        "body": json.dumps({"device_id": "shared-device-id", "profile_id": "profile-2"}),
    })
    assert result["statusCode"] == 409
    assert table.items["shared-device-id"]["profile_id"] == "profile-1"

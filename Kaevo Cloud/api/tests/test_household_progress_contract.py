from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path


os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

HANDLER_PATH = Path(os.environ.get(
    "KAEVO_HANDLER_PATH",
    Path(__file__).resolve().parents[1] / "src" / "handler.py",
))
SPEC = importlib.util.spec_from_file_location("kaevo_household_progress_handler", HANDLER_PATH)
assert SPEC is not None and SPEC.loader is not None
handler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handler)


class ExactProfileTable:
    def __init__(self, items):
        self.items = {item["profile_id"]: dict(item) for item in items}

    def get_item(self, *, Key, ConsistentRead=False):
        item = self.items.get(Key["profile_id"])
        return {"Item": dict(item)} if item else {}


class ProgressEventsTable:
    def __init__(self):
        self.items = {}

    def update_item(self, *, Key, ExpressionAttributeValues, **_):
        values = ExpressionAttributeValues
        self.items[(Key["profile_id"], Key["event_key"])] = {
            "profile_id": Key["profile_id"],
            "event_key": Key["event_key"],
            "event_id": values[":event_id"],
            "event_type": values[":event_type"],
            "item_id": values[":item_id"],
            "source": values[":source"],
            "session_id": values[":session_id"],
            "received_at": values[":received_at"],
            "metadata_json": values[":metadata_json"],
        }

    def query(self, **_):
        return {"Items": [dict(item) for item in self.items.values()]}


def configure(monkeypatch):
    source = {
        "profile_id": "cloud-jefferson-001",
        "household_id": "household-001",
        "state": "active",
        "watching_profile_ids": ["cloud-margaret-002"],
    }
    target = {
        "profile_id": "cloud-margaret-002",
        "household_id": "household-001",
        "state": "active",
        "display_name": "Margaret",
        "profile_type": "adult",
    }
    events = ProgressEventsTable()
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable([source, target]))
    monkeypatch.setattr(handler, "events_table", events)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _: {"profile_id": source["profile_id"]})
    return source, events


def request_body(*, selected_ids, sequence=1):
    return {
        "provider": "jellyfin",
        "item_id": "a" * 32,
        "session_id": "play-session-001",
        "media_type": "movie",
        "session_started_at_epoch_milliseconds": 1_784_000_000_000,
        "sequence": sequence,
        "position_seconds": 600,
        "runtime_seconds": 7_200,
        "selected_viewer_profile_ids": selected_ids,
    }


def test_progress_projects_only_to_exact_authorized_viewers(monkeypatch):
    source, events = configure(monkeypatch)
    result = handler.save_household_progress({"body": json.dumps(request_body(selected_ids=[
        source["profile_id"], "cloud-margaret-002",
    ]))})

    assert result["statusCode"] == 202
    body = json.loads(result["body"])
    assert body["profile_ids"] == ["cloud-jefferson-001", "cloud-margaret-002"]
    assert set(profile_id for profile_id, _ in events.items) == {
        "cloud-jefferson-001", "cloud-margaret-002",
    }
    stored = json.loads(events.items[("cloud-margaret-002", "household-progress#jellyfin#" + "a" * 32)]["metadata_json"])
    assert stored["viewer_profile_ids"] == ["cloud-jefferson-001", "cloud-margaret-002"]
    assert "display_name" not in stored


def test_progress_rejects_a_profile_outside_explicit_watching_audience(monkeypatch):
    source, events = configure(monkeypatch)
    result = handler.save_household_progress({"body": json.dumps(request_body(selected_ids=[
        source["profile_id"], "cloud-unrelated-003",
    ]))})

    assert result["statusCode"] == 403
    assert json.loads(result["body"])["state"] == "viewer_selection_not_authorized"
    assert events.items == {}


def test_progress_requires_the_authenticated_active_profile(monkeypatch):
    source, events = configure(monkeypatch)
    result = handler.save_household_progress({"body": json.dumps(request_body(selected_ids=[
        "cloud-margaret-002",
    ]))})

    assert result["statusCode"] == 400
    assert json.loads(result["body"])["state"] == "active_profile_required"
    assert events.items == {}


def test_departing_authorized_viewer_receives_only_its_final_checkpoint(monkeypatch):
    source, events = configure(monkeypatch)
    body = request_body(selected_ids=[source["profile_id"]])
    body["departed_viewer_profile_ids"] = ["cloud-margaret-002"]

    result = handler.save_household_progress({"body": json.dumps(body)})

    assert result["statusCode"] == 202
    departed = json.loads(events.items[("cloud-margaret-002", "household-progress#jellyfin#" + "a" * 32)]["metadata_json"])
    assert departed["viewer_profile_ids"] == ["cloud-jefferson-001", "cloud-margaret-002"]
    assert departed["is_currently_selected"] is False


def test_progress_read_returns_only_the_authenticated_profiles_rows(monkeypatch):
    source, _ = configure(monkeypatch)
    assert handler.save_household_progress({"body": json.dumps(request_body(selected_ids=[source["profile_id"]]))})["statusCode"] == 202

    result = handler.get_household_progress({})

    assert result["statusCode"] == 200
    body = json.loads(result["body"])
    assert body["profile_id"] == source["profile_id"]
    assert body["items"][0]["item_id"] == "a" * 32
    assert body["items"][0]["viewer_profile_ids"] == [source["profile_id"]]


def test_template_exposes_protected_household_progress_read_and_write_routes():
    template = (HANDLER_PATH.parents[2] / "infra" / "template.yaml").read_text()
    route_blocks = template.split("Path: /v1/household-progress")

    assert len(route_blocks) == 3
    assert "Method: POST" in route_blocks[1].split("\n\n", 1)[0]
    assert "Method: GET" in route_blocks[2].split("\n\n", 1)[0]


def test_template_keeps_the_canonical_roster_query_grant_explicit():
    template = (HANDLER_PATH.parents[2] / "infra" / "template.yaml").read_text()

    assert "Sid: ReadCanonicalHouseholdMembershipRoster" in template
    assert "- dynamodb:Query" in template
    assert "Resource: !GetAtt KaevoHouseholdMembershipsTable.Arn" in template

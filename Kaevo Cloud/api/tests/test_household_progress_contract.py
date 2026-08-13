from __future__ import annotations

import importlib.util
import base64
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
        self.update_requests = []

    def update_item(self, *, Key, ExpressionAttributeValues, **kwargs):
        self.update_requests.append({
            "key": dict(Key),
            "names": dict(kwargs.get("ExpressionAttributeNames") or {}),
            "update": kwargs.get("UpdateExpression"),
            "condition": kwargs.get("ConditionExpression"),
        })
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

    def get_item(self, *, Key, ConsistentRead=False):
        item = self.items.get((Key["profile_id"], Key["event_key"]))
        return {"Item": dict(item)} if item else {}

    def query(self, **_):
        return {"Items": [dict(item) for item in self.items.values()]}


def configure(monkeypatch):
    source = {
        "profile_id": "cloud-jefferson-001",
        "household_id": "household-001",
        "state": "active",
        "switch_profile_ids": ["cloud-margaret-002"],
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
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _: {
        "profile_id": source["profile_id"],
        "household_id": source["household_id"],
    })
    return source, events


def request_body(*, selected_ids, sequence=1, position_seconds=600, session_started_at_epoch_milliseconds=1_784_000_000_000, item_id=None, playback_state="active"):
    return {
        "provider": "jellyfin",
        "item_id": item_id or "a" * 32,
        "session_id": "play-session-001",
        "media_type": "movie",
        "session_started_at_epoch_milliseconds": session_started_at_epoch_milliseconds,
        "sequence": sequence,
        "position_seconds": position_seconds,
        "runtime_seconds": 7_200,
        "selected_viewer_profile_ids": selected_ids,
        "playback_state": playback_state,
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
    assert stored["family_sync_profile_ids"] == ["cloud-jefferson-001", "cloud-margaret-002"]
    assert stored["playback_state"] == "active"
    assert "display_name" not in stored


def test_progress_escapes_dynamodb_reserved_attributes_in_both_expressions(monkeypatch):
    source, events = configure(monkeypatch)

    result = handler.save_household_progress({"body": json.dumps(request_body(selected_ids=[source["profile_id"]]))})

    assert result["statusCode"] == 202
    write = events.update_requests[0]
    assert write["names"]["#source"] == "source"
    assert write["names"]["#timestamp"] == "timestamp"
    assert write["names"]["#sequence"] == "sequence"
    assert "#source = :source" in write["update"]
    assert "#timestamp = :timestamp" in write["update"]
    assert "#sequence < :sequence" in write["condition"]


def test_progress_ignores_provisional_zero_without_replacing_checkpoint(monkeypatch):
    source, events = configure(monkeypatch)
    selected_ids = [source["profile_id"], "cloud-margaret-002"]

    assert handler.save_household_progress({"body": json.dumps(request_body(selected_ids=selected_ids))})["statusCode"] == 202
    result = handler.save_household_progress({"body": json.dumps(request_body(
        selected_ids=[source["profile_id"]],
        position_seconds=0,
        session_started_at_epoch_milliseconds=1_784_000_001_000,
    ))})

    assert result["statusCode"] == 202
    assert json.loads(result["body"])["state"] == "ignored_below_threshold"
    stored = json.loads(events.items[(source["profile_id"], "household-progress#jellyfin#" + "a" * 32)]["metadata_json"])
    assert stored["position_seconds"] == 600


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
    assert departed["playback_state"] == "stopped"


def test_progress_read_returns_only_the_authenticated_profiles_rows(monkeypatch):
    source, _ = configure(monkeypatch)
    assert handler.save_household_progress({"body": json.dumps(request_body(selected_ids=[
        source["profile_id"], "cloud-margaret-002",
    ]))})["statusCode"] == 202

    result = handler.get_household_progress({})

    assert result["statusCode"] == 200
    body = json.loads(result["body"])
    assert body["profile_id"] == source["profile_id"]
    assert len(body["revision"]) == 24
    assert body["items"][0]["item_id"] == "a" * 32
    assert body["items"][0]["viewer_profile_ids"] == ["cloud-jefferson-001", "cloud-margaret-002"]
    assert body["items"][0]["viewer_progress"] == [
        {
            "profile_id": "cloud-jefferson-001",
            "position_seconds": 600.0,
            "runtime_seconds": 7200.0,
            "is_currently_selected": True,
            "playback_state": "active",
            "updated_at": body["items"][0]["updated_at"],
        },
        {
            "profile_id": "cloud-margaret-002",
            "position_seconds": 600.0,
            "runtime_seconds": 7200.0,
            "is_currently_selected": True,
            "playback_state": "active",
            "updated_at": body["items"][0]["updated_at"],
        },
    ]


def test_progress_write_and_read_use_one_exact_switch_authorized_profile(monkeypatch):
    _, events = configure(monkeypatch)
    body = request_body(selected_ids=["cloud-margaret-002"])
    body["profile_id"] = "cloud-margaret-002"

    written = handler.save_household_progress({"body": json.dumps(body)})
    read = handler.get_household_progress({
        "queryStringParameters": {"profile_id": "cloud-margaret-002"},
    })

    assert written["statusCode"] == 202
    assert json.loads(written["body"])["profile_ids"] == ["cloud-margaret-002"]
    assert ("cloud-margaret-002", "household-progress#jellyfin#" + "a" * 32) in events.items
    assert read["statusCode"] == 200
    assert json.loads(read["body"])["profile_id"] == "cloud-margaret-002"


def test_progress_read_keeps_an_authorized_viewer_checkpoint_after_a_solo_session(monkeypatch):
    source, events = configure(monkeypatch)
    assert handler.save_household_progress({"body": json.dumps(request_body(selected_ids=[
        source["profile_id"], "cloud-margaret-002",
    ]))})["statusCode"] == 202

    # The source profile later writes a meaningful solo checkpoint. The exact
    # item's explicit Family Sync membership remains intact.
    assert handler.save_household_progress({"body": json.dumps(request_body(
        selected_ids=[source["profile_id"]],
        position_seconds=720,
        session_started_at_epoch_milliseconds=1_784_000_001_000,
    ))})["statusCode"] == 202

    body = json.loads(handler.get_household_progress({})["body"])
    checkpoints = {entry["profile_id"]: entry["position_seconds"] for entry in body["items"][0]["viewer_progress"]}
    assert checkpoints == {"cloud-jefferson-001": 720.0, "cloud-margaret-002": 600.0}
    assert events.items[(source["profile_id"], "household-progress#jellyfin#" + "a" * 32)]


def test_independent_solo_histories_do_not_create_family_sync(monkeypatch):
    source, events = configure(monkeypatch)
    assert handler.save_household_progress({"body": json.dumps(request_body(
        selected_ids=[source["profile_id"]],
    ))})["statusCode"] == 202

    event_key = "household-progress#jellyfin#" + "a" * 32
    events.items[("cloud-margaret-002", event_key)] = {
        "profile_id": "cloud-margaret-002",
        "event_key": event_key,
        "event_id": "independent-session",
        "event_type": handler.HOUSEHOLD_PROGRESS_EVENT_TYPE,
        "item_id": "a" * 32,
        "source": "kaevo_household_sync",
        "session_id": "margaret-solo",
        "received_at": "2026-08-11T12:00:00Z",
        "metadata_json": json.dumps({
            "position_seconds": 1_200,
            "runtime_seconds": 7_200,
            "family_sync_profile_ids": [],
            "is_currently_selected": False,
            "playback_state": "stopped",
        }),
    }

    item = json.loads(handler.get_household_progress({})["body"])["items"][0]
    assert item["viewer_profile_ids"] == []
    assert item["viewer_progress"] == [{
        "profile_id": source["profile_id"],
        "position_seconds": 600.0,
        "runtime_seconds": 7200.0,
        "is_currently_selected": True,
        "playback_state": "active",
        "updated_at": item["updated_at"],
    }]


def test_family_sync_membership_does_not_carry_to_next_episode(monkeypatch):
    source, _ = configure(monkeypatch)
    assert handler.save_household_progress({"body": json.dumps(request_body(selected_ids=[
        source["profile_id"], "cloud-margaret-002",
    ]))})["statusCode"] == 202
    assert handler.save_household_progress({"body": json.dumps(request_body(
        selected_ids=[source["profile_id"]],
        item_id="b" * 32,
        session_started_at_epoch_milliseconds=1_784_000_001_000,
    ))})["statusCode"] == 202

    items = {
        entry["item_id"]: entry
        for entry in json.loads(handler.get_household_progress({})["body"])["items"]
    }
    assert len(items["a" * 32]["viewer_progress"]) == 2
    assert items["b" * 32]["viewer_profile_ids"] == []
    assert [entry["profile_id"] for entry in items["b" * 32]["viewer_progress"]] == [
        source["profile_id"],
    ]


def decode_ticket_payload(ticket):
    encoded = ticket.split(".", 1)[0]
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))


def test_live_publisher_ticket_preserves_exact_item_audience(monkeypatch):
    source, _ = configure(monkeypatch)
    monkeypatch.setattr(handler, "PLAYBACK_GRANT_SIGNING_KEY", "x" * 32)
    monkeypatch.setattr(handler, "PLAYBACK_RELAY_PUBLIC_URL", "https://relay.example")
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _: {
        "profile_id": source["profile_id"],
        "installation_id": "installation-001",
    })
    assert handler.save_household_progress({"body": json.dumps(request_body(selected_ids=[
        source["profile_id"], "cloud-margaret-002",
    ]))})["statusCode"] == 202

    ticket_request = request_body(selected_ids=[source["profile_id"]])
    ticket_request["role"] = "publisher"
    for field in ("sequence", "position_seconds", "runtime_seconds", "playback_state"):
        ticket_request.pop(field)
    result = handler.create_family_sync_live_ticket({"body": json.dumps(ticket_request)})

    assert result["statusCode"] == 201
    body = json.loads(result["body"])
    assert body["websocket_url"] == "wss://relay.example/v1/family-sync"
    claims = decode_ticket_payload(body["relay_ticket"])
    assert claims["profile_id"] == source["profile_id"]
    assert claims["installation_id"] == "installation-001"
    assert claims["audience_profile_ids"] == ["cloud-jefferson-001", "cloud-margaret-002"]
    assert claims["allowed_profile_ids"] == ["cloud-jefferson-001", "cloud-margaret-002"]
    assert "display_name" not in claims


def test_live_ticket_reuses_the_single_verified_dpop_session(monkeypatch):
    source, _ = configure(monkeypatch)
    monkeypatch.setattr(handler, "PLAYBACK_GRANT_SIGNING_KEY", "x" * 32)
    monkeypatch.setattr(handler, "PLAYBACK_RELAY_PUBLIC_URL", "https://relay.example")
    authentication_calls = []

    def authenticate_once(_):
        authentication_calls.append(True)
        if len(authentication_calls) > 1:
            return None
        return {
            "profile_id": source["profile_id"],
            "installation_id": "installation-001",
        }

    monkeypatch.setattr(handler, "authenticated_app_session", authenticate_once)
    result = handler.create_family_sync_live_ticket({"body": json.dumps({"role": "observer"})})

    assert result["statusCode"] == 201
    assert len(authentication_calls) == 1
    claims = decode_ticket_payload(json.loads(result["body"])["relay_ticket"])
    assert claims["installation_id"] == "installation-001"


def test_live_ticket_rejects_ungranted_viewer(monkeypatch):
    source, _ = configure(monkeypatch)
    monkeypatch.setattr(handler, "PLAYBACK_GRANT_SIGNING_KEY", "x" * 32)
    monkeypatch.setattr(handler, "PLAYBACK_RELAY_PUBLIC_URL", "https://relay.example")
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _: {
        "profile_id": source["profile_id"],
        "installation_id": "installation-001",
    })
    body = request_body(selected_ids=[source["profile_id"], "cloud-unrelated-003"])
    body["role"] = "publisher"
    result = handler.create_family_sync_live_ticket({"body": json.dumps(body)})
    assert result["statusCode"] == 403
    assert json.loads(result["body"])["state"] == "viewer_selection_not_authorized"


def test_template_exposes_protected_household_progress_routes():
    template = (HANDLER_PATH.parents[2] / "infra" / "template.yaml").read_text()
    assert template.count("Path: /v1/household-progress\n") == 2
    assert template.count("Path: /v1/household-progress/live-ticket\n") == 1


def test_template_keeps_the_canonical_roster_query_grant_explicit():
    template = (HANDLER_PATH.parents[2] / "infra" / "template.yaml").read_text()

    assert "Sid: ReadCanonicalHouseholdMembershipRoster" in template
    assert "- dynamodb:Query" in template
    assert "Resource: !GetAtt KaevoHouseholdMembershipsTable.Arn" in template

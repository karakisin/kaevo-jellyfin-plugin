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
TEMPLATE_PATH = Path(__file__).resolve().parents[2] / "infra" / "template.yaml"
SPEC = importlib.util.spec_from_file_location("kaevo_bug_report_handler", HANDLER_PATH)
assert SPEC is not None and SPEC.loader is not None
handler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handler)


def test_bug_report_history_route_is_declared_in_sam_template():
    template = TEMPLATE_PATH.read_text()
    assert "Path: /v1/bug-reports" in template
    assert "Method: GET" in template.split("Path: /v1/bug-reports", 1)[1].split("\n\n", 1)[0]


class FakeEvents:
    def __init__(self, pages):
        self.pages = pages
        self.calls = 0

    def query(self, **_kwargs):
        page = self.pages[self.calls]
        self.calls += 1
        return page


def test_bug_report_history_is_profile_authorized_and_filters_unrelated_events(monkeypatch):
    table = FakeEvents([
        {
            "Items": [
                {
                    "event_id": "resolved-event",
                    "event_type": "bug_report_resolved",
                    "item_id": "KV-ABC12345",
                    "timestamp": "2026-08-14T04:00:00Z",
                    "metadata_json": json.dumps({
                        "resolution": "The full episode row now starts playback.",
                        "probable_cause": "Only the thumbnail owned playback.",
                    }),
                },
                {
                    "event_id": "playback-event",
                    "event_type": "playback_progress",
                    "item_id": "media-id",
                    "timestamp": "2026-08-14T03:00:00Z",
                    "metadata_json": "{}",
                },
            ]
        }
    ])
    monkeypatch.setattr(handler, "events_table", table)
    monkeypatch.setattr(handler, "require_profile_auth", lambda _event, profile_id: profile_id == "profile-1")

    denied = handler.bug_report_events({"queryStringParameters": {"profile_id": "profile-2"}})
    assert denied["statusCode"] == 401

    table.calls = 0
    accepted = handler.bug_report_events({"queryStringParameters": {"profile_id": "profile-1"}})
    assert accepted["statusCode"] == 200
    payload = json.loads(accepted["body"])
    assert payload["profile_id"] == "profile-1"
    assert payload["items"] == [{
        "event_id": "resolved-event",
        "event_type": "bug_report_resolved",
        "reference": "KV-ABC12345",
        "timestamp": "2026-08-14T04:00:00Z",
        "metadata": {
            "resolution": "The full episode row now starts playback.",
            "probable_cause": "Only the thumbnail owned playback.",
        },
    }]


def test_bug_report_history_follows_bounded_event_pages(monkeypatch):
    table = FakeEvents([
        {
            "Items": [{
                "event_id": "other",
                "event_type": "search",
                "item_id": "",
                "timestamp": "2026-08-14T03:00:00Z",
                "metadata_json": "{}",
            }],
            "LastEvaluatedKey": {"profile_id": "profile-1", "event_key": "cursor"},
        },
        {
            "Items": [{
                "event_id": "submitted-event",
                "event_type": "bug_report_submitted",
                "item_id": "KV-ABC12345",
                "timestamp": "2026-08-14T02:00:00Z",
                "metadata_json": json.dumps({"title": "Controls stay visible", "category": "ux"}),
            }]
        },
    ])
    monkeypatch.setattr(handler, "events_table", table)
    monkeypatch.setattr(handler, "require_profile_auth", lambda _event, _profile_id: True)

    result = handler.bug_report_events({"queryStringParameters": {"profile_id": "profile-1"}})
    payload = json.loads(result["body"])
    assert table.calls == 2
    assert [item["reference"] for item in payload["items"]] == ["KV-ABC12345"]

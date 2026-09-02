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
    verification = template.split("Path: /v1/bug-reports/verification", 1)[1].split("\n\n", 1)[0]
    assert "Method: POST" in verification


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
                        "user_action": "Update to Kaevo 4.3 and try again.",
                        "fixed_in_version": "4.3",
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
    body = json.loads(accepted["body"])
    resolved = body["items"][0]
    assert resolved["metadata"]["user_action"] == "Update to Kaevo 4.3 and try again."
    assert resolved["metadata"]["fixed_in_version"] == "4.3"
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
            "user_action": "Update to Kaevo 4.3 and try again.",
            "fixed_in_version": "4.3",
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


def test_sentry_event_binding_must_match_the_immutable_report_reference(monkeypatch):
    table = FakeEvents([{
        "Items": [{
            "event_type": "bug_report_submitted",
            "item_id": "KV-1B1D2228",
            "metadata_json": json.dumps({
                "sentry_event_id": "1b1d2228a1ed4ac2b70d6f9924619659",
            }),
        }],
    }])
    monkeypatch.setattr(handler, "events_table", table)

    assert handler._bug_report_sentry_event_id(
        "profile-1", "KV-1B1D2228"
    ) == "1b1d2228a1ed4ac2b70d6f9924619659"

    table.calls = 0
    assert handler._bug_report_sentry_event_id("profile-1", "KV-AD4A4D54") == ""


class FakeVerificationEvents:
    def __init__(self, latest):
        self.latest = latest
        self.writes = []

    def query(self, **_kwargs):
        return {"Items": [self.latest] if self.latest else []}

    def put_item(self, Item):
        self.writes.append(Item)


def test_exact_reporter_can_confirm_only_a_support_requested_fix(monkeypatch):
    table = FakeVerificationEvents({
        "event_type": "bug_report_verification_requested",
        "item_id": "KV-ABC12345",
        "metadata_json": json.dumps({
            "resolution": "The control now stays inside its button.",
            "probable_cause": "The progress lane did not reserve height.",
            "user_action": "Update to Kaevo 4.3 and try the same title.",
            "fixed_in_version": "4.3",
            "sentry_issue_id": "7673194304",
        }),
    })
    monkeypatch.setattr(handler, "events_table", table)
    monkeypatch.setattr(handler, "require_profile_auth", lambda _event, profile_id: profile_id == "profile-1")
    monkeypatch.setattr(
        handler,
        "_resolve_bug_report_sentry_issue",
        lambda profile_id, reference, proposed: {
            "issue_id": proposed["sentry_issue_id"],
            "status": "resolved",
            "linked_issue_id": "7706478224",
            "linked_issue_status": "resolved",
        },
    )

    result = handler.verify_bug_report_fix({
        "body": json.dumps({
            "profile_id": "profile-1",
            "reference": "KV-ABC12345",
            "verdict": "fixed",
        })
    })

    assert result["statusCode"] == 202
    assert json.loads(result["body"])["state"] == "resolved"
    assert table.writes[0]["event_type"] == "bug_report_verified_resolved"
    metadata = json.loads(table.writes[0]["metadata_json"])
    assert metadata["verification_result"] == "fixed"
    assert metadata["sentry_issue_id"] == "7673194304"
    assert metadata["sentry_issue_status"] == "resolved"
    assert metadata["sentry_linked_issue_id"] == "7706478224"
    assert metadata["sentry_linked_issue_status"] == "resolved"


def test_sentry_failure_does_not_falsely_resolve_the_kaevo_report(monkeypatch):
    table = FakeVerificationEvents({
        "event_type": "bug_report_verification_requested",
        "item_id": "KV-ABC12345",
        "metadata_json": json.dumps({"sentry_issue_id": "7673194304"}),
    })
    monkeypatch.setattr(handler, "events_table", table)
    monkeypatch.setattr(handler, "require_profile_auth", lambda _event, _profile_id: True)

    def fail_resolution(*_args, **_kwargs):
        raise handler.SentryIssueResolutionError(
            "sentry_resolution_request_failed", retryable=True
        )

    monkeypatch.setattr(handler, "_resolve_bug_report_sentry_issue", fail_resolution)

    result = handler.verify_bug_report_fix({
        "body": json.dumps({
            "profile_id": "profile-1",
            "reference": "KV-ABC12345",
            "verdict": "fixed",
        })
    })

    assert result["statusCode"] == 503
    assert json.loads(result["body"])["state"] == "sentry_resolution_request_failed"
    assert table.writes == []


def test_not_fixed_returns_the_exact_report_to_pending(monkeypatch):
    table = FakeVerificationEvents({
        "event_type": "bug_report_verification_requested",
        "item_id": "KV-ABC12345",
        "metadata_json": json.dumps({"resolution": "Proposed fix"}),
    })
    monkeypatch.setattr(handler, "events_table", table)
    monkeypatch.setattr(handler, "require_profile_auth", lambda _event, _profile_id: True)

    result = handler.verify_bug_report_fix({
        "body": json.dumps({
            "profile_id": "profile-1",
            "reference": "KV-ABC12345",
            "verdict": "not_fixed",
            "additional_details": "The episode starts now, but the loading notice never disappears.",
        })
    })

    assert result["statusCode"] == 202
    assert json.loads(result["body"])["state"] == "pending"
    assert table.writes[0]["event_type"] == "bug_report_reopened"
    metadata = json.loads(table.writes[0]["metadata_json"])
    assert metadata["reporter_feedback"] == "The episode starts now, but the loading notice never disappears."


def test_not_fixed_requires_additional_reporter_details(monkeypatch):
    table = FakeVerificationEvents({
        "event_type": "bug_report_verification_requested",
        "item_id": "KV-ABC12345",
        "metadata_json": json.dumps({"resolution": "Proposed fix"}),
    })
    monkeypatch.setattr(handler, "events_table", table)
    monkeypatch.setattr(handler, "require_profile_auth", lambda _event, _profile_id: True)

    result = handler.verify_bug_report_fix({
        "body": json.dumps({
            "profile_id": "profile-1",
            "reference": "KV-ABC12345",
            "verdict": "not_fixed",
        })
    })

    assert result["statusCode"] == 400
    assert "additional_details is required" in json.loads(result["body"])["message"]
    assert table.writes == []


def test_reporter_cannot_forge_a_resolution_through_normal_event_capture(monkeypatch):
    table = FakeVerificationEvents(None)
    monkeypatch.setattr(handler, "events_table", table)
    monkeypatch.setattr(handler, "require_profile_auth", lambda _event, _profile_id: True)

    result = handler.save_event({
        "body": json.dumps({
            "profile_id": "profile-1",
            "event_type": "bug_report_resolved",
            "item_id": "KV-ABC12345",
        })
    })

    assert result["statusCode"] == 403
    assert table.writes == []

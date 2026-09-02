from __future__ import annotations

import json

import pytest

from sentry_issue_resolution import (
    SentryIssueResolutionError,
    parse_credentials,
    resolve_feedback_issue,
)


class FakeResponse:
    def __init__(self, document):
        self.payload = json.dumps(document).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


class FakeOpener:
    def __init__(self, documents):
        self.documents = list(documents)
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append((request, timeout))
        return FakeResponse(self.documents.pop(0))


def feedback_issue(*, status="unresolved", event_id="a" * 32):
    return {
        "id": "7673194304",
        "status": status,
        "issueCategory": "feedback",
        "project": {"slug": "apple-ios"},
        "metadata": {"associated_event_id": event_id},
    }


def linked_event(*, event_id="a" * 32, group_id="7706478224"):
    return {
        "eventID": event_id,
        "groupID": group_id,
    }


def linked_issue(*, status="unresolved", issue_id="7706478224"):
    return {
        "id": issue_id,
        "status": status,
        "issueCategory": "error",
        "project": {"slug": "apple-ios"},
    }


def test_credentials_require_only_the_bounded_server_fields():
    credentials = parse_credentials(json.dumps({
        "auth_token": "secret-token",
        "organization_slug": "kaevo",
        "project_slug": "apple-ios",
        "ignored": "not retained",
    }))

    assert credentials == {
        "auth_token": "secret-token",
        "organization_slug": "kaevo",
        "project_slug": "apple-ios",
    }


def test_exact_feedback_issue_is_verified_before_it_is_resolved():
    opener = FakeOpener([
        feedback_issue(),
        linked_event(),
        linked_issue(),
        feedback_issue(status="resolved"),
        linked_issue(status="resolved"),
    ])

    result = resolve_feedback_issue(
        auth_token="secret-token",
        organization_slug="kaevo",
        project_slug="apple-ios",
        issue_id="7673194304",
        linked_issue_id="7706478224",
        associated_event_id="a" * 32,
        opener=opener,
    )

    assert result == {
        "issue_id": "7673194304",
        "status": "resolved",
        "linked_issue_id": "7706478224",
        "linked_issue_status": "resolved",
    }
    assert [item[0].method for item in opener.requests] == [
        "GET", "GET", "GET", "PUT", "PUT",
    ]
    assert json.loads(opener.requests[3][0].data) == {"status": "resolved"}
    assert opener.requests[3][0].full_url == (
        "https://sentry.io/api/0/organizations/kaevo/issues/7673194304/"
    )
    assert opener.requests[1][0].full_url == (
        "https://sentry.io/api/0/organizations/kaevo/issues/7706478224/events/"
        + ("a" * 32)
        + "/"
    )
    assert json.loads(opener.requests[4][0].data) == {"status": "resolved"}
    assert opener.requests[4][0].full_url == (
        "https://sentry.io/api/0/organizations/kaevo/issues/7706478224/"
    )


def test_mismatched_feedback_event_fails_closed_without_a_write():
    opener = FakeOpener([feedback_issue(event_id="b" * 32)])

    with pytest.raises(SentryIssueResolutionError) as caught:
        resolve_feedback_issue(
            auth_token="secret-token",
            organization_slug="kaevo",
            project_slug="apple-ios",
            issue_id="7673194304",
            linked_issue_id="7706478224",
            associated_event_id="a" * 32,
            opener=opener,
        )

    assert caught.value.state == "sentry_issue_link_mismatch"
    assert [item[0].method for item in opener.requests] == ["GET"]


def test_already_resolved_exact_issue_is_idempotent():
    opener = FakeOpener([
        feedback_issue(status="resolved"),
        linked_event(),
        linked_issue(status="resolved"),
    ])

    result = resolve_feedback_issue(
        auth_token="secret-token",
        organization_slug="kaevo",
        project_slug="apple-ios",
        issue_id="7673194304",
        linked_issue_id="7706478224",
        associated_event_id="a" * 32,
        opener=opener,
    )

    assert result["status"] == "resolved"
    assert result["linked_issue_status"] == "resolved"
    assert [item[0].method for item in opener.requests] == ["GET", "GET", "GET"]


def test_mismatched_linked_issue_fails_closed_before_any_write():
    opener = FakeOpener([
        feedback_issue(),
        linked_event(),
        linked_issue(issue_id="9999999999"),
    ])

    with pytest.raises(SentryIssueResolutionError) as caught:
        resolve_feedback_issue(
            auth_token="secret-token",
            organization_slug="kaevo",
            project_slug="apple-ios",
            issue_id="7673194304",
            linked_issue_id="7706478224",
            associated_event_id="a" * 32,
            opener=opener,
        )

    assert caught.value.state == "sentry_linked_issue_mismatch"
    assert [item[0].method for item in opener.requests] == ["GET", "GET", "GET"]

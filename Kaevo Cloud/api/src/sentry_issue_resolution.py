"""Exact, fail-closed Sentry feedback issue resolution for Kaevo reports."""

from __future__ import annotations

import json
import re
from urllib import error, parse, request


SENTRY_EVENT_ID_PATTERN = re.compile(r"^[a-f0-9]{32}$")
SENTRY_ISSUE_ID_PATTERN = re.compile(r"^[0-9]+$")


class SentryIssueResolutionError(Exception):
    """A bounded Sentry resolution failure safe to translate at the API edge."""

    def __init__(self, state: str, *, retryable: bool):
        super().__init__(state)
        self.state = state
        self.retryable = retryable


def parse_credentials(secret_string: str) -> dict[str, str]:
    try:
        document = json.loads(str(secret_string or ""))
    except json.JSONDecodeError as exc:
        raise SentryIssueResolutionError(
            "sentry_resolution_configuration_invalid", retryable=False
        ) from exc
    if not isinstance(document, dict):
        raise SentryIssueResolutionError(
            "sentry_resolution_configuration_invalid", retryable=False
        )

    credentials = {
        "auth_token": str(document.get("auth_token") or "").strip(),
        "organization_slug": str(document.get("organization_slug") or "").strip(),
        "project_slug": str(document.get("project_slug") or "").strip(),
    }
    if any(not value for value in credentials.values()):
        raise SentryIssueResolutionError(
            "sentry_resolution_configuration_invalid", retryable=False
        )
    if not all(
        re.fullmatch(r"[a-z0-9][a-z0-9_-]*", credentials[key])
        for key in ("organization_slug", "project_slug")
    ):
        raise SentryIssueResolutionError(
            "sentry_resolution_configuration_invalid", retryable=False
        )
    return credentials


def _request_json(
    *,
    url: str,
    auth_token: str,
    method: str = "GET",
    body: dict | None = None,
    opener=None,
) -> dict:
    encoded = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Accept": "application/json",
    }
    if encoded is not None:
        headers["Content-Type"] = "application/json"
    req = request.Request(url, data=encoded, headers=headers, method=method)
    transport = opener or request.urlopen
    try:
        with transport(req, timeout=5) as response:
            payload = response.read()
    except error.HTTPError as exc:
        retryable = exc.code == 429 or exc.code >= 500
        raise SentryIssueResolutionError(
            "sentry_resolution_request_failed", retryable=retryable
        ) from exc
    except (error.URLError, TimeoutError, OSError) as exc:
        raise SentryIssueResolutionError(
            "sentry_resolution_request_failed", retryable=True
        ) from exc
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SentryIssueResolutionError(
            "sentry_resolution_response_invalid", retryable=True
        ) from exc
    if not isinstance(document, dict):
        raise SentryIssueResolutionError(
            "sentry_resolution_response_invalid", retryable=True
        )
    return document


def resolve_feedback_issue(
    *,
    auth_token: str,
    organization_slug: str,
    project_slug: str,
    issue_id: str,
    linked_issue_id: str,
    associated_event_id: str,
    opener=None,
) -> dict[str, str]:
    """Resolve the exact feedback issue and its exact linked event issue."""
    normalized_issue_id = str(issue_id or "").strip()
    normalized_linked_issue_id = str(linked_issue_id or "").strip()
    normalized_event_id = str(associated_event_id or "").strip().lower()
    if not SENTRY_ISSUE_ID_PATTERN.fullmatch(normalized_issue_id):
        raise SentryIssueResolutionError("sentry_issue_link_invalid", retryable=False)
    if not SENTRY_EVENT_ID_PATTERN.fullmatch(normalized_event_id):
        raise SentryIssueResolutionError("sentry_event_link_invalid", retryable=False)
    if (
        not SENTRY_ISSUE_ID_PATTERN.fullmatch(normalized_linked_issue_id)
        or normalized_linked_issue_id == normalized_issue_id
    ):
        raise SentryIssueResolutionError(
            "sentry_linked_issue_link_invalid", retryable=False
        )

    org = parse.quote(organization_slug, safe="")
    issue = parse.quote(normalized_issue_id, safe="")
    issue_url = f"https://sentry.io/api/0/organizations/{org}/issues/{issue}/"
    current = _request_json(
        url=issue_url,
        auth_token=auth_token,
        opener=opener,
    )
    project = current.get("project") if isinstance(current.get("project"), dict) else {}
    metadata = current.get("metadata") if isinstance(current.get("metadata"), dict) else {}
    if (
        str(current.get("id") or "") != normalized_issue_id
        or str(current.get("issueCategory") or "") != "feedback"
        or str(project.get("slug") or "") != project_slug
        or str(metadata.get("associated_event_id") or "").lower() != normalized_event_id
    ):
        raise SentryIssueResolutionError("sentry_issue_link_mismatch", retryable=False)

    linked_issue = parse.quote(normalized_linked_issue_id, safe="")
    event = _request_json(
        url=(
            f"https://sentry.io/api/0/organizations/{org}/issues/{linked_issue}/events/"
            f"{parse.quote(normalized_event_id, safe='')}/"
        ),
        auth_token=auth_token,
        opener=opener,
    )
    if (
        str(event.get("eventID") or "").strip().lower() != normalized_event_id
        or str(event.get("groupID") or "").strip() != normalized_linked_issue_id
    ):
        raise SentryIssueResolutionError("sentry_linked_event_mismatch", retryable=False)

    linked_issue_url = (
        f"https://sentry.io/api/0/organizations/{org}/issues/{linked_issue}/"
    )
    linked_current = _request_json(
        url=linked_issue_url,
        auth_token=auth_token,
        opener=opener,
    )
    linked_project = (
        linked_current.get("project")
        if isinstance(linked_current.get("project"), dict)
        else {}
    )
    if (
        str(linked_current.get("id") or "") != normalized_linked_issue_id
        or str(linked_current.get("issueCategory") or "") != "error"
        or str(linked_project.get("slug") or "") != project_slug
    ):
        raise SentryIssueResolutionError("sentry_linked_issue_mismatch", retryable=False)

    if str(current.get("status") or "") != "resolved":
        updated = _request_json(
            url=issue_url,
            auth_token=auth_token,
            method="PUT",
            body={"status": "resolved"},
            opener=opener,
        )
        if (
            str(updated.get("id") or "") != normalized_issue_id
            or str(updated.get("status") or "") != "resolved"
        ):
            raise SentryIssueResolutionError(
                "sentry_resolution_not_confirmed", retryable=True
            )

    if str(linked_current.get("status") or "") != "resolved":
        linked_updated = _request_json(
            url=linked_issue_url,
            auth_token=auth_token,
            method="PUT",
            body={"status": "resolved"},
            opener=opener,
        )
        if (
            str(linked_updated.get("id") or "") != normalized_linked_issue_id
            or str(linked_updated.get("status") or "") != "resolved"
        ):
            raise SentryIssueResolutionError(
                "sentry_linked_resolution_not_confirmed", retryable=True
            )

    return {
        "issue_id": normalized_issue_id,
        "status": "resolved",
        "linked_issue_id": normalized_linked_issue_id,
        "linked_issue_status": "resolved",
    }

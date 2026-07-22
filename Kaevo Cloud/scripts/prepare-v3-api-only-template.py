#!/usr/bin/env python3
"""Prepare an isolated V3 connector-control deployment template.

The source root is shared by the API and two identity functions.  More
importantly, a V3 review must not accidentally remove a route which a prior
deployment added outside this clean worktree.  This helper therefore uses the
CloudFormation ``Original`` template as the preservation baseline:

* the existing API, identity, and owner-enrollment functions retain their
  complete deployed resource definitions and immutable artifacts;
* every existing API event therefore remains byte-for-byte unchanged;
* the dedicated connector-control function is the only source of the six new
  V3 routes and route-specific invocation permissions.

It writes only a generated deployment template.  It never changes application
source, identity logic, Cognito configuration, or a deployed stack.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


PINNED_FUNCTIONS = (
    "KaevoCloudApiFunction",
    "KaevoIdentityClaimIssuerFunction",
    "KaevoOwnerEnrollmentFunction",
)
API_FUNCTION = "KaevoCloudApiFunction"
HTTP_API = "KaevoCloudHttpApi"
RESOURCE_HEADER = re.compile(r"^  [A-Za-z][A-Za-z0-9]*:\n", re.MULTILINE)
TOP_LEVEL_HEADER = re.compile(r"^[A-Za-z][A-Za-z0-9]*:\n", re.MULTILINE)
EVENT_HEADER = re.compile(r"^        ([A-Za-z][A-Za-z0-9]*):\n", re.MULTILINE)
PATH_LINE = re.compile(r"^            Path: ([^\s]+)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class EventBlock:
    logical_id: str
    path: str
    text: str


def resource_bounds(template: str, logical_id: str) -> tuple[int, int]:
    start = template.find(f"  {logical_id}:\n")
    if start < 0:
        raise ValueError(f"missing resource {logical_id}")
    following = RESOURCE_HEADER.search(template, start + 1)
    top_level = TOP_LEVEL_HEADER.search(template, start + 1)
    boundaries = [match.start() for match in (following, top_level) if match is not None]
    return start, min(boundaries) if boundaries else len(template)


def resource_section(template: str, logical_id: str) -> str:
    start, end = resource_bounds(template, logical_id)
    return template[start:end]


def replace_resource_section(template: str, logical_id: str, replacement: str) -> str:
    start, end = resource_bounds(template, logical_id)
    return template[:start] + replacement + template[end:]


def deployed_code_uri(template: str, logical_id: str) -> str:
    section = resource_section(template, logical_id)
    match = re.search(r"^      CodeUri: (s3://[^\s]+)\s*$", section, re.MULTILINE)
    if match is None:
        raise ValueError(f"{logical_id} must have a deployed immutable s3:// CodeUri")
    return match.group(1)


def replace_code_uri(template: str, logical_id: str, code_uri: str) -> str:
    section = resource_section(template, logical_id)
    current = re.search(r"^      CodeUri: .*$", section, re.MULTILINE)
    if current is None:
        raise ValueError(f"missing CodeUri for {logical_id}")
    replacement = section[:current.start()] + f"      CodeUri: {code_uri}" + section[current.end():]
    return replace_resource_section(template, logical_id, replacement)


def api_events(template: str) -> tuple[dict[str, EventBlock], int, str]:
    """Return API HttpApi event blocks and the insertion point in its resource."""
    section = resource_section(template, API_FUNCTION)
    events_start = section.find("      Events:\n")
    if events_start < 0:
        raise ValueError(f"missing Events for {API_FUNCTION}")
    event_region_start = events_start + len("      Events:\n")
    # SAM can append resource-level Metadata after Properties.  The legacy
    # events must remain inside the Events mapping, never after Metadata.
    event_region_end = len(section)
    cursor = event_region_start
    while cursor < len(section):
        newline = section.find("\n", cursor)
        line_end = len(section) if newline < 0 else newline + 1
        line = section[cursor:line_end]
        if line.strip() and len(line) - len(line.lstrip(" ")) <= 6:
            event_region_end = cursor
            break
        cursor = line_end
    matches = list(EVENT_HEADER.finditer(section, event_region_start, event_region_end))
    if not matches:
        raise ValueError(f"missing HttpApi events for {API_FUNCTION}")

    events: dict[str, EventBlock] = {}
    for index, match in enumerate(matches):
        block_end = matches[index + 1].start() if index + 1 < len(matches) else event_region_end
        block = section[match.start():block_end]
        if "          Type: HttpApi\n" not in block:
            continue
        path = PATH_LINE.search(block)
        if path is None:
            raise ValueError(f"HttpApi event {match.group(1)} has no Path")
        events[match.group(1)] = EventBlock(match.group(1), path.group(1), block)
    return events, event_region_end, section


def legacy_events(template: str) -> dict[str, EventBlock]:
    return {name: event for name, event in api_events(template)[0].items() if not event.path.startswith("/v3/")}


def preserve_legacy_api_events(candidate: str, deployed: str) -> str:
    """Copy missing legacy events and reject any changed deployed legacy event."""
    deployed_legacy = legacy_events(deployed)
    candidate_events, event_region_end, section = api_events(candidate)
    missing: list[EventBlock] = []
    for logical_id, deployed_event in deployed_legacy.items():
        current = candidate_events.get(logical_id)
        if current is None:
            missing.append(deployed_event)
        elif current.text != deployed_event.text:
            raise ValueError(
                f"legacy HttpApi event {logical_id} differs from the deployed baseline; "
                "refusing to alter its route, authorizer, integration, or permission"
            )
    if not missing:
        return candidate

    # Appending inside Events
    # exact deployed blocks preserves the corresponding SAM permission logical
    # IDs and avoids any hand-authored CloudFormation permission resource.
    insertion = event_region_end
    updated_section = section[:insertion] + "".join(event.text for event in missing) + section[insertion:]
    updated = replace_resource_section(candidate, API_FUNCTION, updated_section)
    actual = legacy_events(updated)
    for logical_id, deployed_event in deployed_legacy.items():
        if actual.get(logical_id) != deployed_event:
            raise ValueError(f"failed to preserve deployed legacy HttpApi event {logical_id}")
    return updated


def preserve_http_api_metadata(candidate: str, deployed: str) -> str:
    """Retain deployed SAM identity metadata for the shared HTTP API.

    CloudFormation's original template retains ``SamResourceId`` metadata for
    the transformed HTTP API.  Dropping it from an API-only candidate makes
    SAM report a dynamic ``Body`` change even when every route, authorizer,
    integration, and setting is identical.  Preserve that deployed metadata
    exactly, and fail closed if the candidate supplies different metadata.
    """
    deployed_section = resource_section(deployed, HTTP_API)
    candidate_section = resource_section(candidate, HTTP_API)
    marker = "\n    Metadata:\n"
    deployed_marker = deployed_section.find(marker)
    candidate_marker = candidate_section.find(marker)
    deployed_metadata = "" if deployed_marker < 0 else deployed_section[deployed_marker:]
    candidate_metadata = "" if candidate_marker < 0 else candidate_section[candidate_marker:]
    if not deployed_metadata:
        if candidate_metadata:
            raise ValueError(f"{HTTP_API} metadata differs from the deployed baseline")
        return candidate
    if candidate_metadata and candidate_metadata != deployed_metadata:
        raise ValueError(f"{HTTP_API} metadata differs from the deployed baseline")
    if candidate_metadata:
        return candidate
    return replace_resource_section(candidate, HTTP_API, candidate_section.rstrip("\n") + deployed_metadata)


def prepare_template(candidate: str, deployed: str) -> str:
    for logical_id in PINNED_FUNCTIONS:
        candidate = replace_resource_section(candidate, logical_id, resource_section(deployed, logical_id))
    # Retain the explicit preservation check as a fail-closed regression gate,
    # even though the complete deployed API function is now pinned.
    candidate = preserve_legacy_api_events(candidate, deployed)
    return preserve_http_api_metadata(candidate, deployed)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--deployed-template", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.input.is_file() or not args.deployed_template.is_file():
        raise ValueError("input and deployed-template must exist")
    if args.output.resolve() in {args.input.resolve(), args.deployed_template.resolve()}:
        raise ValueError("output must be distinct from input and deployed-template")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(prepare_template(args.input.read_text(), args.deployed_template.read_text()))


if __name__ == "__main__":
    main()

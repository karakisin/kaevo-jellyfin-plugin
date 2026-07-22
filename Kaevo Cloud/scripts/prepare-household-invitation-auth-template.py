#!/usr/bin/env python3
"""Prepare a deployment template for the household invitation auth repair.

The deployed API function and all unrelated events remain the preservation
baseline.  Only the two household invitation event blocks are taken from the
candidate template.  This lets API Gateway pass the device-bound owner bearer
and DPoP proof to the Lambda, where ``owner_bound_session`` validates both.

The helper writes a generated template only.  It never updates a stack.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "prepare-v3-api-only-template.py"
SPEC = importlib.util.spec_from_file_location("kaevo_api_template_helper", HELPER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load API template helper")
HELPER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HELPER
SPEC.loader.exec_module(HELPER)

HOUSEHOLD_EVENT_IDS = {
    "HouseholdInvitations",
    "RevokeHouseholdInvitation",
}


def prepare_template(candidate: str, deployed: str) -> str:
    prepared = deployed
    candidate_events = HELPER.api_events(candidate)[0]
    deployed_events, _, deployed_api = HELPER.api_events(deployed)

    added = sorted(set(candidate_events) - set(deployed_events))
    if added:
        raise ValueError(f"candidate adds unreviewed API events: {added}")

    updated_api = deployed_api
    for logical_id in HOUSEHOLD_EVENT_IDS:
        candidate_event = candidate_events.get(logical_id)
        deployed_event = deployed_events.get(logical_id)
        if candidate_event is None or deployed_event is None:
            raise ValueError(f"missing required household event {logical_id}")
        if candidate_event.path != deployed_event.path:
            raise ValueError(f"household event path changed for {logical_id}")
        updated_api = updated_api.replace(deployed_event.text, candidate_event.text, 1)

    prepared = HELPER.replace_resource_section(prepared, HELPER.API_FUNCTION, updated_api)
    prepared = HELPER.preserve_http_api_metadata(prepared, deployed)

    actual_events = HELPER.api_events(prepared)[0]
    for logical_id, deployed_event in deployed_events.items():
        if logical_id in HOUSEHOLD_EVENT_IDS:
            if actual_events[logical_id] != candidate_events[logical_id]:
                raise ValueError(f"failed to apply household event {logical_id}")
        elif actual_events[logical_id] != deployed_event:
            raise ValueError(f"unrelated API event changed: {logical_id}")
    return prepared


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

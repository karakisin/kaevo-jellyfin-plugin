#!/usr/bin/env python3
"""Reject a Connector binding IAM correction that changes anything else."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


EXPECTED = {"KaevoIdentityV3ApiDataPolicy": "Modify"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--change-set", required=True, type=Path)
    args = parser.parse_args()
    changes = json.loads(args.change_set.read_text()).get("Changes", [])
    actual = {
        item["ResourceChange"].get("LogicalResourceId"): item["ResourceChange"].get("Action")
        for item in changes
    }
    errors = []
    if actual != EXPECTED:
        errors.append(f"unexpected change-set resources: {actual}")
    for item in changes:
        resource = item["ResourceChange"]
        if resource.get("Replacement") in {True, "True", "Conditional"}:
            errors.append(f"replacement is forbidden: {resource.get('LogicalResourceId')}")
    if errors:
        raise SystemExit(
            "Connector binding IAM correction change-set scope rejected:\n- "
            + "\n- ".join(errors)
        )
    print("IDENTITY_V3_HOME_CONNECTOR_BINDING_IAM_CORRECTION_CHANGE_SET_SCOPE=APPROVED")


if __name__ == "__main__":
    main()

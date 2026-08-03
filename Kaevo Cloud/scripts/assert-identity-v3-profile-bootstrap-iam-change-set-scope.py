#!/usr/bin/env python3
"""Reject any Profile Bootstrap remediation beyond the one IAM policy update."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--change-set", required=True, type=Path)
    args = parser.parse_args()
    changes = json.loads(args.change_set.read_text()).get("Changes", [])
    errors = []
    if len(changes) != 1:
        errors.append(f"expected one change, found {len(changes)}")
    for change in changes:
        resource = change["ResourceChange"]
        if resource.get("LogicalResourceId") != "KaevoIdentityV3ApiDataPolicy":
            errors.append(f"unexpected resource: {resource.get('LogicalResourceId')}")
        if resource.get("Action") != "Modify":
            errors.append(f"unexpected action: {resource.get('Action')}")
        if resource.get("Replacement") in {True, "True", "Conditional"}:
            errors.append("policy replacement is forbidden")
    if errors:
        raise SystemExit("Profile bootstrap IAM change-set scope rejected:\n- " + "\n- ".join(errors))
    print("PROFILE_BOOTSTRAP_IAM_CHANGE_SET_SCOPE=APPROVED")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Fail closed unless a change set updates only connector-control Lambda code."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


RESOURCE = "KaevoV3ConnectorControlFunction"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--change-set", required=True, type=Path)
    args = parser.parse_args()

    document = json.loads(args.change_set.read_text(encoding="utf-8"))
    changes = document.get("Changes", [])
    errors: list[str] = []
    if len(changes) != 1:
        errors.append(f"expected exactly one resource change, found {len(changes)}")

    for change in changes:
        resource = change.get("ResourceChange", {})
        logical_id = resource.get("LogicalResourceId")
        if logical_id != RESOURCE:
            errors.append(f"unexpected resource: {logical_id}")
        if resource.get("Action") != "Modify":
            errors.append(f"expected Modify for {logical_id}, found {resource.get('Action')}")
        if resource.get("Replacement") not in {False, "False", None}:
            errors.append(f"replacement is forbidden for {logical_id}")
        details = resource.get("Details", [])
        if len(details) != 1:
            errors.append(f"expected one property detail for {logical_id}, found {len(details)}")
            continue
        target = details[0].get("Target", {})
        if target.get("Attribute") != "Properties" or target.get("Name") != "Code":
            errors.append(f"only Lambda Code may change, found {target}")
        if details[0].get("Evaluation") != "Static":
            errors.append(f"Lambda Code update must be static, found {details[0].get('Evaluation')}")

    if errors:
        raise SystemExit("V3 connector-control code-only scope rejected:\n- " + "\n- ".join(errors))
    print("V3_CONNECTOR_CONTROL_CODE_ONLY_SCOPE=APPROVED")


if __name__ == "__main__":
    main()

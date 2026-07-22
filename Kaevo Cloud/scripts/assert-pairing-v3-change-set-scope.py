#!/usr/bin/env python3
"""Fail closed unless a Pairing V3 change set has the reviewed resource scope."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ALLOWED_ADDS = {
    "KaevoV3ConnectorControlFunction",
    "KaevoV3ConnectorControlFunctionRole",
    "KaevoV3ConnectorControlLogGroup",
    "KaevoV3ConnectorControlFunctionCreateConnectorRelayTicketV3Permission",
    "KaevoV3ConnectorControlFunctionHeartbeatHomeConnectorV3Permission",
    "KaevoV3ConnectorControlFunctionRegisterHomeConnectorV3Permission",
    "KaevoV3ConnectorControlFunctionRemoteRequestClaimV3Permission",
    "KaevoV3ConnectorControlFunctionRemoteRequestCompleteV3Permission",
    "KaevoV3ConnectorControlFunctionRemoteRequestFailV3Permission",
}
ALLOWED_MODIFIES = {
    "KaevoCloudHttpApi",
}


def scope_errors(change_set: dict) -> list[str]:
    errors: list[str] = []
    for change in change_set.get("Changes", []):
        resource = change["ResourceChange"]
        logical_id = resource["LogicalResourceId"]
        action = resource["Action"]
        replacement = resource.get("Replacement")
        if action == "Remove":
            errors.append(f"forbidden removal: {logical_id}")
        if replacement in {"True", "Conditional", True}:
            errors.append(f"forbidden replacement: {logical_id} ({replacement})")
        if action == "Add" and logical_id not in ALLOWED_ADDS:
            errors.append(f"unexpected addition: {logical_id}")
        elif action == "Modify" and logical_id not in ALLOWED_MODIFIES:
            errors.append(f"unexpected modification: {logical_id}")
        elif action not in {"Add", "Modify", "Remove"}:
            errors.append(f"unexpected action {action}: {logical_id}")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--change-set", required=True, type=Path)
    args = parser.parse_args()
    errors = scope_errors(json.loads(args.change_set.read_text()))
    if errors:
        raise SystemExit("Pairing V3 change-set scope rejected:\n- " + "\n- ".join(errors))
    print("PAIRING_V3_CHANGE_SET_SCOPE=APPROVED")


if __name__ == "__main__":
    main()

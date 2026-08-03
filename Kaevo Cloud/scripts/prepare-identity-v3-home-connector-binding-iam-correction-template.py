#!/usr/bin/env python3
"""Build a policy-only correction for the Connector binding transaction.

The deployed binding route already exists.  This candidate starts from the
live processed template and adds only the DynamoDB action AWS requires for
the existing transaction's ``Update`` member.  It deliberately cannot change
Lambda code, routes, environment variables, or any other resource.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path


POLICY = "KaevoIdentityV3ApiDataPolicy"
HOME_CONNECTORS = "KaevoHomeConnectorsTable"


def get_att(name: str) -> dict:
    return {"Fn::GetAtt": [name, "Arn"]}


def prepare(baseline: dict) -> dict:
    candidate = copy.deepcopy(baseline)
    resources = candidate.get("Resources") or {}
    if POLICY not in resources or HOME_CONNECTORS not in resources:
        raise ValueError("missing required deployed Identity V3 policy resources")

    statements = resources[POLICY]["Properties"]["PolicyDocument"]["Statement"]
    transaction = next(
        (statement for statement in statements
         if statement.get("Sid") == "WriteHomeConnectorBindingAtomically"),
        None,
    )
    if transaction is None:
        raise ValueError("the deployed binding transaction policy is missing")
    if transaction.get("Action") != ["dynamodb:TransactWriteItems"]:
        raise ValueError("the deployed transaction policy does not match the reviewed baseline")
    if any(statement.get("Sid") == "UpdateHomeConnectorBindingRecord" for statement in statements):
        raise ValueError("the UpdateItem correction already exists")

    statements.append({
        "Sid": "UpdateHomeConnectorBindingRecord",
        "Effect": "Allow",
        "Action": ["dynamodb:UpdateItem"],
        "Resource": get_att(HOME_CONNECTORS),
    })

    baseline_resources = baseline["Resources"]
    modified = [name for name in baseline_resources if resources[name] != baseline_resources[name]]
    added = set(resources) - set(baseline_resources)
    if modified != [POLICY] or added:
        raise ValueError(
            f"unexpected correction scope: modified={modified}, added={sorted(added)}"
        )
    return candidate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-processed-template", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.resolve() == args.deployed_processed_template.resolve():
        raise ValueError("output must differ from deployed processed template")
    baseline = json.loads(args.deployed_processed_template.read_text())
    candidate = prepare(baseline)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(candidate, indent=2) + "\n")
    print("IDENTITY_V3_HOME_CONNECTOR_BINDING_IAM_CORRECTION_TEMPLATE=APPROVED")


if __name__ == "__main__":
    main()

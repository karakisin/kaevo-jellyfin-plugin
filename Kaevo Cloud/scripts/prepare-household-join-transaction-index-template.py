#!/usr/bin/env python3
"""Prepare a one-resource Join-transaction-index candidate from live state."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import subprocess


TABLE = "KaevoHouseholdJoinTransactionsTable"
INDEX = "invitation_id-created_at_epoch-index"


def _live_template(*, stack_name: str, region: str, profile: str) -> dict:
    result = subprocess.run(
        ["aws", "cloudformation", "get-template", "--stack-name", stack_name,
         "--template-stage", "Original", "--region", region, "--profile", profile,
         "--output", "json"],
        check=True, capture_output=True, text=True,
    )
    body = json.loads(result.stdout)["TemplateBody"]
    return json.loads(body) if isinstance(body, str) else body


def _index() -> dict:
    return {
        "IndexName": INDEX,
        "KeySchema": [
            {"AttributeName": "invitation_id", "KeyType": "HASH"},
            {"AttributeName": "created_at_epoch", "KeyType": "RANGE"},
        ],
        "Projection": {"ProjectionType": "KEYS_ONLY"},
    }


def prepare(baseline: dict) -> dict:
    candidate = copy.deepcopy(baseline)
    table = candidate.get("Resources", {}).get(TABLE)
    if not isinstance(table, dict):
        raise ValueError("live_template_missing_join_transactions_table")
    properties = table.get("Properties")
    if not isinstance(properties, dict) or properties.get("BillingMode") != "PAY_PER_REQUEST":
        raise ValueError("join_transactions_billing_mode_unexpected")
    definitions = properties.get("AttributeDefinitions")
    if not isinstance(definitions, list) or {entry.get("AttributeName") for entry in definitions if isinstance(entry, dict)} != {"join_resume_hash"}:
        raise ValueError("join_transactions_attribute_definitions_unexpected")
    if properties.get("GlobalSecondaryIndexes"):
        raise ValueError("join_transactions_existing_indexes_unexpected")
    definitions.extend([
        {"AttributeName": "invitation_id", "AttributeType": "S"},
        {"AttributeName": "created_at_epoch", "AttributeType": "N"},
    ])
    properties["GlobalSecondaryIndexes"] = [_index()]
    return candidate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    baseline = _live_template(stack_name=args.stack_name, region=args.region, profile=args.profile)
    candidate = prepare(baseline)
    before = baseline["Resources"]
    after = candidate["Resources"]
    changed = {name for name in before if before[name] != after[name]}
    if changed != {TABLE} or set(before) != set(after):
        raise ValueError("candidate_scope_unexpected")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(candidate, sort_keys=True, indent=2) + "\n")
    print("JOIN_TRANSACTION_INDEX_TEMPLATE_SCOPE=APPROVED")
    print("MODIFIED_RESOURCE_COUNT=1")


if __name__ == "__main__":
    main()

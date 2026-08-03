#!/usr/bin/env python3
"""Create an IAM-only template from the deployed processed stack template."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


def load_policy_generator():
    script = Path(__file__).with_name("prepare-identity-v3-minimal-template.py")
    spec = importlib.util.spec_from_file_location("identity_v3_template_generator", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Identity V3 template generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    result = subprocess.run(
        [
            "aws", "cloudformation", "get-template",
            "--stack-name", args.stack_name,
            "--template-stage", "Processed",
            "--region", args.region,
            "--output", "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    template_body = json.loads(result.stdout)["TemplateBody"]
    baseline = json.loads(template_body) if isinstance(template_body, str) else template_body
    candidate = json.loads(json.dumps(baseline))
    resources = candidate["Resources"]
    logical_id = "KaevoIdentityV3ApiDataPolicy"
    if logical_id not in resources:
        raise RuntimeError(f"missing expected resource: {logical_id}")

    resources[logical_id] = load_policy_generator().identity_v3_data_policy()
    changed = [
        name for name, resource in resources.items()
        if resource != baseline["Resources"].get(name)
    ]
    if changed != [logical_id]:
        raise RuntimeError(f"IAM-only candidate changed unexpected resources: {changed}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(candidate, indent=2) + "\n")
    print(f"IAM_ONLY_TEMPLATE_APPROVED resource={logical_id}")


if __name__ == "__main__":
    main()

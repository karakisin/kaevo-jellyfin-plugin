#!/usr/bin/env python3
"""Add one DELETE path to the deployed transformed API template."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path


API = "KaevoCloudHttpApi"
SOURCE_PATH = "/v2/household/invitations/{invitationId}/revoke"
TARGET_PATH = "/v2/household/invitations/{invitationId}"
SOURCE_PERMISSION = "KaevoCloudApiFunctionRevokeHouseholdInvitationPermission"
TARGET_PERMISSION = "KaevoCloudApiFunctionDeleteHouseholdInvitationPermission"


def prepare_template(wrapper: dict) -> dict:
    template = deepcopy(wrapper.get("TemplateBody"))
    if not isinstance(template, dict):
        raise ValueError("deployed template body must be transformed JSON")
    resources = template.get("Resources")
    if not isinstance(resources, dict) or API not in resources:
        raise ValueError("deployed template is missing the Cloud HTTP API")
    api = resources[API]
    if api.get("Type") != "AWS::ApiGatewayV2::Api":
        raise ValueError("deployed Cloud HTTP API is not transformed")
    external_routes = [
        name
        for name, resource in resources.items()
        if resource.get("Type") == "AWS::ApiGatewayV2::Route"
        and resource.get("Properties", {}).get("ApiId") == {"Ref": API}
    ]
    if external_routes:
        raise ValueError(
            "refusing to update the inline HTTP API body while separately "
            "managed routes exist; use a standalone route or the bounded "
            "route-drift reconciliation workflow"
        )
    body = api.get("Properties", {}).get("Body")
    paths = body.get("paths") if isinstance(body, dict) else None
    if not isinstance(paths, dict):
        raise ValueError("deployed Cloud HTTP API has no inline paths")
    source = paths.get(SOURCE_PATH, {}).get("post")
    if not isinstance(source, dict):
        raise ValueError("deployed invitation revoke integration is missing")
    existing = paths.get(TARGET_PATH)
    if existing is None:
        paths[TARGET_PATH] = {"delete": deepcopy(source)}
    elif not isinstance(existing, dict) or existing.get("delete") != source:
        raise ValueError("deployed invitation DELETE path already differs")

    source_permission = resources.get(SOURCE_PERMISSION)
    if not isinstance(source_permission, dict):
        raise ValueError("deployed invitation revoke permission is missing")
    permission = deepcopy(source_permission)
    source_arn = permission.get("Properties", {}).get("SourceArn", {}).get("Fn::Sub")
    if (
        not isinstance(source_arn, list)
        or not isinstance(source_arn[0], str)
        or "/POST/v2/household/invitations/*/revoke" not in source_arn[0]
    ):
        raise ValueError("deployed invitation revoke permission has unexpected scope")
    source_arn[0] = source_arn[0].replace(
        "/POST/v2/household/invitations/*/revoke",
        "/DELETE/v2/household/invitations/*",
    )
    existing_permission = resources.get(TARGET_PERMISSION)
    if existing_permission is None:
        resources[TARGET_PERMISSION] = permission
    elif existing_permission != permission:
        raise ValueError("deployed invitation DELETE permission already differs")
    return template


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-template-json", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    wrapper = json.loads(args.deployed_template_json.read_text())
    prepared = prepare_template(wrapper)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(prepared, indent=2, sort_keys=True) + "\n")
    print("TRANSFORMED_INVITATION_DELETE_ROUTE=PREPARED")


if __name__ == "__main__":
    main()

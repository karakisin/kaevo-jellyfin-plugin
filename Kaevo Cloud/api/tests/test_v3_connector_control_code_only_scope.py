from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "assert-v3-connector-control-code-only-change-set-scope.py"
SPEC = importlib.util.spec_from_file_location("connector_code_only_scope", SCRIPT)
assert SPEC and SPEC.loader
SCOPE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SCOPE
SPEC.loader.exec_module(SCOPE)


def change(logical_id: str, detail: dict) -> dict:
    return {"ResourceChange": {
        "LogicalResourceId": logical_id,
        "Action": "Modify",
        "Replacement": "False",
        "Details": [detail],
    }}


def test_accepts_code_and_its_exact_non_replacing_http_api_dependency():
    document = {"Changes": [
        change("KaevoCloudHttpApi", {
            "Target": {
                "Attribute": "Properties", "Name": "Body",
                "RequiresRecreation": "Never",
            },
            "Evaluation": "Dynamic",
            "ChangeSource": "ResourceAttribute",
            "CausingEntity": "KaevoV3ConnectorControlFunction.Arn",
        }),
        change("KaevoV3ConnectorControlFunction", {
            "Target": {
                "Attribute": "Properties", "Name": "Code",
                "RequiresRecreation": "Never",
            },
            "Evaluation": "Static",
            "ChangeSource": "DirectModification",
        }),
    ]}

    assert SCOPE.scope_errors(document) == []


def test_rejects_static_http_api_edits_and_unrelated_resources():
    document = {"Changes": [
        change("KaevoCloudHttpApi", {
            "Target": {
                "Attribute": "Properties", "Name": "Body",
                "RequiresRecreation": "Never",
            },
            "Evaluation": "Static",
            "ChangeSource": "DirectModification",
        }),
        change("KaevoV3ConnectorControlFunction", {
            "Target": {
                "Attribute": "Properties", "Name": "Code",
                "RequiresRecreation": "Never",
            },
            "Evaluation": "Static",
            "ChangeSource": "DirectModification",
        }),
        change("KaevoCloudApiFunction", {
            "Target": {
                "Attribute": "Properties", "Name": "Code",
                "RequiresRecreation": "Never",
            },
            "Evaluation": "Static",
        }),
    ]}

    errors = SCOPE.scope_errors(document)
    assert any("unexpected resources" in error for error in errors)
    assert any("unexpected HTTP API dependency" in error for error in errors)

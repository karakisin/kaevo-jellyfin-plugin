from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[2] / "scripts" / "prepare-production-sentry-resolution-template.py"
SPEC = importlib.util.spec_from_file_location("prepare_production_sentry_resolution", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def deployed_template():
    return {
        "Resources": {
            "Unrelated": {"Type": "Safe::Resource", "Properties": {"Value": "same"}},
            MODULE.API_ROLE: {"Type": "AWS::IAM::Role", "Properties": {}},
            MODULE.API_FUNCTION: {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Handler": MODULE.EXPECTED_HANDLER,
                    "Runtime": MODULE.EXPECTED_RUNTIME,
                    "Environment": {"Variables": {"UNCHANGED": "same"}},
                    "Code": {"S3Bucket": "old", "S3Key": "old"},
                },
            },
        }
    }


def test_candidate_changes_only_api_runtime_and_exact_secret_access_policy():
    deployed = deployed_template()
    original = copy.deepcopy(deployed)
    secret_arn = "arn:aws:secretsmanager:us-west-2:123456789012:secret:resolver"

    prepared = MODULE.prepare_template(
        deployed, code_bucket="new", code_key="new", secret_arn=secret_arn,
    )

    assert deployed == original
    assert prepared["Resources"]["Unrelated"] == original["Resources"]["Unrelated"]
    function = prepared["Resources"][MODULE.API_FUNCTION]["Properties"]
    assert function["Code"] == {"S3Bucket": "new", "S3Key": "new"}
    assert function["Environment"]["Variables"]["SENTRY_ISSUE_RESOLVER_SECRET_ARN"] == secret_arn
    policy = prepared["Resources"][MODULE.ACCESS_POLICY]["Properties"]["PolicyDocument"]
    assert policy["Statement"][0]["Resource"] == secret_arn
    assert policy["Statement"][0]["Action"] == ["secretsmanager:GetSecretValue"]


def test_candidate_refuses_an_existing_resolver_configuration():
    deployed = deployed_template()
    deployed["Resources"][MODULE.API_FUNCTION]["Properties"]["Environment"]["Variables"][
        "SENTRY_ISSUE_RESOLVER_SECRET_ARN"
    ] = "already-configured"

    with pytest.raises(MODULE.ScopeError, match="already configured"):
        MODULE.prepare_template(
            deployed,
            code_bucket="new",
            code_key="new",
            secret_arn="arn:aws:secretsmanager:us-west-2:123456789012:secret:resolver",
        )

from __future__ import annotations

import importlib.util
from pathlib import Path

from scripts.iam_policy_semantics import effective_permissions_identical


ROOT = Path(__file__).parents[2]
PREPARER_PATH = ROOT / "scripts" / "prepare-cloud-api-remote-payloads-iam-template.py"


def _preparer():
    spec = importlib.util.spec_from_file_location("remote_payloads_iam", PREPARER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _baseline():
    return {
        "Resources": {
            "KaevoCloudApiFunction": {"Type": "AWS::Lambda::Function"},
            "KaevoCloudApiFunctionRole": {"Properties": {"Policies": [{
                "PolicyName": "KaevoCloudApiFunctionRolePolicy0",
                "PolicyDocument": {"Statement": []},
            }, {
                "PolicyName": "KaevoCloudApiFunctionRolePolicy1",
                "PolicyDocument": {"Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:DeleteObject", "s3:GetObject", "s3:ListBucket", "s3:PutObject"],
                    "Resource": [
                        {"Fn::Sub": "${KaevoRemotePayloadsBucket.Arn}"},
                        {"Fn::Sub": "${KaevoRemotePayloadsBucket.Arn}/*"},
                    ],
                }]},
            }]}},
            "KaevoRemotePayloadsBucket": {"Type": "AWS::S3::Bucket"},
            "KaevoHouseholdJoinTransactionsTable": {"Type": "AWS::DynamoDB::Table", "Properties": {"GlobalSecondaryIndexes": []}},
        },
    }


def test_iam_candidate_adds_only_the_exact_remote_payloads_s3_policy_and_excludes_gsi():
    candidate = _preparer().prepare(_baseline())
    policies = candidate["Resources"]["KaevoCloudApiFunctionRole"]["Properties"]["Policies"]
    assert policies[0] == _baseline()["Resources"]["KaevoCloudApiFunctionRole"]["Properties"]["Policies"][0]
    assert policies[1] == {
        "PolicyName": "KaevoCloudApiFunctionRolePolicy1",
        "PolicyDocument": {"Statement": [{
            "Sid": "ReadAndStoreBoundedRemoteResponses",
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": {"Fn::Sub": "${KaevoRemotePayloadsBucket.Arn}/remote-responses/*"},
        }]},
    }
    assert len(policies) == 2
    assert candidate["Resources"]["KaevoHouseholdJoinTransactionsTable"]["Properties"]["GlobalSecondaryIndexes"] == []


def test_policy_semantics_normalize_order_but_preserve_effect_and_resource_scope():
    first = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": ["bucket/*", "bucket"]}]}
    reordered = {"Statement": [{"Resource": "bucket", "Action": ["s3:PutObject", "s3:GetObject"], "Effect": "Allow"}, {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "bucket/*"}], "Version": "2012-10-17"}
    changed_effect = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": ["bucket/*", "bucket"]}]}
    assert not effective_permissions_identical(first, reordered)  # Statement grouping is semantic.
    assert not effective_permissions_identical(first, changed_effect)


def test_source_template_keeps_remote_payloads_scope_to_proven_object_actions_and_prefix():
    text = (ROOT / "infra" / "template.yaml").read_text()
    start = text.index("        - Statement:\n            - Sid: ReadAndStoreBoundedRemoteResponses")
    scope = text[start:start + 340]
    assert "s3:GetObject" in scope
    assert "s3:PutObject" in scope
    assert "s3:DeleteObject" not in scope
    assert "s3:ListBucket" not in scope
    assert "${KaevoRemotePayloadsBucket.Arn}/remote-responses/*" in scope

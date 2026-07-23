from __future__ import annotations

import importlib.util
import pathlib

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "prepare-managed-login-identity-template.py"
SPEC = importlib.util.spec_from_file_location("managed_login_identity_template", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def candidate() -> str:
    return """Resources:
  KaevoCloudHttpApi:
    Type: AWS::Serverless::HttpApi
    Metadata:
      SamResourceId: KaevoCloudHttpApi
  KaevoCloudApiFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: local/KaevoCloudApiFunction
      Handler: handler.lambda_handler
      Events:
        Health:
          Type: HttpApi
          Properties:
            ApiId:
              Ref: KaevoCloudHttpApi
            Path: /health
            Method: GET
  KaevoIdentityClaimIssuerFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: local/KaevoIdentityClaimIssuerFunction
      Handler: handler.lambda_handler
  KaevoSocialIdentityGuardFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: local/KaevoSocialIdentityGuardFunction
      Handler: handler.lambda_handler
  KaevoSocialIdentityApiFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: local/KaevoSocialIdentityApiFunction
      Handler: handler.lambda_handler
  KaevoOwnerEnrollmentFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: local/KaevoOwnerEnrollmentFunction
      Handler: handler.lambda_handler
  KaevoV3ConnectorControlFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: local/KaevoV3ConnectorControlFunction
      Handler: handler.lambda_handler
"""


def deployed():
    resources = {
        name: {
            "Properties": {
                "Code": {"S3Bucket": "deployed-bucket", "S3Key": f"stable/{name}"}
            }
        }
        for name in MODULE.PINNED_UNRELATED_FUNCTIONS
    }
    resources["KaevoCloudApiFunctionHealthPermission"] = {
        "Type": "AWS::Lambda::Permission",
    }
    return {
        "Resources": resources,
    }


def test_only_unrelated_lambda_artifacts_are_pinned():
    result = MODULE.prepare_template(candidate(), deployed())
    for name in MODULE.PINNED_UNRELATED_FUNCTIONS:
        assert f"CodeUri: s3://deployed-bucket/stable/{name}" in result
    assert "CodeUri: local/KaevoCloudApiFunction" in result
    assert "CodeUri: local/KaevoIdentityClaimIssuerFunction" in result


def test_missing_deployed_artifact_fails_closed():
    broken = deployed()
    broken["Resources"]["KaevoOwnerEnrollmentFunction"]["Properties"]["Code"] = {}
    with pytest.raises(ValueError, match="immutable S3 code object"):
        MODULE.prepare_template(candidate(), broken)


def test_identity_artifact_is_rebased_when_generated_template_moves(tmp_path):
    for name in MODULE.CANDIDATE_FUNCTIONS:
        (tmp_path / "local" / name).mkdir(parents=True)
    result = MODULE.prepare_template(candidate(), deployed(), candidate_directory=tmp_path)
    for name in MODULE.CANDIDATE_FUNCTIONS:
        assert f"CodeUri: {tmp_path / 'local' / name}" in result


def test_removing_a_deployed_api_permission_event_fails_closed():
    broken = deployed()
    broken["Resources"]["KaevoCloudApiFunctionLegacyPermission"] = {
        "Type": "AWS::Lambda::Permission",
    }
    with pytest.raises(ValueError, match="removes deployed API Lambda permissions"):
        MODULE.prepare_template(candidate(), broken)

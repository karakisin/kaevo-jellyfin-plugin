from pathlib import Path
import importlib.util
import sys


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "prepare-api-code-only-template.py"
SPEC = importlib.util.spec_from_file_location("api_code_only_template", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_api_code_only_template_pins_identity_and_preserves_legacy_events():
    deployed = """
Resources:
  KaevoCloudHttpApi:
    Type: AWS::Serverless::HttpApi
  KaevoCloudApiFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: s3://deployed/api
      Events:
        Existing:
          Type: HttpApi
          Properties:
            Path: /v1/existing
            Method: GET
  KaevoIdentityClaimIssuerFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: s3://deployed/issuer
  KaevoOwnerEnrollmentFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: s3://deployed/owner
  KaevoV3ConnectorControlFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: s3://deployed/connector-control
"""
    candidate = deployed.replace("s3://deployed/api", "candidate-api").replace(
        "s3://deployed/issuer", "candidate-shared-root"
    ).replace("s3://deployed/owner", "candidate-shared-root").replace(
        "s3://deployed/connector-control", "candidate-connector-control"
    )

    prepared = MODULE.prepare_template(candidate, deployed)

    assert "CodeUri: candidate-api" in prepared
    assert "CodeUri: s3://deployed/issuer" in prepared
    assert "CodeUri: s3://deployed/owner" in prepared
    assert "CodeUri: s3://deployed/connector-control" in prepared
    assert "Path: /v1/existing" in prepared


def test_api_code_only_template_rebases_the_built_api_artifact(tmp_path):
    artifact = tmp_path / "KaevoCloudApiFunction"
    artifact.mkdir()
    template = """
Resources:
  KaevoCloudApiFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: KaevoCloudApiFunction
"""

    prepared = MODULE.rebase_local_api_code_uri(template, tmp_path)

    assert f"CodeUri: {artifact}" in prepared

import copy
import importlib.util
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).parents[2]
    / "scripts"
    / "prepare-production-api-runtime-template.py"
)
SPEC = importlib.util.spec_from_file_location("prepare_production_api_runtime", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def deployed_template():
    return {
        "Resources": {
            "Unrelated": {"Type": "Safe::Resource", "Properties": {"Value": "same"}},
            MODULE.API_FUNCTION: {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Handler": MODULE.EXPECTED_HANDLER,
                    "Runtime": MODULE.EXPECTED_RUNTIME,
                    "Environment": {"Variables": {"UNCHANGED": "same"}},
                    "Code": {"S3Bucket": "old-bucket", "S3Key": "old-key"},
                },
            },
        }
    }


def test_preparer_changes_only_the_production_api_code_location():
    deployed = deployed_template()
    original = copy.deepcopy(deployed)

    prepared = MODULE.prepare_template(
        deployed, code_bucket="new-bucket", code_key="new-key",
    )

    assert deployed == original
    assert prepared["Resources"][MODULE.API_FUNCTION]["Properties"]["Code"] == {
        "S3Bucket": "new-bucket",
        "S3Key": "new-key",
    }
    prepared_function = prepared["Resources"][MODULE.API_FUNCTION]
    original_function = original["Resources"][MODULE.API_FUNCTION]
    assert {
        key: value
        for key, value in prepared_function["Properties"].items()
        if key != "Code"
    } == {
        key: value
        for key, value in original_function["Properties"].items()
        if key != "Code"
    }
    assert prepared["Resources"]["Unrelated"] == original["Resources"]["Unrelated"]


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("Handler", "other.lambda_handler", "handler changed"),
        ("Runtime", "python3.13", "runtime changed"),
        ("Code", {"ZipFile": "inline"}, "code ownership changed"),
    ],
)
def test_preparer_fails_closed_when_runtime_ownership_changes(field, value, reason):
    deployed = deployed_template()
    deployed["Resources"][MODULE.API_FUNCTION]["Properties"][field] = value

    with pytest.raises(MODULE.ScopeError, match=reason):
        MODULE.prepare_template(deployed, code_bucket="bucket", code_key="key")


def test_preparer_fails_closed_when_inline_api_depends_on_function_arn():
    deployed = deployed_template()
    deployed["Resources"][MODULE.HTTP_API] = {
        "Type": "AWS::ApiGatewayV2::Api",
        "Properties": {
            "Body": {
                "components": {
                    "x-amazon-apigateway-integrations": {
                        "api": {
                            "payloadFormatVersion": "2.0",
                            "uri": {
                                "Fn::Sub": [
                                    "lambda/${FunctionArn}",
                                    {
                                        "FunctionArn": {
                                            "Fn::GetAtt": [MODULE.API_FUNCTION, "Arn"]
                                        }
                                    },
                                ]
                            },
                        }
                    }
                }
            }
        },
    }

    with pytest.raises(MODULE.ScopeError, match="would rewrite separately managed routes"):
        MODULE.prepare_template(deployed, code_bucket="bucket", code_key="key")

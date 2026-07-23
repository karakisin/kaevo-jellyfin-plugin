from __future__ import annotations

import importlib.util
import io
import json
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "api" / "social_identity_api" / "social_identity_dispatcher.py"
SPEC = importlib.util.spec_from_file_location("social_identity_dispatcher", SOURCE)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LambdaClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def invoke(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


def invocation_response(value, *, function_error=None):
    result = {"Payload": io.BytesIO(json.dumps(value).encode("utf-8"))}
    if function_error:
        result["FunctionError"] = function_error
    return result


def test_dispatch_forwards_the_original_event_to_only_the_configured_lambda():
    client = LambdaClient(invocation_response({"statusCode": 201, "body": "{}"}))
    event = {"headers": {"authorization": "redacted-in-test"}, "body": "oauth-code"}
    result = MODULE.dispatch(event, lambda_client=client, target_function_name="kaevo-api")
    assert result == {"statusCode": 201, "body": "{}"}
    assert len(client.calls) == 1
    assert client.calls[0]["FunctionName"] == "kaevo-api"
    assert client.calls[0]["InvocationType"] == "RequestResponse"
    assert json.loads(client.calls[0]["Payload"]) == event


def test_dispatch_fails_closed_without_leaking_dependency_details():
    for response, target in (
        (invocation_response({}, function_error="Unhandled"), "kaevo-api"),
        (invocation_response({"unexpected": True}), "kaevo-api"),
        (invocation_response({"statusCode": 200}), ""),
    ):
        result = MODULE.dispatch({}, lambda_client=LambdaClient(response), target_function_name=target)
        assert result["statusCode"] == 503
        assert json.loads(result["body"]) == {"state": "identity_provider_unavailable"}
        assert result["headers"]["cache-control"] == "no-store"


def test_dispatcher_source_never_logs_or_serializes_payloads_to_diagnostics():
    source = SOURCE.read_text(encoding="utf-8")
    assert "logging" not in source
    assert "print(" not in source
    assert "LOGGER" not in source
    assert "Authorization" not in source

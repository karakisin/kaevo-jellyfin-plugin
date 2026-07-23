"""Privacy-safe dispatcher for the isolated social-identity API routes.

API Gateway invokes this function so the mature shared API Lambda does not
accumulate more resource-policy statements.  The dispatcher deliberately owns
no authentication or identity logic: it forwards the original API Gateway
event to the exact configured Kaevo API Lambda and returns that Lambda's proxy
response unchanged.

Request events and response bodies are never logged because OAuth callbacks can
contain short-lived authorization codes.
"""

from __future__ import annotations

import json
import os
from typing import Any, Mapping

import boto3


TARGET_FUNCTION_NAME = os.environ.get("TARGET_FUNCTION_NAME", "").strip()


def _safe_failure() -> dict[str, Any]:
    return {
        "statusCode": 503,
        "headers": {
            "content-type": "application/json",
            "cache-control": "no-store",
        },
        "body": json.dumps({"state": "identity_provider_unavailable"}),
    }


def dispatch(event: Mapping[str, Any], *, lambda_client: Any, target_function_name: str):
    if not target_function_name:
        return _safe_failure()
    try:
        invocation = lambda_client.invoke(
            FunctionName=target_function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(dict(event), separators=(",", ":")).encode("utf-8"),
        )
        if invocation.get("FunctionError"):
            return _safe_failure()
        payload = invocation["Payload"].read(6 * 1024 * 1024 + 1)
        if len(payload) > 6 * 1024 * 1024:
            return _safe_failure()
        response = json.loads(payload)
        if not isinstance(response, dict) or not isinstance(response.get("statusCode"), int):
            return _safe_failure()
        return response
    except Exception:
        return _safe_failure()


def lambda_handler(event, _context):
    return dispatch(
        event,
        lambda_client=boto3.client("lambda"),
        target_function_name=TARGET_FUNCTION_NAME,
    )

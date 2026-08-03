"""Read-only, exact-binding preflight for the fixture runner."""

from __future__ import annotations

import datetime as dt
import email.utils
import os
from collections.abc import Mapping

from .constants import (
    AWS_ACCOUNT_ID, AWS_PROFILE, AWS_REGION, FIXTURE_ROOT, JOIN_LOGICAL_ID,
    JOIN_TRANSACTIONS_LOGICAL_ID, STACK_NAME, TABLE_BINDINGS,
)
from .control_plane import assert_control_plane_exception
from .contracts import assert_exact_join_transaction_lookup
from .errors import FixtureSafetyError
from .filesystem import validate_fixture_root


def _request_id(response: Mapping[str, object]) -> str:
    metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
    value = metadata.get("RequestId") if isinstance(metadata, Mapping) else ""
    return str(value or "")


def _assert_aws_time(response: Mapping[str, object], now: dt.datetime) -> None:
    metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
    headers = metadata.get("HTTPHeaders") if isinstance(metadata, Mapping) else None
    value = headers.get("date") if isinstance(headers, Mapping) else None
    if not isinstance(value, str):
        raise FixtureSafetyError("AWS_TIME_UNAVAILABLE")
    server = email.utils.parsedate_to_datetime(value)
    if server.tzinfo is None:
        server = server.replace(tzinfo=dt.timezone.utc)
    if abs((server - now).total_seconds()) > 120:
        raise FixtureSafetyError("CLOCK_SKEW_EXCESSIVE")


def _stack_resources(cfn: object) -> dict[str, str]:
    expected = set(TABLE_BINDINGS.values()) | {JOIN_LOGICAL_ID}
    found: dict[str, str] = {}
    seen_tokens: set[str] = set()
    token = None
    while True:
        request = {"StackName": STACK_NAME}
        if token:
            request["NextToken"] = token
        response = cfn.list_stack_resources(**request)
        if not isinstance(response, Mapping):
            raise FixtureSafetyError("STACK_RESOURCE_PAGE_INVALID")
        summaries = response.get("StackResourceSummaries")
        if not isinstance(summaries, list):
            raise FixtureSafetyError("STACK_RESOURCE_PAGE_INVALID")
        for resource in summaries:
            logical = resource.get("LogicalResourceId") if isinstance(resource, Mapping) else None
            physical = resource.get("PhysicalResourceId") if isinstance(resource, Mapping) else None
            if logical in expected and isinstance(physical, str) and physical:
                if logical in found:
                    raise FixtureSafetyError("STACK_RESOURCE_BINDING_DUPLICATE")
                found[logical] = physical
        token = response.get("NextToken")
        if token is None:
            break
        if not isinstance(token, str) or not token or token in seen_tokens:
            raise FixtureSafetyError("STACK_RESOURCE_PAGINATION_INVALID")
        seen_tokens.add(token)
    if set(found) != expected:
        raise FixtureSafetyError("STACK_RESOURCE_BINDING_MISSING")
    return found


def run_preflight(*, session_factory, root: str = FIXTURE_ROOT, now=None) -> dict[str, str]:
    """Perform no writes and return only safe status fields.

    ``session_factory`` is injected for deterministic tests.  Production calls
    it with explicit ``kaevo-dev`` and ``us-west-2`` values.
    """
    os.umask(0o077)
    validate_fixture_root(root)
    session = session_factory(profile_name=AWS_PROFILE, region_name=AWS_REGION)
    if getattr(session, "profile_name", AWS_PROFILE) != AWS_PROFILE or getattr(session, "region_name", AWS_REGION) != AWS_REGION:
        raise FixtureSafetyError("AWS_SESSION_MISMATCH")
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    if str(identity.get("Account") or "") != AWS_ACCOUNT_ID:
        raise FixtureSafetyError("AWS_ACCOUNT_MISMATCH")
    _assert_aws_time(identity, now or dt.datetime.now(dt.timezone.utc))
    cfn = session.client("cloudformation")
    stack_response = cfn.describe_stacks(StackName=STACK_NAME)
    stacks = stack_response.get("Stacks") or []
    stack = stacks[0] if len(stacks) == 1 and isinstance(stacks[0], Mapping) else None
    if not stack or stack.get("StackStatus") != "UPDATE_COMPLETE":
        raise FixtureSafetyError("STACK_NOT_UPDATE_COMPLETE")
    arn = str(stack.get("StackId") or "")
    if f":{AWS_REGION}:{AWS_ACCOUNT_ID}:stack/" not in arn:
        raise FixtureSafetyError("STACK_ARN_MISMATCH")
    resources = _stack_resources(cfn)
    lambda_response = session.client("lambda").get_function_configuration(FunctionName=resources[JOIN_LOGICAL_ID])
    if lambda_response.get("State") != "Active" or lambda_response.get("LastUpdateStatus") != "Successful":
        raise FixtureSafetyError("JOIN_LAMBDA_NOT_READY")
    variables = ((lambda_response.get("Environment") or {}).get("Variables") or {})
    table_client = session.client("dynamodb")
    join_description = None
    for environment_name, logical_id in TABLE_BINDINGS.items():
        physical = resources[logical_id]
        if variables.get(environment_name) != physical:
            raise FixtureSafetyError("LAMBDA_TABLE_BINDING_MISMATCH")
        description = table_client.describe_table(TableName=physical).get("Table") or {}
        if description.get("TableStatus") != "ACTIVE":
            raise FixtureSafetyError("TABLE_NOT_ACTIVE")
        table_arn = str(description.get("TableArn") or "")
        if f":dynamodb:{AWS_REGION}:{AWS_ACCOUNT_ID}:table/" not in table_arn:
            raise FixtureSafetyError("TABLE_ARN_MISMATCH")
        if logical_id == JOIN_TRANSACTIONS_LOGICAL_ID:
            join_description = description
    if not isinstance(join_description, Mapping):
        raise FixtureSafetyError("JOIN_TABLE_BINDING_MISSING")
    lookup = assert_exact_join_transaction_lookup(join_description)
    assert_control_plane_exception(root, now=now or dt.datetime.now(dt.timezone.utc))
    return {"event": "PREFLIGHT_OK", "transaction_lookup": lookup, "request_id": _request_id(identity)[:12]}

"""Fail-closed DynamoDB request construction for protected fixture cleanup."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from types import MappingProxyType


_PLACEHOLDER = re.compile(r"(?:#[A-Za-z0-9_]+|:[A-Za-z0-9_]+)")


class CleanupRequestError(ValueError):
    """A local validation failure; callers must not dispatch a request."""


def _freeze(value):
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _required_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise CleanupRequestError(f"invalid_{label}")
    return value


def build_exact_conditional_delete_request(
    *,
    table_name: str,
    key: Mapping[str, object],
    key_schema: Sequence[str],
    ownership: Mapping[str, object],
    allowed_options: Mapping[str, object] | None = None,
):
    """Build an immutable DynamoDB *resource API* DeleteItem request.

    Only the exact key and a conjunction of ownership predicates are accepted.
    Optional expression maps are omitted when not needed, preventing the AWS
    ``ExpressionAttributeNames must not be empty`` validation failure.
    """
    _required_string(table_name, "table_binding")
    schema = tuple(_required_string(field, "key_field") for field in key_schema)
    if not schema or set(key) != set(schema):
        raise CleanupRequestError("invalid_exact_key_shape")
    if not ownership:
        raise CleanupRequestError("ownership_projection_required")
    if allowed_options and set(allowed_options) - {"ReturnValues"}:
        raise CleanupRequestError("unsupported_deleteitem_option")
    for field, value in {**key, **ownership}.items():
        _required_string(field, "field")
        if value is None or value == "":
            raise CleanupRequestError("invalid_ownership_value")

    names: dict[str, str] = {}
    values: dict[str, object] = {}
    clauses: list[str] = []
    for index, (field, value) in enumerate(sorted(ownership.items())):
        name = f"#o{index}"
        value_name = f":o{index}"
        names[name] = field
        values[value_name] = value
        clauses.append(f"{name} = {value_name}")
    expression = " AND ".join(clauses)
    used = set(_PLACEHOLDER.findall(expression))
    if used != set(names) | set(values):
        raise CleanupRequestError("unused_or_missing_expression_placeholder")
    request: dict[str, object] = {"Key": dict(key), "ConditionExpression": expression}
    if names:
        request["ExpressionAttributeNames"] = names
    if values:
        request["ExpressionAttributeValues"] = values
    if allowed_options:
        request.update(allowed_options)
    return _freeze(request)

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.household_join_live.cleanup import CleanupRequestError, build_exact_conditional_delete_request


def request(**overrides):
    kwargs = {
        "table_name": "fixture-table",
        "key": {"id": "fixture-key"},
        "key_schema": ("id",),
        "ownership": {"fixture_marker": "fixture-a", "state": "active"},
    }
    kwargs.update(overrides)
    return build_exact_conditional_delete_request(**kwargs)


def test_builds_valid_simple_and_composite_exact_conditional_deletes():
    simple = request()
    composite = request(key={"household_id": "h", "membership_id": "m"}, key_schema=("household_id", "membership_id"))
    assert simple["Key"] == {"id": "fixture-key"}
    assert set(composite["Key"]) == {"household_id", "membership_id"}
    assert set(simple["ExpressionAttributeNames"]) == {"#o0", "#o1"}
    assert set(simple["ExpressionAttributeValues"]) == {":o0", ":o1"}


@pytest.mark.parametrize(
    "overrides, code",
    [
        ({"key": {"other": "x"}}, "invalid_exact_key_shape"),
        ({"ownership": {}}, "ownership_projection_required"),
        ({"ownership": {"state": None}}, "invalid_ownership_value"),
        ({"allowed_options": {"ReturnValuesOnConditionCheckFailure": "ALL_OLD"}}, "unsupported_deleteitem_option"),
    ],
)
def test_rejects_invalid_or_unsupported_delete_shapes(overrides, code):
    with pytest.raises(CleanupRequestError, match=code):
        request(**overrides)


def test_request_is_immutable_and_contains_no_empty_expression_maps():
    built = request(ownership={"state": "active"})
    assert built["ExpressionAttributeNames"]
    assert built["ExpressionAttributeValues"]
    with pytest.raises(TypeError):
        built["Key"] = {}

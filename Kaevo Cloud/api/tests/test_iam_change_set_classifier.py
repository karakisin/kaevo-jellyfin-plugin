from __future__ import annotations

import pytest

from scripts.iam_change_set_classifier import (
    DIRECT,
    DYNAMIC,
    UNEXPLAINED,
    classify_change_set,
    classify_detail,
    flatten_change_set_pages,
    redact_value,
)


ROLE = "KaevoCloudApiFunctionRole"
FUNCTION = "KaevoCloudApiFunction"
API = "KaevoCloudHttpApi"
SOCIAL_ROLE = "KaevoSocialIdentityApiFunctionRole"
SOCIAL_FUNCTION = "KaevoSocialIdentityApiFunction"


def detail(name, *, evaluation="Dynamic", source="ResourceAttribute", causing="cause"):
    return {"Evaluation": evaluation, "ChangeSource": source, "CausingEntity": causing, "Target": {"Name": name}}


def change(logical, *details):
    return {"ResourceChange": {"LogicalResourceId": logical, "Action": "Modify", "Details": list(details)}}


def expected_causes():
    return {
        (FUNCTION, "Role"): {f"{ROLE}.Arn"},
        (API, "Body"): {f"{FUNCTION}.Arn", f"{SOCIAL_FUNCTION}.Arn"},
        (SOCIAL_ROLE, "Policies"): {f"{FUNCTION}.Arn"},
        (SOCIAL_FUNCTION, "Role"): {f"{SOCIAL_ROLE}.Arn"},
    }


def safe_pages(extra=None):
    role = detail("Policies", evaluation="Static", source="DirectModification", causing=None)
    return [{"Changes": [
        change(ROLE, role), change(FUNCTION, detail("Role", causing=f"{ROLE}.Arn")),
        change(API, detail("Body", causing=f"{FUNCTION}.Arn"), detail("Body", causing=f"{SOCIAL_FUNCTION}.Arn")),
        change(SOCIAL_ROLE, detail("Policies", causing=f"{FUNCTION}.Arn")),
        change(SOCIAL_FUNCTION, detail("Role", causing=f"{SOCIAL_ROLE}.Arn")),
    ] + ([] if extra is None else [extra])}]


def add_detail(pages, logical, value):
    for item in pages[0]["Changes"]:
        resource = item["ResourceChange"]
        if resource["LogicalResourceId"] == logical:
            resource["Details"].append(value)
            return pages
    raise AssertionError("logical resource not found")


def test_one_direct_static_iam_policy_with_dynamic_dependents_is_execution_safe():
    result, details = classify_change_set(safe_pages(), direct_targets={(ROLE, "Policies")}, expected_causes=expected_causes())
    assert result == "ONE_DIRECT_PLUS_DYNAMIC_NOOP_DEPENDENCIES"
    assert (ROLE, "Policies", DIRECT) in details
    assert (FUNCTION, "Role", DYNAMIC) in details


@pytest.mark.parametrize("logical,name", [(FUNCTION, "Code"), (API, "Body"), (SOCIAL_ROLE, "Policies")])
def test_direct_static_changes_outside_the_approved_role_are_rejected(logical, name):
    result, _ = classify_change_set(add_detail(safe_pages(), logical, detail(name, evaluation="Static", source="DirectModification", causing=None)), direct_targets={(ROLE, "Policies")}, expected_causes=expected_causes())
    assert result == "REAL_MULTI_RESOURCE_CHANGE"


def test_parameter_change_is_rejected():
    result, _ = classify_change_set(add_detail(safe_pages(), FUNCTION, detail("Environment", evaluation="Static", source="ParameterReference", causing="Parameter")), direct_targets={(ROLE, "Policies")}, expected_causes=expected_causes())
    assert result == "REAL_MULTI_RESOURCE_CHANGE"


@pytest.mark.parametrize("name", ["CodeUri", "DefinitionUri", "BodyS3Location"])
def test_newly_packaged_artifact_locations_are_rejected(name):
    assert classify_detail(detail(name, evaluation="Static", source="DirectModification", causing=None)) != DYNAMIC


def test_missing_causing_entity_is_rejected():
    result, _ = classify_change_set(add_detail(safe_pages(), FUNCTION, detail("Role", causing=None)), direct_targets={(ROLE, "Policies")}, expected_causes=expected_causes())
    assert result == "REAL_MULTI_RESOURCE_CHANGE"


def test_unexpected_dynamic_cause_is_rejected():
    result, _ = classify_change_set(add_detail(safe_pages(), FUNCTION, detail("Role", causing="Other.Arn")), direct_targets={(ROLE, "Policies")}, expected_causes=expected_causes())
    assert result == "DEPENDENCY_ATTRIBUTION_AMBIGUOUS"


def test_duplicate_change_set_pages_fail_closed():
    pages = [{"Changes": [change(ROLE, detail("Policies", evaluation="Static", source="DirectModification", causing=None))]}, {"Changes": [change(ROLE, detail("Policies", evaluation="Static", source="DirectModification", causing=None))]}]
    with pytest.raises(ValueError, match="duplicate"):
        flatten_change_set_pages(pages)


@pytest.mark.parametrize("token", ["", "repeat"])
def test_malformed_or_repeated_pagination_token_fails_closed(token):
    pages = [{"Changes": [], "NextToken": "repeat"}, {"Changes": [], "NextToken": token}]
    with pytest.raises(ValueError, match="pagination"):
        flatten_change_set_pages(pages)


def test_secret_values_are_not_returned_from_evidence_redaction():
    assert redact_value({"token": "do-not-display"}) == "[redacted]"
    assert redact_value({"safe": "value"}) != "value"


def test_static_direct_detail_requires_template_delta_when_values_are_absent():
    assert classify_detail(detail("Policies", evaluation="Static", source="DirectModification", causing=None)) == UNEXPLAINED
    assert classify_detail(detail("Policies", evaluation="Static", source="DirectModification", causing=None), template_proves_direct_delta=True) == DIRECT


def test_noop_control_has_no_changes_and_processed_mismatch_requires_review():
    assert flatten_change_set_pages([{"Changes": []}]) == []
    assert {"stack_original": "a", "stack_processed": "b"}["stack_original"] != {"stack_original": "a", "stack_processed": "b"}["stack_processed"]

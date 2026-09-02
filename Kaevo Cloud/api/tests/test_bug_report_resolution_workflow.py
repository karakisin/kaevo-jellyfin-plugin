from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "resolve-bug-report.py"
SPEC = importlib.util.spec_from_file_location("kaevo_bug_report_resolution", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
resolution_workflow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolution_workflow)

ENRICH_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "enrich-bug-report.py"
ENRICH_SPEC = importlib.util.spec_from_file_location(
    "kaevo_bug_report_enrichment", ENRICH_SCRIPT_PATH
)
assert ENRICH_SPEC is not None and ENRICH_SPEC.loader is not None
enrichment_workflow = importlib.util.module_from_spec(ENRICH_SPEC)
ENRICH_SPEC.loader.exec_module(enrichment_workflow)

VERIFICATION_SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "request-bug-report-verification.py"
)
VERIFICATION_SPEC = importlib.util.spec_from_file_location(
    "kaevo_bug_report_verification_request", VERIFICATION_SCRIPT_PATH
)
assert VERIFICATION_SPEC is not None and VERIFICATION_SPEC.loader is not None
verification_workflow = importlib.util.module_from_spec(VERIFICATION_SPEC)
VERIFICATION_SPEC.loader.exec_module(verification_workflow)

RECONCILIATION_SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "reconcile-sentry-bug-report.py"
)
RECONCILIATION_SPEC = importlib.util.spec_from_file_location(
    "kaevo_bug_report_sentry_reconciliation", RECONCILIATION_SCRIPT_PATH
)
assert RECONCILIATION_SPEC is not None and RECONCILIATION_SPEC.loader is not None
reconciliation_workflow = importlib.util.module_from_spec(RECONCILIATION_SPEC)
RECONCILIATION_SPEC.loader.exec_module(reconciliation_workflow)


def test_operator_resolution_reference_is_exact_and_immutable():
    assert resolution_workflow.REFERENCE_PATTERN.fullmatch("KV-ABC12345")
    assert not resolution_workflow.REFERENCE_PATTERN.fullmatch("KV-ABC1234")
    assert not resolution_workflow.REFERENCE_PATTERN.fullmatch("KV-ABC12345-extra")


def test_operator_enrichment_binds_reference_to_sentry_event():
    reference, event_id = enrichment_workflow.validate_identity(
        "kv-1b1d2228",
        "1b1d2228a1ed4ac2b70d6f9924619659",
    )

    assert reference == "KV-1B1D2228"
    assert event_id == "1b1d2228a1ed4ac2b70d6f9924619659"


def test_operator_enrichment_rejects_mismatched_reference():
    try:
        enrichment_workflow.validate_identity(
            "KV-AD4A4D54",
            "1b1d2228a1ed4ac2b70d6f9924619659",
        )
    except ValueError as error:
        assert "does not match" in str(error)
    else:
        raise AssertionError("mismatched reference must be rejected")


def test_operator_verification_request_keeps_resolution_user_confirmed():
    assert verification_workflow.REFERENCE_PATTERN.fullmatch("KV-ABC12345")
    assert verification_workflow.SENTRY_ISSUE_ID_PATTERN.fullmatch("7673194304")
    assert not verification_workflow.SENTRY_ISSUE_ID_PATTERN.fullmatch("APPLE-IOS-1A")
    assert "bug_report_verification_requested" in verification_workflow.LIFECYCLE_EVENT_TYPES
    assert "bug_report_verified_resolved" in verification_workflow.LIFECYCLE_EVENT_TYPES
    assert "bug_report_reopened" in verification_workflow.LIFECYCLE_EVENT_TYPES


def test_reconciliation_accepts_only_the_event_bound_to_the_reference():
    records = [{
        "event_type": "bug_report_submitted",
        "metadata_json": '{"sentry_event_id":"1b1d2228a1ed4ac2b70d6f9924619659"}',
    }]

    assert reconciliation_workflow.immutable_sentry_event_id(
        records, "KV-1B1D2228"
    ) == "1b1d2228a1ed4ac2b70d6f9924619659"
    assert reconciliation_workflow.immutable_sentry_event_id(
        records, "KV-AD4A4D54"
    ) == ""
